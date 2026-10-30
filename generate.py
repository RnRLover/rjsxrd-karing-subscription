"""rjsxrd -> full Xray proxy pool with embedded GeoSite/GeoIP; stdlib only."""
import argparse
import concurrent.futures
import copy
import hashlib
import ipaddress
import json
import os
import re
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from bisect import bisect_right
from collections import Counter
from pathlib import Path

from rjsxrd_parser import parse_url
from routing import domains, policy
from pool_selection import node_key, select_pool, recent_exit
from latency_checks import measure_latency, reusable_latency, latency_report
from ip_reputation import load_feed, rank_nodes, reputation_report
from quality_checks import probe_quality, reusable_quality, record_result, history_summary, quality_report, quality_priority
from certificate_checks import probe_transport, complete_transport, reusable_transport, transport_report

ROOT = Path(__file__).resolve().parent

def serialized_config(config):
    text = json.dumps(config, ensure_ascii=False, separators=(",", ":")) + "\n"
    # Conservative UTF-16 budget with room for INCY patching and IPC metadata.
    # This is a publication guard, not a measurement of Android's actual Parcel.
    if len(text.encode("utf-16-le")) > 250_000:
        raise ValueError("config exceeds Android publication size budget")
    return text

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "rjsxrd-karing-subscription/1"})
    with urllib.request.urlopen(req, timeout=30) as response:
        data = response.read(8_000_001)
    if len(data) > 8_000_000:
        raise ValueError("upstream payload exceeds 8 MB")
    return data.decode("utf-8-sig")

class CountryRanges:
    def __init__(self, cidrs):
        self.ranges = {}
        for version in (4, 6):
            nets = [ipaddress.ip_network(c, strict=False) for c in cidrs]
            intervals = sorted((int(n.network_address), int(n.broadcast_address)) for n in nets if n.version == version)
            merged = []
            for start, end in intervals:
                if merged and start <= merged[-1][1] + 1:
                    merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
                else:
                    merged.append((start, end))
            self.ranges[version] = ([a for a, b in merged], [b for a, b in merged])

    def contains(self, address):
        ip = ipaddress.ip_address(address)
        starts, ends = self.ranges[ip.version]
        i = bisect_right(starts, int(ip)) - 1
        return i >= 0 and int(ip) <= ends[i]

def russian_label(label):
    label = urllib.parse.unquote(label).lower()
    return "🇷🇺" in label or bool(re.search(r"(?<![a-zа-я])(ru|rus|russia|russian|россия|российский|москва)(?![a-zа-я])", label))

def endpoint_allowed(host, resolver=None):
    resolver = resolver or resolve
    addresses = resolver(host)
    return bool(addresses) and all(ipaddress.ip_address(a).is_global for a in addresses)

def egress_allowed(address, ranges):
    try:
        ip = ipaddress.ip_address(address)
        return ip.is_global and not ranges.contains(ip)
    except (ValueError, TypeError):
        return False

def require_exit_checks(enabled, xray):
    if not enabled or not xray:
        raise ValueError('publication requires --verify-exits and --xray: entry country does not establish exit country')

def resolve(host):
    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        pass
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
    except OSError:
        return []

def parse_node(line):
    if not line.startswith(("vless://", "trojan://", "ss://", "vmess://")):
        return None
    cfg = parse_url(line)
    if cfg is None or not cfg.host or not 1 <= cfg.port <= 65535:
        return None
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(line).query)
    val = lambda key: query.get(key, [""])[0]
    if any(val(key).lower() in ("1", "true", "yes") for key in ("allowInsecure", "insecure")) or val("verify").lower() in ("0", "false"):
        return None
    if line.startswith(("vless://", "trojan://", "vmess://")) and not cfg.tls:
        return None
    transport = cfg.transport or "tcp"
    if transport == "raw": cfg.transport = "tcp"
    if transport not in ("", "raw", "tcp", "ws", "grpc"):
        return None
    # Do not silently reinterpret transports/extensions not handled by upstream.
    if val("headerType") not in ("", "none") or val("packetEncoding") or val("plugin"):
        return None
    if val("ed") or val("eh"):
        return None
    if line.startswith("vless://") and (cfg.encryption != "none" or cfg.flow not in ("", "xtls-rprx-vision")):
        return None
    if line.startswith("vmess://") and (cfg.alter_id != 0 or not isinstance(cfg.security, str) or not cfg.security or cfg.security.lower() in ("none", "zero")):
        return None
    if line.startswith("ss://") and cfg.method not in ("aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"):
        return None
    outbound = cfg.to_xray_outbound("candidate")
    if outbound is None: return None
    stream = outbound.get("streamSettings", {})
    if stream.get("security") == "reality":
        reality = stream["realitySettings"]
        if not cfg.sni or not re.fullmatch(r"[A-Za-z0-9_-]{43}", cfg.public_key): return None
        reality["fingerprint"] = val("fp") or "chrome"
        if val("spx"): reality["spiderX"] = val("spx")
    elif stream.get("security") == "tls":
        tls = stream["tlsSettings"]
        tls["fingerprint"] = val("fp") or "chrome"
        if val("alpn"): tls["alpn"] = val("alpn").split(",")
    if stream.get("network") == "grpc":
        if val("authority"): stream["grpcSettings"]["authority"] = val("authority")
        if val("mode") == "multi": stream["grpcSettings"]["multiMode"] = True
    # Vendor may include an obsolete extra fingerprint outside security settings.
    stream.pop("fingerprint", None)
    return {"host": cfg.host, "label": urllib.parse.unquote(cfg.remark), "outbound": outbound, "uri": line}

def build(nodes, routing, minimum=2):
    if len(nodes) < minimum: raise ValueError(f"need at least {minimum} eligible exits")
    proxies = []
    for i, node in enumerate(nodes, 1):
        ob = copy.deepcopy(node["outbound"])
        ob["tag"] = f"pool-{i:02d}"
        proxies.append(ob)
    # Block fallback until probes complete or if the entire pool is down.
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"udp": True}, "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}}, {"tag": "http-in", "listen": "127.0.0.1", "port": 10809, "protocol": "http"}],
        "outbounds": [{"tag": "block", "protocol": "blackhole"}, *proxies, {"tag": "direct", "protocol": "freedom"}],
        "routing": copy.deepcopy(routing),
        "burstObservatory": {"subjectSelector": ["pool-"], "pingConfig": {"destination": "https://www.gstatic.com/generate_204", "interval": "3m", "sampling": 1, "timeout": "5s"}},
        "stats": {},
        "meta": {"serverDescription": "rjsxrd: RU/local direct; ads blocked; all other TCP/UDP via automatic proxy"}
    }

def xray_validate(xray, config):
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "config.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        result = subprocess.run([str(Path(xray).resolve()), "run", "-test", "-config", str(path)], capture_output=True, text=True, timeout=30)
        if result.returncode: raise ValueError("Xray rejected config: " + result.stderr[-800:] + result.stdout[-800:])

def atomic_write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as f:
        f.write(content)
        temporary = Path(f.name)
    os.replace(temporary, path)

def verify_exits(nodes, ranges, xray, failures=None):
    """Collect actual HTTPS egress IPs; country filtering is done by the caller."""
    if not nodes: return []
    failures = failures if failures is not None else Counter()
    held, ports = [], []
    for node in nodes:
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        held.append(sock)
        ports.append(sock.getsockname()[1])
    cfg = {"log": {"loglevel": "none"}, "inbounds": [], "outbounds": [], "routing": {"rules": []}}
    for i, (node, port) in enumerate(zip(nodes, ports)):
        tag = f"test-{i}"
        cfg["inbounds"].append({"tag": tag, "protocol": "http", "listen": "127.0.0.1", "port": port})
        ob = copy.deepcopy(node["outbound"])
        ob["tag"] = tag
        cfg["outbounds"].append(ob)
        cfg["routing"]["rules"].append({"type": "field", "inboundTag": [tag], "outboundTag": tag})
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "probe.json"
        path.write_text(json.dumps(cfg), encoding="utf-8")
        xray_validate(xray, cfg)
        for sock in held: sock.close()
        process = subprocess.Popen([str(Path(xray).resolve()), "run", "-config", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if process.poll() is not None: raise ValueError("Xray probe process stopped")
                try:
                    with socket.create_connection(("127.0.0.1", ports[0]), timeout=0.2): break
                except OSError: time.sleep(0.1)
            def check(pair):
                node, port = pair
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({"https": f"http://127.0.0.1:{port}"}))
                stage = 'transport'
                try:
                    evidence = probe_transport(node)
                    stage = 'xray_https'
                    with opener.open("https://api.ipify.org?format=json", timeout=12) as response:
                        if response.getcode() != 200: raise ValueError('exit_status')
                        ip = json.loads(response.read(1000))["ip"]
                    if not egress_allowed(ip, ranges):
                        return {**node, 'exit_ip': str(ipaddress.ip_address(ip)),
                                'transport_check': complete_transport(evidence)}
                    stage = 'quality'
                    quality = probe_quality(opener)
                    return {**node, 'exit_ip': str(ipaddress.ip_address(ip)),
                            'transport_check': complete_transport(evidence),
                            'latency_check': measure_latency(opener), 'quality_check': quality}
                except Exception as error:
                    return {'probe_failure': stage + ':' + type(error).__name__}
            with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
                results = list(executor.map(check, zip(nodes, ports)))
                failures.update(n['probe_failure'] for n in results if 'probe_failure' in n)
                return [n for n in results if 'probe_failure' not in n]
        finally:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT)
    parser.add_argument("--cache", type=Path, help="use saved upstream data instead of downloading")
    parser.add_argument("--xray", help="Xray binary: required for publication")
    parser.add_argument("--verify-exits", action="store_true", help="check actual HTTPS egress; requires --xray")
    args = parser.parse_args()
    require_exit_checks(args.verify_exits, args.xray)
    settings = json.loads((ROOT / "settings.json").read_text(encoding="utf-8"))
    source_url = settings['subscription_url']
    def read(path, url):
        return (args.cache / path).read_text(encoding="utf-8-sig") if args.cache else fetch(url)
    original = read('rjsxrd.txt', source_url)
    raw = read("geo/geoip/ru.json", settings["ru_cidrs_url"])
    obj = json.loads(raw)
    cidrs = [c for r in obj["rules"] for c in r.get("ip_cidr", [])]
    if not cidrs: raise ValueError("RU address table required")
    ranges = CountryRanges(cidrs)
    country_data = {"url": settings["ru_cidrs_url"], "sha256": hashlib.sha256(raw.encode()).hexdigest(), "use": "server exclusion; client routing uses INCY geoip:ru"}
    geo_sources = []
    categories = {}
    for name, url in settings["geosite_urls"].items():
        data = read("geo/geosite/" + name + ".json", url)
        categories[name] = domains(json.loads(data))
        geo_sources.append({"category": name, "url": url, "sha256": hashlib.sha256(data.encode()).hexdigest(), "entries": len(categories[name])})
    routing = policy(categories["category-ru"], cidrs)
    # The shared clients use standard geodata; do not waste the pool budget
    # on expanded domains that the published policy replaces with this tag.
    routing["rules"][1]["domain"] = ["geosite:category-ru"]
    candidates, seen, counters = [], set(), Counter()
    for line in original.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        counters["source_nodes"] += 1
        try: node = parse_node(line)
        except (ValueError, TypeError, KeyError): node = None
        if node is None:
            counters["unsupported_or_invalid"] += 1
            continue
        if russian_label(node["label"]):
            counters["russian_label_candidates"] += 1
        key = json.dumps(node["outbound"], sort_keys=True)
        if key in seen:
            counters["duplicate"] += 1
            continue
        seen.add(key)
        candidates.append(node)
    hosts = sorted({n["host"] for n in candidates})
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        allowed = dict(zip(hosts, executor.map(endpoint_allowed, hosts)))
    eligible = [n for n in candidates if allowed[n["host"]]]
    counters["nonpublic_or_unresolved_endpoint"] = len(candidates) - len(eligible)
    cache_path = ROOT / '.runtime' / 'exit-cache.json'
    exit_cache = json.loads(cache_path.read_text()) if cache_path.exists() else {}
    now = int(time.time())
    ttl = settings.get('exit_country_cache_seconds', 86400)
    checked, pending = [], []
    for node in eligible:
        key = node_key(node)
        entry = exit_cache.get(key, {})
        cached = recent_exit(node, exit_cache, now, ranges, ttl)
        if (cached and reusable_transport(entry.get('transport_check'), now)
                and reusable_latency(entry.get('latency_check'), now)
                and reusable_quality(entry.get('quality_check'), now)):
            checked.append({**cached, 'transport_check': entry['transport_check'],
                            'latency_check': entry['latency_check'],
                            'quality_check': entry['quality_check'],
                            'quality_history': history_summary(entry, now)})
        else:
            fresh_ru = (not cached and 'exit_ip' in entry
                        and 0 <= now - entry.get('verified_at', 0) < ttl
                        and not egress_allowed(entry['exit_ip'], ranges))
            failed_recently = 0 <= now - entry.get('failed_at', 0) < 900
            if not fresh_ru and not failed_recently:
                pending.append(node)
    counters['cached_foreign_exits'] = len(checked)
    transport_failures = Counter()
    if pending:
        control = probe_quality(urllib.request.build_opener(urllib.request.ProxyHandler({})))
        if not control['passed']:
            raise RuntimeError('Quality test destinations unavailable from runner; preserve existing pool/history: ' + json.dumps(control))
    measured = verify_exits(pending, ranges, args.xray, transport_failures) if pending else []
    print(json.dumps({'transport_failure_counts': dict(transport_failures),
                      'quality_tested': len(measured),
                      'quality_passed': sum(n.get('quality_check', {}).get('passed') is True for n in measured),
                      'quality_errors': dict(Counter(e for n in measured for e in n.get('quality_check', {}).get('errors', [])))}))
    measured_keys = {node_key(node) for node in measured}
    for node in pending:
        key = node_key(node)
        if key not in measured_keys:
            entry = record_result(exit_cache.get(key, {}), False, now)
            entry['failed_at'] = now
            # Never admit stale success after a failed current probe.
            entry.pop('quality_check', None)
            exit_cache[key] = entry
    for node in measured:
        key = node_key(node)
        passed = egress_allowed(node['exit_ip'], ranges) and node.get('quality_check', {}).get('passed') is True
        entry = record_result(exit_cache.get(key, {}), passed, now)
        entry.update({k: node[k] for k in ('exit_ip', 'transport_check', 'latency_check', 'quality_check') if k in node})
        entry['verified_at'] = now
        if passed: entry.pop('failed_at', None)
        else: entry['failed_at'] = now; entry.pop('quality_check', None)
        exit_cache[key] = entry
        if egress_allowed(node['exit_ip'], ranges):
            checked.append({**node, 'quality_history': history_summary(entry, now)})
    # Persist observations even when no pool can be published. A cached result
    # does not add an observation. A missing CI cache starts provisional history.
    active_keys = {node_key(n) for n in eligible}
    for key in list(exit_cache):
        if len(key) == 64 and key not in active_keys:
            last = max(exit_cache[key].get('verified_at', 0), exit_cache[key].get('failed_at', 0))
            if now - last > 7 * 86400: del exit_cache[key]
    cache_path.parent.mkdir(exist_ok=True)
    atomic_write(cache_path, json.dumps(exit_cache, sort_keys=True) + '\n')
    feed, reputation_source = load_feed(exit_cache, fetch, now)
    checked = rank_nodes(checked, feed)
    cache_path.parent.mkdir(exist_ok=True)
    atomic_write(cache_path, json.dumps(exit_cache, sort_keys=True) + '\n')
    previous_path = ROOT / 'ru.json'
    previous = []
    if previous_path.exists():
        previous = [node_key({'outbound': ob}) for ob in json.loads(previous_path.read_bytes())['outbounds'] if ob['protocol'] in ('vless', 'vmess', 'trojan', 'shadowsocks')]
    selected = select_pool(checked, min(settings['max_nodes'], 40), previous, require_quality=True)
    # Preserve the quality/diversity order if the Android budget trims a tail.
    while True:
        config = build(selected, routing)
        try:
            config_text = serialized_config(config)
            if len(config_text.encode('utf-16-le')) > 220_000:
                raise ValueError('config exceeds Android publication size budget')
            break
        except ValueError as error:
            if 'publication size budget' not in str(error) or len(selected) <= 2:
                raise
            selected.pop()
    # A stable node starts first; device-side leastPing is unchanged.
    from latency_checks import latency_value
    selected = sorted(selected, key=lambda n: (quality_priority(n), latency_value(n)))
    reputation = reputation_report(checked, selected, feed, reputation_source)
    print(json.dumps({'ip_reputation': reputation}, ensure_ascii=False))
    config = build(selected, routing)
    config_text = serialized_config(config)
    if args.xray: xray_validate(args.xray, config)
    report = {"generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "pool": "whitelist", "source": source_url, "source_sha256": hashlib.sha256(original.encode()).hexdigest(), "counts": dict(counters), "eligible": len(eligible), "selected": len(selected), "xray_validated": bool(args.xray), "actual_egress_checked": args.verify_exits, "service_acl": False, "country_data": country_data, "excluded_country": "RU", "exclusion_basis": "mandatory actual HTTPS egress IP against RU CIDRs; public Russian entry IPs and RU labels permitted", "selected_protocols": dict(Counter(n["outbound"]["protocol"] for n in selected))}
    report["service_acl"] = False
    report["routing_policy"] = "local direct; RU direct; everything else proxy"
    report['ru_reachability_required'] = False
    report['pool_selection'] = 'verified transfer and two-site HTTPS health; actual rolling success >=90%; prefer established stability/performance bands; strict infrastructure caps; up to 40 nodes; client leastPing'
    report['quality_selection'] = quality_report(checked, selected)
    report['ip_reputation'] = reputation
    report['transport_checks'] = transport_report(selected, transport_failures)
    report['latency_selection'] = latency_report(checked, selected)
    report['latency_selection']['policy'] = 'quality/history bands first, exact median HTTPS latency within band; client leastPing unchanged'
    report['latency_selection']['failed_probe_policy'] = 'current two-site health and full transfer required independently of legacy HEAD measurements'
    report['reputation_excluded'] = sum(n['reputation']['status'] == 'listed' for n in checked)
    report['foreign_exit_candidates'] = len(checked)
    report["geosite_sources"] = geo_sources
    report["client_geoip"] = "geoip:ru from client installed geoip.dat; update client geodata"
    report["config_utf16_bytes"] = len(config_text.encode("utf-16-le"))
    report["config_utf8_bytes"] = len(config_text.encode("utf-8"))
    # Files change only after all inputs and Xray validation succeeded.
    config_name, report_name = ('ru.json', 'report.json')
    atomic_write(args.output / config_name, config_text)
    atomic_write(args.output / report_name, json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"counts": counters, "eligible": len(eligible), "selected": len(selected), "xray_validated": bool(args.xray)}))

if __name__ == "__main__": main()

