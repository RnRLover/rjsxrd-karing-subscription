"""rjsxrd -> full Xray proxy pool without service ACL; Python stdlib only."""
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

ROOT = Path(__file__).resolve().parent

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

def endpoint_allowed(host, ranges, resolver=None):
    resolver = resolver or resolve
    addresses = resolver(host)
    return bool(addresses) and all(ipaddress.ip_address(a).is_global and not ranges.contains(a) for a in addresses)

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
    if line.startswith("vmess://") and (cfg.alter_id != 0 or cfg.security.lower() in ("none", "zero")):
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

def build(nodes):
    if len(nodes) < 2: raise ValueError("need at least two eligible exits")
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
        "routing": {"domainStrategy": "AsIs", "balancers": [{"tag": "auto", "selector": ["pool-"], "fallbackTag": "block", "strategy": {"type": "leastPing"}}], "rules": [{"type": "field", "network": "tcp,udp", "balancerTag": "auto"}]},
        "burstObservatory": {"subjectSelector": ["pool-"], "pingConfig": {"destination": "https://www.gstatic.com/generate_204", "interval": "30s", "sampling": 2, "timeout": "5s"}},
        "stats": {},
        "meta": {"serverDescription": "rjsxrd: Russian endpoints excluded; automatic proxy; no service ACL"}
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

def verify_exits(nodes, ranges, xray):
    """Check actual egress via HTTPS through each proxy, not just TCP reachability."""
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
                try:
                    with opener.open("https://api.ipify.org?format=json", timeout=12) as response:
                        ip = json.loads(response.read(1000))["ip"]
                    if not ipaddress.ip_address(ip).is_global or ranges.contains(ip): return None
                    return node
                except Exception: return None
            with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
                return [node for node in executor.map(check, zip(nodes, ports)) if node is not None]
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
    settings = json.loads((ROOT / "settings.json").read_text(encoding="utf-8"))
    def read(path, url):
        return (args.cache / path).read_text(encoding="utf-8-sig") if args.cache else fetch(url)
    original = read("rjsxrd.txt", settings["subscription_url"])
    raw = read("geo/geoip/ru.json", settings["ru_cidrs_url"])
    obj = json.loads(raw)
    cidrs = [c for r in obj["rules"] for c in r.get("ip_cidr", [])]
    if not cidrs: raise ValueError("RU address table required")
    ranges = CountryRanges(cidrs)
    country_data = {"url": settings["ru_cidrs_url"], "sha256": hashlib.sha256(raw.encode()).hexdigest(), "use": "server exclusion only; not client routing"}
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
            counters["russian_label"] += 1
            continue
        key = json.dumps(node["outbound"], sort_keys=True)
        if key in seen:
            counters["duplicate"] += 1
            continue
        seen.add(key)
        candidates.append(node)
    hosts = sorted({n["host"] for n in candidates})
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        allowed = dict(zip(hosts, executor.map(lambda h: endpoint_allowed(h, ranges), hosts)))
    eligible = [n for n in candidates if allowed[n["host"]]]
    counters["russian_or_unresolved_endpoint"] = len(candidates) - len(eligible)
    # Upstream already sorts by its measured quality. Preserve that order.
    checked = eligible[:max(settings["max_nodes"] * 3, 72)]
    if args.verify_exits:
        if not args.xray: raise ValueError("--verify-exits requires --xray")
        checked = verify_exits(checked, ranges, args.xray)
    selected = checked[:settings["max_nodes"]]
    config = build(selected)
    if args.xray: xray_validate(args.xray, config)
    report = {"generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "source": settings["subscription_url"], "source_sha256": hashlib.sha256(original.encode()).hexdigest(), "counts": dict(counters), "eligible": len(eligible), "selected": len(selected), "xray_validated": bool(args.xray), "actual_egress_checked": args.verify_exits, "service_acl": False, "country_data": country_data, "excluded_country": "RU", "exclusion_basis": "source label, resolved endpoint IP, and (when enabled) actual HTTPS egress IP against RU CIDRs", "selected_protocols": dict(Counter(n["outbound"]["protocol"] for n in selected))}
    # Files change only after all inputs and Xray validation succeeded.
    atomic_write(args.output / "ru.json", json.dumps(config, ensure_ascii=False, separators=(",", ":")) + "\n")
    atomic_write(args.output / "servers.txt", "\n".join(n["uri"] for n in eligible) + "\n")
    atomic_write(args.output / "report.json", json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"counts": counters, "eligible": len(eligible), "selected": len(selected), "xray_validated": bool(args.xray)}))

if __name__ == "__main__": main()
