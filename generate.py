"""Publish the first eligible upstream nodes from each technology for INCY."""
import argparse
from collections import Counter
import concurrent.futures
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request

from incy import (ROOT, PROXY_PROTOCOLS, atomic_write, build,
                  serialized_config, subscription, xray_validate)
from ip_reputation import CACHE_KEY, load_feed, assess_nodes, rate_ip, reputation_report
from rjsxrd_parser import parse_url
from rjsxrd_helpers import query_parameters


def fetch(url, limit=8_000_000):
    for attempt in range(3):
        try:
            request = urllib.request.Request(url, headers={'User-Agent': 'rjsxrd-incy-subscription/2'})
            with urllib.request.urlopen(request, timeout=30) as response:
                data = response.read(limit + 1)
            if len(data) > limit:
                raise ValueError('upstream payload exceeds download budget')
            return data
        except (OSError, TimeoutError):
            if attempt == 2:
                raise
            time.sleep(.5 * (attempt + 1))


def parse_node(line):
    config = parse_url(line)
    if config is None or not config.host or not 1 <= config.port <= 65535:
        return None
    outbound = config.to_xray_outbound('candidate')
    if not outbound or outbound.get('protocol') not in PROXY_PROTOCOLS:
        return None
    params = query_parameters(urllib.parse.urlsplit(line).query)
    stream = outbound.get('streamSettings', {})
    if stream.get('network') == 'raw':
        stream['network'] = 'tcp'
    for key in ('tlsSettings', 'realitySettings'):
        settings = stream.get(key)
        if settings is not None:
            if params.get('alpn'):
                settings['alpn'] = params['alpn'][0].split(',')
            if params.get('spx') and key == 'realitySettings':
                settings['spiderX'] = params['spx'][0]
    if stream.get('network') == 'grpc':
        if params.get('authority'):
            stream['grpcSettings']['authority'] = params['authority'][0]
        if params.get('mode', [''])[0] == 'multi':
            stream['grpcSettings']['multiMode'] = True
    return {'host': config.host, 'label': urllib.parse.unquote(config.remark), 'outbound': outbound}


def collect_nodes(text):
    nodes, seen, counts = [], set(), Counter()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        counts['source_nodes'] += 1
        try:
            node = parse_node(line)
        except (ValueError, TypeError, KeyError, AttributeError):
            node = None
        if node is None:
            counts['unsupported_or_malformed'] += 1
            continue
        key = json.dumps(node['outbound'], sort_keys=True, separators=(',', ':'))
        if key in seen:
            counts['duplicate'] += 1
            continue
        seen.add(key)
        nodes.append(node)
    return nodes, counts


def compatible_nodes(nodes, xray, counts):
    """Only test JSON/core compatibility. This does not connect to the nodes."""
    def check(node):
        try:
            xray_validate(xray, {'outbounds': [node['outbound']]})
            return node
        except ValueError:
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        result = list(executor.map(check, nodes))
    counts['core_incompatible'] += sum(node is None for node in result)
    return [node for node in result if node is not None]


def entry_ips(host):
    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        try:
            return sorted({info[4][0] for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
        except OSError:
            return []


def exclude_listed(nodes):
    """Preserve upstream order, all unknowns and all countries."""
    return [node for node in nodes if node.get('reputation', {}).get('status') != 'listed'
            and not any(record['status'] == 'listed' for record in node.get('entry_reputation', []))]


def technology_key(node):
    outbound = node['outbound']
    stream = outbound.get('streamSettings', {})
    transport = stream.get('network', 'tcp').lower()
    transport = {'raw': 'tcp', 'websocket': 'ws', 'splithttp': 'xhttp'}.get(transport, transport)
    return (outbound['protocol'], transport, stream.get('security', 'none').lower())


def select_per_technology(nodes, limit):
    """Take each technology's first eligible entries without reordering the pool."""
    if type(limit) is not int or limit < 1:
        raise ValueError('max_nodes_per_technology must be a positive integer')
    selected, used = [], Counter()
    for node in nodes:
        key = technology_key(node)
        if used[key] < limit:
            selected.append(node)
            used[key] += 1
    return selected


def technology_report(eligible, selected, limit):
    available = Counter(technology_key(node) for node in eligible)
    groups = {key: {'protocol': key[0], 'transport': key[1], 'security': key[2],
                    'eligible': count, 'selected': 0, 'tags': []}
              for key, count in available.items()}
    for index, node in enumerate(selected, 1):
        group = groups[technology_key(node)]
        group['selected'] += 1
        group['tags'].append('Автовыбор' if index == 1 else f'pool-{index:03d}')
    return {'group_by': ['protocol', 'transport', 'security'], 'per_technology_limit': limit,
            'order': 'first eligible entries in upstream order',
            'balancing': 'one shared leastPing pool', 'groups': list(groups.values())}


def probe_exit(opener, timeout=4):
    # This single small request discovers the public exit for the blacklist.
    # Its latency and success are never membership or ranking criteria.
    with opener.open('https://api64.ipify.org?format=json', timeout=timeout) as response:
        ip = str(ipaddress.ip_address(json.loads(response.read(1000))['ip']))
        if not ipaddress.ip_address(ip).is_global:
            raise ValueError('non-public exit answer')
        return ip


def probe_exits(nodes, xray, workers=24, timeout=4):
    if not nodes:
        return []
    held, ports = [], []
    for _ in nodes:
        sock = socket.socket()
        sock.bind(('127.0.0.1', 0))
        held.append(sock)
        ports.append(sock.getsockname()[1])
    config = {'log': {'loglevel': 'none'}, 'inbounds': [], 'outbounds': [], 'routing': {'rules': []}}
    for index, (node, port) in enumerate(zip(nodes, ports)):
        tag = f'probe-{index}'
        config['inbounds'].append({'tag': tag, 'listen': '127.0.0.1', 'port': port, 'protocol': 'http'})
        outbound = copy.deepcopy(node['outbound'])
        outbound['tag'] = tag
        config['outbounds'].append(outbound)
        config['routing']['rules'].append({'type': 'field', 'inboundTag': [tag], 'outboundTag': tag})
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory, 'probe.json')
        path.write_text(json.dumps(config))
        xray_validate(xray, config)
        for sock in held:
            sock.close()
        process = subprocess.Popen([str(Path(xray).resolve()), 'run', '-c', str(path)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 5
            while True:
                try:
                    with socket.create_connection(('127.0.0.1', ports[0]), timeout=.1):
                        break
                except OSError:
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError('exit reputation probe core did not start')
                    time.sleep(.05)
            def check(pair):
                node, port = pair
                result = copy.deepcopy(node)
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({
                    'https': f'http://127.0.0.1:{port}'}))
                try:
                    result['exit_ip'] = probe_exit(opener, timeout)
                except Exception as error:
                    result['exit_ip'] = None
                    result['exit_discovery_error'] = type(error).__name__
                return result
            # executor.map preserves the source order despite completion order.
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                return list(executor.map(check, zip(nodes, ports)))
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--xray', required=True)
    args = parser.parse_args()
    settings = json.loads((ROOT / 'settings.json').read_bytes())
    original = fetch(settings['subscription_url']).decode('utf-8-sig')
    nodes, counts = collect_nodes(original)
    nodes = compatible_nodes(nodes, args.xray, counts)
    cache_path = ROOT / '.runtime' / 'reputation-cache.json'
    cache = json.loads(cache_path.read_bytes()) if cache_path.exists() else {}
    feed, feed_source = load_feed(cache, lambda url: fetch(url).decode('utf-8-sig'), int(time.time()))
    atomic_write(cache_path, json.dumps({CACHE_KEY: feed}) + '\n')
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as executor:
        addresses = list(executor.map(entry_ips, [node['host'] for node in nodes]))
    for node, ips in zip(nodes, addresses):
        node['entry_reputation'] = [dict(ip=ip, **rate_ip(ip, feed)) for ip in ips]
    retained = exclude_listed(nodes)
    counts['listed_entry'] = len(nodes) - len(retained)
    print(json.dumps({'source': dict(counts), 'exit_reputation_candidates': len(retained)}), flush=True)
    measured = probe_exits(retained, args.xray, settings['reputation_workers'],
                           settings['reputation_timeout_seconds'])
    rated = assess_nodes(measured, feed)
    eligible = exclude_listed(rated)
    counts['listed_exit'] = len(rated) - len(eligible)
    limit = settings['max_nodes_per_technology']
    selected = select_per_technology(eligible, limit)
    counts['over_technology_limit'] = len(eligible) - len(selected)
    if not selected:
        raise ValueError('no non-listed candidates; keep published subscription')
    config = build(selected, probe=settings['probe'])
    xray_validate(args.xray, config)
    report = {
        'generated_at_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'source': settings['subscription_url'], 'source_sha256': hashlib.sha256(original.encode()).hexdigest(),
        'counts': dict(counts), 'selected': len(selected), 'xray_validated': True,
        'selected_protocols': dict(Counter(node['outbound']['protocol'] for node in selected)),
        'pool_selection': 'first eligible entries per protocol/transport/security in upstream order; '
                          'exact duplicates removed; known listed entry/exit IPs excluded',
        'technology_selection': technology_report(eligible, selected, limit),
        'history_used': False, 'github_latency_ranking': False, 'country_filter': False,
        'tcp_udp_quality_gate': False, 'file_transfer_check': False,
        'pool_limit': {'per_technology': limit},
        'unknown_exit_retained': sum(node.get('exit_ip') is None for node in selected),
        'exit_discovery_errors': dict(Counter(node['exit_discovery_error'] for node in selected
                                              if node.get('exit_discovery_error'))),
        'ip_reputation': reputation_report(rated, selected, feed, feed_source),
        'subscription_policy': {
            'clients': ['INCY'], 'format': 'full-xray-json-array-with-body-metadata',
            'native_routing_profile': False,
            'dns_query_strategy': 'UseIP', 'ipv6_supported': True,
            'traffic': 'full-tunnel; no geographic, GitHub or ad-domain routing rules',
            'dns_transport': {'provider': 'AdGuard public filtering DNS', 'all_names': 'doh-direct',
                              'resolvers': [s['address'] for s in config['dns']['servers']],
                              'bootstrap_addresses': config['dns']['hosts'],
                              'independent_provider_fallback': False,
                              'plain_public_dns_fallback': False},
            'direct_domains': [], 'direct_ips': [], 'block_domains': [],
            'ad_blocking': 'AdGuard DNS filtering; no local domain lists',
            'probe': settings['probe'], 'geodata_required': False,
        },
        'config_utf8_bytes': len(serialized_config(config).encode()),
        'config_utf16_bytes': len(serialized_config(config).encode('utf-16-le')),
    }
    atomic_write(ROOT / 'subscription.json', subscription(config))
    atomic_write(ROOT / 'report.json', json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'selected': len(selected), 'protocols': report['selected_protocols'],
                      'technologies': len(report['technology_selection']['groups']),
                      'max_nodes_per_technology': limit,
                      'unknown_exit_retained': report['unknown_exit_retained'],
                      'upstream_order_preserved': True}), flush=True)


if __name__ == '__main__':
    main()
