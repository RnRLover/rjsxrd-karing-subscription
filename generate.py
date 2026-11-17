"""Publish a country catalog with allowlist and current-quality priority."""
import argparse
from collections import Counter
import concurrent.futures
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

from incy import (ROOT, PROXY_PROTOCOLS, BLOCK_DOMAINS, PROXY_DOMAINS, DIRECT_DOMAINS, DIRECT_IPS,
                  GITHUB_DIRECT_DOMAINS,
                  atomic_write, proxy_outbound, vision_blocks_quic,
                  serialized_config, subscription, xray_validate)
from ip_reputation import CACHE_KEY, load_feed, assess_nodes, rate_ip, reputation_report
from pool_quality import PROBE_BATCH_SIZE, ProbeUnavailable, baseline, eligible_nodes, probe_nodes
from rjsxrd_parser import parse_url
from rjsxrd_helpers import query_parameters
from catalog import build_catalog


def fetch(url, limit=64_000_000):
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
    nodes, seen, counts = [], {}, Counter()
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
        # Compare what Xray will actually receive, after common client options.
        node['outbound'] = proxy_outbound(node, 'candidate')
        node['labels'] = [node['label']]
        node['source_order'] = counts['source_nodes'] - 1
        key = json.dumps(node['outbound'], sort_keys=True, separators=(',', ':'))
        if key in seen:
            counts['duplicate'] += 1
            previous = nodes[seen[key]]
            if node['label'] not in previous['labels']:
                previous['labels'].append(node['label'])
            continue
        seen[key] = len(nodes)
        nodes.append(node)
    return nodes, counts


def compatible_nodes(nodes, xray, counts):
    """Validate bounded batches; bisect a rejected batch to isolate bad nodes."""
    def check(batch):
        try:
            xray_validate(xray, {'outbounds': [dict(node['outbound'], tag=f'check-{i}')
                                                for i, node in enumerate(batch)]})
            return batch
        except ValueError:
            if len(batch) == 1:
                return []
            middle = len(batch) // 2
            return check(batch[:middle]) + check(batch[middle:])
    batches = [nodes[start:start + PROBE_BATCH_SIZE] for start in range(0, len(nodes), PROBE_BATCH_SIZE)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        result = [node for batch in executor.map(check, batches) for node in batch]
    counts['core_incompatible'] += len(nodes) - len(result)
    return result


def entry_ips(host, timeout=3):
    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        try:
            # getaddrinfo has no cancellable per-call deadline. Isolate DNS so
            # thousands of unresponsive names cannot hold the whole executor.
            code = ('import json,socket,sys;print(json.dumps(sorted({i[4][0] for i in '
                    'socket.getaddrinfo(sys.argv[1],None,type=socket.SOCK_STREAM)})))')
            result = subprocess.run([sys.executable, '-c', code, host], capture_output=True,
                                    text=True, timeout=timeout, check=True)
            return json.loads(result.stdout)
        except (OSError, ValueError, subprocess.SubprocessError):
            return []


def exclude_listed(nodes):
    """Preserve upstream order, all unknowns and all countries."""
    return [node for node in nodes if node.get('reputation', {}).get('status') != 'listed'
            and not any(record['status'] == 'listed' for record in node.get('entry_reputation', []))]


def probe_exit(opener, timeout=4):
    # This single small request discovers the public exit for the blacklist.
    # Its latency and success are never membership or ranking criteria.
    with opener.open('https://api64.ipify.org?format=json', timeout=timeout) as response:
        ip = str(ipaddress.ip_address(json.loads(response.read(1000))['ip']))
        if not ipaddress.ip_address(ip).is_global:
            raise ValueError('non-public exit answer')
        return ip


def probe_exits(nodes, xray, workers=24, timeout=4):
    results = []
    for start in range(0, len(nodes), PROBE_BATCH_SIZE):
        results.extend(_probe_exit_batch(nodes[start:start + PROBE_BATCH_SIZE],
                                         xray, workers, timeout))
    return results


def _probe_exit_batch(nodes, xray, workers=24, timeout=4):
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


def publish_checked(checked, rated, settings, counts, source_sha, feed, feed_source,
                    baseline_evidence, xray, build_metadata=None):
    eligible = eligible_nodes(checked)
    counts['https_failed'] = sum(not node['quality']['https']['ok'] for node in checked)
    counts['quic_failed_after_https'] = sum(node['quality']['https']['ok'] and
                                           node['quality']['quic'].get('required', True) and
                                           not node['quality']['quic']['ok'] for node in checked)
    counts['vision_quic_intentionally_disabled'] = sum(
        node['quality']['quic'].get('required') is False for node in checked)
    if not eligible:
        print('::notice::No candidate passed the published transport policy; preserve published pool', flush=True)
        return False
    selected = eligible
    configs, catalog = build_catalog(selected, settings['catalog'], settings['probe'])
    # Every profile is self-contained and checked, not only the default auto.
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(lambda config: xray_validate(xray, config), configs))
    body = subscription(configs)
    config = configs[0]
    report = {
        'generated_at_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'source': settings['subscription_url'], 'source_sha256': source_sha,
        'counts': dict(counts), 'selected': len(selected), 'xray_validated': True,
        'selected_protocols': dict(Counter(node['outbound']['protocol'] for node in selected)),
        'pool_selection': 'all admitted unique connections grouped by country; '
                          'allowlist candidates and current HTTPS quality first, upstream order for ties; '
                          'countries follow their best node; auto takes one country leader with exit diversity',
        'catalog': catalog,
        'history_used': False, 'github_latency_ranking': True, 'country_filter': False,
        'tcp_udp_quality_gate': False, 'https_quality_gate': True,
        'quic_quality_gate': 'required except ordinary Vision intentionally blocks UDP/443',
        'file_transfer_check': False,
        'quality_checks': {
            'vantage': 'GitHub Actions runner; not a measurement from the client network',
            'https': 'TLS-verified HEAD over TCP through the actual outbound',
            'quic': 'TLS-verified HTTP/3 HEAD over SOCKS5 UDP ASSOCIATE; no TCP fallback; '
                    'ordinary Vision is explicitly skipped, not counted as a successful QUIC test',
            'settings': settings['quality'], 'direct_baseline': baseline_evidence,
            'candidates_checked': len(checked), 'passed_policy': len(eligible),
            'passed_both': sum(node['quality']['https']['ok'] and node['quality']['quic']['ok']
                               for node in checked),
            'history_used': False, 'latency_ranking': True,
            'selected': [{'node_index': index, **node['quality']}
                         for index, node in enumerate(selected)],
        },
        'pool_limit': {'catalog_per_country': None, **settings['catalog']},
        'allowlist': {'candidate_nodes': sum(n.get('allowlist', {}).get('priority', 0) > 0 for n in selected),
                      'explicit_label_nodes': sum(n.get('allowlist', {}).get('explicit_label', False) for n in selected),
                      'restricted_network_verified': False, 'used_for_ordering': True,
                      'evidence': [{'node_index': i, **n.get('allowlist', {})} for i, n in enumerate(selected)]},
        'build': build_metadata or {},
        'unknown_exit_retained': sum(node.get('exit_ip') is None for node in selected),
        'exit_discovery_errors': dict(Counter(node['exit_discovery_error'] for node in selected
                                              if node.get('exit_discovery_error'))),
        'ip_reputation': reputation_report(rated, selected, feed, feed_source),
        'subscription_policy': {
            'clients': ['INCY'], 'format': 'full-xray-json-array-with-body-metadata',
            'native_routing_profile': False,
            'dns_query_strategy': 'UseIPv4', 'ipv6_supported': False,
            'traffic': 'priority GitHub direct rule, then reference domain/IP/protocol rules; '
                       'AsIs; independent leastLoad per profile',
            'dns_transport': {'provider': 'Yandex DoH, Cloudflare DoH and Cloudflare UDP fallback',
                              'all_names': 'Yandex is also a fallback for names outside its domain categories',
                              'route': 'reference routing; Yandex IP direct, Cloudflare IPs use the pool',
                              'resolvers': [s['address'] for s in config['dns']['servers']],
                              'bootstrap_addresses': config['dns'].get('hosts', {}),
                              'independent_provider_fallback': True,
                              'plain_public_dns_fallback': True},
            'direct_domains': list(GITHUB_DIRECT_DOMAINS + DIRECT_DOMAINS), 'direct_ips': list(DIRECT_IPS),
            'github_direct_domains': list(GITHUB_DIRECT_DOMAINS),
            'direct_protocols': ['bittorrent'], 'proxy_domains': list(PROXY_DOMAINS),
            'block_domains': list(BLOCK_DOMAINS),
            'ad_blocking': 'reference win-spy/category-ads geosite rules; no filtering DNS provider',
            'probe': settings['probe'], 'geodata_required': True,
            'routing_domain_strategy': 'AsIs',
            'balancer': config['routing']['balancers'][0],
            'vision_udp443': 'ordinary Vision intercepts UDP/443 as in the reference',
            'reference_adaptations': ['own upstream connection credentials, endpoints and transport paths',
                                     'GitHub category, subdomains and download hosts go direct before other rules',
                                     'mixed-technology country pools; allowlist and current quality priority; '
                                     'upstream ties; global auto from the best server of each completed country',
                                     'global auto expected 1 and costs 1/2; grouped pools expected 4 '
                                     'with reference baselines and equal costs; first ranked node fallback',
                                     'preserve each upstream XHTTP mode instead of forcing stream-up'],
            'geodata_sha256': {name: hashlib.sha256((ROOT / '.runtime' / name).read_bytes()).hexdigest()
                               for name in ('geoip.dat', 'geosite.dat')},
            'client_geodata_verified': False,
        },
        'config_utf8_bytes': len(serialized_config(config).encode()),
        'config_utf16_bytes': len(serialized_config(config).encode('utf-16-le')),
        'subscription_utf8_bytes': len(body.encode()),
    }
    atomic_write(ROOT / 'subscription.json', body)
    atomic_write(ROOT / 'report.json', json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'selected': len(selected), 'protocols': report['selected_protocols'],
                      'countries': len(catalog['countries']), 'technologies': len(catalog['technologies']),
                      'profiles': len(configs), 'auto_nodes': catalog['auto_nodes'],
                      'unknown_exit_retained': report['unknown_exit_retained'],
                      'source_order_used_for_ties': True}), flush=True)
    return True


def main():
    from pipeline import prepare, probe_shard, assemble, run_all
    parser = argparse.ArgumentParser()
    parser.add_argument('--xray', required=True)
    parser.add_argument('--stage', choices=['all', 'prepare', 'probe', 'assemble'], default='all')
    parser.add_argument('--work', type=Path, default=ROOT / '.runtime' / 'build')
    parser.add_argument('--shard', type=int, default=0)
    args = parser.parse_args()
    if args.stage == 'prepare':
        result = prepare(args.work, args.xray)
        if output := os.environ.get('GITHUB_OUTPUT'):
            with open(output, 'a') as handle:
                handle.write('matrix=' + json.dumps(result['matrix'], separators=(',', ':')) + '\n')
        return result['ready']
    if args.stage == 'probe':
        probe_shard(args.work, args.shard, args.xray)
        return True
    if args.stage == 'assemble':
        return assemble(args.work, args.xray)
    return run_all(args.work, args.xray)


if __name__ == '__main__':
    ready = main()
    if output := os.environ.get('GITHUB_OUTPUT'):
        with open(output, 'a', encoding='utf-8') as handle:
            handle.write('ready=' + str(ready).lower() + '\n')
