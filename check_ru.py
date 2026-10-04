"""Check-Host TCP probes for mandatory Russian reachability and diagnostics."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
import math
from pathlib import Path
import re
import time
import urllib.parse
import urllib.request

BASE = 'https://check-host.net'


def get_json(path):
    req = urllib.request.Request(BASE + path, headers={'Accept': 'application/json', 'User-Agent': 'vpn-subscription-ru-diagnostics/1'})
    with urllib.request.urlopen(req, timeout=5) as response:
        raw = response.read(1_000_001)
    if len(raw) > 1_000_000:
        raise ValueError('oversized diagnostic response')
    return json.loads(raw)


def tcp_result(value):
    if not isinstance(value, list) or not value or not isinstance(value[0], dict):
        return {'status': 'unknown'}
    sample = value[0]
    seconds = sample.get('time')
    if isinstance(seconds, (int, float)) and not isinstance(seconds, bool) and math.isfinite(seconds) and seconds >= 0 and sample.get('address'):
        return {'status': 'reachable', 'tcp_connect_ms': round(seconds * 1000, 2), 'resolved_address': sample['address']}
    if sample.get('error'):
        return {'status': 'unreachable', 'error': str(sample['error'])[:160]}
    return {'status': 'unknown'}


def endpoint(host, port):
    if not isinstance(host, str) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError('invalid endpoint')
    try:
        address = ipaddress.ip_address(host)
        if not address.is_global:
            raise ValueError('nonpublic endpoint')
        return f'[{host}]:{port}' if address.version == 6 else f'{host}:{port}'
    except ValueError:
        if ':' in host or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', host) or '.' not in host:
            raise ValueError('invalid public host')
        # Do not reinterpret a rejected private literal as a DNS name.
        if re.fullmatch(r'[0-9.]+', host) or host.lower().endswith(('.localhost', '.local')):
            raise ValueError('nonpublic endpoint')
        return f'{host}:{port}'


def endpoints(config):
    found = {}
    for outbound in config['outbounds']:
        protocol = outbound.get('protocol')
        if protocol not in ('vless', 'vmess', 'trojan', 'shadowsocks'):
            continue
        settings = outbound['settings']
        server = (settings['vnext'] if protocol in ('vless', 'vmess') else settings['servers'])[0]
        target = endpoint(server['address'], server['port'])
        found.setdefault(target, []).append(outbound['tag'])
    return found


def measure(target, nodes, request=get_json, sleep=time.sleep, deadline=None):
    unknown = {name: {'status': 'unknown'} for name in nodes}
    result = {'endpoint': target, 'status': 'unknown', 'probes': unknown}
    deadline = min(deadline or float('inf'), time.monotonic() + 25)
    try:
        if time.monotonic() >= deadline:
            raise TimeoutError('diagnostic budget exhausted')
        query = urllib.parse.urlencode([('host', target), *[('node', name) for name in nodes]])
        start = request('/check-tcp?' + query)
        request_id = start.get('request_id', '')
        if start.get('ok') != 1 or not re.fullmatch(r'[A-Za-z0-9_-]+', request_id):
            raise ValueError('measurement not accepted')
        # Only accept probes both selected from the live RU inventory and
        # confirmed as Russian in the measurement response.
        accepted = {name for name, meta in start.get('nodes', {}).items() if name in nodes and isinstance(meta, list) and meta and meta[0] == 'ru'}
        if not accepted:
            raise ValueError('no confirmed Russian probes')
        for _ in range(8):
            if time.monotonic() >= deadline:
                break
            sleep(2)
            raw = request('/check-result/' + request_id)
            for name in accepted:
                result['probes'][name] = tcp_result(raw.get(name))
            if all(result['probes'][name]['status'] != 'unknown' for name in accepted):
                break
        states = [v['status'] for v in result['probes'].values()]
        result['status'] = 'reachable' if 'reachable' in states else ('unreachable' if states and all(s == 'unreachable' for s in states) else 'unknown')
        result['report_url'] = BASE + '/check-report/' + request_id
    except Exception:
        # The caller decides whether unknown results must stop publication.
        result['diagnostic_error'] = 'API unavailable, invalid response, or measurement incomplete'
    return result


def probe_targets(targets, request=get_json, measure_fn=measure):
    targets = list(dict.fromkeys(targets))
    try:
        inventory = request('/nodes/hosts')['nodes']
        nodes = {name: meta for name, meta in inventory.items() if meta.get('location', [''])[0] == 'ru'}
        nodes = dict(list(nodes.items())[:3])
    except Exception:
        nodes = {}
    if nodes:
        deadline = time.monotonic() + 90
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = dict(zip(targets, pool.map(lambda target: measure_fn(target, nodes, request, deadline=deadline), targets)))
    else:
        results = {}
    return nodes, results


def filter_candidates(candidates, request=get_json, measure_fn=measure):
    """Fail closed on missing measurements; never send VPN credentials."""
    group = endpoints({'outbounds': [{**node['outbound'], 'tag': str(i)}
        for i, node in enumerate(candidates)]})
    nodes, results = probe_targets(group, request, measure_fn)
    if not nodes or not group or any(results.get(target, {}).get('status') not in
        ('reachable', 'unreachable') for target in group):
        raise ValueError('Russian reachability check unavailable or incomplete; preserve published pool')
    accepted = {int(index) for target, indexes in group.items()
        if results[target]['status'] == 'reachable' for index in indexes}
    if not accepted:
        raise ValueError('No candidates reachable from Russian probes; preserve published pool')
    report = {'generated_at_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'service': BASE, 'measurement': 'TCP connection to entry host:port from Russian probes',
        'filters_pool': True, 'criterion': 'at least one confirmed RU probe succeeds',
        'vpn_handshake_checked': False, 'mobile_whitelist_checked': False, 'probes': nodes,
        'candidate_configs': len(candidates), 'accepted_configs': len(accepted),
        'results': [{**results[target], 'candidate_indices': indexes} for target, indexes in group.items()]}
    return [node for i, node in enumerate(candidates) if i in accepted], report


def run(config_paths, output_dir, limit=48, request=get_json):
    groups = {Path(p).stem: endpoints(json.loads(Path(p).read_bytes())) for p in config_paths}
    targets = list(dict.fromkeys(t for group in groups.values() for t in group))[:limit]
    nodes, results = probe_targets(targets, request)
    reports = {}
    for name, group in groups.items():
        report = {'generated_at_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'service': BASE,
                  'measurement': 'TCP connection to entry host:port from Russian probes', 'filters_pool': False,
                  'vpn_handshake_checked': False, 'mobile_whitelist_checked': False, 'probes': nodes,
                  'results': [{**results.get(target, {'endpoint': target, 'status': 'unknown', 'probes': {}, 'diagnostic_error': 'probe inventory unavailable or limit reached'}), 'outbound_tags': tags} for target, tags in group.items()]}
        path = Path(output_dir) / ('ru-reachability.json' if name == 'ru' else name + '-reachability.json')
        from generate import atomic_write
        atomic_write(path, json.dumps(report, ensure_ascii=False, indent=2) + '\n')
        reports[name] = {state: sum(r['status'] == state for r in report['results']) for state in ('reachable', 'unreachable', 'unknown')}
    return reports


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--configs', nargs='+', default=['ru.json', 'normal.json'])
    parser.add_argument('--output', type=Path, default=Path('.'))
    parser.add_argument('--limit', type=int, default=48)
    args = parser.parse_args()
    if not 1 <= args.limit <= 48:
        parser.error('limit must be between 1 and 48')
    print(json.dumps(run(args.configs, args.output, args.limit)))
