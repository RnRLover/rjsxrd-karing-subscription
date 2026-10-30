"""Exclude listed exits, then fill a stable and diverse automatic pool."""
import hashlib
import ipaddress
import json
import socket
from collections import Counter


def node_key(node):
    outbound = dict(node['outbound'])
    outbound.pop('tag', None)
    return hashlib.sha256(json.dumps(outbound, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def endpoint_network(host):
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
        ip = ipaddress.ip_address(addresses[0])
        return str(ipaddress.ip_network(f'{ip}/{24 if ip.version == 4 else 48}', strict=False))
    except (OSError, ValueError, IndexError):
        return 'unresolved:' + host.lower()


def transport(node):
    ob = node['outbound']
    stream = ob.get('streamSettings', {})
    return (ob['protocol'], stream.get('network', 'tcp'), stream.get('security', 'none'))


def select_pool(nodes, limit, previous=(), network_lookup=endpoint_network, require_quality=False):
    """Quality-gated production selection with strict infrastructure limits.

    Legacy callers can inspect diversity without quality evidence. Publication
    explicitly enables require_quality; there is no unchecked fill fallback.
    """
    from quality_checks import quality_admitted, quality_priority
    if require_quality:
        nodes = [n for n in nodes if quality_admitted(n)]
        limit = min(limit, 40)
    unique = {node_key(n): n for n in nodes
              if n.get('reputation', {}).get('status') != 'listed'}
    networks = {host: network_lookup(host) for host in {n['host'] for n in unique.values()}}
    ranks = {key: index for index, key in enumerate(previous)}
    previous = set(ranks)
    exit_count, net_count, host_count, type_count = Counter(), Counter(), Counter(), Counter()
    result = []
    established = sum(not n.get('quality_history', {}).get('provisional', True) for n in unique.values())
    provisional_limit = 8 if established >= 10 else limit
    provisional_count = 0
    while unique and len(result) < limit:
        choices = unique
        if require_quality:
            choices = {k: n for k, n in unique.items()
                       if exit_count[n.get('exit_ip', n['host'])] < 2
                       and net_count[networks[n['host']]] < 4 and host_count[n['host']] < 2
                       and (not n['quality_history']['provisional'] or provisional_count < provisional_limit)}
        if not choices: break
        key, node = min(choices.items(), key=lambda item: (
            quality_priority(item[1]) if require_quality else (),
            exit_count[item[1].get('exit_ip', item[1]['host'])],
            net_count[networks[item[1]['host']]], host_count[item[1]['host']],
            type_count[transport(item[1])], item[0] not in previous, ranks.get(item[0], len(ranks)), item[0]))
        result.append(node)
        if require_quality and node['quality_history']['provisional']: provisional_count += 1
        del unique[key]
        exit_count[node.get('exit_ip', node['host'])] += 1
        net_count[networks[node['host']]] += 1
        host_count[node['host']] += 1
        type_count[transport(node)] += 1
    return result


def recent_exit(node, cache, now, ranges, ttl=86400):
    entry = cache.get(node_key(node), {})
    try:
        ip = ipaddress.ip_address(entry['exit_ip'])
        if 0 <= now - entry['verified_at'] < ttl and ip.is_global and not ranges.contains(ip):
            return {**node, 'exit_ip': str(ip)}
    except (KeyError, TypeError, ValueError):
        pass
    return None
