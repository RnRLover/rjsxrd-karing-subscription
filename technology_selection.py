"""Device-side leastPing between technologies and inside each technology."""
from collections import defaultdict

PROXY_PROTOCOLS = ('vless', 'vmess', 'trojan', 'shadowsocks')


def technology(outbound):
    stream = outbound.get('streamSettings', {})
    network = stream.get('network', stream.get('method', 'tcp')).lower()
    network = {'raw': 'tcp', 'websocket': 'ws'}.get(network, network)
    return (outbound['protocol'], network, stream.get('security', 'none').lower())


def groups(proxies):
    members = defaultdict(list)
    for outbound in proxies:
        members[technology(outbound)].append(outbound['tag'])
    result = []
    for key, tags in sorted(members.items()):
        # Indices are identifiers, not priorities. leastPing ranks groups on
        # the device; their order in JSON never fixes a preferred technology.
        suffix = f'{len(result) + 1:02d}'
        result.append({'protocol': key[0], 'transport': key[1], 'security': key[2],
                       'servers': tags, 'balancer': 'technology-' + suffix,
                       'outbound': 'technology-out-' + suffix,
                       'inbound': 'technology-in-' + suffix})
    return result


def balancing(proxies):
    technologies = groups(proxies)
    if not technologies:
        raise ValueError('A checked proxy pool is required')
    routes = [g['outbound'] for g in technologies]
    return {
        'outbounds': [{'tag': g['outbound'], 'protocol': 'loopback',
                       'settings': {'inboundTag': g['inbound']}} for g in technologies],
        'rules': [{'type': 'field', 'inboundTag': [g['inbound']],
                   'balancerTag': g['balancer']} for g in technologies],
        'balancers': [
            {'tag': 'auto', 'selector': routes, 'fallbackTag': proxies[0]['tag'],
             'strategy': {'type': 'leastPing'}},
            *[{'tag': g['balancer'], 'selector': g['servers'], 'fallbackTag': 'block',
               'strategy': {'type': 'leastPing'}} for g in technologies],
        ],
        # A group probe traverses its fastest observed member. This measures
        # the actual group path rather than reusing GitHub runner latency.
        'subjects': [o['tag'] for o in proxies] + routes,
    }


def selection_report(config):
    proxies = [o for o in config['outbounds'] if o['protocol'] in PROXY_PROTOCOLS]
    return {'strategy': 'two-level-leastPing',
            'ranking_vantage': 'client device',
            'group_by': ['protocol', 'transport', 'security'],
            'group_score': 'live HTTPing through the fastest observed member',
            'priority_order': 'dynamic_on_device',
            'initial_fallback': proxies[0]['tag'],
            'probe_subjects': len(config['burstObservatory']['subjectSelector']),
            'groups': groups(proxies)}
