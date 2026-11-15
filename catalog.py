"""Build a fresh, bounded INCY catalog from upstream country/technology labels."""
from collections import Counter, defaultdict
from itertools import zip_longest
import re

from incy import build, serialized_config

FLAG = re.compile('[\U0001f1e6-\U0001f1ff]{2}')
EXIT_CODE = re.compile(r'\b(?:OUT|EXIT)\s*[:=]\s*([A-Z]{2})\b', re.I)
REPEATED_CODE = re.compile(r'\[(?:\d+\s*ms\s+)?([A-Z]{2})\s+\1(?:\s|\])')


def country_key(node):
    countries = {_label_country(label) for label in node.get('labels', [node.get('label', '')])}
    countries.discard(None)
    return next(iter(countries)) if len(countries) == 1 else None


def _label_country(label):
    """Use source metadata, never entry-IP geolocation or an invented country."""
    exits = {code.upper() for code in EXIT_CODE.findall(label)}
    if exits:
        return next(iter(exits)) if len(exits) == 1 else None
    codes = {''.join(chr(ord(c) - 0x1f1e6 + ord('A')) for c in flag)
             for flag in FLAG.findall(label)}
    codes -= {'EU', 'UN'}  # Region/organization flags do not identify a country.
    if len(codes) == 1:
        return next(iter(codes))
    if len(codes) > 1:
        # Multi-hop/anycast labels do not establish one exit country.
        return None
    codes = set(REPEATED_CODE.findall(label))
    return next(iter(codes)) if len(codes) == 1 else None


def technology_key(node):
    outbound = node['outbound']
    stream = outbound.get('streamSettings', {})
    transport = stream.get('network', 'tcp').lower()
    transport = {'raw': 'tcp', 'websocket': 'ws', 'splithttp': 'xhttp'}.get(transport, transport)
    return (outbound['protocol'], transport, stream.get('security', 'none').lower())


def technology_name(key):
    protocol, transport, security = key
    if protocol == 'hysteria' and transport == 'hysteria':
        return 'Hysteria2'
    names = {'grpc': 'gRPC', 'ws': 'WebSocket', 'httpupgrade': 'HTTPUpgrade',
             'reality': 'Reality', 'none': 'без TLS'}
    return ' · '.join(names.get(part, part.upper()) for part in key)


def country_name(code):
    if code is None:
        return '🌐 Страна не указана'
    flag = ''.join(chr(0x1f1e6 + ord(c) - ord('A')) for c in code)
    return flag + ' ' + code


def positive_limit(options, name):
    value = options[name]
    if type(value) is not int or value < 1:
        raise ValueError(name + ' must be a positive integer')
    return value


def rank(node):
    quality = node.get('quality', {}).get('https', {})
    delay = quality.get('median_ms')
    return (-node.get('allowlist', {}).get('priority', 0),
            -quality.get('success_rate', 1), delay if delay is not None else float('inf'),
            quality.get('jitter_ms') or 0, node.get('source_order', 0))


def build_catalog(nodes, options, probe=None):
    """Every admitted node appears once in country/technology profiles.

    Rank within country/technology mini-pools, then select their leaders.
    Allowlist evidence wins within the admitted quality tier. Technology
    diversity and shared exits bound the compact global selection.
    """
    if not nodes:
        raise ValueError('empty catalog; keep published subscription')
    auto_limit = positive_limit(options, 'auto_max_nodes')
    profile_limit = positive_limit(options, 'max_nodes_per_profile')
    groups = defaultdict(list)
    for index, node in enumerate(nodes):
        groups[(country_key(node), technology_key(node))].append(index)
    configs, profiles = [], []
    for (country, technology), indices in sorted(
            groups.items(), key=lambda item: (item[0][0] is None, item[0][0] or '', item[0][1])):
        indices.sort(key=lambda index: rank(nodes[index]))
        parts = (len(indices) + profile_limit - 1) // profile_limit
        for part, start in enumerate(range(0, len(indices), profile_limit), 1):
            members = indices[start:start + profile_limit]
            title = country_name(country) + ' · ' + technology_name(technology)
            if parts > 1:
                title += f' · {part}'
            configs.append(build([nodes[i] for i in members], probe, remarks=title,
                                 balancer_settings={'baselines': ['400ms', '800ms'],
                                                    'expected': 4, 'maxRTT': '1500ms',
                                                    'tolerance': .2}))
            profiles.append({'kind': 'country-technology', 'country': country,
                             'technology': list(technology), 'part': part,
                             'node_indices': members})
    # Select from completed mini-pools, including every partition of a large group.
    leaders = [profile['node_indices'][0] for profile in profiles]
    leaders.sort(key=lambda index: (rank(nodes[index]), index))
    priority_groups = defaultdict(lambda: defaultdict(list))
    for index in leaders:
        priority_groups[nodes[index].get('allowlist', {}).get('priority', 0)][technology_key(nodes[index])].append(index)
    leaders = [index for priority in sorted(priority_groups, reverse=True)
               for row in zip_longest(*priority_groups[priority].values())
               for index in sorted((i for i in row if i is not None), key=lambda i: (rank(nodes[i]), i))]
    auto_indices, risks, risk_technologies = [], Counter(), set()
    exit_limit = options.get('auto_max_per_exit', 2)
    if type(exit_limit) is not int or exit_limit < 1:
        raise ValueError('auto_max_per_exit must be a positive integer')
    for index in leaders:
        node = nodes[index]
        risk = node.get('exit_ip') or node.get('host') or str(index)
        pair = (risk, technology_key(node))
        if risks[risk] >= exit_limit or pair in risk_technologies:
            continue
        auto_indices.append(index)
        risks[risk] += 1
        risk_technologies.add(pair)
        if len(auto_indices) == auto_limit:
            break
    auto_indices.sort(key=lambda index: (rank(nodes[index]), index))
    configs.insert(0, build([nodes[i] for i in auto_indices], probe, remarks='⚡ Автовыбор'))
    profiles.insert(0, {'kind': 'auto', 'country': None, 'technology': None,
                        'part': 1, 'node_indices': auto_indices})
    for index, (config, profile) in enumerate(zip(configs, profiles)):
        profile.update(index=index, name=config['remarks'], nodes=len(profile['node_indices']),
                       config_utf8_bytes=len(serialized_config(config).encode()))
    countries = Counter(country_key(node) for node in nodes)
    return configs, {
        'group_by': ['upstream_country_label', 'protocol', 'transport', 'security'],
        'country_source': 'explicit OUT/EXIT code, unique flag, or repeated source country code; '
                          'ambiguous/missing labels retained as unknown; not verified geolocation',
        'countries': sorted(code for code in countries if code is not None),
        'unknown_country_nodes': countries[None],
        'technologies': [list(key) for key in sorted({technology_key(n) for n in nodes})],
        'unique_nodes': len(nodes), 'auto_nodes': len(auto_indices),
        'auto_max_nodes': auto_limit, 'max_nodes_per_profile': profile_limit,
        'representatives_from_completed_pools': True,
        'ordering': 'allowlist candidates, current success rate, median response time, jitter, source tie',
        'catalog_nodes_omitted': 0, 'profiles': profiles,
    }
