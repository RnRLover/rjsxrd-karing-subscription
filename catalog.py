"""Group admitted nodes by country, ranked by current success rate and upstream ties."""
from collections import Counter
import re

import incy
from incy import ConfigSizeError, build, serialized_config

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


def rank(node, source_position):
    quality = node.get('quality', {}).get('https', {})
    return (-quality.get('success_rate', 1), source_position)


def country_profiles(nodes, indices, country, probe):
    """Keep a country whole unless its full configuration exceeds the byte budget."""
    title = country_name(country)
    def make(members, name):
        return build([nodes[i] for i in members], probe, remarks=name,
                     balancer_settings={'baselines': ['400ms', '800ms'], 'expected': 4,
                                        'maxRTT': '1500ms', 'tolerance': .2})
    try:
        return [(make(indices, title), indices)]
    except ConfigSizeError:
        pass
    # Reserve enough title space for every possible part number. Only a size
    # failure may trigger partitioning; other build errors preserve publication.
    reserved_title = title + f' · {len(indices)}'
    parts, start = [], 0
    while start < len(indices):
        low, high, best = 1, len(indices) - start, None
        while low <= high:
            count = (low + high) // 2
            members = indices[start:start + count]
            try:
                config = make(members, reserved_title)
            except ConfigSizeError:
                high = count - 1
            else:
                best = (config, members)
                low = count + 1
        if best is None:
            raise ConfigSizeError('one country node exceeds the full configuration budget')
        parts.append(best)
        start += len(best[1])
    for part, (config, _) in enumerate(parts, 1):
        config['remarks'] = title + f' · {part}'
        serialized_config(config)
    return parts


def build_catalog(nodes, options, probe=None):
    """Every admitted node appears once in a country pool with mixed transports.

    Rank by current success rate, then upstream order. Ignore latency, jitter and allowlist evidence.
    Countries follow their best node; auto takes that first representative.
    """
    if not nodes:
        raise ValueError('empty catalog; keep published subscription')
    auto_limit = positive_limit(options, 'auto_max_nodes')
    positions = {}
    for index, node in enumerate(nodes):
        order = node.get('source_order', index)
        if type(order) is not int or order < 0:
            raise ValueError('source_order must be a non-negative integer')
        positions[index] = order + 1
    ordered = sorted(range(len(nodes)), key=lambda index: (positions[index], index))
    groups = {}
    for index in ordered:
        groups.setdefault(country_key(nodes[index]), []).append(index)
    for indices in groups.values():
        indices.sort(key=lambda index: (rank(nodes[index], positions[index]), index))
    groups = dict(sorted(groups.items(), key=lambda item:
                         (rank(nodes[item[1][0]], positions[item[1][0]]), item[1][0])))
    configs, profiles = [], []
    for country, indices in groups.items():
        parts = country_profiles(nodes, indices, country, probe)
        for part, (config, members) in enumerate(parts, 1):
            configs.append(config)
            profiles.append({'kind': 'country', 'country': country, 'technology': None,
                             'technologies': [list(key) for key in dict.fromkeys(technology_key(nodes[i]) for i in members)],
                             'part': part, 'parts': len(parts), 'node_indices': members,
                             'country_leader_source_position': positions[indices[0]]})
    # A split country still has just one representative in the global auto pool.
    leaders = [indices[0] for indices in groups.values()]
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
    configs.insert(0, build([nodes[i] for i in auto_indices], probe, remarks='⚡ Автовыбор'))
    profiles.insert(0, {'kind': 'auto', 'country': None, 'technology': None,
                        'part': 1, 'parts': 1, 'node_indices': auto_indices})
    for index, (config, profile) in enumerate(zip(configs, profiles)):
        profile.update(index=index, name=config['remarks'], nodes=len(profile['node_indices']),
                       config_utf8_bytes=len(serialized_config(config).encode()),
                       source_positions=[positions[i] for i in profile['node_indices']],
                       first_source_position=positions[profile['node_indices'][0]])
    return configs, {
        'group_by': ['upstream_country_label'],
        'country_source': 'explicit OUT/EXIT code, unique flag, or repeated source country code; '
                          'ambiguous/missing labels retained as unknown; not verified geolocation',
        'countries': [code for code in groups if code is not None],
        'unknown_country_nodes': len(groups.get(None, [])),
        'technologies': [list(key) for key in dict.fromkeys(technology_key(nodes[i]) for i in ordered)],
        'unique_nodes': len(nodes), 'auto_nodes': len(auto_indices),
        'auto_max_nodes': auto_limit, 'max_nodes_per_profile': None,
        'max_config_utf16_bytes': incy.MAX_CONFIG_UTF16,
        'country_partitioning': 'only when the full country exceeds the configuration byte budget',
        'representatives_from_completed_pools': True,
        'ordering': 'current HTTPS success rate, upstream tie; '
                    'countries by their best node',
        'auto_selection': 'one best representative per country in country priority order, with shared-exit safeguards',
        'catalog_nodes_omitted': 0, 'profiles': profiles,
    }
