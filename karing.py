"""OpenCCK routing and upstream Karing advertising lists for INCY/Happ."""
import argparse
import concurrent.futures
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.request
from collections import Counter

from generate import atomic_write, serialized_config, xray_validate
from routing import domains
from geo_dat import geosite, geoip

ROOT = Path(__file__).resolve().parent
BASE = 'https://raw.githubusercontent.com/KaringX/karing-ruleset/sing/'
PUBLIC = 'https://raw.githubusercontent.com/RnRLover/rjsxrd-karing-subscription/refs/heads/main/'
PROXY_DNS = ['8.8.8.8', '8.8.4.4']
DIRECT_DNS = ['8.8.8.8', '8.8.4.4']
RESERVE_DNS = ['77.88.8.8', '77.88.8.1']
OPENCCK = [('cckproxy', 'iplist', 'proxy'), ('cckbeta', 'beta.iplist', 'proxy'),
           ('cckdirect', 'russia.iplist', 'direct')]


def load_opencck(cache=None):
    lists, sources = {}, []
    for tag, host, action in OPENCCK:
        rules = []
        for kind in ('domains', 'cidr4', 'cidr6'):
            url = f'https://{host}.opencck.org/?format=singbox&data={kind}'
            path = cache / 'opencck' / f'{host}-{kind}.json' if cache else None
            raw = path.read_bytes() if path and path.exists() else download(url, 30_000_000)
            obj = json.loads(raw)
            sites, ips = matchers(obj)
            if kind == 'domains' and (not sites or ips):
                raise ValueError('invalid OpenCCK domain export')
            if kind != 'domains':
                if sites or not ips:
                    raise ValueError('invalid OpenCCK IP export')
                for value in ips:
                    network = ipaddress.ip_network(value, strict=False)
                    if network.prefixlen == 0 or network.version != (4 if kind == 'cidr4' else 6):
                        raise ValueError('unsafe OpenCCK IP export')
            rules.extend(obj['rules'])
            sources.append({'reference': tag + ':' + kind, 'url': url,
                            'sha256': hashlib.sha256(raw).hexdigest()})
        lists[tag] = {'version': 1, 'rules': rules}
    return lists, sources


def download(url, limit=10_000_000):
    with urllib.request.urlopen(url, timeout=40) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('upstream rules exceed download budget')
    return data


def matchers(raw):
    """Our sources use OR-unions; reject logical/combined conditions."""
    sites, ips = [], []
    for rule in raw['rules']:
        if not isinstance(rule, dict):
            raise ValueError('invalid source rule')
        site = {key: value for key, value in rule.items() if key != 'ip_cidr'}
        if site:
            sites.extend(domains({'version': raw['version'], 'rules': [site]}))
        values = rule.get('ip_cidr', [])
        ips.extend([values] if isinstance(values, str) else values)
    if not sites and not ips:
        raise ValueError('empty Karing list')
    return list(dict.fromkeys(sites)), list(dict.fromkeys(ips))


def selected_groups(profile):
    """Reuse only the two upstream ad filters."""
    result = []
    for number, group in enumerate(profile['rules'], 1):
        if group['outbound'] not in ('block', 'direct', 'currentSelected'):
            raise ValueError('unknown Karing action')
        ad_filter = group['outbound'] == 'block' and any(ref in (
            'geosite:category-ads', 'acl:BanProgramAD', 'acl:BanADCompany') for ref in group['rule_set'])
        if ad_filter:
            result.append((number, group))
    if not result:
        raise ValueError('no requested Karing ad filters')
    return result


def assemble(profile, lists, old, opencck):
    """Three policy groups; separate domain/IP rules implement OR matching."""
    sites, ips, rules, groups = {}, {}, [], []
    ads = [lists[ref] for _, group in selected_groups(profile) for ref in group['rule_set']]
    specs = [('ads', 'Adblock + AdblockPlus', 'block', ads),
             ('cckproxy', 'OpenCCK main + beta', 'proxy', [opencck['cckproxy'], opencck['cckbeta']]),
             ('cckdirect', 'OpenCCK Russia', 'direct', [opencck['cckdirect']])]
    for tag, name, action, exports in specs:
        ds, cs = [], []
        for raw in exports:
            d, c = matchers(raw)
            ds.extend(d); cs.extend(c)
        suffixes = {v[7:] for v in ds if v.startswith('domain:')}
        # A suffix already includes its children. Remove redundant entries
        # only within the same action group, preserving routing semantics.
        def covered(value):
            if not value.startswith(('domain:', 'full:')):
                return False
            kind, host = value.split(':', 1)
            parts = host.split('.')
            start = 0 if kind == 'full' else 1
            return any('.'.join(parts[i:]) in suffixes for i in range(start, len(parts)))
        ds = sorted(set(v for v in ds if not covered(v)))
        cs = sorted({str(ipaddress.ip_network(v, strict=False)) for v in cs})
        if ds: sites[tag] = ds
        if cs: ips[tag] = cs
        target = {'balancerTag': 'auto'} if action == 'proxy' else {'outboundTag': action}
        if ds: rules.append({'type': 'field', 'ruleTag': tag + '-sites', 'domain': ['geosite:' + tag], **target})
        if cs: rules.append({'type': 'field', 'ruleTag': tag + '-ips', 'ip': ['geoip:' + tag], **target})
        groups.append({'tag': tag, 'name': name, 'action': action, 'enabled': True, 'sites': len(ds), 'cidrs': len(cs)})
    rules.append({'type': 'field', 'network': 'tcp,udp', 'balancerTag': 'auto'})
    config = copy.deepcopy(old)
    config['remarks'] = 'rjsxrd + OpenCCK + adblock'
    config['routing']['rules'] = rules
    config['routing']['domainStrategy'] = 'IPOnDemand'
    return config, sites, ips, groups


def automatic_config(config, label='Автовыбор'):
    variant = copy.deepcopy(config)
    proxies = [o for o in variant['outbounds'] if o.get('tag', '').startswith('pool-')]
    if not proxies:
        raise ValueError('no checked proxy servers for automatic pool')
    old_tag = proxies[0]['tag']
    proxies[0]['tag'] = label
    variant['remarks'] = label
    tags = [o['tag'] for o in proxies]
    for rule in variant['routing']['rules']:
        if rule.get('outboundTag') == old_tag:
            rule['outboundTag'] = label
    for balancer in variant['routing']['balancers']:
        balancer['selector'] = tags[:]
    for key in ('observatory', 'burstObservatory'):
        if key in variant:
            variant[key]['subjectSelector'] = tags[:]
    serialized_config(variant)
    return variant


def fit_client_pool(config, budget=240_000):
    """Leave room under the Android guard; trim the same tail in both profiles."""
    result = copy.deepcopy(config)
    while True:
        try:
            variants = subscription_variants(result)
            if max(len(serialized_config(v).encode('utf-16-le')) for v in variants) <= budget:
                return result, variants
        except ValueError as error:
            if 'publication size budget' not in str(error):
                raise
        proxies = [o for o in result['outbounds'] if o.get('tag', '').startswith('pool-')]
        if len(proxies) <= 2:
            raise ValueError('routing alone exceeds Android budget')
        result['outbounds'].remove(proxies[-1])


def with_fakedns(config, direct_dns=None):
    direct_dns = list(DIRECT_DNS if direct_dns is None else direct_dns)
    variant = copy.deepcopy(config)
    variant['fakedns'] = [{'ipPool': '198.18.0.0/15', 'poolSize': 4096}]
    # External DNS gets synthetic IPs. Xray's internal resolver excludes the
    # FakeDNS server when real IPs are needed for dialing and GeoIP matching.
    # Preserve route precedence for overlapping domain categories. FakeDNS
    # matches first for client queries and is excluded by Xray for real-IP lookup.
    servers = [{'address': 'fakedns', 'domains': ['regexp:.*']}]
    # Observatory must resolve its probe before the leastPing balancer is ready.
    # Resolve proxy entry names here too, so their lookup cannot depend on them.
    bootstrap_names = ['full:www.gstatic.com']
    for outbound in variant['outbounds']:
        settings = outbound.get('settings', {})
        for server in settings.get('vnext', []) + settings.get('servers', []):
            host = server.get('address', '')
            try:
                ipaddress.ip_address(host)
            except ValueError:
                if host:
                    bootstrap_names.append('full:' + host)
                    # Dial entry domains through the profile's built-in resolver,
                    # rather than silently using the operating system resolver.
                    outbound.setdefault('streamSettings', {}).setdefault('sockopt', {})['domainStrategy'] = 'UseIPv4'
    bootstrap_names = list(dict.fromkeys(bootstrap_names))
    servers.extend({'address': address, 'domains': bootstrap_names[:], 'skipFallback': True,
                    'tag': 'dns-bootstrap'} for address in direct_dns)
    for rule in variant['routing']['rules']:
        names = rule.get('domain', [])
        if not names:
            continue
        if rule.get('outboundTag') == 'direct':
            addresses, tag = direct_dns, 'dns-bootstrap'
        elif rule.get('balancerTag') == 'auto':
            addresses, tag = PROXY_DNS, 'dns-proxy'
        else:
            continue
        servers.extend({'address': address, 'domains': names[:], 'skipFallback': True, 'tag': tag} for address in addresses)
    servers.extend({'address': address, 'tag': 'dns-proxy'} for address in PROXY_DNS)
    variant['dns'] = {'tag': 'dns-bootstrap', 'queryStrategy': 'UseIPv4',
                      'servers': servers}
    for inbound in variant['inbounds']:
        sniffing = inbound.setdefault('sniffing', {})
        sniffing.update({'enabled': True, 'routeOnly': False})
        sniffing['destOverride'] = list(dict.fromkeys(['fakedns', *sniffing.get('destOverride', ['http', 'tls', 'quic'])]))
    variant['outbounds'].append({'tag': 'dns-out', 'protocol': 'dns'})
    variant['routing']['rules'][:0] = [
        {'type': 'field', 'inboundTag': ['dns-proxy'], 'balancerTag': 'auto'},
        {'type': 'field', 'inboundTag': ['dns-bootstrap'], 'outboundTag': 'direct'},
        {'type': 'field', 'inboundTag': [i['tag'] for i in variant['inbounds']], 'port': '53', 'network': 'tcp,udp', 'outboundTag': 'dns-out'},
    ]
    return variant


def client_routing_profile(config):
    """Use INCY's documented field names, keeping UI and full config consistent."""
    profile = {'Name': 'rjsxrd OpenCCK + Adblock', 'GlobalProxy': 'true',
        'DomainStrategy': 'IPOnDemand', 'LastUpdated': str(int(time.time())),
        'Geoipurl': PUBLIC + 'karing-geoip.dat', 'Geositeurl': PUBLIC + 'karing-geosite.dat',
        'DirectSites': [], 'DirectIp': [],
        'ProxySites': [], 'ProxyIp': [], 'BlockSites': [], 'BlockIp': [],
        'FakeDNS': 'true', 'RemoteDNSType': 'DoU',
        'RemoteDNSDomain': '', 'RemoteDNSIP': PROXY_DNS[0]}
    # Full configs own their DNS. A shared geodata profile must not dictate
    # one DomesticDNS value for different selectable full configs.
    for rule in config['routing']['rules']:
        prefix = 'Proxy' if 'balancerTag' in rule else ('Direct' if rule.get('outboundTag') == 'direct' else 'Block')
        profile[prefix + 'Sites'].extend(rule.get('domain', []))
        profile[prefix + 'Ip'].extend(rule.get('ip', []))
    for key in ('DirectSites', 'DirectIp', 'ProxySites', 'ProxyIp', 'BlockSites', 'BlockIp'):
        profile[key] = list(dict.fromkeys(profile[key]))
    return profile


def happ_config(config, sites, ips):
    """Self-contained full config: no custom client metadata or geo assets."""
    result = copy.deepcopy(config)
    dns_servers = [s for s in result.get('dns', {}).get('servers', []) if isinstance(s, dict)]
    for rule in result['routing']['rules'] + dns_servers:
        for key, prefix, categories in (('domain', 'geosite:', sites), ('domains', 'geosite:', sites), ('ip', 'geoip:', ips)):
            if key not in rule:
                continue
            expanded = []
            for value in rule[key]:
                if value.startswith(prefix):
                    tag = value[len(prefix):].lower()
                    if tag not in categories or not categories[tag]:
                        raise ValueError('missing inline category: ' + value)
                    expanded.extend(categories[tag])
                elif value.startswith(('geosite:', 'geoip:', 'ext:')):
                    raise ValueError('unresolved external matcher: ' + value)
                else:
                    expanded.append(value)
            rule[key] = list(dict.fromkeys(expanded))
    # Match panel-generated full configs: a real proxy is first, with service
    # outbounds after it. Explicit routing and balancer tags stay unchanged.
    proxies = [o for o in result['outbounds'] if o['protocol'] in ('vless', 'vmess', 'trojan', 'shadowsocks')]
    if not proxies:
        raise ValueError('Happ config has no representative proxy')
    result['outbounds'] = proxies + [o for o in result['outbounds'] if o not in proxies]
    return result


def happ_subscription(config):
    configs = config if isinstance(config, list) else [config]
    body = json.dumps(configs, ensure_ascii=False, separators=(',', ':')) + '\n'
    # Separate from INCY's Binder budget: never pass this file to INCY.
    if len(body.encode('utf-8')) > 30_000_000:
        raise ValueError('self-contained Happ subscription exceeds 30 MB')
    if not configs or len(json.loads(body)) != len(configs):
        raise ValueError('Happ subscription must contain complete full configs')
    return body


def incy_subscription(config):
    """Experimental transport: full JSON plus INCY body metadata.

    INCY documents stripping special lines, but does not explicitly document
    full JSON mixed with autorouting. Keep this separate until a real import
    confirms both fullConfigJson and geodata activation on the target client.
    """
    configs = config if isinstance(config, list) else [config]
    for item in configs:
        serialized_config(item)
    text = json.dumps(config, ensure_ascii=False, separators=(',', ':')) + '\n'
    body = text + '://autorouting/onadd/' + PUBLIC + 'karing-routing.json\n' + '#profile-update-interval: 1\n'
    if len(body.encode('utf-8')) > 2_000_000:
        raise ValueError('INCY subscription exceeds download size budget')
    return body


def subscription_variants(config):
    return [with_fakedns(automatic_config(config, 'Основной'), DIRECT_DNS),
            with_fakedns(automatic_config(config, 'Резерв'), RESERVE_DNS)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--xray', required=True)
    parser.add_argument('--singbox', required=True)
    parser.add_argument('--cache', type=Path)
    args = parser.parse_args()
    cache = args.cache
    def data(path):
        return (cache / path).read_bytes() if cache and (cache / path).exists() else download(BASE + path)
    profile_data = data('recommend/ru.json')
    profile = json.loads(profile_data)
    refs = list(dict.fromkeys(ref for _, group in selected_groups(profile) for ref in group['rule_set']))
    sources = []
    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)
        def load(ref):
            kind, name = ref.split(':', 1)
            path = f'ACL4SSR/{name}.srs' if kind == 'acl' else f'geo/{kind}/{name}.srs'
            # Local test cache can use upstream JSON exports when available.
            # Production always uses the exact compiled lists Karing consumes.
            if cache and not (cache / path).exists():
                alternatives = [path[:-4] + '.json']
                if kind == 'acl': alternatives.append(f'ACL4SSR/Ruleset/{name}.json')
                for candidate in alternatives:
                    cached = cache / candidate
                    if cached.exists():
                        raw = cached.read_bytes()
                        return ref, json.loads(raw), {'reference': ref, 'url': BASE + candidate, 'sha256': hashlib.sha256(raw).hexdigest()}
            raw = data(path)
            key = hashlib.sha256(ref.encode()).hexdigest()[:16]
            binary, target = temp / (key + '.srs'), temp / (key + '.json')
            binary.write_bytes(raw)
            subprocess.run([str(Path(args.singbox).resolve()), 'rule-set', 'decompile', '--output', str(target), str(binary)], check=True, capture_output=True, timeout=60)
            return ref, json.loads(target.read_bytes()), {'reference': ref, 'url': BASE + path, 'sha256': hashlib.sha256(raw).hexdigest()}
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            loaded = list(pool.map(load, refs))
        lists = {ref: obj for ref, obj, meta in loaded}
        sources.extend(meta for ref, obj, meta in loaded)
        old = json.loads((ROOT / 'ru.json').read_bytes())
        opencck, cck_sources = load_opencck(cache)
        sources.extend(cck_sources)
        config, sites, ips, groups = assemble(profile, lists, old, opencck)
        assets = Path(args.xray).resolve().parent
        # Retain original categories for other INCY profiles; protobuf repeated
        # entry streams can be concatenated without replacing original entries.
        geo_files = {'geosite.dat': (assets / 'geosite.dat').read_bytes() + geosite(sites), 'geoip.dat': (assets / 'geoip.dat').read_bytes() + geoip(ips)}
        for filename, content in geo_files.items():
            (temp / filename).write_bytes(content)
        text = serialized_config(config)
        config, variants = fit_client_pool(config)
        text = serialized_config(config)
        incy_body = incy_subscription(variants)
        # Validation needs these specific custom assets, never a global install.
        prior = os.environ.get('XRAY_LOCATION_ASSET')
        os.environ['XRAY_LOCATION_ASSET'] = str(temp)
        try:
            xray_validate(args.xray, config)
            for variant in variants:
                xray_validate(args.xray, variant)
        finally:
            if prior is None: os.environ.pop('XRAY_LOCATION_ASSET', None)
            else: os.environ['XRAY_LOCATION_ASSET'] = prior
        route_profile = client_routing_profile(config)
        happ_ips = ips
        happ_variants = [happ_config(v, sites, happ_ips) for v in variants]
        happ_body = happ_subscription(happ_variants)
        # A missing custom database must never break this independent variant.
        for variant in happ_variants:
            xray_validate(args.xray, variant)
        report = {'profile_url': BASE + 'recommend/ru.json', 'profile_sha256': hashlib.sha256(profile_data).hexdigest(), 'all_groups_enabled': False, 'selection': 'Adblock/AdblockPlus block; OpenCCK main/beta proxy; OpenCCK Russia direct; default proxy', 'groups': groups, 'sources': sources, 'xray_validated': True, 'config_utf16_bytes': len(text.encode('utf-16-le')), 'geofiles_sha256': {name: hashlib.sha256(content).hexdigest() for name, content in geo_files.items()}, 'requires_geodata_import': True, 'preserved_ru_direct': False, 'local_exceptions': False, 'generated_at_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
        report['variants'] = [{'name': v['remarks'], 'servers': sum(o['protocol'] in ('vless', 'shadowsocks', 'trojan', 'vmess') for o in v['outbounds']), 'config_utf16_bytes': len(serialized_config(v).encode('utf-16-le'))} for v in variants]
        report['fakedns'] = True
        report['same_main_reserve_pool'] = True
        report['dns_policy'] = {'Основной': DIRECT_DNS, 'Резерв': RESERVE_DNS,
                                'proxy': PROXY_DNS}
        report['happ_import_verified'] = False
        report['happ_self_contained'] = True
        report['happ_bytes'] = len(happ_body.encode('utf-8'))
        # Do not touch active ru.json. Publish complete new variant after checks.
        for filename, content in geo_files.items():
            out = ROOT / ('karing-' + filename)
            tmp = out.with_suffix('.tmp')
            tmp.write_bytes(content)
            tmp.replace(out)
            atomic_write(ROOT / ('karing-' + filename + '.sha256'), hashlib.sha256(content).hexdigest() + '\n')
        atomic_write(ROOT / 'ru-karing.json', text)
        atomic_write(ROOT / 'ru-karing-incy.txt', incy_body)
        atomic_write(ROOT / 'ru-karing-happ.txt', happ_body)
        atomic_write(ROOT / 'karing-routing.json', json.dumps(route_profile, ensure_ascii=False, indent=2) + '\n')
        # Keep the source pool, raw links and report consistent after size trimming.
        retained = {o['tag'] for o in config['outbounds']}
        old['outbounds'] = [o for o in old['outbounds'] if o['tag'] in retained]
        proxies = [o for o in old['outbounds'] if o.get('tag', '').startswith('pool-')]
        from pool_selection import node_key
        from generate import parse_node
        keys = {node_key({'outbound': o}) for o in proxies}
        links = []
        for link in (ROOT / 'servers.txt').read_text(encoding='utf-8').splitlines():
            node = parse_node(link)
            if node is not None and node_key(node) in keys:
                links.append(link)
        atomic_write(ROOT / 'ru.json', serialized_config(old))
        atomic_write(ROOT / 'servers.txt', '\n'.join(links) + '\n')
        source_report = json.loads((ROOT / 'report.json').read_bytes())
        before_limit = source_report['selected']
        source_report['selected_before_size_limit'] = before_limit
        source_report['selected'] = len(proxies)
        source_report['selected_protocols'] = dict(Counter(o['protocol'] for o in proxies))
        source_report['config_utf16_bytes'] = len(serialized_config(old).encode('utf-16-le'))
        source_report['config_utf8_bytes'] = len(serialized_config(old).encode('utf-8'))
        source_report['client_size_trimmed'] = before_limit > len(proxies)
        atomic_write(ROOT / 'report.json', json.dumps(source_report, ensure_ascii=False, indent=2) + '\n')
        atomic_write(ROOT / 'karing-report.json', json.dumps(report, ensure_ascii=False, indent=2) + '\n')
        print(json.dumps({'groups': len(groups), 'config_bytes': len(text.encode()), 'geofiles_bytes': {name: len(content) for name, content in geo_files.items()}, 'xray_validated': True}))


if __name__ == '__main__':
    main()
