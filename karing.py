"""Karing's ordered Russian profile + our existing RU-direct policy.

Publish a separate full config: existing clients need to install the associated
geofiles once before switching. The current ru.json remains usable throughout.
"""
import argparse
import concurrent.futures
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.request

from generate import atomic_write, serialized_config, xray_validate
from routing import domains, LOCAL_IPS
from geo_dat import geosite, geoip, geoip_cidrs

ROOT = Path(__file__).resolve().parent
BASE = 'https://raw.githubusercontent.com/KaringX/karing-ruleset/sing/'
PUBLIC = 'https://raw.githubusercontent.com/RnRLover/rjsxrd-karing-subscription/refs/heads/main/'


def download(url):
    with urllib.request.urlopen(url, timeout=40) as response:
        data = response.read(10_000_001)
    if len(data) > 10_000_000:
        raise ValueError('upstream rules exceed 10 MB')
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
    """Reuse upstream direct routes and two ad filters, in original order."""
    result = []
    for number, group in enumerate(profile['rules'], 1):
        if group['outbound'] not in ('block', 'direct', 'currentSelected'):
            raise ValueError('unknown Karing action')
        ad_filter = group['outbound'] == 'block' and any(ref in (
            'geosite:category-ads', 'acl:BanProgramAD', 'acl:BanADCompany') for ref in group['rule_set'])
        if group['outbound'] == 'direct' or ad_filter:
            result.append((number, group))
    if not result:
        raise ValueError('no requested Karing routes')
    return result


def assemble(profile, lists, old):
    site_groups, ip_groups, routing_rules, groups = {}, {}, [], []
    routing_rules.append({'type': 'field', 'ip': LOCAL_IPS, 'outboundTag': 'direct'})
    for number, group in selected_groups(profile):
        tag = f'kg{number:02d}'
        sites, ips = [], []
        for ref in group['rule_set']:
            ds, cs = matchers(lists[ref])
            sites.extend(ds)
            ips.extend(cs)
        target = {'balancerTag': 'auto'} if group['outbound'] == 'currentSelected' else {'outboundTag': group['outbound']}
        # Separate rules preserve domain OR IP; putting both in one Xray rule
        # would instead require both to match.
        if sites:
            site_groups[tag] = list(dict.fromkeys(sites))
            routing_rules.append({'type': 'field', 'ruleTag': tag + '-sites', 'domain': ['geosite:' + tag], **target})
        if ips:
            ip_groups[tag] = list(dict.fromkeys(ips))
            routing_rules.append({'type': 'field', 'ruleTag': tag + '-ips', 'ip': ['geoip:' + tag], **target})
        groups.append({'tag': tag, 'name': group['name'], 'action': group['outbound'], 'enabled': True, 'upstream_switch': group['switch'], 'sites': len(set(sites)), 'cidrs': len(set(ips))})
    # Preserve exactly our two RU-direct rules, without duplicating them.
    ru_rules = old['routing']['rules'][-3:-1]
    if len(ru_rules) != 2 or any(rule.get('outboundTag') != 'direct' for rule in ru_rules) or ru_rules[-1].get('ip') != ['geoip:ru']:
        raise ValueError('existing RU policy changed; review required')
    routing_rules.extend(copy.deepcopy(ru_rules))
    routing_rules.append({'type': 'field', 'network': 'tcp,udp', 'balancerTag': 'auto'})
    config = copy.deepcopy(old)
    config['remarks'] = 'rjsxrd + Karing + RU direct'
    config['routing']['rules'] = routing_rules
    config['routing']['domainStrategy'] = 'IPOnDemand'
    return config, site_groups, ip_groups, groups


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


def with_fakedns(config):
    variant = copy.deepcopy(config)
    variant['fakedns'] = [{'ipPool': '198.18.0.0/15', 'poolSize': 4096}]
    # External DNS gets synthetic IPs. Xray's internal resolver excludes the
    # FakeDNS server when real IPs are needed for dialing and GeoIP matching.
    # Preserve route precedence for overlapping domain categories. FakeDNS
    # matches first for client queries and is excluded by Xray for real-IP lookup.
    servers = [{'address': 'fakedns', 'domains': ['regexp:.*']}]
    for rule in variant['routing']['rules']:
        names = rule.get('domain', [])
        if not names:
            continue
        if rule.get('outboundTag') == 'direct':
            addresses = ['77.88.8.8', '77.88.8.1']
        elif rule.get('balancerTag') == 'auto':
            addresses = ['1.1.1.1']
        else:
            continue
        servers.extend({'address': address, 'domains': names[:], 'skipFallback': True} for address in addresses)
    servers.append('1.1.1.1')
    variant['dns'] = {'tag': 'dns-bootstrap', 'queryStrategy': 'UseIPv4', 'servers': servers}
    for inbound in variant['inbounds']:
        sniffing = inbound.setdefault('sniffing', {})
        sniffing.update({'enabled': True, 'routeOnly': False})
        sniffing['destOverride'] = list(dict.fromkeys(['fakedns', *sniffing.get('destOverride', ['http', 'tls', 'quic'])]))
    variant['outbounds'].append({'tag': 'dns-out', 'protocol': 'dns'})
    variant['routing']['rules'][:0] = [
        {'type': 'field', 'inboundTag': ['dns-bootstrap'], 'outboundTag': 'direct'},
        {'type': 'field', 'inboundTag': [i['tag'] for i in variant['inbounds']], 'port': '53', 'network': 'tcp,udp', 'outboundTag': 'dns-out'},
    ]
    return variant


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
        config, sites, ips, groups = assemble(profile, lists, old)
        assets = Path(args.xray).resolve().parent
        # Retain original categories for other INCY profiles; protobuf repeated
        # entry streams can be concatenated without replacing original entries.
        geo_files = {'geosite.dat': (assets / 'geosite.dat').read_bytes() + geosite(sites), 'geoip.dat': (assets / 'geoip.dat').read_bytes() + geoip(ips)}
        for filename, content in geo_files.items():
            (temp / filename).write_bytes(content)
        text = serialized_config(config)
        normal_old = json.loads((ROOT / 'normal.json').read_bytes())
        normal_config, _, _, _ = assemble(profile, lists, normal_old)
        variants = [with_fakedns(automatic_config(normal_config, 'Для обычного интернета')),
                    with_fakedns(automatic_config(config, 'Для белых списков (если не работает)'))]
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
        digest = hashlib.sha256(b''.join(geo_files.values())).hexdigest()
        route_profile = {'Name': 'rjsxrd Karing geodata', 'GlobalProxy': 'true', 'DomainStrategy': 'IPOnDemand', 'LastUpdated': str(int(time.time())), 'Geoipurl': PUBLIC + 'karing-geoip.dat?v=' + digest, 'Geositeurl': PUBLIC + 'karing-geosite.dat?v=' + digest, 'DirectSites': [], 'DirectIp': LOCAL_IPS + ['geoip:ru'], 'ProxySites': [], 'ProxyIp': [], 'BlockSites': [], 'BlockIp': []}
        for rule in config['routing']['rules']:
            prefix = 'Proxy' if 'balancerTag' in rule else ('Direct' if rule.get('outboundTag') == 'direct' else 'Block')
            route_profile[prefix + 'Sites'].extend(rule.get('domain', []))
            route_profile[prefix + 'Ip'].extend(rule.get('ip', []))
        for key in ('DirectSites', 'DirectIp', 'ProxySites', 'ProxyIp', 'BlockSites', 'BlockIp'):
            route_profile[key] = list(dict.fromkeys(route_profile[key]))
        route_profile.update({'FakeDNS': 'true', 'LocalDNSType': 'DoU', 'LocalDNSIP': '77.88.8.8', 'LocalDNSDomain': '', 'RemoteDNSType': 'DoU', 'RemoteDNSIP': '1.1.1.1', 'RemoteDNSDomain': ''})
        happ_ips = {**ips, 'ru': geoip_cidrs(geo_files['geoip.dat'], 'ru')}
        happ_variants = [happ_config(v, sites, happ_ips) for v in variants]
        happ_body = happ_subscription(happ_variants)
        # A missing custom database must never break this independent variant.
        for variant in happ_variants:
            xray_validate(args.xray, variant)
        report = {'profile_url': BASE + 'recommend/ru.json', 'profile_sha256': hashlib.sha256(profile_data).hexdigest(), 'all_groups_enabled': False, 'selection': 'direct groups plus Adblock and AdblockPlus; no Anticensor or custom advertising/Google additions', 'groups': groups, 'sources': sources, 'xray_validated': True, 'config_utf16_bytes': len(text.encode('utf-16-le')), 'geofiles_sha256': {name: hashlib.sha256(content).hexdigest() for name, content in geo_files.items()}, 'requires_geodata_import': True, 'preserved_ru_direct': True, 'generated_at_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
        report['variants'] = [{'name': v['remarks'], 'servers': sum(o['protocol'] in ('vless', 'shadowsocks', 'trojan', 'vmess') for o in v['outbounds']), 'config_utf16_bytes': len(serialized_config(v).encode('utf-16-le'))} for v in variants]
        report['fakedns'] = True
        report['happ_import_verified'] = False
        report['happ_self_contained'] = True
        report['happ_bytes'] = len(happ_body.encode('utf-8'))
        # Do not touch active ru.json. Publish complete new variant after checks.
        for filename, content in geo_files.items():
            out = ROOT / ('karing-' + filename)
            tmp = out.with_suffix('.tmp')
            tmp.write_bytes(content)
            tmp.replace(out)
        atomic_write(ROOT / 'ru-karing.json', text)
        atomic_write(ROOT / 'ru-karing-incy.txt', incy_body)
        atomic_write(ROOT / 'ru-karing-happ.txt', happ_body)
        atomic_write(ROOT / 'karing-routing.json', json.dumps(route_profile, ensure_ascii=False, indent=2) + '\n')
        atomic_write(ROOT / 'karing-report.json', json.dumps(report, ensure_ascii=False, indent=2) + '\n')
        print(json.dumps({'groups': len(groups), 'config_bytes': len(text.encode()), 'geofiles_bytes': {name: len(content) for name, content in geo_files.items()}, 'xray_validated': True}))


if __name__ == '__main__':
    main()
