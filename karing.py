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
    from russia_config import variant
    return [variant(config)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--xray', required=True)
    parser.add_argument('--singbox')
    parser.add_argument('--cache', type=Path)
    args = parser.parse_args()
    from russia_config import main as generate_russia
    generate_russia(args.xray)


if __name__ == '__main__':
    main()
