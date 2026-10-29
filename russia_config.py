"""Translate the exported INCY region profile into our full Xray subscription."""
import copy
import json
import os
from pathlib import Path
import time

from geo_dat import protobuf_fields, geoip_cidrs
from generate import atomic_write, serialized_config, xray_validate

ROOT = Path(__file__).resolve().parent


def geosite_domains(blob, category):
    prefixes = {0: 'keyword:', 1: 'regexp:', 2: 'domain:', 3: 'full:'}
    for n, w, entry in protobuf_fields(blob):
        if (n, w) != (1, 2): continue
        fields = list(protobuf_fields(entry))
        code = next((v.decode() for n, w, v in fields if (n, w) == (1, 2)), '')
        if code.lower() != category.lower(): continue
        result = []
        for n, w, value in fields:
            if (n, w) != (2, 2): continue
            domain = list(protobuf_fields(value))
            kind = next((v for n, w, v in domain if (n, w) == (1, 0)), 0)
            text = next(v.decode() for n, w, v in domain if (n, w) == (2, 2))
            result.append(prefixes[kind] + text)
        if not result: raise ValueError('empty category: ' + category)
        return result
    raise ValueError('missing category: ' + category)


def build(config, profile):
    result = copy.deepcopy(config)
    result.pop('fakedns', None)
    result.pop('dns', None)
    result['remarks'] = 'Russia'
    # No DNS resolver, DNS interception, loopback or external routing profile.
    # A real proxy first also keeps full-JSON detection compatible across clients.
    result['outbounds'] = [o for o in result['outbounds']
                           if o.get('protocol') not in ('dns', 'loopback')]
    proxies = [o for o in result['outbounds']
               if o.get('protocol') in ('vless', 'vmess', 'trojan', 'shadowsocks')]
    result['outbounds'] = proxies + [o for o in result['outbounds'] if o not in proxies]
    for balancer in result['routing'].get('balancers', []):
        balancer['fallbackTag'] = proxies[0]['tag'] if proxies else 'block'
    for inbound in result['inbounds']:
        inbound['sniffing'] = {'enabled': True, 'destOverride': ['http', 'tls', 'quic'], 'routeOnly': True}
    # With the explicit final auto rule, IPOnDemand checks domain IPs before it.
    result['routing']['domainStrategy'] = 'IPOnDemand'
    rules = []
    order = profile.get('RouteOrder', 'block-proxy-direct').split('-')
    if len(order) != 3 or set(order) != {'block', 'direct', 'proxy'}:
        raise ValueError('RouteOrder must contain block, direct and proxy exactly once')
    groups = {'block': ('Block', 'block'), 'direct': ('Direct', 'direct'), 'proxy': ('Proxy', 'auto')}
    for name in order:
        prefix, target = groups[name]
        action = {'balancerTag': target} if target == 'auto' else {'outboundTag': target}
        for key, field in [('Sites', 'domain'), ('Ip', 'ip')]:
            if profile[prefix + key]:
                rules.append({'type': 'field', field: profile[prefix + key], **action})
    # Preserve the DNS destination chosen by the client/system.
    rules.insert(0, {'type': 'field', 'port': '53', 'network': 'tcp,udp', 'outboundTag': 'direct'})
    rules.append({'type': 'field', 'network': 'tcp,udp', 'balancerTag': 'auto'})
    result['routing']['rules'] = rules
    return result


def variant(config):
    from karing import automatic_config
    result = automatic_config(config, 'Основной')
    return build(result, json.loads((ROOT / 'russia-routing.json').read_bytes()))


def happ_routing_test_subscription(configs, profile):
    """Legacy filename is an identical alias of the common subscription."""
    from karing import incy_subscription
    return incy_subscription(configs)


def main(xray):
    from karing import download, fit_client_pool, incy_subscription, happ_config, happ_subscription, PUBLIC
    profile = json.loads((ROOT / 'russia-routing.json').read_bytes())
    # Fetch the exact databases declared by the profile, not Xray's bundled
    # databases, whose domain categories may differ.
    assets = {name: download(profile[key], 40_000_000) for name, key in
              [('geosite.dat', 'Geositeurl'), ('geoip.dat', 'Geoipurl')]}
    sites = {tag: geosite_domains(assets['geosite.dat'], tag) for tag in ['category-ru', 'category-ads-all']}
    ips = {tag: geoip_cidrs(assets['geoip.dat'], tag) for tag in ['ru', 'private']}
    old = json.loads((ROOT / 'ru.json').read_bytes())
    config = build(old, profile)
    config, variants = fit_client_pool(config)
    import tempfile
    with tempfile.TemporaryDirectory() as temp:
        for name, data in assets.items(): Path(temp, name).write_bytes(data)
        prior = os.environ.get('XRAY_LOCATION_ASSET')
        os.environ['XRAY_LOCATION_ASSET'] = temp
        try:
            xray_validate(xray, config)
            for v in variants: xray_validate(xray, v)
        finally:
            if prior is None: os.environ.pop('XRAY_LOCATION_ASSET', None)
            else: os.environ['XRAY_LOCATION_ASSET'] = prior
    body = incy_subscription(variants)
    outputs = {'ru-karing.json': serialized_config(config),
               'subscription.json': body,
               'ru-karing-incy.txt': body, 'ru-karing-happ.txt': body,
               'ru-karing-happ-routing-test.txt': body}
    outputs['karing-report.json'] = json.dumps({
        'subscription_url': PUBLIC + 'subscription.json',
        'variants': [{'name': v['remarks'], 'servers': sum(
            o.get('protocol') in ('vless', 'vmess', 'trojan', 'shadowsocks')
            for o in v['outbounds'])} for v in variants],
        'fakedns': False, 'routing': 'embedded block / RU and private direct / automatic proxy',
        'domainStrategy': 'IPOnDemand', 'dns_policy': 'not supplied; client settings',
        'route_order': profile['RouteOrder'], 'autorouting': {'incy': False, 'happ': False},
        'geodata': 'standard client geosite.dat and geoip.dat; keep current',
        'xray_validated': True,
        'generated_at_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())},
        ensure_ascii=False, indent=2)
    import hashlib
    for name, data in assets.items():
        (ROOT / ('karing-' + name)).write_bytes(data)
        atomic_write(ROOT / ('karing-' + name + '.sha256'), hashlib.sha256(data).hexdigest() + '\n')
    for name, text in outputs.items(): atomic_write(ROOT / name, text + '\n')
    print('Published one common DNS-free subscription; old client URLs are identical aliases')
