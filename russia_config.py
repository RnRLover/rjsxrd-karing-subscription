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
    # Keep the default loopback so unmatched traffic reaches the auto pool.
    result['outbounds'].insert(0, {'tag': 'default-proxy', 'protocol': 'loopback',
        'settings': {'inboundTag': 'default-auto'}})
    for inbound in result['inbounds']:
        inbound['sniffing'] = {'enabled': True, 'destOverride': ['http', 'tls', 'quic'], 'routeOnly': True}
    result['routing']['domainStrategy'] = profile['DomainStrategy']
    rules = [
        {'type': 'field', 'inboundTag': ['default-auto'], 'balancerTag': 'auto'},
        # Preserve the resolver destination selected by the client/device.
        {'type': 'field', 'inboundTag': [i['tag'] for i in result['inbounds']],
         'port': '53', 'network': 'tcp,udp', 'outboundTag': 'direct'}]
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
    result['routing']['rules'] = rules
    return result


def variant(config):
    from karing import automatic_config
    result = automatic_config(config, 'Основной')
    if any(o['tag'] == 'default-proxy' for o in result['outbounds']):
        return result
    return build(result, json.loads((ROOT / 'russia-routing.json').read_bytes()))


def happ_routing_test_subscription(configs, profile):
    """Compatibility filename now serves the same pure JSON without imports."""
    from karing import happ_subscription
    return happ_subscription(configs)


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
    happ = [happ_config(v, sites, ips) for v in variants]
    # Preserve default outbound ordering for IPIfNonMatch fallback.
    for v in happ:
        loop = next(o for o in v['outbounds'] if o['tag'] == 'default-proxy')
        v['outbounds'].remove(loop); v['outbounds'].insert(0, loop)
        xray_validate(xray, v)
    outputs = {'ru-karing.json': serialized_config(config), 'ru-karing-incy.txt': incy_subscription(variants),
               'ru-karing-happ.txt': happ_subscription(happ),
               'ru-karing-happ-routing-test.txt': happ_routing_test_subscription(happ, profile),
               'karing-routing.json': json.dumps(profile, ensure_ascii=False, indent=2)}
    outputs['karing-report.json'] = json.dumps({'profile_url': None,
        'variants': [{'name': v['remarks'], 'servers': sum(o.get('tag','').startswith('pool-') or o.get('tag') == 'Основной' for o in v['outbounds'])} for v in variants],
        'fakedns': bool(config.get('fakedns')), 'routing': 'embedded Russia rules; no separate profile import', 'domainStrategy': 'IPIfNonMatch',
        'dns_policy': 'client/device managed; no subscription DNS servers',
        'route_order': profile['RouteOrder'], 'autorouting': False,
        'happ_url': PUBLIC + 'ru-karing-happ.txt',
        'xray_validated': True, 'generated_at_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}, ensure_ascii=False, indent=2)
    import hashlib
    for name, data in assets.items():
        (ROOT / ('karing-' + name)).write_bytes(data)
        atomic_write(ROOT / ('karing-' + name + '.sha256'), hashlib.sha256(data).hexdigest() + '\n')
    for name, text in outputs.items(): atomic_write(ROOT / name, text + '\n')
    print('Published single Russia profile; Xray validated INCY and standalone Happ')
