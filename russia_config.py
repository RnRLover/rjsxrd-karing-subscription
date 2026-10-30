"""Apply embedded RU/LAN/adblock rules and publish one common subscription."""
import copy
import json
import os
from pathlib import Path

from generate import atomic_write, serialized_config, xray_validate

ROOT = Path(__file__).resolve().parent


def build(config, profile):
    result = copy.deepcopy(config)
    result.pop('fakedns', None)
    result.pop('dns', None)
    result['remarks'] = 'Russia'
    result['geodata'] = {
        'cron': '17 */12 * * *',
        'assets': [
            {'url': profile['Geoipurl'], 'file': 'geoip.dat'},
            {'url': profile['Geositeurl'], 'file': 'geosite.dat'},
        ],
    }
    # No subscription-owned DNS resolver, interception or routing profile.
    # Unmatched traffic uses the default loopback only after both GeoIP passes.
    result['outbounds'] = [o for o in result['outbounds']
                           if o.get('protocol') not in ('dns', 'loopback')]
    proxies = [o for o in result['outbounds']
               if o.get('protocol') in ('vless', 'vmess', 'trojan', 'shadowsocks')]
    result['outbounds'] = [{'tag': 'default-proxy', 'protocol': 'loopback',
                            'settings': {'inboundTag': 'default-auto'}}] + proxies + [
                                o for o in result['outbounds'] if o not in proxies]
    for balancer in result['routing'].get('balancers', []):
        balancer['fallbackTag'] = proxies[0]['tag'] if proxies else 'block'
    for inbound in result['inbounds']:
        inbound['sniffing'] = {'enabled': True, 'destOverride': ['http', 'tls', 'quic'], 'routeOnly': True}
    # Prefer the original destination IP. Resolve unmatched domains on a second
    # pass; an unconditional catch-all would prevent that pass from happening.
    result['routing']['domainStrategy'] = 'IPIfNonMatch'
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
    # Loopback re-entry is scoped to a synthetic tag, not a catch-all. It
    # reaches the automatic pool without repeating classification indefinitely.
    rules.insert(0, {'type': 'field', 'inboundTag': ['default-auto'], 'balancerTag': 'auto'})
    result['routing']['rules'] = rules
    return result


def variant(config):
    from karing import automatic_config
    result = automatic_config(config, 'Основной')
    return build(result, json.loads((ROOT / 'russia-routing.json').read_bytes()))


def main(xray):
    from karing import download, fit_client_pool, common_subscription
    profile = json.loads((ROOT / 'russia-routing.json').read_bytes())
    # Fetch the exact databases declared by the profile, not Xray's bundled
    # databases, whose domain categories may differ.
    assets = {name: download(profile[key], 40_000_000) for name, key in
              [('geosite.dat', 'Geositeurl'), ('geoip.dat', 'Geoipurl')]}
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
    body = common_subscription(variants)
    # Local validation assets; clients download their own copies via geodata.
    runtime = ROOT / '.runtime'
    runtime.mkdir(exist_ok=True)
    for name, data in assets.items():
        (runtime / name).write_bytes(data)
    atomic_write(ROOT / 'subscription.json', body + '\n')
    print('Published common subscription')
