"""One self-contained Xray policy for Happ and INCY; no native profiles."""
import copy
import hashlib
import json
import ipaddress
import os
import tempfile
from pathlib import Path
from generate import atomic_write, xray_validate
from technology_selection import PROXY_PROTOCOLS, balancing, selection_report

ROOT = Path(__file__).resolve().parent
LABEL = 'Автовыбор'


def read_policy():
    return json.loads((ROOT / 'routing-policy.json').read_bytes())


def build(config, policy):
    result = copy.deepcopy(config)
    proxies = [o for o in result['outbounds']
               if o.get('protocol') in PROXY_PROTOCOLS]
    if not proxies:
        raise ValueError('A checked proxy pool is required')
    selection = balancing(proxies)
    result.pop('fakedns', None)
    result.pop('observatory', None)
    result['remarks'] = LABEL
    result['log'] = {'loglevel': 'warning'}
    result['meta'] = {'serverDescription': 'IPv4 · IPv6 пока не поддерживается · RU/LAN напрямую · реклама заблокирована · автовыбор технологии и сервера'}
    result['dns'] = copy.deepcopy(policy['dns'])
    # Bootstrap proxy hostnames without requiring a working proxy connection.
    bootstrap = set()
    for outbound in proxies:
        settings = outbound.get('settings', {})
        for server in settings.get('vnext', []) + settings.get('servers', []):
            host = server.get('address', '')
            if not host:
                continue
            try:
                ipaddress.ip_address(host)
            except ValueError:
                bootstrap.add('full:' + host.lower().rstrip('.'))
    for server in result['dns']['servers']:
        if isinstance(server, dict) and server.get('tag') == 'dns-direct':
            server['domains'] = list(dict.fromkeys(server['domains'] + sorted(bootstrap)))
    result['geodata'] = {
        'cron': '17 */12 * * *',
        'assets': [{'url': policy['geoip_url'], 'file': 'geoip.dat'},
                   {'url': policy['geosite_url'], 'file': 'geosite.dat'}],
    }
    result['outbounds'] = [
        {'tag': 'default-proxy', 'protocol': 'loopback',
         'settings': {'inboundTag': 'default-auto'}},
        *proxies,
        *selection['outbounds'],
        {'tag': 'direct', 'protocol': 'freedom'},
        {'tag': 'block', 'protocol': 'blackhole'},
        {'tag': 'dns-out', 'protocol': 'dns', 'settings': {'nonIPQuery': 'drop'}},
    ]
    for inbound in result['inbounds']:
        inbound['sniffing'] = {'enabled': True, 'destOverride': ['http', 'tls', 'quic'],
                               'routeOnly': True}
    # Route internal DNS before interception and country rules: external DoH
    # stays in the checked proxy pool, RU/bootstrap DNS stays direct.
    result['routing'] = {
        'domainStrategy': 'IPIfNonMatch',
        'balancers': selection['balancers'],
        'rules': [
            {'type': 'field', 'inboundTag': ['dns-direct'], 'outboundTag': 'direct'},
            {'type': 'field', 'inboundTag': ['dns-proxy'], 'balancerTag': 'auto'},
            {'type': 'field', 'inboundTag': ['default-auto'], 'balancerTag': 'auto'},
            *selection['rules'],
            {'type': 'field', 'inboundTag': [i['tag'] for i in result['inbounds']],
             'port': '53', 'network': 'tcp,udp', 'outboundTag': 'dns-out'},
            {'type': 'field', 'domain': copy.deepcopy(policy['block_domains']), 'outboundTag': 'block'},
            {'type': 'field', 'ip': ['0.0.0.0/32', '::/128'], 'outboundTag': 'block'},
            {'type': 'field', 'domain': copy.deepcopy(policy['direct_domains']), 'outboundTag': 'direct'},
            {'type': 'field', 'ip': copy.deepcopy(policy['direct_ips']), 'outboundTag': 'direct'},
        ],
    }
    # No unconditional catch-all: IPIfNonMatch must get its second GeoIP pass.
    result['burstObservatory'] = {'subjectSelector': selection['subjects'],
                                  'pingConfig': copy.deepcopy(policy['probe'])}
    result['stats'] = {}
    return result


def variant(config):
    from karing import automatic_config
    return build(automatic_config(config, LABEL), read_policy())


def main(xray):
    from karing import download, fit_client_pool, common_subscription
    policy = read_policy()
    assets = {name: download(policy[key], 40_000_000) for name, key in
              [('geosite.dat', 'geosite_url'), ('geoip.dat', 'geoip_url')]}
    base = json.loads((ROOT / 'ru.json').read_bytes())
    _, variants = fit_client_pool(build(base, policy))
    with tempfile.TemporaryDirectory() as temp:
        for name, data in assets.items():
            Path(temp, name).write_bytes(data)
        previous = os.environ.get('XRAY_LOCATION_ASSET')
        os.environ['XRAY_LOCATION_ASSET'] = temp
        try:
            for config in variants:
                xray_validate(xray, config)
        finally:
            if previous is None:
                os.environ.pop('XRAY_LOCATION_ASSET', None)
            else:
                os.environ['XRAY_LOCATION_ASSET'] = previous
    runtime = ROOT / '.runtime'
    runtime.mkdir(exist_ok=True)
    for name, data in assets.items():
        (runtime / name).write_bytes(data)
    report = json.loads((ROOT / 'report.json').read_bytes())
    report.pop('gemini_check', None)
    report['subscription_policy'] = {
        'clients': ['Happ', 'INCY'], 'format': 'full-xray-json-array',
        'native_routing_profile': False,
        'block_domains': policy['block_domains'],
        'direct_domains': policy['direct_domains'], 'direct_ips': policy['direct_ips'],
        'dns_ad_filter': True, 'dns_query_strategy': policy['dns']['queryStrategy'],
        'ipv6_supported': False,
        'dns_transport': {'ru_and_bootstrap': 'direct', 'external': 'doh-via-auto',
                          'external_direct_fallback': False},
        'probe': policy['probe'],
        'automatic_selection': selection_report(variants[0]),
        'geodata_sha256': {name: hashlib.sha256(data).hexdigest() for name, data in assets.items()},
        'client_geodata_download_verified': False,
    }
    atomic_write(ROOT / 'subscription.json', common_subscription(variants))
    atomic_write(ROOT / 'report.json', json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print('Published one common full-JSON subscription without native profiles')
