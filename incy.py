"""INCY full configuration and its subscription-bound native routing profile."""
import copy
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import tempfile
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
PUBLIC = 'https://raw.githubusercontent.com/RnRLover/rjsxrd-karing-subscription/refs/heads/main/'
PROFILE_URL = PUBLIC + 'incy-routing.json'
PROXY_PROTOCOLS = ('vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria')
MAX_CONFIG_UTF16 = 800_000


def read_profile():
    return json.loads((ROOT / 'incy-routing.json').read_bytes())


def serialized_config(config):
    text = json.dumps(config, ensure_ascii=False, separators=(',', ':'))
    # Keep every candidate. Refuse an oversized publication instead of silently
    # removing the tail of the pool. This is a guard, not an IPC measurement.
    if len(text.encode('utf-16-le')) > MAX_CONFIG_UTF16:
        raise ValueError('full configuration exceeds the publication size budget')
    return text


def atomic_write(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                     delete=False) as handle:
        handle.write(content)
        temporary = Path(handle.name)
    os.replace(temporary, path)


def xray_validate(xray, config):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory, 'config.json')
        path.write_text(json.dumps(config), encoding='utf-8')
        result = subprocess.run([str(Path(xray).resolve()), 'run', '-test', '-c', str(path)],
                                capture_output=True, text=True, timeout=20)
        if result.returncode:
            raise ValueError('Xray rejected configuration: ' + (result.stderr + result.stdout)[-900:])


def server_address(outbound):
    settings = outbound.get('settings', {})
    if outbound.get('protocol') == 'hysteria':
        return settings.get('address', '')
    servers = settings.get('vnext', []) + settings.get('servers', [])
    return servers[0].get('address', '') if servers else ''


def build(nodes, profile=None, probe=None):
    profile = profile or read_profile()
    if not nodes:
        raise ValueError('no supported non-listed candidates; keep published subscription')
    proxies = []
    bootstrap = set()
    for index, node in enumerate(nodes, 1):
        outbound = copy.deepcopy(node['outbound'] if 'outbound' in node else node)
        outbound['tag'] = 'Автовыбор' if index == 1 else f'pool-{index:03d}'
        stream = outbound.setdefault('streamSettings', {})
        sockopt = stream.setdefault('sockopt', {})
        if stream.get('network') == 'hysteria':
            # QUIC is UDP; TCP Happy Eyeballs does not apply to its socket.
            sockopt['domainStrategy'] = 'ForceIPv4v6'
        else:
            sockopt.update(domainStrategy='ForceIP', happyEyeballs={
                'tryDelayMs': 250, 'prioritizeIPv6': False,
                'interleave': 1, 'maxConcurrentTry': 4})
        host = server_address(outbound)
        if host:
            try:
                ipaddress.ip_address(host)
            except ValueError:
                bootstrap.add('full:' + host.lower().rstrip('.'))
        proxies.append(outbound)
    tags = [outbound['tag'] for outbound in proxies]
    direct_domains = copy.deepcopy(profile['DirectSites'])
    # Private names use the local resolver; public direct/bootstrap names use
    # the profile's domestic resolver. Never send LAN-only names to Yandex.
    public_direct = [domain for domain in direct_domains if domain != 'geosite:private']
    remote = profile['RemoteDNSDomain']
    if profile['RemoteDNSType'] != 'DoH' or not remote.startswith('https://'):
        raise ValueError('remote DNS must be HTTPS DoH')
    if ipaddress.ip_address(profile['RemoteDNSIP']).version not in (4, 6):
        raise ValueError('invalid remote DNS bootstrap address')
    remote_host = urlsplit(remote).hostname
    try:
        ipaddress.ip_address(remote_host)
    except ValueError:
        pass
    else:
        raise ValueError('DoH URL must use a hostname to survive INCY DNS-IP bypass rules')
    hosts = copy.deepcopy(profile.get('DnsHosts', {}))
    hosts[remote_host] = profile['RemoteDNSIP']
    for domain in profile['BlockSites']:
        hosts[domain] = '0.0.0.0'
    sniffing = {'enabled': True, 'destOverride': ['http', 'tls', 'quic'], 'routeOnly': True}
    rules = [
        {'type': 'field', 'inboundTag': ['dns-direct'], 'outboundTag': 'direct'},
        {'type': 'field', 'inboundTag': ['dns-proxy'], 'balancerTag': 'auto'},
        {'type': 'field', 'inboundTag': ['default-auto'], 'balancerTag': 'auto'},
        {'type': 'field', 'inboundTag': ['socks-in', 'http-in'], 'port': '53',
         'network': 'tcp,udp', 'outboundTag': 'dns-out'},
        {'type': 'field', 'domain': copy.deepcopy(profile['BlockSites']), 'outboundTag': 'block'},
        {'type': 'field', 'ip': copy.deepcopy(profile['BlockIp']), 'outboundTag': 'block'},
        {'type': 'field', 'domain': ['geosite:private'], 'outboundTag': 'lan'},
        {'type': 'field', 'domain': public_direct, 'outboundTag': 'direct'},
        {'type': 'field', 'ip': ['geoip:private'], 'outboundTag': 'lan'},
        {'type': 'field', 'ip': [ip for ip in profile['DirectIp'] if ip != 'geoip:private'],
         'outboundTag': 'direct'},
    ]
    config = {
        'remarks': 'Автовыбор', 'log': {'loglevel': 'warning'},
        'meta': {'serverDescription': 'INCY · IPv4/IPv6 · RU и GitHub напрямую · блокировка рекламы'},
        'dns': {'queryStrategy': 'UseIP', 'disableFallbackIfMatch': True,
                'tag': 'dns-proxy', 'hosts': hosts, 'servers': [
                    {'address': 'localhost', 'domains': ['geosite:private'], 'skipFallback': True},
                    {'address': profile['DomesticDNSIP'], 'domains': public_direct + sorted(bootstrap),
                     'skipFallback': True, 'tag': 'dns-direct'},
                    {'address': remote, 'tag': 'dns-proxy'},
                ]},
        'inbounds': [
            {'tag': 'socks-in', 'listen': '127.0.0.1', 'port': 10808, 'protocol': 'socks',
             'settings': {'udp': True}, 'sniffing': copy.deepcopy(sniffing)},
            {'tag': 'http-in', 'listen': '127.0.0.1', 'port': 10809, 'protocol': 'http',
             'sniffing': copy.deepcopy(sniffing)},
        ],
        'outbounds': [
            {'tag': 'default-proxy', 'protocol': 'loopback', 'settings': {'inboundTag': 'default-auto'}},
            *proxies,
            {'tag': 'direct', 'protocol': 'freedom', 'streamSettings': {'sockopt': {
                'domainStrategy': 'ForceIP', 'happyEyeballs': {
                    'tryDelayMs': 250, 'prioritizeIPv6': False, 'interleave': 1, 'maxConcurrentTry': 4}}}},
            {'tag': 'lan', 'protocol': 'freedom'},
            {'tag': 'block', 'protocol': 'blackhole'},
            # The modern default imports A/AAAA and answers other types with
            # empty NOERROR, rather than silently dropping them until timeout.
            {'tag': 'dns-out', 'protocol': 'dns'},
        ],
        'routing': {'domainStrategy': profile['DomainStrategy'], 'rules': rules,
                    'balancers': [{'tag': 'auto', 'selector': tags, 'fallbackTag': tags[0],
                                   'strategy': {'type': 'leastPing'}}]},
        'burstObservatory': {'subjectSelector': tags, 'pingConfig': copy.deepcopy(probe or {
            'destination': 'https://www.gstatic.com/generate_204', 'interval': '1m',
            'sampling': 1, 'timeout': '4s', 'httpMethod': 'HEAD'})},
        'stats': {},
    }
    serialized_config(config)
    return config


def subscription(config):
    """Keep the existing URL; INCY extracts these body commands before JSON."""
    return (serialized_config([config]) + '\n'
            + 'incy://autorouting/onadd/' + PROFILE_URL + '\n'
            + '#profile-title: rjsxrd · INCY\n'
            + '#routing-geo-update-interval: 24\n')


def load_configs(path):
    text = Path(path).read_text(encoding='utf-8-sig').strip()
    # Accept pure JSON fixtures as well as the delivered JSON + body metadata.
    configs, end = json.JSONDecoder().raw_decode(text)
    for line in text[end:].strip().splitlines():
        if not (line.startswith('incy://autorouting/onadd/') or line.startswith('#')):
            raise ValueError('unexpected subscription body command')
    return configs if isinstance(configs, list) else [configs]
