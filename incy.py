"""INCY full configuration with DNS and routing kept inside the JSON."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
PROXY_PROTOCOLS = ('vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria')
MAX_CONFIG_UTF16 = 800_000
# Published standard filtering endpoints, not the unfiltered or family service.
# Fixed bootstrap addresses avoid asking another DNS provider for this hostname.
ADGUARD_DOH = 'https://dns.adguard-dns.com/dns-query'
ADGUARD_HOST = 'dns.adguard-dns.com'
ADGUARD_IPS = ('94.140.14.14', '94.140.15.15',
               '2a10:50c0::ad1:ff', '2a10:50c0::ad2:ff')


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


def build(nodes, probe=None):
    if not nodes:
        raise ValueError('no supported non-listed candidates; keep published subscription')
    proxies = []
    for index, node in enumerate(nodes, 1):
        outbound = copy.deepcopy(node['outbound'] if 'outbound' in node else node)
        outbound['tag'] = 'Автовыбор' if index == 1 else f'pool-{index:03d}'
        if outbound.get('protocol') == 'vless':
            settings = outbound.get('settings', {})
            users = [settings] + [user for peer in settings.get('vnext', [])
                                   for user in peer.get('users', [])]
            for user in users:
                # Preserve Vision while allowing proxied QUIC instead of the
                # plain Vision client's deliberate rejection of UDP/443.
                if user.get('flow') == 'xtls-rprx-vision':
                    user['flow'] = 'xtls-rprx-vision-udp443'
        stream = outbound.setdefault('streamSettings', {})
        sockopt = stream.setdefault('sockopt', {})
        if stream.get('network') == 'hysteria':
            # QUIC is UDP; TCP Happy Eyeballs does not apply to its socket.
            sockopt['domainStrategy'] = 'ForceIPv4v6'
        else:
            sockopt.update(domainStrategy='ForceIP', happyEyeballs={
                'tryDelayMs': 250, 'prioritizeIPv6': False,
                'interleave': 1, 'maxConcurrentTry': 4})
        proxies.append(outbound)
    tags = [outbound['tag'] for outbound in proxies]
    sniffing = {'enabled': True, 'destOverride': ['http', 'tls', 'quic'], 'routeOnly': True}
    rules = [
        # DNS must work even before the observatory has measured any proxies.
        {'type': 'field', 'inboundTag': ['dns-remote'], 'outboundTag': 'direct'},
        {'type': 'field', 'inboundTag': ['socks-in', 'http-in'], 'port': '53',
         'network': 'tcp,udp', 'outboundTag': 'dns-out'},
        # AdGuard may answer blocked A/AAAA questions with unspecified addresses.
        {'type': 'field', 'ip': ['0.0.0.0/32', '::/128'], 'outboundTag': 'block'},
        {'type': 'field', 'network': 'tcp,udp', 'balancerTag': 'auto'},
    ]
    config = {
        'remarks': 'Автовыбор', 'log': {'loglevel': 'warning'},
        'meta': {'serverDescription': 'INCY · IPv4/IPv6 · весь трафик через VPN · AdGuard DNS'},
        'dns': {'queryStrategy': 'UseIP', 'tag': 'dns-remote',
                'hosts': {ADGUARD_HOST: list(ADGUARD_IPS)},
                'servers': [{'address': ADGUARD_DOH, 'tag': 'dns-remote'}]},
        'inbounds': [
            {'tag': 'socks-in', 'listen': '127.0.0.1', 'port': 10808, 'protocol': 'socks',
             'settings': {'udp': True}, 'sniffing': copy.deepcopy(sniffing)},
            {'tag': 'http-in', 'listen': '127.0.0.1', 'port': 10809, 'protocol': 'http',
             'sniffing': copy.deepcopy(sniffing)},
        ],
        'outbounds': [
            *proxies,
            {'tag': 'direct', 'protocol': 'freedom', 'streamSettings': {'sockopt': {
                'domainStrategy': 'ForceIP', 'happyEyeballs': {
                    'tryDelayMs': 250, 'prioritizeIPv6': False, 'interleave': 1, 'maxConcurrentTry': 4}}}},
            {'tag': 'block', 'protocol': 'blackhole'},
            # The modern default imports A/AAAA and answers other types with
            # empty NOERROR, rather than silently dropping them until timeout.
            {'tag': 'dns-out', 'protocol': 'dns'},
        ],
        'routing': {'domainStrategy': 'AsIs', 'rules': rules,
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
    """Keep the existing URL without installing or activating routing profiles."""
    return (serialized_config([config]) + '\n'
            + '#profile-title: rjsxrd · INCY\n')


def load_configs(path):
    text = Path(path).read_text(encoding='utf-8-sig').strip()
    # Accept pure JSON fixtures as well as the delivered JSON + body metadata.
    configs, end = json.JSONDecoder().raw_decode(text)
    for line in text[end:].strip().splitlines():
        if not line.startswith('#'):
            raise ValueError('unexpected subscription body command')
    return configs if isinstance(configs, list) else [configs]
