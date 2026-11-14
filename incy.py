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
ADGUARD_IPS = ('94.140.14.14', '94.140.15.15')
YANDEX_DOH = 'https://77.88.8.8/dns-query'
BLOCK_DOMAINS = ('geosite:win-spy', 'geosite:category-ads')
PROXY_DOMAINS = ('habr.com', '4pda.to', 'kemono.su', 'jut.su', 'kara.su',
                 'theins.ru', 'tvrain.ru', 'echo.msk.ru', 'the-village.ru',
                 'snob.ru', 'novayagazeta.ru', 'moscowtimes.ru')
DIRECT_DOMAINS = ('geosite:private', 'geosite:apple', 'geosite:twitch',
                  'geosite:category-gov-ru', 'geosite:category-ru')
DIRECT_IPS = ('geoip:ru', 'geoip:private')


def proxy_tag(index):
    return f'proxy-{index}'


def vision_blocks_quic(node):
    outbound = node.get('outbound', node)
    settings = outbound.get('settings', {})
    users = [settings] + [user for peer in settings.get('vnext', [])
                           for user in peer.get('users', [])]
    return outbound.get('protocol') == 'vless' and any(
        user.get('flow') in ('xtls-rprx-vision', 'xtls-rprx-vision-udp443') for user in users)


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


def proxy_outbound(node, tag):
    """Use identical node parameters in the publication and live pool checks."""
    outbound = copy.deepcopy(node['outbound'] if 'outbound' in node else node)
    outbound['tag'] = tag
    if outbound.get('protocol') == 'vless':
        settings = outbound.get('settings', {})
        users = [settings] + [user for peer in settings.get('vnext', [])
                               for user in peer.get('users', [])]
        for user in users:
            # Match the supplied reference: ordinary Vision intentionally
            # intercepts UDP/443 so browsers can fall back to HTTPS over TCP.
            if user.get('flow') == 'xtls-rprx-vision-udp443':
                user['flow'] = 'xtls-rprx-vision'
    stream = outbound.setdefault('streamSettings', {})
    sockopt = stream.setdefault('sockopt', {})
    sockopt.pop('happyEyeballs', None)
    sockopt.update(domainStrategy='UseIPv4', tcpKeepAliveIdle=30, tcpKeepAliveInterval=15)
    network = stream.get('network', 'tcp')
    if network in ('tcp', 'raw', 'grpc'):
        sockopt['tcpNoDelay'] = True
    if network in ('tcp', 'raw'):
        sockopt['tcpFastOpen'] = True
    for key in ('tlsSettings', 'realitySettings'):
        if key in stream:
            stream[key]['fingerprint'] = 'firefox'
    if network == 'hysteria':
        stream.setdefault('finalmask', {}).setdefault('quicParams', {}).update(
            congestion='bbr', debug=False)
    if network == 'xhttp':
        xhttp = stream.setdefault('xhttpSettings', {})
        xhttp['mode'] = 'stream-up'
        xhttp.setdefault('extra', {}).update(xPaddingBytes='100-1000', xmux={
            'cMaxReuseTimes': 0, 'hKeepAlivePeriod': 0, 'hMaxRequestTimes': '600-900',
            'hMaxReusableSecs': '1800-3000', 'maxConcurrency': '16-32', 'maxConnections': 0})
    return outbound


def build(nodes, probe=None):
    if not nodes:
        raise ValueError('no supported non-listed candidates; keep published subscription')
    proxies = [proxy_outbound(node, proxy_tag(index)) for index, node in enumerate(nodes)]
    tags = [outbound['tag'] for outbound in proxies]
    sniffing = {'enabled': True, 'destOverride': ['http', 'tls']}
    rules = [
        # DNS must work even before the observatory has measured any proxies.
        {'type': 'field', 'inboundTag': ['dns-remote'], 'outboundTag': 'direct'},
        {'type': 'field', 'domain': list(BLOCK_DOMAINS), 'outboundTag': 'block'},
        {'type': 'field', 'protocol': ['bittorrent'], 'outboundTag': 'direct'},
        {'type': 'field', 'domain': list(PROXY_DOMAINS), 'balancerTag': 'balancer'},
        {'type': 'field', 'domain': list(DIRECT_DOMAINS), 'outboundTag': 'direct'},
        {'type': 'field', 'ip': list(DIRECT_IPS), 'outboundTag': 'direct'},
        {'type': 'field', 'network': 'tcp,udp', 'balancerTag': 'balancer'},
    ]
    config = {
        'remarks': '🇪🇺 ⚡️ Автовыбор', 'log': {'loglevel': 'warning'},
        'meta': {'serverDescription': 'INCY · IPv4 · leastLoad · Яндекс / AdGuard DNS'},
        'dns': {'queryStrategy': 'UseIPv4', 'tag': 'dns-remote',
                'hosts': {ADGUARD_HOST: list(ADGUARD_IPS)},
                'servers': [{'address': YANDEX_DOH,
                             'domains': ['geosite:category-ru', 'geosite:category-gov-ru']},
                            {'address': ADGUARD_DOH, 'skipFallback': False},
                            {'address': ADGUARD_IPS[0], 'skipFallback': False}]},
        'inbounds': [
            {'tag': 'socks', 'listen': '127.0.0.1', 'port': 10808, 'protocol': 'socks',
             'settings': {'auth': 'noauth', 'udp': True, 'userLevel': 8},
             'sniffing': copy.deepcopy(sniffing)},
            {'tag': 'http', 'listen': '127.0.0.1', 'port': 10809, 'protocol': 'http',
             'settings': {'userLevel': 8}, 'sniffing': copy.deepcopy(sniffing)},
        ],
        'outbounds': [
            *proxies,
            {'tag': 'direct', 'protocol': 'freedom', 'settings': {'domainStrategy': 'UseIPv4'}},
            {'tag': 'block', 'protocol': 'blackhole'},
        ],
        'routing': {'domainStrategy': 'AsIs', 'rules': rules,
                    'balancers': [{'tag': 'balancer', 'selector': ['proxy-'], 'fallbackTag': tags[0],
                                   'strategy': {'type': 'leastLoad', 'settings': {
                                       'expected': 1, 'maxRTT': '1500ms', 'tolerance': .2,
                                       'costs': [{'match': '^' + tag + '$', 'regexp': True, 'value': 2}
                                                 for tag in tags[1:]]}}}]},
        'burstObservatory': {'subjectSelector': ['proxy-'], 'pingConfig': copy.deepcopy(probe or {
            'destination': 'https://www.gstatic.com/generate_204', 'interval': '5m',
            'sampling': 2, 'timeout': '5s'})},
        'policy': {'system': {'statsOutboundDownlink': True, 'statsOutboundUplink': True}},
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
