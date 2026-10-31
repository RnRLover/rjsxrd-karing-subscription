"""Build disposable native-profile isolation checks, separate from production."""
import base64
import copy
import json
from pathlib import Path
from urllib.parse import quote, urlencode


def control_subscriptions(configs, profile):
    """Use one existing TLS/TCP Trojan node in both plain-link subscriptions."""
    candidates = [o for config in configs for o in config['outbounds']
                  if o.get('protocol') == 'trojan'
                  and o.get('streamSettings', {}).get('security') == 'tls'
                  and o['streamSettings'].get('network', 'tcp') == 'tcp'
                  and not o['streamSettings'].get('tlsSettings', {}).get('allowInsecure')]
    if not candidates:
        raise ValueError('No TLS/TCP Trojan node in the current pool; controls were not rebuilt')
    node = candidates[0]
    server = node['settings']['servers'][0]
    tls = node['streamSettings']['tlsSettings']
    if not tls.get('serverName'):
        raise ValueError('Control node requires the original TLS server name')
    host = server['address']
    if ':' in host:
        host = '[' + host + ']'
    params = {'security': 'tls', 'type': 'tcp', 'sni': tls['serverName']}
    if tls.get('fingerprint'):
        params['fp'] = tls['fingerprint']
    if tls.get('alpn'):
        params['alpn'] = ','.join(tls['alpn'])
    if server.get('flow'):
        params['flow'] = server['flow']
    link = (f"trojan://{quote(server['password'], safe='')}@{host}:{server['port']}?"
            + urlencode(params) + '#Routing-isolation-control\n')
    native = copy.deepcopy(profile)
    native.update(Name='Isolation A - block example.org', GlobalProxy='true',
                  RouteOrder='block-direct-proxy', DomainStrategy='AsIs',
                  DirectSites=[], DirectIp=[], ProxySites=[], ProxyIp=[],
                  BlockSites=['domain:example.org'], BlockIp=[],
                  useChunkFiles=False)
    # Do not inherit DNS settings from a future production profile.
    for key in list(native):
        if 'dns' in key.lower() and key != 'FakeDNS':
            del native[key]
    payload = base64.b64encode(json.dumps(native, ensure_ascii=False,
                                         separators=(',', ':')).encode()).decode()
    return {'isolation-a.txt': '#profile-title: Isolation A - block\n' + link
            + 'incy://routing/onadd/' + payload + '\n',
            'isolation-b.txt': '#profile-title: Isolation B - no profile\n' + link}


if __name__ == '__main__':
    root = Path(__file__).resolve().parent
    configs = json.loads((root / 'subscription.json').read_bytes())
    profile = json.loads((root / 'russia-routing.json').read_bytes())
    for name, body in control_subscriptions(configs, profile).items():
        (root / name).write_text(body)
    print('Wrote disposable A/B controls from the current published pool')
