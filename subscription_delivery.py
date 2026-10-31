"""Bundle full configs and native geofile bootstrap metadata in one publication."""
import copy
import hashlib
import json
import time

PROFILE_KEYS = ('DirectSites', 'DirectIp', 'ProxySites', 'ProxyIp', 'BlockSites', 'BlockIp')


def bundle(configs, policy, assets, previous=None, now=None):
    profile = {
        'Name': 'Russia · автоматические геобазы',
        'GlobalProxy': 'true',
        'DomainStrategy': 'IPIfNonMatch',
        'RouteOrder': policy['RouteOrder'],
        'FakeDNS': 'false',
        'useChunkFiles': False,
        'Geoipurl': policy['Geoipurl'],
        'Geositeurl': policy['Geositeurl'],
        **{key: copy.deepcopy(policy[key]) for key in PROFILE_KEYS},
    }
    hashes = {name: hashlib.sha256(assets[name]).hexdigest()
              for name in ('geoip.dat', 'geosite.dat')}
    # Server rotation must not make clients download 28 MB of databases again.
    previous = previous or {}
    prior_profile = dict(previous.get('profile', {}))
    old_timestamp = int(prior_profile.pop('LastUpdated', '0'))
    if prior_profile == profile and previous.get('geodata_sha256') == hashes:
        stamp = old_timestamp
    else:
        stamp = max(int(time.time() if now is None else now), old_timestamp + 1)
    profile['LastUpdated'] = str(stamp)
    return {'version': 1, 'configs': copy.deepcopy(configs),
            'profile': profile, 'geodata_sha256': hashes}


def read_previous(path):
    try:
        return json.loads(path.read_bytes())
    except FileNotFoundError:
        return None
