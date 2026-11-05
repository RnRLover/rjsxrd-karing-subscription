"""Build the common full-Xray subscription for INCY and Happ."""
import argparse
import copy
import json
import urllib.request
from generate import serialized_config

def download(url, limit=10_000_000):
    with urllib.request.urlopen(url, timeout=40) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('upstream rules exceed download budget')
    return data


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
    """Leave room under the Android guard; trim only when the common config is too large."""
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


def common_subscription(config):
    """One pure JSON array for both clients, without provider commands."""
    configs = config if isinstance(config, list) else [config]
    for item in configs:
        serialized_config(item)
    body = json.dumps(configs, ensure_ascii=False, separators=(',', ':')) + '\n'
    if len(body.encode('utf-8')) > 2_000_000:
        raise ValueError('subscription exceeds download size budget')
    return body


def subscription_variants(config):
    from russia_config import variant
    return [variant(config)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--xray', required=True)
    args = parser.parse_args()
    from russia_config import main as generate_subscription
    generate_subscription(args.xray)


if __name__ == '__main__':
    main()
