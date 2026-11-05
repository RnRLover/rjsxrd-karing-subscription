import copy
import json
import unittest
from karing import common_subscription, automatic_config, subscription_variants
from russia_config import build, read_policy


def base_config():
    return {'inbounds': [{'tag': 'socks-in', 'protocol': 'socks'}],
            'outbounds': [{'tag': 'pool-01', 'protocol': 'vless'},
                          {'tag': 'pool-02', 'protocol': 'trojan'},
                          {'tag': 'direct', 'protocol': 'freedom'}],
            'routing': {'rules': [], 'balancers': []}}


class KaringTests(unittest.TestCase):
    def test_common_config_is_self_contained_and_idempotent(self):
        policy = read_policy()
        base = base_config()
        original = copy.deepcopy(base)
        configs = subscription_variants(base)
        self.assertEqual(base, original)
        self.assertEqual(len(configs), 1)
        config = configs[0]
        self.assertEqual(config['remarks'], 'Автовыбор')
        self.assertEqual(build(config, policy), config)
        self.assertEqual(config['dns'], policy['dns'])
        self.assertNotIn('fakedns', config)
        self.assertEqual(config['geodata']['assets'][0]['url'], policy['geoip_url'])
        self.assertEqual(config['geodata']['assets'][1]['url'], policy['geosite_url'])
        self.assertEqual(config['burstObservatory']['pingConfig']['sampling'], 3)
        self.assertEqual(config['burstObservatory']['pingConfig']['interval'], '30s')
        self.assertTrue(all(i['sniffing']['routeOnly'] for i in config['inbounds']))
        body = common_subscription(configs)
        self.assertEqual(json.loads(body), configs)
        for forbidden in ('://routing/', '://autorouting/', 'profile-update-interval'):
            self.assertNotIn(forbidden, body)

    def test_ad_block_precedes_ru_and_dns_cannot_loop(self):
        config = subscription_variants(base_config())[0]
        rules = config['routing']['rules']
        ads = next(i for i, r in enumerate(rules) if r.get('domain') == ['geosite:category-ads-all'])
        ru = next(i for i, r in enumerate(rules) if 'geosite:category-ru' in r.get('domain', []))
        self.assertLess(ads, ru)
        self.assertEqual(config['dns']['hosts']['geosite:category-ads-all'], '0.0.0.0')
        self.assertEqual(rules[0], {'type': 'field', 'inboundTag': ['dns-direct'], 'outboundTag': 'direct'})
        intercept = next(r for r in rules if r.get('port') == '53')
        self.assertEqual(intercept['outboundTag'], 'dns-out')
        self.assertEqual(intercept['inboundTag'], ['socks-in'])
        self.assertEqual(config['routing']['domainStrategy'], 'IPIfNonMatch')
        self.assertFalse(any(r.get('balancerTag') and not r.get('inboundTag') for r in rules))
        self.assertEqual(config['routing']['balancers'][0]['fallbackTag'], 'Автовыбор')

    def test_all_pool_protocols_are_preserved_and_selected(self):
        config = base_config()
        config['outbounds'].append({'tag': 'pool-03', 'protocol': 'shadowsocks'})
        config['outbounds'].append({'tag': 'pool-04', 'protocol': 'vmess'})
        result = subscription_variants(config)[0]
        proxies = [o for o in result['outbounds'] if o['protocol'] in ('vless','trojan','shadowsocks','vmess')]
        tags = [o['tag'] for o in proxies]
        self.assertEqual([o['protocol'] for o in proxies], ['vless','trojan','shadowsocks','vmess'])
        self.assertEqual(result['routing']['balancers'][0]['selector'], tags)
        self.assertEqual(result['burstObservatory']['subjectSelector'], tags)

    def test_dns_split_has_no_direct_external_fallback_and_bootstraps_pool(self):
        base = base_config()
        base['outbounds'][0]['settings'] = {'vnext': [{'address': 'vpn.fixture-domain.com'}]}
        config = subscription_variants(base)[0]
        self.assertTrue(config['dns']['disableFallbackIfMatch'])
        servers = config['dns']['servers']
        for server in servers[:2]:
            self.assertEqual(server['tag'], 'dns-direct')
            self.assertTrue(server['skipFallback'])
            self.assertIn('full:vpn.fixture-domain.com', server['domains'])
            self.assertTrue(set(read_policy()['direct_domains']).issubset(server['domains']))
        for server in servers[2:]:
            self.assertEqual(server['tag'], 'dns-proxy')
            self.assertTrue(server['address'].startswith('https://'))
            self.assertNotIn('+local', server['address'])
        self.assertEqual(config['routing']['rules'][1],
                         {'type': 'field', 'inboundTag': ['dns-proxy'], 'balancerTag': 'auto'})
        self.assertEqual(build(config, read_policy()), config)

    def test_empty_checked_pool_stops_publication(self):
        base = base_config()
        base['outbounds'] = [{'tag': 'direct', 'protocol': 'freedom'}]
        with self.assertRaises(ValueError):
            subscription_variants(base)
