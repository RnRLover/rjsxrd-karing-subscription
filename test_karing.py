import json
import unittest
from karing import common_subscription, automatic_config, subscription_variants


class KaringTests(unittest.TestCase):

    def test_common_config_has_no_dns_or_profile_and_routes_geoip_before_auto(self):
        from russia_config import build
        from pathlib import Path
        profile = json.loads(Path(__file__).with_name('russia-routing.json').read_bytes())
        base = {'inbounds': [{'tag': 'socks-in'}], 'outbounds': [{'tag': 'pool-01', 'protocol': 'vless'}, {'tag': 'direct', 'protocol': 'freedom'}, {'tag': 'block', 'protocol': 'blackhole'}], 'routing': {'rules': [], 'balancers': [{'tag': 'auto', 'selector': ['pool-']}]}, 'burstObservatory': {'subjectSelector': ['pool-']}}
        configs = subscription_variants(base)
        self.assertEqual(len(configs), 1)
        c = configs[0]
        self.assertNotIn('dns', c)
        self.assertNotIn('fakedns', c)
        self.assertEqual(c['geodata'], {
            'cron': '17 */12 * * *',
            'assets': [
                {'url': profile['Geoipurl'], 'file': 'geoip.dat'},
                {'url': profile['Geositeurl'], 'file': 'geosite.dat'},
            ],
        })
        self.assertFalse(any((o.get('protocol') in ('dns', 'loopback') for o in c['outbounds'])))
        self.assertTrue(all((i['sniffing']['routeOnly'] for i in c['inbounds'])))
        self.assertEqual(c['routing']['domainStrategy'], 'IPOnDemand')
        self.assertEqual(c['outbounds'][0]['tag'], 'Основной')
        self.assertEqual(c['routing']['balancers'][0]['fallbackTag'], 'Основной')
        self.assertEqual(c['routing']['rules'][0]['outboundTag'], 'direct')
        self.assertEqual(c['routing']['rules'][0]['port'], '53')
        self.assertEqual(c['routing']['rules'][1]['domain'], ['geosite:category-ads-all'])
        self.assertEqual(c['routing']['rules'][2]['domain'], ['geosite:category-ru'])
        self.assertIn('geoip:ru', c['routing']['rules'][-2]['ip'])
        self.assertEqual(c['routing']['rules'][-1]['balancerTag'], 'auto')
        self.assertEqual(json.loads(common_subscription(configs)), configs)
        self.assertNotIn('DomesticDNS', profile)
        self.assertNotIn('ExternalDNS', profile)

    def test_russia_route_order_applies_to_embedded_rules(self):
        from pathlib import Path
        from russia_config import build
        profile = json.loads(Path(__file__).with_name('russia-routing.json').read_bytes())
        for prefix in ['Block', 'Direct', 'Proxy']:
            profile[prefix + 'Sites'] = ['full:overlap.test']
            profile[prefix + 'Ip'] = ['192.0.2.0/24']
        base = {'inbounds': [], 'outbounds': [], 'routing': {}}
        rules = build(base, profile)['routing']['rules']
        self.assertEqual([r.get('outboundTag', r.get('balancerTag')) for r in rules[1:-1]], ['block', 'block', 'direct', 'direct', 'auto', 'auto'])
        profile['RouteOrder'] = 'proxy-block-direct'
        rules = build(base, profile)['routing']['rules']
        self.assertEqual([r.get('outboundTag', r.get('balancerTag')) for r in rules[1:-1]], ['auto', 'auto', 'block', 'block', 'direct', 'direct'])
        profile['RouteOrder'] = 'direct-direct-proxy'
        with self.assertRaises(ValueError):
            build(base, profile)

    def test_single_auto_pool_keeps_all_protocols_and_routing(self):
        config = {'inbounds': [], 'outbounds': [{'tag': 'block', 'protocol': 'blackhole'}, {'tag': 'pool-01', 'protocol': 'vless'}, {'tag': 'pool-02', 'protocol': 'trojan'}, {'tag': 'pool-03', 'protocol': 'vless'}, {'tag': 'direct', 'protocol': 'freedom'}], 'routing': {'rules': [{'ip': ['geoip:ru'], 'outboundTag': 'direct'}, {'network': 'tcp,udp', 'balancerTag': 'auto'}], 'balancers': [{'tag': 'auto', 'selector': ['pool-'], 'fallbackTag': 'block', 'strategy': {'type': 'leastPing'}}]}, 'burstObservatory': {'subjectSelector': ['pool-'], 'pingConfig': {'interval': '30s'}}}
        variant = automatic_config(config)
        self.assertEqual(variant['routing']['rules'], config['routing']['rules'])
        proxies = [o for o in variant['outbounds'] if o['protocol'] not in ('blackhole', 'freedom')]
        self.assertEqual([o['protocol'] for o in proxies], ['vless', 'trojan', 'vless'])
        self.assertEqual(variant['routing']['balancers'][0]['selector'], [o['tag'] for o in proxies])
        self.assertEqual(variant['burstObservatory']['subjectSelector'], [o['tag'] for o in proxies])
        self.assertEqual(config['outbounds'][1]['tag'], 'pool-01')
        self.assertEqual(json.loads(common_subscription(variant)), [variant])

    def test_common_subscription_is_pure_json_without_import_commands(self):
        config = {'inbounds': [], 'outbounds': [], 'routing': {'rules': [], 'balancers': [{'tag': 'auto'}]}}
        bodies = [common_subscription([config]), common_subscription(config)]
        self.assertEqual(len(set(bodies)), 1)
        for body in bodies:
            self.assertEqual(json.loads(body), [config])
            self.assertNotIn('://routing/', body)
            self.assertNotIn('://autorouting/', body)
            self.assertNotIn('profile-update-interval', body)


if __name__ == '__main__':
    unittest.main()
