import json
import unittest
from karing import assemble, matchers, incy_subscription, automatic_config, with_fakedns, happ_config, happ_subscription, PUBLIC
from routing import policy
from geo_dat import geoip, geosite, geoip_cidrs
from generate import diverse_pool


class KaringTests(unittest.TestCase):
    def test_sampling_does_not_starve_protocols_late_in_source(self):
        nodes = [{'outbound': {'protocol': protocol}, 'id': i} for i, protocol in enumerate(['vless'] * 90 + ['shadowsocks'] * 2 + ['trojan'])]
        sample = diverse_pool(nodes, 6)
        self.assertEqual([n['id'] for n in sample], [0, 90, 92, 1, 91, 2])
        self.assertEqual(len(diverse_pool(nodes, 100)), 93)
        self.assertEqual(diverse_pool([], 24), [])

    def test_single_auto_pool_keeps_all_protocols_and_routing(self):
        config = {'inbounds': [], 'outbounds': [{'tag': 'block', 'protocol': 'blackhole'}, {'tag': 'pool-01', 'protocol': 'vless'}, {'tag': 'pool-02', 'protocol': 'trojan'}, {'tag': 'pool-03', 'protocol': 'vless'}, {'tag': 'direct', 'protocol': 'freedom'}], 'routing': {'rules': [{'ip': ['geoip:ru'], 'outboundTag': 'direct'}, {'network': 'tcp,udp', 'balancerTag': 'auto'}], 'balancers': [{'tag': 'auto', 'selector': ['pool-'], 'fallbackTag': 'block', 'strategy': {'type': 'leastPing'}}]}, 'burstObservatory': {'subjectSelector': ['pool-'], 'pingConfig': {'interval': '30s'}}}
        variant = automatic_config(config)
        self.assertEqual(variant['routing']['rules'], config['routing']['rules'])
        proxies = [o for o in variant['outbounds'] if o['protocol'] not in ('blackhole', 'freedom')]
        self.assertEqual([o['protocol'] for o in proxies], ['vless', 'trojan', 'vless'])
        self.assertEqual(variant['routing']['balancers'][0]['selector'], [o['tag'] for o in proxies])
        self.assertEqual(variant['burstObservatory']['subjectSelector'], [o['tag'] for o in proxies])
        self.assertEqual(config['outbounds'][1]['tag'], 'pool-01')
        self.assertIsInstance(json.loads(incy_subscription(variant).splitlines()[0]), dict)

    def test_happ_is_complete_json_with_fakedns_and_no_asset_dependency(self):
        original = {'inbounds': [{'tag': 'socks-in', 'sniffing': {'destOverride': ['tls'], 'routeOnly': True}}], 'outbounds': [{'tag': 'direct', 'protocol': 'freedom'}], 'routing': {'rules': [{'ip': ['geoip:ru'], 'outboundTag': 'direct'}, {'network': 'tcp,udp', 'balancerTag': 'auto'}]}}
        config = with_fakedns(original)
        self.assertEqual(config['routing']['rules'][2:], original['routing']['rules'])
        self.assertFalse(config['inbounds'][0]['sniffing']['routeOnly'])
        self.assertIn('fakedns', config['inbounds'][0]['sniffing']['destOverride'])
        self.assertEqual(config['routing']['rules'][0]['inboundTag'], ['dns-bootstrap'])
        config['outbounds'].insert(0, {'tag': 'block', 'protocol': 'blackhole'})
        config['outbounds'].append({'tag': 'Автовыбор', 'protocol': 'vless'})
        config['routing']['rules'].insert(2, {'domain': ['geosite:kg01'], 'outboundTag': 'block'})
        expanded = happ_config(config, {'kg01': ['full:ads.test']}, {'ru': ['192.0.2.0/24']})
        body = happ_subscription(expanded)
        # Parse the WHOLE response, not just its first line (the old bug).
        self.assertEqual(json.loads(body), [expanded])
        self.assertEqual(expanded['outbounds'][0]['protocol'], 'vless')
        self.assertEqual(expanded['routing']['rules'][2]['domain'], ['full:ads.test'])
        self.assertEqual(expanded['routing']['rules'][-2]['ip'], ['192.0.2.0/24'])
        self.assertEqual(expanded['routing']['rules'][-1], config['routing']['rules'][-1])
        self.assertNotIn('happ://', body)
        self.assertNotIn('geoip:', body)
        self.assertNotIn('geosite:', body)
        self.assertNotIn('dns', original)

    def test_happ_refuses_missing_categories(self):
        config = {'outbounds': [{'protocol': 'vless'}], 'routing': {'rules': [{'domain': ['geosite:missing']}]}}
        with self.assertRaisesRegex(ValueError, 'missing inline category'):
            happ_config(config, {}, {})

    def test_geoip_export_preserves_exact_ipv4_ipv6_and_rejects_missing(self):
        values = ['192.0.2.0/24', '2001:db8::/32', '0.0.0.0/0']
        blob = geoip({'other': ['10.0.0.0/8'], 'ru': values})
        self.assertEqual(geoip_cidrs(blob, 'RU'), values)
        with self.assertRaisesRegex(ValueError, 'not found'):
            geoip_cidrs(blob, 'missing')

    def test_incy_transport_preserves_full_config_and_remote_profile(self):
        config = {'inbounds': [], 'outbounds': [], 'routing': {'rules': [{'ip': ['geoip:ru'], 'outboundTag': 'direct'}, {'network': 'tcp,udp', 'balancerTag': 'auto'}], 'balancers': [{'tag': 'auto'}]}, 'burstObservatory': {'subjectSelector': ['pool-']}}
        lines = incy_subscription(config).splitlines()
        self.assertEqual(json.loads(lines[0]), config)
        self.assertEqual(lines[1], '://autorouting/onadd/' + PUBLIC + 'karing-routing.json')
        self.assertEqual(lines[2], '#profile-update-interval: 1')
        # This checks our envelope, not INCY's undocumented mixed-JSON parser.
        self.assertEqual(len(lines), 3)

    def test_profile_order_and_single_ru_tail_are_preserved(self):
        profile = {'rules': [
            {'name': 'Ads', 'rule_set': ['ads'], 'outbound': 'block', 'switch': False},
            {'name': 'Google', 'rule_set': ['google'], 'outbound': 'currentSelected', 'switch': False},
            {'name': 'OneDrive', 'rule_set': ['onedrive'], 'outbound': 'direct', 'switch': False},
        ]}
        lists = {name: {'version': 1, 'rules': [{'domain_suffix': [name + '.test'], 'ip_cidr': ['1.2.3.0/24']}]} for name in ('ads', 'google', 'onedrive')}
        old = {'routing': policy(['domain:example.ru'], ['domain:ad.test'], ['5.0.0.0/8']), 'outbounds': [{'tag': 'pool-01'}]}
        config, sites, ips, groups = assemble(profile, lists, old, {})
        rules = config['routing']['rules']
        self.assertEqual([r['ruleTag'] for r in rules if 'ruleTag' in r], ['kg01-sites', 'kg01-ips', 'kg02-sites', 'kg02-ips', 'kg03-sites', 'kg03-ips'])
        self.assertTrue(all(not ('ip' in rule and 'domain' in rule) for rule in rules))
        self.assertEqual(rules[-3:-1], old['routing']['rules'][-3:-1])
        self.assertEqual(sum(r.get('ip') == ['geoip:ru'] for r in rules), 1)
        self.assertEqual(rules[-1]['network'], 'tcp,udp')
        self.assertEqual(rules[3]['balancerTag'], 'auto')
        self.assertEqual(rules[5]['outboundTag'], 'direct')
        self.assertTrue(all(g['enabled'] for g in groups))
        self.assertEqual(len(old['routing']['rules']), 6)

    def test_no_silent_loss_of_unknown_source_conditions(self):
        with self.assertRaises(ValueError):
            matchers({'version': 1, 'rules': [{'process_name': ['test.exe']}]})
        with self.assertRaises(ValueError):
            matchers({'version': 1, 'rules': []})

    def test_geodata_encodes_canonical_ipv4_and_ipv6(self):
        self.assertEqual(geoip({'TEST': ['1.2.3.4/24']}), geoip({'test': ['1.2.3.0/24']}))
        self.assertIn(bytes.fromhex('20010db8000000000000000000000000'), geoip({'v6': ['2001:db8::/32']}))
        self.assertTrue(geosite({'ads': ['keyword:ad', 'regexp:^ad', 'domain:ad.test', 'full:ad.test']}))


if __name__ == '__main__':
    unittest.main()
