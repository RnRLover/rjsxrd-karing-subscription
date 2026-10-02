import json
import unittest
from karing import assemble, matchers, incy_subscription, PUBLIC
from routing import policy
from geo_dat import geoip, geosite


class KaringTests(unittest.TestCase):
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
