import json
import unittest
from karing import selected_groups, assemble, matchers, incy_subscription, automatic_config, with_fakedns, happ_config, happ_subscription, PUBLIC, REMOTE_DOH, client_routing_profile, subscription_variants, RESERVE_DNS
from routing import policy
from geo_dat import geoip, geosite, geoip_cidrs
from generate import diverse_pool, premium_pool, CountryRanges


class KaringTests(unittest.TestCase):
    def test_three_profiles_share_main_reserve_pool_but_not_dns(self):
        def base(count):
            return {'inbounds': [], 'outbounds': [{'tag': f'pool-{i:02d}', 'protocol': 'vless',
                'settings': {'vnext': [{'address': 'entry.example', 'port': 443}]}} for i in range(1, count + 1)],
                'routing': {'rules': [{'domain': ['domain:example.ru'], 'outboundTag': 'direct'},
                {'network': 'tcp,udp', 'balancerTag': 'auto'}], 'balancers': [{'tag': 'auto', 'selector': ['pool-']}]},
                'burstObservatory': {'subjectSelector': ['pool-']}}
        configs = subscription_variants(base(3), base(1))
        self.assertEqual([c['remarks'] for c in configs], ['Основной', 'Резерв', 'Премиум'])
        self.assertEqual([len(c['outbounds']) for c in configs], [4, 4, 2])
        self.assertEqual([o['settings'] for o in configs[0]['outbounds'] if 'settings' in o],
                         [o['settings'] for o in configs[1]['outbounds'] if 'settings' in o])
        for config, dns in zip(configs, [['8.8.8.8', '8.8.4.4'], RESERVE_DNS, ['8.8.8.8', '8.8.4.4']]):
            direct = [s for s in config['dns']['servers'] if s.get('tag') == 'dns-bootstrap']
            self.assertEqual(sorted({s['address'] for s in direct}), sorted(dns))
            self.assertTrue(all('full:entry.example' in s['domains'] for s in direct[:2]))
            self.assertEqual(config['dns']['servers'][-1], {'address': REMOTE_DOH, 'tag': 'dns-proxy'})
        self.assertEqual(len(json.loads(incy_subscription(configs).splitlines()[0])), 3)
        self.assertEqual(len(json.loads(happ_subscription(configs))), 3)

    def test_premium_uses_verified_exit_not_flag_or_entry_ip(self):
        ranges = CountryRanges(['8.8.8.0/24'])
        nodes = [{'id': 1, 'label': 'US', 'host': '8.8.8.8', 'exit_ip': '5.5.5.5', 'outbound': {'protocol': 'vless'}},
            {'id': 2, 'label': 'RU', 'host': '5.5.5.5', 'exit_ip': '8.8.8.8', 'outbound': {'protocol': 'vless'}},
            {'id': 3, 'label': 'US', 'outbound': {'protocol': 'trojan'}}]
        self.assertEqual([n['id'] for n in premium_pool(nodes, ranges, 24)], [2])
        with self.assertRaisesRegex(ValueError, 'no verified US exits'):
            premium_pool(nodes[:1], ranges, 24)
        with self.assertRaisesRegex(ValueError, 'US address table required'):
            premium_pool(nodes, CountryRanges([]), 24)

    def test_selection_retains_ads_and_direct_but_rejects_proxy_and_malware(self):
        specifications = [('Adblock', 'block', 'geosite:category-ads'),
            ('AdblockPlus', 'block', 'acl:BanProgramAD'),
            ('Malware', 'block', 'geosite:malware'),
            ('Google', 'currentSelected', 'geosite:google'),
            ('OneDrive', 'direct', 'geosite:onedrive'),
            ('Apple', 'direct', 'geosite:apple'),
            ('Anticensor', 'currentSelected', 'geosite:blocked@ru')]
        profile = {'rules': [{'name': name, 'outbound': action, 'rule_set': [ref], 'switch': False}
            for name, action, ref in specifications]}
        self.assertEqual([(number, group['name']) for number, group in selected_groups(profile)],
            [(1, 'Adblock'), (2, 'AdblockPlus'), (5, 'OneDrive'), (6, 'Apple')])

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
        self.assertEqual(config['dns']['servers'][0], {'address': 'fakedns', 'domains': ['regexp:.*']})
        self.assertEqual(config['dns']['servers'][-1], {'address': REMOTE_DOH, 'tag': 'dns-proxy'})
        self.assertEqual(config['routing']['rules'][3:], original['routing']['rules'])
        self.assertFalse(config['inbounds'][0]['sniffing']['routeOnly'])
        self.assertIn('fakedns', config['inbounds'][0]['sniffing']['destOverride'])
        self.assertEqual(config['routing']['rules'][0], {'type': 'field', 'inboundTag': ['dns-proxy'], 'balancerTag': 'auto'})
        self.assertEqual(config['routing']['rules'][1]['inboundTag'], ['dns-bootstrap'])
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

    def test_direct_dns_uses_google_without_overriding_prior_proxy_domain(self):
        original = {'inbounds': [], 'outbounds': [{'tag': 'direct', 'protocol': 'freedom'}, {'tag': 'pool-01', 'protocol': 'vless'}], 'routing': {'rules': [
            {'domain': ['geosite:google'], 'balancerTag': 'auto'},
            {'domain': ['geosite:ru'], 'outboundTag': 'direct'},
            {'ip': ['geoip:ru'], 'outboundTag': 'direct'},
            {'network': 'tcp,udp', 'balancerTag': 'auto'}]}}
        config = with_fakedns(original)
        servers = config['dns']['servers']
        self.assertEqual([s['address'] for s in servers[:-1]], ['fakedns', '8.8.8.8', '8.8.4.4', REMOTE_DOH, '8.8.8.8', '8.8.4.4'])
        self.assertEqual(servers[3]['domains'], ['geosite:google'])
        self.assertEqual(servers[3]['tag'], 'dns-proxy')
        self.assertEqual(servers[4]['domains'], ['geosite:ru'])
        self.assertEqual(servers[4]['tag'], 'dns-bootstrap')
        self.assertTrue(servers[4]['skipFallback'])
        self.assertEqual(config['routing']['rules'][3:], original['routing']['rules'])
        expanded = happ_config(config, {'google': ['domain:google.test'], 'ru': ['domain:yandex.test']}, {'ru': ['5.0.0.0/8']})
        self.assertEqual(expanded['dns']['servers'][4]['domains'], ['domain:yandex.test'])
        self.assertNotIn('geosite:', happ_subscription(expanded))

    def test_client_profile_uses_documented_domestic_dns_and_retains_routes(self):
        config = {'routing': {'rules': [{'domain': ['geosite:kg01'], 'outboundTag': 'block'}, {'domain': ['domain:yandex.ru'], 'outboundTag': 'direct'}, {'network': 'tcp,udp', 'balancerTag': 'auto'}]}}
        profile = client_routing_profile(config)
        self.assertFalse(any('DNS' in key and key != 'FakeDNS' for key in profile))
        self.assertFalse(any(key.startswith('LocalDNS') for key in profile))
        self.assertEqual(profile['BlockSites'], ['geosite:kg01'])
        self.assertEqual(profile['DirectSites'], ['domain:yandex.ru'])
        self.assertEqual(profile['FakeDNS'], 'true')
        self.assertTrue(profile['Geoipurl'].endswith('.dat'))

    def test_proxy_entry_and_observatory_dns_do_not_depend_on_balancer(self):
        config = {'inbounds': [], 'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{'address': 'entry.example', 'port': 443}]}}], 'routing': {'rules': []}}
        result = with_fakedns(config)
        bootstrap = result['dns']['servers'][1:3]
        self.assertTrue(all('full:entry.example' in s['domains'] and 'full:www.gstatic.com' in s['domains'] and s['tag'] == 'dns-bootstrap' and s['skipFallback'] for s in bootstrap))
        self.assertEqual(result['dns']['hosts'], {'dns.google': '8.8.8.8'})
        self.assertEqual(result['outbounds'][0]['streamSettings']['sockopt']['domainStrategy'], 'UseIPv4')

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
            {'name': 'Anticensor', 'rule_set': ['geosite:blocked@ru', 'geoip:blocked@ru'], 'outbound': 'currentSelected', 'switch': True},
        ]}
        lists = {name: {'version': 1, 'rules': [{'domain_suffix': [name + '.test'], 'ip_cidr': ['1.2.3.0/24']}]} for name in ('ads', 'google', 'onedrive')}
        lists['geosite:blocked@ru'] = {'version': 1, 'rules': [{'domain_suffix': ['blocked.ru']}]}
        lists['geoip:blocked@ru'] = {'version': 1, 'rules': [{'ip_cidr': ['5.1.0.0/16']}]}
        # Removed groups need no downloaded lists at all.
        del lists['ads'], lists['google']
        old = {'routing': policy(['domain:example.ru'], ['5.0.0.0/8']), 'outbounds': [{'tag': 'pool-01'}]}
        config, sites, ips, groups = assemble(profile, lists, old)
        rules = config['routing']['rules']
        self.assertEqual([r['ruleTag'] for r in rules if 'ruleTag' in r], ['kg03-sites', 'kg03-ips'])
        self.assertTrue(all(not ('ip' in rule and 'domain' in rule) for rule in rules))
        self.assertEqual(rules[-3:-1], old['routing']['rules'][-3:-1])
        self.assertEqual(sum(r.get('ip') == ['geoip:ru'] for r in rules), 1)
        self.assertEqual(rules[-1]['network'], 'tcp,udp')
        self.assertEqual(rules[1]['outboundTag'], 'direct')
        self.assertEqual([g['name'] for g in groups], ['OneDrive'])
        self.assertEqual(sum('balancerTag' in r for r in rules), 1)
        self.assertTrue(all(g['enabled'] for g in groups))
        self.assertEqual(len(old['routing']['rules']), 4)

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
