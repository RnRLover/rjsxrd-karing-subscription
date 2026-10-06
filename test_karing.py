import json
import unittest
from karing import selected_groups, assemble, matchers, incy_subscription, automatic_config, with_fakedns, happ_config, happ_subscription, PUBLIC, PROXY_DNS, client_routing_profile, subscription_variants, RESERVE_DNS
from routing import policy
from geo_dat import geoip, geosite, geoip_cidrs
from generate import diverse_pool


class KaringTests(unittest.TestCase):
    def test_single_profile_matches_export_and_has_geoip_fallback(self):
        from russia_config import build
        from pathlib import Path
        profile = json.loads(Path(__file__).with_name('russia-routing.json').read_bytes())
        base = {'inbounds': [{'tag': 'socks-in'}], 'outbounds': [{'tag': 'pool-01', 'protocol': 'vless'}, {'tag': 'direct', 'protocol': 'freedom'}, {'tag': 'block', 'protocol': 'blackhole'}],
                'routing': {'rules': [], 'balancers': [{'tag': 'auto', 'selector': ['pool-']}]}, 'burstObservatory': {'subjectSelector': ['pool-']}}
        configs = subscription_variants(base)
        self.assertEqual(len(configs), 1)
        c = configs[0]
        self.assertNotIn('fakedns', c)
        self.assertEqual(c['routing']['domainStrategy'], 'IPIfNonMatch')
        self.assertEqual(c['outbounds'][0]['protocol'], 'loopback')
        self.assertFalse(any(r.get('network') == 'tcp,udp' and 'port' not in r for r in c['routing']['rules']))
        self.assertEqual(c['dns']['servers'][-1]['address'], profile['RemoteDNSDomain'])
        self.assertEqual(c['dns']['servers'][1]['address'], '77.88.8.8')
        self.assertEqual(c['routing']['rules'][-2]['domain'], ['geosite:category-ru'])
        self.assertEqual(len(json.loads(incy_subscription(configs).splitlines()[0])), 1)
        self.assertEqual(len(json.loads(happ_subscription(configs))), 1)

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
            [(1, 'Adblock'), (2, 'AdblockPlus')])

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
        self.assertEqual(config['dns']['servers'][-2:], [{'address': address, 'tag': 'dns-proxy'} for address in PROXY_DNS])
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
        self.assertEqual([s['address'] for s in servers], ['fakedns', '8.8.8.8', '8.8.4.4', *PROXY_DNS, '8.8.8.8', '8.8.4.4', *PROXY_DNS])
        self.assertEqual([s['domains'] for s in servers[3:5]], [['geosite:google']] * 2)
        self.assertTrue(all(s['tag'] == 'dns-proxy' and s['skipFallback'] for s in servers[3:5]))
        self.assertEqual(servers[5]['domains'], ['geosite:ru'])
        self.assertEqual(servers[5]['tag'], 'dns-bootstrap')
        self.assertTrue(servers[5]['skipFallback'])
        self.assertEqual(config['routing']['rules'][3:], original['routing']['rules'])
        expanded = happ_config(config, {'google': ['domain:google.test'], 'ru': ['domain:yandex.test']}, {'ru': ['5.0.0.0/8']})
        self.assertEqual(expanded['dns']['servers'][5]['domains'], ['domain:yandex.test'])
        self.assertNotIn('geosite:', happ_subscription(expanded))

    def test_client_profile_uses_documented_domestic_dns_and_retains_routes(self):
        config = {'routing': {'rules': [{'domain': ['geosite:kg01'], 'outboundTag': 'block'}, {'domain': ['domain:yandex.ru'], 'outboundTag': 'direct'}, {'network': 'tcp,udp', 'balancerTag': 'auto'}]}}
        profile = client_routing_profile(config)
        self.assertFalse(any(key.startswith('DomesticDNS') for key in profile))
        self.assertEqual(profile['RemoteDNSType'], 'DoU')
        self.assertEqual(profile['RemoteDNSIP'], PROXY_DNS[0])
        self.assertEqual(profile['RemoteDNSDomain'], '')
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
        self.assertNotIn('hosts', result['dns'])
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

    def test_only_three_groups_no_legacy_ru_or_local_routes(self):
        profile = {'rules': [{'name': 'Ads', 'rule_set': ['geosite:category-ads'], 'outbound': 'block', 'switch': False},
                             {'name': 'Apple', 'rule_set': ['apple'], 'outbound': 'direct', 'switch': True}]}
        lists = {'geosite:category-ads': {'version': 1, 'rules': [{'domain_suffix': ['ads.test']}]}}
        def export(domain, cidr):
            return {'version': 1, 'rules': [{'domain_suffix': [domain], 'domain': [domain]}, {'ip_cidr': [cidr]}]}
        cck = {'cckproxy': export('overlap.test', '192.0.2.0/24'),
               'cckbeta': export('beta.test', '2001:db8::/32'),
               'cckdirect': export('overlap.test', '192.0.2.0/24')}
        old = {'routing': policy(['domain:legacy.ru'], ['5.0.0.0/8']), 'outbounds': []}
        config, sites, ips, groups = assemble(profile, lists, old, cck)
        rules = config['routing']['rules']
        self.assertEqual([g['action'] for g in groups], ['block', 'proxy', 'direct'])
        self.assertEqual([r.get('ruleTag') for r in rules], ['ads-sites', 'cckproxy-sites', 'cckproxy-ips', 'cckdirect-sites', 'cckdirect-ips', None])
        self.assertEqual(rules[-1]['balancerTag'], 'auto')
        self.assertTrue(all(not ('ip' in r and 'domain' in r) for r in rules))
        self.assertNotIn('geoip:ru', json.dumps(config))
        self.assertNotIn('legacy.ru', json.dumps(config))
        self.assertNotIn('10.0.0.0/8', json.dumps(config))
        self.assertEqual(sites['cckproxy'], ['domain:beta.test', 'domain:overlap.test'])
        self.assertEqual(client_routing_profile(config)['DirectIp'], ['geoip:cckdirect'])
        self.assertEqual(old['routing']['rules'][0]['ip'][0], '10.0.0.0/8')

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
