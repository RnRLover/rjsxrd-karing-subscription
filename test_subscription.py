import copy
from pathlib import Path
import tempfile
import unittest

from generate import (collect_nodes, exclude_listed, parse_node, select_per_technology,
                      technology_report)
from incy import (CLOUDFLARE_DOH, CLOUDFLARE_UDP, YANDEX_DOH,
                  BLOCK_DOMAINS, PROXY_DOMAINS, DIRECT_DOMAINS, DIRECT_IPS,
                  PROXY_PROTOCOLS, build, load_configs,
                  serialized_config, subscription)

UUID = '123e4567-e89b-12d3-a456-426614174000'
URI = f'vless://{UUID}@1.1.1.1:443?security=reality&pbk={"A" * 43}&sni=example.com&type=tcp#test'


class SubscriptionTests(unittest.TestCase):
    def test_source_order_and_distinct_transport_options_survive(self):
        grpc = URI.replace('type=tcp', 'type=grpc&serviceName=one')
        nodes, counts = collect_nodes('\n'.join([grpc, URI, grpc]))
        self.assertEqual([n['outbound']['streamSettings']['network'] for n in nodes], ['grpc', 'tcp'])
        self.assertEqual(counts['duplicate'], 1)
        self.assertEqual(nodes[0]['outbound']['streamSettings']['grpcSettings']['serviceName'], 'one')

    def test_hysteria_preserves_auth_sni_and_salamander(self):
        node = parse_node('hysteria2://secret@node.example:443?sni=tls.example&obfs=salamander&obfs-password=mask')
        ob = node['outbound']
        self.assertEqual(ob['protocol'], 'hysteria')
        self.assertEqual(ob['settings'], {'version': 2, 'address': 'node.example', 'port': 443})
        self.assertEqual(ob['streamSettings']['hysteriaSettings']['auth'], 'secret')
        self.assertEqual(ob['streamSettings']['tlsSettings']['serverName'], 'tls.example')
        self.assertEqual(ob['streamSettings']['finalmask']['udp'][0]['settings']['password'], 'mask')

    def test_xhttp_and_httpupgrade_are_not_silently_converted_to_tcp(self):
        for network, key in [('xhttp', 'xhttpSettings'), ('httpupgrade', 'httpupgradeSettings')]:
            ob = parse_node(URI.replace('type=tcp', f'type={network}&path=%2Fhello&host=edge.example'))['outbound']
            self.assertEqual(ob['streamSettings']['network'], network)
            self.assertEqual(ob['streamSettings'][key]['path'], '/hello')
            self.assertEqual(ob['streamSettings'][key]['host'], 'edge.example')

    def test_filter_does_not_remove_unknown_failed_or_russian_exits(self):
        nodes = [{'host': str(i), 'exit_ip': ip, 'reputation': {'status': status}}
                 for i, (ip, status) in enumerate([(None, 'unknown'), ('77.88.8.8', 'not_listed'),
                                                  ('9.9.9.9', 'listed'), ('::1', 'unknown')])]
        self.assertEqual(exclude_listed(nodes), [nodes[0], nodes[1], nodes[3]])
        nodes[0]['entry_reputation'] = [{'ip': '1.1.1.1', 'status': 'listed'}]
        self.assertEqual(exclude_listed(nodes), [nodes[1], nodes[3]])

    def test_three_first_eligible_nodes_per_technology_share_one_balancer(self):
        uris = []
        for i in range(5):
            tcp = URI.replace('1.1.1.1', f'node{i}.example')
            uris.extend([tcp, tcp, tcp.replace('type=tcp', 'type=xhttp')])
        uris.append('hy2://secret@hy.example:443?sni=hy.example')
        nodes, counts = collect_nodes('\n'.join(uris))
        self.assertEqual(counts['duplicate'], 5)
        nodes[0]['entry_reputation'] = [{'status': 'listed'}]
        nodes[1]['reputation'] = {'status': 'listed'}
        nodes[2]['exit_ip'] = None
        nodes[2]['reputation'] = {'status': 'unknown'}
        nodes[2]['exit_discovery_error'] = 'TimeoutError'
        eligible = exclude_listed(nodes)
        selected = select_per_technology(eligible, 3)
        self.assertEqual(selected, nodes[2:8] + [nodes[-1]])
        config = build(selected)
        proxies = [o for o in config['outbounds'] if o['protocol'] in PROXY_PROTOCOLS]
        self.assertEqual(len(config['routing']['balancers']), 1)
        self.assertEqual(config['routing']['balancers'][0]['selector'], ['proxy-'])
        report = technology_report(eligible, selected, 3)
        self.assertEqual([g['selected'] for g in report['groups']], [3, 3, 1])
        self.assertEqual([g['eligible'] for g in report['groups']], [4, 4, 1])
        self.assertEqual(report['groups'][0]['tags'], ['proxy-0', 'proxy-2', 'proxy-4'])

    def test_security_variants_have_separate_quotas_and_invalid_limits_fail(self):
        reality = [parse_node(URI.replace(':443?', f':{1000+i}?')) for i in range(4)]
        tls = [parse_node(URI.replace('security=reality', 'security=tls').replace(':443?', f':{2000+i}?'))
               for i in range(4)]
        self.assertEqual(select_per_technology(reality + tls, 3), reality[:3] + tls[:3])
        for limit in [0, -1, 2.5, True, '3']:
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                select_per_technology(reality, limit)

    def test_builder_preserves_all_supplied_nodes_without_an_additional_cap(self):
        nodes = [parse_node(URI.replace(':443?', f':{1000+i}?')) for i in range(400)]
        before = copy.deepcopy(nodes)
        config = build(nodes)
        proxies = [o for o in config['outbounds'] if o['protocol'] in PROXY_PROTOCOLS]
        self.assertEqual(len(proxies), 400)
        self.assertEqual([o['settings']['vnext'][0]['port'] for o in proxies], list(range(1000, 1400)))
        self.assertEqual(nodes, before)
        self.assertEqual(config['routing']['balancers'][0]['fallbackTag'], proxies[0]['tag'])
        self.assertEqual(config['routing']['balancers'][0]['selector'], ['proxy-'])
        self.assertEqual(config['burstObservatory']['pingConfig']['sampling'], 2)
        self.assertEqual(config['burstObservatory']['pingConfig']['interval'], '5m')
        serialized_config(config)

    def test_reference_policy_includes_the_exact_original_dns(self):
        config = build([parse_node(URI)])
        direct = [r for r in config['routing']['rules'] if r.get('outboundTag') == 'direct']
        self.assertTrue(any(r.get('domain') == list(DIRECT_DOMAINS) for r in direct))
        self.assertTrue(any(r.get('ip') == list(DIRECT_IPS) for r in direct))
        self.assertEqual(config['routing']['domainStrategy'], 'AsIs')
        self.assertEqual(config['routing']['rules'][-1]['balancerTag'], 'balancer')
        self.assertEqual(config['dns']['queryStrategy'], 'UseIPv4')
        self.assertEqual(config['dns']['servers'], [
            {'address': YANDEX_DOH, 'domains': ['geosite:category-ru', 'geosite:category-gov-ru']},
            {'address': CLOUDFLARE_DOH, 'skipFallback': False},
            {'address': CLOUDFLARE_UDP, 'skipFallback': False}])
        self.assertNotIn('hosts', config['dns'])
        self.assertNotIn('tag', config['dns'])
        for removed in ['adguard', '94.140.14.14', 'dns.google', 'geosite:github']:
            self.assertNotIn(removed, serialized_config(config))
        self.assertFalse(any(o['protocol'] == 'loopback' for o in config['outbounds']))
        self.assertNotIn('fakedns', config)
        direct_out = next(o for o in config['outbounds'] if o['tag'] == 'direct')
        self.assertEqual(direct_out['settings']['domainStrategy'], 'UseIPv4')
        rules = config['routing']['rules']
        self.assertEqual(rules[0]['domain'], list(BLOCK_DOMAINS))
        self.assertEqual(rules[1]['protocol'], ['bittorrent'])
        self.assertEqual(rules[2]['domain'], list(PROXY_DOMAINS))
        self.assertFalse(any(o['protocol'] == 'dns' for o in config['outbounds']))

    def test_reference_has_no_custom_dns_bootstrap_and_retains_hysteria(self):
        nodes = [parse_node(URI.replace('1.1.1.1', 'vpn.example')),
                 parse_node('hy2://secret@hy.example:443?sni=hy.example')]
        config = build(nodes)
        public_dns = [s for s in config['dns']['servers'] if s['address'] != 'localhost']
        self.assertEqual(public_dns[-1]['address'], CLOUDFLARE_UDP)
        self.assertFalse(any(r.get('inboundTag') == ['dns-remote'] for r in config['routing']['rules']))
        self.assertNotIn('hosts', config['dns'])
        self.assertEqual(config['routing']['balancers'][0]['selector'], ['proxy-'])
        self.assertTrue(any(o['protocol'] == 'hysteria' for o in config['outbounds']))

    def test_fallback_and_costs_follow_the_actual_pool_without_stale_reference_tags(self):
        nodes = [parse_node(URI.replace('1.1.1.1', f'node{i}.example')) for i in range(3)]
        config = build(nodes)
        b = config['routing']['balancers'][0]
        self.assertEqual(b['strategy']['type'], 'leastLoad')
        self.assertEqual(b['fallbackTag'], 'proxy-0')
        self.assertEqual(b['strategy']['settings']['costs'], [
            {'match': '^proxy-1$', 'regexp': True, 'value': 2},
            {'match': '^proxy-2$', 'regexp': True, 'value': 2}])
        self.assertEqual(build(nodes[:1])['routing']['balancers'][0]['strategy']['settings']['costs'], [])

    def test_ordinary_vision_and_server_specific_transport_parameters_survive(self):
        node = parse_node(URI + '&flow=xtls-rprx-vision')
        node['outbound']['settings']['vnext'][0]['users'][0]['flow'] = 'xtls-rprx-vision-udp443'
        before = copy.deepcopy(node)
        ob = build([node])['outbounds'][0]
        self.assertEqual(ob['settings']['vnext'][0]['users'][0]['flow'], 'xtls-rprx-vision')
        self.assertEqual(ob['settings']['vnext'][0]['address'], '1.1.1.1')
        self.assertEqual(ob['settings']['vnext'][0]['users'][0]['id'], UUID)
        self.assertEqual(ob['streamSettings']['realitySettings']['publicKey'], 'A' * 43)
        self.assertEqual(ob['streamSettings']['sockopt']['domainStrategy'], 'UseIPv4')
        self.assertEqual(node, before)
        xhttp = parse_node(URI.replace('type=tcp', 'type=xhttp&path=%2Fown-path&host=own.example'))
        ob = build([xhttp])['outbounds'][0]
        self.assertEqual(ob['streamSettings']['xhttpSettings']['path'], '/own-path')
        self.assertEqual(ob['streamSettings']['xhttpSettings']['host'], 'own.example')
        self.assertEqual(ob['streamSettings']['xhttpSettings']['mode'], 'stream-up')

    def test_delivery_keeps_one_full_config_without_routing_profile_commands(self):
        config = build([parse_node(URI)])
        body = subscription(config)
        self.assertNotIn('incy://', body)
        self.assertNotIn('routing-geo-update-interval', body)
        self.assertIn('#profile-title: rjsxrd · INCY', body)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'subscription.json')
            path.write_text(body)
            self.assertEqual(load_configs(path), [config])
            for command in ['happ://routing/onadd/unexpected',
                            'incy://autorouting/onadd/https://example.com/routing.json']:
                path.write_text(body + command + '\n')
                with self.assertRaises(ValueError):
                    load_configs(path)

    def test_oversized_and_empty_pools_fail_without_truncation(self):
        with self.assertRaises(ValueError):
            build([])
        with self.assertRaises(ValueError):
            serialized_config({'oversized': 'x' * 400_001})


if __name__ == '__main__':
    unittest.main()
