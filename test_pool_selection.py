import copy
import json
import unittest
from pathlib import Path
from generate import CountryRanges
from pool_selection import node_key, select_pool, recent_exit
from publication_changed import canonical
from karing import fit_client_pool


def node(host, protocol='trojan', network='tcp'):
    return {'host': host, 'outbound': {'tag': 'pool-01', 'protocol': protocol,
        'settings': {'servers': [{'address': host, 'port': 443, 'password': 'test'}]},
        'streamSettings': {'network': network, 'security': 'tls'}}}


class PoolTests(unittest.TestCase):
    def test_source_reordering_and_duplicates_do_not_change_pool(self):
        nodes = [node('a'), node('b'), node('c')]
        lookup = lambda host: host
        a = select_pool(nodes, 2, network_lookup=lookup)
        b = select_pool(list(reversed(nodes)) + [nodes[0]], 2, network_lookup=lookup)
        self.assertEqual(a, b)

    def test_distinct_networks_before_same_host_alternatives(self):
        nodes = [node('a'), node('a', network='ws'), node('b'), node('c')]
        chosen = select_pool(nodes, 2, network_lookup=lambda host: 'net1' if host in ('a', 'b') else 'net2')
        self.assertIn('c', [n['host'] for n in chosen])
        self.assertEqual(len({n['host'] for n in chosen}), 2)

    def test_previous_membership_and_order_win_equal_diversity_ties(self):
        a, b, c = node('a'), node('b'), node('c')
        keys = [node_key(b), node_key(a)]
        chosen = select_pool([c, a, b], 2, keys, lambda host: 'same-network')
        self.assertEqual([node_key(n) for n in chosen], keys)

    def test_exit_cache_rejects_ru_expired_and_nonpublic(self):
        n = node('a'); ranges = CountryRanges(['5.0.0.0/8'])
        for ip, timestamp in [('5.1.1.1', 99), ('127.0.0.1', 99), ('8.8.8.8', 0)]:
            self.assertIsNone(recent_exit(n, {node_key(n): {'exit_ip': ip, 'verified_at': timestamp}}, 100, ranges, ttl=50))
        self.assertEqual(recent_exit(n, {node_key(n): {'exit_ip': '8.8.8.8', 'verified_at': 99}}, 100, ranges)['exit_ip'], '8.8.8.8')
        changed = copy.deepcopy(n); changed['outbound']['settings']['servers'][0]['password'] = 'different'
        self.assertNotEqual(node_key(n), node_key(changed))

    def test_only_routing_timestamp_is_ignored_for_publication(self):
        a = {'LastUpdated': '1', 'RemoteDNSIP': '8.8.8.8'}
        b = {**a, 'LastUpdated': '2'}
        self.assertEqual(canonical('karing-routing.json', json.dumps(a).encode()), canonical('karing-routing.json', json.dumps(b).encode()))
        b['RemoteDNSIP'] = '8.8.4.4'
        self.assertNotEqual(canonical('karing-routing.json', json.dumps(a).encode()), canonical('karing-routing.json', json.dumps(b).encode()))

    def test_size_trimming_keeps_identical_pools_and_dns_in_two_profiles(self):
        original = json.loads((Path(__file__).parent / 'ru-karing.json').read_bytes())
        proxies = [o for o in original['outbounds'] if o.get('tag', '').startswith('pool-')]
        self.assertTrue(proxies)
        original['outbounds'] = [o for o in original['outbounds'] if o not in proxies]
        for i in range(150):
            ob = copy.deepcopy(proxies[i % len(proxies)]); ob['tag'] = f'pool-{i:04d}'
            # Force the size boundary regardless of the current routing size.
            ob['remarks'] = 'size-test-' + 'x' * 2000
            original['outbounds'].append(ob)
        trimmed, variants = fit_client_pool(original)
        self.assertLess(len(trimmed['outbounds']), len(original['outbounds']))
        self.assertEqual(variants[0]['outbounds'][0]['protocol'], variants[1]['outbounds'][0]['protocol'])
        for v in variants:
            self.assertLessEqual(len(json.dumps(v, ensure_ascii=False, separators=(',', ':')).encode('utf-16-le')) + 2, 240000)
            tags = {o['tag'] for o in v['outbounds'] if o['protocol'] in ('vless','vmess','trojan','shadowsocks')}
            self.assertEqual(set(v['routing']['balancers'][0]['selector']), tags)
            self.assertEqual(set(v['burstObservatory']['subjectSelector']), tags)
        for variant, expected in zip(variants, ({'8.8.8.8','8.8.4.4'}, {'77.88.8.8','77.88.8.1'})):
            self.assertEqual({s['address'] for s in variant['dns']['servers'] if s.get('tag') == 'dns-bootstrap'}, expected)
            self.assertEqual({s['address'] for s in variant['dns']['servers'] if s.get('tag') == 'dns-proxy'}, {'8.8.8.8','8.8.4.4'})


if __name__ == '__main__':
    unittest.main()
