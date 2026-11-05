import copy
import json
import unittest
from pathlib import Path
from pool_selection import node_key, select_pool
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

    def test_changed_credentials_have_a_distinct_identity(self):
        original = node('a')
        changed = copy.deepcopy(original)
        changed['outbound']['settings']['servers'][0]['password'] = 'different'
        self.assertNotEqual(node_key(original), node_key(changed))

    def test_size_trimming_keeps_common_pool_and_client_dns(self):
        from russia_config import build
        root = Path(__file__).parent
        original = build(json.loads((root / 'ru.json').read_bytes()),
                         json.loads((root / 'routing-policy.json').read_bytes()))
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
        self.assertEqual(len(variants), 1)
        for v in variants:
            self.assertLessEqual(len(json.dumps(v, ensure_ascii=False, separators=(',', ':')).encode('utf-16-le')) + 2, 240000)
            tags = {o['tag'] for o in v['outbounds'] if o['protocol'] in ('vless','vmess','trojan','shadowsocks')}
            groups = v['routing']['balancers'][1:]
            self.assertEqual({tag for group in groups for tag in group['selector']}, tags)
            routes = {o['tag'] for o in v['outbounds']
                      if o['protocol'] == 'loopback' and o['tag'] != 'default-proxy'}
            self.assertEqual(set(v['routing']['balancers'][0]['selector']), routes)
            self.assertEqual(set(v['burstObservatory']['subjectSelector']), tags | routes)
        self.assertIn('dns', trimmed)
        for variant in variants:
            self.assertIn('dns', variant)
            self.assertTrue(any(o.get('protocol') == 'dns' for o in variant['outbounds']))



if __name__ == '__main__':
    unittest.main()
