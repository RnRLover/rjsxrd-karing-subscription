"""Exercise changing upstream catalogs, complete coverage and bounded profiles."""
from collections import Counter
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from catalog import build_catalog, country_key
from generate import parse_node
from incy import load_configs, proxy_outbound, serialized_config, subscription

OPTIONS = {'auto_max_nodes': 64, 'auto_max_per_exit': 2}
COUNTRIES = ('DE NL FI FR ES SE GB PL KZ AT TR US CZ LT AM AE BY SG BG BE CH LV EE MD IN '
             'RO NO IT AL AU CA CN HK IR JP KR RU SK UA GE AZ BR AR MX NZ ZA IS PT IE IL').split()
UUID = '123e4567-e89b-12d3-a456-426614174000'


def node(index, country='DE', network='tcp', security='reality'):
    uri = (f'vless://{UUID}@node{index}.example:443?security={security}&pbk={"A" * 43}'
           f'&sni=example.com&type={network}#OUT: {country}')
    return parse_node(uri)


def proxies(config):
    return config['outbounds'][:-2]


class CatalogTests(unittest.TestCase):
    def assert_coverage(self, nodes, configs, report):
        indices = [i for profile in report['profiles'][1:] for i in profile['node_indices']]
        self.assertEqual(Counter(indices), Counter(range(len(nodes))))
        self.assertEqual(report['catalog_nodes_omitted'], 0)
        self.assertLessEqual(len(proxies(configs[0])), OPTIONS['auto_max_nodes'])
        self.assertEqual(len({config['remarks'] for config in configs}), len(configs))
        for config, profile in zip(configs, report['profiles']):
            expected = [proxy_outbound(nodes[i], f'proxy-{j}')
                        for j, i in enumerate(profile['node_indices'])]
            self.assertEqual(proxies(config), expected)  # Credentials/paths stay with their server.
            if profile['kind'] != 'auto':
                self.assertEqual(profile['kind'], 'country')
                self.assertIsNone(profile['technology'])
                self.assertLessEqual(len(serialized_config(config).encode('utf-16-le')),
                                     report['max_config_utf16_bytes'])
            balancer = config['routing']['balancers'][0]
            self.assertIn(balancer['fallbackTag'], {out['tag'] for out in expected})
            self.assertEqual(balancer['selector'], ['proxy-'])
            self.assertEqual(config['burstObservatory']['subjectSelector'], ['proxy-'])
            self.assertFalse(any(out['protocol'] == 'loopback' for out in config['outbounds']))

    def test_ten_countries_grow_to_fifty_then_shrink_with_new_technology(self):
        # One generator/options object; no country list or profile manifest is edited.
        for countries, networks in [(COUNTRIES[:10], ['tcp', 'grpc']),
                                    (COUNTRIES, ['tcp', 'grpc']),
                                    (['NZ', 'ZA'], ['xhttp'])]:
            nodes = [node(i, code, network) for i, (code, network, _) in enumerate(
                (code, network, replica) for code in countries for network in networks for replica in range(5))]
            before = copy.deepcopy(nodes)
            configs, report = build_catalog(nodes, OPTIONS)
            self.assertEqual(report['countries'], list(countries))
            self.assertEqual({key[1] for key in report['technologies']}, set(networks))
            self.assertEqual(len(configs), 1 + len(countries))
            self.assert_coverage(nodes, configs, report)
            self.assertEqual(nodes, before)
            self.assertEqual(build_catalog(nodes, OPTIONS), (configs, report))

    def test_country_has_no_five_or_fifty_node_quota(self):
        nodes = [node(i) for i in range(123)]
        configs, report = build_catalog(nodes, OPTIONS)
        self.assertEqual([p['nodes'] for p in report['profiles']], [1, 123])
        self.assertEqual(report['profiles'][0]['node_indices'], [0])
        self.assertEqual(report['profiles'][1]['node_indices'], list(range(123)))
        self.assert_coverage(nodes, configs, report)
        for config in configs[1:]:
            self.assertEqual(config['routing']['balancers'][0]['strategy']['settings'], {
                'baselines': ['400ms', '800ms'], 'expected': 4, 'maxRTT': '1500ms', 'tolerance': .2})

    def test_mixed_protocols_share_the_same_country_profile(self):
        nodes = [node(i, code) for i, code in enumerate(COUNTRIES)]
        hy = parse_node('hy2://secret@hy.example:443?sni=hy.example#OUT: NL')
        grpc = node(100, 'DE', 'grpc')
        configs, report = build_catalog(nodes + [hy, grpc], {**OPTIONS, 'auto_max_nodes': 4})
        self.assertEqual(report['profiles'][0]['node_indices'], [0, 1, 2, 3])
        countries = {p['country']: p for p in report['profiles'][1:]}
        self.assertEqual(countries['DE']['node_indices'], [0, len(nodes) + 1])
        self.assertEqual(countries['NL']['node_indices'], [1, len(nodes)])
        self.assertEqual(len(configs), 1 + len(COUNTRIES))
        self.assert_coverage(nodes + [hy, grpc], configs, report)

    def test_allowlist_and_ping_rank_nodes_and_countries_before_upstream_ties(self):
        nodes = [node(0, 'US'), node(1, 'DE', 'ws'), node(2, 'US', 'grpc'),
                 node(3, 'FR'), node(4, 'DE')]
        for index, n in enumerate(nodes):
            n['source_order'] = index * 10
            n['quality'] = {'https': {'success_rate': 1, 'median_ms': [300, 100, 200, 20, 50][index],
                                    'jitter_ms': 1}}
            n['allowlist'] = {'priority': 4 if index in (1, 2, 4) else 0}
        configs, report = build_catalog(nodes, OPTIONS)
        self.assertEqual(report['countries'], ['DE', 'US', 'FR'])
        self.assertEqual([p['node_indices'] for p in report['profiles']], [[4, 2, 3], [4, 1], [2, 0], [3]])
        self.assertEqual([p['country_leader_source_position'] for p in report['profiles'][1:]], [41, 21, 31])
        self.assert_coverage(nodes, configs, report)

    def test_equal_priority_uses_original_source_positions_even_if_input_is_shuffled(self):
        nodes = [node(0, 'DE'), node(1, 'FR'), node(2, 'DE', 'grpc'), node(3, 'FR', 'ws')]
        for n, order in zip(nodes, (9, 0, 1, 5)):
            n['source_order'] = order
        configs, report = build_catalog(nodes, OPTIONS)
        self.assertEqual(report['countries'], ['FR', 'DE'])
        self.assertEqual([p['node_indices'] for p in report['profiles']], [[1, 2], [1, 3], [2, 0]])
        self.assertEqual([p['source_positions'] for p in report['profiles'][1:]], [[1, 6], [2, 10]])
        self.assert_coverage(nodes, configs, report)

    def test_only_byte_budget_splits_a_country_and_auto_still_uses_one_leader(self):
        nodes = [node(i, 'DE', 'grpc' if i % 2 else 'tcp') for i in range(123)]
        with patch('incy.MAX_CONFIG_UTF16', 48_000):
            configs, report = build_catalog(nodes, OPTIONS)
            self.assertGreater(len(configs), 2)
            self.assertEqual(report['profiles'][0]['node_indices'], [0])
            self.assertEqual([i for p in report['profiles'][1:] for i in p['node_indices']], list(range(123)))
            self.assertTrue(all(p['country'] == 'DE' for p in report['profiles'][1:]))
            self.assertEqual([p['part'] for p in report['profiles'][1:]], list(range(1, len(configs))))
            self.assert_coverage(nodes, configs, report)
        with patch('incy.MAX_CONFIG_UTF16', 1):
            with self.assertRaisesRegex(ValueError, 'one country node'):
                build_catalog(nodes[:1], OPTIONS)

    def test_source_country_is_conservative_and_understands_explicit_exit(self):
        labels = {'🇷🇺 Russia (сервер) | 🇮🇹 Italy (выход)': None,
                  '🌐 Anycast-IP | 🇩🇪 🇳🇱': None,
                  '🇨🇭 Join Telegram 🇨🇭': 'CH', '🇪🇺 Europe': None,
                  '🇪🇺 🇩🇪 Germany': 'DE', 'no location': None,
                  '[422ms BY BY @source]': 'BY',
                  'IN: RU OUT: DE': 'DE', '🇷🇺 IN: RU | EXIT=NL': 'NL',
                  'OUT: DE EXIT: NL': None}
        for label, expected in labels.items():
            with self.subTest(label=label):
                self.assertEqual(country_key({'label': label}), expected)
        nodes = [node(0), node(1)]
        nodes[1]['label'] = '🌐 Anycast-IP | 🇩🇪 🇳🇱'
        configs, report = build_catalog(nodes, OPTIONS)
        self.assertEqual(report['unknown_country_nodes'], 1)
        self.assertEqual(report['profiles'][-1]['country'], None)
        self.assert_coverage(nodes, configs, report)

    def test_empty_and_invalid_catalogs_fail_without_publishing_partial_results(self):
        with self.assertRaises(ValueError):
            build_catalog([], OPTIONS)
        for key in OPTIONS:
            for bad in (0, -1, True, 1.5, '50'):
                with self.subTest(key=key, value=bad), self.assertRaises(ValueError):
                    build_catalog([node(0)], {**OPTIONS, key: bad})
        with self.assertRaises(ValueError):
            subscription([])

    def test_delivery_can_exceed_one_profile_budget_and_still_load_every_profile(self):
        # A larger catalog is not one large running configuration.
        nodes = [node(i, COUNTRIES[i % 50]) for i in range(1000)]
        configs, report = build_catalog(nodes, OPTIONS)
        body = subscription(configs)
        self.assertGreater(len(body.splitlines()[0].encode('utf-16-le')), 800_000)
        self.assertNotIn('://routing/', body)
        self.assertNotIn('://autorouting/', body)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'subscription.json')
            path.write_text(body, encoding='utf-8')
            self.assertEqual(load_configs(path), configs)
        with patch('incy.MAX_SUBSCRIPTION_UTF8', len(body.encode()) - 1):
            with self.assertRaisesRegex(ValueError, 'download budget'):
                subscription(configs)
        self.assert_coverage(nodes, configs, report)


if __name__ == '__main__':
    unittest.main()
