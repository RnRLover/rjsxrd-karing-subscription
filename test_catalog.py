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
from incy import load_configs, proxy_outbound, subscription

OPTIONS = {'auto_max_nodes': 64, 'max_nodes_per_profile': 50}
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
                self.assertLessEqual(len(expected), OPTIONS['max_nodes_per_profile'])
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
            self.assertEqual(report['countries'], sorted(countries))
            self.assertEqual({key[1] for key in report['technologies']}, set(networks))
            self.assertEqual(len(configs), 1 + len(countries) * len(networks))
            self.assert_coverage(nodes, configs, report)
            self.assertEqual(nodes, before)
            self.assertEqual(build_catalog(nodes, OPTIONS), (configs, report))

    def test_large_groups_are_partitioned_without_truncation_or_source_reordering(self):
        nodes = [node(i) for i in range(123)]
        configs, report = build_catalog(nodes, OPTIONS)
        self.assertEqual([p['nodes'] for p in report['profiles']], [3, 50, 50, 23])
        self.assertEqual(report['profiles'][0]['node_indices'], [0, 50, 100])
        self.assertEqual([p['part'] for p in report['profiles'][1:]], [1, 2, 3])
        self.assert_coverage(nodes, configs, report)
        for config in configs[1:]:
            self.assertEqual(config['routing']['balancers'][0]['strategy']['settings'], {
                'baselines': ['400ms', '800ms'], 'expected': 4, 'maxRTT': '1500ms', 'tolerance': .2})

    def test_late_technologies_get_representatives_before_early_technology_fills_auto(self):
        nodes = [node(i, code) for i, code in enumerate(COUNTRIES)]
        hy = parse_node('hy2://secret@hy.example:443?sni=hy.example#OUT: NL')
        grpc = node(100, 'DE', 'grpc')
        configs, report = build_catalog(nodes + [hy, grpc], {**OPTIONS, 'auto_max_nodes': 4})
        self.assertEqual(report['profiles'][0]['node_indices'], [0, 1, len(nodes), len(nodes) + 1])
        self.assertEqual([o['protocol'] for o in proxies(configs[0])], ['vless', 'vless', 'hysteria', 'vless'])

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
