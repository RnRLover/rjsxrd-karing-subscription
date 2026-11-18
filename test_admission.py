"""Quality thresholds, diagnostic-only allowlist evidence and normalized identity."""
from collections import Counter
import copy
import itertools
import ssl
import unittest
from unittest.mock import patch

from allowlist import annotate, load_reference
from catalog import build_catalog, country_key
from generate import collect_nodes, compatible_nodes
from pool_quality import Endpoint, sample_https
from test_catalog import node, OPTIONS
from test_subscription import URI


class AdmissionTests(unittest.TestCase):
    def test_normalized_duplicates_merge_all_labels_and_do_not_invent_country(self):
        first = URI.replace('#test', '&fp=chrome#OUT: DE')
        second = URI.replace('#test', '&fp=firefox#OUT: NL White List')
        nodes, counts = collect_nodes('\n'.join([first, second, first]))
        self.assertEqual(len(nodes), 1)
        self.assertEqual(counts['duplicate'], 2)
        self.assertEqual(len(nodes[0]['labels']), 2)
        self.assertIsNone(country_key(nodes[0]))
        annotate(nodes, {'available': False})
        self.assertTrue(nodes[0]['allowlist']['explicit_label'])
        self.assertFalse(nodes[0]['allowlist']['restricted_network_verified'])

    def test_batched_core_validation_isolates_bad_node_and_keeps_the_tail(self):
        nodes = [node(i) for i in range(300)]
        nodes[139]['outbound']['bad_fixture'] = True
        sizes = []
        def validate(xray, config):
            sizes.append(len(config['outbounds']))
            if any(o.get('bad_fixture') for o in config['outbounds']): raise ValueError('invalid fixture')
        counts = Counter()
        with patch('generate.xray_validate', side_effect=validate):
            kept = compatible_nodes(nodes, 'fixture', counts)
        self.assertEqual(kept, nodes[:139] + nodes[140:])
        self.assertEqual(counts['core_incompatible'], 1)
        self.assertLessEqual(max(sizes), 128)
        self.assertLess(len(sizes), 30)

    def test_equal_success_uses_upstream_order_without_allowlist_or_latency_priority(self):
        nodes = [node(i) for i in range(7)]
        for i, n in enumerate(nodes):
            n['source_order'] = i
            n['quality'] = {'https': {'success_rate': 1, 'median_ms': 10 + i, 'jitter_ms': 1}}
        nodes[4]['label'] = 'OUT: DE White List'
        nodes[4]['quality']['https']['median_ms'] = 300
        nodes[0]['quality']['https'].update(median_ms=1200, jitter_ms=99)
        annotate(nodes, {'available': False})
        configs, report = build_catalog(nodes, OPTIONS)
        self.assertEqual(report['profiles'][1]['node_indices'], list(range(7)))
        self.assertEqual(report['profiles'][0]['node_indices'], [0])
        self.assertEqual(len(configs), 2)
        self.assertEqual(set(report['profiles'][1]['node_indices']), set(range(7)))
        self.assertEqual(configs[1]['routing']['balancers'][0]['fallbackTag'], 'proxy-0')

    def test_evidence_matches_label_boundaries_and_is_not_a_mobile_verification(self):
        reference = load_reference(lambda url: b'example.com\n' if 'whitelist-all' in url else b'192.0.2.0/24\n')
        nodes = [node(0), node(1)]
        for n, sni in zip(nodes, ['a.example.com', 'example.com.evil.invalid']):
            n['outbound']['streamSettings']['realitySettings']['serverName'] = sni
            n['entry_reputation'] = [{'ip': '192.0.2.7'}]
        annotate(nodes, reference)
        self.assertEqual(nodes[0]['allowlist']['priority'], 5)
        self.assertEqual(nodes[1]['allowlist']['priority'], 2)
        self.assertTrue(all(not n['allowlist']['restricted_network_verified'] for n in nodes))

    def test_shared_exit_limit_preserves_an_alternative_transport(self):
        nodes = [node(0, 'DE'), node(1, 'NL'), node(2, 'FI', 'grpc'), node(3, 'FR', 'xhttp')]
        for n in nodes: n['exit_ip'] = '198.51.100.1'
        _, report = build_catalog(nodes, {**OPTIONS, 'auto_max_per_exit': 2})
        self.assertEqual(report['profiles'][0]['node_indices'], [0, 2])
        self.assertEqual(sum(p['nodes'] for p in report['profiles'][1:]), 4)

    def series(self, outcomes, step=.05):
        endpoints = [Endpoint('https://a.example/', 'a.example', '/', '192.0.2.1'),
                     Endpoint('https://b.example/', 'b.example', '/', '192.0.2.2')]
        clock = itertools.count(0, step)
        with patch('pool_quality.https_head', side_effect=outcomes), \
                patch('pool_quality.time.monotonic', side_effect=lambda: next(clock)):
            return sample_https(endpoints, 1080, {'timeout_seconds': 4})

    def test_single_recovery_does_not_hide_repeated_failures_or_slow_responses(self):
        self.assertTrue(self.series([None, TimeoutError(), None, None, None, None])['ok'])
        failed = self.series([None, TimeoutError(), TimeoutError()])
        self.assertFalse(failed['ok'])
        self.assertEqual(failed['attempts'], 3)  # Remaining probes cannot meet 5/6.
        self.assertFalse(self.series([None] * 6, step=2)['ok'])
        certificate = self.series([ssl.SSLCertVerificationError('wrong certificate')])
        self.assertFalse(certificate['ok'])
        self.assertEqual(certificate['attempts'], 1)


if __name__ == '__main__':
    unittest.main()
