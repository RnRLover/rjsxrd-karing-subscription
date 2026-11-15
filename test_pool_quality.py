import copy
from collections import Counter
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import generate
from pool_quality import Endpoint, ProbeUnavailable, attempt, baseline, eligible_nodes, probe_nodes


class QualityTests(unittest.TestCase):
    def test_growing_pool_checks_use_bounded_batches_without_dropping_the_tail(self):
        nodes = [{'index': i} for i in range(400)]
        for function, target in [(probe_nodes, 'pool_quality._probe_batch'),
                                 (generate.probe_exits, 'generate._probe_exit_batch')]:
            sizes = []
            def batch(members, *args):
                sizes.append(len(members))
                return members
            with self.subTest(function=function.__name__), patch(target, side_effect=batch):
                if function is probe_nodes:
                    results = function(nodes, 'unused', {}, {})
                else:
                    results = function(nodes, 'unused')
            self.assertEqual(sizes, [128, 128, 128, 16])
            self.assertEqual(results, nodes)
        with patch('pool_quality._probe_batch', side_effect=[nodes[:128], ProbeUnavailable('batch failed')]):
            with self.assertRaises(ProbeUnavailable):
                probe_nodes(nodes, 'unused', {}, {})

    def test_alternate_target_and_retry_can_recover_without_dropping_node(self):
        endpoints = [Endpoint('https://a.example/', 'a.example', '/', '192.0.2.1'),
                     Endpoint('https://b.example/', 'b.example', '/', '192.0.2.2')]
        calls = []
        def probe(endpoint, **kwargs):
            calls.append(endpoint.host)
            if len(calls) != 3:
                raise TimeoutError()
        result = attempt(probe, endpoints, 1080, 4, 2)
        self.assertTrue(result['ok'])
        self.assertEqual(calls, ['a.example', 'b.example', 'a.example'])
        self.assertEqual(result['attempts'], 3)

    def test_gate_keeps_every_passing_node_in_source_order(self):
        nodes = []
        for index, flags in enumerate([(True, False), (True, True), (False, True),
                                        (True, True), (True, True), (True, True)]):
            nodes.append({'host': str(index), 'outbound': {'protocol': 'vless'},
                          'quality': {kind: {'ok': flag} for kind, flag in zip(('https', 'quic'), flags)}})
        before = copy.deepcopy(nodes)
        eligible = eligible_nodes(nodes)
        self.assertEqual([node['host'] for node in eligible], ['1', '3', '4', '5'])
        self.assertEqual(nodes, before)
        self.assertEqual(eligible_nodes([{'quality': {'https': {'ok': True}}}]), [])

    def test_direct_udp_failure_defers_admission_even_with_working_https(self):
        settings = {'timeout_seconds': 1, 'attempts': 2, 'workers': 2,
                    'targets': ['https://a.example/', 'https://b.example/']}
        with patch('pool_quality.socket.getaddrinfo', return_value=[(2, 2, 17, '', ('192.0.2.1', 443))]), \
                patch('pool_quality.https_head'), patch('pool_quality.quic_head', side_effect=TimeoutError):
            with self.assertRaises(ProbeUnavailable):
                baseline(settings)

    def test_intentional_vision_udp443_policy_is_not_reported_as_a_pass(self):
        node = {'outbound': {'protocol': 'vless', 'settings': {'vnext': [{'users': [
            {'flow': 'xtls-rprx-vision'}]}]}}, 'quality': {'https': {'ok': True},
            'quic': {'ok': False, 'required': False,
                     'skipped': 'ordinary_vision_intentionally_blocks_udp443'}}}
        self.assertEqual(eligible_nodes([node]), [node])
        other = copy.deepcopy(node)
        other['outbound']['settings']['vnext'][0]['users'][0]['flow'] = ''
        self.assertEqual(eligible_nodes([other]), [])
        failed = copy.deepcopy(node)
        failed['quality']['https']['ok'] = False
        self.assertEqual(eligible_nodes([failed]), [])

    def test_probe_site_or_total_pool_failure_preserves_both_published_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = {'quality': {}, 'subscription_url': 'https://fixture.example/',
                        'reputation_workers': 1, 'reputation_timeout_seconds': 1}
            (root / 'settings.json').write_text(json.dumps(settings))
            for name in ('subscription.json', 'report.json'):
                (root / name).write_text('unchanged')
            node = {'host': '192.0.2.1', 'reputation': {'status': 'unknown'},
                    'quality': {'https': {'ok': True}, 'quic': {'ok': False}}}
            for unavailable in (True, False):
                with self.subTest(direct_baseline_failed=unavailable), \
                        patch.object(generate, 'ROOT', root), \
                        patch('sys.argv', ['generate.py', '--xray', 'unused']), \
                        patch('generate.baseline', side_effect=ProbeUnavailable('fixture unavailable')
                              if unavailable else None, return_value=({'https': [], 'quic': []}, {})), \
                        patch('generate.fetch', return_value=b'fixture'), \
                        patch('generate.collect_nodes', return_value=([node], Counter())), \
                        patch('generate.compatible_nodes', side_effect=lambda nodes, *_: nodes), \
                        patch('generate.load_feed', return_value=({}, 'fixture')), \
                        patch('generate.entry_ips', return_value=[]), \
                        patch('generate.probe_exits', return_value=[node]), \
                        patch('generate.assess_nodes', return_value=[node]), \
                        patch('generate.probe_nodes', return_value=[node]), \
                        redirect_stdout(io.StringIO()):
                    self.assertFalse(generate.main())
                for name in ('subscription.json', 'report.json'):
                    self.assertEqual((root / name).read_text(), 'unchanged')

    def test_invalid_later_profile_preserves_the_entire_published_catalog(self):
        nodes = [generate.parse_node(
            f'vless://123e4567-e89b-12d3-a456-426614174000@node{i}.example:443'
            f'?security=tls&sni=example.com#OUT: {country}')
            for i, country in enumerate(['DE', 'NL'])]
        for node in nodes:
            node.update(reputation={'status': 'unknown'}, quality={
                'https': {'ok': True}, 'quic': {'ok': True}})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = {'quality': {}, 'subscription_url': 'https://fixture.example/',
                        'reputation_workers': 1, 'reputation_timeout_seconds': 1,
                        'catalog': {'auto_max_nodes': 64, 'max_nodes_per_profile': 50}, 'probe': {}}
            (root / 'settings.json').write_text(json.dumps(settings))
            for name in ('subscription.json', 'report.json'):
                (root / name).write_text('unchanged')
            def validate(xray, config):
                if config['remarks'].startswith('🇳🇱'):
                    raise ValueError('invalid later profile')
            with patch.object(generate, 'ROOT', root), \
                    patch('sys.argv', ['generate.py', '--xray', 'unused']), \
                    patch('generate.baseline', return_value=({}, {})), \
                    patch('generate.fetch', return_value=b'fixture'), \
                    patch('generate.collect_nodes', return_value=(nodes, Counter())), \
                    patch('generate.compatible_nodes', side_effect=lambda nodes, *_: nodes), \
                    patch('generate.load_feed', return_value=({}, 'fixture')), \
                    patch('generate.entry_ips', return_value=[]), \
                    patch('generate.probe_exits', return_value=nodes), \
                    patch('generate.assess_nodes', return_value=nodes), \
                    patch('generate.probe_nodes', return_value=nodes), \
                    patch('generate.xray_validate', side_effect=validate), \
                    redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ValueError, 'invalid later profile'):
                    generate.main()
            for name in ('subscription.json', 'report.json'):
                self.assertEqual((root / name).read_text(), 'unchanged')


if __name__ == '__main__':
    unittest.main()
