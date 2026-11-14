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
from pool_quality import Endpoint, ProbeUnavailable, attempt, baseline, eligible_nodes


class QualityTests(unittest.TestCase):
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

    def test_gate_precedes_technology_quota_and_preserves_source_order(self):
        nodes = []
        for index, flags in enumerate([(True, False), (True, True), (False, True),
                                        (True, True), (True, True), (True, True)]):
            nodes.append({'host': str(index), 'outbound': {'protocol': 'vless'},
                          'quality': {kind: {'ok': flag} for kind, flag in zip(('https', 'quic'), flags)}})
        before = copy.deepcopy(nodes)
        eligible = eligible_nodes(nodes)
        selected = generate.select_per_technology(eligible, 3)
        self.assertEqual([node['host'] for node in selected], ['1', '3', '4'])
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


if __name__ == '__main__':
    unittest.main()
