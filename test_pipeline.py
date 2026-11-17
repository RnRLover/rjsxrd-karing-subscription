"""Exercise full partition/merge behavior and publication guards without live nodes."""
from contextlib import ExitStack, redirect_stdout
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import generate
from incy import load_configs
from pipeline import prepare, probe_shard, assemble, read_input, write
from test_catalog import COUNTRIES, UUID

SETTINGS = json.loads((Path(__file__).parent / 'settings.json').read_text())
FEED = {'counts': {}, 'published_at': 1, 'fetched_at': 1, 'sha256': 'fixture'}


def source_text(count):
    return '\n'.join(f'vless://{UUID}@node{i}.example:443?security=tls&sni=example.com#OUT: {COUNTRIES[i % 50]}'
                     for i in range(count)).encode()


def checked(nodes, *args):
    return [dict(node, quality={'https': {'ok': True, 'trials': 6, 'successes': 6, 'success_rate': 1,
                                        'median_ms': 100, 'jitter_ms': 0}, 'quic': {'ok': True}}) for node in nodes]


class PipelineTests(unittest.TestCase):
    def environment(self, root, count, shard_size=500):
        settings = copy.deepcopy(SETTINGS)
        settings['subscription_url'] = 'https://fixture.example/source'
        settings['build']['shard_nodes'] = shard_size
        (root / 'settings.json').write_text(json.dumps(settings))
        (root / '.runtime').mkdir(exist_ok=True)
        for name in ('geoip.dat', 'geosite.dat'):
            (root / '.runtime' / name).write_bytes(b'fixture')
        for name in ('subscription.json', 'report.json'):
            (root / name).write_text('previous publication')
        def fetch(url):
            if url == settings['subscription_url']:
                return source_text(count)
            return b'example.com\n' if 'whitelist-all' in url else b'192.0.2.0/24\n'
        stack = ExitStack()
        for target, kwargs in [
            ('generate.fetch', {'side_effect': fetch}),
            ('generate.compatible_nodes', {'side_effect': lambda nodes, *_: nodes}),
            ('generate.load_feed', {'return_value': (FEED, 'fixture')}),
            ('generate.entry_ips', {'return_value': []}),
            ('generate.probe_exits', {'side_effect': lambda nodes, *_: [dict(n, exit_ip=None) for n in nodes]}),
            ('generate.baseline', {'return_value': ({'https': [], 'quic': []}, {})}),
            ('generate.probe_nodes', {'side_effect': checked}),
            ('generate.xray_validate', {}),
        ]:
            stack.enter_context(patch(target, **kwargs))
        stack.enter_context(patch.object(generate, 'ROOT', root))
        stack.enter_context(redirect_stdout(io.StringIO()))
        return stack

    def test_one_and_ten_thousand_candidates_complete_without_truncation(self):
        for count in (1, 10_000):
            with self.subTest(count=count), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with self.environment(root, count):
                    work = root / '.runtime/build'
                    result = prepare(work, 'fixture')
                    self.assertTrue(result['ready'])
                    self.assertEqual(len(result['matrix']['shard']), (count + 499) // 500)
                    for index in result['matrix']['shard']:
                        probe_shard(work, index, 'fixture')
                    self.assertTrue(assemble(work, 'fixture'))
                    configs = load_configs(root / 'subscription.json')
                    report = json.loads((root / 'report.json').read_text())
                    self.assertEqual(report['selected'], count)
                    self.assertEqual(sum(len(c['outbounds']) - 2 for c in configs[1:]), count)
                    self.assertEqual(len(configs), 1 + min(count, 50))
                    self.assertEqual(report['catalog']['group_by'], ['upstream_country_label'])
                    self.assertEqual(report['catalog']['profiles'][0]['node_indices'], list(range(min(count, 50))))
                    self.assertTrue(all(p['kind'] == 'country' for p in report['catalog']['profiles'][1:]))
                    self.assertLessEqual(len(configs[0]['outbounds']) - 2, 64)
                    self.assertTrue(report['build']['complete'])
                    self.assertFalse(report['history_used'])
                    self.assertEqual(report['catalog']['catalog_nodes_omitted'], 0)
                    if count == 10_000:
                        self.assertGreater((root / 'subscription.json').stat().st_size, 800_000)

    def test_missing_stale_tampered_and_deferred_shards_preserve_previous_files(self):
        for failure in ('missing', 'stale', 'tampered', 'lost_accounting', 'deferred'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with self.environment(root, 3, shard_size=2):
                    work = root / '.runtime/build'
                    prepare(work, 'fixture')
                    probe_shard(work, 0, 'fixture')
                    if failure != 'missing':
                        result = probe_shard(work, 1, 'fixture')
                        if failure == 'stale': result['build_id'] = 'another run'
                        if failure == 'tampered': result['nodes'][0]['outbound']['settings']['vnext'][0]['port'] = 444
                        if failure == 'lost_accounting': result['dispositions'] = {}
                        if failure == 'deferred': result['status'] = 'deferred'
                        write(work / 'results/result-0001.json', result)
                    if failure == 'deferred':
                        self.assertFalse(assemble(work, 'fixture'))
                    else:
                        with self.assertRaises(ValueError): assemble(work, 'fixture')
                    for name in ('subscription.json', 'report.json'):
                        self.assertEqual((root / name).read_text(), 'previous publication')

    def test_corrupt_input_and_catalog_shrink_do_not_reuse_old_results(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / '.runtime/build'
            with self.environment(root, 3, shard_size=2):
                prepare(work, 'fixture')
                path = work / 'input/shard-0000.json'
                path.write_text('{}')
                with self.assertRaisesRegex(ValueError, 'checksum'): read_input(work, 0)
                write(work / 'results/result-0099.json', {'stale': True})
            with self.environment(root, 1):
                prepare(work, 'fixture')
                self.assertFalse((work / 'input/shard-0001.json').exists())
                self.assertFalse((work / 'results/result-0099.json').exists())
                probe_shard(work, 0, 'fixture')
                self.assertTrue(assemble(work, 'fixture'))

    def test_changed_core_or_geodata_preserves_previous_publication(self):
        for changed in ('xray', 'geoip.dat', 'geosite.dat'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with self.environment(root, 1):
                    work = root / '.runtime/build'
                    xray = root / 'fixture-xray'
                    xray.write_bytes(b'verified fixture core')
                    prepare(work, str(xray))
                    probe_shard(work, 0, str(xray))
                    path = xray if changed == 'xray' else root / '.runtime' / changed
                    path.write_bytes(b'different bytes')
                    with self.assertRaisesRegex(ValueError, 'runtime'):
                        probe_shard(work, 0, str(xray))
                    with self.assertRaisesRegex(ValueError, 'runtime'):
                        assemble(work, str(xray))
                    for name in ('subscription.json', 'report.json'):
                        self.assertEqual((root / name).read_text(), 'previous publication')


if __name__ == '__main__':
    unittest.main()
