import json
import unittest
from latency_checks import measure_latency, reusable_latency, latency_priority, latency_signature, URL, TTL
from pool_selection import select_pool, node_key
from test_pool_selection import node


class Response:
    def __init__(self, status=204): self.status = status
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def getcode(self): return self.status


class Opener:
    def __init__(self, outcomes): self.outcomes = iter(outcomes); self.requests = []
    def open(self, request, timeout):
        self.requests.append((request.full_url, request.method, timeout))
        value = next(self.outcomes)
        if isinstance(value, Exception): raise value
        return Response(value)


def measured(host, ms, failed=0, reputation='not_listed'):
    return {**node(host), 'latency_check': {'median_ms': ms, 'failed': failed},
            'reputation': {'status': reputation, 'blacklist_count': 1}}


class LatencyTests(unittest.TestCase):
    def test_two_head_probes_and_median(self):
        opener = Opener([204, 204]); clock = iter([1, 1.1, 2, 2.3])
        evidence = measure_latency(opener, lambda: next(clock), lambda: 100)
        self.assertEqual(evidence['samples_ms'], [100.0, 300.0])
        self.assertEqual(evidence['median_ms'], 200)
        self.assertEqual(evidence['failed'], 0)
        self.assertTrue(all(r == (URL, 'HEAD', 5) for r in opener.requests))
        self.assertTrue(reusable_latency(evidence, 100 + TTL - 1))
        self.assertFalse(reusable_latency(evidence, 100 + TTL))
        self.assertFalse(reusable_latency(evidence, 99))
        self.assertFalse(reusable_latency(None, 100))

    def test_failures_are_not_zero_latency_and_partial_probe_is_recorded(self):
        e = measure_latency(Opener([200, TimeoutError()]), lambda: 1, lambda: 100)
        self.assertIsNone(e['median_ms']); self.assertEqual(e['failed'], 2)
        self.assertEqual(latency_priority({'latency_check': e}), (2, 0))
        times = iter([0, 0.2, 1])
        e = measure_latency(Opener([204, TimeoutError()]), lambda: next(times), lambda: 100)
        self.assertEqual(e['median_ms'], 200)
        self.assertEqual(latency_priority({'latency_check': e}), (1, 2))

    def test_fast_nodes_beat_previous_membership_and_unknown_measurements(self):
        slow, fast, unknown = measured('slow', 1300), measured('fast', 80), node('unknown')
        selected = select_pool([slow, unknown, fast], 1, [node_key(slow)], lambda h: h)
        self.assertEqual(selected[0]['host'], 'fast')

    def test_reputation_precedes_latency_and_bucket_retains_diversity(self):
        clean, listed = measured('clean', 1500), measured('listed', 10, reputation='listed')
        self.assertEqual(select_pool([listed, clean], 1, network_lookup=lambda h: h)[0]['host'], 'clean')
        nodes = [measured('a', 10), measured('a', 20), measured('b', 80)]
        nodes[1]['outbound']['streamSettings']['network'] = 'ws'
        chosen = select_pool(nodes, 2, network_lookup=lambda h: h)
        self.assertEqual([n['host'] for n in chosen], ['a', 'b'])

    def test_measurement_dates_do_not_change_publication_signature(self):
        report = {'latency_selection': {'servers': [{'tag': 'pool-01', 'latency': {'median_ms': 20, 'checked_at': 10}}]}}
        a = json.dumps(report); report['latency_selection']['servers'][0]['latency']['checked_at'] = 20
        self.assertEqual(latency_signature(a), latency_signature(json.dumps(report)))
        report['latency_selection']['servers'][0]['latency']['median_ms'] = 80
        self.assertNotEqual(latency_signature(a), latency_signature(json.dumps(report)))
