import copy
import json
import unittest
from email.utils import formatdate

from ip_reputation import (CACHE_KEY, FEED_URL, MAX_AGE_SECONDS, parse_feed,
                           load_feed, rate_ip, rank_nodes, reputation_report)
from pool_selection import node_key, select_pool
from publication_changed import reputation_signature


NOW = 1800000000


def text(stamp=NOW, rows='1.1.1.1\t1\n8.8.8.8\t3\n'):
    return ('# IPsum Threat Intelligence Feed\n# Last update: ' +
            formatdate(stamp, usegmt=True) + '\n' + rows)


def node(host, exit_ip):
    return {'host': host, 'exit_ip': exit_ip,
            'outbound': {'tag': 'candidate', 'protocol': 'trojan',
                         'settings': {'servers': [{'address': host, 'port': 443,
                                                  'password': 'test'}]}}}


class ReputationTests(unittest.TestCase):
    def setUp(self):
        self.feed = parse_feed(text(), NOW)

    def test_known_counts_score_monotonically_and_ipv6_absence_is_unknown(self):
        self.assertEqual(rate_ip('9.9.9.9', self.feed),
                         {'status': 'not_listed', 'score': 100, 'blacklist_count': 0})
        self.assertEqual(rate_ip('1.1.1.1', self.feed)['score'], 80)
        self.assertEqual(rate_ip('8.8.8.8', self.feed)['score'], 40)
        for address in ('2606:4700:4700::1111', None, 'invalid', '127.0.0.1'):
            self.assertEqual(rate_ip(address, self.feed)['status'], 'unknown')
            self.assertIsNone(rate_ip(address, self.feed)['score'])
        self.feed['counts']['1.1.1.1'] = 20
        self.assertEqual(rate_ip('1.1.1.1', self.feed)['score'], 0)

    def test_invalid_or_stale_feed_is_not_an_empty_clean_list(self):
        bad = ['<html>error</html>', text(rows=''), text(stamp=NOW-MAX_AGE_SECONDS-1),
               text(stamp=NOW+3601), text(rows='not-an-ip 1\n'),
               text(rows='1.1.1.1 0\n'), text(rows='1.1.1.1 1\n1.1.1.1 2\n')]
        for content in bad:
            with self.subTest(content=content), self.assertRaises(ValueError):
                parse_feed(content, NOW)

    def test_cache_refresh_is_daily_and_keeps_country_evidence(self):
        country = {'exit_ip': '9.9.9.9', 'verified_at': NOW}
        cache, calls = {'node-key': country}, []
        def fetch(url):
            calls.append(url)
            return text()
        first, source = load_feed(cache, fetch, NOW)
        second, source2 = load_feed(cache, fetch, NOW+3600)
        self.assertEqual((source, source2), ('download', 'cache'))
        self.assertEqual(calls, [FEED_URL])
        self.assertEqual(first, second)
        self.assertEqual(cache['node-key'], country)
        load_feed(cache, fetch, NOW+86400)
        self.assertEqual(len(calls), 2)

    def test_network_failure_cannot_create_clean_evidence(self):
        def fail(url):
            raise OSError('offline')
        with self.assertRaisesRegex(ValueError, 'keep published pool'):
            load_feed({}, fail, NOW)
        cache = {CACHE_KEY: self.feed}
        feed, source = load_feed(cache, fail, NOW+86401)
        self.assertEqual(source, 'cache_after_refresh_error')
        self.assertEqual(feed, self.feed)
        with self.assertRaises(ValueError):
            load_feed(cache, fail, NOW+MAX_AGE_SECONDS+1)

    def test_entry_ip_does_not_substitute_for_actual_exit(self):
        a, b = rank_nodes([node('1.1.1.1', '9.9.9.9'),
                           node('9.9.9.9', '1.1.1.1')], self.feed)
        self.assertEqual(a['reputation']['score'], 100)
        self.assertEqual(b['reputation']['score'], 80)
        self.assertNotIn('reputation', a['outbound'])

    def test_unlisted_exits_beat_diversity_and_previous_marked_membership(self):
        a, b, marked = rank_nodes([node('a', '9.9.9.9'), node('b', '9.9.9.10'),
                                  node('c', '1.1.1.1')], self.feed)
        chosen = select_pool([marked, b, a], 2, [node_key(marked)],
                             lambda host: 'other' if host == 'c' else 'same')
        self.assertEqual({n['host'] for n in chosen}, {'a', 'b'})
        self.assertEqual(chosen, select_pool([a, b, marked, a], 2, [node_key(marked)],
                                           lambda host: 'other' if host == 'c' else 'same'))

    def test_listed_exits_are_excluded_even_when_pool_has_space(self):
        nodes = rank_nodes([node('three', '8.8.8.8'), node('one', '1.1.1.1'),
                            node('unknown', '2606:4700:4700::1111'),
                            node('unlisted', '9.9.9.9')], self.feed)
        chosen = select_pool(nodes, 4, network_lookup=lambda host: host)
        self.assertEqual({n['host'] for n in chosen}, {'unlisted', 'unknown'})

    def test_distinct_actual_exits_precede_different_entry_networks(self):
        nodes = rank_nodes([node('a', '9.9.9.9'), node('b', '9.9.9.9'),
                            node('c', '9.9.9.10')], self.feed)
        chosen = select_pool(nodes, 2, network_lookup=lambda host: host)
        self.assertEqual(len({n['exit_ip'] for n in chosen}), 2)

    def test_report_and_publication_capture_score_changes_without_timestamp_churn(self):
        nodes = rank_nodes([node('a', '9.9.9.9')], self.feed)
        report = {'ip_reputation': reputation_report(nodes, nodes, self.feed, 'download')}
        other = copy.deepcopy(report)
        other['ip_reputation']['fetched_at'] += 86400
        other['ip_reputation']['evidence_source'] = 'cache'
        self.assertEqual(reputation_signature(json.dumps(report)), reputation_signature(json.dumps(other)))
        other['ip_reputation']['servers'][0].update(status='listed', score=80, blacklist_count=1)
        self.assertNotEqual(reputation_signature(json.dumps(report)), reputation_signature(json.dumps(other)))
        self.assertNotEqual(reputation_signature('{}'), reputation_signature(json.dumps(report)))
        self.assertEqual(report['ip_reputation']['selected'], {'not_listed': 1})
        self.assertEqual(report['ip_reputation']['servers'][0]['tag'], 'pool-01')


if __name__ == '__main__':
    unittest.main()
