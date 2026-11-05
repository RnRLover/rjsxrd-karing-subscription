import copy
import unittest

from karing import automatic_config, subscription_variants
from technology_selection import balancing, groups, selection_report, technology


def node(tag, protocol='vless', network='tcp', security='reality'):
    return {'tag': tag, 'protocol': protocol,
            'streamSettings': {'network': network, 'security': security}}


class TechnologySelectionTests(unittest.TestCase):
    def test_groups_separate_protocol_transport_and_security(self):
        nodes = [node('a'), node('b', network='raw'), node('c', network='grpc'),
                 node('d', security='tls'), node('e', protocol='trojan', security='tls')]
        original = copy.deepcopy(nodes)
        grouped = groups(nodes)
        self.assertEqual(nodes, original)
        self.assertEqual(len(grouped), 4)
        self.assertIn(['a', 'b'], [g['servers'] for g in grouped])
        self.assertEqual(sorted(t for g in grouped for t in g['servers']), list('abcde'))
        self.assertEqual(technology(node('a', network='ws')),
                         technology(node('b', network='websocket')))

    def test_only_group_paths_are_ranked_globally_and_all_members_are_observed(self):
        nodes = [node('a'), node('b'), node('c', network='grpc')]
        selection = balancing(nodes)
        grouped = groups(nodes)
        paths = {g['outbound'] for g in grouped}
        self.assertEqual(set(selection['balancers'][0]['selector']), paths)
        self.assertEqual(selection['balancers'][0]['fallbackTag'], 'a')
        self.assertEqual(set(selection['subjects']), paths | {'a', 'b', 'c'})
        by_tag = {b['tag']: b for b in selection['balancers']}
        for group in grouped:
            balancer = by_tag[group['balancer']]
            self.assertEqual(balancer['selector'], group['servers'])
            self.assertEqual(balancer['fallbackTag'], 'block')
            self.assertEqual(balancer['strategy'], {'type': 'leastPing'})
            self.assertIn({'type': 'field', 'inboundTag': [group['inbound']],
                           'balancerTag': group['balancer']}, selection['rules'])

    def test_rebuilding_and_renaming_do_not_flatten_or_duplicate_groups(self):
        base = {'inbounds': [{'tag': 'socks-in', 'protocol': 'socks'}],
                'outbounds': [node('pool-01'), node('pool-02'), node('pool-03', network='grpc')],
                'routing': {'rules': [], 'balancers': []}}
        config = subscription_variants(base)[0]
        self.assertEqual(subscription_variants(config)[0], config)
        renamed = automatic_config(config, 'Renamed')
        self.assertEqual(len({o['tag'] for o in renamed['outbounds']}), len(renamed['outbounds']))
        self.assertEqual(renamed['routing']['balancers'][0]['selector'],
                         config['routing']['balancers'][0]['selector'])
        report = selection_report(config)
        self.assertEqual(report['priority_order'], 'dynamic_on_device')
        self.assertEqual(len(report['groups']), 2)
        self.assertEqual(report['probe_subjects'], 5)


if __name__ == '__main__':
    unittest.main()
