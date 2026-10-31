import base64
import copy
import json
import unittest
from urllib.parse import parse_qs, unquote, urlsplit
from routing_isolation import control_subscriptions


class IsolationTests(unittest.TestCase):
    def test_same_transport_and_only_a_supplies_native_rules(self):
        configs = [{'outbounds': [{'protocol': 'trojan',
                    'settings': {'servers': [{'address': '2001:db8::1', 'port': 443,
                                             'password': 'a/@?#:'}]},
                    'streamSettings': {'security': 'tls', 'network': 'tcp',
                                       'tlsSettings': {'serverName': 'example.net',
                                                       'fingerprint': 'chrome'}}}]}]
        profile = {'Name': 'Production', 'RemoteDNSIP': '1.1.1.1',
                   'DirectSites': ['geosite:category-ru'], 'LastUpdated': '100'}
        original = copy.deepcopy(profile)
        controls = control_subscriptions(configs, profile)
        a = controls['isolation-a.txt'].splitlines()
        b = controls['isolation-b.txt'].splitlines()
        self.assertEqual(a[1], b[1])
        self.assertEqual(len(b), 2)
        parsed = urlsplit(a[1])
        self.assertEqual(unquote(parsed.username), 'a/@?#:')
        self.assertEqual(parsed.hostname, '2001:db8::1')
        self.assertEqual(parse_qs(parsed.query)['sni'], ['example.net'])
        native = json.loads(base64.b64decode(a[2].removeprefix('incy://routing/onadd/')))
        self.assertEqual(native['BlockSites'], ['domain:example.org'])
        self.assertEqual(native['DirectSites'], [])
        self.assertNotIn('RemoteDNSIP', native)
        self.assertEqual(original, profile)

    def test_no_compatible_node_cannot_produce_misleading_controls(self):
        with self.assertRaises(ValueError):
            control_subscriptions([{'outbounds': []}], {})
