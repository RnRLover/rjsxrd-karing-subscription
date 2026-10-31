import copy
import base64
import json
from pathlib import Path
import unittest
from subscription_delivery import bundle

ROOT = Path(__file__).resolve().parent


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.configs = json.loads((ROOT / 'subscription.json').read_bytes())
        self.policy = json.loads((ROOT / 'russia-routing.json').read_bytes())
        self.assets = {'geoip.dat': b'ip-fixture', 'geosite.dat': b'site-fixture'}

    def test_pool_rotation_does_not_force_geodata_download(self):
        before = bundle(self.configs, self.policy, self.assets, now=100)
        configs = copy.deepcopy(self.configs)
        configs[0]['remarks'] = 'changed server pool'
        after = bundle(configs, self.policy, self.assets, before, now=200)
        self.assertEqual(before['profile'], after['profile'])
        self.assertNotEqual(before['configs'], after['configs'])

    def test_changed_geodata_and_rules_advance_timestamp(self):
        before = bundle(self.configs, self.policy, self.assets, now=100)
        changed = {**self.assets, 'geosite.dat': b'new-site-fixture'}
        self.assertEqual(bundle(self.configs, self.policy, changed, before, now=99)['profile']['LastUpdated'], '101')
        policy = copy.deepcopy(self.policy)
        policy['DirectSites'].append('domain:example.ru')
        self.assertEqual(bundle(self.configs, policy, self.assets, before, now=200)['profile']['LastUpdated'], '200')

    def test_profile_has_exact_rules_and_no_dns_override(self):
        result = bundle(self.configs, self.policy, self.assets, now=100)
        for key in ('DirectSites', 'DirectIp', 'ProxySites', 'ProxyIp', 'BlockSites', 'BlockIp', 'RouteOrder'):
            self.assertEqual(result['profile'][key], self.policy[key])
        self.assertFalse(result['profile']['useChunkFiles'])
        self.assertEqual(result['configs'], self.configs)
        self.assertFalse(any('dns' in key.lower() for key in result['profile'] if key != 'FakeDNS'))
        result['configs'][0]['remarks'] = 'test'
        self.assertNotEqual(result['configs'], self.configs)

    def test_missing_asset_stops_publication(self):
        with self.assertRaises(KeyError):
            bundle(self.configs, self.policy, {}, now=100)

    def test_incy_body_preserves_full_config_and_attaches_bootstrap_commands(self):
        from subscription_delivery import incy_subscription
        body = incy_subscription(self.configs)
        lines = body.splitlines()
        self.assertEqual(json.loads(lines[0]), self.configs)
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[1], 'incy://autorouting/onadd/https://raw.githubusercontent.com/RnRLover/rjsxrd-karing-subscription/refs/heads/main/russia-routing.json')
        self.assertEqual(lines[2], '#routing-geo-update-interval: 24')
        self.assertNotIn('workers.dev', body)
        self.assertLess(len(body.encode()), 2_000_000)

    def test_happ_body_keeps_config_and_exact_geodata_policy(self):
        from subscription_delivery import happ_subscription
        profile = bundle(self.configs, self.policy, self.assets, now=100)['profile']
        original = copy.deepcopy(profile)
        body = happ_subscription(self.configs, profile)
        config, command = body.splitlines()
        self.assertEqual(json.loads(config), self.configs)
        self.assertTrue(command.startswith('happ://routing/onadd/'))
        native = json.loads(base64.b64decode(command.removeprefix('happ://routing/onadd/'), validate=True))
        self.assertEqual(native.pop('UseChunkFiles'), 'false')
        self.assertEqual(native, {k: v for k, v in profile.items() if k != 'useChunkFiles'})
        self.assertEqual(profile, original)
        self.assertNotIn('workers.dev', body)

    def test_publication_comparison_handles_native_body_commands(self):
        from publication_changed import canonical
        from subscription_delivery import happ_subscription, incy_subscription
        for name, body in [('happ.txt', happ_subscription(self.configs, self.policy)),
                           ('incy.txt', incy_subscription(self.configs))]:
            self.assertEqual(canonical(name, body.encode()), canonical(name, (body + '\n').rstrip('\n').encode()))
            self.assertNotEqual(canonical(name, body.encode()), canonical(name, (body + '#changed: 1\n').encode()))
