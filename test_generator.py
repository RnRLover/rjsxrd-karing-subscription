import json
import tempfile
import unittest
from pathlib import Path

from generate import CountryRanges, endpoint_allowed, parse_node, translate_rules, build, russian_label, atomic_write

UUID = "123e4567-e89b-12d3-a456-426614174000"
KEY = "A" * 43
URI = f"vless://{UUID}@1.1.1.1:443?security=reality&pbk={KEY}&sni=example.com&type=tcp&fp=chrome#test"

class SubscriptionTests(unittest.TestCase):
    def test_ru_filter_checks_all_resolved_addresses(self):
        ru = CountryRanges(["5.0.0.0/8", "2a00:1::/32"])
        self.assertTrue(endpoint_allowed("host.test", ru, lambda h: ["1.1.1.1"]))
        self.assertFalse(endpoint_allowed("host.test", ru, lambda h: ["1.1.1.1", "5.1.2.3"]))
        self.assertFalse(endpoint_allowed("host.test", ru, lambda h: ["2a00:1::1"]))
        self.assertFalse(endpoint_allowed("host.test", ru, lambda h: []))
        self.assertFalse(endpoint_allowed("host.test", ru, lambda h: ["127.0.0.1"]))

    def test_ru_labels_do_not_depend_on_flag_only(self):
        for label in ("🇷🇺", "%F0%9F%87%B7%F0%9F%87%BA", "Russia", "RU:server", "Россия"):
            self.assertTrue(russian_label(label))
        self.assertFalse(russian_label("Brussels"))

    def test_reuse_preserves_transport(self):
        node = parse_node(URI.replace("type=tcp", "type=grpc&serviceName=myservice&authority=example.com"))
        stream = node["outbound"]["streamSettings"]
        self.assertEqual(stream["grpcSettings"]["serviceName"], "myservice")
        self.assertEqual(stream["grpcSettings"]["authority"], "example.com")
        self.assertEqual(stream["realitySettings"]["fingerprint"], "chrome")
        self.assertEqual(parse_node(URI.replace("type=tcp", "type=raw"))["outbound"]["streamSettings"]["network"], "tcp")

    def test_insecure_and_unhandled_options_are_rejected(self):
        self.assertIsNone(parse_node(URI.replace("security=reality", "security=none")))
        self.assertIsNone(parse_node(URI.replace("type=tcp", "type=xhttp")))
        self.assertIsNone(parse_node(URI.replace("type=tcp", "type=tcp&allowInsecure=1")))
        self.assertIsNone(parse_node(URI.replace("type=tcp", "type=tcp&headerType=http")))

    def test_domain_and_ip_alternatives_survive_conversion(self):
        obj = {"version": 2, "rules": [{"domain": ["a.test"], "domain_suffix": ["b.test", ".c.test"], "domain_keyword": ["ads"], "ip_cidr": ["91.108.0.0/16"]}]}
        rules = translate_rules(obj, "proxy")
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0]["balancerTag"], "auto")
        self.assertIn("full:a.test", rules[0]["domain"])
        self.assertIn("domain:b.test", rules[0]["domain"])
        self.assertIn("regexp:.*\\.c\\.test$", rules[0]["domain"])
        self.assertNotIn("ip", rules[0])
        self.assertNotIn("domain", rules[1])
        with self.assertRaises(ValueError): translate_rules({"version": 2, "rules": [{"process_name": ["a.exe"]}]}, "proxy")

    def test_unavailable_pool_blocks_and_udp_is_routed(self):
        node = parse_node(URI)
        config = build([node, node], [])
        self.assertEqual(config["outbounds"][0]["protocol"], "blackhole")
        self.assertEqual(config["routing"]["balancers"][0]["fallbackTag"], "block")
        self.assertEqual(config["routing"]["rules"][-1]["network"], "tcp,udp")
        self.assertTrue(config["inbounds"][0]["settings"]["udp"])
        with self.assertRaises(ValueError): build([], [])

    def test_atomic_cache_replaces_valid_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ru.json"
            atomic_write(path, "old")
            atomic_write(path, "new")
            self.assertEqual(path.read_text(), "new")
            self.assertEqual(len(list(path.parent.iterdir())), 1)

if __name__ == "__main__": unittest.main()
