import json
import tempfile
import unittest
from pathlib import Path

from routing import domains, policy
from generate import CountryRanges, endpoint_allowed, parse_node, build, russian_label, atomic_write, serialized_config

UUID = "123e4567-e89b-12d3-a456-426614174000"
KEY = "A" * 43
URI = f"vless://{UUID}@1.1.1.1:443?security=reality&pbk={KEY}&sni=example.com&type=tcp&fp=chrome#test"

ROUTING = policy(["domain:example.ru"], ["domain:ads.example.ru"], ["5.0.0.0/8"])

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

    def test_geo_policy_blocks_ads_before_ru_and_proxies_everything_else(self):
        config = build([parse_node(URI)] * 2, ROUTING)
        rules = config["routing"]["rules"]
        self.assertEqual(config["routing"]["domainStrategy"], "IPOnDemand")
        self.assertEqual(rules[0]["outboundTag"], "block")
        self.assertEqual(rules[0]["domain"], ["domain:ads.example.ru"])
        self.assertEqual([rules[i]["outboundTag"] for i in (1, 3, 4)], ["direct"] * 3)
        self.assertEqual(rules[4]["ip"], ["geoip:ru"])
        self.assertEqual(rules[-1], {"type": "field", "network": "tcp,udp", "balancerTag": "auto"})
        self.assertFalse(any("port" in r or "protocol" in r for r in rules))
        config["routing"]["rules"].clear()
        self.assertEqual(len(ROUTING["rules"]), 6)

    def test_gemini_and_google_api_proxy_rule_precedes_ru_ip_direct(self):
        rules = policy(["domain:google.com"], ["domain:ads.test"], ["5.0.0.0/8"], ["domain:gemini.google.com"])["rules"]
        self.assertEqual(rules[2]["balancerTag"], "auto")
        for domain in ("domain:google.com", "domain:googleapis.com", "domain:gstatic.com", "domain:googleusercontent.com", "domain:gemini.google.com"):
            self.assertIn(domain, rules[2]["domain"])
        self.assertEqual(rules[3]["outboundTag"], "direct")
        self.assertEqual(rules[4]["ip"], ["geoip:ru"])
        self.assertEqual(rules[0]["outboundTag"], "block")

    def test_geosite_conversion_preserves_matching_semantics(self):
        converted = domains({"version": 2, "rules": [{"domain": ["exact.test"], "domain_suffix": [".suffix.test"], "domain_regex": [r"^ad[0-9]+\.test$"], "domain_keyword": ["advert"]}]})
        self.assertEqual(converted, ["full:exact.test", "domain:suffix.test", r"regexp:^ad[0-9]+\.test$", "keyword:advert"])
        self.assertEqual(domains({"version": 2, "rules": [{"domain_regex": "^ads\\."}]}), ["regexp:^ads\\."])
        with self.assertRaises(ValueError): domains({"version": 2, "rules": [{"process_name": ["bad"]}]})
        with self.assertRaises(ValueError): domains({"version": 2, "rules": []})
        with self.assertRaises(ValueError): policy([], ["domain:ads.test"], ["5.0.0.0/8"])

    def test_unavailable_pool_blocks_and_udp_is_routed(self):
        node = parse_node(URI)
        config = build([node, node], ROUTING)
        self.assertEqual(config["outbounds"][0]["protocol"], "blackhole")
        self.assertEqual(config["routing"]["balancers"][0]["fallbackTag"], "block")
        self.assertEqual(config["routing"]["rules"][-1]["network"], "tcp,udp")
        self.assertTrue(config["inbounds"][0]["settings"]["udp"])
        with self.assertRaises(ValueError): build([], ROUTING)

    def test_atomic_cache_replaces_valid_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ru.json"
            atomic_write(path, "old")
            atomic_write(path, "new")
            self.assertEqual(path.read_text(), "new")
            self.assertEqual(len(list(path.parent.iterdir())), 1)

    def test_android_size_guard_refuses_oversized_publication(self):
        self.assertEqual(json.loads(serialized_config({"ok": True})), {"ok": True})
        with self.assertRaises(ValueError): serialized_config({"oversized": "x" * 125_000})

if __name__ == "__main__": unittest.main()
