import json
from pathlib import Path
import tempfile
import unittest
from check_ru import tcp_result, endpoint, endpoints, measure, run


class RussianProbeTests(unittest.TestCase):
    def test_tcp_success_is_not_icmp_ping_and_pending_is_unknown(self):
        self.assertEqual(tcp_result([{'time': 0.012, 'address': '1.1.1.1'}])['tcp_connect_ms'], 12)
        self.assertEqual(tcp_result([{'error': 'Connection timed out'}])['status'], 'unreachable')
        for value in (None, [], [[None]], [{}], [{'time': float('nan'), 'address': '1.1.1.1'}]):
            self.assertEqual(tcp_result(value)['status'], 'unknown')

    def test_endpoint_extraction_does_not_send_keys(self):
        config = {'outbounds': [{'tag': 'pool-1', 'protocol': 'vless', 'settings': {'vnext': [{'address': '1.1.1.1', 'port': 443, 'users': [{'id': 'secret'}]}]}}, {'tag': 'direct', 'protocol': 'freedom'}]}
        self.assertEqual(endpoints(config), {'1.1.1.1:443': ['pool-1']})
        self.assertEqual(endpoint('2606:4700:4700::1111', 443), '[2606:4700:4700::1111]:443')
        for host in ('127.0.0.1', '10.0.0.1', '::1', 'host/path', 'host.local'):
            with self.assertRaises(ValueError): endpoint(host, 443)

    def test_only_confirmed_ru_probes_count(self):
        def request(path):
            if path.startswith('/check-tcp?'):
                return {'ok': 1, 'request_id': 'abc', 'nodes': {'ru1': ['ru', 'Russia'], 'ru2': ['de', 'Germany']}}
            return {'ru1': [{'error': 'Connection timed out'}], 'ru2': [{'time': 0.001, 'address': '1.1.1.1'}]}
        result = measure('1.1.1.1:443', {'ru1': {}, 'ru2': {}}, request, lambda _: None)
        self.assertEqual(result['status'], 'unknown')
        self.assertEqual(result['probes']['ru1']['status'], 'unreachable')
        self.assertEqual(result['probes']['ru2']['status'], 'unknown')

    def test_inventory_outage_keeps_config_and_reports_unknown(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'ru.json'
            config = {'outbounds': [{'tag': 'pool-1', 'protocol': 'trojan', 'settings': {'servers': [{'address': '1.1.1.1', 'port': 443, 'password': 'secret'}]}}]}
            path.write_text(json.dumps(config))
            original = path.read_bytes()
            def request(_): raise OSError('API down')
            self.assertEqual(run([path], temp, request=request)['ru']['unknown'], 1)
            self.assertEqual(path.read_bytes(), original)
            report = json.loads((Path(temp) / 'ru-reachability.json').read_bytes())
            self.assertFalse(report['filters_pool'])
            self.assertNotIn('secret', json.dumps(report))
