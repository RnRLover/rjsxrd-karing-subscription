import json
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from certificate_checks import (probe_transport, complete_transport, reusable_transport,
                                 transport_report, transport_signature)


def node(security='tls', name='localhost', port=443, protocol='trojan'):
    return {'outbound': {'protocol': protocol, 'settings': {'servers': [
        {'address': '127.0.0.1', 'port': port}]}, 'streamSettings': {
        'security': security, 'tlsSettings': {'serverName': name}}}}


class EvidenceTests(unittest.TestCase):
    def test_reality_needs_xray_and_has_no_certificate_expiry_claim(self):
        evidence = probe_transport(node('reality'))
        self.assertFalse(reusable_transport(evidence, 100))
        done = complete_transport(evidence, 100)
        self.assertEqual(done['status'], 'passed')
        self.assertNotIn('not_after', done)
        self.assertTrue(reusable_transport(done, 101))
        self.assertFalse(reusable_transport(done, 3700))

    def test_ss_without_tls_is_not_applicable_but_others_are_rejected(self):
        evidence = probe_transport(node('none', protocol='shadowsocks'))
        self.assertEqual(evidence['status'], 'not_applicable')
        with self.assertRaises(ValueError):
            probe_transport(node('none'))

    def test_cached_certificate_cannot_outlive_expiry_or_clock_rollback(self):
        done = complete_transport({'kind': 'tls', 'status': 'passed', 'not_after': 150}, 100)
        self.assertEqual(done['next_check_at'], 150)
        for now in (99, 150, 3700):
            self.assertFalse(reusable_transport(done, now))
        self.assertTrue(reusable_transport(done, 149))
        self.assertFalse(reusable_transport(None, 100))
        self.assertFalse(reusable_transport({'status': 'failed'}, 100))

    def test_verification_bypasses_are_rejected(self):
        for key, value in [('allowInsecure', True), ('disableSystemRoot', True),
                           ('pinnedPeerCertSha256', 'abc'), ('verifyPeerCertByName', 'other.test')]:
            n = node(); n['outbound']['streamSettings']['tlsSettings'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                probe_transport(n)

    def test_report_publishes_renewal_or_warning_changes_not_check_timestamps(self):
        evidence = complete_transport({'kind': 'tls', 'status': 'passed', 'not_after': 5000,
                                       'sha256': 'abc', 'expires_soon': True}, 100)
        report = {'transport_checks': transport_report([{'transport_check': evidence}], {'xray_https:TimeoutError': 1})}
        a = transport_signature(json.dumps(report))
        evidence['checked_at'] = 200; evidence['next_check_at'] = 3800
        report['transport_checks']['servers'][0].update(evidence)
        self.assertEqual(a, transport_signature(json.dumps(report)))
        report['transport_checks']['servers'][0]['sha256'] = 'renewed'
        self.assertNotEqual(a, transport_signature(json.dumps(report)))


@unittest.skipUnless(shutil.which('openssl'), 'local TLS fixtures require OpenSSL')
class LocalTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.key = str(Path(cls.temp.name) / 'key.pem')
        cls.cert = str(Path(cls.temp.name) / 'cert.pem')
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', cls.key, '-out', cls.cert, '-days', '2',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.default_context = staticmethod(ssl.create_default_context)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def connect(self, name='localhost', trusted=True, now=None):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen()
        listener.settimeout(5)
        port = listener.getsockname()[1]
        def server():
            try:
                with listener:
                    sock, _ = listener.accept()
                    with sock:
                        with context.wrap_socket(sock, server_side=True):
                            pass
            except (OSError, ssl.SSLError):
                pass
        thread = threading.Thread(target=server, daemon=True); thread.start()
        try:
            with patch('certificate_checks.ssl.create_default_context',
                       side_effect=lambda: self.default_context(cafile=self.cert if trusted else None)):
                return probe_transport(node(name=name, port=port), now=now)
        finally:
            thread.join(timeout=6)

    def test_valid_chain_name_and_expiry_are_recorded(self):
        result = self.connect()
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(result['server_name'], 'localhost')
        self.assertEqual(len(result['sha256']), 64)
        self.assertTrue(result['expires_soon'])
        self.assertGreater(result['not_after'], int(time.time()))

    def test_expiry_cutoff_is_enforced(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.connect(now=int(time.time()) + 3 * 86400)

    def test_hostname_mismatch_fails_real_handshake(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.connect(name='wrong.example')

    def test_untrusted_self_signed_certificate_fails_real_handshake(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.connect(trusted=False)


if __name__ == '__main__':
    unittest.main()
