import copy
import json
import unittest
from unittest.mock import patch
from gemini_checks import probe, experimental_profile, PAGE_URL, DATA_BYTES, LABEL
from karing import subscription_variants


class Response:
    def __init__(self, body, status=200, url=PAGE_URL, kind='text/html'):
        self.body, self.status, self.url = body, status, url
        self.headers = {'Content-Type': kind}
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def getcode(self): return self.status
    def geturl(self): return self.url
    def read(self, n): return self.body[:n]


class Opener:
    def __init__(self, *responses): self.responses = iter(responses)
    def open(self, *args, **kwargs): return next(self.responses)


def page(text='Welcome to Gemini'):
    return ('<html><title>Google Gemini</title><body>' + text + ' ' * 5000 + '</body></html>').encode()


class GeminiChecks(unittest.TestCase):
    def test_complete_page_and_transfer_pass(self):
        result = probe(Opener(Response(page()), Response(b'x' * DATA_BYTES)))
        self.assertTrue(result['passed'])
        self.assertEqual(result['transfer_bytes'], DATA_BYTES)

    def test_denial_redirect_captcha_and_incomplete_transfer_fail(self):
        responses = [Response(page(), status=403), Response(page(), url='https://accounts.google.com/'),
                     Response(page("Gemini isn't available in your country")),
                     Response(page('Our systems have detected unusual traffic')),
                     Response(b'<html>Gemini</html>'), Response(page(), kind='text/plain')]
        for response in responses:
            with self.subTest(response=response), self.assertRaises(ValueError):
                probe(Opener(response))
        with self.assertRaises(ValueError):
            probe(Opener(Response(page()), Response(b'x' * (DATA_BYTES - 1))))

    def test_unused_script_denial_strings_do_not_reject_normal_page(self):
        result = probe(Opener(Response(page("Welcome<script>Gemini isn't available in your country</script>")),
                              Response(b'x' * DATA_BYTES)))
        self.assertTrue(result['passed'])

    def test_publication_ignores_probe_timestamps_but_tracks_membership(self):
        from publication_changed import gemini_signature
        a = {'gemini_check': {'status': 'available', 'selected_source_tags': ['pool-01'],
                             'servers': [{'tag': 'pool-01', 'passed': True, 'checked_at': 1}]}}
        b = copy.deepcopy(a); b['gemini_check']['servers'][0]['checked_at'] = 2
        self.assertEqual(gemini_signature(json.dumps(a)), gemini_signature(json.dumps(b)))
        b['gemini_check']['servers'][0]['passed'] = False
        self.assertNotEqual(gemini_signature(json.dumps(a)), gemini_signature(json.dumps(b)))

    def test_experiment_keeps_main_and_references_only_selected_nodes(self):
        base = {'inbounds': [{'tag': 'socks-in'}], 'outbounds': [
            {'tag': 'pool-01', 'protocol': 'vless'}, {'tag': 'pool-02', 'protocol': 'vless'},
            {'tag': 'pool-03', 'protocol': 'trojan'}, {'tag': 'direct', 'protocol': 'freedom'},
            {'tag': 'block', 'protocol': 'blackhole'}], 'routing': {'rules': [], 'balancers': [
                {'tag': 'auto', 'selector': ['pool-']}]}, 'burstObservatory': {'subjectSelector': ['pool-']}}
        before = copy.deepcopy(base)
        main_before = subscription_variants(base)
        result = experimental_profile(base, [base['outbounds'][1], base['outbounds'][2]])
        self.assertEqual(base, before)
        self.assertEqual(subscription_variants(base), main_before)
        self.assertEqual(result['remarks'], LABEL)
        self.assertEqual(result['routing']['balancers'][0]['selector'], [LABEL, 'pool-03'])
        self.assertEqual(result['routing']['balancers'][0]['fallbackTag'], LABEL)
        self.assertEqual(result['burstObservatory']['subjectSelector'], [LABEL, 'pool-03'])
        self.assertNotIn('dns', result)
        self.assertEqual(result['routing']['rules'], main_before[0]['routing']['rules'])
        self.assertIsNone(experimental_profile(base, []))
