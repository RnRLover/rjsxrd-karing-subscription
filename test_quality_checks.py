import copy
import io
import json
import unittest
from quality_checks import (probe_quality, HEALTH_URLS, TRANSFER_URL, TRANSFER_BYTES,
                            TTL, reusable_quality, record_result, history_summary,
                            quality_admitted, quality_signature, MAX_AGE)
from pool_selection import select_pool
from test_pool_selection import node


class Response:
    def __init__(self, url, status=204, body=b'', content_type='application/octet-stream'):
        self.url, self.status, self.body = url, status, io.BytesIO(body)
        self.headers = {'Content-Type': content_type}
    def getcode(self): return self.status
    def geturl(self): return self.url
    def read(self, n): return self.body.read(n)
    def __enter__(self): return self
    def __exit__(self, *args): pass


class Opener:
    def __init__(self, failures=(), body=None, redirect=False, kind='application/octet-stream'):
        self.calls = []; self.failures = set(failures)
        self.body = b'x' * TRANSFER_BYTES if body is None else body
        self.redirect, self.kind = redirect, kind
    def open(self, request, timeout):
        i = len(self.calls); self.calls.append(request.full_url)
        if i in self.failures: raise TimeoutError()
        url = request.full_url
        return Response('https://portal.invalid/' if self.redirect else url,
                        200 if url == TRANSFER_URL else 204,
                        self.body if url == TRANSFER_URL else b'', self.kind)


class Clock:
    def __init__(self, step=.01): self.value = 0; self.step = step
    def __call__(self): self.value += self.step; return self.value


def healthy(host, ip, observations=3, latency=100):
    q = {'version': 1, 'passed': True, 'checked_at': 100,
         'samples_ms': [latency] * 4, 'median_ms': latency, 'spread_ms': 0,
         'transfer_ms': 500, 'transfer_bytes': TRANSFER_BYTES}
    return {**node(host), 'exit_ip': ip, 'quality_check': q,
            'quality_history': {'observations': observations, 'passed': observations,
                                'success_rate': 1, 'provisional': observations < 3}}


class QualityTests(unittest.TestCase):
    def test_two_independent_sites_and_complete_bounded_transfer(self):
        opener = Opener(); q = probe_quality(opener, Clock(), lambda:100)
        self.assertTrue(q['passed']); self.assertEqual(q['transfer_bytes'], TRANSFER_BYTES)
        self.assertEqual(opener.calls, [HEALTH_URLS[0]]*2+[HEALTH_URLS[1]]*2+[TRANSFER_URL])
        self.assertTrue(reusable_quality(q, 100+TTL-1))
        for at in (99, 100+TTL): self.assertFalse(reusable_quality(q, at))
        self.assertFalse(reusable_quality({'version':0}, 100))

    def test_one_transient_probe_allowed_but_both_sites_required(self):
        self.assertTrue(probe_quality(Opener(failures=[0]), Clock())['passed'])
        for failures in ([0,1], [0,2], [0,1,2,3]):
            opener=Opener(failures); q=probe_quality(opener, Clock())
            self.assertFalse(q['passed']); self.assertNotIn(TRANSFER_URL, opener.calls)

    def test_short_oversized_html_redirect_and_stalled_download_fail(self):
        for opener in (Opener(body=b'x'*16000), Opener(body=b'x'*(TRANSFER_BYTES+1)),
                       Opener(kind='text/html'), Opener(redirect=True)):
            self.assertFalse(probe_quality(opener, Clock())['passed'])
        self.assertFalse(probe_quality(Opener(), Clock(step=2))['passed'])

    def test_real_observations_only_rolling_window_age_and_recovery(self):
        entry={}
        for at in range(10, 20): entry=record_result(entry, at!=10, at)
        summary=history_summary(entry,20)
        self.assertEqual(summary['observations'],10);self.assertEqual(summary['success_rate'],.9)
        unchanged=record_result(entry, True, 19)
        self.assertEqual(unchanged,entry)
        entry=record_result(entry,True,20)
        self.assertEqual(history_summary(entry,21)['success_rate'],1)
        self.assertEqual(history_summary(entry,21+MAX_AGE)['observations'],0)
        n=healthy('a','8.8.8.8'); n['quality_history']['success_rate']=.8
        self.assertFalse(quality_admitted(n))
        n['quality_history']['success_rate']=.9
        self.assertTrue(quality_admitted(n))
        n['quality_check']['passed']=False
        self.assertFalse(quality_admitted(n))

    def test_strict_exit_prefix_and_host_caps_no_unchecked_fallback(self):
        nodes=[healthy(f'h{i}', '8.8.8.8') for i in range(12)]
        selected=select_pool(nodes,40,network_lookup=lambda h:'net',require_quality=True)
        self.assertEqual(len(selected),2)
        for i,n in enumerate(nodes): n['exit_ip']=f'8.8.4.{i+1}'
        self.assertEqual(len(select_pool(nodes,40,network_lookup=lambda h:'net',require_quality=True)),4)
        self.assertEqual(select_pool([node('unchecked')],40,network_lookup=lambda h:h,require_quality=True),[])
        same=[]
        for i in range(5):
            n=healthy('host',f'8.8.4.{i+1}'); n['outbound']['streamSettings']['network']=str(i);same.append(n)
        self.assertEqual(len(select_pool(same,40,network_lookup=lambda h:h,require_quality=True)),2)

    def test_established_quality_precedes_ping_and_new_nodes_are_limited(self):
        slow=healthy('slow','8.8.8.8',latency=200)
        new=healthy('new','1.1.1.1',observations=1,latency=1)
        self.assertEqual(select_pool([new,slow],1,network_lookup=lambda h:h,require_quality=True),[slow])
        mature=[healthy(f'm{i}', f'8.8.4.{i+1}') for i in range(10)]
        new=[healthy(f'n{i}', f'1.1.1.{i+1}',observations=1) for i in range(50)]
        chosen=select_pool(mature+new,40,network_lookup=lambda h:h,require_quality=True)
        self.assertEqual(len(chosen),18)
        self.assertEqual(len(select_pool(new,512,network_lookup=lambda h:h,require_quality=True)),40)

    def test_jitter_penalty_and_diversity_within_quality_band(self):
        a=healthy('a','8.8.8.8',latency=50); b=healthy('b','1.1.1.1',latency=100)
        a['quality_check']['spread_ms']=1500
        self.assertEqual(select_pool([a,b],1,network_lookup=lambda h:h,require_quality=True),[b])
        nodes=[healthy('a','8.8.8.8'),healthy('b','8.8.8.8'),healthy('c','1.1.1.1')]
        chosen=select_pool(nodes,2,network_lookup=lambda h:h,require_quality=True)
        self.assertEqual(len({n['exit_ip'] for n in chosen}),2)

    def test_quality_report_timestamp_does_not_trigger_publication(self):
        data={'quality_selection':{'servers':[{'tag':'pool-01','check':{'checked_at':1,'passed':True}}]}}
        before=quality_signature(json.dumps(data));data['quality_selection']['servers'][0]['check']['checked_at']=2
        self.assertEqual(before,quality_signature(json.dumps(data)))
        data['quality_selection']['servers'][0]['check']['passed']=False
        self.assertNotEqual(before,quality_signature(json.dumps(data)))

if __name__=='__main__': unittest.main()
