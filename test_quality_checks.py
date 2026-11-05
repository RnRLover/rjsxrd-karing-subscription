import copy
import json
import unittest
from unittest.mock import patch
from quality_checks import (probe_quality, probe_control, HEALTH_URLS,
                            quality_admitted, quality_signature)
from pool_selection import select_pool
from test_pool_selection import node


class Response:
    def __init__(self, url, status=204):
        self.url, self.status = url, status
    def getcode(self): return self.status
    def geturl(self): return self.url
    def __enter__(self): return self
    def __exit__(self, *args): pass


class Opener:
    def __init__(self, failures=(), redirect=False, status=204):
        self.calls = []; self.methods = []; self.failures = set(failures)
        self.redirect, self.status = redirect, status
    def open(self, request, timeout):
        i = len(self.calls); self.calls.append(request.full_url)
        self.methods.append(request.get_method())
        if i in self.failures: raise TimeoutError()
        return Response('https://portal.invalid/' if self.redirect else request.full_url, self.status)


class Clock:
    def __init__(self, step=.01): self.value = 0; self.step = step
    def __call__(self): self.value += self.step; return self.value


def healthy(host, ip, latency=100):
    q = {'version': 3, 'passed': True, 'checked_at': 100,
         'samples_ms': [latency] * 4, 'median_ms': latency, 'spread_ms': 0,
         'sites': [{'url': url, 'passed': 2, 'attempts': 2} for url in HEALTH_URLS]}
    return {**node(host), 'exit_ip': ip, 'quality_check': q}


class QualityTests(unittest.TestCase):
    def test_only_two_site_https_head_is_requested_without_file_download(self):
        opener=Opener(); q=probe_quality(opener,Clock(),lambda:100)
        self.assertTrue(q['passed'])
        self.assertEqual(opener.calls,[HEALTH_URLS[0]]*2+[HEALTH_URLS[1]]*2)
        self.assertEqual(opener.methods,['HEAD']*4)
        self.assertNotIn('transfer_bytes',q)

    def test_one_transient_probe_allowed_but_both_sites_required(self):
        self.assertTrue(probe_quality(Opener(failures=[0]),Clock())['passed'])
        for failures in ([0,1], [0,2], [0,1,2,3]):
            self.assertFalse(probe_quality(Opener(failures=failures),Clock())['passed'])
        self.assertFalse(probe_quality(Opener(redirect=True),Clock())['passed'])
        self.assertFalse(probe_quality(Opener(status=200),Clock())['passed'])

    def test_runner_control_retries_without_admitting_a_failed_control(self):
        failed={'passed':False,'errors':['TimeoutError']}
        passed={'passed':True,'errors':[]}
        pauses=[]
        with patch('quality_checks.probe_quality', side_effect=[failed.copy(),passed.copy()]):
            result=probe_control(None,pause=pauses.append)
            self.assertTrue(result['passed']); self.assertEqual(result['control_attempts'],2)
            self.assertEqual(pauses,[.5])
        with patch('quality_checks.probe_quality', return_value=failed.copy()):
            result=probe_control(None,pause=lambda _:None)
            self.assertFalse(result['passed']); self.assertEqual(result['control_attempts'],3)

    def test_strict_exit_prefix_and_host_caps_no_unchecked_fallback(self):
        nodes=[healthy(f'h{i}', '8.8.8.8') for i in range(12)]
        self.assertEqual(len(select_pool(nodes,40,network_lookup=lambda h:'net',require_quality=True)),2)
        for i,n in enumerate(nodes): n['exit_ip']=f'8.8.4.{i+1}'
        self.assertEqual(len(select_pool(nodes,40,network_lookup=lambda h:'net',require_quality=True)),4)
        self.assertEqual(select_pool([node('unchecked')],40,network_lookup=lambda h:h,require_quality=True),[])
        same=[]
        for i in range(5):
            n=healthy('host',f'8.8.4.{i+1}'); n['outbound']['streamSettings']['network']=str(i);same.append(n)
        self.assertEqual(len(select_pool(same,40,network_lookup=lambda h:h,require_quality=True)),2)

    def test_current_quality_wins_regardless_of_old_history(self):
        slow=healthy('slow','8.8.8.8',latency=500)
        fast=healthy('fast','1.1.1.1',latency=1)
        slow['quality_history']={'observations':10,'success_rate':1,'provisional':False}
        fast['quality_history']={'observations':1,'success_rate':0,'provisional':True}
        self.assertEqual(select_pool([slow,fast],1,network_lookup=lambda h:h,require_quality=True),[fast])
        current=[healthy(f'n{i}',f'1.1.1.{i+1}') for i in range(50)]
        self.assertEqual(len(select_pool(current,40,network_lookup=lambda h:h,require_quality=True)),40)
        failed=healthy('failed','1.1.1.2');failed['quality_check']['passed']=False
        self.assertFalse(quality_admitted(failed))

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
