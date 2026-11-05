"""Current-run HTTPS tunnel health and latency checks; no measurement history."""
import json
import math
import statistics
import time
import urllib.request

VERSION = 3
HEALTH_URLS = ('https://www.gstatic.com/generate_204', 'https://cp.cloudflare.com/generate_204')
HTTP_TIMEOUT = 4
CONTROL_ATTEMPTS = 3


def probe_quality(opener, clock=time.monotonic, now=time.time):
    samples, sites, errors = [], [], []
    for url in HEALTH_URLS:
        passed = 0
        for _ in range(2):
            start = clock()
            try:
                req = urllib.request.Request(url, method='HEAD', headers={'Cache-Control': 'no-cache'})
                with opener.open(req, timeout=HTTP_TIMEOUT) as response:
                    if response.getcode() != 204 or response.geturl() != url:
                        raise ValueError('health_status_or_redirect')
                elapsed = (clock() - start) * 1000
                if not math.isfinite(elapsed) or elapsed < 0:
                    raise ValueError('invalid_timing')
                samples.append(round(elapsed, 1)); passed += 1
            except Exception as error:
                errors.append(type(error).__name__ + (':' + str(error.code) if hasattr(error, 'code') else ''))
        sites.append({'url': url, 'passed': passed, 'attempts': 2})
    median = round(statistics.median(samples), 1) if samples else None
    spread = round(max(samples) - min(samples), 1) if samples else None
    return {'version': VERSION, 'checked_at': int(now()),
            'passed': all(s['passed'] for s in sites) and len(samples) >= 3,
            'method': 'HEAD', 'sites': sites, 'samples_ms': samples, 'median_ms': median,
            'spread_ms': spread, 'worst_ms': max(samples) if samples else None, 'errors': errors}


def probe_control(opener, attempts=CONTROL_ATTEMPTS, pause=time.sleep):
    """Retry a transient runner-side outage before rejecting the whole build."""
    for attempt in range(1, attempts + 1):
        result = probe_quality(opener)
        result['control_attempts'] = attempt
        if result['passed']:
            return result
        if attempt < attempts:
            pause(.5 * attempt)
    return result


def quality_admitted(node):
    q = node.get('quality_check') or {}
    sites = q.get('sites') or []
    return (q.get('version') == VERSION and q.get('passed') is True
            and len(q.get('samples_ms', [])) >= 3
            and {s.get('url') for s in sites if s.get('passed', 0) > 0} == set(HEALTH_URLS))


def quality_priority(node):
    q = node['quality_check']
    score = (q['median_ms'] + .5 * q['spread_ms']
             + 2000 * (1 - len(q['samples_ms']) / 4))
    return int(score // 250)


def quality_report(nodes, selected):
    return {'version': VERSION, 'vantage': 'GitHub Actions runner',
            'health_urls': list(HEALTH_URLS), 'method': 'HEAD',
            'file_transfer_check': False, 'measurement_cache': False,
            'selection_basis': 'current_run_only',
            'warning': 'HTTPS latency checks do not measure sustained transfer speed or device/operator reachability.',
            'candidates': len(nodes), 'admitted': sum(quality_admitted(n) for n in nodes),
            'selected': len(selected),
            'caps': {'nodes': 40, 'per_exit_ip': 2, 'per_entry_prefix': 4, 'per_host': 2},
            'servers': [{'tag': f'pool-{i:02d}', 'check': n['quality_check'],
                         'priority': quality_priority(n)} for i, n in enumerate(selected, 1)]}


def quality_signature(data):
    servers = json.loads(data).get('quality_selection', {}).get('servers', [])
    return [{**s, 'check': {k: v for k, v in s['check'].items() if k != 'checked_at'}} for s in servers]
