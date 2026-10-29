"""HTTP health latency through the exact Xray outbound, not ICMP to its entry."""
import json
import math
import statistics
import time
import urllib.request
from collections import Counter

URL = 'https://www.gstatic.com/generate_204'
SAMPLES = 2
TIMEOUT = 5
TTL = 3600
BUCKET_MS = 100


def measure_latency(opener, clock=time.perf_counter, now=time.time):
    samples, errors = [], Counter()
    for _ in range(SAMPLES):
        try:
            start = clock()
            with opener.open(urllib.request.Request(URL, method='HEAD'), timeout=TIMEOUT) as response:
                if response.getcode() != 204:
                    raise ValueError('health response must be HTTP 204')
                elapsed = (clock() - start) * 1000
                if not math.isfinite(elapsed) or elapsed < 0:
                    raise ValueError('invalid measurement')
                samples.append(round(elapsed, 1))
        except Exception as error:
            errors[type(error).__name__] += 1
    return {'url': URL, 'method': 'HEAD', 'checked_at': int(now()),
            'samples_ms': samples, 'attempts': SAMPLES, 'failed': SAMPLES - len(samples),
            'median_ms': round(statistics.median(samples), 1) if samples else None,
            'errors': dict(errors)}


def reusable_latency(evidence, now):
    try:
        return (evidence['url'] == URL and evidence['method'] == 'HEAD'
                and evidence['attempts'] == SAMPLES
                and 0 <= now - evidence['checked_at'] < TTL)
    except (TypeError, KeyError):
        return False


def latency_priority(node):
    evidence = node.get('latency_check') or {}
    value = evidence.get('median_ms')
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        return (2, 0)
    return (0 if evidence.get('failed') == 0 else 1, int(value // BUCKET_MS))


def latency_value(node):
    return (node['latency_check']['median_ms']
            if latency_priority(node)[0] < 2 else math.inf)


def order_by_latency(nodes):
    """Sort the already selected pool by median milliseconds; unknowns last.

    Sorting is stable for equal/unknown latency, preserving diversity order.
    No node is excluded because a health probe failed.
    """
    return sorted(nodes, key=latency_value)


def latency_report(nodes, selected):
    return {'url': URL, 'method': 'HEAD', 'attempts': SAMPLES, 'timeout_seconds': TIMEOUT,
            'cache_seconds': TTL, 'vantage': 'GitHub Actions runner',
            'policy': 'select reputation-eligible diverse membership first; order selected pool by ascending median milliseconds; unknown last',
            'failed_probe_policy': 'keep nodes; partial samples use their median; no successful samples sorts last',
            'candidates': len(nodes),
            'candidates_measured': sum(latency_priority(n)[0] < 2 for n in nodes),
            'servers': [{'tag': f'pool-{i:02d}', 'latency': n.get('latency_check')}
                        for i, n in enumerate(selected, 1)]}


def latency_signature(data):
    # Evidence dates alone do not require a new subscription commit.
    servers = json.loads(data).get('latency_selection', {}).get('servers', [])
    return [{**s, 'latency': {k: v for k, v in (s.get('latency') or {}).items()
                             if k != 'checked_at'}} for s in servers]
