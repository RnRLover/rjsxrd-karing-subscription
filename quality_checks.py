"""Bounded, verified HTTPS transfer checks and actual-observation history."""
import json
import math
import statistics
import time
import urllib.request

VERSION = 1
HEALTH_URLS = ('https://www.gstatic.com/generate_204', 'https://cp.cloudflare.com/generate_204')
TRANSFER_URL = 'https://speed.cloudflare.com/__down?bytes=262144'
TRANSFER_BYTES = 262144
TTL = 900
WINDOW = 10
MAX_AGE = 7 * 86400
HTTP_TIMEOUT = 4
TRANSFER_SECONDS = 12


def probe_quality(opener, clock=time.monotonic, now=time.time):
    samples, sites, errors = [], [], []
    # Two probes at each independently operated HTTPS destination. Responses
    # must be exactly 204: redirects/HTML/captive portals are not successes.
    for url in HEALTH_URLS:
        passed = 0
        for _ in range(2):
            start = clock()
            try:
                req = urllib.request.Request(url, headers={'Cache-Control': 'no-cache'})
                with opener.open(req, timeout=HTTP_TIMEOUT) as response:
                    if response.getcode() != 204 or response.geturl() != url:
                        raise ValueError('health_status_or_redirect')
                elapsed = (clock() - start) * 1000
                if not math.isfinite(elapsed) or elapsed < 0:
                    raise ValueError('invalid_timing')
                samples.append(round(elapsed, 1)); passed += 1
            except Exception as error:
                errors.append(type(error).__name__)
        sites.append({'url': url, 'passed': passed, 'attempts': 2})
    transferred, transfer_ms, transfer_ok = 0, None, False
    if all(s['passed'] for s in sites) and len(samples) >= 3:
        start = clock()
        try:
            request = urllib.request.Request(TRANSFER_URL, headers={
                'Accept-Encoding': 'identity', 'Cache-Control': 'no-cache'})
            with opener.open(request, timeout=HTTP_TIMEOUT) as response:
                if response.getcode() != 200 or response.geturl() != TRANSFER_URL:
                    raise ValueError('transfer_status_or_redirect')
                if response.headers.get('Content-Encoding', 'identity').lower() != 'identity':
                    raise ValueError('compressed_transfer')
                if response.headers.get('Content-Type', '').split(';')[0].strip().lower() != 'application/octet-stream':
                    raise ValueError('unexpected_transfer_type')
                while transferred <= TRANSFER_BYTES:
                    if clock() - start > TRANSFER_SECONDS:
                        raise TimeoutError('transfer_deadline')
                    chunk = response.read(min(16384, TRANSFER_BYTES + 1 - transferred))
                    if not chunk: break
                    transferred += len(chunk)
            transfer_ms = round((clock() - start) * 1000, 1)
            transfer_ok = transferred == TRANSFER_BYTES and 0 < transfer_ms <= TRANSFER_SECONDS * 1000
            if not transfer_ok: raise ValueError('incomplete_or_slow_transfer')
        except Exception as error:
            errors.append(type(error).__name__)
    median = round(statistics.median(samples), 1) if samples else None
    spread = round(max(samples) - min(samples), 1) if samples else None
    return {'version': VERSION, 'checked_at': int(now()),
            'passed': all(s['passed'] for s in sites) and len(samples) >= 3 and transfer_ok,
            'sites': sites, 'samples_ms': samples, 'median_ms': median,
            'spread_ms': spread, 'worst_ms': max(samples) if samples else None,
            'transfer_bytes': transferred, 'transfer_ms': transfer_ms,
            'transfer_url': TRANSFER_URL, 'errors': errors}


def reusable_quality(evidence, now):
    try:
        return (evidence['version'] == VERSION and evidence['passed'] is True
                and 0 <= now - evidence['checked_at'] < TTL
                and evidence['transfer_bytes'] == TRANSFER_BYTES)
    except (KeyError, TypeError):
        return False


def history_summary(entry, now):
    history = [h for h in entry.get('quality_history', [])
               if h.get('version') == VERSION and 0 <= now - h.get('at', 0) < MAX_AGE][-WINDOW:]
    passed = sum(h['passed'] is True for h in history)
    return {'observations': len(history), 'passed': passed,
            'success_rate': passed / len(history) if history else 0,
            'provisional': len(history) < 3}


def record_result(entry, passed, now):
    history = [h for h in entry.get('quality_history', [])
               if h.get('version') == VERSION and 0 <= now - h.get('at', 0) < MAX_AGE]
    # Reuse of a cached measurement never calls this function. Guard against
    # duplicate recording of the same actual observation, too.
    if not history or history[-1]['at'] != now:
        history.append({'at': now, 'passed': bool(passed), 'version': VERSION})
    return {**entry, 'quality_history': history[-WINDOW:]}


def quality_admitted(node):
    q, h = node.get('quality_check') or {}, node.get('quality_history') or {}
    return (q.get('passed') is True and h.get('observations', 0) > 0
            and h.get('success_rate', 0) >= .9)


def quality_priority(node):
    q, h = node['quality_check'], node['quality_history']
    # Coarse performance bands allow infrastructure diversity within a similar
    # quality level. Historical failures and jitter count alongside median RTT.
    score = (q['median_ms'] + .5 * q['spread_ms'] + .05 * q['transfer_ms']
             + 2000 * (1 - h['success_rate']) + 2000 * (1 - len(q['samples_ms']) / 4))
    return (int(h['provisional']), int(score // 250))


def quality_report(nodes, selected):
    return {'version': VERSION, 'vantage': 'GitHub Actions runner',
            'health_urls': list(HEALTH_URLS), 'transfer_url': TRANSFER_URL,
            'transfer_bytes': TRANSFER_BYTES, 'transfer_deadline_seconds': TRANSFER_SECONDS,
            'cache_seconds': TTL, 'history_window': WINDOW, 'history_max_age_seconds': MAX_AGE,
            'history_min_success_rate': .9, 'established_after_observations': 3,
            'warning': 'Runner tests do not measure reachability or speed on the device/operator; provisional is not established reliability.',
            'candidates': len(nodes), 'admitted': sum(quality_admitted(n) for n in nodes),
            'selected': len(selected), 'provisional_selected': sum(n['quality_history']['provisional'] for n in selected),
            'caps': {'nodes': 40, 'per_exit_ip': 2, 'per_entry_prefix': 4, 'per_host': 2},
            'servers': [{'tag': f'pool-{i:02d}', 'check': n['quality_check'],
                         'history': n['quality_history'], 'priority': quality_priority(n)}
                        for i, n in enumerate(selected, 1)]}


def quality_signature(data):
    servers = json.loads(data).get('quality_selection', {}).get('servers', [])
    return [{**s, 'check': {k: v for k, v in s['check'].items() if k != 'checked_at'}} for s in servers]
