"""Exit-IP reputation evidence from IPsum; absence is not a whitelist guarantee."""
import hashlib
import ipaddress
import re
from email.utils import parsedate_to_datetime


FEED_URL = 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt'
CACHE_KEY = '_ipsum_reputation_v1'
REFRESH_SECONDS = 86400
MAX_AGE_SECONDS = 3 * 86400


def usable(feed, now):
    try:
        return (feed['url'] == FEED_URL and feed['counts'] and
                -3600 <= now - feed['published_at'] <= MAX_AGE_SECONDS and
                0 <= now - feed['fetched_at'] <= MAX_AGE_SECONDS)
    except (KeyError, TypeError):
        return False


def parse_feed(text, now):
    """Reject malformed/error/undated input rather than assign false clean scores."""
    header = re.search(r'^# Last update:\s*(.+)$', text, re.MULTILINE)
    if not text.startswith('# IPsum Threat Intelligence Feed') or not header:
        raise ValueError('IPsum feed header or publication time missing')
    stamp = parsedate_to_datetime(header[1])
    if stamp.tzinfo is None:
        raise ValueError('IPsum publication time needs a timezone')
    counts = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        fields = line.split()
        if len(fields) != 2:
            raise ValueError('invalid IPsum record')
        ip = ipaddress.ip_address(fields[0])
        count = int(fields[1])
        if not ip.is_global or count < 1 or str(ip) in counts:
            raise ValueError('invalid or duplicate IPsum address/count')
        counts[str(ip)] = count
    feed = {'url': FEED_URL, 'published_at': int(stamp.timestamp()),
            'fetched_at': now, 'sha256': hashlib.sha256(text.encode()).hexdigest(),
            'counts': counts}
    if not usable(feed, now):
        raise ValueError('IPsum feed is empty, stale, or future-dated')
    return feed


def load_feed(cache, fetch, now):
    """Share the existing Actions evidence cache; refresh daily, expire after 72h."""
    cached = cache.get(CACHE_KEY)
    if usable(cached, now) and now - cached['fetched_at'] < REFRESH_SECONDS:
        return cached, 'cache'
    try:
        feed = parse_feed(fetch(FEED_URL), now)
    except Exception as error:
        if usable(cached, now):
            return cached, 'cache_after_refresh_error'
        raise ValueError('no usable IPsum reputation evidence; keep published pool') from error
    cache[CACHE_KEY] = feed
    return feed, 'download'


def rate_ip(address, feed):
    try:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ValueError('non-public IP')
    except (ValueError, TypeError):
        return {'status': 'unknown', 'score': None, 'blacklist_count': None}
    count = feed['counts'].get(str(ip), 0)
    # IPsum currently provides IPv4 coverage. Do not call an absent IPv6 clean.
    if ip.version == 6 and not count:
        return {'status': 'unknown', 'score': None, 'blacklist_count': None}
    return {'status': 'listed' if count else 'not_listed',
            'score': max(0, 100 - 20 * count), 'blacklist_count': count}


def rank_nodes(nodes, feed):
    return [{**node, 'reputation': rate_ip(node.get('exit_ip'), feed)} for node in nodes]


def reputation_report(nodes, selected, feed, source):
    from collections import Counter
    return {
        'provider': 'IPsum (stamparm/ipsum)', 'url': FEED_URL,
        'published_at': feed['published_at'], 'fetched_at': feed['fetched_at'],
        'sha256': feed['sha256'], 'feed_entries': len(feed['counts']),
        'evidence_source': source, 'unlisted_coverage': 'IPv4 only',
        'score_formula': 'max(0, 100 - 20 * IPsum blacklist occurrence count)',
        'selection_priority': 'exclude listed exits; retain unlisted and unknown coverage; maximize count and infrastructure diversity',
        'meaning': 'No listing in this feed is not a positive whitelist or proof of Gemini access.',
        'candidates': dict(Counter(n['reputation']['status'] for n in nodes)),
        'selected': dict(Counter(n['reputation']['status'] for n in selected)),
        'servers': [{'tag': f'pool-{i:02d}', 'exit_ip': n['exit_ip'], **n['reputation']}
                    for i, n in enumerate(selected, 1)],
    }
