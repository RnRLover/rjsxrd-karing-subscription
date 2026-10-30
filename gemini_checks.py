"""Logged-out Gemini page reachability, not authenticated service eligibility."""
import concurrent.futures
import copy
import html
from html.parser import HTMLParser
import json
import re
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

PAGE_URL = 'https://gemini.google.com/app?hl=en'
DATA_URL = 'https://speed.cloudflare.com/__down?bytes=262144'
DATA_BYTES = 262144
MAX_PAGE = 2_000_000
TIMEOUT = 12
LABEL = 'Gemini · проверка страницы'
LIMIT = 40


class VisibleText(HTMLParser):
    def __init__(self):
        super().__init__(); self.hidden = 0; self.parts = []
    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'): self.hidden += 1
    def handle_endtag(self, tag):
        if tag in ('script', 'style'): self.hidden = max(0, self.hidden - 1)
    def handle_data(self, data):
        if not self.hidden: self.parts.append(data)


def probe(opener):
    started = time.monotonic()
    request = urllib.request.Request(PAGE_URL, headers={
        'User-Agent': 'Mozilla/5.0', 'Accept-Language': 'en-US,en;q=0.9'})
    with opener.open(request, timeout=TIMEOUT) as response:
        final = urllib.parse.urlsplit(response.geturl())
        if response.getcode() != 200 or final.scheme != 'https' or final.hostname != 'gemini.google.com':
            raise ValueError('not_gemini_page')
        if 'text/html' not in response.headers.get('Content-Type', '').lower():
            raise ValueError('not_html')
        data = response.read(MAX_PAGE + 1)
    if len(data) > MAX_PAGE or len(data) < 4096:
        raise ValueError('page_size')
    text = html.unescape(data.decode('utf-8', errors='replace')).lower().replace('’', "'")
    title = re.search(r'<title[^>]*>(.*?)</title>', text, re.S)
    if not title or 'gemini' not in title.group(1):
        raise ValueError('missing_gemini_title')
    visible = VisibleText(); visible.feed(text)
    page_text = ' '.join(' '.join(visible.parts).split())
    if any(s in page_text for s in ["not supported in your country", "not available in your country",
                               "gemini isn't available", "gemini is not available",
                               'our systems have detected unusual traffic', 'verify you are human']):
        raise ValueError('explicit_denial')
    with opener.open(DATA_URL, timeout=TIMEOUT) as response:
        if response.getcode() != 200 or len(response.read(DATA_BYTES + 1)) != DATA_BYTES:
            raise ValueError('incomplete_transfer')
    return {'passed': True, 'checked_at': int(time.time()), 'page_bytes': len(data),
            'transfer_bytes': DATA_BYTES, 'elapsed_ms': round((time.monotonic() - started) * 1000)}


def check_pool(config, xray):
    from generate import xray_validate
    proxies = [o for o in config['outbounds'] if o.get('tag', '').startswith('pool-')]
    held, ports = [], []
    cfg = {'log': {'loglevel': 'none'}, 'inbounds': [], 'outbounds': [], 'routing': {'rules': []}}
    try:
        for i, outbound in enumerate(proxies):
            sock = socket.socket(); sock.bind(('127.0.0.1', 0)); held.append(sock)
            port = sock.getsockname()[1]; ports.append(port); tag = f'probe-{i}'
            cfg['inbounds'].append({'tag': tag, 'protocol': 'http', 'listen': '127.0.0.1', 'port': port})
            ob = copy.deepcopy(outbound); ob['tag'] = tag; cfg['outbounds'].append(ob)
            cfg['routing']['rules'].append({'type': 'field', 'inboundTag': [tag], 'outboundTag': tag})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'probe.json'); path.write_text(json.dumps(cfg))
            xray_validate(xray, cfg)
            for sock in held: sock.close()
            process = subprocess.Popen([str(Path(xray).resolve()), 'run', '-config', str(path)],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(100):
                    if process.poll() is not None: raise RuntimeError('Gemini probe core stopped')
                    try:
                        with socket.create_connection(('127.0.0.1', ports[0]), timeout=.1): break
                    except OSError: time.sleep(.05)
                else: raise RuntimeError('Gemini probe core startup timeout')
                def check(pair):
                    outbound, port = pair
                    opener = urllib.request.build_opener(urllib.request.ProxyHandler({
                        'http': f'http://127.0.0.1:{port}', 'https': f'http://127.0.0.1:{port}'}))
                    try: evidence = probe(opener)
                    except Exception as error:
                        evidence = {'passed': False, 'checked_at': int(time.time()),
                                    'error': str(error) if isinstance(error, ValueError) else type(error).__name__,
                                    'http_status': getattr(error, 'code', None)}
                    return {'tag': outbound['tag'], **evidence}
                with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
                    evidence = list(executor.map(check, zip(proxies, ports)))
            finally:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
    finally:
        for sock in held: sock.close()
    passed = {e['tag'] for e in evidence if e['passed']}
    # Existing base order is by measured HTTPS latency. Keep distinct entry hosts
    # first, then fill from the remaining verified nodes, up to the experiment cap.
    eligible = [o for o in proxies if o['tag'] in passed]
    selected, rest, hosts = [], [], set()
    for outbound in eligible:
        endpoint = outbound['settings'].get('vnext', outbound['settings'].get('servers', []))[0]
        host = endpoint['address']
        if host in hosts: rest.append(outbound)
        else: selected.append(outbound); hosts.add(host)
    selected = (selected + rest)[:LIMIT]
    selected_tags = {o['tag'] for o in selected}
    # Keep latency order after diversity chooses membership.
    selected = [o for o in eligible if o['tag'] in selected_tags]
    report = {'page_url': PAGE_URL, 'transfer_url': DATA_URL, 'transfer_bytes': DATA_BYTES,
              'vantage': 'GitHub Actions runner', 'authenticated': False,
              'meaning': 'Logged-out HTML page and data transfer passed; not proof of account/app access',
              'checked': len(proxies), 'passed': len(passed), 'selected': len(selected),
              'selected_source_tags': [o['tag'] for o in selected],
              'status': 'available' if selected else 'no_eligible_nodes', 'servers': evidence}
    return selected, report


def experimental_profile(config, selected):
    if not selected: return None
    from karing import automatic_config
    from russia_config import build, ROOT
    result = copy.deepcopy(config)
    result['outbounds'] = copy.deepcopy(selected) + [o for o in result['outbounds']
        if o.get('protocol') in ('freedom', 'blackhole')]
    result = build(automatic_config(result, LABEL), json.loads((ROOT / 'russia-routing.json').read_bytes()))
    result['remarks'] = LABEL
    result.setdefault('meta', {})['serverDescription'] = (
        'Эксперимент: страница Gemini без входа и передача 256 КБ проверены с GitHub. '
        'Работа после входа не гарантируется. РУ/LAN напрямую; реклама заблокирована.')
    return result
