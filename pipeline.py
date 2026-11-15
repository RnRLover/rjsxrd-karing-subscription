"""Bounded prepare/probe/assemble stages, reusable by GitHub's dynamic matrix."""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import time
import uuid

import generate as source
from allowlist import annotate, load_reference


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def node_id(node):
    outbound = dict(node['outbound'])
    outbound.pop('tag', None)
    return digest(outbound)


def write(path, value):
    source.atomic_write(path, json.dumps(value, ensure_ascii=False, separators=(',', ':')) + '\n')


def runtime_hashes(xray):
    files = {'xray': Path(xray), **{name: source.ROOT / '.runtime' / name for name in ('geoip.dat', 'geosite.dat')}}
    return {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in files.items() if path.is_file()}


def verify_runtime(manifest, xray):
    if runtime_hashes(xray) != manifest['runtime']:
        raise ValueError('Xray or geodata differs from the prepared runtime')


def admitted_scheme(node, settings):
    outbound = node.get('outbound', {})
    stream = outbound.get('streamSettings', {})
    return (outbound.get('protocol') in settings.get('allowed_protocols', ['vless', 'hysteria']) and
            stream.get('security') in ('tls', 'reality') and
            not stream.get('tlsSettings', {}).get('allowInsecure', False))


def prepare(work, xray):
    work = Path(work)
    settings = json.loads((source.ROOT / 'settings.json').read_bytes())
    original = source.fetch(settings['subscription_url']).decode('utf-8-sig')
    nodes, counts = source.collect_nodes(original)
    retained = [node for node in nodes if admitted_scheme(node, settings['quality'])]
    counts['outside_quality_policy'] = len(nodes) - len(retained)
    nodes = source.compatible_nodes(retained, xray, counts)
    if not nodes:
        print('::notice::No compatible candidate satisfies admission policy; preserve publication', flush=True)
        return {'ready': False, 'matrix': {'shard': [0]}}
    limits = settings.get('build', {})
    shard_size, max_shards = limits.get('shard_nodes', 500), limits.get('max_shards', 32)
    if (type(shard_size) is not int or shard_size < 1 or type(max_shards) is not int or
            not 1 <= max_shards <= 256):
        raise ValueError('invalid build partition limits')
    shard_size = max(shard_size, math.ceil(len(nodes) / max_shards))
    cache_path = source.ROOT / '.runtime/reputation-cache.json'
    cache = json.loads(cache_path.read_bytes()) if cache_path.exists() else {}
    feed, feed_source = source.load_feed(cache, lambda url: source.fetch(url).decode('utf-8-sig'), int(time.time()))
    write(cache_path, {source.CACHE_KEY: feed})
    reference = load_reference(source.fetch)
    revision = os.environ.get('GITHUB_SHA')
    if not revision:
        result = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=source.ROOT, capture_output=True, text=True)
        revision = result.stdout.strip() or 'local'
    manifest = {'version': 1, 'build_id': str(uuid.uuid4()), 'revision': revision,
                'source_sha': hashlib.sha256(original.encode()).hexdigest(), 'settings': settings,
                'counts': dict(counts), 'feed': feed, 'feed_source': feed_source,
                'allowlist_reference': reference, 'shards': [], 'candidate_count': len(nodes),
                'runtime': runtime_hashes(xray)}
    for directory, pattern in [('input', 'shard-*.json'), ('results', 'result-*.json')]:
        for stale in (work / directory).glob(pattern):
            stale.unlink()
    for node in nodes:
        node['node_id'] = node_id(node)
    for index, start in enumerate(range(0, len(nodes), shard_size)):
        members = nodes[start:start + shard_size]
        shard = {'build_id': manifest['build_id'], 'index': index, 'nodes': members}
        path = work / 'input' / f'shard-{index:04d}.json'
        write(path, shard)
        manifest['shards'].append({'index': index, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                                   'node_ids': [node['node_id'] for node in members]})
    write(work / 'input/manifest.json', manifest)
    print(json.dumps({'prepared_candidates': len(nodes), 'shards': len(manifest['shards']),
                      'nodes_per_shard': shard_size, 'counts': dict(counts)}), flush=True)
    return {'ready': True, 'matrix': {'shard': list(range(len(manifest['shards'])))}}


def read_input(work, index):
    work = Path(work)
    manifest = json.loads((work / 'input/manifest.json').read_bytes())
    if os.environ.get('GITHUB_SHA') and manifest['revision'] != os.environ['GITHUB_SHA']:
        raise ValueError('input belongs to a different source revision')
    if type(index) is not int or not 0 <= index < len(manifest['shards']):
        raise ValueError('unknown shard index')
    spec = manifest['shards'][index]
    payload = (work / 'input' / f'shard-{index:04d}.json').read_bytes()
    if hashlib.sha256(payload).hexdigest() != spec['sha256']:
        raise ValueError('shard input checksum mismatch')
    shard = json.loads(payload)
    if (shard['build_id'] != manifest['build_id'] or shard['index'] != index or
            [n['node_id'] for n in shard['nodes']] != spec['node_ids'] or
            any(node_id(n) != n['node_id'] for n in shard['nodes'])):
        raise ValueError('shard input identity mismatch')
    return manifest, shard


def probe_shard(work, index, xray):
    manifest, shard = read_input(work, index)
    verify_runtime(manifest, xray)
    settings, nodes, feed = manifest['settings'], shard['nodes'], manifest['feed']
    result = {'version': 1, 'build_id': manifest['build_id'], 'revision': manifest['revision'],
              'source_sha': manifest['source_sha'], 'index': index,
              'input_ids': [n['node_id'] for n in nodes], 'status': 'complete',
              'dispositions': {}, 'nodes': [], 'reputation_statuses': [], 'counts': {}}
    counts = Counter()
    try:
        controls = dict(settings['quality'], require_quic=any(not source.vision_blocks_quic(n) for n in nodes))
        usable, evidence = source.baseline(controls)
        result['baseline'] = evidence
        hosts = list(dict.fromkeys(node['host'] for node in nodes))
        with ThreadPoolExecutor(max_workers=settings['reputation_workers']) as executor:
            addresses = dict(zip(hosts, executor.map(source.entry_ips, hosts)))
        for node in nodes:
            node['entry_reputation'] = [dict(ip=ip, **source.rate_ip(ip, feed)) for ip in addresses[node['host']]]
        retained = source.exclude_listed(nodes)
        retained_ids = {n['node_id'] for n in retained}
        for node in nodes:
            if node['node_id'] not in retained_ids:
                result['dispositions'][node['node_id']] = 'listed_entry'
                counts['listed_entry'] += 1
        rated = source.assess_nodes(source.probe_exits(retained, xray, settings['reputation_workers'],
                                                     settings['reputation_timeout_seconds']), feed)
        result['reputation_statuses'] = [{'reputation': node['reputation']} for node in rated]
        candidates = source.exclude_listed(rated)
        candidate_ids = {n['node_id'] for n in candidates}
        for node in rated:
            if node['node_id'] not in candidate_ids:
                result['dispositions'][node['node_id']] = 'listed_exit'
                counts['listed_exit'] += 1
        if candidates:
            checked = source.probe_nodes(candidates, xray, settings['quality'], usable)
            annotate(checked, manifest['allowlist_reference'])
            eligible = {n['node_id'] for n in source.eligible_nodes(checked)}
            for node in checked:
                result['dispositions'][node['node_id']] = 'eligible' if node['node_id'] in eligible else 'quality_failed'
            result['nodes'] = checked
        result['counts'] = dict(counts)
    except source.ProbeUnavailable as error:
        result.update(status='deferred', reason=str(error), nodes=[], dispositions={})
        print('::notice::Shard checking infrastructure unavailable; publication will be preserved', flush=True)
    write(Path(work) / 'results' / f'result-{index:04d}.json', result)
    print(json.dumps({'shard': index, 'status': result['status'], 'candidates': len(nodes),
                      'eligible': sum(v == 'eligible' for v in result['dispositions'].values())}), flush=True)
    return result


def assemble(work, xray):
    work = Path(work)
    manifest = json.loads((work / 'input/manifest.json').read_bytes())
    verify_runtime(manifest, xray)
    if os.environ.get('GITHUB_SHA') and manifest['revision'] != os.environ['GITHUB_SHA']:
        raise ValueError('assembly belongs to a different source revision')
    expected = {f'result-{s["index"]:04d}.json' for s in manifest['shards']}
    actual = {p.name for p in (work / 'results').glob('result-*.json')}
    if actual != expected:
        raise ValueError('missing or unexpected shard results; publication preserved')
    checked, rated, baselines, seen = [], [], [], set()
    counts = Counter(manifest['counts'])
    deferred = False
    for spec in manifest['shards']:
        index = spec['index']
        result = json.loads((work / 'results' / f'result-{index:04d}.json').read_bytes())
        if (any(result[k] != manifest[k] for k in ('build_id', 'revision')) or
                result['source_sha'] != manifest['source_sha'] or result['index'] != index or
                result['input_ids'] != spec['node_ids'] or seen.intersection(result['input_ids'])):
            raise ValueError('mixed, duplicate or stale shard results; publication preserved')
        seen.update(result['input_ids'])
        if result['status'] == 'deferred':
            deferred = True
            continue
        if result['status'] != 'complete' or set(result['dispositions']) != set(spec['node_ids']):
            raise ValueError('incomplete shard accounting; publication preserved')
        if not set(result['dispositions'].values()) <= {'eligible', 'quality_failed', 'listed_entry', 'listed_exit'}:
            raise ValueError('unknown shard disposition')
        checked_ids = [n['node_id'] for n in result['nodes']]
        expected_checked = {key for key, value in result['dispositions'].items() if value in ('eligible', 'quality_failed')}
        if (len(set(checked_ids)) != len(checked_ids) or set(checked_ids) != expected_checked or
                any(node_id(n) != n['node_id'] for n in result['nodes'])):
            raise ValueError('lost or altered shard nodes; publication preserved')
        if {n['node_id'] for n in source.eligible_nodes(result['nodes'])} != {
                key for key, value in result['dispositions'].items() if value == 'eligible'}:
            raise ValueError('quality disposition mismatch')
        checked.extend(result['nodes'])
        rated.extend(result['reputation_statuses'])
        counts.update(result['counts'])
        baselines.append(result.get('baseline', {}))
    if deferred:
        print('::notice::At least one shard was deferred; preserve the complete previous publication', flush=True)
        return False
    if len(seen) != manifest['candidate_count']:
        raise ValueError('candidate coverage mismatch')
    checked.sort(key=lambda node: node.get('source_order', 0))
    return source.publish_checked(checked, rated, manifest['settings'], counts, manifest['source_sha'],
                                  manifest['feed'], manifest['feed_source'], baselines, xray,
                                  {'build_id': manifest['build_id'], 'revision': manifest['revision'],
                                   'shards': len(manifest['shards']), 'complete': True,
                                   'runtime': manifest['runtime'],
                                   'candidate_count': manifest['candidate_count']})


def run_all(work, xray):
    result = prepare(work, xray)
    if not result['ready']:
        return False
    for index in result['matrix']['shard']:
        probe_shard(work, index, xray)
    return assemble(work, xray)
