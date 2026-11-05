"""Publish validated outputs only while their source revision is still current."""
from pathlib import Path
import json
import subprocess

ROOT = Path(__file__).resolve().parent
OUTPUTS = ('subscription.json', 'report.json')
RETIRED = ('ru.json',)


def report_signature(data):
    report = json.loads(data)
    reputation = report.get('ip_reputation', {})
    return {'servers': reputation.get('servers', []),
            'selection': reputation.get('selection_priority'),
            'policy': report.get('subscription_policy'),
            'counts': report.get('counts')}


def changed(root):
    for name in OUTPUTS:
        old = git(root, 'show', 'HEAD:' + name, check=False)
        if old.returncode:
            return True
        new = (root / name).read_text(encoding='utf-8')
        if name == 'report.json':
            if report_signature(old.stdout) != report_signature(new):
                return True
        elif old.stdout != new:
            return True
    return False


def git(root, *args, check=True):
    return subprocess.run(['git', *args], cwd=root, check=check, capture_output=True, text=True)


def notice(message):
    print('::notice::' + message, flush=True)


def publish(root=ROOT):
    base = git(root, 'rev-parse', 'HEAD').stdout.strip()
    git(root, 'fetch', 'origin', 'main')
    if git(root, 'rev-parse', 'origin/main').stdout.strip() != base:
        notice('Main changed during validation; preserve the newer branch. The next run will rebuild it.')
        return False
    retired = [name for name in RETIRED if git(root, 'ls-files', '--', name).stdout.strip()]
    if not changed(root) and not retired:
        print('Validated subscription unchanged', flush=True)
        return False
    git(root, 'config', 'user.name', 'github-actions[bot]')
    git(root, 'config', 'user.email', '41898282+github-actions[bot]@users.noreply.github.com')
    git(root, 'add', *OUTPUTS)
    if retired:
        git(root, 'rm', '--', *retired)
    git(root, 'commit', '-m', 'Update validated rjsxrd subscription')
    result = git(root, 'push', 'origin', 'HEAD:main', check=False)
    if result.returncode:
        # Recheck a real race after the pre-push check. Do not force-push or
        # merge generated files from a build using superseded source code.
        git(root, 'fetch', 'origin', 'main')
        if git(root, 'rev-parse', 'origin/main').stdout.strip() != base:
            notice('Main advanced before push; preserve the newer branch. The next run will rebuild it.')
            return False
        raise RuntimeError('Git push failed without a newer remote commit: ' + result.stderr)
    print(result.stdout + result.stderr, flush=True)
    return True


if __name__ == '__main__':
    publish()
