"""Publish client-visible changes, not report timestamps or unused source nodes."""
import json
from certificate_checks import transport_signature
from latency_checks import latency_signature
from pathlib import Path
import subprocess

CLIENT_FILES = ('subscription.json', 'ru.json', 'ru-karing-incy.txt', 'ru-karing-happ.txt')


def canonical(name, data):
    return json.dumps(json.loads(data.decode('utf-8-sig')), sort_keys=True, ensure_ascii=False)


def reputation_signature(data):
    """Publish changed selected-exit evidence, without timestamp/feed churn."""
    reputation = json.loads(data).get('ip_reputation', {})
    return {'servers': reputation.get('servers', []),
            'selection_priority': reputation.get('selection_priority')}


def changed(root):
    for name in CLIENT_FILES:
        old = subprocess.run(['git', 'show', 'HEAD:' + name], cwd=root, capture_output=True)
        if old.returncode or canonical(name, old.stdout) != canonical(name, (root / name).read_bytes()):
            return True
    report = root / 'report.json'
    if report.exists():
        old = subprocess.run(['git', 'show', 'HEAD:report.json'], cwd=root, capture_output=True)
        if old.returncode or reputation_signature(old.stdout) != reputation_signature(report.read_bytes()) or transport_signature(old.stdout) != transport_signature(report.read_bytes()) or latency_signature(old.stdout) != latency_signature(report.read_bytes()):
            return True
    return False


if __name__ == '__main__':
    import sys
    result = changed(Path(__file__).resolve().parent)
    print('Client content changed' if result else 'Pool, DNS, routing and geodata unchanged; no commit')
    sys.exit(0 if result else 1)
