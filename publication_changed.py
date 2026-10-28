"""Publish client-visible changes, not report timestamps or unused source nodes."""
import json
from certificate_checks import transport_signature
from pathlib import Path
import subprocess

CLIENT_FILES = ('ru.json', 'ru-karing.json', 'ru-karing-incy.txt',
                'ru-karing-happ.txt', 'ru-karing-happ-routing-test.txt', 'karing-routing.json',
                'karing-geoip.dat', 'karing-geosite.dat')


def canonical(name, data):
    if name.endswith('.dat'):
        return data
    text = data.decode('utf-8-sig')
    if name == 'ru-karing-incy.txt':
        lines = text.splitlines()
        return json.dumps(json.loads(lines[0]), sort_keys=True, ensure_ascii=False) + '\n' + '\n'.join(lines[1:])
    if name == 'ru-karing-happ-routing-test.txt':
        command, body = text.split('\n', 1)
        if not command.startswith('happ://routing/onadd/'):
            raise ValueError('missing Happ routing command')
        return command + '\n' + json.dumps(json.loads(body), sort_keys=True, ensure_ascii=False)
    obj = json.loads(text)
    if name == 'karing-routing.json':
        obj.pop('LastUpdated', None)
    return json.dumps(obj, sort_keys=True, ensure_ascii=False)


def reputation_signature(data):
    """Publish changed selected-exit evidence, without timestamp/feed churn."""
    return json.loads(data).get('ip_reputation', {}).get('servers', [])


def changed(root):
    for name in CLIENT_FILES:
        old = subprocess.run(['git', 'show', 'HEAD:' + name], cwd=root, capture_output=True)
        if old.returncode or canonical(name, old.stdout) != canonical(name, (root / name).read_bytes()):
            return True
    report = root / 'report.json'
    if report.exists():
        old = subprocess.run(['git', 'show', 'HEAD:report.json'], cwd=root, capture_output=True)
        if old.returncode or reputation_signature(old.stdout) != reputation_signature(report.read_bytes()) or transport_signature(old.stdout) != transport_signature(report.read_bytes()):
            return True
    return False


if __name__ == '__main__':
    import sys
    result = changed(Path(__file__).resolve().parent)
    print('Client content changed' if result else 'Pool, DNS, routing and geodata unchanged; no commit')
    sys.exit(0 if result else 1)
