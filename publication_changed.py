"""Publish client-visible changes, not report timestamps or unused source nodes."""
import json
from pathlib import Path
import subprocess

CLIENT_FILES = ('ru.json', 'ru-karing.json', 'ru-karing-incy.txt',
                'ru-karing-happ.txt', 'karing-routing.json',
                'karing-geoip.dat', 'karing-geosite.dat')


def canonical(name, data):
    if name.endswith('.dat'):
        return data
    text = data.decode('utf-8-sig')
    if name == 'ru-karing-incy.txt':
        lines = text.splitlines()
        return json.dumps(json.loads(lines[0]), sort_keys=True, ensure_ascii=False) + '\n' + '\n'.join(lines[1:])
    obj = json.loads(text)
    if name == 'karing-routing.json':
        obj.pop('LastUpdated', None)
    return json.dumps(obj, sort_keys=True, ensure_ascii=False)


def changed(root):
    for name in CLIENT_FILES:
        old = subprocess.run(['git', 'show', 'HEAD:' + name], cwd=root, capture_output=True)
        if old.returncode or canonical(name, old.stdout) != canonical(name, (root / name).read_bytes()):
            return True
    return False


if __name__ == '__main__':
    import sys
    result = changed(Path(__file__).resolve().parent)
    print('Client content changed' if result else 'Pool, DNS, routing and geodata unchanged; no commit')
    sys.exit(0 if result else 1)
