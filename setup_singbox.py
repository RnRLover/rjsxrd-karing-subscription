"""Pinned official sing-box, used only to decompile upstream SRS lists."""
import hashlib
import io
import os
from pathlib import Path
import tarfile
import urllib.request
import zipfile

VERSION = '1.14.2'
SHA256 = {
    'windows-amd64.zip': 'c2d8bfff918755808781dfdeeb8581b6c91eb3a243d9a7b55483cfc0c0684d32',
    'linux-amd64.tar.gz': 'a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6',
}

if __name__ == '__main__':
    platform = 'windows-amd64.zip' if os.name == 'nt' else 'linux-amd64.tar.gz'
    name = f'sing-box-{VERSION}-{platform}'
    url = f'https://github.com/SagerNet/sing-box/releases/download/v{VERSION}/{name}'
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(60_000_001)
    if hashlib.sha256(data).hexdigest() != SHA256[platform]:
        raise ValueError('sing-box SHA256 mismatch')
    exe = 'sing-box.exe' if os.name == 'nt' else 'sing-box'
    member = f'sing-box-{VERSION}-{platform.split(".")[0]}/{exe}'
    if os.name == 'nt':
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            binary = archive.read(member)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            binary = archive.extractfile(member).read()
    root = Path('.runtime')
    root.mkdir(exist_ok=True)
    (root / exe).write_bytes(binary)
    if os.name != 'nt':
        (root / exe).chmod(0o755)
    print('Verified official sing-box', VERSION)
