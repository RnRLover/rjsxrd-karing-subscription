"""Download latest stable official Xray release and verify its publisher checksum."""
import hashlib
import io
import os
import re
import urllib.request
import zipfile
from pathlib import Path

LATEST_RELEASE = "https://github.com/XTLS/Xray-core/releases/latest"
GEODATA_SOURCES = {
    'geoip.dat': 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat',
    'geosite.dat': 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat',
}


def latest_version():
    # Resolve GitHub's stable release redirect once, then pin all assets to it.
    with urllib.request.urlopen(LATEST_RELEASE, timeout=60) as response:
        release_url = response.geturl()
    match = re.fullmatch(r"https://github\.com/XTLS/Xray-core/releases/tag/(v[0-9]+(?:\.[0-9]+){2})", release_url)
    if not match:
        raise ValueError(f"Unexpected official Xray release URL: {release_url}")
    return match.group(1)

def download(url):
    with urllib.request.urlopen(url, timeout=60) as r: return r.read()


def prepare_geodata(root, fetch=download):
    """CI assets only; neither these files nor a routing profile are imported."""
    hashes = {}
    for name, url in GEODATA_SOURCES.items():
        data = fetch(url)
        if not 1000 < len(data) < 40_000_000:
            raise ValueError('invalid geodata payload size: ' + name)
        (root / name).write_bytes(data)
        hashes[name] = hashlib.sha256(data).hexdigest()
    return hashes

if __name__ == "__main__":
    version = latest_version()
    name = "Xray-windows-64.zip" if os.name == "nt" else "Xray-linux-64.zip"
    base = f"https://github.com/XTLS/Xray-core/releases/download/{version}/"
    data = download(base + name)
    digest = download(base + name + ".dgst").decode()
    sha = hashlib.sha256(data).hexdigest()
    if sha.lower() not in digest.lower(): raise ValueError("Xray SHA256 mismatch")
    root = Path(".runtime")
    root.mkdir(exist_ok=True)
    executable = "xray.exe" if os.name == "nt" else "xray"
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        (root / executable).write_bytes(archive.read(executable))
    if os.name != "nt": (root / executable).chmod(0o755)
    prepare_geodata(root)
    print(f"Verified {version} SHA256 {sha}")
