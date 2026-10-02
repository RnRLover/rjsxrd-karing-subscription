"""Download pinned official Xray release and verify its publisher checksum."""
import hashlib
import io
import os
import urllib.request
import zipfile
from pathlib import Path

VERSION = "v26.3.27"
def download(url):
    with urllib.request.urlopen(url, timeout=60) as r: return r.read()

if __name__ == "__main__":
    name = "Xray-windows-64.zip" if os.name == "nt" else "Xray-linux-64.zip"
    base = f"https://github.com/XTLS/Xray-core/releases/download/{VERSION}/"
    data = download(base + name)
    digest = download(base + name + ".dgst").decode()
    sha = hashlib.sha256(data).hexdigest()
    if sha.lower() not in digest.lower(): raise ValueError("Xray SHA256 mismatch")
    root = Path(".runtime")
    root.mkdir(exist_ok=True)
    executable = "xray.exe" if os.name == "nt" else "xray"
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        (root / executable).write_bytes(archive.read(executable))
        (root / "geoip.dat").write_bytes(archive.read("geoip.dat"))
    if os.name != "nt": (root / executable).chmod(0o755)
    print(f"Verified {VERSION} SHA256 {sha}")
