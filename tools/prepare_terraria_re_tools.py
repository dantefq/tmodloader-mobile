"""Acquire portable official analysis tools; never installs or launches the target APK."""
import concurrent.futures
import hashlib
import json
from pathlib import Path
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1] / '.tools' / 'terraria-re'
TOOLS = [
    ('ghidra', 'https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip'),
    ('jadx', 'https://github.com/skylot/jadx/releases/download/v1.5.6/jadx-1.5.6.zip'),
    ('jadx-mcp', 'https://github.com/1013503897/jadx-headless-mcp/releases/download/v0.7.1/jadx-headless-mcp-0.7.1-all.jar'),
]
EXPECTED_SHA256 = {
    'ghidra': 'ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db',
    'jadx': '545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974',
    'jadx-mcp': '6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75',
}

def acquire(item):
    name, url = item
    dest = ROOT / url.rsplit('/', 1)[1]
    if not dest.exists():
        partial = dest.with_suffix(dest.suffix + '.partial')
        with urllib.request.urlopen(url, timeout=60) as response, partial.open('wb') as stream:
            while chunk := response.read(1024 * 1024):
                stream.write(chunk)
        partial.replace(dest)
    with dest.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest != EXPECTED_SHA256[name]:
        raise ValueError(f'Pinned tool checksum mismatch: {name}')
    if dest.suffix == '.zip':
        out = ROOT / name
        marker = out / '.extracted'
        if not marker.exists():
            out.mkdir(exist_ok=True)
            with zipfile.ZipFile(dest) as archive:
                for member in archive.infolist():
                    resolved = (out / member.filename).resolve()
                    if not resolved.is_relative_to(out.resolve()):
                        raise ValueError('Unsafe archive path')
                archive.extractall(out)
            marker.write_text(digest)
    result = {'name': name, 'source': url, 'path': str(dest), 'size': dest.stat().st_size, 'sha256': digest}
    print(json.dumps(result), flush=True)
    return result

if __name__ == '__main__':
    ROOT.mkdir(parents=True, exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(acquire, TOOLS))
    (ROOT / 'tools.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
