"""Fetch four pinned public tML arithmetic sources for differential host tests.

No Terraria game code or third-party mod DLL is included. Keep references outside
the checkout; verify every retained file before compiling it.
"""
import argparse
import hashlib
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
COMMIT = '597a11b70fcc2c5b6257d33f78146322a676477a'
FILES = {
    'StatModifier.cs': 'dcc8c3bfceb84ebe5d68e2533c2fecdd02f7a3851d8e333d86c6e775842cdf6c',
    'StatInheritanceData.cs': '54be240be6959a276b3d6e44a72411ef2be81e9b6d95e0dbe66d8ad0bc526212',
    'MultipliableFloat.cs': 'd487032525fbf9ddd77bf9d57eb8baa52cefa3e642c40d33ccc417647171a036',
    'AddableFloat.cs': '40c02ebfb3cf684db07d552881cc22f3e135b01742ee0762f06a62ed041afdc5',
    'LICENSE': '472279759f98a8e7c220321257ffdd181c99072e46a36ad673cd82e776636066',
}


def verify(folder):
    folder = Path(folder).resolve()
    for name, digest in FILES.items():
        path = folder / name
        if path.stat().st_size > 256 * 1024 or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('Pinned reference checksum mismatch: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab', type=Path, required=True)
    args = parser.parse_args()
    folder = args.lab.resolve() / 'upstream-stats'
    if folder.is_relative_to(ROOT):
        raise ValueError('Keep upstream fixtures outside the source checkout')
    folder.mkdir(parents=True, exist_ok=True)
    for name, digest in FILES.items():
        target = folder / name
        if target.exists():
            continue  # verify() below rejects changed existing files; never overwrite them.
        relative = 'LICENSE' if name == 'LICENSE' else 'patches/tModLoader/Terraria/ModLoader/' + name
        url = f'https://raw.githubusercontent.com/tModLoader/tModLoader/{COMMIT}/{relative}'
        with urllib.request.urlopen(url, timeout=30) as response:
            data = response.read(256 * 1024 + 1)
        if len(data) > 256 * 1024 or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('Downloaded reference checksum mismatch: ' + name)
        with target.open('xb') as output:
            output.write(data)
    verify(folder)
    print(f'Upstream stats references verified: {folder}; commit {COMMIT}')


if __name__ == '__main__':
    main()
