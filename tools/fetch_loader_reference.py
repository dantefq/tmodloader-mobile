"""Fetch pinned public Info/dependency sources for differential host checks."""
import argparse
import hashlib
from pathlib import Path
import urllib.request

from fetch_stats_reference import COMMIT, FILES as STATS_FILES

ROOT = Path(__file__).resolve().parents[1]
FILES = {
    'BuildProperties.cs': 'e281b742380d8608e208880726359b317023acea97509fe4b7659ae87ca24f32',
    'ModOrganizer.cs': 'f4659014cb17d380213f01f8a5d2a6704fde70a3aebed1cdf6e27874a4596ffe',
    'ModSide.cs': '81a64c4e03ddb9a8d508cd4aae7a91073a5aab28a09e5e30a56c12252c051822',
    'LICENSE': STATS_FILES['LICENSE'],
}


def verify(folder):
    for name, digest in FILES.items():
        path = Path(folder) / name
        if path.stat().st_size > 1024 * 1024 or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('Pinned loader reference checksum mismatch: ' + name)


def prepare_validators(folder, output):
    verify(folder)
    source = (Path(folder) / 'ModOrganizer.cs').read_text(encoding='utf-8-sig')
    start = source.index('\tinternal static void EnsureDependenciesExist(')
    end = source.index('\tinternal static void EnsureHashesAreValid(', start)
    section = source[start:end]
    if section.count('internal static void') != 2:
        raise ValueError('Unexpected pinned dependency validators')
    Path(output).write_text('using System; using System.Collections.Generic; using System.Linq; '
                            'using System.Text; using Terraria.Localization;\n'
                            'namespace Terraria.ModLoader.Core;\ninternal static partial class ReferenceOrganizer\n{\n'
                            + section + '\n}\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab', type=Path, required=True)
    args = parser.parse_args()
    folder = args.lab.resolve() / 'upstream-loader'
    if folder.is_relative_to(ROOT):
        raise ValueError('Keep upstream sources outside the checkout')
    folder.mkdir(parents=True, exist_ok=True)
    for name, digest in FILES.items():
        target = folder / name
        if target.exists():
            continue
        relative = 'LICENSE' if name == 'LICENSE' else 'patches/tModLoader/Terraria/ModLoader/' + (
            name if name == 'ModSide.cs' else 'Core/' + name)
        with urllib.request.urlopen(f'https://raw.githubusercontent.com/tModLoader/tModLoader/{COMMIT}/{relative}', timeout=30) as response:
            data = response.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024 or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('Downloaded loader reference checksum mismatch: ' + name)
        with target.open('xb') as output:
            output.write(data)
    verify(folder)
    print(f'Upstream loader references verified: {folder}; commit {COMMIT}')


if __name__ == '__main__':
    main()
