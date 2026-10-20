"""Fetch pinned public tML combat sources, outside the checkout, for host tests.

These fixtures are public patch sources, not extracted game DLLs or an APK.
"""
import argparse
import hashlib
from pathlib import Path
import urllib.request

from fetch_stats_reference import COMMIT, FILES as STATS_FILES

ROOT = Path(__file__).resolve().parents[1]
FILES = dict(STATS_FILES, **{
    'Main.cs.patch': 'c81fd22e1ea15db36dc2b9c341ffcf6060a4d9a43df76967aee6b65c34119cb4',
    'NPC.TML.Hit.cs': '6de113105bbec92b4fe56931a0b7a0e9ec0bd244387eaa34be8a9d99d0ec12a2',
    'DamageClass.cs': '0ace21d36bbe2df82b137eee6c24e809d34bce3e7e951490bf9be782c54d79f0',
    'DamageClassLoader.cs': 'b66df93c70b7e6c9923086b0a8df402cd7cf626f41bb33d348b0d2de63f2df13',
    'VanillaDamageClasses.cs': '5153be97cffcac9bba6a81979623993f222d5349a401784670cb8c4fcf50d5f9',
    'Player.TML.cs': '390112709476d27c157826a3c4aff8a5f1a42bca6a3d55fde50e9e6587c5644d',
})


def verify(folder):
    folder = Path(folder).resolve()
    for name, digest in FILES.items():
        path = folder / name
        if path.stat().st_size > 1024 * 1024 or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('Pinned combat reference checksum mismatch: ' + name)


def prepare_player(folder, output):
    """Retain exact upstream text for the five stat getters and aggregators.

    The full Player patch depends on the game. Compile only its stat section;
    separate test scaffolding supplies DamageClassData and a public reset helper.
    """
    verify(folder)
    if '+\tpublic static int DefaultDamageVariationPercent = 15;' not in (Path(folder) / 'Main.cs.patch').read_text(encoding='utf-8'):
        raise ValueError('Unexpected upstream default damage spread')
    source = (Path(folder) / 'Player.TML.cs').read_text(encoding='utf-8')
    start = source.index('\tprivate DamageClassData[] damageData;')
    end = source.index('\n\tpublic int GetWeaponArmorPenetration(', start)
    section = source[start:end]
    if section.count('public ref ') != 10 or section.count('public StatModifier GetTotal') != 4:
        raise ValueError('Unexpected pinned Player stat section')
    Path(output).write_text('using Terraria.ModLoader;\nnamespace Terraria;\npublic partial class Player\n{\n'
                            + section + '\n}\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab', type=Path, required=True)
    args = parser.parse_args()
    folder = args.lab.resolve() / 'upstream-combat'
    if folder.is_relative_to(ROOT):
        raise ValueError('Keep upstream references outside the source checkout')
    folder.mkdir(parents=True, exist_ok=True)
    for name, digest in FILES.items():
        target = folder / name
        if target.exists():
            continue
        relative = 'LICENSE' if name == 'LICENSE' else 'patches/tModLoader/Terraria/' + (
            name if name in ('Player.TML.cs', 'NPC.TML.Hit.cs', 'Main.cs.patch') else 'ModLoader/' + name)
        url = f'https://raw.githubusercontent.com/tModLoader/tModLoader/{COMMIT}/{relative}'
        with urllib.request.urlopen(url, timeout=30) as response:
            data = response.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024 or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('Downloaded combat reference checksum mismatch: ' + name)
        with target.open('xb') as output:
            output.write(data)
    verify(folder)
    print(f'Upstream combat references verified: {folder}; commit {COMMIT}')


if __name__ == '__main__':
    main()
