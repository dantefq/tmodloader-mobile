"""Compile an own contract against PC tModLoader; run it against our snapshot API."""
import argparse
import json
from pathlib import Path
import subprocess

from managed_api_sources import API_SOURCES

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lab', required=True, type=Path)
    p.add_argument('--dotnet', type=Path, default=Path('C:/Program Files/dotnet'))
    p.add_argument('--tml', type=Path, default=Path('C:/Program Files (x86)/Steam/steamapps/common/tModLoader/tModLoader.dll'))
    args = p.parse_args()
    lab = args.lab.resolve() / 'pc-item-economy'
    if lab.is_relative_to(ROOT):
        raise ValueError('Keep binaries outside source checkout')
    lab.mkdir(parents=True, exist_ok=True)
    sdk = args.dotnet
    refs = sorted((sdk / 'packs/Microsoft.NETCore.App.Ref/8.0.31/ref/net8.0').glob('*.dll'))
    csc = sdk / 'sdk/8.0.425/Roslyn/bincore/csc.dll'
    if not refs or not csc.is_file() or not args.tml.is_file():
        raise ValueError('Pinned .NET SDK and local PC tModLoader required')
    def compile(name, sources, extra=(), exe=False):
        output = lab / name
        rsp = lab / (name + '.rsp')
        rsp.write_text('\n'.join(['-nologo', '-nostdlib+', '-deterministic+', '-langversion:12',
            '-target:' + ('exe' if exe else 'library'), f'-out:"{output}"',
            *[f'-r:"{r}"' for r in [*refs, *extra]], *[f'"{ROOT / s}"' for s in sources]]), encoding='utf-8')
        subprocess.run([str(sdk / 'dotnet.exe'), str(csc), '@' + str(rsp)], check=True, timeout=120)
        return output
    compile('tModLoader.dll', API_SOURCES)
    probe = compile('PcItemEconomyProbe.dll', ['managed/tests/PcItemEconomyProbe.cs'], [args.tml], exe=True)
    probe.with_suffix('.runtimeconfig.json').write_text(json.dumps({'runtimeOptions': {
        'tfm': 'net8.0', 'framework': {'name': 'Microsoft.NETCore.App', 'version': '8.0.31'}}}), encoding='utf-8')
    subprocess.run([str(sdk / 'dotnet.exe'), str(probe)], check=True, timeout=60)


if __name__ == '__main__':
    main()
