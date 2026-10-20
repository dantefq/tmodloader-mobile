"""Compile own field fixture against real PC tModLoader; run it with our API.

No PC game code is copied to the runtime folder. The fixture DLL is not rebuilt
against the shim. Outputs stay in a private lab outside the source checkout.
"""
import argparse
import json
from pathlib import Path
import subprocess
from apk_format import sha256
from managed_api_sources import API_SOURCES

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pc-assembly', type=Path, required=True)
    p.add_argument('--lab', type=Path, required=True)
    p.add_argument('--dotnet', type=Path, default=Path('C:/Program Files/dotnet'))
    args = p.parse_args()
    lab = args.lab.resolve()/'pc-favorite-contract'
    if lab.is_relative_to(ROOT): raise ValueError('Keep binaries outside source checkout')
    lab.mkdir(parents=True, exist_ok=True)
    csc = args.dotnet/'sdk/8.0.425/Roslyn/bincore/csc.dll'
    refs = sorted((args.dotnet/'packs/Microsoft.NETCore.App.Ref/8.0.31/ref/net8.0').glob('*.dll'))
    if not csc.is_file() or not refs: raise ValueError('Pinned SDK/ref pack missing')
    pc_hash = sha256(args.pc_assembly)
    def compile(name, sources, extra=(), exe=False):
        output = lab/name; rsp = lab/(name+'.rsp')
        lines = ['-nologo', '-nostdlib+', '-deterministic+', '-langversion:12',
                 '-target:'+('exe' if exe else 'library'), f'-out:"{output}"']
        lines += [f'-r:"{ref}"' for ref in [*refs, *extra]]
        lines += [f'"{ROOT/source}"' for source in sources]
        rsp.write_text('\n'.join(lines), encoding='utf-8')
        subprocess.run([str(args.dotnet/'dotnet.exe'), str(csc), '@'+str(rsp)], check=True, timeout=120)
        return output
    fixture = compile('PcFavoriteFixture.dll', ['managed/tests/PcFavoriteFixture.cs'], [args.pc_assembly])
    fixture_hash = sha256(fixture)
    shim = compile('tModLoader.dll', API_SOURCES)
    runner = compile('PcFavoriteRunner.dll', ['managed/tests/PcFavoriteRunner.cs'], [fixture, shim], True)
    runner.with_suffix('.runtimeconfig.json').write_text(json.dumps({'runtimeOptions': {
        'tfm':'net8.0', 'framework':{'name':'Microsoft.NETCore.App','version':'8.0.31'}}}), encoding='utf-8')
    result = subprocess.run([str(args.dotnet/'dotnet.exe'), str(runner)], check=True,
                            capture_output=True, text=True, timeout=120)
    if sha256(fixture) != fixture_hash or sha256(args.pc_assembly) != pc_hash:
        raise ValueError('Fixture or original PC assembly changed')
    report = {'status':'verified', 'date':'2026-10-10', 'host_only':True,
              'pc_assembly_sha256':pc_hash, 'fixture_sha256':fixture_hash,
              'shim_sha256':sha256(shim), 'fixture_recompiled_against_shim':False,
              'pc_game_code_copied':False, 'checks':['PC favorited field write/read',
              'PC field visible through favorite alias', 'alias visible through PC field'],
              'stdout':result.stdout.strip()}
    (ROOT/'reports/pc-favorite-contract-validation.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__': main()
