"""Check selected .tmod metadata/dependencies on host CLR, without executing mods.

Print a JSON load plan. Exit 0 means graph validation passed, 2 means conflicts,
3 means archive/Info input failure. A valid plan does not imply compatibility.
"""
import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def build(dotnet_root, lab_root):
    folder = Path(lab_root).resolve() / 'mod-plan'
    if folder.is_relative_to(ROOT):
        raise ValueError('Keep compiler outputs outside the source checkout')
    folder.mkdir(parents=True, exist_ok=True)
    sdk = Path(dotnet_root).resolve()
    dotnet = sdk / ('dotnet.exe' if (sdk / 'dotnet.exe').exists() else 'dotnet')
    csc = sdk / 'sdk/8.0.425/Roslyn/bincore/csc.dll'
    refs = sorted((sdk / 'packs/Microsoft.NETCore.App.Ref/8.0.31/ref/net8.0').glob('*.dll'))
    if not csc.is_file() or not refs:
        raise ValueError('Pinned .NET SDK 8.0.425 / refs 8.0.31 required')
    output = folder / 'TerrariaMobile.ModPlan.dll'
    sources = [ROOT / name for name in ('managed/compat/MobileTmodArchive.cs', 'managed/compat/ModManifest.cs',
               'managed/api-host/MobileModLoadPlan.cs', 'managed/api-host/MobileTmodMetadata.cs', 'managed/api-host/ModPlanCli.cs')]
    lines = ['-nologo', '-nostdlib+', '-deterministic+', '-langversion:12', '-target:exe', f'-out:"{output}"']
    lines += [f'-r:"{ref}"' for ref in refs] + [f'"{source}"' for source in sources]
    response = folder / 'compile.rsp'; response.write_text('\n'.join(lines), encoding='utf-8')
    subprocess.run([str(dotnet), str(csc), '@' + str(response)], check=True, timeout=120)
    output.with_suffix('.runtimeconfig.json').write_text(json.dumps({'runtimeOptions': {
        'tfm': 'net8.0', 'framework': {'name': 'Microsoft.NETCore.App', 'version': '8.0.31'}}}), encoding='utf-8')
    return [str(dotnet), str(output)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dotnet', type=Path, required=True)
    parser.add_argument('--lab', type=Path, required=True)
    parser.add_argument('--role', choices=('client', 'server'), default='client')
    parser.add_argument('mods', type=Path, nargs='+', help='Explicitly selected .tmod files; no auto-enabling')
    args = parser.parse_args()
    if len(args.mods) > 1024:
        parser.error('At most 1024 selected files')
    command = build(args.dotnet, args.lab)
    return subprocess.run([*command, args.role, *map(str, args.mods)], timeout=300).returncode


if __name__ == '__main__':
    raise SystemExit(main())
