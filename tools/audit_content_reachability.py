"""Inventory a selected content type's IL dependencies without executing its DLL."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from inspect_mod_api import assembly_bytes

ROOT = Path(__file__).resolve().parents[1]


def build(dotnet_root, lab):
    folder = Path(lab).resolve() / 'content-reachability'
    if folder.is_relative_to(ROOT):
        raise ValueError('Keep binaries and private evidence outside source checkout')
    folder.mkdir(parents=True, exist_ok=True)
    sdk = Path(dotnet_root)
    refs = sorted((sdk / 'packs/Microsoft.NETCore.App.Ref/8.0.31/ref/net8.0').glob('*.dll'))
    csc = sdk / 'sdk/8.0.425/Roslyn/bincore/csc.dll'
    if not refs or not csc.is_file():
        raise ValueError('Pinned .NET SDK 8.0.425 / refs 8.0.31 required')
    output = folder / 'ContentReachability.dll'
    response = folder / 'compile.rsp'
    response.write_text('\n'.join(['-nologo', '-nostdlib+', '-deterministic+', '-langversion:12',
        '-target:exe', f'-out:"{output}"', *[f'-r:"{r}"' for r in refs],
        f'"{ROOT / "managed/tools/ContentReachability.cs"}"']), encoding='utf-8')
    subprocess.run([str(sdk / 'dotnet.exe'), str(csc), '@' + str(response)], check=True, timeout=120)
    output.with_suffix('.runtimeconfig.json').write_text(json.dumps({'runtimeOptions': {
        'tfm': 'net8.0', 'framework': {'name': 'Microsoft.NETCore.App', 'version': '8.0.31'}}}), encoding='utf-8')
    return [str(sdk / 'dotnet.exe'), str(output)], folder


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('tmod', type=Path)
    p.add_argument('--assembly', required=True)
    p.add_argument('--type', required=True)
    p.add_argument('--methods', nargs='+', help='Optional exact root method names; defaults to all methods')
    p.add_argument('--lab', type=Path, required=True)
    p.add_argument('--dotnet', type=Path, default=Path('C:/Program Files/dotnet'))
    args = p.parse_args()
    command, folder = build(args.dotnet, args.lab)
    before = hashlib.sha256(args.tmod.read_bytes()).hexdigest()
    dll, header = assembly_bytes(args.tmod, args.assembly)
    digest = hashlib.sha256(dll).hexdigest()
    source = folder / (digest + '.dll')
    source.write_bytes(dll)
    roots = [','.join(args.methods)] if args.methods else []
    result = subprocess.run([*command, str(source), args.type, *roots], capture_output=True, text=True,
                            encoding='utf-8', check=True, timeout=120)
    report = json.loads(result.stdout)
    if hashlib.sha256(args.tmod.read_bytes()).hexdigest() != before:
        raise ValueError('Source archive changed during audit')
    report.update(artifact=header, tmod_sha256=before, assembly_sha256=digest)
    analyzer_sha = hashlib.sha256((ROOT / 'managed/tools/ContentReachability.cs').read_bytes()).hexdigest()
    report['analyzer_source_sha256'] = analyzer_sha
    # Preserve different assembly versions, root selections and analyzer revisions.
    identity = json.dumps({'assembly': digest, 'type': args.type, 'roots': report['root_methods'],
                           'analyzer': analyzer_sha}, sort_keys=True).encode()
    output = folder / (hashlib.sha256(identity).hexdigest()[:24] + '.json')
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'type': args.type, 'methods': len(report['methods']),
                      'dependencies': len(report['dependencies']), 'blockers': len(report['blockers']),
                      'assembly_executed': False, 'report': str(output)}, indent=2))


if __name__ == '__main__':
    main()
