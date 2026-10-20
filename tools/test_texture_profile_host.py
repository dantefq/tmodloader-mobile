"""Run the exact own probe assembly on host CLR with pinned private image data."""
import argparse
import json
from pathlib import Path
import shutil

from build_companion import run
from build_texture_bridge_probe import sha
from texture_bridge_fixture import verify_export
from texture_lab_profiles import PINNED, read_reference

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--lab', type=Path, required=True)
    parser.add_argument('--dotnet', type=Path, default=Path('C:/Program Files/dotnet'))
    args = parser.parse_args()
    lab = args.lab.resolve(); build = args.build.resolve()
    if lab.exists() or lab.is_relative_to(ROOT) or build.is_relative_to(ROOT): raise ValueError('New private lab and private probe build required')
    report = json.loads((build / 'build.json').read_text('utf-8'))
    if report.get('resource_profile') != PINNED: raise ValueError('Pinned source profile build required')
    reference = read_reference(build / 'assets/managed/pinned-icon.rawimg')
    lab.mkdir(parents=True)
    for name, digest in report['files'].items():
        source = build / 'assets/managed' / name
        if name not in ('tModLoader.dll', 'TerrariaMobile.ManagedDemo.dll') or sha(source) != digest:
            raise ValueError('Own probe assembly differs')
        shutil.copyfile(source, lab / name)
    (lab / 'pinned-icon.rawimg').write_bytes(reference)
    refs = sorted((args.dotnet / 'packs/Microsoft.NETCore.App.Ref/8.0.31/ref/net8.0').glob('*.dll'))
    csc = args.dotnet / 'sdk/8.0.425/Roslyn/bincore/csc.dll'; executable = lab / 'TextureProfileHostChecks.dll'
    if not refs or not csc.is_file(): raise ValueError('Pinned SDK and refs required')
    lines = ['-nologo', '-target:exe', '-nostdlib+', '-deterministic+', '-langversion:12', '-out:"' + str(executable) + '"']
    lines += ['-r:"' + str(ref) + '"' for ref in [*refs, lab / 'tModLoader.dll', lab / 'TerrariaMobile.ManagedDemo.dll']]
    lines += ['"' + str(ROOT / 'managed/tests/TextureProfileHostChecks.cs') + '"']
    response = lab / 'host.rsp'; response.write_text('\n'.join(lines), encoding='utf-8')
    run([args.dotnet / 'dotnet.exe', csc, '@' + str(response)])
    executable.with_suffix('.runtimeconfig.json').write_text(json.dumps({'runtimeOptions': {
        'tfm': 'net8.0', 'framework': {'name': 'Microsoft.NETCore.App', 'version': '8.0.31'}}}), encoding='utf-8')
    (lab / 'stdout.txt').write_text(run([args.dotnet / 'dotnet.exe', executable]), encoding='utf-8')
    verify_export(json.loads((lab / 'host-export.json').read_text('utf-8')), PINNED, reference)
    result = json.loads((lab / 'host-result.json').read_text('utf-8'))
    print(json.dumps({'host_profile_checks': result['checks'], 'managed_profile_guards': 4,
        'all_1496_rgba_pixels_independently_verified': True, 'native_graphics_executed': False, 'original_mod_code_executed': False}))


if __name__ == '__main__': main()
