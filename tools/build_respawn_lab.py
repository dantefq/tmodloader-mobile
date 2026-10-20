"""Run the pinned original ShorterRespawn DLL on isolated host snapshots.

No phone/game process is touched. The optional IL manipulator is applied to an
offline Cecil body from the user's PC install, which is never written/executed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from inspect_mod_api import assembly_bytes
from check_mod_signatures import compare

ROOT = Path(__file__).resolve().parents[1]
DLL_SHA = 'aeaf65ac9b0699950ebbd033f42891c298f807fa07d665da67c77adf2d4b5e9a'
TMOD_SHA = '4756cd6ae2125584920b5b6bc9be893705b820062bd2e0730bab11857b36e88a'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lab', type=Path, required=True)
    p.add_argument('--dotnet', type=Path, default=Path('C:/Program Files/dotnet'))
    p.add_argument('--game', type=Path, default=Path('C:/Program Files (x86)/Steam/steamapps/common/tModLoader'))
    p.add_argument('--tmod', type=Path, default=Path('C:/Program Files (x86)/Steam/steamapps/workshop/content/1281930/2562997415/2026.7/ShorterRespawn.tmod'))
    args = p.parse_args()
    lab = args.lab.resolve() / 'host-snapshots'
    if lab.is_relative_to(ROOT):
        raise ValueError('Keep third-party artifacts and binaries private')
    lab.mkdir(parents=True, exist_ok=True)
    if digest(args.tmod) != TMOD_SHA:
        raise ValueError('Pinned TMOD changed')
    data, header = assembly_bytes(args.tmod, 'ShorterRespawn.dll')
    if hashlib.sha256(data).hexdigest() != DLL_SHA:
        raise ValueError('Pinned DLL changed')
    (lab / 'ShorterRespawn.dll').write_bytes(data)
    libraries = args.game / 'Libraries'
    dependencies = {
        'FNA.dll': libraries / 'FNA/1.0.0/FNA.dll',
        'ReLogic.dll': libraries / 'ReLogic/1.0.0/ReLogic.dll',
        'log4net.dll': libraries / 'log4net/2.0.8.0/log4net.dll',
        'Newtonsoft.Json.dll': libraries / 'newtonsoft.json/13.0.3/lib/net6.0/Newtonsoft.Json.dll',
        'Mono.Cecil.dll': libraries / 'mono.cecil/0.11.6/lib/netstandard2.0/Mono.Cecil.dll',
        'MonoMod.Utils.dll': libraries / 'monomod.utils/25.0.10/lib/net8.0/MonoMod.Utils.dll',
    }
    # MonoMod helpers are transitive dependencies, copied from the same install.
    for name in ('MonoMod.Backports.dll', 'MonoMod.ILHelpers.dll'):
        candidates = list(libraries.rglob(name))
        if len(candidates) == 1:
            dependencies[name] = candidates[0]
        elif len(candidates) > 1:
            raise ValueError('Ambiguous installed dependency: ' + name)
    for name, path in dependencies.items():
        shutil.copyfile(path, lab / name)
    refs = sorted((args.dotnet / 'packs/Microsoft.NETCore.App.Ref/8.0.31/ref/net8.0').glob('*.dll'))
    if not refs:
        raise ValueError('Pinned .NET reference assemblies missing')
    def compile(name, sources, extra):
        target = lab / name
        lines = ['-nologo', '-nostdlib+', '-deterministic+', '-langversion:12',
                 '-target:' + ('exe' if name == 'OriginalRespawnChecks.dll' else 'library'),
                 f'-out:"{target}"']
        lines += [f'-r:"{path}"' for path in [*refs, *extra]]
        lines += [f'"{ROOT / source}"' for source in sources]
        rsp = lab / (name + '.rsp')
        rsp.write_text('\n'.join(lines), encoding='utf-8')
        subprocess.run([str(args.dotnet / 'dotnet.exe'),
                        str(args.dotnet / 'sdk/8.0.425/Roslyn/bincore/csc.dll'),
                        '@' + str(rsp)], check=True, timeout=120)
        return target
    deps = [lab / name for name in dependencies]
    shim = compile('tModLoader.dll', ['managed/respawn-lab/SnapshotApi.cs'], deps)
    hooks = compile('TerrariaHooks.dll', ['managed/respawn-lab/RecordedHooks.cs'], deps)
    preflight = compare(data, shim.read_bytes())
    unsupported = [r for r in preflight['member_checks'] if r['status'] not in ('exact-signature', 'unsupported-owner')]
    if preflight['missing_types'] or unsupported or set(preflight['override_counts']) != {'exact-override'}:
        raise ValueError('Snapshot ABI preflight failed: ' + json.dumps(preflight))
    host_sources = ['managed/respawn-lab/OriginalRespawnChecks.cs', 'managed/respawn-lab/LiveRespawnHost.cs']
    runner = compile('OriginalRespawnChecks.dll', host_sources, [shim, hooks, *deps])
    runner.with_suffix('.runtimeconfig.json').write_text(json.dumps({'runtimeOptions': {
        'tfm': 'net8.0', 'framework': {'name': 'Microsoft.NETCore.App', 'version': '8.0.31'}}}), encoding='utf-8')
    game = args.game / 'tModLoader.dll'
    before_game_hash = digest(game)
    result = subprocess.run([str(args.dotnet / 'dotnet.exe'), str(runner), str(game)],
                            capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    checks = json.loads(result.stdout)
    if digest(game) != before_game_hash or digest(lab / 'ShorterRespawn.dll') != DLL_SHA:
        raise ValueError('Input assembly changed during checks')
    host = compile('TerrariaMobile.ManagedDemo.dll', host_sources, [shim, hooks, *deps])
    report = {'status': checks['status'], 'header': header,
              'source_tmod_sha256': TMOD_SHA, 'source_dll_sha256': DLL_SHA,
              'source_pc_game_sha256': before_game_hash,
              'dependencies': {name: {'source': str(path), 'sha256': digest(path)} for name, path in dependencies.items()},
              'own_shim_sha256': digest(shim), 'own_recorded_hooks_sha256': digest(hooks),
              'static_signature_preflight': preflight, 'checks': checks,
              'phone_touched': False, 'general_mod_compatibility_verified': False}
    (lab / 'host-validation.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    (ROOT / 'reports/shorter-respawn-host-validation.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    bundle = args.lab.resolve() / 'respawn-demo/bundle'
    bundle.mkdir(parents=True, exist_ok=True)
    names = [host.name, shim.name, hooks.name, 'ShorterRespawn.dll', *dependencies]
    for name in names:
        shutil.copyfile(lab / name, bundle / name)
    contract = {'mode': 'respawn-snapshot', 'mod': 'ShorterRespawn', 'version': '1.2.1.1',
                'mod_dll_sha256': DLL_SHA, 'callback_checks': len(checks['callbacks']) - 1,
                'live_snapshot_checks': checks['live_snapshot_checks'],
                'live_game_supported': False, 'native_hook_installed': False}
    (bundle / 'demo-contract.json').write_text(json.dumps(contract, indent=2) + '\n', encoding='utf-8')
    bundle_report = {'status': 'built-host-snapshots-verified', 'bundle': str(bundle),
                     'files': {name: digest(bundle / name) for name in [*names, 'demo-contract.json']},
                     'own_api_shim': True, 'game_code_bundled': False, 'original_dll_patched': False,
                     'private_lab_only': True, 'contract': contract}
    (bundle.parent / 'bundle-build.json').write_text(json.dumps(bundle_report, indent=2) + '\n', encoding='utf-8')
    (ROOT / 'reports/respawn-demo-build.json').write_text(json.dumps(bundle_report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(checks, indent=2))


if __name__ == '__main__':
    main()
