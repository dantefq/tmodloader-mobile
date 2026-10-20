"""Verify the original local sleep mod's isolated Android probe result."""
import argparse
import json
from pathlib import Path
import subprocess
from datetime import datetime
from apk_format import sha256

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--serial', required=True)
    p.add_argument('--unified', action='store_true')
    p.add_argument('--adb', type=Path, default=Path.home()/'AppData/Local/Android/Sdk/platform-tools/adb.exe')
    args = p.parse_args()
    def adb(*words):
        r = subprocess.run([str(args.adb), '-s', args.serial, *words], capture_output=True, text=True, timeout=25)
        if r.returncode: raise ValueError(r.stderr)
        return r.stdout.strip()
    stem = 'unified-sleep' if args.unified else 'sleep'
    build = json.loads((ROOT/f'reports/{stem}-probe-build.json').read_text())
    bundle = json.loads((ROOT/f'reports/{stem}-demo-build.json').read_text())
    row = json.loads(adb('shell', 'run-as', 'tm.loader.managedprobe', 'cat', 'files/managed/result.json'))
    if row.get('status') != 'original-local-mod-executed-in-isolated-android-probe' or row['in_game_verified'] or row['game_accessed']:
        raise ValueError('Unexpected probe scope')
    if sha256(Path(build['apk'])) != build['sha256'] or row['mod_dll_sha256'] != bundle['files']['ChangeSleepTime.dll']:
        raise ValueError('Build or mod hash differs')
    actual = adb('shell', 'run-as', 'tm.loader.managedprobe', 'sha256sum', 'files/managed/ChangeSleepTime.dll').split()[0]
    if actual != row['mod_dll_sha256']: raise ValueError('Device DLL differs from the original local mod')
    for name, digest in bundle['files'].items():
        if adb('shell', 'run-as', 'tm.loader.managedprobe', 'sha256sum', 'files/managed/'+name).split()[0] != digest:
            raise ValueError('Device bundle differs: '+name)
    if len(row['cases']) != 10 or any(c['expected'] != c['actual'] for c in row['cases']): raise ValueError('Time cases failed')
    if row['handlers'] != 1 or row['selfTest'] != 10 or row['gcStressBytes'] != 16777216 or row['afterGc'] != [5,5,5]:
        raise ValueError('Host or post-GC check failed')
    paths = adb('shell', 'pm', 'path', 'tm.loader.managedprobe').splitlines()
    if len(paths) != 1 or not paths[0].startswith('package:'): raise ValueError('Unexpected installed probe paths')
    installed = Path(build['apk']).parent/'installed-probe.apk'
    adb('pull', paths[0][8:], str(installed))
    if sha256(installed) != build['sha256']: raise ValueError('Installed probe APK differs from build')
    if args.unified:
        expected_item = 'd7c838eaf97d17cf48f314f507a8d89292af47d6fe952cfe6522417bf8c14826'
        if (row.get('api_revision') != 'managed-foundation-v2' or row.get('lifecycleChecks') != 7
            or row.get('contentChecks') != 14 or row.get('pc_item_dll_sha256') != expected_item):
            raise ValueError('Unified host checks differ')
        if adb('shell', 'run-as', 'tm.loader.managedprobe', 'sha256sum', 'files/managed/PcModItemDemo.dll').split()[0] != expected_item:
            raise ValueError('Extracted PC item DLL differs')
    row.update({'probe_apk_sha256': build['sha256'], 'date_local': datetime.now().date().isoformat(),
                'installed_probe_apk_hash_matched': True, 'device_bundle_hashes_matched': True,
                'device_serial': args.serial,
                'device': adb('shell','getprop','ro.product.model')+' Android'+adb('shell','getprop','ro.build.version.release'),
                'device_abis': adb('shell','getprop','ro.product.cpu.abilist').split(','),
                'probe_pid': int(adb('shell', 'pidof', 'tm.loader.managedprobe')),
                'device_dll_hash_matched': True, 'files': bundle['files'], 'local_source_tmod_sha256': bundle['source_tmod_sha256']})
    (ROOT/f'reports/{stem}-probe-validation.json').write_text(json.dumps(row, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'status': row['status'], 'cases': len(row['cases']), 'device_dll_hash_matched': True, 'in_game_verified': False}))


if __name__ == '__main__': main()
