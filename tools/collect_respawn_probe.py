"""Verify installed probe, copied bundle, and live-process original-DLL results."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lab', type=Path, required=True)
    p.add_argument('--serial', required=True)
    args = p.parse_args()
    lab = args.lab.resolve()
    if lab.is_relative_to(ROOT):
        raise ValueError('Keep raw device artifacts private')
    adb_path = Path.home() / 'AppData/Local/Android/Sdk/platform-tools/adb.exe'
    def adb(*words):
        return subprocess.check_output([str(adb_path), '-s', args.serial, *words], timeout=60)
    def sha(data):
        return hashlib.sha256(data).hexdigest()
    package = 'tm.loader.managedprobe'
    pid = adb('shell', 'pidof', package).decode().strip()
    if not pid.isdigit():
        raise ValueError('Expected one running isolated probe')
    build = json.loads((lab / 'respawn-probe/probe-build.json').read_text())
    bundle = json.loads((lab / 'respawn-demo/bundle-build.json').read_text())
    path = adb('shell', 'pm', 'path', package).decode().strip()
    if not path.startswith('package:') or '\n' in path:
        raise ValueError('Expected one installed APK')
    installed = adb('exec-out', 'cat', path[8:])
    if sha(installed) != build['sha256']:
        raise ValueError('Installed probe differs from signed build')
    private_root = '/data/user/0/' + package + '/files/managed/'
    names = bundle['files']
    if len(names) != 13:
        raise ValueError('Expected thirteen pinned managed bundle files')
    if any(not name.replace('.', '').replace('-', '').replace('_', '').isalnum() for name in names):
        raise ValueError('Unexpected bundle filename')
    raw_hashes = adb('exec-out', 'su', '-c', 'sha256sum ' + ' '.join(private_root + name for name in names))
    actual = {Path(line.split()[1]).name: line.split()[0] for line in raw_hashes.decode().splitlines()}
    if actual != names:
        raise ValueError('Copied Android managed files differ from pinned bundle')
    raw_result = adb('exec-out', 'su', '-c', 'cat ' + private_root + 'result.json')
    result = json.loads(raw_result)
    if (result['first'], result['afterGc'], result['gcStressBytes']) != (13, 13, 16777216):
        raise ValueError('Original callback/GC results differ')
    checks = result['callbacks']
    if checks['dll_sha256'] != bundle['contract']['mod_dll_sha256']:
        raise ValueError('Executed mod identity differs')
    if len(checks['callbacks']) != 13 or any(row['actual'] != row['expected'] for row in checks['callbacks']):
        raise ValueError('Original callback result mismatch')
    if checks.get('live_snapshot_checks') != 8 or bundle['contract'].get('live_snapshot_checks') != 8:
        raise ValueError('Live snapshot transport checks differ')
    expected = [('kill', 3, 600, True, 180), ('kill', 61, 600, True, 3660),
                ('dead', 61, 3660, False, 3660), ('dead', 3, 3660, True, 180)]
    for name in ('nativeJsonBeforeGc', 'nativeJsonAfterGc'):
        rows = result.get(name, [])
        transport_actual = [(r['phase'], r['seconds'], r['timer'], r['adjust'], r['actual']) for r in rows]
        if transport_actual != expected or any(r['expected'] != r['actual'] for r in rows):
            raise ValueError('Native JSON snapshot results differ')
    if result.get('nativeJsonGcBytes') != 16777216:
        raise ValueError('Native JSON GC stress differs')
    if result['game_accessed'] or result['native_hook_installed'] or result['in_game_verified']:
        raise ValueError('Snapshot scope differs')
    raw_log = adb('logcat', '-d', '--pid=' + pid, '-v', 'threadtime')
    if b'RESPAWN_PROBE_OK ' not in raw_log or b'RESPAWN_PROBE_FAILED ' in raw_log:
        raise ValueError('Probe process success/failure log differs')
    if adb('shell', 'pidof', package).decode().strip() != pid:
        raise ValueError('Probe process changed during collection')
    (lab / 'android-result.json').write_bytes(raw_result)
    (lab / 'android-logcat.txt').write_bytes(raw_log)
    (lab / 'android-bundle-hashes.txt').write_bytes(raw_hashes)
    report = {'status': 'verified-original-respawn-callbacks-on-android-snapshots',
              'serial': args.serial, 'pid': int(pid), 'installed_apk_sha256': sha(installed),
              'managed_files_sha256': actual, 'result': result,
              'raw_result': str(lab / 'android-result.json'), 'raw_result_sha256': sha(raw_result),
              'raw_log': str(lab / 'android-logcat.txt'), 'raw_log_sha256': sha(raw_log),
              'live_game_respawn_supported': False, 'full_mod_lifecycle_supported': False,
              'original_dll_recompiled_or_patched': False,
              'limitations': ['Mod.Load records its IL request; no live IL2CPP rewrite is installed.',
                              'Mod.PostSetupContent, optional mod UI, multiplayer, and actual death/respawn were not tested.',
                              'Snapshot API is isolated from the current common item/time API.']}
    (ROOT / 'reports/shorter-respawn-android-validation.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': report['status'], 'pid': int(pid), 'files_verified': len(actual),
                      'checks_before_gc': 13, 'checks_after_gc': 13, 'live_transport_checks': 8,
                      'native_json_checks': 8, 'in_game_verified': False}, indent=2))


if __name__ == '__main__':
    main()
