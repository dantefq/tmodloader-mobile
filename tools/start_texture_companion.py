"""Start only the separate own texture companion after a verified save baseline.

Instrumentation prepares runtime libraries without launching Unity. The probe
must initialize Mono first, then launch the game activity in the same process.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import time

from android_texture_game_scope import GAME, backup_saves
from build_companion import EXPECTED
from build_texture_bridge_probe import sha

ROOT = Path(__file__).resolve().parents[1]


def adb_client(executable, serial):
    def adb(*words, binary=False, required=True):
        value = subprocess.run([str(executable), '-s', serial, *words], capture_output=True, timeout=40)
        if required and value.returncode: raise RuntimeError('ADB texture-lab action failed: ' + value.stderr.decode('utf-8', 'replace'))
        return value.stdout if binary else value.stdout.decode('utf-8', 'replace').strip()
    return adb


def target_hash(adb):
    path = adb('shell', 'pm', 'path', GAME)
    if not path.startswith('package:') or '\n' in path: raise ValueError('One target APK required')
    return adb('shell', 'sha256sum', path[8:]).split()[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', required=True)
    for name in ('build', 'probe-build', 'lab', 'save-backup'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--saved-and-exited', action='store_true')
    parser.add_argument('--adb', type=Path, default=Path.home() / 'AppData/Local/Android/Sdk/platform-tools/adb.exe')
    args = parser.parse_args()
    lab = args.lab.resolve(); build = args.build.resolve(); probe = args.probe_build.resolve()
    if (not args.saved_and_exited or lab.exists() or any(p.is_relative_to(ROOT) for p in (lab, build, probe, args.save_backup.resolve()))):
        raise ValueError('Saved/exited confirmation, new private lab and private build/backup required')
    lab.mkdir(parents=True)
    report = json.loads((build / 'build.json').read_text('utf-8')); apk = build / 'Texture-Bridge-Companion.apk'
    script = probe / 'texture-bridge-probe.js'
    if (report.get('format') != 'tmal-texture-companion-build-v1' or report.get('bootstrap_order') != 'mono-before-unity' or sha(apk) != report['apk_sha256'] or
            sha(script) != report['probe_script_sha256'] or report['target_apk_sha256'] != EXPECTED):
        raise ValueError('Pinned companion/probe identities differ')
    adb = adb_client(args.adb, args.serial)
    if adb('get-state') != 'device' or adb('shell', 'getprop', 'ro.product.cpu.abi') != 'arm64-v8a' or target_hash(adb) != EXPECTED:
        raise ValueError('Authorized native ARM64 target and exact researched APK required')
    saves = backup_saves(args.save_backup)
    for row in saves:
        data = adb('exec-out', 'su', '-c', 'cat ' + shlex.quote('/storage/emulated/0/Android/data/' + GAME + '/' + row['path']), binary=True)
        if hashlib.sha256(data).hexdigest() != row['sha256']: raise ValueError('Save backup is not the current baseline')
    (lab / 'install.txt').write_text(adb('install', '-r', str(apk)), encoding='utf-8')
    component = 'tm.loader.texturecompanion/tm.loader.texturecompanion.TextureInstrumentation'
    (lab / 'instrumentation-start.txt').write_text(adb('shell', 'am', 'instrument', '--user', '0', component), encoding='utf-8')
    deadline = time.monotonic() + 25; pid = None
    while time.monotonic() < deadline:
        pid = adb('shell', 'pidof', GAME, required=False)
        if pid.isdigit():
            log = adb('logcat', '-d', '--pid=' + pid, '-s', 'TMALTexture:I', '*:S')
            if 'Texture lab setup failed' in log:
                (lab / 'failed-setup-log.txt').write_text(log, encoding='utf-8'); raise RuntimeError('Texture instrumentation setup failed')
            if 'TEXTURE_INSTRUMENTATION_READY' in log: break
        time.sleep(0.25)
    else: raise RuntimeError('Own texture instrumentation did not become ready')
    if 'TEXTURE_MONO_LIBRARIES_READY_BEFORE_ACTIVITY' not in log:
        raise RuntimeError('Runtime libraries were not prepared before the activity')
    (lab / 'bootstrap-log.txt').write_text(log, encoding='utf-8')
    managed_root = '/data/user/0/' + GAME + '/files/tmloader-texture-lab/managed'
    for name, digest in report['managed_files'].items():
        if name not in ('TerrariaMobile.ManagedDemo.dll', 'tModLoader.dll'): raise ValueError('Unexpected managed file')
        observed = adb('shell', 'su', '-c', shlex.quote('sha256sum ' + shlex.quote(managed_root + '/' + name))).split()[0]
        if observed != digest: raise ValueError('Copied own managed file differs')
    for name, digest in report.get('resource_files', {}).items():
        if name != 'pinned-icon.rawimg': raise ValueError('Unexpected original resource')
        observed = adb('shell', 'su', '-c', shlex.quote('sha256sum ' + shlex.quote(managed_root + '/' + name))).split()[0]
        if observed != digest: raise ValueError('Copied pinned image differs')
    if target_hash(adb) != EXPECTED: raise RuntimeError('Target APK changed')
    prepared = {'status': 'prepared-runtime-before-unity', 'bootstrap_order': 'mono-before-unity', 'serial': args.serial, 'game_pid': pid, 'managed_root': managed_root,
                'companion_apk_sha256': report['apk_sha256'], 'managed_files': report['managed_files'],
                'script': str(script), 'script_sha256': report['probe_script_sha256'], 'target_apk_sha256': EXPECTED,
                'saves': saves, 'backup_sha256': sha(args.save_backup), 'original_mod_code_bundled': False}
    prepared.update(resource_profile=report.get('resource_profile', 'own-2x2'), resource_files=report.get('resource_files', {}),
                    reference_path=str(probe / 'assets/managed/pinned-icon.rawimg') if report.get('resource_files') else None)
    (lab / 'prepared.json').write_text(json.dumps(prepared, indent=2), encoding='utf-8')
    print(json.dumps({'runtime_libraries_loaded_in_game': True, 'exact_own_managed_files_matched': True,
                      'target_apk_unchanged': True, 'scene_or_graphics_verified': False}))


if __name__ == '__main__': main()
