"""Install and execute only our isolated texture probe on an explicit ADB target.

Uses an already configured loopback Frida server. All evidence stays private.
The optional two-process native game lab requires a private save backup. It
restores copied tables and never adds inventory entries or writes saves.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
from texture_bridge_fixture import verify_export
from texture_lab_profiles import OWN, PINNED, read_reference

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'tm.loader.textureprobe'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--build', required=True, type=Path)
    parser.add_argument('--lab', required=True, type=Path)
    parser.add_argument('--adb', type=Path, default=Path.home() / 'AppData/Local/Android/Sdk/platform-tools/adb.exe')
    parser.add_argument('--port', type=int, default=27043)
    parser.add_argument('--native-game', action='store_true', help='Own Android registry stays alive through the separate native game lab')
    parser.add_argument('--save-backup', type=Path, help='Required private Players/Worlds tar baseline for --native-game')
    parser.add_argument('--profile', choices=(OWN, PINNED), help='Explicit override of the build-selected fixed profile')
    args = parser.parse_args()
    lab = args.lab.resolve(); build = args.build.resolve()
    if lab.exists() or lab.is_relative_to(ROOT) or build.is_relative_to(ROOT) or not 1 <= args.port <= 65535:
        raise ValueError('New private evidence folder, private build and valid loopback port required')
    lab.mkdir(parents=True)
    report = json.loads((build / 'build.json').read_text('utf-8'))
    profile = args.profile or report.get('resource_profile', OWN)
    reference_path = build / 'assets/managed/pinned-icon.rawimg' if profile == PINNED else None
    reference = read_reference(reference_path) if reference_path else None
    apk = build / 'Texture-Bridge-Probe.apk'; script_path = build / 'texture-bridge-probe.js'
    if report['format'] != 'tmal-texture-probe-build-v1' or sha(apk) != report['apk_sha256'] or sha(script_path) != report['script_sha256']:
        raise ValueError('Own build identities differ')
    if set(report['files']) != {'TerrariaMobile.ManagedDemo.dll', 'tModLoader.dll'}:
        raise ValueError('Only the two own managed assemblies are supported')
    def adb(*words, required=True, binary=False):
        result = subprocess.run([str(args.adb), '-s', args.serial, *words], capture_output=True, timeout=60)
        if required and result.returncode:
            raise RuntimeError('ADB probe action failed; private stderr: ' + result.stderr.decode('utf-8', 'replace'))
        return result.stdout if binary else result.stdout.decode('utf-8', 'replace').strip()
    if adb('get-state') != 'device' or adb('shell', 'getprop', 'ro.product.cpu.abi') != 'arm64-v8a':
        raise ValueError('Authorized native ARM64 device required')
    saves = None; game_pid = None
    if args.native_game:
        if args.save_backup is None or args.save_backup.resolve().is_relative_to(ROOT):
            raise ValueError('Private save backup required for the native game scope')
        from android_texture_game_scope import backup_saves
        saves = backup_saves(args.save_backup)
        game_pid = adb('shell', 'pidof', 'com.and.games505.TerrariaPaid', required=False)
        if not game_pid.isdigit(): raise ValueError('Existing game process required; no game restart is performed')
    (lab / 'install.txt').write_text(adb('install', '-r', str(apk)), encoding='utf-8')
    adb('shell', 'am', 'force-stop', PACKAGE)
    adb('shell', 'run-as', PACKAGE, 'rm', '-f', 'files/ready')
    (lab / 'launch.txt').write_text(adb('shell', 'am', 'start', '-W', '-n', PACKAGE + '/.TextureProbeActivity'), encoding='utf-8')
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if adb('shell', 'run-as', PACKAGE, 'cat', 'files/ready', required=False) == '\x01': break
        time.sleep(0.25)
    else: raise RuntimeError('Isolated Java/Mono readiness timed out')
    pid = adb('shell', 'pidof', PACKAGE)
    if not pid.isdigit(): raise ValueError('One isolated probe process required')
    package_path = adb('shell', 'pm', 'path', PACKAGE)
    if not package_path.startswith('package:') or '\n' in package_path:
        raise ValueError('Single probe APK path required')
    if adb('shell', 'sha256sum', package_path[8:]).split()[0] != report['apk_sha256']:
        raise ValueError('Installed own probe APK differs')
    for name, digest in report['files'].items():
        if adb('shell', 'run-as', PACKAGE, 'sha256sum', 'files/managed/' + name).split()[0] != digest:
            raise ValueError('Extracted own managed file differs: ' + name)
    for name, digest in report.get('resource_files', {}).items():
        if name != 'pinned-icon.rawimg' or adb('shell', 'run-as', PACKAGE, 'sha256sum', 'files/managed/' + name).split()[0] != digest:
            raise ValueError('Extracted pinned resource differs')
    sys.path.insert(0, str(ROOT / '.tools/frida-deps'))
    import frida
    session = frida.get_device_manager().add_remote_device('127.0.0.1:' + str(args.port)).attach(int(pid))
    messages = []; script = None; retention = {'required': False}
    try:
        script = session.create_script(script_path.read_text('utf-8'), runtime='qjs')
        script.on('message', lambda message, data: messages.append(message))
        script.load()
        if args.native_game:
            from android_texture_game_scope import run_scope
            receipt = run_scope(script, adb, lab, args.serial, args.port, game_pid, saves, retention,
                                profile=profile, reference_path=reference_path)
            receipt.update(apk_sha256=report['apk_sha256'], script_sha256=report['script_sha256'], own_managed_files_matched=True)
            (lab / 'validation.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
            print(json.dumps(receipt))
            return
        result = script.exports_sync.run('/data/user/0/' + PACKAGE + '/files/managed', profile)
        (lab / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        if (result.get('status') != 'passed' or result.get('host_checks') != 29 or result.get('gc_bytes') != 16777216 or
                result.get('profile_checks') != 4 or result.get('resource_profile') != profile or
                result.get('native_graphics_executed') is not False or result.get('native_teardown_acknowledgements_simulated') is not True):
            raise ValueError('Isolated bridge checks did not pass at the claimed scope')
        exports = [row['response'] for row in result['transcript'] if row['operation'] == 'begin' and 'plan' in row['response']]
        if len(exports) != 2: raise ValueError('Expected two own transfer exports')
        for index, value in enumerate(exports):
            (lab / ('export-' + str(index) + '.json')).write_text(json.dumps(value, indent=2), encoding='utf-8')
            verify_export(value, profile, reference)
        if (exports[0]['plan']['generation'] != exports[1]['plan']['generation'] or
                exports[0]['plan']['transferId'] == exports[1]['plan']['transferId']):
            raise ValueError('Expected one generation and distinct transfer IDs')
        receipt = {'status': 'verified-isolated-android-texture-bridge', 'apk_sha256': report['apk_sha256'],
                   'script_sha256': report['script_sha256'], 'own_managed_files_matched': True,
                   'installed_apk_matched': True, 'independent_png_pixels_matched': True,
                   'game_execution_verified': False, 'original_mod_execution_verified': False,
                   'native_teardown_acknowledgements_simulated': True}
        receipt.update(resource_profile=profile, pinned_original_texture_used=profile == PINNED,
                       resource_files=report.get('resource_files', {}))
        (lab / 'validation.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
        print(json.dumps(receipt))
    finally:
        (lab / 'frida-messages.json').write_text(json.dumps(messages, indent=2), encoding='utf-8')
        if script is not None:
            if retention['required']: script.eternalize()
            else: script.unload()
        session.detach()
        (lab / 'logcat.txt').write_text(adb('logcat', '-d', '--pid=' + pid, '-t', '1500', required=False), encoding='utf-8')


if __name__ == '__main__':
    main()
