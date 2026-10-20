"""Run the own texture lab in a prepared companion game process, not gameplay."""
import argparse
import json
from pathlib import Path
import shlex
import sys
import time
import hashlib

from android_texture_game_scope import run_scope
from build_companion import EXPECTED
from build_texture_bridge_probe import sha
from start_texture_companion import adb_client, target_hash

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared', type=Path, required=True)
    parser.add_argument('--lab', type=Path, required=True)
    parser.add_argument('--adb', type=Path, default=Path.home() / 'AppData/Local/Android/Sdk/platform-tools/adb.exe')
    parser.add_argument('--port', type=int, default=27043)
    args = parser.parse_args()
    lab = args.lab.resolve()
    if lab.exists() or lab.is_relative_to(ROOT) or args.prepared.resolve().is_relative_to(ROOT) or not 1 <= args.port <= 65535:
        raise ValueError('New private lab, private preparation receipt and valid port required')
    prepared = json.loads(args.prepared.read_text('utf-8')); source = Path(prepared['script'])
    root = '/data/user/0/com.and.games505.TerrariaPaid/files/tmloader-texture-lab/managed'
    if (prepared.get('status') != 'prepared-runtime-before-unity' or prepared.get('bootstrap_order') != 'mono-before-unity' or prepared['managed_root'] != root or
            source.resolve().is_relative_to(ROOT) or sha(source) != prepared['script_sha256']):
        raise ValueError('Prepared own runtime scope differs')
    adb = adb_client(args.adb, prepared['serial'])
    if adb('shell', 'pidof', 'com.and.games505.TerrariaPaid') != prepared['game_pid'] or target_hash(adb) != EXPECTED:
        raise ValueError('Prepared game process/APK changed')
    if set(prepared['managed_files']) != {'TerrariaMobile.ManagedDemo.dll', 'tModLoader.dll'}:
        raise ValueError('Only own validated fixture assemblies are supported')
    for name, digest in prepared['managed_files'].items():
        observed = adb('shell', 'su', '-c', shlex.quote('sha256sum ' + shlex.quote(root + '/' + name))).split()[0]
        if observed != digest: raise ValueError('Prepared managed files changed before execution')
    for name, digest in prepared.get('resource_files', {}).items():
        if name != 'pinned-icon.rawimg': raise ValueError('Unexpected original resource')
        observed = adb('shell', 'su', '-c', shlex.quote('sha256sum ' + shlex.quote(root + '/' + name))).split()[0]
        if observed != digest: raise ValueError('Pinned resource changed before execution')
    lab.mkdir(parents=True)
    sys.path.insert(0, str(ROOT / '.tools/frida-deps'))
    import frida
    session = frida.get_device_manager().add_remote_device('127.0.0.1:' + str(args.port)).attach(int(prepared['game_pid']))
    script = None; diagnostic = None; retention = {'required': False}; messages = []; report = None
    snapshots = []
    def snapshot(label):
        value = diagnostic.exports_sync.state(); snapshots.append({'phase': label, **value})
        (lab / 'signal-ownership.json').write_text(json.dumps(snapshots, indent=2), encoding='utf-8')
        return value
    def before_unity_launch(description):
        value = snapshot('mono-initialized-before-unity')
        if not value['mono_initialized'] or value['unity_loaded'] or any(
                row['owner'] != 'libmonosgen-2.0.so' for row in value['signals'] if row['signal'] in (24, 30)):
            raise RuntimeError('Early Mono signal ownership differs')
        (lab / 'activity-start.txt').write_text(adb('shell', 'am', 'start', '-W', '-n',
            'com.and.games505.TerrariaPaid/com.unity3d.player.UnityPlayerActivity'), encoding='utf-8')
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if adb('shell', 'pidof', 'com.and.games505.TerrariaPaid', required=False) != prepared['game_pid']:
                raise RuntimeError('Early-bootstrap game process exited')
            value = snapshot('unity-loading')
            if value['unity_loaded'] and all(row['owner'] == 'libil2cpp.so' for row in value['signals'] if row['signal'] in (24, 30)):
                break
            time.sleep(0.5)
        else: raise RuntimeError('Unity did not establish its own suspend/restart signals')
        time.sleep(8)
        (lab / 'menu-after-early-bootstrap.png').write_bytes(adb('exec-out', 'screencap', '-p', binary=True))
    try:
        diagnostic = session.create_script((ROOT / 'runtime/mono-signal-state.js').read_text('utf-8'), runtime='qjs'); diagnostic.load()
        initial = snapshot('before-mono')
        if initial['mono_initialized'] or initial['unity_loaded']:
            raise RuntimeError('Fresh process before Mono and Unity initialization required')
        script = session.create_script(source.read_text('utf-8'), runtime='qjs')
        script.on('message', lambda message, data: messages.append(message)); script.load()
        report = run_scope(script, adb, lab, prepared['serial'], args.port, prepared['game_pid'], prepared['saves'], retention,
                           managed_root=root, in_process=True, profile=prepared.get('resource_profile', 'own-2x2'),
                           reference_path=prepared.get('reference_path'), after_initialize=before_unity_launch)
        if target_hash(adb) != EXPECTED: raise RuntimeError('Target APK changed during the probe')
        report.update(status='functional-complete-awaiting-detach-check', game_apk_unchanged=True,
                      companion_apk_sha256=prepared['companion_apk_sha256'], script_sha256=prepared['script_sha256'],
                      bootstrap_order='mono-before-unity', own_managed_files=prepared['managed_files'])
        snapshot('after-native-rollback-before-detach')
        (lab / 'validation.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    finally:
        (lab / 'frida-messages.json').write_text(json.dumps(messages, indent=2), encoding='utf-8')
        if script is not None:
            if retention['required']: script.eternalize()
            else: script.unload()
        if diagnostic is not None: diagnostic.unload()
        session.detach()
        (lab / 'process-log.txt').write_text(adb('logcat', '-d', '--pid=' + prepared['game_pid'], '-t', '1500', required=False), encoding='utf-8')
    # Functional success inside the controller is insufficient: the runtime must
    # remain alive after all script-owned native code has been unloaded.
    samples = []; start = time.monotonic()
    for index in range(13):
        alive = adb('shell', 'pidof', 'com.and.games505.TerrariaPaid', required=False) == prepared['game_pid']
        samples.append({'elapsed_seconds': round(time.monotonic() - start, 2), 'same_process': alive})
        if not alive: break
        if index < 12: time.sleep(5)
    checks = []
    for row in prepared['saves']:
        data = adb('exec-out', 'su', '-c', 'cat ' + shlex.quote('/storage/emulated/0/Android/data/com.and.games505.TerrariaPaid/' + row['path']), binary=True)
        checks.append({'path': row['path'], 'unchanged': hashlib.sha256(data).hexdigest() == row['sha256']})
    crash = adb('logcat', '-b', 'crash', '-d', '--pid=' + prepared['game_pid'], required=False)
    (lab / 'after-detach-crash.txt').write_text(crash, encoding='utf-8')
    health = {'samples': samples, 'saves': checks, 'crash_buffer_empty': not any(
        line.strip() and not line.startswith('---------') for line in crash.splitlines())}
    health['passed'] = len(samples) == 13 and all(row['same_process'] for row in samples) and all(row['unchanged'] for row in checks) and health['crash_buffer_empty']
    (lab / 'after-detach-health.json').write_text(json.dumps(health, indent=2), encoding='utf-8')
    report.update(status='verified-in-process-texture-companion-lab' if health['passed'] else 'failed-after-controller-detach',
                  post_detach_health_verified=health['passed'], post_detach_observation_seconds=round(time.monotonic() - start, 2))
    (lab / 'validation.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    if not health['passed']: raise RuntimeError('Game health failed after controller detach')
    print(json.dumps({key: value for key, value in report.items() if key != 'own_managed_files'}))


if __name__ == '__main__': main()
