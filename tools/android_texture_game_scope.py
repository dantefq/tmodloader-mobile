"""Own Android registry to the game's bounded native laboratory scope.

External control supports a separate app or the own in-process test companion.
Only fixed lab image profiles are exported. Native rollback precedes their ACK.
"""
import hashlib
import json
from pathlib import PurePosixPath
import shlex
import sys
import tarfile

from texture_bridge_fixture import verify_export
from texture_lab_profiles import OWN, PINNED, definition, read_reference

GAME = 'com.and.games505.TerrariaPaid'


def backup_saves(path):
    saves = []
    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            name = PurePosixPath(member.name)
            if name.is_absolute() or '..' in name.parts or not name.parts or name.parts[0] not in ('Players', 'Worlds'):
                raise ValueError('Unexpected private backup member')
            if member.isfile() and name.suffix in ('.plr', '.wld'):
                if member.size > 64 * 1024 * 1024: raise ValueError('Save backup member exceeds lab bounds')
                saves.append({'path': member.name, 'sha256': hashlib.sha256(archive.extractfile(member).read()).hexdigest()})
    if not saves or len({row['path'] for row in saves}) != len(saves): raise ValueError('Unique save baseline required')
    return saves


def run_scope(script, adb, lab, serial, port, expected_pid, saves, retention,
              managed_root='/data/user/0/tm.loader.textureprobe/files/managed', in_process=False,
              profile=OWN, reference_path=None, after_initialize=None):
    expected = definition(profile)
    reference = read_reference(reference_path) if profile == PINNED else None
    transcript = []; transfer_id = None; native_attempted = False; released = False
    def request(value):
        raw = script.exports_sync.request(value); parsed = json.loads(raw)
        transcript.append({'request': value, 'response': parsed})
        (lab / 'live-host-transcript.json').write_text(json.dumps(transcript, indent=2), encoding='utf-8')
        return raw, parsed
    def require(value, message):
        if not value: raise RuntimeError(message)
    def acknowledge():
        nonlocal released
        _, ack = request({'operation': 'ack', 'transferId': transfer_id})
        require(ack.get('pending') == 0, 'Android registry rejected matching native teardown ACK')
        released = True; retention['required'] = False
        _, unloaded = request({'operation': 'unload'})
        require(unloaded.get('status') == 'unloaded' and unloaded.get('pending') == 0 and unloaded.get('cacheBytes') == 0 and
                unloaded.get('hostChecks') == 29,
                'Android registry did not unload after native teardown')
    try:
        for row in saves:
            current = adb('exec-out', 'su', '-c', 'cat ' + shlex.quote('/storage/emulated/0/Android/data/' + GAME + '/' + row['path']), binary=True)
            require(hashlib.sha256(current).hexdigest() == row['sha256'], 'Save backup is not the current pre-test baseline')
        description = script.exports_sync.initialize(managed_root, profile)
        require(description.get('format') == 'tmal-texture-bridge-v1' and description.get('pending') == 0, 'Own Android registry not ready')
        require(description.get('profile') == profile and description.get('profileChecks') == 4, 'Android resource profile guards differ')
        if after_initialize is not None: after_initialize(description)
        retention['required'] = True
        exported, value = request({'operation': 'begin'})
        plan, _, _, _ = verify_export(value, profile, reference); transfer_id = plan['transferId']
        require(plan['generation'] == description['generation'], 'Android registry generation changed before export')
        checked = script.exports_sync.checkexport(exported, {'generation': description['generation'], 'itemType': 6196, 'item': expected['item']})
        require(checked.get('transferId') == transfer_id and checked.get('width') == expected['width'] and checked.get('height') == expected['height'], 'Android receiver differs')
        export_path = lab / 'own-android-export.json'; export_path.write_text(exported, encoding='utf-8')
        require(request({'operation': 'unload'})[1].get('error') == 'InvalidOperationException', 'Pending Android export did not block unload')
        _, gc = request({'operation': 'gc'})
        require(gc.get('bytes') == 16777216 and gc.get('generation') == description['generation'], 'Android transfer did not survive GC')
        require(request({'operation': 'read', 'transferId': transfer_id})[0] == exported, 'Android export changed after GC')
        require(adb('shell', 'pidof', GAME) == expected_pid, 'Existing game process changed before graphics')
        (lab / 'return-to-game.txt').write_text(adb('shell', 'am', 'start', '-W', '-n', GAME + '/com.unity3d.player.UnityPlayerActivity'), encoding='utf-8')
        require(adb('shell', 'pidof', GAME) == expected_pid, 'Returning to game restarted its process')
        from probe_device_texture_upload import main as native_probe
        previous = sys.argv
        sys.argv = ['probe_device_texture_upload.py', '--serial', serial, '--port', str(port), '--lab', str(lab / 'native'),
                    '--own-bridge-export', str(export_path), '--verify-xna-wrapper', '--verify-native-asset',
                    '--verify-private-slot', '--verify-menu-overlay', '--verify-item-icon']
        if profile == PINNED:
            sys.argv += ['--pinned-bridge-resource', str(reference_path)]
        native_attempted = True
        try: native_probe()
        finally: sys.argv = previous
        native = json.loads((lab / 'native/texture-upload-result.json').read_text('utf-8'))
        teardown = json.loads((lab / 'native/teardown-result.json').read_text('utf-8'))
        require(native.get('phase') == 'complete' and native.get('content_tables_restored') and native.get('destroy_observed') and
                native.get('texture_transfer_id') == transfer_id and teardown.get('teardown_complete') is True,
                'Native restoration/destruction must precede Android ACK')
        require(request({'operation': 'read', 'transferId': transfer_id})[0] == exported, 'Android owner/export changed during native scope')
        require(request({'operation': 'unload'})[1].get('error') == 'InvalidOperationException', 'Android unload bypassed pending native transfer')
        acknowledge()
        require(request({'operation': 'read', 'transferId': transfer_id})[1].get('error') == 'InvalidOperationException', 'Old Android export remained active')
        checks = []
        for row in saves:
            data = adb('exec-out', 'su', '-c', 'cat ' + shlex.quote('/storage/emulated/0/Android/data/' + GAME + '/' + row['path']), binary=True)
            checks.append({'path': row['path'], 'unchanged': hashlib.sha256(data).hexdigest() == row['sha256']})
        crash = adb('logcat', '-b', 'crash', '-d', '--pid=' + expected_pid)
        (lab / 'game-crash-buffer.txt').write_text(crash, encoding='utf-8')
        health = {'same_game_process': adb('shell', 'pidof', GAME) == expected_pid, 'saves': checks,
                  'crash_buffer_empty': not any(line.strip() and not line.startswith('---------') for line in crash.splitlines())}
        (lab / 'game-health.json').write_text(json.dumps(health, indent=2), encoding='utf-8')
        require(health['same_game_process'] and all(row['unchanged'] for row in checks) and health['crash_buffer_empty'], 'Post-scope game health differs')
        return {'status': 'verified-android-registry-to-native-game-lab', 'android_registry_active_during_game_graphics': True,
                'native_teardown_acknowledgements_simulated': False, 'native_graphics_executed': True,
                'same_process_companion_integration': in_process, 'own_fixture_only': profile == OWN,
                'resource_profile': profile, 'pinned_original_texture_used': profile == PINNED, 'original_mod_code_executed': False,
                'profile_rejection_checks': 4,
                'content_tables_restored': True, 'game_health_verified': True, 'inventory_item_rendered': False}
    finally:
        if transfer_id is None and retention['required']:
            (lab / 'recovery.json').write_text(json.dumps({'android_transfer_state': 'unknown',
                'native_attempted': native_attempted, 'android_controller_retention_required': True}, indent=2), encoding='utf-8')
        if transfer_id is not None and not released:
            # Only acknowledge a failed attempt if its native controller confirms
            # terminal cleanup. A missing/uncertain receipt never authorizes ACK.
            teardown_path = lab / 'native/teardown-result.json'
            clean = not native_attempted
            if native_attempted and teardown_path.exists():
                status = json.loads(teardown_path.read_text('utf-8'))
                clean = status.get('teardown_complete') is True and status.get('phase') in ('idle', 'complete', 'failed')
            recovery = {'native_attempted': native_attempted, 'native_cleanup_confirmed': clean, 'android_transfer_released': False}
            if clean:
                try: acknowledge(); recovery['android_transfer_released'] = True
                except Exception as error: recovery['release_error'] = str(error)
            retention['required'] = not released
            recovery['android_controller_retention_required'] = retention['required']
            (lab / 'recovery.json').write_text(json.dumps(recovery, indent=2), encoding='utf-8')
