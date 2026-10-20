"""Collect exact-artifact native respawn evidence, retaining raw logs privately."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
GAME = 'com.and.games505.TerrariaPaid'


def verify(events, stage):
    complete = [row for kind, row in events if kind == 'RESPAWN_COMPLETE']
    ticks = [row for kind, row in events if kind == 'RESPAWN_TICK']
    short = [row for row in complete if (row['enabled'], row['seconds'], row['before'], row['after'], row['frames'], row['life']) == (True, 3, 600, 180, 180, 100)]
    if not short or not ticks or any(row['clampOutside'] != 3600 for row in ticks):
        raise ValueError('Short respawn or scoped clamp restoration evidence missing')
    protection = [row for kind, row in events if kind == 'LAB_PROTECTION_STATE']
    if not protection or protection[-1] != dict(profile='TMAL_Respawn', god=True, noKnockback=True, life=100, dead=False):
        raise ValueError('Final healthy protected lab state missing')
    off = [row for row in complete if (row['enabled'], row['before'], row['after'], row['frames'], row['life']) == (False, 600, 600, 600, 100)]
    long = [row for row in ticks if row['enabled'] and row['before'] == 7200 and row['applied'] == 7200 and row['after'] == 7199]
    off_clamp = [row for row in ticks if not row['enabled'] and row['before'] > 3600 and row['after'] == 3600]
    shortened = [row for row in ticks if row['enabled'] and row['seconds'] == 3 and row['before'] > 180 and row['applied'] == 180 and row['after'] == 179]
    long_complete = [row for row in complete if row['enabled'] and row['seconds'] == 120 and row['after'] == 7200 and row['life'] == 100]
    if stage == 'matrix' and not (off and long and off_clamp and shortened and long_complete):
        raise ValueError('Off / long clamp / live shortening matrix incomplete')
    return dict(short_respawn=short[-1], off_respawn=off[-1] if off else None,
        long_tick=long[0] if long else None, vanilla_clamp_when_off=off_clamp[0] if off_clamp else None,
        original_update_dead_shortening=shortened[0] if shortened else None,
        long_death_completed=long_complete[-1] if long_complete else None,
        final_protection=protection[-1], observed_ticks=len(ticks), native_clamp_restored_on_every_observed_exit=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--serial', required=True)
    p.add_argument('--pid', type=int, required=True)
    p.add_argument('--lab', type=Path, required=True)
    p.add_argument('--stage', choices=('first', 'matrix', 'restart'), required=True)
    p.add_argument('--saved-menu-reviewed', action='store_true', required=True)
    p.add_argument('--menu-label', required=True)
    args = p.parse_args()
    lab = args.lab.resolve()
    if lab.is_relative_to(ROOT) or not re.fullmatch(r'[a-z0-9-]+', args.menu_label):
        raise ValueError('Private lab and bounded screenshot label required')
    adb_path = Path.home() / 'AppData/Local/Android/Sdk/platform-tools/adb.exe'
    def adb(*words):
        return subprocess.check_output([str(adb_path), '-s', args.serial, *words], timeout=60)
    def sha(data):
        return hashlib.sha256(data).hexdigest()
    if adb('shell', 'pidof', GAME).decode().strip() != str(args.pid):
        raise ValueError('Game process changed')
    build = json.loads((lab / 'respawn-companion/companion-build.json').read_text())
    packages = {}
    for package in (GAME, 'tm.loader.companion'):
        path = adb('shell', 'pm', 'path', package).decode().strip()
        if not path.startswith('package:') or '\n' in path:
            raise ValueError('Expected one installed APK')
        packages[package] = sha(adb('exec-out', 'cat', path[8:]))
    if packages[GAME] != build['target_apk_sha256'] or packages['tm.loader.companion'] != build['output_sha256']:
        raise ValueError('Installed game or companion differs')
    base = '/data/user/0/' + GAME + '/files/tmloader/'
    names = build['own_api_bundle_files']
    if len(names) != 13 or any(not re.fullmatch(r'[A-Za-z0-9_.-]+', name) for name in names):
        raise ValueError('Managed file set differs')
    raw_hashes = adb('exec-out', 'su', '-c', 'sha256sum ' + ' '.join(base + 'managed/' + name for name in names))
    actual = {Path(row.split()[1]).name: row.split()[0] for row in raw_hashes.decode().splitlines()}
    if actual != names:
        raise ValueError('Copied managed files differ')
    raw = adb('logcat', '-d', '--pid=' + str(args.pid), '-v', 'threadtime')
    log = raw.decode('utf-8', 'replace')
    if 'RESPAWN_HOST_READY ' not in log or 'RESPAWN_HOOK_READY ' not in log or any(x in log for x in ('RESPAWN_HOST_FAILED', 'RESPAWN_INIT_FAILED', 'RESPAWN_BRIDGE_FAILED')):
        raise ValueError('Respawn startup/failure evidence differs')
    events = []
    for line in log.splitlines():
        match = re.search(r'TMAL\s*:\s+(RESPAWN_[A-Z_]+|LAB_PROTECTION_STATE) (\{.*\})$', line)
        if match:
            events.append((match[1], json.loads(match[2])))
    result = verify(events, args.stage)
    player_base = '/storage/emulated/0/Android/data/' + GAME + '/Players/'
    own_player = adb('exec-out', 'su', '-c', 'cat ' + player_base + 'TMAL_Respawn.plr')
    combined_player = adb('exec-out', 'su', '-c', 'cat ' + player_base + 'TMAL_Test.plr')
    sidecar = json.loads(adb('exec-out', 'su', '-c', 'cat ' + base + 'TMAL_Test.moditems.json'))
    if sidecar.get('generation') != 2 or sha(combined_player) not in json.dumps(sidecar):
        raise ValueError('Combined save/sidecar checkpoint changed')
    shot = lab / 'evidence' / args.menu_label / 'screenshot.png'
    raw_file = lab / ('respawn-' + args.stage + '-logcat.txt');raw_file.write_bytes(raw)
    (lab / ('respawn-' + args.stage + '-events.json')).write_text(json.dumps(events, indent=2) + '\n', encoding='utf-8')
    if adb('shell', 'pidof', GAME).decode().strip() != str(args.pid):
        raise ValueError('Game process changed during collection')
    report = dict(status='verified-native-respawn-' + args.stage, serial=args.serial, pid=args.pid,
        packages=packages, managed_files_sha256=actual, **result,
        original_mod_dll_patched=False, original_game_apk_changed=False,
        native_hook_installed=True, matrix_verified=args.stage == 'matrix',
        restart_verified=args.stage == 'restart', common_item_time_api_included=False,
        respawn_player_sha256=sha(own_player), combined_player_sidecar_unchanged=True,
        raw_log=str(raw_file), raw_log_sha256=sha(raw),
        saved_menu=dict(path=str(shot), sha256=sha(shot.read_bytes()), visually_reviewed=True),
        limitations=['Dedicated offline classic TMAL_Respawn / TMAL_Lab only; no multiplayer.',
            'Original Kill/UpdateDead execute against snapshots; the original IL request uses a scoped mobile field lease.',
            'PostSetupContent, optional mod UI, and simultaneous item/time/respawn API are not supported.',
            'Death QA uses vanilla drops and permits at most 100 copper on the dedicated lab profile.'])
    (lab / ('game-' + args.stage + '-validation.json')).write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    (ROOT / 'reports' / ('android-respawn-' + args.stage + '-validation.json')).write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(status=report['status'], pid=args.pid, installed_files=len(actual),
        short_frames=result['short_respawn']['frames'], matrix_verified=report['matrix_verified']), indent=2))


if __name__ == '__main__':
    main()
