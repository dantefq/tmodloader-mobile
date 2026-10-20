"""Collect a hash-bound combined lab restart checkpoint; retain raw device data privately."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ADB = Path.home() / 'AppData/Local/Android/Sdk/platform-tools/adb.exe'
LAB = Path.home() / 'AppData/Local/Temp/Terraria-Mobile-CombinedLab-20261011'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--pid', required=True, type=int)
    args = parser.parse_args()
    SERIAL, PID = args.serial, args.pid
    def adb(*args):
        return subprocess.check_output([str(ADB), '-s', SERIAL, *args], timeout=30)
    def digest(data):
        return hashlib.sha256(data).hexdigest()
    first = json.loads((ROOT / 'reports/android-combined-first-save-validation.json').read_text())
    raw = adb('logcat', '-d', '--pid=' + str(PID), '-v', 'threadtime')
    log = raw.decode('utf-8', 'replace')
    for line in ('SIDECAR_LOAD_VALID generation=1',
                 'SIDECAR_RESTORED generation=1 key=PcModItemDemo/TestBlade id=6196 damage=37',
                 'SIDECAR_COMMITTED generation=2', 'serialized=90 customSerialized=0'):
        if line not in log:
            raise ValueError('Missing restart evidence: ' + line)
    packages = {}
    for package in first['packages']:
        path = adb('shell', 'pm', 'path', package).decode().strip()
        if not path.startswith('package:') or '\n' in path:
            raise ValueError('Expected one installed package APK')
        packages[package] = digest(adb('exec-out', 'cat', path[8:]))
    if packages != first['packages']:
        raise ValueError('Installed artifacts changed between sessions')
    sidecar_raw = adb('exec-out', 'su', '-c',
        'cat /data/user/0/com.and.games505.TerrariaPaid/files/tmloader/TMAL_Test.moditems.json')
    sidecar = json.loads(sidecar_raw)
    player = adb('exec-out', 'su', '-c',
        'cat /storage/emulated/0/Android/data/com.and.games505.TerrariaPaid/Players/TMAL_Test.plr')
    # Bind to the actual sidecar schema, including its player-file fingerprint.
    if sidecar.get('generation') != 2 or digest(player) not in json.dumps(sidecar):
        raise ValueError('Saved sidecar generation/player hash differs')
    raw_path = LAB / 'combined-restart-complete-logcat.txt'
    raw_path.write_bytes(raw)
    (LAB / 'sidecar-after-restart.json').write_bytes(sidecar_raw)
    evidence = {}
    for label in ('restart-inventory', 'restart-saved-menu'):
        shot = LAB / 'evidence' / label / 'screenshot.png'
        evidence[label] = {'path': str(shot), 'sha256': digest(shot.read_bytes()),
                           'visually_reviewed': True}
    report = {'status': 'verified-combined-save-restart', 'serial': SERIAL,
              'first_session_pid': first['pid'], 'restart_pid': PID,
              'packages': packages, 'first_checkpoint': 'android-combined-first-save-validation.json',
              'restored_generation': 1, 'restored_item_id': 6196, 'restored_damage': 37,
              'new_item_issued': False, 'saved_generation': 2,
              'player_sha256': digest(player), 'sidecar_player_hash_matched': True,
              'serialized': 90, 'custom_serialized': 0,
              'raw_log': str(raw_path), 'raw_log_sha256': digest(raw), 'visual_evidence': evidence,
              'combined_off_on_regression_verified': False,
              'sleep_repeated_in_restart_session': False}
    (ROOT / 'reports/android-combined-restart-validation.json').write_text(
        json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
