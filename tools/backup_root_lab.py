"""Read a private rooted lab backup after visually checking the saved main menu."""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'com.and.games505.TerrariaPaid'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--serial', required=True)
    p.add_argument('--lab', type=Path, required=True)
    p.add_argument('--saved-menu-reviewed', action='store_true', required=True)
    args = p.parse_args()
    lab = args.lab.resolve()
    if lab.is_relative_to(ROOT):
        raise ValueError('Keep saves and binaries private')
    lab.mkdir(parents=True, exist_ok=True)
    output = lab / 'before-respawn-companion.tar'
    if output.exists():
        raise ValueError('Preserve the existing backup; use a new private lab directory')
    adb = Path.home() / 'AppData/Local/Android/Sdk/platform-tools/adb.exe'
    def call(*words):
        return subprocess.check_output([str(adb), '-s', args.serial, *words], timeout=60)
    if call('exec-out', 'su', '-c', 'id -u').strip() != b'0':
        raise ValueError('Authorized root lab required')
    base = '/storage/emulated/0/Android/data/' + PACKAGE
    private = '/data/user/0/' + PACKAGE + '/files/tmloader'
    # Relative members avoid toybox's leading-slash warning being multiplexed
    # into adb exec-out's binary stdout stream.
    raw = call('exec-out', 'su', '-c', 'tar -C / -cf - ' + base[1:] + '/Players ' + base[1:] + '/Worlds ' + private[1:])
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        members = archive.getmembers()
        for member in members:
            name = PurePosixPath(member.name)
            if name.is_absolute() or '..' in name.parts or not (member.isfile() or member.isdir()):
                raise ValueError('Unexpected tar entry')
        files = {member.name: member for member in members if member.isfile()}
        def read(suffix):
            selected = [member for name, member in files.items() if name.endswith(suffix)]
            if len(selected) != 1:
                raise ValueError('Missing or duplicate backup entry: ' + suffix)
            return archive.extractfile(selected[0]).read()
        player_hash = hashlib.sha256(read('/Players/TMAL_Test.plr')).hexdigest()
        sidecar = json.loads(read('/tmloader/TMAL_Test.moditems.json'))
        if sidecar.get('generation') != 2 or player_hash not in json.dumps(sidecar):
            raise ValueError('Combined player/sidecar backup pair differs')
        read('/Worlds/TMAL_Lab.wld')
        total_bytes = sum(member.size for member in files.values())
    # Never extract the archive onto the host or device.
    output.write_bytes(raw)
    report = dict(status='verified-private-root-lab-backup', serial=args.serial,
        backup=str(output), sha256=hashlib.sha256(raw).hexdigest(), files=len(files),
        expanded_file_bytes=total_bytes, includes_players_worlds_and_private_loader=True,
        combined_generation=2, combined_player_sha256=player_hash,
        combined_player_sidecar_hash_matched=True, saved_menu_visually_reviewed=True)
    (lab / 'backup-report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    (ROOT / 'reports/android-before-respawn-backup.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
