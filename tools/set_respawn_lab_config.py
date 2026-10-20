"""Atomically update bounded respawn settings in the authorized root lab."""
import argparse
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import uuid


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--serial', required=True)
    p.add_argument('--seconds', type=int)
    p.add_argument('--adjust', choices=('true', 'false'))
    p.add_argument('--enabled', choices=('true', 'false'))
    args = p.parse_args()
    if args.seconds is not None and not 0 <= args.seconds <= 3600:
        p.error('Seconds must be between zero and 3600')
    if args.seconds is None and args.adjust is None and args.enabled is None:
        p.error('Supply at least one setting')
    adb_path = Path.home() / 'AppData/Local/Android/Sdk/platform-tools/adb.exe'
    def adb(*words):
        return subprocess.check_output([str(adb_path), '-s', args.serial, *words], timeout=30).decode().strip()
    def root(command):
        return adb('shell', 'su', '-c', shlex.quote(command))
    if root('id -u') != '0':
        raise ValueError('Authorized root lab required')
    base = '/data/user/0/com.and.games505.TerrariaPaid/files/tmloader/'
    owner = root('stat -c %u /data/user/0/com.and.games505.TerrariaPaid')
    if not owner.isdigit() or int(owner) < 10000:
        raise ValueError('Game UID differs')
    current = json.loads(root('cat ' + base + 'respawn-config.json'))
    current = dict(seconds=current['seconds'], adjust=current['adjust'])
    if args.seconds is not None:
        current['seconds'] = args.seconds
    if args.adjust is not None:
        current['adjust'] = args.adjust == 'true'
    if type(current['seconds']) is not int or not 0 <= current['seconds'] <= 3600 or type(current['adjust']) is not bool:
        raise ValueError('Config outside bounds')
    writes = {'respawn-config.json': current}
    if args.enabled is not None:
        writes['managed-enabled.json'] = {'enabled': args.enabled == 'true'}
    for filename, payload in writes.items():
        nonce = str(uuid.uuid4());remote = '/data/local/tmp/tmal-config-' + nonce + '.json'
        with tempfile.TemporaryDirectory(prefix='tmal-respawn-') as temp:
            local = Path(temp) / 'config.json';local.write_text(json.dumps(payload), encoding='utf-8')
            adb('push', str(local), remote)
            try:
                target = base + filename;pending = target + '.' + nonce + '.tmp'
                root('cp ' + remote + ' ' + pending + ' && chown ' + owner + ':' + owner + ' ' + pending +
                    ' && chmod 600 ' + pending + ' && restorecon ' + pending + ' && mv ' + pending + ' ' + target)
                if json.loads(root('cat ' + target)) != payload:
                    raise ValueError('Config readback differs')
            finally:
                root('rm -f ' + remote)
    print(json.dumps(dict(status='written-runtime-application-not-yet-verified', writes=writes)))


if __name__ == '__main__':
    main()
