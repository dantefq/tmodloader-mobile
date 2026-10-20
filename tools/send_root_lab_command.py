"""Queue one bounded test command in the rooted Terraria lab; runtime guards still apply."""
import argparse
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--adb', type=Path, default=Path.home()/'AppData/Local/Android/Sdk/platform-tools/adb.exe')
    parser.add_argument('action', choices=('prepare-blade', 'persist-blade', 'test-blade', 'use-bed', 'respawn-die'))
    args = parser.parse_args()
    prefix = [str(args.adb), '-s', args.serial]

    def adb(*words):
        result = subprocess.run(prefix+list(words), capture_output=True, text=True, timeout=25)
        if result.returncode:
            raise RuntimeError(result.stdout+result.stderr)
        return result.stdout.strip()

    def root(command):
        return adb('shell', 'su', '-c', shlex.quote(command))

    if adb('get-state') != 'device' or root('id -u') != '0':
        raise RuntimeError('Authorized rooted device required')
    nonce = str(uuid.uuid4())
    filename = 'respawn-command.json' if args.action == 'respawn-die' else 'sleep-command.json' if args.action == 'use-bed' else 'content-command.json'
    base = '/data/user/0/com.and.games505.TerrariaPaid/files/tmloader/'
    owner = root('stat -c %u /data/user/0/com.and.games505.TerrariaPaid')
    if not owner.isdigit() or int(owner) < 10000:
        raise RuntimeError('Unexpected game UID')
    payload = {'action': args.action, 'nonce': nonce}
    remote = '/data/local/tmp/tmal-command-'+nonce+'.json'
    with tempfile.TemporaryDirectory(prefix='tmal-command-') as temp:
        local = Path(temp)/'command.json'
        local.write_text(json.dumps(payload), encoding='utf-8')
        adb('push', str(local), remote)
        try:
            target = base+filename
            pending = target+'.'+nonce+'.tmp'
            root('cp '+remote+' '+pending+' && chown '+owner+':'+owner+' '+pending+
                 ' && chmod 600 '+pending+' && restorecon '+pending+' && mv '+pending+' '+target)
            if json.loads(root('cat '+target)) != payload:
                raise RuntimeError('Command readback differs')
        finally:
            root('rm -f '+remote)
    print(json.dumps({'status': 'queued-not-yet-executed', **payload}))


if __name__ == '__main__':
    main()
