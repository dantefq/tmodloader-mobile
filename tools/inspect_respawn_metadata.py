"""Read live Terraria IL2CPP method/field metadata through the authorized root lab server."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--serial', required=True)
    args = p.parse_args()
    adb = Path.home() / 'AppData/Local/Android/Sdk/platform-tools/adb.exe'
    package = 'com.and.games505.TerrariaPaid'
    def call(*words):
        return subprocess.check_output([str(adb), '-s', args.serial, *words], timeout=30)
    pid = call('shell', 'pidof', package).decode().strip()
    if not pid.isdigit():
        raise ValueError('Expected an already running game; this tool does not launch it')
    source = (ROOT / 'runtime/respawn-metadata.js').read_bytes()
    call('forward', 'tcp:27043', 'tcp:27042')
    sys.path.insert(0, str(ROOT / '.tools/frida-deps'))
    import frida
    session = frida.get_device_manager().add_remote_device('127.0.0.1:27043').attach(int(pid))
    try:
        script = session.create_script(source.decode())
        script.load()
        result = script.exports_sync.inspect()
        script.unload()
    finally:
        session.detach()
    result['script_sha256'] = hashlib.sha256(source).hexdigest()
    result['serial'] = args.serial
    result['native_respawn_hook_installed'] = False
    (ROOT / 'reports/android-respawn-method-metadata.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
