"""Collect read-only texture metadata from an explicit authorized native ARM64 target.

Requires a previously configured loopback Frida server/ADB forward. Does not
start/restart the game, install a server, create textures or change saves.
"""
import argparse
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'com.and.games505.TerrariaPaid'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--serial', required=True)
    p.add_argument('--lab', required=True, type=Path)
    p.add_argument('--expected-library-sha256', required=True)
    p.add_argument('--port', type=int, default=27043)
    p.add_argument('--adb', type=Path, default=Path.home() / 'AppData/Local/Android/Sdk/platform-tools/adb.exe')
    args = p.parse_args()
    lab = args.lab.resolve()
    if lab.is_relative_to(ROOT) or not re.fullmatch('[0-9a-f]{64}', args.expected_library_sha256) or not 1 <= args.port <= 65535:
        raise ValueError('Explicit private lab, SHA256 and loopback port required')
    lab.mkdir(parents=True, exist_ok=True)
    def adb(*words):
        result = subprocess.run([str(args.adb), '-s', args.serial, *words], capture_output=True, timeout=30)
        if result.returncode:
            (lab / 'adb-error.txt').write_bytes(result.stderr + result.stdout)
            raise RuntimeError('ADB command failed; details retained privately')
        return result.stdout.decode('utf-8', 'replace').strip()
    if adb('get-state') != 'device' or adb('shell', 'getprop', 'ro.product.cpu.abi') != 'arm64-v8a':
        raise RuntimeError('Authorized native ARM64 target required')
    pid = adb('shell', 'pidof', PACKAGE)
    if not pid.isdigit():
        raise RuntimeError('Expected one existing game process; no launch/restart performed')
    sys.path.insert(0, str(ROOT / '.tools/frida-deps'))
    import frida
    device = frida.get_device_manager().add_remote_device('127.0.0.1:' + str(args.port))
    session = device.attach(int(pid))
    script = None
    try:
        script = session.create_script((ROOT / 'runtime/texture-capabilities.js').read_text(encoding='utf-8'))
        script.load()
        info = script.exports_sync.moduleinfo()
        if info['architecture'] != 'arm64' or info['pointer_size'] != 8:
            raise RuntimeError('Attached process architecture differs')
        path = info['library_path']
        if not path.startswith('/') or not path.endswith('/libil2cpp.so') or '!' in path:
            raise RuntimeError('Direct library file identity unavailable; no metadata probe invoked')
        command = 'sha256sum ' + shlex.quote(path)
        digest = adb('shell', 'su', '-c', shlex.quote(command)).split()[0]
        if digest != args.expected_library_sha256:
            raise RuntimeError('Live library file hash differs; no metadata probe invoked')
        report = script.exports_sync.inspect()
        if adb('shell', 'pidof', PACKAGE) != pid:
            raise RuntimeError('Game process changed during inspection')
        if any(report[k] for k in ('game_methods_invoked', 'texture_created', 'hooks_installed', 'content_tables_changed', 'saves_accessed', 'gpu_upload_verified')):
            raise RuntimeError('Metadata-only scope differs')
        report.update(serial=args.serial, pid=int(pid), library_sha256=digest, library_path=path)
        (lab / 'texture-capabilities.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'status': 'metadata-collected', 'classes': len(report['classes']),
                          'game_methods_invoked': False, 'gpu_upload_verified': False}))
    finally:
        try:
            if script is not None:
                script.unload()
        finally:
            session.detach()


if __name__ == '__main__':
    main()
