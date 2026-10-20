"""Start the installed Android Terraria companion through authorized USB ADB."""
import argparse
import json
from pathlib import Path
import shlex
import subprocess
import time

PACKAGE = 'com.and.games505.TerrariaPaid'
COMPONENT = 'tm.loader.companion/tm.loader.companion.ModInstrumentation'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--serial', required=True)
    p.add_argument('--adb', type=Path, default=Path.home()/'AppData/Local/Android/Sdk/platform-tools/adb.exe')
    p.add_argument('--mod', type=Path)
    p.add_argument('--managed-demo',action='store_true',help='Opt in to the own C# test DLL in the managed companion')
    p.add_argument('--saved-and-exited', action='store_true', help='Confirm the world is saved and at the main menu before restart')
    args = p.parse_args()
    prefix = [str(args.adb), '-s', args.serial]
    def adb(*words, required=True):
        result = subprocess.run(prefix+list(words), capture_output=True, encoding='utf-8', errors='replace', timeout=25)
        if required and result.returncode: raise RuntimeError(result.stdout+result.stderr)
        return result.stdout.strip()
    if adb('get-state') != 'device': raise RuntimeError('Selected device is not authorized')
    abis=adb('shell','getprop','ro.product.cpu.abilist').split(',')
    if not abis or abis[0]!='arm64-v8a':
        raise RuntimeError('This loader requires native ARM64. ARM translation on an x86 emulator cannot run the tested Gadget build; no game restart was performed.')
    if adb('shell', 'pidof', PACKAGE, required=False) and not args.saved_and_exited:
        raise RuntimeError('Save and exit the world first, then pass --saved-and-exited. Instrumentation restarts the game.')
    words = ['am', 'instrument', '--user', '0']
    if args.managed_demo: words += ['-e','managed_demo','true']
    if args.mod:
        if args.mod.suffix.lower() != '.json': raise ValueError('Only mobile JSON mods are supported; PC .tmod cannot run here')
        if args.mod.stat().st_size > 65536: raise ValueError('Mod exceeds 64 KiB')
        mod = json.loads(args.mod.read_text(encoding='utf-8-sig'))
        if not isinstance(mod, dict) or mod.get('format') != 'terraria-mobile-json-v1': raise ValueError('Expected terraria-mobile-json-v1')
        text = json.dumps(mod, ensure_ascii=True, separators=(',', ':'))
        if len(text) > 20000: raise ValueError('USB importer accepts up to 20000 serialized characters; split into smaller mods')
        words += ['-e', 'mobile_json', text]
    words.append(COMPONENT)
    # ADB invokes Android's shell. Quote tokens as POSIX shell data, never code.
    print(adb('shell', ' '.join(shlex.quote(word) for word in words)))
    deadline = time.monotonic()+18
    while time.monotonic() < deadline:
        pid = adb('shell', 'pidof', PACKAGE, required=False)
        if pid.isdigit():
            log = adb('logcat', '-d', '--pid='+pid, '-t', '1000')
            if 'Instrumentation initialization failed' in log: raise RuntimeError('Mod rejected by Android validator; inspect TMAL log')
            if 'Instrumentation registry ready' in log and 'Original Application.onCreate returned' in log: break
        time.sleep(0.4)
    else: raise RuntimeError('Instrumentation did not become ready; inspect TMAL log')
    print(adb('shell', 'am', 'start', '-W', '-n', PACKAGE+'/com.unity3d.player.UnityPlayerActivity'))
    print('Android Terraria started. Open Mobile Mods; use single-player. Reload character after changing mods.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error))
