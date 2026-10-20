"""Read-only Android evidence capture; never installs, launches, or clears logs."""
import argparse
import datetime
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', type=Path, default=Path.home()/'AppData/Local/Android/Sdk/platform-tools/adb.exe')
    parser.add_argument('--serial')
    parser.add_argument('--seconds', type=int, default=45)
    parser.add_argument('--lab', type=Path, default=Path.home()/'AppData/Local/Temp/Terraria-Mobile-ModLab-20261008')
    args = parser.parse_args()
    if not 1 <= args.seconds <= 60: parser.error('--seconds must be 1–60')
    def call(command):
        result = subprocess.run([str(args.adb),*command],capture_output=True,timeout=15)
        if result.returncode: raise RuntimeError(result.stderr.decode('utf-8','replace'))
        return result.stdout
    devices = call(['devices','-l']).decode('utf-8','replace')
    ready=[line.split()[0] for line in devices.splitlines()[1:] if len(line.split())>1 and line.split()[1]=='device']
    if not ready: raise RuntimeError('No authorized device. Connect USB and confirm Android RSA prompt.')
    if args.serial:
        if args.serial not in ready: raise RuntimeError('Selected serial is not an authorized connected device')
        serial=args.serial
    else:
        if len(ready)!=1: raise RuntimeError('Multiple devices. Select --serial explicitly.')
        serial=ready[0]
    prefix=['-s',serial]
    try:
        pids=call(prefix+['shell','pidof','com.and.games505.TerrariaPaid']).decode().split()
    except RuntimeError as error:
        raise RuntimeError('Launch Terraria manually before capture; game process is not running.') from error
    if len(pids)!=1 or not pids[0].isdigit(): raise RuntimeError('Expected exactly one running game process')
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    evidence=args.lab.resolve()/'evidence'/stamp
    if evidence.is_relative_to(ROOT): raise ValueError('Raw device evidence must remain outside repository')
    evidence.mkdir(parents=True,exist_ok=True)
    report={'device_serial':serial,'capture_utc':stamp,'seconds':args.seconds,
            'model':call(prefix+['shell','getprop','ro.product.model']).decode().strip(),
            'android':call(prefix+['shell','getprop','ro.build.version.release']).decode().strip(),
            'package_path':call(prefix+['shell','pm','path','com.and.games505.TerrariaPaid']).decode().strip(),
            'in_game_verified':False}
    report['game_pid']=int(pids[0])
    with (evidence/'logcat.txt').open('wb') as stream:
        child=subprocess.Popen([str(args.adb),*prefix,'logcat','--pid='+pids[0],'-T','1','-v','threadtime'],stdout=stream,stderr=subprocess.PIPE)
        try:
            print('Capturing game logs. Inspect the demo sword in Terraria.',flush=True)
            time.sleep(args.seconds)
        finally:
            child.terminate()
            try: child.wait(timeout=5)
            except subprocess.TimeoutExpired: child.kill(); child.wait(timeout=5)
    focus=call(prefix+['shell','dumpsys','window']).decode('utf-8','replace')
    foreground=any('com.and.games505.TerrariaPaid' in line for line in focus.splitlines() if 'mCurrentFocus=' in line)
    report['screenshot_captured']=foreground
    if foreground: (evidence/'screenshot.png').write_bytes(call(prefix+['exec-out','screencap','-p']))
    logs=(evidence/'logcat.txt').read_text(encoding='utf-8',errors='replace')
    matched=[line for line in logs.splitlines() if 'TMAL' in line]
    report.update({'tmloader_log_lines':matched,'evidence_directory':str(evidence),
                   'hook_ready_seen':any('HOOK_READY' in line for line in matched),
                   'demo_applied_seen':any('Applied copper-sword-demo' in line for line in matched)})
    # Evidence flags never automatically promote the result to an in-game verified mod.
    (ROOT/'reports').mkdir(exist_ok=True)
    report_path=ROOT/'reports'/('device-'+stamp+'.json')
    report_path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(report_path)


if __name__=='__main__': main()
