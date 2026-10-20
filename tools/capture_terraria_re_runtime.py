"""Bounded capture from the disposable Terraria RE emulator only."""
import argparse, hashlib, json, subprocess
from pathlib import Path
from datetime import datetime, timezone
p=argparse.ArgumentParser();p.add_argument('label');a=p.parse_args()
assert a.label.replace('-','').replace('_','').isalnum()
lab=Path('C:/Temp/terraria-re-20261012');out=lab/'runtime-evidence'/a.label
out.mkdir(parents=True,exist_ok=False)
adb=Path.home()/'AppData/Local/Android/Sdk/platform-tools/adb.exe'
prefix=[str(adb),'-s','emulator-5580']
def call(name,args,binary=False,timeout=20):
    r=subprocess.run(prefix+args,capture_output=True,timeout=timeout)
    (out/name).write_bytes(r.stdout)
    if r.stderr:(out/(name+'.stderr')).write_bytes(r.stderr)
    return r
pid=call('pid.txt',['shell','pidof','com.and.games505.TerrariaPaid']).stdout.decode().strip()
call('window.txt',['shell','dumpsys','window','windows'])
shot=call('screen.png',['exec-out','screencap','-p'],True)
assert shot.returncode==0 and shot.stdout.startswith(b'\x89PNG\r\n\x1a\n')
call('ui.xml',['exec-out','uiautomator','dump','/dev/tty'])
call('crash.txt',['logcat','-d','-b','crash'])
if pid.isdigit():call('app-logcat.txt',['logcat','-d','--pid',pid])
call('airplane.txt',['shell','settings','get','global','airplane_mode_on'])
call('routes.txt',['shell','ip','route'])
record={'captured_utc':datetime.now(timezone.utc).isoformat(),'serial':'emulator-5580',
        'package':'com.and.games505.TerrariaPaid','pid_at_capture':pid,
        'files':{f.name:{'bytes':f.stat().st_size,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()} for f in out.iterdir() if f.is_file()}}
(out/'capture.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps({'out':str(out),'pid':pid,'files':len(record['files'])}))
