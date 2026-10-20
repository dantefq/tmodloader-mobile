"""Short, foreground-guarded ADB actions limited to the Terraria lab app."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import struct
import time
from xml.etree import ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
PACKAGE='com.and.games505.TerrariaPaid'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial',required=True)
    parser.add_argument('--package',choices=(PACKAGE,'tm.loader.companion','tm.loader.managedprobe'),default=PACKAGE)
    parser.add_argument('--adb',type=Path,default=Path.home()/'AppData/Local/Android/Sdk/platform-tools/adb.exe')
    parser.add_argument('--lab',type=Path,default=Path.home()/'AppData/Local/Temp/Terraria-Mobile-ModLab-20261008')
    sub=parser.add_subparsers(dest='action',required=True)
    shot=sub.add_parser('snapshot');shot.add_argument('label');shot.add_argument('--hold',nargs=2,type=int)
    tap=sub.add_parser('tap');tap.add_argument('x',type=int);tap.add_argument('y',type=int)
    ui=sub.add_parser('ui-tap');ui.add_argument('label',help='Exact text of a native button or checkbox in the lab app')
    text=sub.add_parser('text');text.add_argument('value');text.add_argument('--replace',action='store_true')
    key=sub.add_parser('key');key.add_argument('code',type=int)
    args=parser.parse_args()
    prefix=[str(args.adb),'-s',args.serial]
    def call(*command):
        result=subprocess.run(prefix+list(command),capture_output=True,timeout=20)
        if result.returncode: raise RuntimeError(result.stderr.decode('utf-8','replace'))
        return result.stdout
    window=call('shell','dumpsys','window').decode('utf8','replace')
    focused=any(args.package+'/' in line for line in window.splitlines() if 'mCurrentFocus=' in line)
    immersive=any('ImmersiveModeConfirmation' in line for line in window.splitlines() if 'mCurrentFocus=' in line) and any(args.package+'/' in line for line in window.splitlines() if 'mFocusedApp=' in line)
    if not focused and not immersive:
        raise RuntimeError('Selected lab app is not foreground; no screenshot or input was performed')
    screen=call('exec-out','screencap','-p')
    if screen[:8]!=b'\x89PNG\r\n\x1a\n': raise ValueError('Expected Android PNG screenshot')
    width,height=struct.unpack('>II',screen[16:24])
    if args.action=='tap':
        if not 0<=args.x<width or not 0<=args.y<height: raise ValueError('Coordinates outside selected app bounds')
        call('shell','input','tap',str(args.x),str(args.y))
    elif args.action=='ui-tap':
        if immersive: raise RuntimeError('Dismiss immersive confirmation before selecting native controls')
        raw=call('exec-out','uiautomator','dump','/dev/tty').decode('utf8','replace')
        start,end=raw.find('<?xml'),raw.rfind('</hierarchy>')
        if start<0 or end<0: raise ValueError('UI hierarchy unavailable')
        tree=ET.fromstring(raw[start:end+12])
        matches=[n for n in tree.iter('node') if n.get('package')==args.package and
                 n.get('text')==args.label and n.get('enabled')=='true' and
                 ((n.get('class')=='android.widget.Button' and n.get('clickable')=='true') or
                  (n.get('class')=='android.widget.CheckedTextView' and n.get('checkable')=='true'))]
        if len(matches)!=1: raise ValueError('Native target must have exactly one enabled clickable match')
        bounds=list(map(int,re.findall(r'\d+',matches[0].get('bounds',''))))
        if len(bounds)!=4 or not (0<=bounds[0]<bounds[2]<=width and 0<=bounds[1]<bounds[3]<=height):
            raise ValueError('Native target outside app bounds')
        call('shell','input','tap',str((bounds[0]+bounds[2])//2),str((bounds[1]+bounds[3])//2))
        print(json.dumps({'native_control':args.label,'bounds':bounds}))
    elif args.action=='text':
        if immersive: raise RuntimeError('Dismiss the immersive confirmation before typing')
        if not re.fullmatch('[A-Za-z0-9_]{1,40}',args.value): raise ValueError('Only bounded alphanumeric test names are allowed')
        if args.replace:
            # Use only after observing the caret at the end of a lab name field.
            call('shell','input','keyevent',*(['67']*64))
        call('shell','input','text',args.value)
    elif args.action=='key':
        if immersive: raise RuntimeError('Dismiss the immersive confirmation before sending keys')
        if args.code not in (4,66,67): raise ValueError('Only Back, Enter, Delete keys are allowed')
        call('shell','input','keyevent',str(args.code))
    else:
        if not re.fullmatch('[a-z0-9-]{1,48}',args.label): raise ValueError('Invalid evidence label')
        folder=args.lab.resolve()/'evidence'/args.label
        if folder.is_relative_to(ROOT): raise ValueError('Keep raw game evidence outside source repository')
        folder.mkdir(parents=True,exist_ok=True)
        held = None
        try:
            if args.hold:
                x,y=args.hold
                if not 0<=x<width or not 0<=y<height: raise ValueError('Coordinates outside selected Android app bounds')
                held=subprocess.Popen(prefix+['shell','input','swipe',str(x),str(y),str(x),str(y),'1500'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                time.sleep(0.5)
            folder.joinpath('screenshot.png').write_bytes(call('exec-out','screencap','-p'))
        finally:
            if held is not None:
                # The bounded swipe releases the touch by itself; always reap ADB.
                held.communicate(timeout=10)
        pid=call('shell','pidof',args.package).decode().strip()
        if not pid.isdigit(): raise ValueError('Expected one running game PID')
        log=call('logcat','-d','--pid='+pid,'-t','3000','-v','threadtime')
        folder.joinpath('logcat.txt').write_bytes(log)
        lines=[line for line in log.decode('utf8','replace').splitlines() if 'TMAL' in line]
        print(json.dumps({'pid':int(pid),'screenshot':str(folder/'screenshot.png'),'tmloader':lines},ensure_ascii=False,indent=2))


if __name__=='__main__': main()
