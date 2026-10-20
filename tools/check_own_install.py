"""Accept Play Protect's per-app scan only for our companion installation."""
import argparse
import re
import subprocess
from pathlib import Path
from xml.etree import ElementTree as ET

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--serial',required=True)
    p.add_argument('--adb',type=Path,default=Path.home()/'AppData/Local/Android/Sdk/platform-tools/adb.exe')
    args=p.parse_args()
    def adb(*words):
        r=subprocess.run([str(args.adb),'-s',args.serial,*words],capture_output=True,timeout=20)
        if r.returncode: raise RuntimeError(r.stderr.decode('utf-8','replace'))
        return r.stdout.decode('utf-8','replace')
    def nodes():
        window=adb('shell','dumpsys','window')
        if not any('com.android.vending/' in line and 'PlayProtect' in line for line in window.splitlines() if 'mCurrentFocus=' in line):
            raise ValueError('Own install scan is not foreground')
        adb('shell','uiautomator','dump','/data/local/tmp/tmal-install-ui.xml')
        tree=ET.fromstring(adb('shell','cat','/data/local/tmp/tmal-install-ui.xml'))
        if not any(n.get('text')=='Terraria Mobile Mods' for n in tree.iter('node')):
            raise ValueError('Scan is not for our companion')
        return list(tree.iter('node'))
    rows=nodes()
    if not any(n.get('text')=='Проверить это приложение' for n in rows):
        adb('shell','input','swipe','1600','960','1600','360','350');rows=nodes()
    choices=[n for n in rows if n.get('text')=='Проверить это приложение']
    if len(choices)!=1: raise ValueError('Per-app scan choice is not unique')
    bounds=list(map(int,re.findall(r'\d+',choices[0].get('bounds',''))))
    if len(bounds)!=4 or not 0<=bounds[1]<bounds[3]<=1080: raise ValueError('Per-app choice not visible')
    adb('shell','input','tap',str((bounds[0]+bounds[2])//2),str((bounds[1]+bounds[3])//2))
    print('Requested scan of own companion only; global Play Protect preferences unchanged.')

if __name__=='__main__':main()
