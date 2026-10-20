"""Bounded QA of the owned TerrariaRE AVD; screenshot-based taps explicitly user-authorized."""
import argparse, datetime, hashlib, json, pathlib, shlex, subprocess, time

LAB=pathlib.Path('C:/Temp/terraria-re-20261012')
OUT=LAB/'runtime-world-20261014'
ADB=pathlib.Path.home()/'AppData/Local/Android/Sdk/platform-tools/adb.exe'
PACKAGE='com.and.games505.TerrariaPaid'


def command(args,timeout=20):
    result=subprocess.run([str(ADB),'-s','emulator-5580']+args,capture_output=True,timeout=timeout)
    event={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'args':args,'returncode':result.returncode}
    with (OUT/'commands.jsonl').open('a',encoding='utf8') as f:f.write(json.dumps(event)+'\n')
    if result.returncode:raise RuntimeError(result.stderr.decode(errors='replace'))
    return result.stdout


def main():
    ap=argparse.ArgumentParser();ap.add_argument('action',choices=['launch','restart','capture','key','gamepad','text','clear-text','tap','swipe','files','stop']);ap.add_argument('value',nargs='?');a=ap.parse_args()
    launch=json.loads((OUT/'launch.json').read_text(encoding='utf-8-sig'))
    if launch['avd']!='TerrariaRE' or launch['personal_avd_used'] is not False:raise ValueError('Disposable AVD marker missing')
    if 'TerrariaRE' not in command(['emu','avd','name']).decode():raise ValueError('Wrong AVD serial')
    if command(['shell','getprop','sys.boot_completed']).strip()!=b'1':raise ValueError('AVD not booted')
    if a.action=='launch':
        command(['shell','cmd','connectivity','airplane-mode','enable']);command(['shell','svc','wifi','disable']);command(['shell','svc','data','disable'])
        routes=command(['shell','ip','route']);(OUT/'prelaunch-routes.txt').write_bytes(routes)
        if routes.strip():raise ValueError('Expected no network routes')
        package=command(['shell','pm','path',PACKAGE]).decode().strip()
        if not package.startswith('package:') or '\n' in package:raise ValueError('Expected one installed APK')
        digest=command(['shell','sha256sum',package.removeprefix('package:')]).decode().split()[0]
        if digest!='1f8e2ba7ddabaee961a1b2552d44bc0c281c9b5122480642b018779bcbf2fe8e':raise ValueError('Installed APK changed')
        (OUT/'installed-apk-sha256.txt').write_text(digest+'\n');command(['logcat','-c'])
        result=command(['shell','am','start','-W','-n',PACKAGE+'/com.unity3d.player.UnityPlayerActivity'],40)
        (OUT/'app-start.txt').write_bytes(result);print(result.decode())
    elif a.action=='restart':
        command(['shell','am','force-stop',PACKAGE])
        result=command(['shell','am','start','-W','-n',PACKAGE+'/com.unity3d.player.UnityPlayerActivity'],40)
        (OUT/'app-restart.txt').write_bytes(result);print(result.decode())
    elif a.action=='capture':
        time.sleep(2)
        if not a.value or not a.value.replace('-','').isalnum():raise ValueError('Safe capture label required')
        dest=OUT/a.value;dest.mkdir(exist_ok=False)
        for name,args in [('screen.png',['exec-out','screencap','-p']),('ui.xml',['exec-out','uiautomator','dump','/dev/tty']),('pid.txt',['shell','pidof',PACKAGE]),('crash.txt',['logcat','-d','-b','crash'])]:
            data=command(args)
            if name=='screen.png' and not data.startswith(b'\x89PNG\r\n\x1a\n'):raise ValueError('Invalid PNG')
            (dest/name).write_bytes(data)
        pid=(dest/'pid.txt').read_text().strip()
        if pid.isdigit():(dest/'app-logcat.txt').write_bytes(command(['logcat','-d','--pid',pid]))
        (dest/'capture.json').write_text(json.dumps({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'files':{f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in dest.iterdir() if f.is_file()}},indent=2))
        print(dest)
    elif a.action=='key':
        if a.value not in ('KEYCODE_DPAD_UP','KEYCODE_DPAD_DOWN','KEYCODE_DPAD_LEFT','KEYCODE_DPAD_RIGHT','KEYCODE_DPAD_CENTER','KEYCODE_ENTER','KEYCODE_TAB','KEYCODE_BACK','KEYCODE_ESCAPE'):raise ValueError('Unsupported QA key')
        command(['shell','input','keyevent',a.value]);print(a.value)
    elif a.action=='gamepad':
        if a.value not in ('KEYCODE_BUTTON_A','KEYCODE_BUTTON_START','KEYCODE_DPAD_DOWN','KEYCODE_DPAD_UP'):raise ValueError('Unsupported QA gamepad key')
        command(['shell','input','gamepad','keyevent',a.value]);print(a.value)
    elif a.action=='files':
        if not a.value or not a.value.replace('-','').isalnum():raise ValueError('Safe snapshot label required')
        remote_root='/sdcard/Android/data/'+PACKAGE
        listing=command(['shell','find',remote_root,'-maxdepth','4','-type','f']).decode().splitlines()
        rows=[]
        for remote in listing:
            if not remote.startswith(remote_root+'/'):raise ValueError('Unexpected save path')
            if pathlib.PurePosixPath(remote).suffix.lower() not in ('.plr','.wld','.bak','.map'):continue
            digest=command(['shell','sha256sum',shlex.quote(remote)]).decode().split()[0]
            rows.append({'path':remote,'sha256':digest})
        (OUT/(a.value+'-files.json')).write_text(json.dumps({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'files':rows},indent=2)+'\n')
        print(json.dumps(rows))
    elif a.action=='swipe':
        if launch.get('screenshot_taps_user_authorized') is not True:raise ValueError('Screenshot input not authorized')
        x1,y1,x2,y2,duration=map(int,a.value.split(','))
        if not (0<=x1<1280 and 0<=x2<1280 and 0<=y1<720 and 0<=y2<720 and 1<=duration<=2000):raise ValueError('Invalid bounded swipe')
        command(['shell','input','swipe',str(x1),str(y1),str(x2),str(y2),str(duration)])
        print('bounded swipe completed')
    elif a.action=='tap':
        if launch.get('screenshot_taps_user_authorized') is not True:raise ValueError('Screenshot taps require recorded user authorization')
        x,y=map(int,a.value.split(','))
        if not 0<=x<1280 or not 0<=y<720:raise ValueError('Tap outside observed landscape frame')
        command(['shell','input','tap',str(x),str(y)]);print(f'tap {x},{y}')
    elif a.action=='clear-text':
        command(['shell','input','keyevent','KEYCODE_MOVE_END'])
        command(['shell','input','keyevent']+['KEYCODE_DEL']*48)
        print('Focused test-name field cleared')
    elif a.action=='text':
        if not a.value or not a.value.isalnum() or len(a.value)>24:raise ValueError('Only short test name allowed')
        command(['shell','input','text',a.value]);print('test name entered')
    else:
        command(['shell','am','force-stop',PACKAGE]);command(['emu','kill']);print('Disposable app/emulator stopped')


if __name__=='__main__':main()
