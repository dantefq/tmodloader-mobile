"""Record the current isolated Android probe result, with extracted DLL identity."""
import argparse
import json
from pathlib import Path
import subprocess
from apk_format import sha256

ROOT=Path(__file__).resolve().parents[1]

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--serial',required=True)
    p.add_argument('--lab',type=Path,required=True)
    p.add_argument('--adb',type=Path,default=Path.home()/'AppData/Local/Android/Sdk/platform-tools/adb.exe')
    p.add_argument('--mode',choices=('global-item','mod-item'),default='global-item')
    p.add_argument('--unified-api',action='store_true')
    p.add_argument('--date',help='Client-local verification date, YYYY-MM-DD')
    args=p.parse_args()
    def adb(*words):
        result=subprocess.run([str(args.adb),'-s',args.serial,*words],capture_output=True,timeout=25)
        if result.returncode: raise RuntimeError(result.stderr.decode('utf-8','replace'))
        return result.stdout.decode('utf-8').strip()
    pid=adb('shell','pidof','tm.loader.managedprobe')
    if not pid.isdigit(): raise ValueError('Probe is not alive')
    if args.unified_api and args.mode!='mod-item': raise ValueError('Unified probe currently supports the own ModItem demo only')
    stem='unified-moditem' if args.unified_api else 'moditem' if args.mode=='mod-item' else 'api'
    build=json.loads((ROOT/'reports'/f'{stem}-probe-build.json').read_text())
    bundle=json.loads((ROOT/'reports'/f'{stem}-demo-build.json').read_text())
    if sha256(Path(build['apk']))!=build['sha256']: raise ValueError('Probe APK changed')
    result=json.loads(adb('shell','run-as','tm.loader.managedprobe','cat','files/managed/result.json'))
    if args.unified_api and (result.get('api_revision')!='managed-foundation-v1' or result.get('foundationChecks')!=8):
        raise ValueError('Merged foundation checks did not execute')
    if result['mode']!=args.mode or result['handlers']!=1 or not result['own_tmod_executed'] or result['arbitrary_tmod_supported']:
        raise ValueError('Own GlobalItem probe did not execute')
    checks=[[c['id'],c['input'],c['actual']] for c in result['checks']]
    if checks!=bundle['contract']['checks'] or result['name']!=bundle['contract']['name'] or result['gcStressBytes']!=16777216:
        raise ValueError('Own GlobalItem results differ')
    identity='PcModItemDemo' if args.mode=='mod-item' else 'PcGlobalItemDemo'
    extracted=adb('shell','run-as','tm.loader.managedprobe','sha256sum',f'files/managed/{identity}.dll').split()[0]
    if extracted!=bundle['contract']['mod_dll_sha256']: raise ValueError('Extracted PC-compiled DLL differs')
    for name,digest in bundle['files'].items():
        if adb('shell','run-as','tm.loader.managedprobe','sha256sum','files/managed/'+name).split()[0]!=digest:
            raise ValueError('Device bundle file differs: '+name)
    package_path=adb('shell','pm','path','tm.loader.managedprobe')
    if not package_path.startswith('package:') or '\n' in package_path: raise ValueError('Expected one installed probe APK')
    if adb('shell','sha256sum',package_path[8:]).split()[0]!=build['sha256']:
        raise ValueError('Installed probe APK differs')
    lab=args.lab.resolve()/f'evidence/{stem}-probe'
    if lab.is_relative_to(ROOT): raise ValueError('Keep raw evidence outside repository')
    lab.mkdir(parents=True,exist_ok=True)
    (lab/'logcat.txt').write_text(adb('logcat','-d','--pid='+pid,'-t','3000'),encoding='utf-8')
    report={'status':'verified','date':args.date,'device':'Android ARM64 target Android 14 native ARM64',
            'pid':int(pid),'probe_apk_sha256':build['sha256'],'files':bundle['files'],
            'extracted_pc_mod_sha256':extracted,'result':result,'evidence':str(lab),
            'terraria_started_by_probe':False,'calamity_or_thorium_verified':False,
            'api_revision':bundle['contract'].get('api_revision'),'device_bundle_hashes_matched':True,
            'installed_probe_apk_hash_matched':True,'in_game_verified':False}
    (ROOT/'reports'/f'{stem}-probe-validation.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
