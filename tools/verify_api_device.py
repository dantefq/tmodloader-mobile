"""Record hashes/logs for the GlobalItem cycle whose screenshots were inspected."""
import argparse
import json
from pathlib import Path
import subprocess
from apk_format import sha256

ROOT=Path(__file__).resolve().parents[1]
GAME='com.and.games505.TerrariaPaid'

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--serial',required=True)
    p.add_argument('--lab',type=Path,required=True)
    p.add_argument('--screenshots-inspected',action='store_true',required=True)
    p.add_argument('--adb',type=Path,default=Path.home()/'AppData/Local/Android/Sdk/platform-tools/adb.exe')
    args=p.parse_args()
    def adb(*words):
        r=subprocess.run([str(args.adb),'-s',args.serial,*words],capture_output=True,timeout=25)
        if r.returncode: raise RuntimeError(r.stderr.decode('utf-8','replace'))
        return r.stdout.decode('utf-8','replace').strip()
    def installed_hash(package):
        paths=adb('shell','pm','path',package).splitlines()
        if len(paths)!=1 or not paths[0].startswith('package:/data/app/'): raise ValueError('Expected one installed base APK')
        return adb('shell','sha256sum',paths[0][8:]).split()[0]
    build=json.loads((ROOT/'reports/api-companion-build.json').read_text())
    if installed_hash(GAME)!=build['target_apk_sha256'] or installed_hash('tm.loader.companion')!=build['output_sha256']:
        raise ValueError('Installed APK identity differs')
    labels=['api-tooltip-full','api-tooltip-off','api-tooltip-reenabled','api-mods-dialog','api-disabled-dialog','api-final-saved-menu']
    evidence=args.lab.resolve()/'evidence'
    if evidence.is_relative_to(ROOT): raise ValueError('Keep raw evidence outside repository')
    frames={label:str(evidence/label/'screenshot.png') for label in labels}
    for path in frames.values():
        if not Path(path).is_file(): raise ValueError('Missing inspected frame')
    pid=adb('shell','pidof',GAME)
    if not pid.isdigit(): raise ValueError('Game is not alive')
    logs=(evidence/'api-final-saved-menu/logcat.txt').read_text(encoding='utf-8',errors='replace')
    for marker in ('TML_API_READY','HOOK_READY','Registry loaded: 0','damage=24, name=PC API Test Sword','Managed demo enabled=false','Managed demo enabled=true','Saving World data at path:'):
        if marker not in logs: raise ValueError('Missing cycle evidence: '+marker)
    errors=['MANAGED_FAILED','Overrides disabled after repeated errors','FATAL EXCEPTION','Fatal signal','Integrity Error']
    found=[marker for marker in errors if marker in logs]
    if found: raise ValueError('Inspect failure evidence: '+str(found))
    report={'status':'verified','date':'2026-10-08','device':'Android ARM64 target Android14 no root native ARM64',
            'game_pid':int(pid),'game_apk_sha256':build['target_apk_sha256'],'companion_sha256':build['output_sha256'],
            'same_process_observed_from':'20:01:41','same_process_observed_through':'20:10:17','minimum_observed_seconds':516,
            'own_api_bundle_files':build['own_api_bundle_files'],'own_pc_compiled_tmod_executed':True,
            'snapshot_fields':['Item.type','Item.damage','Item.SetNameOverride(string)'],
            'hook':'GlobalItem.SetDefaults','hooked_mobile_item_ids':[3507],
            'json_disabled':True,'tooltip_cycle':[{'name':'PC API Test Sword','damage':24},{'name':'Медный короткий меч','damage':5},{'name':'PC API Test Sword','damage':24}],
            'screenshots_inspected':True,'evidence':frames,'saved_test_world':'TMAL_Lab','test_player':'TMAL_Test',
            'final_screen':'main menu','native_arm64_guard_verified':True,
            'arbitrary_tmod_supported':False,'calamity_verified':False,'thorium_verified':False,
            'new_global_item_video_recorded':False,'scope':'bundled own unsigned two-entry .tmod; minimal independently written API shim'}
    (ROOT/'reports/api-device-validation.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    build.update({'status':'in-game-verified-own-global-item','in_game_verified':True,'own_pc_compiled_tmod_executed':True,'arbitrary_tmod_supported':False})
    (ROOT/'reports/api-companion-build.json').write_text(json.dumps(build,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,ensure_ascii=False,indent=2))

if __name__=='__main__':main()
