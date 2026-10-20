"""Verify saved unified time-game evidence and bounded protection controls."""
import argparse
import hashlib
import json
from pathlib import Path
from inspect_sleep_companion import inspect
from verify_sleep_checkpoint import objects,phase,validate_session
from verify_unified_checkpoint import parse_events,require

ROOT=Path(__file__).resolve().parents[1]
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()

def validate_matrix(report,pid):
    require(report['pid']==pid and len(report['checks'])==10,'Matrix process/count differs')
    variants=['off']*2+['knockback-only']*2+['full']*2+['off']*2+['full']*2
    for i,(row,variant) in enumerate(zip(report['checks'],variants)):
        before,after,restored=row['before'],row['after'],row['restored']
        direction=(-1,1)[i%2]
        require(row['pid']==pid and row['variant']==variant and row['direction']==direction and row['inputDamage']==20,'Hit scope differs')
        require(before['life']==100 and restored['life']==100 and not after['dead'] and not restored['dead'],'Health restoration differs')
        require(restored['position']==before['position'] and restored['velocity']==[0,0],'Transient motion not restored')
        expected_loss=0 if variant=='full' else 20
        require(row['healthLost']==before['life']-after['life']==expected_loss and row['returnedDamage']==expected_loss,'Damage control differs')
        velocity=[direction*4.5,-3.5] if variant=='off' else [0,0]
        require(after['velocity']==velocity,'Knockback control differs')
        require(before['god']==(variant=='full') and before['noKnockback']==(variant!='off'),'Protection control flags differ')
    final=report['final_state']
    require(final['enabled'] and final['god'] and final['noKnockback'] and final['life']==100 and not final['dead'],'Final protection not restored')
    return dict(pid=pid,hits=10,off_damage=20,off_velocity=[4.5,-3.5],no_knockback_velocity=[0,0],full_damage=0,final_life=100)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab',type=Path,required=True)
    parser.add_argument('--build',type=Path,required=True)
    parser.add_argument('--output',type=Path,default=ROOT/'reports/android-unified-time-game-validation.json')
    args=parser.parse_args()
    device=json.loads((args.lab/'checkpoint-device.json').read_text('utf-8'))
    build=json.loads(args.build.read_text('utf-8'))
    manifest=inspect(Path(device['installed_apk']))
    require(build['variant']==manifest['variant']=='unified-sleep-demo','Wrong companion variant')
    require(build['output_sha256']==manifest['output_sha256']==device['packages']['tm.loader.companion']['sha256'],'Installed APK identity differs')
    require(build['own_api_bundle_files']==manifest['own_api_bundle_files'],'Five-file API bundle differs')
    require(device['packages']['com.and.games505.TerrariaPaid']['sha256']==build['target_apk_sha256']=='1f8e2ba7ddabaee961a1b2552d44bc0c281c9b5122480642b018779bcbf2fe8e','Original game APK changed')
    require(manifest['own_api_bundle_files']['ChangeSleepTime.dll']=='3170283e245da54517d960a0ee7667de00ee166b3fddd751e180c8f4797d47c8','Original mod DLL changed')
    sessions=[]
    for label,expected in (('android-first-save',((True,10,0,1),(True,10,1,10),(True,5,1,5),(False,10,1,5),(True,10,1,10),(True,10,0,1))),
                           ('android-final-save',((True,10,0,1),(True,10,1,10),(True,10,0,1)))):
        folder=args.lab/'evidence'/label;log=(folder/'logcat.txt').read_text('utf-8-sig');rows=parse_events(log)
        measured=validate_session(rows)
        require('UNIFIED_TIME_API_READY lifecycleChecks=7 contentChecks=14 nativeItemBridge=false' in log,'Common lifecycle/content checks missing')
        require('Saving World data at path:/storage/emulated/0/Android/data/com.and.games505.TerrariaPaid/Worlds/TMAL_Lab.wld' in log,'Final lab world save missing')
        require(all(m['delta']==m['expected'] for _,m in objects(rows,'TIME_ADVANCE')),'Incorrect clock window emitted')
        phases=[];index=-1
        for values in expected:index,result=phase(measured,*values,after=index);phases.append(result)
        require(any(a['vanillaSleepAPI'] for _,a in objects(rows,'SLEEP_SCENE_ACTION')),'Vanilla bed action missing')
        states=[s for _,s in objects(rows,'LAB_PROTECTION_STATE')]
        require(len(states)>=2 and all(s['life']==100 and s['god'] and s['noKnockback'] and not s['dead'] for s in states),'Protected game state differs')
        sessions.append(dict(pid=rows[0]['pid'],phases=phases,log_sha256=sha(folder/'logcat.txt'),screenshot_sha256=sha(folder/'screenshot.png')))
    require(sessions[0]['pid']!=sessions[1]['pid']==device['pid'],'Same-APK new process absent')
    restarted=(args.lab/'evidence/android-final-save/logcat.txt').read_text('utf-8-sig')
    require('SLEEP_SCENE_BUILT ' not in restarted,'Room rebuilt after restart')
    matrices=[]
    for name,session in zip(('android-protection-matrix-first-session.json','android-protection-matrix-validation.json'),sessions):
        matrices.append(validate_matrix(json.loads((ROOT/'reports'/name).read_text('utf-8')),session['pid']))
    require(device['configs']=={'sleep-config.json':{'multiplier':10},'managed-enabled.json':{'enabled':True},'lab-protection.json':{'enabled':True}},'Final config differs')
    report=dict(status='verified-unified-time-sleep-protection-save-restart',device=device,installed_companion=manifest,
                sessions=sessions,controlled_matrices=matrices,original_dll_recompiled_or_patched=False,
                limitations=['Time/clock/tile bridge only; native item bridge absent in this companion.',
                             'Two offline classic lab sessions on Android; no other-profile guard or full source-of-damage matrix.',
                             'No general importer, Calamity or Infernum runtime compatibility is established.'])
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(status=report['status'],pids=[s['pid'] for s in sessions],controlled_hits=20)))

if __name__=='__main__':main()
