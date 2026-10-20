"""Validate the corrected observer against actual clock/config transitions."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path

from inspect_sleep_companion import inspect
from verify_sleep_checkpoint import objects, phase, validate_session
from verify_unified_checkpoint import parse_events, require

ROOT=Path(__file__).resolve().parents[1]
TRANSITION='TIME_ADVANCE_TRANSITION discardedMixedRateWindow=true'
# Revalidate this recorded session against its installed artifact, even when
# subsequent development has changed the source used for new companions.
CHECKPOINT_APK='c66263e4d08abb38a8768ec1ff8e554c9e647d51c60932abdab40829708710e9'
CHECKPOINT_SCRIPT='df321f61d04b851fd5dd9d5289a7c11265d486fde99598eb2f74f1d076321df6'


def validate_artifact(manifest, build, source_hash, require_current_source=False):
    require(manifest['output_sha256']==CHECKPOINT_APK,'Installed APK differs from recorded observer checkpoint')
    require(manifest['runtime_script_sha256']==CHECKPOINT_SCRIPT,'Embedded observer script differs from checkpoint')
    require(build['output_sha256']==manifest['output_sha256'],'Installed companion differs from build')
    require(build['own_api_bundle_files']==manifest['own_api_bundle_files'],'Installed bundle differs')
    require(manifest['own_api_bundle_files']['ChangeSleepTime.dll']=='3170283e245da54517d960a0ee7667de00ee166b3fddd751e180c8f4797d47c8',
            'Original mod DLL changed')
    matches=source_hash==manifest['runtime_script_sha256']
    if require_current_source:
        require(matches,'Installed script differs from current source')
    return dict(checkpoint_apk_sha256=CHECKPOINT_APK,checkpoint_script_sha256=CHECKPOINT_SCRIPT,
                current_source_sha256=source_hash,current_source_matches_checkpoint=matches,
                current_source_match_required=require_current_source)


def validate(rows):
    measured=validate_session(rows)
    all_measured=objects(rows,'TIME_ADVANCE')
    require(all(m['delta']==m['expected'] for _,m in all_measured),
            'Corrected observer emitted a mixed/incorrect clock window')
    phases=[]; index=-1
    for args in ((True,10,0,1),(True,10,1,10),(True,5,1,5),(False,10,1,5),(True,10,1,10),(True,10,0,1)):
        index,result=phase(measured,*args,after=index);phases.append(result)
    changes=[(i,r) for i,r in enumerate(rows) if r['message'].startswith('TIME_CONFIG ')][1:]
    require(len(changes)>=4,'Missing config transitions')
    transitions=[]
    stamp=lambda r:datetime.strptime(r['time'],'%m-%d %H:%M:%S.%f')
    for i,change in changes:
        match=next((r for r in rows[i+1:] if r['message']==TRANSITION and
                    0<=(stamp(r)-stamp(change)).total_seconds()<1),None)
        require(match is not None,'Config transition not followed by discarded window')
        transitions.append(dict(config_time=change['time'],config=change['message'],discard_time=match['time']))
    states=[s for _,s in objects(rows,'LAB_PROTECTION_STATE')]
    require(len(states)>=2 and all(s['god'] and s['noKnockback'] and s['life']>0 and not s['dead'] for s in states),
            'Protection state missing or changed')
    require(any(a['vanillaSleepAPI'] for _,a in objects(rows,'SLEEP_SCENE_ACTION')),'Vanilla sleep action absent')
    return dict(pid=rows[0]['pid'],phases=phases,config_transitions=transitions,
        completed_exact_windows=len(all_measured),protection_observations=len(states))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab',type=Path,required=True)
    parser.add_argument('--build',type=Path,default=ROOT/'reports/sleep-companion-build.json')
    parser.add_argument('--output',type=Path,default=ROOT/'reports/sleep-observer-validation.json')
    parser.add_argument('--require-current-source',action='store_true',
                        help='Also require current runtime source to match the historical APK')
    args=parser.parse_args()
    manifest=inspect(args.lab/'installed-observer-companion.apk')
    build=json.loads(args.build.read_text('utf-8'))
    script=b'\n'.join((ROOT/name).read_bytes() for name in ('runtime/managed-time-host.js','runtime/sleep-scene.js','runtime/time-loader.js'))
    script+=b'\n'+(ROOT/'runtime/lab-protection.js').read_bytes()
    artifact_checks=validate_artifact(manifest,build,hashlib.sha256(script).hexdigest(),args.require_current_source)
    folder=args.lab/'evidence/observer-final-save'
    log=(folder/'logcat.txt').read_text('utf-8')
    require('Saving World data at path:' in log and '/Worlds/TMAL_Lab.wld' in log,'Final world save log absent')
    checks=validate(parse_events(log))
    report=dict(status='verified-config-transition-observer',date_local='2026-10-11',**checks,
        installed_companion=manifest,artifact_checks=artifact_checks,final_evidence=str(folder),
        final_screenshot_sha256=hashlib.sha256((folder/'screenshot.png').read_bytes()).hexdigest(),
        limitations=['One real-device session; previous same-APK restart checkpoint is recorded separately.',
            'Clock/tile bridge only; no event-rate, Journey or multiplayer support.',
            'Protection state observed; controlled damage/knockback matrix remains untested.'])
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(status=report['status'],pid=report['pid'],exact_windows=report['completed_exact_windows'],
        transitions=len(report['config_transitions']))))


if __name__=='__main__':main()
