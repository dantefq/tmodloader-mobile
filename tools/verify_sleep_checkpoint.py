"""Validate captured real-world sleep measurements; no device access or OCR."""
import argparse
import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path
from verify_unified_checkpoint import parse_events, require


def objects(rows, marker):
    return [(i, json.loads(r['message'][len(marker)+1:])) for i, r in enumerate(rows)
            if r['message'].startswith(marker+' ')]


def validate_session(rows):
    require(rows and len({r['pid'] for r in rows}) == 1, 'Missing or mixed process evidence')
    for marker in ('TIME_HOST_READY originalChangeSleepTime=true cases=10',
                   'TIME_HOOK_READY originalDLL=true normalOfflineTestWorldOnly=true clockAndTilesOnly=true'):
        require(any(r['message'] == marker for r in rows), 'Missing time readiness')
    require(not any('FAILED' in r['message'] or 'REJECTED' in r['message'] for r in rows), 'Runtime failure/rejection in selected session')
    measurements=[]
    for index, m in objects(rows,'TIME_ADVANCE'):
        require(m['active']==1 and m['sleeping'] in (0,1) and m['frames']==180, 'Unexpected observed frame counts')
        require(m['expected']==180*m['dayRate'], 'Expected clock sum differs from applied rate')
        require(0<m['wallMs']<15000, 'Measurement timing outside test bounds')
        if m['delta']!=m['expected']:
            end=datetime.strptime(rows[index]['time'],'%m-%d %H:%M:%S.%f')
            start=end-timedelta(milliseconds=m['wallMs'])
            # Historical observer could label the last transition tick with its
            # entry rate. Exclude only a window containing a logged, different
            # config; never count that window as a successful measurement.
            configs=[r for r in rows[:index] if r['message'].startswith('TIME_CONFIG ') and
                     start<=datetime.strptime(r['time'],'%m-%d %H:%M:%S.%f')<=end and
                     r['message']!=f"TIME_CONFIG enabled={str(m['enabled']).lower()} multiplier={m['multiplier']}"]
            require(configs, 'Actual clock differs from applied rate without a config transition')
            continue
        measurements.append((index,m))
    return measurements


def phase(measurements, enabled, multiplier, sleeping, rate, after=-1):
    found=[(i,m) for i,m in measurements if i>after and
           (m['enabled'],m['multiplier'],m['sleeping'],m['dayRate'])==(enabled,multiplier,sleeping,rate)]
    require(len(found)>=2, f'Missing repeated actual measurements: {enabled}/{multiplier}/{sleeping}/{rate}')
    return found[1][0], {'enabled':enabled,'multiplier':multiplier,'sleeping':sleeping,
                        'day_rate':rate,'samples': [m for _,m in found[:2]]}


def validate(initial, protected, restarted):
    measurements=validate_session(initial)
    first=[];index=-1
    for args in ((True,10,0,1),(True,10,1,10),(True,5,1,5),(False,10,1,5),(True,10,1,10),(True,10,0,1)):
        index,row=phase(measurements,*args,after=index);first.append(row)
    require(any(r['message'].startswith('SLEEP_SCENE_BUILT ') for r in initial), 'Actual room placement missing')
    for enabled,multiplier,sleeping,rate in ((True,10,0,1),(True,10,1,10),(True,5,1,5),(False,10,1,5)):
        bridges=[b for _,b in objects(initial,'TIME_BRIDGE') if
                 (b['enabled'],b['multiplier'],b['sleeping'])==(enabled,multiplier,sleeping)]
        require(any(b['active']==1 and b['after']==[rate,rate] and b['classicOnly'] is True and b['eventRateApplied'] is False for b in bridges), 'Clock/tile binding evidence absent')
    result=[]
    for rows in (protected,restarted):
        measured=validate_session(rows)
        index,awake=phase(measured,True,10,0,1)
        _,asleep=phase(measured,True,10,1,10,after=index)
        require(any(r['message']=='LAB_PROTECTION_READY offlineClassicTestProfilesOnly=true' for r in rows), 'Protection hook absent')
        states=[s for _,s in objects(rows,'LAB_PROTECTION_STATE')]
        require(len(states)>=2 and all(s['profile']=='TMAL_Sleep' and s['god'] is True and s['noKnockback'] is True and s['life']>0 and s['dead'] is False for s in states), 'Protection state differs')
        require(any(a['action']=='use-bed' and a['vanillaSleepAPI'] is True for _,a in objects(rows,'SLEEP_SCENE_ACTION')), 'Vanilla bed activation absent')
        result.append({'pid':rows[0]['pid'],'awake':awake,'asleep':asleep,'protection_observations':len(states)})
    require(protected[0]['pid']!=restarted[0]['pid'], 'Same-companion full restart absent')
    require(protected[-1]['time']<restarted[0]['time'], 'Unordered or cross-day evidence')
    require(any(r['message']=='LAB_PROTECTION_CONFIG enabled=false' for r in protected) and any(r['message']=='LAB_PROTECTION_RELEASED' for r in protected), 'Protection off/release absent')
    require(sum(r['message']=='LAB_PROTECTION_CONFIG enabled=true' for r in protected)>=2, 'Protection re-enable absent')
    excluded=[{'time':initial[i]['time'],**m} for i,m in objects(initial,'TIME_ADVANCE') if m['delta']!=m['expected']]
    return {'initial_pid':initial[0]['pid'],'initial_phases':first,'same_companion_sessions':result,
            'excluded_historical_mixed_config_windows':excluded}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('initial-evidence','evidence','initial-apk','apk','initial-build','build','output'):
        p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args()
    builds=[]
    for apk,report in ((a.initial_apk,a.initial_build),(a.apk,a.build)):
        b=json.loads(report.read_text('utf-8-sig'));digest=hashlib.sha256(apk.read_bytes()).hexdigest()
        require(b['variant']=='sleep-demo' and b['output_sha256']==digest,'Installed time companion hash differs')
        require(b['own_api_bundle_files']['ChangeSleepTime.dll']=='3170283e245da54517d960a0ee7667de00ee166b3fddd751e180c8f4797d47c8','Original mod DLL changed')
        builds.append(digest)
    def read(root,label):return parse_events((root/label/'logcat.txt').read_text('utf-8'))
    checks=validate(read(a.initial_evidence,'sleep-first-save'),read(a.evidence,'protected-first-save'),read(a.evidence,'protected-final-save'))
    report={'status':'verified-original-sleep-clock-tile-rates-off-and-restart','date_local':'2026-10-10',
            'profile':'TMAL_Sleep','world':'TMAL_Lab','device':'Android ARM64 target Android14 native ARM64 no root',
            'installed_companion_hashes_matched':builds,'original_dll_recompiled_or_patched':False,
            **checks,'initial_evidence':str(a.initial_evidence),'protected_evidence':str(a.evidence),
            'limitations':['Clock and tile rates only; mobile world-event rate binding absent.',
                           'Offline classic test profiles only; no Journey or multiplayer conformance.',
                           'Protection flags/living state observed; no controlled hit or knockback matrix yet.',
                           'Time API remains separate from unified item API; no general tmod importer.',
                           'Players/Worlds backup excludes private sidecar.'], 'github_upload':False}
    a.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'status':report['status'],'restart_pids':[s['pid'] for s in checks['same_companion_sessions']]}))


if __name__=='__main__':main()
