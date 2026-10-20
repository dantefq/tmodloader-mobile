"""Summarize own save observer events without copying game log or save bytes."""
import argparse
import hashlib
import json
from pathlib import Path


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evidence',type=Path,required=True)
    p.add_argument('--apk',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    lines=(args.evidence/'logcat.txt').read_text(encoding='utf-8').splitlines()
    events=[]
    for i,line in enumerate(lines):
        if 'SAVE_TRACE {' in line:
            events.append({**json.loads(line.split('SAVE_TRACE ',1)[1]),'time':line[:18].strip(),'line':i})
    assert events and not any(e['event']=='observer.error' for e in events)
    saves=[e for e in events if e['event']=='SavePlayer.enter' and e.get('custom')==1]
    assert len(saves)==1,'Expected exactly one custom test save'
    save=saves[0]
    internal=next(e for e in events if e['seq']>save['seq'] and e['event']=='InternalSavePlayerFile.leave')
    assert internal['custom']==0 and internal['base']==1 and internal['serialized']>=58 and internal['customSerialized']==0
    guard=next(i for i,line in enumerate(lines) if i>save['line'] and 'MODITEM_LEASE_RESTORED reason=player-save' in line)
    assert save['line']<guard<internal['line']
    loaded=next(e for e in events if e['seq']>internal['seq'] and e['event']=='LoadPlayer.leave')
    entered=next(e for e in events if e['seq']>loaded['seq'] and e['event']=='ItemCheck.player')
    assert loaded['expectedPlayer'] and loaded['custom']==0 and entered['custom']==0 and entered['base']==1
    report={'status':'verified-readonly-save-trace-and-transient-rollback','persistent_content_implemented':False,
            'companion_sha256':hashlib.sha256(args.apk.read_bytes()).hexdigest(),
            'profile':'TMAL_Test','world':'TMAL_Lab','events':[save,internal,loaded,entered],
            'observer_errors':0,'custom_id_serialized':False,
            'tooltip_after_reload':{'item':'Copper Shortsword','damage':5,'visual_evidence':'trace-final-tooltip'},
            'limitations':['This report verifies transient rollback, not the later sidecar prototype.',
                           'No general save compatibility or arbitrary PC mod support.']}
    for row in report['events']:row.pop('line',None)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
