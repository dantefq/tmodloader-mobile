"""Collect our read-only IL2CPP array-size diagnostics from the selected phone."""
import argparse
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--serial',required=True)
    p.add_argument('--lab',type=Path,required=True)
    p.add_argument('--adb',type=Path,default=Path.home()/'AppData/Local/Android/Sdk/platform-tools/adb.exe')
    args=p.parse_args()
    def adb(*words):
        r=subprocess.run([str(args.adb),'-s',args.serial,*words],capture_output=True,timeout=25)
        if r.returncode: raise RuntimeError(r.stderr.decode('utf-8','replace'))
        return r.stdout.decode('utf-8','replace').strip()
    pid=adb('shell','pidof','com.and.games505.TerrariaPaid')
    if not pid.isdigit(): raise ValueError('Game process is not alive')
    log=adb('logcat','-d','--pid='+pid,'-s','TMAL:I','-v','raw')
    if 'CONTENT_RECON_FAILED' in log or 'CONTENT_RECON_OK' not in log: raise ValueError('Content diagnostics not complete')
    header=None;classes={}
    for line in log.splitlines():
        if line.startswith('CONTENT_RECON_HEADER '): header=json.loads(line.split(' ',1)[1])
        elif line.startswith('CONTENT_RECON_FIELDS '):
            group=json.loads(line.split(' ',1)[1]);classes.setdefault(group['class'],[]).extend(group['fields'])
    if header is None or header['itemTextureLength']!=6196: raise ValueError('Unexpected current mobile item count')
    lab=args.lab.resolve()/'evidence/content-recon'
    if lab.is_relative_to(ROOT): raise ValueError('Keep raw game diagnostics outside repository')
    lab.mkdir(parents=True,exist_ok=True);(lab/'logcat.txt').write_text(log,encoding='utf-8')
    candidates={name:[f for f in fields if f.get('length')==6196] for name,fields in classes.items()}
    report={'status':'read-only-recon-verified','date':'2026-10-08','device':'Android ARM64 target Android14 native ARM64',
            'game_pid':int(pid),'item_texture_length':6196,'proposed_first_new_id':6196,
            'candidate_arrays':candidates,'candidate_array_count':sum(map(len,candidates.values())),
            'count_field':[f for f in classes.get('Terraria.ID.ItemID',[]) if f['name']=='Count'],
            'diagnostics_changed_arrays':False,'new_item_registered':False,'evidence':str(lab)}
    (ROOT/'reports/content-recon.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='candidate_arrays'},indent=2))
    for name,fields in candidates.items(): print(name+': '+', '.join(f['name'] for f in fields))

if __name__=='__main__':main()
