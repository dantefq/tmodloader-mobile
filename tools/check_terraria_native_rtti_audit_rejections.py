"""Negative proof mutations must be rejected by the independent RTTI auditor."""
import argparse, copy, hashlib, json, pathlib, subprocess, sys, tempfile
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);ap.add_argument('--out',type=pathlib.Path,required=True);a=ap.parse_args();doc=json.loads((a.out/'rtti-links.json').read_text());auditor=pathlib.Path(__file__).with_name('audit_terraria_native_rtti_continuation.py')
    def badslot(x):x['vtable_prefixes'][0]['slots'][0]['target']='0x0'
    def badname(x):x['rtti_objects'][0]['name']='FORGED'
    def badvp(x):x['rtti_objects'][0]['vptr_relocation']['link_time_target']='0x0'
    def badoffset(x):x['vtable_prefixes'][0]['offset_to_top']=12345
    def badextent(x):x['vtable_prefixes'][0]['prefix_end_exclusive']='0x0'
    def badcategory(x):
        s=x['vtable_prefixes'][0]['slots'][0];s['original_category_unknown']=not s['original_category_unknown']
    cases=[]
    for label,fn in [('wrong_FDE_target',badslot),('forged_RTTI_name',badname),('wrong_ABS64_resolution',badvp),('false_offset_to_top',badoffset),('false_prefix_extent',badextent),('false_unknown_category',badcategory)]:
        with tempfile.TemporaryDirectory(prefix='.negative-',dir=a.out) as temp:
            scratch=pathlib.Path(temp).resolve();assert scratch.parent==a.out.resolve();mutated=copy.deepcopy(doc);fn(mutated);(scratch/'rtti-links.json').write_text(json.dumps(mutated),encoding='utf8')
            run=subprocess.run([sys.executable,str(auditor),'--lab',str(a.lab),'--out',str(scratch)],capture_output=True,text=True)
            assert run.returncode!=0 and ('AssertionError' in run.stderr or 'ValueError' in run.stderr) and not (scratch/'independent-audit.json').exists(),(label,run.returncode,run.stderr)
            cases.append({'case':label,'rejected':True})
    proof={'passed':True,'checker_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'auditor_sha256':hashlib.sha256(auditor.read_bytes()).hexdigest(),'cases':cases,'source_and_original_proof_modified':False};(a.out/'negative-audit-checks.json').write_text(json.dumps(proof,indent=2),encoding='utf8');print(json.dumps(proof))
if __name__=='__main__':main()
