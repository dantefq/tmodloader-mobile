"""Reject four deliberately corrupted proof records; source ELF untouched."""
import copy, hashlib, json, pathlib, subprocess, sys
lab=pathlib.Path(sys.argv[1]);root=lab/'hard-switches-v2';source=root/'switches.json'
doc=json.loads(source.read_text(encoding='utf8'));output=lab/'switch-v2-negative-fixtures';output.mkdir(exist_ok=True)
results=[]
for kind in ('table_byte','target','guard','and_mask'):
    candidate=copy.deepcopy(doc)
    tables=[t for m in candidate['methods'] for t in m['switch_candidates']]
    if kind=='table_byte':
        table=tables[0];blob=bytearray.fromhex(table['table_raw_bytes']);blob[0]^=1
        table['table_raw_bytes']=blob.hex();table['table_sha256']=hashlib.sha256(blob).hexdigest()
    elif kind=='target':tables[0]['entries'][0]['target']=hex(int(tables[0]['entries'][0]['target'],16)+4)
    elif kind=='guard':tables[0]['guard_compare']=hex(int(tables[0]['guard_compare'],16)+4)
    else:
        table=next(t for t in tables if any(r['instruction'].startswith('and ') for r in t['straight_line_evidence']))
        row=next(r for r in table['straight_line_evidence'] if r['instruction'].startswith('and '))
        row['instruction']=row['instruction'].replace('#0xff','#0x7f')
        assert row['instruction']!=next(r for t in [next(t for m in doc['methods'] for t in m['switch_candidates'] if t['branch']==table['branch'])] for r in t['straight_line_evidence'] if r['address']==row['address'])['instruction']
    path=output/(kind+'.json');path.write_text(json.dumps(candidate),encoding='utf8')
    process=subprocess.run([sys.executable,str(pathlib.Path(__file__).with_name('audit_terraria_switches_v2_independent.py')),str(lab),str(path)],capture_output=True,text=True)
    assert process.returncode!=0,kind
    results.append({'fixture':kind,'rejected':True,'fixture_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'exit_code':process.returncode})
report={'passed':True,'cases':results,'original_producer_output_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'tool_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'scope':'Corrupt producer claims; original ELF and canonical producer output never modified.'}
(root/'audit-negative-tests.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps(report))
