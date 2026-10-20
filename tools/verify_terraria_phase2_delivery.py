"""Join freshly hashed delivery files to their independently audited source ledgers."""
import argparse,hashlib,json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--lab',type=Path,required=True);p.add_argument('--delivery',type=Path,required=True);a=p.parse_args()
old=json.loads((a.lab/'delivery-manifest-before-phase2.json').read_text())
current=json.loads((a.delivery/'artifact-manifest.json').read_text())
files={r['path']:r for r in current['files']};assert len(files)==len(current['files'])==current['file_count']
assert old['apk_sha256']==current['apk_sha256']=='1f8e2ba7ddabaee961a1b2552d44bc0c281c9b5122480642b018779bcbf2fe8e'
immutable=0
for r in old['files']:
    if r['path'].startswith(('pseudocode/','metadata/','native/','android/','assets/','jadx/')):
        assert files.get(r['path'])==r,('Baseline immutable file changed',r['path']);immutable+=1
def match(relative,expected):
    assert relative in files and files[relative]['sha256']==expected,('Delivery differs from audited source',relative)
for relative in ['index.html','native-ranges.html','PHASE2.ru.md']:
    match(relative,hashlib.sha256((a.lab/relative).read_bytes()).hexdigest())
def rows(relative):return [json.loads(line) for line in (a.lab/relative).read_text().splitlines()]
native=rows('native-ranges-pseudocode/coverage.jsonl');assert len(native)==29162
native_files=0
for r in native:
    for path_key,sha_key in [('file','file_sha256'),('asm_file','asm_sha256'),('calls_file','calls_sha256')]:
        match('native-ranges-pseudocode/'+r[path_key],r[sha_key]);native_files+=1
typed=json.loads((a.lab/'pseudocode-v4-hard/audit.json').read_text());assert typed['passed'] and typed['decompiled_candidates']==2
for r in typed['files']:match('pseudocode-v4-hard/'+r['file'],r['sha256'])
high_files=0
for r in rows('hard-functions-ir/results.jsonl'):
    if r['status']=='ir_complete':
        for artifact in r['artifacts']:match('hard-functions-ir/'+artifact['file'],artifact['sha256']);high_files+=1
raw=rows('hard-functions-raw-ir/results.jsonl');assert len(raw)==20
for r in raw:
    assert r['status']=='raw_ir_complete';match('hard-functions-raw-ir/'+r['file'],r['sha256'])
report={'passed':True,'file_count':current['file_count'],'total_bytes':current['total_bytes'],
        'unchanged_baseline_artifacts':immutable,'audited_native_files_matched':native_files,
        'typed_C_candidates_matched':len(typed['files']),'high_IR_artifacts_matched':high_files,'raw_IR_artifacts_matched':len(raw),
        'manifest_sha256':hashlib.sha256((a.delivery/'artifact-manifest.json').read_bytes()).hexdigest(),
        'scope':'Matches actual delivered file hashes to source audits; does not prove recovered-code semantics.'}
(a.lab/'delivery-phase2-verification.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
