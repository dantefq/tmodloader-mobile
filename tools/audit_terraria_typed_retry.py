"""Audit provenance and files of typed-v4 candidates; does not prove C semantics."""
import argparse,hashlib,json
from collections import Counter
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--lab',type=Path,default=Path('C:/Temp/terraria-re-20261012'));a=p.parse_args();lab=a.lab.resolve();out=lab/'pseudocode-v4-hard'
def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
progress=json.loads((out/'retry-progress.json').read_text())
assert progress['finished'] and progress['attempted']==progress['retry_total']==20,'Typed retry is unfinished'
baseline_path=lab/'coverage-v3-before-stack32.jsonl';baseline_sha=sha(baseline_path)
baseline={r['address']:r for line in baseline_path.read_text().splitlines() if (r:=json.loads(line))['status']!='decompiled'}
assert len(baseline)==20
signatures_sha=sha(lab/'native/abi-v4/signatures.tsv')
engine_sha=sha(lab/'ghidra-stack32/Ghidra/Features/Decompiler/os/win_x86_64/decompile.exe')
profile='bounded-fde-flat-aggregate-abi-v4-candidate-stack32'
rows=[json.loads(line) for line in (out/'retry-results.jsonl').read_text().splitlines()]
assert len(rows)==len({r['address'] for r in rows})==20 and {r['address'] for r in rows}==baseline.keys()
files=[];counts=Counter();warnings=0
for r in rows:
    original=baseline[r['address']]
    for key in ['address','compiler_end_exclusive','image_base','method','image','instructions','instruction_bytes','compiler_size']:
        assert r[key]==original[key],(r['address'],key)
    assert r['baseline_sha256']==baseline_sha and r['abi_signatures_sha256']==signatures_sha
    assert r['actual_engine_sha256']==r['expected_engine_sha256']==engine_sha
    assert r['profile']==profile and not r['baseline_ledger_modified'] and r['typed_abi_candidate']
    counts[r['status']]+=1
    if r['status']=='decompiled':
        path=(out/r['file']).resolve();assert path.is_relative_to(out.resolve()) and path.is_file() and not path.is_symlink()
        text=path.read_text(encoding='utf-8')
        header=('/* RECOVERED GHIDRA PSEUDOCODE; NOT ORIGINAL C#; typed ABI candidate; static analysis only.\n'
                f" * Method: {r['method'].replace('*/','* /')}\n * ELF VA: {r['address']}; image base: 0\n"
                f" * Compiler unwind extent end-exclusive: {r['compiler_end_exclusive']}\n * Analysis profile: {profile}\n */\n")
        assert text.startswith(header) and text[len(header):].strip()
        warnings+=text.count('WARNING:')
        files.append({'address':r['address'],'file':r['file'],'sha256':sha(path),'bytes':path.stat().st_size,'warnings':text.count('WARNING:')})
    else:assert r['file']=='',r['address']
assert counts['decompiled']==progress['decompiled'] and len(rows)-counts['decompiled']==progress['failed']
assert {p.resolve() for p in out.rglob('*.c')}=={(out/r['file']).resolve() for r in files}
result={'passed':True,'scope':'Candidate provenance/header/file audit, not ABI or C semantic equivalence proof',
        'profile':profile,'targets':20,'decompiled_candidates':counts['decompiled'],'failed':progress['failed'],
        'warnings':warnings,'files':files,'baseline_sha256':baseline_sha,'abi_signatures_sha256':signatures_sha,
        'engine_sha256':engine_sha,'coverage_sha256':sha(out/'retry-results.jsonl'),'runtime_verified':False}
(out/'audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:result[k] for k in ['passed','targets','decompiled_candidates','failed','warnings']}))
