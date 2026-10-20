"""Freeze the conditional stack-check profile and independently proved imports."""
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

LAB=Path(r'C:\Temp\terraria-re-20261012')
TOOLS=Path(__file__).resolve().parent
APK=Path(r'C:/Private\Downloads\Terraria-v1-4-5-8-6-patched.apk')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
SOURCE='2abbe851f83a5bcde7864dda26652cdb7083d10634fea796bf9506e375cea3a0'
assert sha(TOOLS/'apk-native-v3/ApkNativeRangeExport.java')==SOURCE
assert sha(TOOLS/'prove_apk_stackchk_imports.py')=='1b261576562c6b0b4452046f6cbb8982d2221cd82d3c6f3662a980190ff6dd33'
assert sha(TOOLS/'prove_libmain_stackchk_import.py')=='b3fc8f7a171a177f97cf7b8be5d1514e312daf8d9661a32851bd800e2edffd3a'
out=LAB/'other-native-range-v3-manifests-20261019'
frozen=LAB/'other-native-exporter-v3-sources-20261019'
proofs=LAB/'other-native-stackchk-proofs-20261019'
assert not out.exists() and not frozen.exists() and not proofs.exists()
out.mkdir();frozen.mkdir();proofs.mkdir()
shutil.copyfile(TOOLS/'apk-native-v3/ApkNativeRangeExport.java',frozen/'ApkNativeRangeExport.java')
for name in ('apk-native-v3/audit_apk_native_range_export_v3.py','prove_apk_stackchk_imports.py','prove_libmain_stackchk_import.py'):
    dest=frozen/'tools'/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(TOOLS/name,dest)
parent=LAB/'other-native-range-v2-manifests-20261019'
results=[]
for row in json.loads((parent/'summary.json').read_text()):
    old=parent/(row['library']+'.manifest.json');assert sha(old)==row['manifest_sha256']
    m=json.loads(old.read_text());proof_dir=proofs/row['library']
    command=[sys.executable,str(TOOLS/'prove_apk_stackchk_imports.py'),'--apk',str(APK),'--elf',m['binary_path'],
             '--expected-elf-sha256',m['elf_sha256'],'--output',str(proof_dir)]
    call=subprocess.run(command,capture_output=True,text=True)
    if call.returncode:
        results.append(dict(row,status='unsupported_stackchk_import_proof',error=call.stderr[-2000:]));continue
    proof=proof_dir/'evidence.json';p=json.loads(proof.read_text())
    assert p['elf_sha256']==m['elf_sha256'] and p['known_noreturn_imports']
    assert p['producer_sha256']==sha(TOOLS/'prove_apk_stackchk_imports.py')
    m.update(profile='apk-native-bounded-range-C-v3-conditional-stackchk',
             derived_from_v2_manifest_sha256=sha(old),v3_generator_sha256=sha(Path(__file__)),v3_exporter_sha256=SOURCE,
             noreturn_import_proof_file=str(proof),noreturn_import_proof_sha256=sha(proof),
             known_noreturn_imports=p['known_noreturn_imports'],conditional_noreturn_assumptions=p['conditional_noreturn_assumptions'])
    target=out/old.name;target.write_text(json.dumps(m,indent=2)+'\n')
    results.append(dict(row,manifest_sha256=sha(target),status='ready_conditional_profile',proof_sha256=sha(proof)))
(out/'summary.json').write_text(json.dumps(results,indent=2)+'\n')
files=[dict(path=p.relative_to(frozen).as_posix(),sha256=sha(p)) for p in sorted(frozen.rglob('*')) if p.is_file()]
(frozen/'source-manifest.json').write_text(json.dumps(files,indent=2)+'\n')
print(json.dumps([dict(library=r['library'],status=r['status'],manifest_sha256=r.get('manifest_sha256')) for r in results]))
