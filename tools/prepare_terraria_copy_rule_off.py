"""Derive a separate diagnostic profile using the official single-rule toggle."""
import ast
import hashlib
import json
import shutil
from pathlib import Path

LAB = Path(r'C:\Temp\terraria-re-20261012')
TOOLS = Path(__file__).resolve().parent
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
parent = LAB / 'portable-branch-long-sources-20261019'
out = LAB / 'copy-rule-off-sources-20261019'
assert not out.exists()
java = (parent / 'TerrariaPortableBranchLongProbe.java').read_text()
audit = (parent / 'audit_terraria_portable_branch_long.py').read_text()
assert sha(parent / 'audit_terraria_portable_branch_long.py') == '439b73e45745b3cc15080d02d8f3a92f45fa69ec08104840b017a1630f1e40a3'
changes = [
    ('TerrariaPortableBranchLongProbe', 'TerrariaCopyRuleOffProbe'),
    ('audit_terraria_portable_branch_long.py', 'audit_terraria_copy_rule_off.py'),
    ('pseudocode-portable-branch-long-c-', 'pseudocode-copy-rule-off-c-'),
    ('portable-branch-preserving-long-C-v1', 'copy-rule-off-diagnostic-C-v1'),
    ('int injections=0,toggleInjections=0;', 'int injections=0,toggleInjections=0,ruleInjections=0;'),
    ('                    injections++;', '''                    encoder.openElement(ELEM_TOGGLERULE);
                    content(encoder,ELEM_PARAM1,"universal:fullloop:mainloop:stackstall:oppool1:propagatecopy");
                    content(encoder,ELEM_PARAM2,"off");
                    encoder.closeElement(ELEM_TOGGLERULE);ruleInjections++;
                    injections++;'''),
    ('JsonObject rec=new JsonObject();', 'JsonObject rec=new JsonObject();rec.addProperty("disabled_rule_path","universal:fullloop:mainloop:stackstall:oppool1:propagatecopy");rec.addProperty("rule_disabled_runtime_verified",false);rec.addProperty("diagnostic_only",true);'),
]
for old, new in changes:
    assert old in java
    java = java.replace(old, new)
# Keep the independently pinned grandparent reconstruction verbatim, then apply
# precisely the additional transforms. Never accept arbitrary producer edits.
start = audit.index('    branch_parent=')
end = audit.index("    assert a.producer.read_text()==expected,'Unexpected branch profile change'")
reconstruct = audit[start:end]
audit = audit[:start] + '    # RECONSTRUCTION_PLACEHOLDER\n' + audit[end:]
for old, new in changes[:4]:
    audit = audit.replace(old, new)
reconstruct += ''.join('    expected=expected.replace(' + repr(old) + ',' + repr(new) + ')\n' for old, new in changes)
audit = audit.replace('    # RECONSTRUCTION_PLACEHOLDER\n', reconstruct)
audit = audit.replace('def model_record(r):\n', '''def model_record(r):
    assert r['disabled_rule_path']=='universal:fullloop:mainloop:stackstall:oppool1:propagatecopy'
    assert r['diagnostic_only'] is True
    assert r['rule_disabled_runtime_verified'] is False
''')
audit = audit.replace('        model_record(good)\n', "        good.update(disabled_rule_path='universal:fullloop:mainloop:stackstall:oppool1:propagatecopy',diagnostic_only=True,rule_disabled_runtime_verified=False)\n        model_record(good)\n")
# This experiment cannot promote C coverage merely by returning text.
audit = audit.replace('eligible_for_new_C_coverage=', 'eligible_for_new_C_coverage=False,diagnostic_candidate_returned=')
ast.parse(audit)
out.mkdir()
for p in parent.iterdir():
    if p.name not in ('source-manifest.json','TerrariaPortableBranchLongProbe.java','audit_terraria_portable_branch_long.py'):
        shutil.copyfile(p, out / p.name)
(out / 'TerrariaCopyRuleOffProbe.java').write_text(java, encoding='utf8', newline='\n')
(out / 'audit_terraria_copy_rule_off.py').write_text(audit, encoding='utf8', newline='\n')
manifest = json.loads((parent / 'source-manifest.json').read_text())
manifest.update(generator_sha256=sha(Path(__file__)), parent_producer_sha256=sha(parent/'TerrariaPortableBranchLongProbe.java'), diagnostic_only=True,
                source_files=[dict(name=p.name,sha256=sha(p)) for p in sorted(out.iterdir())])
(out / 'source-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
runner = (TOOLS / 'run_terraria_portable_branch_long.ps1').read_text()
assert sha(TOOLS / 'run_terraria_portable_branch_long.ps1') == 'f633bc466e87a7ce64c0cba5b9a83add14c38fcc82e6cfb9b77ccd6a97ae32d8'
for old,new in [('portable-branch-long','copy-rule-off'),('TerrariaPortableBranchLongProbe','TerrariaCopyRuleOffProbe'),('audit_terraria_portable_branch_long.py','audit_terraria_copy_rule_off.py')]:
    runner=runner.replace(old,new)
(TOOLS/'run_terraria_copy_rule_off.ps1').write_text(runner,encoding='utf8',newline='\n')
state = LAB/'portable-branch-long-kill-interruption-20261019.json'
assert not state.exists()
state.write_text(json.dumps(dict(status='interrupted_without_result', observed_UTC=__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(),
    original_state_preserved=True, native_timeout_confirmed=False, current_boot_local='2026-10-19T17:25:15+03:00',cause='unknown',C_coverage_addition=0),indent=2)+'\n')
print('Prepared isolated copy-rule-off diagnostic and preserved interruption sidecar.')
