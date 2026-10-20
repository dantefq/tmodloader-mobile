"""Prepare a pinned 1800-second branch-preserving profile; no engine execution."""
import ast
import hashlib
import json
import shutil
from pathlib import Path


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def one(text, old, new):
    assert text.count(old) == 1, old[:100]
    return text.replace(old, new, 1)


lab = Path(r'C:\Temp\terraria-re-20261012')
tools = Path(__file__).resolve().parent
parent = tools / 'TerrariaBranchPreservingCProbe.java'
auditor = tools / 'audit_terraria_branch_preserving_c.py'
parent_sha = '635ba766f3ef0371f9b13882acd818e3cfa0e98a81048de3605d0b96f5192eed'
assert sha(parent) == parent_sha
assert sha(auditor) == '16967bb4a9475fb792a5e70f76ffe8b9bc6bcd98e2d3b21059947f066698d09e'
engine = 'd64bd049b88d8d2f9452b92079705d4e95b71abb0aad018f596f143246f9f67a'
assert sha(lab / 'ghidra-guard-range-20261019/Ghidra/Features/Decompiler/os/win_x86_64/decompile.exe') == engine
build = lab / 'portable-decompiler-guard-range-source-20261019/incremental-build-20261019/build-manifest.json'
pe = lab / 'pe-review-guard-range-20261019.json'
identities = [
    ('TerrariaBranchPreservingCProbe', 'TerrariaPortableBranchLongProbe'),
    ('audit_terraria_branch_preserving_c.py', 'audit_terraria_portable_branch_long.py'),
    ('pseudocode-branch-preserving-c-', 'pseudocode-portable-branch-long-c-'),
    ('smoke-20261016', 'smoke-20261019'),
    ('verified-known-islands-conditional-noreturn-branch-preserving-C-v4-stack32-v1', 'portable-branch-preserving-long-C-v1'),
]
java, audit = parent.read_text(), auditor.read_text()
for old, new in identities:
    java, audit = java.replace(old, new), audit.replace(old, new)
fields = dict(derived_from_branch_preserving_sha256=parent_sha, engine_changed=True,
              portable_engine_build_sha256=sha(build), portable_engine_PE_review_sha256=sha(pe),
              branch_action_groups_unchanged=True, hard_timeout_changed_from_600_to_1800=True)
properties = ''.join('rec.addProperty(' + json.dumps(k) + ',' + json.dumps(v) + ');' for k, v in fields.items())
changes = [
    ('public class TerrariaPortableBranchLongProbe extends TerrariaCoarseCopiesProbe {',
     'public class TerrariaPortableBranchLongProbe extends TerrariaCoarseCopiesProbe {\n    static final String ENGINE="' + engine + '";'),
    ('smoke?60:600', 'smoke?60:1800'),
    ('JsonObject rec=new JsonObject();', 'JsonObject rec=new JsonObject();' + properties),
]
for old, new in changes:
    assert old in java
    java = java.replace(old, new)
audit = one(audit, "ENGINE='1fd85827247f1ff1417fa412db26a53066d050c59017db98dd23ff196751521e'", "ENGINE='" + engine + "'")
audit = one(audit, "else 600)", "else 1800)")
audit = one(audit, 'timeout_seconds=600,status=', 'timeout_seconds=1800,status=')
extra = ''.join('    assert r[' + repr(k) + ']==' + repr(v) + '\n' for k, v in fields.items())
audit = one(audit, 'def model_record(r):\n', 'def model_record(r):\n' + extra)
audit = one(audit, '        model_record(good)\n', '        good.update(' + repr(fields) + ')\n        model_record(good)\n')
# Independently reconstruct every producer byte from a separately pinned parent.
validation = "    branch_parent=a.producer.with_name('TerrariaBranchPreservingCProbe.java').read_bytes()\n"
validation += '    assert sha(branch_parent)==' + repr(parent_sha) + '\n    expected=branch_parent.decode()\n'
for old, new in identities + changes:
    validation += '    expected=expected.replace(' + repr(old) + ',' + repr(new) + ')\n'
validation += "    assert a.producer.read_text()==expected,'Unexpected branch profile change'\n"
anchor = "    assert a.producer.name=='TerrariaPortableBranchLongProbe.java'\n"
audit = one(audit, anchor, anchor + validation)
ast.parse(audit)
out = lab / 'portable-branch-long-sources-20261019'
assert not out.exists()
out.mkdir()
(out / 'TerrariaPortableBranchLongProbe.java').write_text(java, encoding='utf8', newline='\n')
(out / 'audit_terraria_portable_branch_long.py').write_text(audit, encoding='utf8', newline='\n')
for name in ('TerrariaBranchPreservingCProbe.java', 'TerrariaCoarseCopiesProbe.java',
             'TerrariaExtendedNoreturnProbe.java', 'TerrariaUntypedCProbe.java',
             'audit_terraria_nullguard_noreturn_model.py'):
    shutil.copyfile(tools / name, out / name)
(out / 'source-manifest.json').write_text(json.dumps(dict(
    generator_sha256=sha(Path(__file__)), engine_sha256=engine, fields=fields,
    source_files=[dict(name=p.name, sha256=sha(p)) for p in sorted(out.iterdir())],
    engine_executed=False, original_branch_plan_complete=False, C_coverage_addition=0), indent=2) + '\n')
print('Prepared separate branch-preserving long-budget profile; actual same-source smoke remains required.')
