"""Prepare separately pinned range-trace runtime/profiles and inherited runners."""
import hashlib
import json
import shutil
from pathlib import Path
from prepare_terraria_portable_smoke_sources import templates, HELPERS, replace_once


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


lab = Path(r'C:\Temp\terraria-re-20261012')
tools = Path(__file__).resolve().parent
source = lab / 'portable-decompiler-guard-range-source-20261019'
build = source / 'incremental-build-20261019/build-manifest.json'
engine = source / 'incremental-build-20261019/decompile.exe'
pepath = lab / 'pe-review-guard-range-20261019.json'
record = json.loads(build.read_text())
pe = json.loads(pepath.read_text())
assert sha(engine) == record['engine_sha256'] == pe['sha256'] == 'd64bd049b88d8d2f9452b92079705d4e95b71abb0aad018f596f143246f9f67a'
assert record['status'] == 'linked_uninspected_unexecuted' and pe['header_gates_passed'] and not pe['static_gate_failures']
assert pe['inspector_sha256'] == 'fcecf18468c6c0568eca73c8cd1250f287ca81f7cb26199b69815518e36a78e8'
assert len(record['objects']) == 79 and [r['source'] for r in record['objects'] if r['rebuilt']] == ['heritage.cc']
for obj in record['objects']:
    assert sha(Path(obj['object'])) == obj['sha256']
dest = lab / 'ghidra-guard-range-20261019'
assert not dest.exists()
shutil.copytree(lab / 'ghidra-heritage-trace-20261019', dest)
osdir = dest / 'Ghidra/Features/Decompiler/os/win_x86_64'
shutil.copy2(engine, osdir / 'decompile.exe')
assert sha(osdir / 'decompile.exe') == sha(engine)
for name, expected in {
    'libc++.dll': '06a2ed158f5a91e4d500c8b0764a25dfe57097991d137d8272c529eeb5c66048',
    'libunwind.dll': 'aa282fa47bb2c4e210cea5e470cdbdca58568f0be0bc73e404d86ab9cd95ef6a',
}.items():
    assert sha(osdir / name) == expected
for mode in ('off', 'on'):
    out = lab / ('guard-range-' + mode + '-sources-20261019')
    assert not out.exists()
    java, audit, fields = templates(tools, sha(engine), sha(build), sha(pepath))
    cls = 'TerrariaGuardRange' + mode.title() + 'Probe'
    auditor = 'audit_terraria_guard_range_' + mode + '.py'
    for old, new in (
        ('TerrariaPortableBaselineCSmoke', cls),
        ('audit_terraria_portable_baseline_c_smoke.py', auditor),
        ('portable-baseline-conditional-untyped-C-smoke-v1', 'guard-range-' + mode + '-conditional-untyped-C-v1'),
        ('pseudocode-portable-baseline-c-', 'pseudocode-guard-range-' + mode + '-c-'),
    ):
        java, audit = java.replace(old, new), audit.replace(old, new)
    if mode == 'on':
        restriction = 'if(!smoke)throw new Exception("Portable baseline restricted to C smoke");'
        java = replace_once(java, restriction, '')
        audit = replace_once(audit, '    assert a.producer.read_text()==expected,',
                            '    expected=expected.replace(' + repr(restriction) + ', "")\n    assert a.producer.read_text()==expected,')
        audit = replace_once(audit, '        assert a.address==SMOKE and a.folder==SMOKE_FOLDER\n', '')
    out.mkdir()
    (out / (cls + '.java')).write_text(java, encoding='utf8', newline='\n')
    (out / auditor).write_text(audit, encoding='utf8', newline='\n')
    for name in HELPERS:
        shutil.copyfile(tools / name, out / name)
    (out / 'source-manifest.json').write_text(json.dumps(dict(
        generator_sha256=sha(Path(__file__)), engine_sha256=sha(engine), fields=fields,
        source_files=[dict(name=f.name, sha256=sha(f)) for f in sorted(out.iterdir())],
        engine_executed=False, eligible_for_new_C_coverage=False), indent=2) + '\n')
parents = {}
for name in ('smokes', 'diagnostic'):
    parent = tools / ('run_terraria_heritage_' + name + '.ps1')
    text = parent.read_text()
    if name == 'diagnostic':
        assert sha(parent) == '05f50408e8029f1a1c4c9d51c9225146cb0e6ebdd13d34d15525c0237970eb87'
    text = text.replace('TerrariaHeritage', 'TerrariaGuardRange').replace('audit_terraria_heritage_', 'audit_terraria_guard_range_')
    text = text.replace('heritage-', 'guard-range-')
    text = text.replace('ghidra-guard-range-trace-20261019', 'ghidra-guard-range-20261019')
    runner = tools / ('run_terraria_guard_range_' + name + '.ps1')
    assert not runner.exists()
    runner.write_text(text, encoding='utf8', newline='\n')
    parents[name] = dict(parent_sha256=sha(parent), runner_sha256=sha(runner))
(lab / 'guard-range-runtime-provenance-20261019.json').write_text(json.dumps(dict(
    generator_sha256=sha(Path(__file__)), engine_sha256=sha(engine),
    inherited_runners=parents, supervisor_policy_changed=False, engine_executed=False), indent=2) + '\n')
print('Isolated deployment, off/on profiles and inherited runners prepared; no execution.')
