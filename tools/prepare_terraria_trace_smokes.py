"""Prepare separate trace-engine deployment and off/on smoke sources; no execution."""
import hashlib
import json
import shutil
from pathlib import Path
from prepare_terraria_portable_smoke_sources import templates, HELPERS


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


lab = Path(r'C:\Temp\terraria-re-20261012')
tools = Path(__file__).resolve().parent
trace = lab / 'portable-decompiler-trace-source-20261017'
build = trace / 'incremental-build-20261018/build-manifest.json'
pepath = lab / 'pe-review-portable-trace-20261018.json'
engine = trace / 'incremental-build-20261018/decompile.exe'
pe = json.loads(pepath.read_text())
record = json.loads(build.read_text())
assert sha(engine) == record['engine_sha256'] == pe['sha256'] == '34d75f09cd070c2149be8509dd84f67f32d48038d87f26a3540a8c0a3b8899a7'
assert pe['header_gates_passed'] and record['status'] == 'linked_uninspected_unexecuted'
assert len(record['objects']) == 79
assert [r['source'] for r in record['objects'] if r['rebuilt']] == ['action.cc', 'ghidra_process.cc']
for obj in record['objects']:
    assert sha(Path(obj['object'])) == obj['sha256']
assert sha(tools / 'prepare_terraria_portable_smoke_sources.py') == '513f51f8dc62dafaf682a7e444425e7ba7b1b660d9f8008762cfd8450f3781b3'
destination = lab / 'ghidra-portable-trace-20261018'
assert not destination.exists()
shutil.copytree(lab / 'ghidra-portable-baseline-20261018', destination)
osdir = destination / 'Ghidra/Features/Decompiler/os/win_x86_64'
shutil.copy2(engine, osdir / 'decompile.exe')
assert sha(osdir / 'decompile.exe') == sha(engine)
sources = []
for mode in ('off', 'on'):
    out = lab / ('portable-trace-' + mode + '-smoke-sources-20261018')
    assert not out.exists()
    java, audit, fields = templates(tools, sha(engine), sha(build), sha(pepath))
    for old, new in (
        ('TerrariaPortableBaselineCSmoke', 'TerrariaPortableTrace' + mode.title() + 'CSmoke'),
        ('audit_terraria_portable_baseline_c_smoke.py', 'audit_terraria_portable_trace_' + mode + '_c_smoke.py'),
        ('portable-baseline', 'portable-trace-' + mode),
    ):
        java, audit = java.replace(old, new), audit.replace(old, new)
    out.mkdir()
    (out / ('TerrariaPortableTrace' + mode.title() + 'CSmoke.java')).write_text(java, encoding='utf8', newline='\n')
    (out / ('audit_terraria_portable_trace_' + mode + '_c_smoke.py')).write_text(audit, encoding='utf8', newline='\n')
    for helper in HELPERS:
        shutil.copyfile(tools / helper, out / helper)
    sources.append(dict(mode=mode, path=str(out), files=[dict(name=f.name, sha256=sha(f)) for f in sorted(out.iterdir())]))
(lab / 'portable-trace-smoke-preparation-20261018.json').write_text(json.dumps(dict(
    engine_sha256=sha(engine), generator_sha256=sha(Path(__file__)),
    build_manifest_sha256=sha(build), PE_review_sha256=sha(pepath),
    deployment=str(destination), sources=sources, engine_executed=False,
    trace_environment_variable='TERRARIA_DECOMP_TRACE_FILE', C_coverage_addition=0), indent=2) + '\n')
print('Separate trace deployment and off/on sources prepared; no engine executed.')
