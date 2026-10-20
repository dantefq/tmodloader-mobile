"""Deploy a separate heritage trace engine and derive pinned off/on profiles."""
import hashlib
import json
import shutil
from pathlib import Path
from prepare_terraria_portable_smoke_sources import templates, HELPERS, replace_once


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


lab = Path(r'C:\Temp\terraria-re-20261012')
tools = Path(__file__).resolve().parent
trace = lab / 'portable-decompiler-heritage-trace-source-20261018'
build = trace / 'incremental-build-20261018/build-manifest.json'
engine = trace / 'incremental-build-20261018/decompile.exe'
pepath = lab / 'pe-review-heritage-trace-20261019.json'
record = json.loads(build.read_text())
pe = json.loads(pepath.read_text())
assert sha(engine) == record['engine_sha256'] == pe['sha256'] == 'c9ce16f3525a4a1c75ba694440307db312f93874f444f828516ab0a3da69c02a'
assert pe['header_gates_passed'] and len(record['objects']) == 79
assert [r['source'] for r in record['objects'] if r['rebuilt']] == ['heritage.cc']
for obj in record['objects']:
    assert sha(Path(obj['object'])) == obj['sha256']
assert sha(tools / 'prepare_terraria_portable_smoke_sources.py') == '513f51f8dc62dafaf682a7e444425e7ba7b1b660d9f8008762cfd8450f3781b3'
dest = lab / 'ghidra-heritage-trace-20261019'
assert not dest.exists()
shutil.copytree(lab / 'ghidra-portable-trace-20261018', dest)
osdir = dest / 'Ghidra/Features/Decompiler/os/win_x86_64'
shutil.copy2(engine, osdir / 'decompile.exe')
assert sha(osdir / 'decompile.exe') == sha(engine)
for name, expected in {
    'libc++.dll': '06a2ed158f5a91e4d500c8b0764a25dfe57097991d137d8272c529eeb5c66048',
    'libunwind.dll': 'aa282fa47bb2c4e210cea5e470cdbdca58568f0be0bc73e404d86ab9cd95ef6a',
}.items():
    assert sha(osdir / name) == expected
for mode in ('off', 'on'):
    folder = lab / ('heritage-' + mode + '-sources-20261019')
    assert not folder.exists()
    java, audit, fields = templates(tools, sha(engine), sha(build), sha(pepath))
    cls = 'TerrariaHeritage' + mode.title() + 'Probe'
    auditor = 'audit_terraria_heritage_' + mode + '.py'
    for old, new in (
        ('TerrariaPortableBaselineCSmoke', cls),
        ('audit_terraria_portable_baseline_c_smoke.py', auditor),
        ('portable-baseline-conditional-untyped-C-smoke-v1', 'heritage-' + mode + '-conditional-untyped-C-v1'),
        ('pseudocode-portable-baseline-c-', 'pseudocode-heritage-' + mode + '-c-'),
    ):
        java, audit = java.replace(old, new), audit.replace(old, new)
    if mode == 'on':
        restriction = 'if(!smoke)throw new Exception("Portable baseline restricted to C smoke");'
        java = replace_once(java, restriction, '')
        audit = replace_once(audit, '    assert a.producer.read_text()==expected,',
                            '    expected=expected.replace(' + repr(restriction) + ', "")\n    assert a.producer.read_text()==expected,')
        audit = replace_once(audit, '        assert a.address==SMOKE and a.folder==SMOKE_FOLDER\n', '')
    folder.mkdir()
    (folder / (cls + '.java')).write_text(java, encoding='utf8', newline='\n')
    (folder / auditor).write_text(audit, encoding='utf8', newline='\n')
    for name in HELPERS:
        shutil.copyfile(tools / name, folder / name)
    (folder / 'source-manifest.json').write_text(json.dumps(dict(
        generator_sha256=sha(Path(__file__)), engine_sha256=sha(engine), fields=fields,
        source_files=[dict(name=f.name, sha256=sha(f)) for f in sorted(folder.iterdir())],
        engine_executed=False, eligible_for_new_C_coverage=False), indent=2) + '\n')
print('Isolated heritage deployment and off/on source profiles prepared; no engine executed.')
