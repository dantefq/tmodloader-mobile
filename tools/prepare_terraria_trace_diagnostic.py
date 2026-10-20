"""Prepare a separate full-method diagnostic profile; never launch an engine."""
import hashlib
import json
import shutil
from pathlib import Path
from prepare_terraria_portable_smoke_sources import templates, HELPERS, replace_once


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


lab = Path(r'C:\Temp\terraria-re-20261012')
tools = Path(__file__).resolve().parent
trace = lab / 'portable-decompiler-trace-source-20261017'
build = trace / 'incremental-build-20261018/build-manifest.json'
pe = lab / 'pe-review-portable-trace-20261018.json'
engine = trace / 'incremental-build-20261018/decompile.exe'
assert sha(engine) == '34d75f09cd070c2149be8509dd84f67f32d48038d87f26a3540a8c0a3b8899a7'
for mode in ('off', 'on'):
    audit = json.loads((lab / ('pseudocode-portable-trace-' + mode + '-c-smoke-20261017/audit.json')).read_text())
    assert audit['integrity_passed'] and audit['c_smoke']
    assert sha(lab / ('pseudocode-portable-trace-' + mode + '-c-smoke-20261017/conditional_candidate.c')) == 'd6d0d7351117938b7514d03b94a0c2398c60c12b71f1ea1b774f744d19d63cf9'
java, auditor, fields = templates(tools, sha(engine), sha(build), sha(pe))
for old, new in (
    ('TerrariaPortableBaselineCSmoke', 'TerrariaPortableTraceDiagnostic'),
    ('audit_terraria_portable_baseline_c_smoke.py', 'audit_terraria_portable_trace_diagnostic.py'),
    ('portable-baseline-conditional-untyped-C-smoke-v1', 'portable-trace-diagnostic-conditional-untyped-C-v1'),
    ('pseudocode-portable-baseline-c-', 'pseudocode-portable-trace-diagnostic-c-'),
):
    java, auditor = java.replace(old, new), auditor.replace(old, new)
restriction = 'if(!smoke)throw new Exception("Portable baseline restricted to C smoke");'
assert java.count(restriction) == 1
java = java.replace(restriction, '')
# The auditor independently reconstructs the same explicit restriction removal.
auditor = replace_once(auditor, '    assert a.producer.read_text()==expected,',
                      '    expected=expected.replace(' + repr(restriction) + ', "")\n    assert a.producer.read_text()==expected,')
auditor = replace_once(auditor, '        assert a.address==SMOKE and a.folder==SMOKE_FOLDER\n', '')
out = lab / 'portable-trace-diagnostic-sources-20261018'
assert not out.exists()
out.mkdir()
(out / 'TerrariaPortableTraceDiagnostic.java').write_text(java, encoding='utf8', newline='\n')
(out / 'audit_terraria_portable_trace_diagnostic.py').write_text(auditor, encoding='utf8', newline='\n')
for name in HELPERS:
    shutil.copyfile(tools / name, out / name)
(out / 'source-manifest.json').write_text(json.dumps(dict(
    generator_sha256=sha(Path(__file__)), engine_sha256=sha(engine),
    fields=fields, source_files=[dict(name=p.name, sha256=sha(p)) for p in sorted(out.iterdir())],
    only_change_to_smoke_restriction='Allow frozen reviewed target addresses; same-source actual smoke remains mandatory.',
    native_timeout_seconds=1800, external_diagnostic_deadline_is_separate=True,
    eligible_for_new_C_coverage=False, engine_executed=False), indent=2) + '\n')
print('Diagnostic profile prepared; actual same-source smoke required before hard targets.')
