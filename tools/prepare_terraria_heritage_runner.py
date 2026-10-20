"""Derive the heritage runner by changing only pinned profile/deployment paths."""
import hashlib
import json
from pathlib import Path

tools = Path(__file__).resolve().parent
source = tools / 'run_terraria_trace_diagnostic.ps1'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(source) == '69b37d0f0a64346636ac46662c026b3b7367b9cddf4ca7a7e44966ff80329a4e'
text = source.read_text()
for old, new in (
    ('audit_terraria_portable_trace_diagnostic.py', 'audit_terraria_heritage_on.py'),
    ('TerrariaPortableTraceDiagnostic', 'TerrariaHeritageOnProbe'),
    ('portable-trace-diagnostic', 'heritage-on'),
    ('heritage-on-sources-20261018', 'heritage-on-sources-20261019'),
    ('heritage-on-$terrariaName-20261018', 'heritage-on-$terrariaName-20261019'),
    ('heritage-on-$terrariaName-launch-20261018', 'heritage-on-$terrariaName-launch-20261019'),
    ('ghidra-portable-trace-20261018', 'ghidra-heritage-trace-20261019'),
    ('ghidra-appdata-portable-trace', 'ghidra-appdata-heritage-20261019'),
):
    assert old in text, old
    text = text.replace(old, new)
dest = tools / 'run_terraria_heritage_diagnostic.ps1'
assert not dest.exists()
dest.write_text(text, encoding='utf8', newline='\n')
lab = Path(r'C:\Temp\terraria-re-20261012')
(lab / 'heritage-runner-provenance-20261019.json').write_text(json.dumps(dict(
    parent_sha256=sha(source), runner_sha256=sha(dest), generator_sha256=sha(Path(__file__)),
    supervisor_policy_changed=False, engine_executed=False), indent=2) + '\n')
print(str(dest))
