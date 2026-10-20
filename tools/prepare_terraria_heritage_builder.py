"""Derive a separately pinned one-unit heritage trace build; no compilation."""
import hashlib
import json
from pathlib import Path


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


lab = Path(r'C:\Temp\terraria-re-20261012')
parent = Path(__file__).with_name('build_terraria_trace_incremental.ps1')
assert sha(parent) == 'ef424ef32e72d4a58b32884352b26a23af85ef35b7a2d4ad5e06898871df290b'
dest = lab / 'portable-decompiler-heritage-trace-source-20261018'
manifest = dest / 'heritage-source-manifest.json'
text = parent.read_text()
replacements = [
    ('# Builds two trace-only units against the verified 77 remaining baseline objects.', '# Builds heritage.cc against 78 verified parent trace objects. Never executes an engine.'),
    ("$terrariaTrace=\"$terrariaLab/portable-decompiler-trace-source-20261017\"", "$terrariaTrace=\"$terrariaLab/portable-decompiler-heritage-trace-source-20261018\"\n$terrariaParent=\"$terrariaLab/portable-decompiler-trace-source-20261017\""),
    ("'66032dc9194647d8b9b2296b6d53168ade2dc22bea62e00b313171804e01ce7b'", repr(sha(manifest))),
    ('trace-source-manifest.json', 'heritage-source-manifest.json'),
    ('$terrariaBaseline=Get-Content "$terrariaBase/baseline-build/build-manifest.json"', '$terrariaBaseline=Get-Content "$terrariaParent/incremental-build-20261018/build-manifest.json"'),
    ("'5d39674818484db40000dd0a3171493661ed6e3efd01a80de47cc21321eac40c'", "'34d75f09cd070c2149be8509dd84f67f32d48038d87f26a3540a8c0a3b8899a7'"),
    ('$terrariaBaseline.compiled', '$terrariaBaseline.objects'),
    ('$terrariaSnapshot.trace_snapshot_files', '$terrariaSnapshot.source_files'),
    ('baseline_manifest_sha256=(Get-TerrariaHash "$terrariaBase/baseline-build/build-manifest.json")', 'parent_build_manifest_sha256=(Get-TerrariaHash "$terrariaParent/incremental-build-20261018/build-manifest.json")'),
    ('$terrariaObject="$terrariaBase/baseline-build/$terrariaStem.o"', '$terrariaObject=[string]$terrariaRow.object'),
    ('$terrariaRow.object_sha256', '$terrariaRow.sha256'),
    ("@('action.cc','ghidra_process.cc')", "@('heritage.cc')"),
]
for old, new in replacements:
    assert old in text, old
    text = text.replace(old, new)
out = dest / 'build-heritage-trace.ps1'
assert not out.exists()
out.write_text(text, encoding='utf8', newline='\n')
(dest / 'heritage-builder-provenance.json').write_text(json.dumps(dict(
    generator_sha256=sha(Path(__file__)), parent_builder_sha256=sha(parent),
    builder_sha256=sha(out), source_manifest_sha256=sha(manifest),
    changed_units=['heritage.cc'], reused_units=78, compile_and_link_flags_changed=False,
    compiler_invoked=False, engine_executed=False), indent=2) + '\n')
print(str(out))
