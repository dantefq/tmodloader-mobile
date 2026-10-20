"""Derive a one-unit range-trace build with pinned parent objects and supervisor."""
import hashlib
import json
from pathlib import Path

lab = Path(r'C:\Temp\terraria-re-20261012')
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
source = lab / 'portable-decompiler-heritage-trace-source-20261018/build-heritage-trace.ps1'
assert sha(source) == 'afd671ba47b820c1be4ddd73fc06ce836e96793ec6baf3814144e03a0e6dc3f6'
dest = lab / 'portable-decompiler-guard-range-source-20261019'
manifest = dest / 'heritage-source-manifest.json'
text = source.read_text()
for old, new in (
    ('$terrariaTrace="$terrariaLab/portable-decompiler-heritage-trace-source-20261018"', '$terrariaTrace="$terrariaLab/portable-decompiler-guard-range-source-20261019"'),
    ('$terrariaParent="$terrariaLab/portable-decompiler-trace-source-20261017"', '$terrariaParent="$terrariaLab/portable-decompiler-heritage-trace-source-20261018"'),
    ('d13118023be9d5f9cd7f507fc2b3fcf05d6001664a78e57b53c7063d4797bc85', sha(manifest)),
    ('34d75f09cd070c2149be8509dd84f67f32d48038d87f26a3540a8c0a3b8899a7', 'c9ce16f3525a4a1c75ba694440307db312f93874f444f828516ab0a3da69c02a'),
    ('$terrariaBuild="$terrariaTrace/incremental-build-20261018"', '$terrariaBuild="$terrariaTrace/incremental-build-20261019"'),
):
    assert text.count(old) == 1, old
    text = text.replace(old, new, 1)
out = dest / 'build-guard-range.ps1'
assert not out.exists()
out.write_text(text, encoding='utf8', newline='\n')
(dest / 'guard-range-builder-provenance.json').write_text(json.dumps(dict(
    parent_builder_sha256=sha(source), builder_sha256=sha(out), source_manifest_sha256=sha(manifest),
    generator_sha256=sha(Path(__file__)), changed_units=['heritage.cc'], reused_units=78,
    compile_and_link_flags_changed=False, engine_executed=False), indent=2) + '\n')
print(str(out))
