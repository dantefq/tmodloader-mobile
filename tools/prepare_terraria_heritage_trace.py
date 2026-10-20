"""Prepare deeper heritage timing hooks without changing analysis calls or flags."""
import difflib
import hashlib
import json
import re
import shutil
from pathlib import Path


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


lab = Path(r'C:\Temp\terraria-re-20261012')
parent = lab / 'portable-decompiler-trace-source-20261017'
manifest_path = parent / 'trace-source-manifest.json'
assert sha(manifest_path) == '66032dc9194647d8b9b2296b6d53168ade2dc22bea62e00b313171804e01ce7b'
manifest = json.loads(manifest_path.read_text())
for row in manifest['trace_snapshot_files']:
    assert Path(row['path']).name == row['path']
    assert sha(parent / 'source' / row['path']) == row['sha256']
original = (parent / 'source/heritage.cc').read_text(encoding='utf8')
assert original.count('#include "heritage.hh"') == 1
after = original.replace('#include "heritage.hh"', '#include "heritage.hh"\n#include "terraria_action_trace.hh"', 1)
hooks = []
for name in ('buildADT', 'processJoins', 'discoverIndexedStackPointers', 'collect',
             'refinement', 'guardInput', 'guard', 'calcMultiequals',
             'placeMultiequals', 'rename', 'reprocessFreeStores',
             'analyzeNewLoadGuards', 'handleNewLoadCopies'):
    pattern = r'(^[^\n]*\bHeritage::' + re.escape(name) + r'\([^)]*\)(?: const)?\s*\n\s*\{)'
    found = list(re.finditer(pattern, after, re.MULTILINE))
    assert len(found) == 1, (name, len(found))
    match = found[0]
    insert = '\n  terraria_trace::Scope terrariaHeritageScope("heritage","' + name + '","diagnostic",fd->getName().c_str(),fd->getAddress().getOffset());'
    after = after[:match.end()] + insert + after[match.end():]
    hooks.append(name)
out = lab / 'portable-decompiler-heritage-trace-source-20261018'
assert not out.exists()
out.mkdir()
shutil.copytree(parent / 'source', out / 'source')
(out / 'source/heritage.cc').write_text(after, encoding='utf8', newline='\n')
patch = ''.join(difflib.unified_diff(original.splitlines(True), after.splitlines(True), fromfile='trace/heritage.cc', tofile='heritage-trace/heritage.cc'))
(out / 'heritage-trace-only.patch').write_text(patch, encoding='utf8', newline='\n')
rows = [dict(path=f.name, bytes=f.stat().st_size, sha256=sha(f)) for f in sorted((out / 'source').iterdir())]
record = dict(parent_manifest_sha256=sha(manifest_path), generator_sha256=sha(Path(__file__)),
              modified_relative_to_parent=['heritage.cc'], hooks=hooks,
              source_files=rows, sources=manifest['sources'],
              previous_trace_modifications_retained=['action.cc', 'ghidra_process.cc', 'terraria_action_trace.hh'],
              compile_or_execution_performed=False, analysis_calls_or_options_changed=False,
              trace_limits_unchanged=True, C_coverage_addition=0)
(out / 'heritage-source-manifest.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(dict(source_snapshot=str(out), hooks=hooks, engine_executed=False)))
