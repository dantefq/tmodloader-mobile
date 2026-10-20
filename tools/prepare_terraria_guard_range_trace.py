"""Add range identity and nested guard timings to an isolated source snapshot."""
import difflib
import hashlib
import json
import re
import shutil
from pathlib import Path


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


lab = Path(r'C:\Temp\terraria-re-20261012')
parent = lab / 'portable-decompiler-heritage-trace-source-20261018'
manifest_path = parent / 'heritage-source-manifest.json'
assert sha(manifest_path) == 'd13118023be9d5f9cd7f507fc2b3fcf05d6001664a78e57b53c7063d4797bc85'
manifest = json.loads(manifest_path.read_text())
for row in manifest['source_files']:
    assert Path(row['path']).name == row['path']
    assert sha(parent / 'source' / row['path']) == row['sha256']
before = (parent / 'source/heritage.cc').read_text(encoding='utf8')
helper = r'''
namespace {
// Timing-only adapter: fixed stack buffer, no analysis-state mutation.
class TerrariaGuardRangeScope {
  char group[96];
  terraria_trace::Scope scope;
  static const char *format(char *out, const Address &addr, int4 size) noexcept {
    terraria_trace::PreserveErrno preserveErrno;
    std::snprintf(out,96,"%s@0x%llx+%d",addr.getSpace()->getName().c_str(),
                  static_cast<unsigned long long>(addr.getOffset()),static_cast<int>(size));
    return out;
  }
public:
  TerrariaGuardRangeScope(const char *kind,const char *name,Funcdata *fd,const Address &addr,int4 size) noexcept
    :scope(kind,name,format(group,addr,size),fd->getName().c_str(),fd->getAddress().getOffset()) {}
};
} // anonymous namespace
'''
assert before.count('namespace ghidra {') == 1
after = before.replace('namespace ghidra {', 'namespace ghidra {\n' + helper, 1)
for name in ('guard', 'guardInput'):
    old = 'terraria_trace::Scope terrariaHeritageScope("heritage","' + name + '","diagnostic",fd->getName().c_str(),fd->getAddress().getOffset());'
    new = 'TerrariaGuardRangeScope terrariaHeritageScope("heritage","' + name + '",fd,addr,size);'
    assert after.count(old) == 1
    after = after.replace(old, new, 1)
hooks = []
for name in ('guardCalls', 'guardStores', 'guardLoads', 'guardReturns'):
    pattern = r'(^[^\n]*\bHeritage::' + re.escape(name) + r'\([^)]*\)\s*\n\s*\{)'
    matches = list(re.finditer(pattern, after, re.MULTILINE))
    assert len(matches) == 1, name
    match = matches[0]
    added = '\n  TerrariaGuardRangeScope terrariaGuardScope("guard-detail","' + name + '",fd,addr,size);'
    after = after[:match.end()] + added + after[match.end():]
    hooks.append(dict(name=name, added_text=added))
# Round-trip removes all new adapter code and restores the exact parent source.
restored = after.replace('\n' + helper, '', 1)
for name in ('guard', 'guardInput'):
    restored = restored.replace('TerrariaGuardRangeScope terrariaHeritageScope("heritage","' + name + '",fd,addr,size);',
                                'terraria_trace::Scope terrariaHeritageScope("heritage","' + name + '","diagnostic",fd->getName().c_str(),fd->getAddress().getOffset());', 1)
for hook in hooks:
    restored = restored.replace(hook['added_text'], '', 1)
assert restored == before
out = lab / 'portable-decompiler-guard-range-source-20261019'
assert not out.exists()
out.mkdir()
shutil.copytree(parent / 'source', out / 'source')
(out / 'source/heritage.cc').write_text(after, encoding='utf8', newline='\n')
(out / 'guard-range-only.patch').write_text(''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='heritage/heritage.cc',tofile='guard-range/heritage.cc')), encoding='utf8')
record = dict(parent_manifest_sha256=sha(manifest_path), generator_sha256=sha(Path(__file__)),
              modified_relative_to_parent=['heritage.cc'], sources=manifest['sources'],
              source_files=[dict(path=p.name, bytes=p.stat().st_size, sha256=sha(p)) for p in sorted((out / 'source').iterdir())],
              new_nested_guard_hooks=[r['name'] for r in hooks], ranged_existing_hooks=['guard','guardInput'],
              exact_parent_text_restored_by_removing_instrumentation=True,
              analysis_calls_or_options_changed=False, trace_limits_unchanged=True,
              range_group_format='space@0xOFFSET+SIZE; address-space offset, not automatically an ELF virtual address',
              engine_executed=False, C_coverage_addition=0)
(out / 'heritage-source-manifest.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(dict(source_snapshot=str(out), parent_text_roundtrip=True)))
