"""Prepare explicit, disjoint FDE/symbol ranges for other APK libraries."""
import bisect
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from terraria_native_map import ELF

LAB=Path(r'C:\Temp\terraria-re-20261012')
DELIVERY=Path(r'C:/Private\Documents\ChatGPT\Terraria-Reverse-20261012')
INV=LAB/'apk-native-scope-inventory-20261019'
OUT=LAB/'other-native-range-manifests-20261019'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
digest=lambda b:hashlib.sha256(b).hexdigest()
assert not OUT.exists()
OUT.mkdir()
inventory=json.loads((INV/'summary.json').read_text())
summaries=[]
for lib in inventory['libraries']:
    name=lib['name']
    if name=='libil2cpp.so':continue
    binary=DELIVERY/'android-native'/name
    assert sha(binary)==lib['sha256']
    elf=ELF(binary.read_bytes())
    fdes=[json.loads(l) for l in (INV/(name+'.fde-ranges.jsonl')).read_text().splitlines()]
    primary=sorted((int(r['address'],16),int(r['end_exclusive'],16),r) for r in fdes)
    assert all(lo<hi for lo,hi,_ in primary)
    assert all(a[1]<=b[0] for a,b in zip(primary,primary[1:]))
    starts=[p[0] for p in primary]
    def overlaps_fde(lo,hi):
        at=bisect.bisect_left(starts,hi)-1
        return at>=0 and primary[at][1]>lo
    def executable(lo,hi):
        return any(s['flags']&4 and s['vaddr']<=lo<hi<=s['vaddr']+s['size'] for s in elf.sections)
    def record(lo,hi,kind,label):
        assert lo%4==0 and hi%4==0 and executable(lo,hi)
        offset=elf.file_offset(lo)
        assert elf.file_offset(hi-1)==offset+hi-lo-1
        return dict(address=hex(lo),end_exclusive=hex(hi),file_offset=hex(offset),
                    source_sha256=digest(elf.data[offset:offset+hi-lo]),evidence_kind=kind,name=label)
    rows=[record(lo,hi,'fde','FDE_'+hex(lo)) for lo,hi,_ in primary]
    symbols=[json.loads(l) for l in (INV/(name+'.dynamic-function-symbols.jsonl')).read_text().splitlines()]
    grouped=defaultdict(list);unknown=[]
    for s in symbols:grouped[int(s['address'],16)].append(s)
    candidates=[]
    for lo,aliases in grouped.items():
        ends={lo+s['size'] for s in aliases if s['size']>0}
        if len(ends)!=1:
            unknown.append(dict(address=hex(lo),reason='zero_or_conflicting_symbol_sizes',symbols=aliases));continue
        hi=ends.pop()
        if overlaps_fde(lo,hi):
            unknown.append(dict(address=hex(lo),end_exclusive=hex(hi),reason='already_overlaps_primary_FDE',symbols=aliases));continue
        if lo%4 or hi%4 or not executable(lo,hi):
            unknown.append(dict(address=hex(lo),reason='extent_not_aligned_or_not_in_executable_section',symbols=aliases));continue
        candidates.append((lo,hi,aliases))
    candidates.sort()
    conflicts=set();furthest=-1;active=[]
    for index,(lo,hi,aliases) in enumerate(candidates):
        active=[i for i in active if candidates[i][1]>lo]
        if active:conflicts.add(index);conflicts.update(active)
        active.append(index)
    for index,(lo,hi,aliases) in enumerate(candidates):
        if index in conflicts:
            unknown.append(dict(address=hex(lo),end_exclusive=hex(hi),reason='overlapping_nonFDE_symbol_extents',symbols=aliases))
        else:rows.append(record(lo,hi,'defined_function_symbol',aliases[0]['name']))
    rows.sort(key=lambda r:int(r['address'],16))
    assert all(int(a['end_exclusive'],16)<=int(b['address'],16) for a,b in zip(rows,rows[1:]))
    manifest=dict(schema_version=1,profile='apk-native-bounded-range-C-v1',binary_path=str(binary),elf_sha256=lib['sha256'],
        engine_sha256='d64bd049b88d8d2f9452b92079705d4e95b71abb0aad018f596f143246f9f67a',
        limits=dict(timeout_seconds=20,max_instructions=100000,max_payload_mb=64),
        inventory_sha256=sha(INV/'summary.json'),generator_sha256=sha(Path(__file__)),
        unwind_carrier_sha256=sha(INV/(name+'.fde-ranges.jsonl')),
        symbol_carrier_sha256=sha(INV/(name+'.dynamic-function-symbols.jsonl')),rows=rows,
        assumptions='Bounded compiler unwind or positive-sized defined dynamic-function symbol extents only. Aliases deduplicated; overlaps/conflicting sizes omitted from extra symbol queue. No inferred terminal CALL_RETURN, NoReturn, switch or flow overrides. Imported external prototypes remain inferred; C presence is not semantic equivalence, original source or buildability.')
    output=OUT/(name+'.manifest.json');output.write_text(json.dumps(manifest,indent=2)+'\n')
    (OUT/(name+'.symbol-associations-and-unknowns.jsonl')).write_text(''.join(json.dumps(u)+'\n' for u in unknown))
    summaries.append(dict(library=name,manifest_sha256=sha(output),rows=len(rows),FDE_rows=len(primary),
        extra_symbol_rows=len(rows)-len(primary),symbol_association_or_unknown_rows=len(unknown),
        queued_bytes=sum(int(r['end_exclusive'],16)-int(r['address'],16) for r in rows)))
(OUT/'summary.json').write_text(json.dumps(summaries,indent=2)+'\n')
print(json.dumps(summaries))
