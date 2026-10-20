"""Hash-bound APK ELF/FDE inventory, independent of any new decompiler run."""
import hashlib
import json
import struct
import zipfile
from pathlib import Path
from terraria_native_map import ELF
from terraria_unwind_ranges import parse_frames, parse_header

APK=Path(r'C:/Private\Downloads\Terraria-v1-4-5-8-6-patched.apk')
LAB=Path(r'C:\Temp\terraria-re-20261012')
DELIVERY=Path(r'C:/Private\Documents\ChatGPT\Terraria-Reverse-20261012')
OUT=LAB/'apk-native-scope-inventory-20261019'
TOOLS=Path(__file__).resolve().parent
digest=lambda b:hashlib.sha256(b).hexdigest()
sha=lambda p:digest(p.read_bytes())
assert sha(APK)=='1f8e2ba7ddabaee961a1b2552d44bc0c281c9b5122480642b018779bcbf2fe8e'
assert not OUT.exists()
OUT.mkdir()
def merged(ranges):
    result=[]
    for lo,hi in sorted(ranges):
        assert lo<hi
        if result and lo<=result[-1][1]:result[-1][1]=max(result[-1][1],hi)
        else:result.append([lo,hi])
    return result
assert merged([(1,4),(2,3),(4,6),(8,9)])==[[1,6],[8,9]]
rows=[]
with zipfile.ZipFile(APK) as z:
    entries=[n for n in z.namelist() if n.startswith('lib/') and n.endswith('.so')]
    assert len(entries)==len(set(entries))==8
    for entry in sorted(entries):
        data=z.read(entry);name=Path(entry).name
        delivered=DELIVERY/'android-native'/name
        assert sha(delivered)==digest(data)
        catalog=delivered.with_suffix('.so.json')
        catalog_record=json.loads(catalog.read_text())
        assert catalog_record['sha256']==digest(data)
        elf=ELF(data)
        assert all(0<=s['offset']<=len(data) and s['offset']+s['size']<=len(data) for s in elf.sections if s['type']!=8)
        executable=merged([(s['vaddr'],s['vaddr']+s['size']) for s in elf.sections if s['flags']&4 and s['size']])
        row=dict(apk_member=entry,name=name,file_bytes=len(data),sha256=digest(data),
                 delivered_copy_sha256=sha(delivered),prior_catalog_sha256=sha(catalog),
                 executable_sections=[s for s in elf.sections if s['flags']&4],
                 executable_section_union_bytes=sum(hi-lo for lo,hi in executable),
                 dynamic_symbol_function_records=sum(s['defined'] and s['type']==2 for s in elf.symbols),
                 unique_dynamic_function_addresses=len({s['address'] for s in elf.symbols if s['defined'] and s['type']==2}),
                 whole_library_C_export_ledger='existing separately qualified libil2cpp ledgers' if name=='libil2cpp.so' else 'not located in reviewed delivery; selected JNI analyses may exist',
                 new_C_coverage_addition=0)
        functions=[s for s in elf.symbols if s['defined'] and s['type']==2]
        (OUT/(name+'.dynamic-function-symbols.jsonl')).write_text(''.join(json.dumps(s)+'\n' for s in functions))
        sections={s['name']:s for s in elf.sections}
        if '.eh_frame' not in sections:
            row.update(unwind_status='no_named_eh_frame_section',FDE_count=None,FDE_bytes=None)
        else:
            try:
                section,cies,ranges,padding=parse_frames(elf)
                index={int(r['fde_address'],16):r for r in ranges}
                assert len(index)==len(ranges)
                if '.eh_frame_hdr' in sections:
                    header,pairs=parse_header(elf)
                    assert int(header['eh_frame_pointer'],16)==section['vaddr']
                    assert all(fde in index and int(index[fde]['address'],16)==pc for pc,fde in pairs)
                    checked=len(pairs)
                else:checked=None
                union=merged([(int(r['address'],16),int(r['end_exclusive'],16)) for r in ranges if r['size']])
                inside=sum(max(0,min(hi,b)-max(lo,a)) for lo,hi in union for a,b in executable)
                ordered=sorted(ranges,key=lambda r:int(r['address'],16))
                overlap_count=sum(int(a['end_exclusive'],16)>int(b['address'],16) for a,b in zip(ordered,ordered[1:]))
                row.update(unwind_status='decoded',FDE_count=len(ranges),FDE_bytes=sum(r['size'] for r in ranges),
                           FDE_union_bytes=sum(hi-lo for lo,hi in union),FDE_intersection_executable_sections_bytes=inside,
                           executable_section_bytes_outside_FDE=row['executable_section_union_bytes']-inside,
                           header_index_entries_crosschecked=checked,adjacent_sorted_overlap_count=overlap_count,
                           zero_size_FDE_count=sum(r['size']==0 for r in ranges))
                (OUT/(name+'.fde-ranges.jsonl')).write_text(''.join(json.dumps(r)+'\n' for r in ordered))
                # Bounds-negative control against the same frame parser.
                damaged=bytearray(data);struct.pack_into('<I',damaged,section['offset'],0xfffffff0)
                try:parse_frames(ELF(bytes(damaged)))
                except (ValueError,struct.error,IndexError):row['oversized_frame_negative_control_rejected']=True
                else:raise AssertionError('Invalid frame accepted')
            except (ValueError,struct.error,IndexError,StopIteration) as error:
                row.update(unwind_status='unsupported_or_invalid',unwind_error=str(error),FDE_count=None,FDE_bytes=None)
        rows.append(row)
summary=dict(apk_sha256=sha(APK),libraries=rows,library_count=len(rows),
             producer_sha256=sha(Path(__file__)),ELF_parser_sha256=sha(TOOLS/'terraria_native_map.py'),
             unwind_parser_sha256=sha(TOOLS/'terraria_unwind_ranges.py'),C_coverage_addition=0,
             limits='FDE ranges describe unwind coverage, not all instructions or function semantics. Dynamic symbols can alias and omit internal functions. Section gaps can include non-code/padding; no reachability inference. No native target execution or fresh Ghidra run. Missing named unwind data is not absence of code. libil2cpp percentages exclude the other seven libraries.')
(OUT/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
files=[dict(name=p.name,sha256=sha(p),bytes=p.stat().st_size) for p in sorted(OUT.iterdir())]
(OUT/'files.json').write_text(json.dumps(files,indent=2)+'\n')
print(json.dumps([dict(name=r['name'],FDE_count=r['FDE_count'],FDE_bytes=r['FDE_bytes'],unwind_status=r['unwind_status']) for r in rows]))
