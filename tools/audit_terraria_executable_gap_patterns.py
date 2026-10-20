"""Classify source bytes outside known FDEs by raw encodings, without code/padding claims."""
import argparse,collections,hashlib,json,mmap,struct
from pathlib import Path
ELF='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
PARENT='5588a08e9b8691aed171d75e1417ae0dae64f87a89103dd749617b41455075d5'
FDE='8b238f458b7a0505138fc56ea70ffe59c21d46a6b83ea2e4106f6f896a3f7756'
def sha(b):return hashlib.sha256(b).hexdigest()
def merge(rows):
    out=[]
    for a,b in sorted(rows):
        if out and a<=out[-1][1]:out[-1][1]=max(out[-1][1],b)
        else:out.append([a,b])
    return out

def branch(w,pc):
    assert w>>26==5
    n=w&0x3ffffff;return pc+4*(n-0x4000000 if n&0x2000000 else n)
def kind(w):
    if w==0xd503201f:return 'exact_NOP_word'
    if w==0:return 'zero_word'
    if w&0xffe0001f==0xd4200000:return 'BRK_encoding_word'
    return 'opaque_word'
def main():
    p=argparse.ArgumentParser();p.add_argument('lab',type=Path);p.add_argument('--output',type=Path);a=p.parse_args();lab=a.lab.resolve()
    assert kind(0xd503201f)=='exact_NOP_word' and kind(0)=='zero_word' and kind(0xd4200000)=='BRK_encoding_word' and kind(0xd4200020)=='BRK_encoding_word' and kind(0xd4000001)=='opaque_word'
    parent_path=lab/'fde-byte-scope-audit-20261016/evidence.json';parent_bytes=parent_path.read_bytes();assert sha(parent_bytes)==PARENT;parent=json.loads(parent_bytes)
    fde_raw=(lab/'native/unwind-function-ranges.tsv').read_bytes();assert sha(fde_raw)==FDE
    fdes=[tuple(int(v,16) for v in row.split()) for row in fde_raw.decode().splitlines()]
    flows_raw=(lab/'native/flow-islands.json').read_bytes();flows=json.loads(flows_raw)
    gap_rows=[]
    for section in parent['exec_sections']:
        for g in section['without_FDE_intervals']:gap_rows.append(dict(section=section['name'],start=int(g['start'],16),end=int(g['end_exclusive'],16)))
    assert sum(r['end']-r['start'] for r in gap_rows)==480092
    assert sum(b-a for a,b in merge((r['start'],r['end']) for r in gap_rows))==480092
    categories=collections.Counter();opaque_words=collections.Counter();repeated_B=[];section_counts={};whole_gap_counts=collections.Counter();opaque=[];known=[];gap_hashes=[]
    with (lab/'native/libil2cpp.so').open('rb') as fh,mmap.mmap(fh.fileno(),0,access=mmap.ACCESS_READ) as raw:
        assert sha(raw)==ELF and raw[:6]==b'\x7fELF\x02\x01'
        ph,sh=struct.unpack_from('<QQ',raw,32);psz,pnum,ssz,snum,stridx=struct.unpack_from('<HHHHH',raw,54)
        segments=[]
        for i in range(pnum):
            ty,flags,off,va,_,fs,ms,_=struct.unpack_from('<IIQQQQQQ',raw,ph+i*psz)
            if ty==1:segments.append((va,va+fs,off,flags))
        def read(va,n):
            matches=[off+va-lo for lo,hi,off,flags in segments if lo<=va and va+n<=hi and flags&1];assert len(matches)==1
            return raw[matches[0]:matches[0]+n]
        sections=[struct.unpack_from('<IIQQQQIIQQ',raw,sh+i*ssz) for i in range(snum)];names=sections[stridx];strings=raw[names[4]:names[4]+names[5]]
        actual={strings[s[0]:strings.find(b'\0',s[0])].decode():s for s in sections if s[2]&4}
        for reported in parent['exec_sections']:
            section=actual[reported['name']];assert section[3]==reported['virtual_address'] and section[5]==reported['size']
            cursor=section[3];expected=[]
            for lo,hi in fdes:
                if hi<=cursor:continue
                if lo>=section[3]+section[5]:break
                if lo>cursor:expected.append((cursor,min(lo,section[3]+section[5])))
                cursor=max(cursor,hi)
            if cursor<section[3]+section[5]:expected.append((cursor,section[3]+section[5]))
            assert expected==[(int(g['start'],16),int(g['end_exclusive'],16)) for g in reported['without_FDE_intervals']]
        for row in flows:
            if not row['proven_encoded_path']:continue
            origin=int(row['origin'],16);target=int(row['target'],16);steps=row['steps'];assert len(steps)==2
            assert read(origin,4).hex()==row['origin_raw_bytes'] and branch(struct.unpack('<I',read(origin,4))[0],origin)==target
            assert struct.unpack('<I',read(target,4))[0]&0xffc00000 in {0xf9400000,0x39400000,0xb9400000,0xbd400000,0xfd400000,0x3dc00000}, 'not a reviewed unsigned-immediate load encoding'
            assert branch(struct.unpack('<I',read(target+4,4))[0],target+4)==origin+4==int(row['return_target'],16)
            for index,step in enumerate(steps):
                pc=int(step['address'],16);assert pc==target+index*4 and read(pc,4).hex()==step['raw_bytes']
                assert not any(lo<=pc<hi for lo,hi in fdes)
            known.append((target,target+8))
        known=merge(known);known_words={pc for lo,hi in known for pc in range(lo,hi,4)}
        for gap in gap_rows:
            lo,hi,section=gap['start'],gap['end'],gap['section'];assert (lo|hi)%4==0
            data=read(lo,hi-lo);words=struct.unpack('<'+'I'*((hi-lo)//4),data)
            labels=[];base_labels=[]
            for i,w in enumerate(words):
                pc=lo+i*4;base=kind(w);base_labels.append(base)
                label='PLT_section_bytes' if section=='.plt' else 'verified_known_flow_island_bytes' if pc in known_words else base
                labels.append(label)
                if label=='opaque_word':
                    opaque_words[w]+=1
                    if w==0x14000400:
                        target=branch(w,pc);repeated_B.append(dict(address=hex(pc),target=hex(target),target_equals_this_section_gap_end=target==hi,target_is_catalogue_FDE_start=any(lo==target for lo,end in fdes),is_first_word_of_gap=pc==lo))
            if section=='.plt':whole_gap_counts['PLT_section_gap']+=1
            elif len(set(base_labels))==1:whole_gap_counts['entire_gap_'+base_labels[0]]+=1
            else:whole_gap_counts['mixed_encoding_gap']+=1
            stats=collections.Counter(labels);section_counts.setdefault(section,collections.Counter()).update({k:4*v for k,v in stats.items()});categories.update({k:4*v for k,v in stats.items()})
            gap_hashes.append(dict(section=section,start=hex(lo),end_exclusive=hex(hi),bytes=hi-lo,sha256=sha(data),first_16_bytes=data[:16].hex(),partition_byte_counts={k:4*v for k,v in stats.items()}))
            first=0
            while first<len(labels):
                last=first+1
                while last<len(labels) and labels[last]==labels[first]:last+=1
                if labels[first]=='opaque_word':
                    blob=data[first*4:last*4];opaque.append(dict(section=section,start=hex(lo+4*first),end_exclusive=hex(lo+4*last),bytes=len(blob),sha256=sha(blob),first_16_bytes=blob[:16].hex()))
                first=last
    assert sum(categories.values())==480092
    result=dict(integrity_passed=True,elf_sha256=ELF,fde_catalogue_sha256=FDE,parent_evidence_sha256=PARENT,flow_catalogue_sha256=sha(flows_raw),auditor_sha256=sha(Path(__file__).read_bytes()),gap_total_bytes=480092,gap_interval_count=len(gap_rows),classification_priority=['PLT_section_bytes','verified_known_flow_island_bytes','exact_NOP_word','zero_word','BRK_encoding_word','opaque_word'],deduplicated_partition_bytes=dict(categories),per_section_partition_bytes={k:dict(v) for k,v in section_counts.items()},whole_original_gap_counts=dict(whole_gap_counts),verified_known_flow_paths=sum(bool(r['proven_encoded_path']) for r in flows),known_island_union_bytes=sum(hi-lo for lo,hi in known),opaque_word_frequencies=[dict(word=hex(w),count=n,bytes=4*n) for w,n in opaque_words.most_common()],repeated_0x14000400_B_encoding_count=len(repeated_B),repeated_B_all_targets_are_gap_end=all(r['target_equals_this_section_gap_end'] for r in repeated_B),repeated_B_all_targets_are_FDE_start=all(r['target_is_catalogue_FDE_start'] for r in repeated_B),repeated_B_all_first_word_of_gap=all(r['is_first_word_of_gap'] for r in repeated_B),repeated_0x14000400_B_locations=repeated_B,opaque_interval_count=len(opaque),opaque_intervals=opaque,all_original_gap_hashes=gap_hashes,limits=['Raw word encodings do not establish instruction reachability or padding intent.','NOP/BRK may execute; zero/opaque words may be instructions or data; no instruction-boundary inference beyond aligned words.','Known islands are original structurally verified catalogue paths, not new discoveries or full CFG proof.','PLT bytes are separated by ELF section identity, without asserting every byte is a complete stub.','No new C coverage is claimed; conditional candidate presence does not prove source-byte semantic coverage.'])
    if a.output:
        dest=a.output.resolve();assert dest.is_relative_to(lab);dest.parent.mkdir(parents=True,exist_ok=True);dest.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps({k:v for k,v in result.items() if k not in ('opaque_intervals','all_original_gap_hashes','opaque_word_frequencies','repeated_0x14000400_B_locations','limits')},ensure_ascii=False))
if __name__=='__main__':main()
