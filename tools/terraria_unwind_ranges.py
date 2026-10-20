"""Recover compiler-described ARM64 ELF function extents from DWARF unwind data.

No disassembler flow inference is used. FDE ranges describe unwind coverage;
they do not prove every byte is an instruction or every control-flow edge is
contained. Crosschecks use the independently encoded .eh_frame_hdr index.
"""
import argparse
from bisect import bisect_right
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import struct

from terraria_native_map import ELF

ROOT=Path(__file__).resolve().parents[1]


class Reader:
    def __init__(self,elf,start,end):
        self.elf=elf
        self.start=start
        self.pos=start
        self.end=end

    def take(self,n):
        if n<0 or self.pos+n>self.end: raise ValueError('Unwind field exceeds record bounds')
        result=self.elf.data[self.pos:self.pos+n]
        self.pos+=n
        return result

    def number(self,n,signed=False):
        return int.from_bytes(self.take(n),'little',signed=signed)

    def uleb(self):
        value=0
        for i in range(10):
            b=self.number(1)
            value|=(b&127)<<(i*7)
            if not b&128: return value
        raise ValueError('ULEB128 exceeds 64-bit bound')

    def sleb(self):
        value=0
        for i in range(10):
            b=self.number(1)
            value|=(b&127)<<(i*7)
            if not b&128:
                return value-(1<<((i+1)*7)) if b&64 else value
        raise ValueError('SLEB128 exceeds 64-bit bound')

    def string(self):
        result=[]
        for _ in range(256):
            b=self.take(1)
            if b==b'\0': return b''.join(result).decode('ascii')
            result.append(b)
        raise ValueError('CIE augmentation string exceeds bound')

    def encoded(self,encoding,data_base=None,text_base=None,function_base=None,resolve_indirect=True):
        if encoding==255: return None
        application=encoding&0x70
        if application==0x50:
            aligned=(self.elf.va(self.pos)+7)&~7
            self.pos=self.elf.file_offset(aligned)
            application=0
        position=self.elf.va(self.pos)
        form=encoding&15
        if form==0: value=self.number(8)
        elif form==1: value=self.uleb()
        elif form in (2,3,4): value=self.number({2:2,3:4,4:8}[form])
        elif form==9: value=self.sleb()
        elif form in (10,11,12): value=self.number({10:2,11:4,12:8}[form],True)
        else: raise ValueError(f'Unsupported DW_EH_PE format 0x{form:x}')
        # Encoded null pointers stay null, including optional LSDA pointers.
        if value==0: return 0
        if application==0x10: value+=position
        elif application==0x20:
            if text_base is None: raise ValueError('DW_EH_PE_textrel without base')
            value+=text_base
        elif application==0x30:
            if data_base is None: raise ValueError('DW_EH_PE_datarel without base')
            value+=data_base
        elif application==0x40:
            if function_base is None: raise ValueError('DW_EH_PE_funcrel without base')
            value+=function_base
        elif application!=0: raise ValueError(f'Unsupported DW_EH_PE application 0x{application:x}')
        if encoding&0x80 and resolve_indirect:
            value=self.elf.pointer(value)
        return value


def parse_frames(elf):
    section=next(s for s in elf.sections if s['name']=='.eh_frame')
    start=section['offset'];end=start+section['size'];pos=start
    cies={};ranges=[];padding=0
    text_base=min(s['vaddr'] for s in elf.segments if s['type']==1 and s['flags']&1)
    while pos<end:
        if end-pos<4:
            if any(elf.data[pos:end]): raise ValueError('Nonzero .eh_frame trailing bytes')
            padding=end-pos;break
        length=struct.unpack_from('<I',elf.data,pos)[0]
        if not length:
            if any(elf.data[pos:end]): raise ValueError('Nonzero records after .eh_frame terminator')
            padding=end-pos;break
        head=4;id_size=4
        if length==0xffffffff:
            length=struct.unpack_from('<Q',elf.data,pos+4)[0];head=12;id_size=8
        record_end=pos+head+length
        if length<id_size or record_end>end: raise ValueError('Invalid .eh_frame record size')
        r=Reader(elf,pos+head,record_end)
        id_position=r.pos;identifier=r.number(id_size)
        if identifier==0:
            version=r.number(1);augmentation=r.string()
            if version not in (1,3,4): raise ValueError('Unsupported CIE version '+str(version))
            address_size=8;segment_size=0
            if version==4:
                address_size=r.number(1);segment_size=r.number(1)
                if address_size!=8 or segment_size: raise ValueError('Unsupported CIE address/segment size')
            if augmentation.startswith('eh'): raise ValueError('Legacy CIE eh augmentation unsupported')
            code_alignment=r.uleb();data_alignment=r.sleb()
            return_register=r.number(1) if version==1 else r.uleb()
            pointer_encoding=0;lsda_encoding=255;personality=None;personality_encoding=None;signal=False
            if augmentation.startswith('z'):
                augmentation_length=r.uleb();augmentation_end=r.pos+augmentation_length
                if augmentation_end>r.end: raise ValueError('CIE augmentation outside record')
                for char in augmentation[1:]:
                    if char=='R': pointer_encoding=r.number(1)
                    elif char=='L': lsda_encoding=r.number(1)
                    elif char=='P':
                        personality_encoding=r.number(1)
                        # The encoded pointer can name a GOT entry resolved only
                        # by the dynamic linker. Keep this raw encoded target.
                        personality=r.encoded(personality_encoding,text_base=text_base,resolve_indirect=False)
                    elif char=='S': signal=True
                    else: raise ValueError('Unknown CIE augmentation '+char)
                if r.pos!=augmentation_end: raise ValueError('CIE augmentation length mismatch')
            elif augmentation: raise ValueError('Unsupported non-z CIE augmentation')
            cies[pos]=dict(file_offset=pos,address=elf.va(pos),version=version,augmentation=augmentation,pointer_encoding=pointer_encoding,lsda_encoding=lsda_encoding,personality_encoded_target=personality,personality_encoding=personality_encoding,signal_frame=signal,code_alignment=code_alignment,data_alignment=data_alignment,return_register=return_register,instructions_offset=r.pos,instructions_size=r.end-r.pos)
        else:
            cie_offset=id_position-identifier
            if cie_offset not in cies: raise ValueError('FDE refers to missing/nonpreceding CIE')
            cie=cies[cie_offset]
            pc=r.encoded(cie['pointer_encoding'],text_base=text_base)
            size=r.encoded(cie['pointer_encoding']&15)
            if pc is None or size is None or size<0: raise ValueError('Invalid FDE PC/range')
            lsda=None
            if cie['augmentation'].startswith('z'):
                augmentation_length=r.uleb();augmentation_end=r.pos+augmentation_length
                if augmentation_end>r.end: raise ValueError('FDE augmentation outside record')
                if cie['lsda_encoding']!=255:
                    lsda=r.encoded(cie['lsda_encoding'],text_base=text_base,function_base=pc,resolve_indirect=False)
                if r.pos!=augmentation_end: raise ValueError('FDE augmentation length mismatch')
            executable=bool(size and elf.executable(pc) and elf.executable(pc+size-1))
            ranges.append(dict(address=hex(pc),end_exclusive=hex(pc+size),size=size,fde_file_offset=hex(pos),fde_address=hex(elf.va(pos)),cie_file_offset=hex(cie_offset),pointer_encoding=hex(cie['pointer_encoding']),lsda_encoded_target=hex(lsda) if lsda is not None else None,executable_load_contained=executable,cfi_instructions_file_offset=hex(r.pos),cfi_instructions_size=r.end-r.pos))
        pos=record_end
    return section,list(cies.values()),ranges,padding


def parse_header(elf):
    s=next(s for s in elf.sections if s['name']=='.eh_frame_hdr')
    r=Reader(elf,s['offset'],s['offset']+s['size'])
    version=r.number(1);frame_encoding=r.number(1);count_encoding=r.number(1);table_encoding=r.number(1)
    if version!=1: raise ValueError('Unsupported .eh_frame_hdr version')
    frame=r.encoded(frame_encoding,data_base=s['vaddr'])
    count=r.encoded(count_encoding,data_base=s['vaddr'])
    if count is None or not 0<=count<10000000: raise ValueError('Invalid FDE index count')
    pairs=[]
    for _ in range(count):
        pc=r.encoded(table_encoding,data_base=s['vaddr'])
        fde=r.encoded(table_encoding,data_base=s['vaddr'])
        pairs.append((pc,fde))
    if r.pos!=r.end: raise ValueError('Unexpected bytes after .eh_frame_hdr table')
    if any(pairs[i][0]>pairs[i+1][0] for i in range(len(pairs)-1)): raise ValueError('Unsorted .eh_frame_hdr table')
    return dict(version=version,eh_frame_pointer_encoding=hex(frame_encoding),fde_count_encoding=hex(count_encoding),table_encoding=hex(table_encoding),eh_frame_pointer=hex(frame),fde_count=count),pairs


def verify_tsv(path,ranges):
    """Read the emitted carrier independently and compare every exact extent."""
    rows=[]
    for line in path.read_text(encoding='utf-8').splitlines():
        fields=line.split('\t')
        if len(fields)!=2: raise ValueError('Range TSV must have exactly two columns')
        start,end=map(lambda s:int(s,16),fields)
        if not start<end or start%4 or end%4: raise ValueError('Invalid or non-ARM64-aligned TSV extent')
        if rows and start<rows[-1][1]: raise ValueError('Unsorted or overlapping TSV extents')
        rows.append((start,end))
    expected=[(int(r['address'],16),int(r['end_exclusive'],16)) for r in ranges]
    if rows!=expected: raise ValueError('TSV extents differ from independently decoded FDE records')
    return dict(path=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),row_count=len(rows),columns=['address','end_exclusive'],has_header=False,all_rows_equal_decoded_fdes=True,all_rows_arm64_aligned=True,sorted_without_overlaps=True,addresses_are='Unrebased ELF virtual addresses; import image base 0, or explicitly translate all addresses')


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--native',type=Path,required=True)
    ap.add_argument('--report',type=Path)
    args=ap.parse_args();out=args.native.resolve()
    if out.is_relative_to(ROOT): raise ValueError('Keep proprietary native evidence outside repository')
    binary=out/'libil2cpp.so';elf=ELF(binary.read_bytes())
    section,cies,ranges,padding=parse_frames(elf)
    header,pairs=parse_header(elf)
    if int(header['eh_frame_pointer'],16)!=section['vaddr']: raise ValueError('Header .eh_frame pointer mismatch')
    by_fde={int(r['fde_address'],16):r for r in ranges}
    if len(by_fde)!=len(ranges): raise ValueError('Duplicate FDE addresses')
    mismatches=[]
    for pc,fde in pairs:
        r=by_fde.get(fde)
        if r is None or int(r['address'],16)!=pc: mismatches.append(dict(pc=hex(pc),fde=hex(fde)))
    if mismatches: raise ValueError('Header/frame mismatches: '+str(mismatches[:10]))
    indexed_fdes={fde for _,fde in pairs}
    for r in ranges: r['header_index_crosschecked']=int(r['fde_address'],16) in indexed_fdes
    ordered=sorted(ranges,key=lambda r:(int(r['address'],16),int(r['end_exclusive'],16)))
    overlaps=[];active=[]
    for r in ordered:
        start=int(r['address'],16);end=int(r['end_exclusive'],16)
        active=[p for p in active if int(p['end_exclusive'],16)>start]
        for p in active:
            overlaps.append(dict(first_start=p['address'],first_end=p['end_exclusive'],second_start=r['address'],second_end=r['end_exclusive']))
        if end>start: active.append(r)
    starts=[int(r['address'],16) for r in ordered]
    seed_map={}
    for name,kind in [('method-addresses.json','direct'),('generic-method-addresses.json','generic')]:
        for m in json.loads((out/name).read_text(encoding='utf-8')):
            if not m.get('address'): continue
            address=int(m['address'],16)
            seed_map.setdefault(address,[]).append(dict(kind=kind,method_index=m['method_index'],type=m['type'],name=m['name'],image=m['image']))
    seed_rows=[];status=Counter()
    exact_map={}
    for r in ordered: exact_map.setdefault(int(r['address'],16),[]).append(r)
    for address,methods in sorted(seed_map.items()):
        if address in exact_map:
            candidates=exact_map[address]
            label='exact_fde_start' if len(candidates)==1 else 'duplicate_fde_start'
        else:
            index=bisect_right(starts,address)-1
            candidates=[]
            if index>=0 and address<int(ordered[index]['end_exclusive'],16): candidates=[ordered[index]]
            label='inside_fde_not_start' if candidates else 'no_fde'
        status[label]+=1
        candidate=candidates[0] if len(candidates)==1 else None
        seed_rows.append(dict(address=hex(address),status=label,end_exclusive=candidate['end_exclusive'] if candidate else None,size_from_seed=(int(candidate['end_exclusive'],16)-address) if candidate else None,fde_address=candidate['fde_address'] if candidate else None,fde_start=candidate['address'] if candidate else None,methods=methods))
    range_path=out/'unwind-function-ranges.json'
    range_path.write_text(json.dumps(ordered,indent=2)+'\n',encoding='utf-8')
    with (out/'unwind-function-ranges.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(ordered[0]));w.writeheader();w.writerows(ordered)
    with (out/'unwind-function-ranges.tsv').open('w',encoding='utf-8',newline='') as f:
        w=csv.writer(f,delimiter='\t',lineterminator='\n')
        for r in ordered:
            w.writerow([r['address'],r['end_exclusive']])
    tsv_verification=verify_tsv(out/'unwind-function-ranges.tsv',ordered)
    (out/'unwind-function-ranges-verification.json').write_text(json.dumps(tsv_verification,indent=2)+'\n',encoding='utf-8')
    (out/'unwind-method-coverage.json').write_text(json.dumps(seed_rows,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    (out/'unwind-overlaps.json').write_text(json.dumps(overlaps,indent=2)+'\n',encoding='utf-8')
    targets=[]
    for s in seed_rows:
        if any((m['type']=='Terraria.Player' and m['name'] in ['UpdateDead','Spawn','KillMe']) or (m['type']=='Terraria.Main' and ('flushLighting' in m['name'] or m['name'] in ['get_gameMenu','set_gameMenu','get_GameMode','set_GameMode'])) or (m['type']=='Terraria.WorldGen' and m['name']=='GenerateWorld') for m in s['methods']): targets.append(s)
    summary=dict(binary=str(binary),binary_sha256=hashlib.sha256(elf.data).hexdigest(),eh_frame=section,header=header,cie_count=len(cies),cies=cies,fde_count=len(ranges),indexed_fde_count=len(indexed_fdes),unindexed_fde_count=len(ranges)-len(indexed_fdes),header_pairs_crosschecked=len(pairs),header_mismatch_count=len(mismatches),padding_bytes=padding,executable_contained_fde_count=sum(r['executable_load_contained'] for r in ranges),zero_size_fde_count=sum(r['size']==0 for r in ranges),overlap_count=len(overlaps),managed_seed_count=len(seed_map),managed_seed_coverage=dict(status),target_function_ranges=targets,tsv_verification=tsv_verification,outputs=[str(range_path),str(out/'unwind-function-ranges.csv'),str(out/'unwind-function-ranges.tsv'),str(out/'unwind-function-ranges-verification.json'),str(out/'unwind-method-coverage.json'),str(out/'unwind-overlaps.json')],limitations=['FDE extents are compiler-provided unwind coverage, not a reconstructed original source body.','Disjoint fragments, thunks, shared tails, and tail calls may require additional control-flow analysis.','An address inside an FDE but not equal to its start is explicitly distinct from a verified FDE entrypoint.','No DWARF CFI state-machine interpretation or target execution was performed.'])
    report=args.report or out/'unwind-summary.json';report.parent.mkdir(parents=True,exist_ok=True)
    report.write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:summary[k] for k in ['fde_count','cie_count','header_pairs_crosschecked','header_mismatch_count','overlap_count','managed_seed_count','managed_seed_coverage','target_function_ranges']},indent=2))


if __name__=='__main__':main()
