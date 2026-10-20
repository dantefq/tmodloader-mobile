"""Fixed 60-byte gap + two discovered PLT slots; raw and Capstone cross-check, no function creation."""
import argparse,hashlib,json,mmap,struct,sys
from pathlib import Path
ELF='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
SOURCE='62fb0f277b286f95ae55c7aafd6e714ac45a8d5d358eeb5cb97cb95df4321a69'
START,END=0x5a1b1c,0x5a1b58

def sha(b):return hashlib.sha256(b).hexdigest()
def signed(n,bits):return n-(1<<bits) if n>>(bits-1) else n
def decode(w,pc):
    rd=w&31;rn=(w>>5)&31
    if w&0x9f000000==0x90000000:return dict(op='adrp',rd=rd,target=(pc&~4095)+(signed(((w>>5)&0x7ffff)<<2|((w>>29)&3),21)<<12))
    if w&0xffc00000==0x91000000:return dict(op='add',rd=rd,rn=rn,offset=(w>>10)&4095)
    if w&0xfc000000==0x14000000:return dict(op='b',target=pc+4*signed(w&0x3ffffff,26))
    if w&0xfffffc1f==0xd65f0000:return dict(op='ret',rn=rn)
    if w&0xfffffc1f==0xd61f0000:return dict(op='br',rn=rn)
    if w&0xff000000==0xb4000000:return dict(op='cbz',rd=rd,target=pc+4*signed((w>>5)&0x7ffff,19))
    if w&0xffe0ffe0==0xaa0003e0:return dict(op='mov',rd=rd,rm=(w>>16)&31)
    if w&0xffc00000==0xf9400000:return dict(op='ldr',rd=rd,rn=rn,offset=8*((w>>10)&4095))
    raise ValueError('outside fixed reviewed opcode set')

def main():
    p=argparse.ArgumentParser();p.add_argument('lab',type=Path);p.add_argument('--output',type=Path);a=p.parse_args();lab=a.lab.resolve();sys.path.insert(0,str(lab/'python-analysis'))
    import capstone
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
    assert capstone.__version__=='5.0.7';cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    rejects=0
    for invalid in (0,0xd4200000,0xd4000001,0x94000000):
        try:decode(invalid,START)
        except ValueError:rejects+=1
        else:raise AssertionError('negative opcode accepted')
    with (lab/'native/libil2cpp.so').open('rb') as fh,mmap.mmap(fh.fileno(),0,access=mmap.ACCESS_READ) as raw:
        assert sha(raw)==ELF and raw[:6]==b'\x7fELF\x02\x01'
        ph,sh=struct.unpack_from('<QQ',raw,32);psz,pnum,ssz,snum,stridx=struct.unpack_from('<HHHHH',raw,54)
        segments=[]
        for i in range(pnum):
            ty,flags,off,va,_,fs,_,_=struct.unpack_from('<IIQQQQQQ',raw,ph+i*psz)
            if ty==1:segments.append((va,va+fs,off,flags))
        def read(va,n,execute=False):
            matches=[off+va-lo for lo,hi,off,flags in segments if lo<=va and va+n<=hi and (not execute or flags&1)];assert len(matches)==1
            return raw[matches[0]:matches[0]+n]
        sections=[struct.unpack_from('<IIQQQQIIQQ',raw,sh+i*ssz) for i in range(snum)];st=sections[stridx];names=raw[st[4]:st[4]+st[5]]
        named={names[s[0]:names.find(b'\0',s[0])].decode():s for s in sections}
        def disasm(lo,n):
            blob=read(lo,n,True);instructions=list(cs.disasm(blob,lo));assert len(instructions)*4==n;rows=[]
            for i,ins in enumerate(instructions):
                pc=lo+4*i;w=struct.unpack_from('<I',blob,4*i)[0];r=decode(w,pc);assert ins.address==pc and ins.size==4 and ins.mnemonic==r['op']
                reg=lambda operand:ins.reg_name(operand.reg)
                op=r['op'];ops=ins.operands
                if op=='adrp':assert reg(ops[0])=='x'+str(r['rd']) and ops[1].imm==r['target']
                elif op=='add':assert reg(ops[0])=='x'+str(r['rd']) and reg(ops[1])=='x'+str(r['rn']) and ops[2].imm==r['offset'] and ops[2].shift.value==0
                elif op=='b':assert ops[0].imm==r['target']
                elif op=='cbz':assert reg(ops[0])=='x'+str(r['rd']) and ops[1].imm==r['target']
                elif op=='br':assert reg(ops[0])=='x'+str(r['rn'])
                elif op=='ret':assert r['rn']==30 and not ops
                elif op=='mov':assert reg(ops[0])=='x'+str(r['rd']) and reg(ops[1])=='x'+str(r['rm'])
                elif op=='ldr':assert reg(ops[0])=='x'+str(r['rd']) and ins.reg_name(ops[1].mem.base)=='x'+str(r['rn']) and ops[1].mem.disp==r['offset']
                rows.append(dict(address=hex(pc),raw_bytes=ins.bytes.hex(),capstone=ins.mnemonic+' '+ins.op_str,raw_decoded=r))
            return rows
        source=read(START,END-START,True);assert sha(source)==SOURCE;instructions=disasm(START,END-START);by={int(r['address'],16):r['raw_decoded'] for r in instructions}
        dso=by[START]['target']+by[START+4]['offset'];assert by[START]['rd']==0 and by[START+4]['rd']==by[START+4]['rn']==0
        finalize_plt=by[START+8]['target'];atexit_plt=by[END-4]['target'];plts=[]
        for entry in (finalize_plt,atexit_plt):
            sec=named['.plt'];assert sec[3]<=entry and entry+16<=sec[3]+sec[5] and (entry-sec[3])%16==0
            rows=disasm(entry,16);d=[r['raw_decoded'] for r in rows]
            assert [r['op'] for r in d]==['adrp','ldr','add','br'] and d[0]['rd']==16 and d[1]['rd']==17 and d[1]['rn']==16 and d[2]['rd']==d[2]['rn']==16 and d[3]['rn']==17 and d[1]['offset']==d[2]['offset']
            plts.append(dict(entry=hex(entry),GOT_slot=hex(d[0]['target']+d[1]['offset']),instructions=rows,source_sha256=sha(read(entry,16,True))))
        arrays={}
        for name in ('.init_array','.fini_array'):
            s=named[name];assert s[5]%8==0 and s[5]<=4096
            arrays[name]=[dict(slot=hex(s[3]+i),raw_value=hex(struct.unpack('<Q',read(s[3]+i,8))[0])) for i in range(0,s[5],8)]
        wanted={dso}|{int(r['GOT_slot'],16) for r in plts}|{int(r['slot'],16) for entries in arrays.values() for r in entries};relocations=[]
        for name,sec in named.items():
            if sec[1]!=4:continue
            assert sec[9]==24
            symbols=sections[sec[6]];assert symbols[1]==11 and symbols[9]==24;strings=sections[symbols[6]];straw=raw[strings[4]:strings[4]+strings[5]]
            for off in range(sec[4],sec[4]+sec[5],24):
                slot,info,addend=struct.unpack_from('<QQq',raw,off)
                if slot not in wanted:continue
                index=info>>32;assert index*24<symbols[5];symbol=struct.unpack_from('<IBBHQQ',raw,symbols[4]+index*24);sn=straw[symbol[0]:straw.find(b'\0',symbol[0])].decode()
                relocations.append(dict(section=name,record_file_offset=hex(off),raw_bytes=raw[off:off+24].hex(),slot=hex(slot),type=info&0xffffffff,symbol_index=index,symbol=sn,symbol_section_index=symbol[3],symbol_value=hex(symbol[4]),addend=hex(addend)))
        for plt in plts:
            matches=[r for r in relocations if r['slot']==plt['GOT_slot']];assert len(matches)==1;rel=matches[0];assert rel['type']==1026 and rel['symbol_section_index']==0 and int(rel['addend'],16)==0;plt['relocation']=rel
        assert plts[0]['relocation']['symbol']=='__cxa_finalize' and plts[1]['relocation']['symbol']=='__cxa_atexit'
        callback=by[0x5a1b3c]['target']+by[0x5a1b40]['offset'];assert callback==0x5a1b30 and by[0x5a1b44]['target']+by[0x5a1b48]['offset']==dso
        assert by[0x5a1b4c]==dict(op='mov',rd=1,rm=0) and by[0x5a1b50]==dict(op='mov',rd=0,rm=8)
        assert by[callback]==dict(op='cbz',rd=0,target=0x5a1b38) and by[callback+4]==dict(op='br',rn=0) and by[callback+8]==dict(op='ret',rn=30)
        assert by[0x5a1b28]==dict(op='ret',rn=30) and by[0x5a1b2c]==dict(op='b',target=0x5a1b28)
        for row in arrays['.fini_array']:
            rel=[r for r in relocations if r['slot']==row['slot']];assert len(rel)==1 and rel[0]['type']==1027 and rel[0]['symbol_index']==0 and rel[0]['addend']==row['raw_value'];row['relative_relocation']=rel[0]
        assert {int(r['raw_value'],16) for r in arrays['.fini_array']}=={0x5a1b2c,START}
        self_reloc=[r for r in relocations if int(r['slot'],16)==dso];assert len(self_reloc)==1 and self_reloc[0]['type']==1027 and self_reloc[0]['symbol_index']==0 and int(self_reloc[0]['addend'],16)==dso and struct.unpack('<Q',read(dso,8))[0]==dso
        outlines=[dict(name=n,address=hex(s[3]),bytes=s[5]) for n,s in named.items() if s[3]<=dso<s[3]+s[5]]
        anchors={r['entry'] for r in plts}|{hex(dso),hex(callback)}|{hex(START),hex(0x5a1b2c)};matching_symbols=[]
        for name,sec in named.items():
            if sec[1] not in (2,11):continue
            st=sections[sec[6]];text=raw[st[4]:st[4]+st[5]]
            for off in range(sec[4],sec[4]+sec[5],sec[9]):
                row=struct.unpack_from('<IBBHQQ',raw,off)
                if hex(row[4]) in anchors:matching_symbols.append(dict(table=name,name=text[row[0]:text.find(b'\0',row[0])].decode(),value=hex(row[4]),size=row[5],section_index=row[3]))
    result=dict(integrity_passed=True,elf_sha256=ELF,source_start=hex(START),source_end_exclusive=hex(END),source_bytes=END-START,source_sha256=SOURCE,auditor_sha256=sha(Path(__file__).read_bytes()),capstone_version=capstone.__version__,raw_capstone_checked_instruction_count=23,negative_opcode_controls_rejected=rejects,instructions=instructions,PLT_bindings=plts,init_fini_arrays=arrays,matching_relocations=relocations,dso_anchor=hex(dso),dso_anchor_sections=outlines,dso_self_pointer_relocation=self_reloc[0],matching_anchor_symbols=matching_symbols,static_facts=['fini_array points to the tail-B __cxa_finalize path and a separate B-to-RET path.','The registration tail-B targets imported __cxa_atexit with x0=callback, x1=original x0, x2=dso anchor.','The callback checks x0 for null and otherwise branches to x0.','DSO anchor is an address in .data.rel.ro containing an R_AARCH64_RELATIVE self pointer.'],interpretation='CRT/atexit compatibility bridge pattern under the conventional external __cxa_atexit/__cxa_finalize contracts; not Terraria gameplay code attribution.',limits=['No function boundaries created or original function names recovered. The 60-byte container holds several instruction sequences, not proven one function.','No whole-ELF instruction or incoming-reference scan; external entries and all callers remain unknown.','Imported names do not prove runtime GOT resolution or implementation identity.','No runtime observation, C candidate output or increment to C coverage.'])
    if a.output:
        dest=a.output.resolve();assert dest.is_relative_to(lab);dest.parent.mkdir(parents=True,exist_ok=True);dest.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps({k:v for k,v in result.items() if k not in ('instructions','init_fini_arrays','matching_relocations','limits','PLT_bindings')},ensure_ascii=False));print(json.dumps([dict(entry=r['entry'],GOT=r['GOT_slot'],symbol=r['relocation']['symbol']) for r in plts]))
if __name__=='__main__':main()
