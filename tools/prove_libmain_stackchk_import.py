"""Bounded raw ARM64/ELF proof; does not execute/import target native code."""
import argparse
import copy
import hashlib
import json
import struct
import zipfile
from pathlib import Path

APK_SHA='1f8e2ba7ddabaee961a1b2552d44bc0c281c9b5122480642b018779bcbf2fe8e'
ELF_SHA='e2a12641542457e7355f3da2fa93b138463711d7a1f0edea24e9d9cfff5fa0b4'
MANIFEST_SHA='6b6ff08573d6a654845183e0dd11d1967de14d2d4823e03e1b0212d05bd3e3fd'
sha=lambda b:hashlib.sha256(b).hexdigest()


def require(v,message):
    if not v:raise ValueError(message)


def signed(v,bits):return v-(1<<bits) if v&(1<<(bits-1)) else v


def call_target(word,pc):
    require(word&0xfc000000==0x94000000,'Not AArch64 BL immediate')
    return pc+signed(word&0x3ffffff,26)*4


def plt_effects(words,start):
    require(len(words)==4,'Expected exactly four PLT words')
    adr,load,add,branch=words
    require(adr&0x9f000000==0x90000000 and adr&31==16,'Expected ADRP X16')
    page=(start&~4095)+(signed((((adr>>5)&0x7ffff)<<2)|((adr>>29)&3),21)<<12)
    require(load&0xffc00000==0xf9400000 and load&31==17 and (load>>5)&31==16,'Expected LDR X17,[X16,#imm]')
    load_offset=((load>>10)&4095)*8
    require(add&0xffc00000==0x91000000 and add&31==16 and (add>>5)&31==16,'Expected ADD X16,X16,#imm12')
    add_offset=(add>>10)&4095
    require(load_offset==add_offset,'PLT LDR/ADD slot discrepancy')
    require(branch&0xfffffc1f==0xd61f0000 and (branch>>5)&31==17,'Expected BR X17 preserving caller LR')
    return dict(page=page,slot=page+load_offset,load_offset=load_offset,add_offset=add_offset,
                register_effect='X16=page; X17=MEM64[page+offset]; X16=page+offset; PC=X17; LR is not overwritten by BR')


def relocation_contract(rel,symbol):
    require(rel['slot']==0x7fb0 and rel['type']==1026 and rel['symbol_index']==5 and rel['addend']==0,'Wrong GOT relocation tuple')
    require(symbol['name']=='__stack_chk_fail' and symbol['shndx']==0 and symbol['value']==0
            and symbol['binding']==1 and symbol['type']==2,'Not expected undefined global function symbol')


class ELF:
    def __init__(self,raw):
        self.raw=raw
        require(len(raw)>=64 and raw[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<H',raw,18)[0]==183,'Not ELF64 LE AArch64')
        self.loads=[]
        ph=struct.unpack_from('<Q',raw,32)[0];size,count=struct.unpack_from('<HH',raw,54)
        self.bound(ph,size*count);require(size>=56,'Short program header')
        for i in range(count):
            kind,flags,off,va,_,filesz,memsz,_=struct.unpack_from('<II6Q',raw,ph+i*size)
            if kind==1:
                self.bound(off,filesz);require(filesz<=memsz,'Bad segment size');self.loads.append((va,va+filesz,off,flags))
        sh=struct.unpack_from('<Q',raw,40)[0];size,count,names=struct.unpack_from('<3H',raw,58)
        self.bound(sh,size*count);require(size>=64 and names<count,'Section table invalid')
        records=[struct.unpack_from('<IIQQQQIIQQ',raw,sh+i*size) for i in range(count)]
        r=records[names];self.bound(r[4],r[5]);pool=raw[r[4]:r[4]+r[5]]
        self.sections=[]
        for r in records:
            name=self.string(pool,r[0]);section=dict(name=name,type=r[1],flags=r[2],va=r[3],offset=r[4],size=r[5],link=r[6],entsize=r[9])
            if r[1]!=8:self.bound(r[4],r[5])
            self.sections.append(section)
    def bound(self,off,size):require(0<=off<=len(self.raw) and 0<=size<=len(self.raw)-off,'File range outside ELF')
    @staticmethod
    def string(pool,off):
        require(0<=off<len(pool),'String offset outside table');end=pool.find(b'\0',off);require(end>=off,'Unterminated string')
        return pool[off:end].decode('ascii','strict')
    def section(self,name):
        matches=[s for s in self.sections if s['name']==name];require(len(matches)==1,'Section not unique: '+name);return matches[0]
    def mapping(self,va,size,executable=False):
        matches=[off+va-lo for lo,hi,off,flags in self.loads if lo<=va and va+size<=hi and (not executable or flags&1)]
        require(len(matches)==1,'VA not uniquely file-backed');return matches[0]
    def read(self,va,size,executable=False):
        off=self.mapping(va,size,executable);return self.raw[off:off+size]


def main():
    p=argparse.ArgumentParser();p.add_argument('--apk',type=Path,required=True);p.add_argument('--elf',type=Path,required=True)
    p.add_argument('--manifest',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    require(not a.output.exists(),'Fresh proof output required')
    require(sha(a.apk.read_bytes())==APK_SHA,'APK SHA mismatch');raw=a.elf.read_bytes();require(sha(raw)==ELF_SHA,'ELF SHA mismatch')
    with zipfile.ZipFile(a.apk) as z:require(z.read('lib/arm64-v8a/libmain.so')==raw,'APK and extracted ELF differ')
    manifest_raw=a.manifest.read_bytes();require(sha(manifest_raw)==MANIFEST_SHA,'Pinned original range manifest differs')
    manifest=json.loads(manifest_raw);row=next(r for r in manifest['rows'] if r['address']=='0xbd4')
    require(row['end_exclusive']=='0xd20' and row['evidence_kind']=='fde','Expected original FDE row')
    elf=ELF(raw);source=elf.read(0xbd4,0xd20-0xbd4,True);require(sha(source)==row['source_sha256'],'Original FDE bytes mismatch')
    terminal_pc=0xd1c;word=struct.unpack('<I',elf.read(terminal_pc,4,True))[0]
    require(call_target(word,terminal_pc)==0x8a0,'Terminal BL does not target selected PLT')
    require(terminal_pc+4==int(row['end_exclusive'],16),'Call continuation not exactly FDE end')
    plt=elf.section('.plt');require(plt['va']<=0x8a0 and 0x8b0<=plt['va']+plt['size'],'Selected PLT range outside .plt')
    plt_raw=elf.read(0x8a0,16,True);words=list(struct.unpack('<4I',plt_raw));effects=plt_effects(words,0x8a0)
    require(effects['slot']==0x7fb0,'Unexpected computed GOT slot')
    got=elf.section('.got');require(got['va']<=effects['slot'] and effects['slot']+8<=got['va']+got['size'],'Slot not in .got')
    relsec=elf.section('.rela.plt');require(relsec['type']==4 and relsec['entsize']==24 and relsec['size']%24==0,'Unexpected .rela.plt layout')
    rels=[]
    for off in range(relsec['offset'],relsec['offset']+relsec['size'],24):
        slot,info,addend=struct.unpack_from('<QQq',raw,off)
        if slot==effects['slot']:rels.append(dict(slot=slot,type=info&0xffffffff,symbol_index=info>>32,addend=addend,file_offset=off,raw_bytes=raw[off:off+24].hex()))
    require(len(rels)==1,'Slot relocation is missing/ambiguous');rel=rels[0]
    require(0<=relsec['link']<len(elf.sections),'Relocation symbol link outside sections');symbols=elf.sections[relsec['link']]
    require(symbols['name']=='.dynsym' and symbols['type']==11 and symbols['entsize']==24,'Relocation not linked to expected dynsym')
    require(0<=symbols['link']<len(elf.sections),'Dynsym string link outside sections');strings=elf.sections[symbols['link']]
    require(strings['name']=='.dynstr' and strings['type']==3,'Dynsym not linked to dynstr')
    symoff=symbols['offset']+rel['symbol_index']*24;require(symoff+24<=symbols['offset']+symbols['size'],'Symbol index outside dynsym')
    name,info,other,shndx,value,size=struct.unpack_from('<IBBHQQ',raw,symoff)
    symbol=dict(name=elf.string(raw[strings['offset']:strings['offset']+strings['size']],name),binding=info>>4,type=info&15,
                shndx=shndx,value=value,size=size,visibility=other&3,file_offset=symoff,raw_bytes=raw[symoff:symoff+24].hex(),name_string_offset=name)
    relocation_contract(rel,symbol)
    controls=[]
    def reject(label,fn):
        try:fn()
        except (ValueError,struct.error,KeyError):controls.append(label)
        else:raise ValueError('Negative control accepted: '+label)
    reject('B_instead_of_BL',lambda:call_target(word&0x7fffffff,terminal_pc))
    for i in range(4):
        bad=words.copy();bad[i]=0xd503201f
        reject('wrong_PLT_opcode_'+str(i),lambda bad=bad:plt_effects(bad,0x8a0))
    bad=words.copy();bad[2]^=1<<10
    reject('PLT_ADD_slot_mismatch',lambda:plt_effects(bad,0x8a0))
    for key,val in [('type',1025),('symbol_index',4),('slot',0x7fb8),('addend',8)]:
        bad=copy.deepcopy(rel);bad[key]=val;reject('wrong_relocation_'+key,lambda bad=bad:relocation_contract(bad,symbol))
    for key,val in [('name','__stack_chk_guard'),('shndx',1),('binding',2),('type',1)]:
        bad=copy.deepcopy(symbol);bad[key]=val;reject('wrong_symbol_'+key,lambda bad=bad:relocation_contract(rel,bad))
    assumptions=[
        'The dynamic loader resolves this import to a Bionic-compatible __stack_chk_fail implementation honoring its abort/no-normal-return behavior.',
        'No symbol interposition, GOT rewriting, hook, modified PLT or ABI-violating replacement makes this call return normally.',
        'Standard AArch64 BL/BR semantics apply; no return-address corruption or asynchronous control-flow rewriting fabricates a continuation.',
        'Signals, longjmp, exception/nonlocal transfers do not reenter this function at a path later returning normally from this call.']
    result=dict(integrity_passed=True,APK_sha256=APK_SHA,ELF_sha256=ELF_SHA,range_manifest_sha256=MANIFEST_SHA,
                producer_sha256=sha(Path(__file__).read_bytes()),scope='Single libmain call/PLT/GOT/import binding from original static bytes; no runtime symbol resolution proof',
                function_entry='0xbd4',function_end_exclusive='0xd20',function_bytes=len(source),function_source_sha256=sha(source),
                terminal_call=dict(pc=hex(terminal_pc),word=hex(word),raw_bytes=elf.read(terminal_pc,4,True).hex(),file_offset=elf.mapping(terminal_pc,4,True),target='0x8a0',normal_continuation='0xd20'),
                PLT=dict(address='0x8a0',bytes=plt_raw.hex(),sha256=sha(plt_raw),words=[hex(w) for w in words],effects=effects),
                GOT=dict(slot='0x7fb0',file_offset=elf.mapping(0x7fb0,8),raw_pointer=hex(struct.unpack('<Q',elf.read(0x7fb0,8))[0]),raw_pointer_is_runtime_resolution=False),
                relocation=rel,symbol=symbol,negative_controls_rejected=controls,conditional_assumptions=assumptions,
                standard_contract_sources=[dict(url='https://android.googlesource.com/platform/bionic/+/master/libc/bionic/__stack_chk_fail.cpp',observed_blob='5f5a5f69afeef53caba9c37687e3331caaedf5ab',fact='Calls async_safe_fatal on stack corruption'),
                    dict(url='https://raw.githubusercontent.com/aosp-mirror/platform_bionic/master/libc/async_safe/include/async_safe/log.h',fact='async_safe_fatal macro logs then calls abort'),
                    dict(url='https://raw.githubusercontent.com/aosp-mirror/platform_bionic/master/libc/include/stdlib.h',fact='abort declared __noreturn'),
                    dict(url='https://raw.githubusercontent.com/aosp-mirror/platform_bionic/master/libc/private/bionic_ssp.h',fact='__stack_chk_fail declaration alone has no explicit noreturn attribute')],
                source_review_date='2026-10-19',actual_loaded_libc_identity_verified=False,runtime_registration_or_resolution_observed=False,
                NoReturn_annotation_applied=False,flow_override_applied=False,semantic_equivalence_verified=False,
                supports_separate_conditional_NoReturn_profile=True,C_coverage_addition=0)
    a.output.mkdir(parents=True)
    (a.output/'evidence.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
    (a.output/'source-range.bin').write_bytes(source);(a.output/'plt-8a0.bin').write_bytes(plt_raw)
    provenance=dict(inputs=[dict(path=str(p),sha256=sha(p.read_bytes())) for p in [a.apk,a.elf,a.manifest,Path(__file__)]],
                    outputs=[dict(name=p.name,sha256=sha(p.read_bytes()),bytes=p.stat().st_size) for p in sorted(a.output.iterdir())])
    (a.output/'manifest.json').write_text(json.dumps(provenance,indent=2)+'\n',encoding='utf8')
    print(json.dumps(dict(integrity_passed=True,terminal_call='0xd1c -> 0x8a0 -> GOT0x7fb0 -> __stack_chk_fail',negative_controls_rejected=len(controls),C_coverage_addition=0)))


if __name__=='__main__':main()
