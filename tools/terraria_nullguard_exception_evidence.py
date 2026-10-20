"""Source-bound facts behind a null-guard exception interpretation; no runtime/noreturn proof."""
import argparse, hashlib, json, pathlib, struct, sys
from terraria_flow_islands import Elf
from terraria_native_map import ELF


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);a=ap.parse_args();lab=a.lab
    sys.path.insert(0,str(lab/'python-analysis'))
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
    path=lab/'native/libil2cpp.so';elf=Elf(path);layout=ELF(elf.raw)
    if sha(path)!='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5':raise ValueError('ELF identity mismatch')
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    bounds=[(0x6ff6ac,0x6ff6b4),(0x741278,0x74128c),(0x74128c,0x74129c),(0x74129c,0x7412c4),(0x7411e0,0x741208)]
    fdes={int(s.split('\t')[0],16):int(s.split('\t')[1],16) for s in (lab/'native/unwind-function-ranges.tsv').read_text().splitlines()}
    functions=[];decoded={}
    for start,end in bounds:
        if fdes[start]!=end:raise ValueError('FDE extent mismatch')
        raw=elf.raw[elf.at(start):elf.at(end-4)+4];code=list(cs.disasm(raw,start))
        if len(code)*4!=len(raw):raise ValueError('Incomplete decode')
        decoded.update({i.address:i for i in code})
        functions.append({'start':hex(start),'end_exclusive':hex(end),'source_sha256':hashlib.sha256(raw).hexdigest(),
                          'instructions':[{'address':hex(i.address),'bytes':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str} for i in code]})
    edges=[(0x6ff6b0,0x741278),(0x741288,0x74128c),(0x741290,0x74129c),(0x741298,0x7411e0),(0x7412c0,0x741bcc),(0x7411f0,0x59ec50),(0x741204,0x59fe50)]
    for site,target in edges:
        word=elf.word(site);imm=word&0x3ffffff
        if imm&(1<<25):imm-=1<<26
        if word&0x7c000000!=0x14000000 or site+imm*4!=target:raise ValueError('Direct encoded edge mismatch')
    # ADRP/ADD pairs supply X1/X2 directly before tail-branch to constructor-like helper.
    string_values=[]
    for page_site,add_site,register,wanted in [(0x7412a8,0x7412b0,'x1','System'),(0x7412ac,0x7412b4,'x2','NullReferenceException')]:
        page,add=decoded[page_site],decoded[add_site]
        if page.mnemonic!='adrp' or add.mnemonic!='add' or page.reg_name(page.operands[0].reg)!=register or add.reg_name(add.operands[0].reg)!=register or add.reg_name(add.operands[1].reg)!=register:raise ValueError('String register sequence mismatch')
        address=page.operands[1].imm+add.operands[2].imm;off=layout.file_offset(address);raw=elf.raw[off:elf.raw.index(b'\0',off)+1]
        if raw.decode('utf8').rstrip('\0')!=wanted:raise ValueError('String contents mismatch')
        string_values.append({'register_at_tail_branch':register,'address':hex(address),'raw_bytes_including_NUL':raw.hex(),'text':wanted})
    prior=lab/'unknown-native-behaviors-v1/behaviors.json';source=json.loads(prior.read_text());symbols=[]
    for va,name in [(0x59ec50,'__cxa_allocate_exception'),(0x59fe50,'__cxa_throw')]:
        match=[r for r in source['verified_plt_stubs'] if r['address']==hex(va) and r['symbol_name']==name]
        if len(match)!=1:raise ValueError('Missing independently audited PLT identity')
        ev=match[0];off=layout.file_offset(va)
        if elf.raw[off:off+16].hex()!=ev['raw_bytes']:raise ValueError('PLT bytes changed')
        symbols.append(ev)
    guards=json.loads((lab/'guarded-native-behaviors-v1/behaviors.json').read_text())
    if len(guards['results'])!=411 or any(r['zero_path']['direct_call_target']!='0x6ff6ac' for r in guards['results']):raise ValueError('Guard relationship mismatch')
    out=lab/'native-continuation-20261014';out.mkdir(exist_ok=True)
    rtti_path=lab/'native-rtti-continuation-v1/rtti-links.json';rtti_audit=json.loads((rtti_path.parent/'independent-audit.json').read_text())
    if rtti_audit.get('integrity_passed') is not True or rtti_audit['rtti_links_sha256']!=sha(rtti_path):raise ValueError('RTTI evidence stale')
    rtti=json.loads(rtti_path.read_text());typeinfo=[r for r in rtti['rtti_objects'] if r['address']=='0x2f5c378']
    if len(typeinfo)!=1 or typeinfo[0]['name']!='22Il2CppExceptionWrapper':raise ValueError('Exception typeinfo identity mismatch')
    if decoded[0x7411f4].operands[1].imm+decoded[0x7411f8].operands[2].imm!=0x2f5c378:raise ValueError('Typeinfo register value mismatch')
    doc={'elf_sha256':sha(path),'producer_sha256':sha(pathlib.Path(__file__)),'audited_plt_source_sha256':sha(prior),
         'guarded_source_sha256':sha(lab/'guarded-native-behaviors-v1/behaviors.json'),'guarded_wrapper_count':411,'functions':functions,
         'encoded_direct_edges':[{'site':hex(s),'target':hex(t)} for s,t in edges],'strings_supplied_to_helper_0x741bcc':string_values,'relocation_bound_symbols':symbols,
         'throw_X1_typeinfo':{'address':'0x2f5c378','literal_RTTI_name':'22Il2CppExceptionWrapper','source_rtti_sha256':sha(rtti_path),'runtime_binding_verified':False},
         'interpretation':'The observed null path enters a chain that passes System/NullReferenceException to a helper and later calls the relocation-bound __cxa_throw symbol. This supports a null-reference exception path interpretation, conditional on helper behavior and normal symbol binding.',
         'not_proven':['runtime execution','helper 0x741bcc return value or exact prototype','dynamic loader interposition','unconditional noreturn','exception propagation or catch behavior']}
    (out/'nullguard-exception-chain.json').write_text(json.dumps(doc,ensure_ascii=False,indent=2)+'\n',encoding='utf8');print(json.dumps({'functions':len(functions),'encoded_edges':len(edges),'guarded_wrappers':411}))


if __name__=='__main__':main()
