"""Original ELF RTTI-backed virtual-slot candidates; no names inferred from strings alone.

R_AARCH64_ABS64 resolution uses the artifact's defined symbol value and is
conditional on that definition being selected at runtime (interposition untested).
Only relocation-backed contiguous FDE-pointer prefixes are recorded, never full
anonymous table sizes or guessed virtual member/destructor names.
"""
import argparse, collections, hashlib, json, pathlib, struct
from terraria_native_map import ELF
SOURCE='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);ap.add_argument('--out',type=pathlib.Path,required=True);a=ap.parse_args()
    src=a.lab/'native/libil2cpp.so';assert sha(src)==SOURCE;e=ELF(src.read_bytes());raw=e.data
    ro=next(s for s in e.sections if s['name']=='.rodata');data=next(s for s in e.sections if s['name']=='.data.rel.ro')
    sealed=[s for s in e.segments if s['type']==0x6474e552];assert len(sealed)==1;sealed=sealed[0]
    assert sealed['vaddr']<=data['vaddr'] and data['vaddr']+data['size']<=sealed['vaddr']+sealed['memsz']
    def bounded(addr,size,sec):return sec['vaddr']<=addr and addr+size<=sec['vaddr']+sec['size']
    rel={};unresolved=[]
    for sec in e.sections:
        if sec['type']!=4:continue
        sy=e.sections[sec['link']];pool=e.sections[sy['link']]
        for p in range(sec['offset'],sec['offset']+sec['size'],sec['entsize'] or 24):
            slot,inf,add=struct.unpack_from('<QQq',raw,p);typ=inf&0xffffffff
            if typ not in (1027,257):continue
            item={'relocation_file_offset':hex(p),'relocation_bytes':raw[p:p+24].hex(),'type':typ,'addend':add,'slot':hex(slot),'in_place_bytes':raw[e.file_offset(slot):e.file_offset(slot)+8].hex()}
            if typ==1027:item['link_time_target']=hex(add)
            else:
                index=inf>>32;sp=sy['offset']+index*sy['entsize'];n,flags,other,defined,value,size=struct.unpack_from('<IBBHQQ',raw,sp);no=pool['offset']+n;name=raw[no:raw.index(b'\0',no)].decode('utf8')
                item.update(symbol_index=index,symbol_name=name,symbol_defined=bool(defined),symbol_value=hex(value),symbol_record_file_offset=hex(sp),symbol_record_bytes=raw[sp:sp+24].hex())
                if not defined:unresolved.append(item);continue
                item['link_time_target']=hex(value+add)
            assert slot not in rel;rel[slot]=item
    ptr=lambda x:int(rel[x]['link_time_target'],16) if x in rel else e.raw_pointer(x)
    abi={int(s['address'],16)+16:s for s in e.symbols if s['defined'] and s['type']==1 and s['name'].startswith('_ZTVN10__cxxabiv1') and s['size']>=24}
    ti=[]
    for address in range(data['vaddr'],data['vaddr']+data['size']-15,8):
        if address not in rel or address+8 not in rel:continue
        vp=ptr(address);np=ptr(address+8)
        if vp not in abi or not bounded(np,1,ro):continue
        off=e.file_offset(np);end=raw.find(b'\0',off,min(off+512,ro['offset']+ro['size']))
        if end<off or end==off or any(c<32 or c>=127 for c in raw[off:end]):continue
        symbol=abi[vp];at=int(symbol['address'],16)
        assert ptr(at)==0 and at+8 in rel
        ti.append({'address':hex(address),'vptr':hex(vp),'abi_vtable_symbol':symbol,'abi_vtable_header_raw':raw[e.file_offset(at):e.file_offset(at)+16].hex(),'vptr_relocation':rel[address],'name_pointer':hex(np),'name':raw[off:end].decode('ascii'),'name_bytes':raw[off:end+1].hex(),'name_relocation':rel[address+8]})
    by_ti={int(x['address'],16):x for x in ti}
    ranges_path=a.lab/'native/unwind-function-ranges.json';catalog_path=a.lab/'native/unmapped-fde-classification.json';ranges=json.loads(ranges_path.read_text());fde={int(x['address'],16) for x in ranges};unknown={int(x['address'],16) for x in json.loads(catalog_path.read_text()) if x['category']=='unknown'}
    vt=[];slots=[]
    class_kinds={'_ZTVN10__cxxabiv117__class_type_infoE','_ZTVN10__cxxabiv120__si_class_type_infoE','_ZTVN10__cxxabiv121__vmi_class_type_infoE'}
    named=[s for s in e.symbols if s['defined'] and s['name'].startswith('_ZTV') and s['size']]
    for h in range(data['vaddr'],data['vaddr']+data['size']-23,8):
        off=struct.unpack_from('<q',raw,e.file_offset(h))[0]
        if h in rel or abs(off)>1048576 or h+8 not in rel or ptr(h+8) not in by_ti:continue
        typ=by_ti[ptr(h+8)]
        if typ['abi_vtable_symbol']['name'] not in class_kinds:continue
        p=h+16;prefix=[]
        containing=[s for s in named if int(s['address'],16)<=h and h+24<=int(s['address'],16)+s['size']]
        limit=min([data['vaddr']+data['size']]+[int(s['address'],16)+s['size'] for s in containing])
        while p+8<=limit and p in rel and ptr(p) in fde:
            target=ptr(p);prefix.append({'slot':hex(p),'slot_index_from_address_point':len(prefix),'target':hex(target),'original_category_unknown':target in unknown,'relocation':rel[p]});p+=8
        if not prefix:continue
        vt.append({'header':hex(h),'address_point':hex(h+16),'offset_to_top':off,'header_bytes':raw[e.file_offset(h):e.file_offset(h)+16].hex(),'typeinfo':typ['address'],'typeinfo_name':typ['name'],'typeinfo_slot_relocation':rel[h+8],'containing_named_vtable_symbols':containing,'prefix_end_exclusive':hex(p),'prefix_not_complete_vtable_extent':True,'slots':prefix})
        slots.extend(x for x in prefix if x['original_category_unknown'])
    named_ti={int(s['address'],16) for s in e.symbols if s['defined'] and s['name'].startswith('_ZTI')}
    doc={'profile':'original-elf-rtti-backed-virtual-slot-prefixes-v1','producer_sha256':sha(pathlib.Path(__file__)),'inputs':{'native/libil2cpp.so':SOURCE,'native/unwind-function-ranges.json':sha(ranges_path),'native/unmapped-fde-classification.json':sha(catalog_path)},'scan_section':data,'type_name_section':ro,'gnu_relro_segment':sealed,'rtti_objects':ti,'vtable_prefixes':vt,'typeinfo_objects':len(ti),'typeinfo_objects_without_ZTI_symbol':sum(int(x['address'],16) not in named_ti for x in ti),'vtable_prefix_count':len(vt),'unknown_target_slot_links':len(slots),'unique_original_unknown_FDE_targets':len({x['target'] for x in slots}),'unique_original_unknown_FDE_addresses':sorted({x['target'] for x in slots},key=lambda x:int(x,16)),'limits':['ABS64 defined-symbol target is a conditional link-time identity, runtime interposition not checked','no runtime vptr assignment or virtual call observed','contiguous relocation-backed FDE prefix is not a complete anonymous vtable extent','offset-to-top accepted only within +/-1MiB; bounded scan is not exhaustive C++ recovery','virtual member names, destructor slots, prototypes and gameplay role not inferred','GNU_RELRO is a program-header declaration, runtime page protection not observed'],'baseline_modified':False}
    a.out.mkdir(parents=True,exist_ok=True);(a.out/'rtti-links.json').write_text(json.dumps(doc,indent=2),encoding='utf8');print(json.dumps({k:doc[k] for k in ('typeinfo_objects','typeinfo_objects_without_ZTI_symbol','vtable_prefix_count','unknown_target_slot_links','unique_original_unknown_FDE_targets')}))
if __name__=='__main__':main()
