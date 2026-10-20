"""Independent ELF-header/RELA/dynsym audit of recorded RTTI/slot links.

Does not import producer or its ELF parser. Validates supplied bounded candidates;
does not claim all possible RTTI or virtual slots have been recovered.
"""
import argparse, hashlib, json, pathlib, struct
SOURCE='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);ap.add_argument('--out',type=pathlib.Path,required=True);a=ap.parse_args();p=a.out/'rtti-links.json';d=json.loads(p.read_text());raw=(a.lab/'native/libil2cpp.so').read_bytes();assert hashlib.sha256(raw).hexdigest()==SOURCE
    for name,h in d['inputs'].items():assert sha(a.lab/name)==h
    def un(fmt,off):return struct.unpack_from(fmt,raw,off)
    assert raw[:6]==b'\x7fELF\x02\x01' and un('<H',18)[0]==183
    po=un('<Q',32)[0];ps,pn=un('<HH',54);segments=[un('<IIQQQQQQ',po+i*ps) for i in range(pn)]
    so=un('<Q',40)[0];ss,sn,strings_index=un('<HHH',58);sh=[un('<IIQQQQIIQQ',so+i*ss) for i in range(sn)];pool=sh[strings_index]
    def cstr(off,end):
        z=raw.index(b'\0',off,end);return raw[off:z].decode('ascii')
    names={cstr(pool[4]+x[0],pool[4]+pool[5]):x for x in sh}
    def at(va,size=8):
        found=[x[2]+va-x[3] for x in segments if x[0]==1 and x[3]<=va and va+size<=x[3]+x[5]];assert len(found)==1;return found[0]
    def insec(va,size,sec):return sec[3]<=va and va+size<=sec[3]+sec[5]
    def executable(va):return any(x[0]==1 and x[1]&1 and x[3]<=va< x[3]+x[5] for x in segments)
    ro=names['.rodata'];data=names['.data.rel.ro'];seal=[x for x in segments if x[0]==0x6474e552];assert len(seal)==1;seal=seal[0];assert seal[3]<=data[3] and data[3]+data[5]<=seal[3]+seal[6]
    rel={};syms={}
    for sec in sh:
        if sec[1]==11:
            sy_pool=sh[sec[6]]
            for off in range(sec[4],sec[4]+sec[5],sec[9]):
                n,flags,other,defined,value,size=un('<IBBHQQ',off);name=cstr(sy_pool[4]+n,sy_pool[4]+sy_pool[5])
                if name:syms[name]={'name':name,'defined':bool(defined),'binding':flags>>4,'type':flags&15,'address':hex(value),'size':size}
        if sec[1]!=4:continue
        for off in range(sec[4],sec[4]+sec[5],sec[9]):
            slot,info,add=un('<QQq',off);assert slot not in rel;rel[slot]=(off,info,add,sec[6])
    verified_relocs=set()
    def relocation(proof,slot):
        assert proof['slot']==hex(slot);off,info,add,si=rel[slot];typ=info&0xffffffff
        assert proof['relocation_file_offset']==hex(off) and proof['relocation_bytes']==raw[off:off+24].hex() and proof['type']==typ and proof['addend']==add
        assert proof['in_place_bytes']==raw[at(slot):at(slot)+8].hex()
        if typ==1027:value=add
        else:
            assert typ==257;sec=sh[si];ix=info>>32;sp=sec[4]+ix*sec[9];n,flags,other,defined,value,size=un('<IBBHQQ',sp);pool=sh[sec[6]];name=cstr(pool[4]+n,pool[4]+pool[5])
            assert defined and proof['symbol_defined'] is True and proof['symbol_value']==hex(value) and proof['symbol_index']==ix and proof['symbol_name']==name and proof['symbol_record_file_offset']==hex(sp) and proof['symbol_record_bytes']==raw[sp:sp+24].hex();value+=add
        assert proof['link_time_target']==hex(value);verified_relocs.add(slot);return value
    def pointer(slot):
        if slot not in rel:return un('<Q',at(slot))[0]
        off,info,add,si=rel[slot]
        if info&0xffffffff==1027:return add
        assert info&0xffffffff==257;sec=sh[si];sym=un('<IBBHQQ',sec[4]+(info>>32)*sec[9]);assert sym[3];return sym[4]+add
    typeinfos={};anon=0
    for row in d['rtti_objects']:
        va=int(row['address'],16);assert va not in typeinfos and va%8==0 and insec(va,16,data);vp=relocation(row['vptr_relocation'],va);np=relocation(row['name_relocation'],va+8)
        symbol=row['abi_vtable_symbol'];assert syms[symbol['name']]==symbol and symbol['defined'] and symbol['name'].startswith('_ZTVN10__cxxabiv1') and symbol['size']>=24
        obj=int(symbol['address'],16);assert vp==obj+16 and vp==int(row['vptr'],16) and np==int(row['name_pointer'],16) and pointer(obj)==0 and obj+8 in rel
        assert row['abi_vtable_header_raw']==raw[at(obj,16):at(obj,16)+16].hex() and insec(np,len(bytes.fromhex(row['name_bytes'])),ro)
        value=cstr(at(np,1),min(at(np,1)+512,ro[4]+ro[5]));assert value and value==row['name'] and raw[at(np,1):at(np,1)+len(value)+1].hex()==row['name_bytes'] and all(32<=ord(c)<127 for c in value)
        typeinfos[va]=row
        anon+=not any(s['defined'] and s['name'].startswith('_ZTI') and int(s['address'],16)==va for s in syms.values())
    catalog={int(r['address'],16):r for r in json.loads((a.lab/'native/unmapped-fde-classification.json').read_text())};fde={int(r['address'],16) for r in json.loads((a.lab/'native/unwind-function-ranges.json').read_text())};targets=set();slotcount=0;headers=set();total=0
    kinds={'_ZTVN10__cxxabiv117__class_type_infoE','_ZTVN10__cxxabiv120__si_class_type_infoE','_ZTVN10__cxxabiv121__vmi_class_type_infoE'}
    for row in d['vtable_prefixes']:
        h=int(row['header'],16);assert h not in headers and insec(h,24,data) and h%8==0;headers.add(h);assert h not in rel
        assert row['header_bytes']==raw[at(h,16):at(h,16)+16].hex() and un('<q',at(h))[0]==row['offset_to_top'] and abs(row['offset_to_top'])<=1048576 and row['address_point']==hex(h+16)
        tv=relocation(row['typeinfo_slot_relocation'],h+8);assert row['typeinfo']==hex(tv) and tv in typeinfos and typeinfos[tv]['abi_vtable_symbol']['name'] in kinds and row['typeinfo_name']==typeinfos[tv]['name']
        named=[s for s in syms.values() if s['defined'] and s['name'].startswith('_ZTV') and s['size'] and int(s['address'],16)<=h and h+24<=int(s['address'],16)+s['size']]
        assert sorted(named,key=lambda x:x['name'])==sorted(row['containing_named_vtable_symbols'],key=lambda x:x['name']);limit=min([data[3]+data[5]]+[int(s['address'],16)+s['size'] for s in named]);assert row['slots']
        for ix,item in enumerate(row['slots']):
            slot=h+16+ix*8;target=relocation(item['relocation'],slot);assert slot+8<=limit and item['slot']==hex(slot) and item['slot_index_from_address_point']==ix and item['target']==hex(target) and target in fde and executable(target)
            unknown=target in catalog and catalog[target]['category']=='unknown';assert item['original_category_unknown']==unknown
            if unknown:targets.add(hex(target));slotcount+=1
            total+=1
        stop=h+16+len(row['slots'])*8;assert row['prefix_end_exclusive']==hex(stop) and row['prefix_not_complete_vtable_extent'] is True
        assert stop+8>limit or stop not in rel or pointer(stop) not in fde
    assert len(typeinfos)==d['typeinfo_objects'] and anon==d['typeinfo_objects_without_ZTI_symbol'] and len(headers)==d['vtable_prefix_count'] and len(targets)==d['unique_original_unknown_FDE_targets'] and slotcount==d['unknown_target_slot_links'] and set(d['unique_original_unknown_FDE_addresses'])==targets
    result={'integrity_passed':True,'profile':'independent-elf-rela-dynsym-rtti-links-v1','auditor_sha256':sha(pathlib.Path(__file__)),'rtti_links_sha256':sha(p),'source_sha256':SOURCE,'rtti_objects_verified':len(typeinfos),'vtable_prefixes_verified':len(headers),'all_FDE_slot_links_verified':total,'original_unknown_slot_links_verified':slotcount,'unique_original_unknown_FDE_targets_verified':len(targets),'unique_relocation_records_verified':len(verified_relocs),'producer_or_ELF_parser_imported':False,'runtime_symbol_binding_or_virtual_dispatch_proven':False}
    (a.out/'independent-audit.json').write_text(json.dumps(result,indent=2),encoding='utf8');print(json.dumps(result))
if __name__=='__main__':main()
