"""Independent low-memory byte, relocation, field, type-root and branch audit."""
import argparse,copy,hashlib,json,mmap,pathlib,struct

SOURCE='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);ap.add_argument('--check-source-only',action='store_true');a=ap.parse_args();lab=a.lab;binary=lab/'native/libil2cpp.so';assert sha(binary)==SOURCE;bf=binary.open('rb');r=mmap.mmap(bf.fileno(),0,access=mmap.ACCESS_READ)
    def un(fmt,p):return struct.unpack_from(fmt,r,p)
    ph=un('<Q',32)[0];pw,pn=un('<HH',54);segments=[un('<II6Q',ph+i*pw) for i in range(pn)]
    def at(va,n=8):
        offsets=[s[2]+va-s[3] for s in segments if s[0]==1 and s[3]<=va and va+n<=s[3]+s[5]];assert len(offsets)==1;return offsets[0]
    def read(va,n):p=at(va,n);return r[p:p+n]
    def word(va):return un('<I',at(va,4))[0]
    def target(va):
        w=word(va);assert w&0x7c000000==0x14000000;imm=w&0x3ffffff;imm-=1<<26 if imm&1<<25 else 0;return va+imm*4
    def zero(va):
        w=word(va);assert w&0x7e000000==0x34000000;i=(w>>5)&0x7ffff;i-=1<<19 if i&1<<18 else 0;return va+i*4
    # Explicit fresh/reuse normal paths, shared allocator entry and header store.
    for pc,to in [(0x1acf6d8,0x1acf6f4),(0x1acf81c,0x1acf838)]:assert zero(pc)==to and word(pc)&0x01000000==0
    for pc,to in [(0x1acf704,0x6ff5f4),(0x1acf848,0x6ff5f4),(0x6ff5f8,0x7146a8),(0x75336c,0x7146a8),(0x1acf6ec,0x1f09574),(0x1acf830,0x1f09574),(0x1acf6f0,0x1acf708),(0x1acf834,0x1acf84c)]:assert target(pc)==to
    for pc,value in [(0x1acf6fc,0xb9401281),(0x1acf840,0xb9401281),(0x1acf708,0xaa0003f5),(0x1acf84c,0xaa0003f5),(0x1acf728,0xaa1503e0),(0x1acf86c,0xaa1503e0),(0x6ff5f4,0x2a0103e1),(0x7146b4,0xaa0103f4),(0x7147a8,0xf9000eb4),(0x7147c0,0xaa1503e0)]:assert word(pc)==value
    assert zero(0x7146c4)==0x7147d4 and word(0x7146c0)==0xd35ffe88
    if a.check_source_only:print(json.dumps({'source_paths_verified':2,'shared_allocator_export_target':'0x7146a8','header_length_store':'0x7147a8','fresh_size_load_offset':16,'returned_header_length_offset':24}));r.close();bf.close();return
    out=lab/'setfactory-buffer-model-20261015';p=out/'buffer-model.json';d=json.loads(p.read_text());metadata=lab/'native/global-metadata.dat';assert sha(metadata)==d['metadata_sha256']=='4c904c49d168913d28ef547c4f461e539d926d2ed27c0253ed53a2954e9585f7';m=metadata.read_bytes();so,ss=struct.unpack_from('<II',m,24);to,ts=struct.unpack_from('<II',m,160);fo,fs=struct.unpack_from('<II',m,96)
    def name(i):assert 0<=i<ss;return m[so+i:m.index(b'\0',so+i,so+ss)].decode()
    sh=un('<Q',40)[0];sw,sn=un('<HH',58);sections=[un('<IIQQQQIIQQ',sh+i*sw) for i in range(sn)];wanted={int(x['slot'],16) for x in d['pointer_proofs']};rel={};exports={}
    for sec in sections:
        if sec[1]==4:
            for off in range(sec[4],sec[4]+sec[5],sec[9]):
                slot,info,add=un('<QQq',off)
                if slot in wanted:assert slot not in rel and info&0xffffffff==1027;rel[slot]=(off,add)
        if sec[1]==11:
            pool=sections[sec[6]]
            for off in range(sec[4],sec[4]+sec[5],sec[9]):
                ni,flags,other,defined,value,size=un('<IBBHQQ',off);base=pool[4]+ni;end=r.find(b'\0',base,pool[4]+pool[5]);text=r[base:end].decode()
                if defined:exports[text]=(value,size,off)
    def ptr(slot):return rel[slot][1] if slot in rel else un('<Q',at(slot))[0]
    def verify(doc):
        assert doc['elf_sha256']==SOURCE
        for dep,h in doc['dependencies'].items():assert sha(lab/dep)==h
        assert doc['dependencies']['static-field-roots-20261015/static-field-roots.json']=='22f6f7fd1eba05ae5c284adcc4adb856296122133ff5050d8e9a553459ef02e3'
        for proof in doc['pointer_proofs']:
            slot=int(proof['slot'],16);off,value=rel[slot];assert proof['target']==hex(value) and proof['relocation_file_offset']==hex(off) and proof['relocation_bytes']==r[off:off+24].hex()
        for f in doc['instruction_fragments']:
            start=int(f['start'],16);end=int(f['end_exclusive'],16);b=read(start,end-start);assert f['bytes']==b.hex() and f['sha256']==hashlib.sha256(b).hexdigest() and len(f['instructions'])*4==len(b)
            for i,ins in enumerate(f['instructions']):assert ins['address']==hex(start+i*4) and ins['raw_bytes']==b[i*4:i*4+4].hex()
        typ=struct.unpack_from('<IIiiiiIIiiiiiiii8HII',m,to+1808*88);assert name(typ[0])=='SetFactory' and name(typ[1])=='Terraria.ID';offsets=ptr(ptr(0x2fdb588+88)+1808*8)
        for field,index,expected_name,offset in zip(doc['factory_field_sources'],[33140,33141,33143,33145],['_size','_intBufferCache','_boolBufferCache','_queueLock'],[16,24,40,56]):
            fp=fo+index*12;ni,ti,token=struct.unpack_from('<IiI',m,fp);slot=offsets+(index-typ[8])*4;tp=ptr(0x2ff5128+ti*8);data,bits=un('<QI',at(tp,12));assert typ[8]<=index<typ[8]+typ[18] and name(ni)==field['name']==expected_name and field['index']==index and field['offset']==un('<i',at(slot,4))[0]==offset and field['metadata_record_file_offset']==hex(fp) and field['metadata_record_bytes']==m[fp:fp+12].hex() and field['native_offset_slot']==hex(slot) and field['native_offset_bytes']==read(slot,4).hex() and field['native_field_type_pointer']==hex(tp) and field['native_field_type_bytes']==read(tp,12).hex() and not bits&16 and field['instance_storage'] is True
        for row,kind,got,slot,index,tag,cache in zip(doc['buffers'],['bool','int'],[0x305c5f8,0x3077198],[0x3104b38,0x3104e60],[5719,5924],[2,8],[40,24]):
            assert row['kind']==kind and row['cache_field_offset']==cache and row['observed_cache_test_offset']==32 and row['array_root_GOT']==hex(got) and ptr(got)==slot and row['array_usage_slot']==hex(slot);encoded=un('<Q',at(slot))[0];assert encoded&1 and encoded>>29&7==1 and (encoded>>1)&0xfffffff==index and row['array_type_index']==index and row['initial_usage_word']==hex(encoded) and row['initial_usage_bytes']==read(slot,8).hex();tp=ptr(0x2ff5128+index*8);td,tb=un('<QI',at(tp,12));ep=ptr(tp);ed,eb=un('<QI',at(ep,12));assert tb>>16&255==29 and eb>>16&255==row['element_type_tag']==tag and row['native_array_type_pointer']==hex(tp) and row['native_array_type_bytes']==read(tp,12).hex() and row['native_element_type_pointer']==hex(ep) and row['native_element_type_bytes']==read(ep,12).hex()
        e=doc['allocator_export'];value,size,off=exports['il2cpp_array_new_specific'];assert (value,size)==(0x75336c,4) and e['address']==hex(value) and e['size']==size and e['symbol_record_file_offset']==hex(off) and e['symbol_record_bytes']==r[off:off+24].hex()
    verify(d);rejected=[]
    for label,mut in [('wrong_bool_cache',lambda x:x['buffers'][0].update(cache_field_offset=24)),('wrong_size_field_offset',lambda x:x['factory_field_sources'][0].update(offset=20)),('wrong_element_type',lambda x:x['buffers'][0].update(element_type_tag=8)),('wrong_allocator_export',lambda x:x['allocator_export'].update(address='0x753368')),('changed_length_store_bytes',lambda x:x['instruction_fragments'][4].update(bytes='00'*300)),('wrong_array_usage_index',lambda x:x['buffers'][1].update(array_type_index=5925))]:
        bad=copy.deepcopy(d);mut(bad)
        try:verify(bad)
        except (AssertionError,ValueError,KeyError):rejected.append(label)
        else:raise AssertionError('Negative accepted '+label)
    result={'integrity_passed':True,'auditor_sha256':sha(pathlib.Path(__file__)),'evidence_sha256':sha(p),'producer_or_ELF_parser_imported':False,'mmap_low_memory':True,'factory_fields_verified':4,'fresh_and_reuse_paths_verified':2,'array_roots_verified':2,'array_allocator_export_shared_target':'0x7146a8','source_instruction_bytes_verified':904,'native_length_header_store_verified':True,'negative_controls_rejected':rejected,'full_cached_length_or_ownership_invariant_proven':False,'runtime_execution_proven':False}
    (out/'independent-audit.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8');print(json.dumps(result));r.close();bf.close()

if __name__=='__main__':main()
