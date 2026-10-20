"""Fresh ELF/metadata byte audit of conditional class-root evidence, without producer imports."""
import argparse,copy,hashlib,json,pathlib,struct

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);a=ap.parse_args();lab=a.lab;out=lab/'static-field-roots-20261015';p=out/'static-field-roots.json';d=json.loads(p.read_text(encoding='utf8'));raw=(lab/'native/libil2cpp.so').read_bytes();meta=(lab/'native/global-metadata.dat').read_bytes()
    assert hashlib.sha256(raw).hexdigest()==d['elf_sha256']=='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
    assert hashlib.sha256(meta).hexdigest()==d['metadata_sha256']=='4c904c49d168913d28ef547c4f461e539d926d2ed27c0253ed53a2954e9585f7'
    def un(fmt,off):return struct.unpack_from(fmt,raw,off)
    po=un('<Q',32)[0];ps,pn=un('<HH',54);segs=[un('<IIQQQQQQ',po+i*ps) for i in range(pn)]
    def at(va,n=8):
        candidates=[s[2]+va-s[3] for s in segs if s[0]==1 and s[3]<=va and va+n<=s[3]+s[5]];assert len(candidates)==1;return candidates[0]
    so=un('<Q',40)[0];ss,sn=un('<HH',58);secs=[un('<IIQQQQIIQQ',so+i*ss) for i in range(sn)];rel={};symbols={}
    for sec in secs:
        if sec[1]==4:
            for off in range(sec[4],sec[4]+sec[5],sec[9]):
                slot,info,add=un('<QQq',off)
                if info&0xffffffff==1027:rel[slot]=(off,add)
        if sec[1]==11:
            pool=secs[sec[6]]
            for off in range(sec[4],sec[4]+sec[5],sec[9]):
                name,flags,other,defined,value,size=un('<IBBHQQ',off);base=pool[4]+name;end=raw.index(b'\0',base,pool[4]+pool[5]);text=raw[base:end].decode()
                if defined:symbols[text]=(value,size)
    def ptr(slot):return rel[slot][1] if slot in rel else un('<Q',at(slot))[0]
    def mstring(index):
        off,size=struct.unpack_from('<II',meta,24);assert 0<=index<size;return meta[off+index:meta.index(b'\0',off+index,off+size)].decode()
    to,ts=struct.unpack_from('<II',meta,160);fo,fs=struct.unpack_from('<II',meta,96)
    def verify(doc):
        for item in doc['relocations_independently_reparsed']:
            slot=int(item['slot'],16);off,value=rel[slot];r=item['relocation'];assert int(item['value'],16)==value==r['addend'] and r['file_offset']==hex(off) and r['bytes']==raw[off:off+24].hex()
        for f in doc['instruction_fragments']:
            start=int(f['start'],16);end=int(f['end_exclusive'],16);b=raw[at(start,end-start):at(start,end-start)+end-start];assert b.hex()==f['bytes'] and hashlib.sha256(b).hexdigest()==f['sha256']
            assert len(f['instructions'])*4==len(b)
            for i,ins in enumerate(f['instructions']):assert ins['address']==hex(start+i*4) and ins['raw_bytes']==b[i*4:i*4+4].hex()
        assert ptr(0x306f9c0)==0x2fdb588 and ptr(0x2fdb5c0)==0x2ff5128 and ptr(0x30530c0)==0x310d958
        for r,expected_index,expected_def in zip(doc['roots'],[19270,14457],[1764,1808]):
            slot=int(r['slot'],16);w=un('<Q',at(slot))[0];index=(w>>1)&0xfffffff;assert w&1 and (w>>29)&7==1 and index==r['type_index']==expected_index and r['initial_bytes']==raw[at(slot):at(slot)+8].hex() and r['initial_word']==hex(w)
            t=ptr(0x2ff5128+index*8);data,bits=un('<QI',at(t));assert t==int(r['native_type_pointer'],16) and data==r['typedef_index']==expected_def and bits>>16&255==18 and r['native_type_bytes']==raw[at(t):at(t)+12].hex()
            off=to+data*88;assert off+88<=to+ts and r['metadata_type_record_file_offset']==hex(off) and r['metadata_type_record_bytes']==meta[off:off+88].hex();name,namespace,byval=struct.unpack_from('<IIi',meta,off);assert byval==index and mstring(name)==r['type_record_name'] and mstring(namespace)==r['namespace']
        f=doc['declared_static_field'];off=fo+30109*12;assert off+12<=fo+fs and f['index']==30109 and f['metadata_record_file_offset']==hex(off) and f['metadata_record_bytes']==meta[off:off+12].hex();name,typeindex,token=struct.unpack_from('<IiI',meta,off);assert mstring(name)=='Factory' and f['name']=='Factory' and typeindex==f['type_index'];t=ptr(0x2ff5128+typeindex*8);data,bits=un('<QI',at(t));assert data==1808 and bits&16 and bits>>16&255==18 and f['native_type_bytes']==raw[at(t):at(t)+12].hex()
        offsets=ptr(0x2fdb588+0x58);slot=ptr(offsets+1764*8);assert f['native_field_offset_slot']==hex(slot) and un('<i',at(slot))[0]==f['native_static_offset']==0 and f['native_field_offset_bytes']==raw[at(slot):at(slot)+4].hex()
        assert symbols['il2cpp_class_get_static_field_data']==(0x753450,8) and un('<II',at(0x753450))==(0xf9405c00,0xd65f03c0)
        for name,pc in [('il2cpp_class_from_type',0x753418),('il2cpp_class_from_il2cpp_type',0x7533b0)]:
            assert symbols[name]==(pc,8);mov,b=un('<II',at(pc));imm=b&0x3ffffff;imm-=1<<26 if imm&1<<25 else 0;assert mov==0x52800021 and b&0xfc000000==0x14000000 and pc+4+imm*4==0x6ea7ec
        sets_offset=to+1764*88;assert struct.unpack_from('<i',meta,sets_offset+32)[0]==30109
        parent_index=struct.unpack_from('<i',meta,sets_offset+12)[0];parent_type=ptr(0x2ff5128+parent_index*8);parent_def,parent_bits=un('<QI',at(parent_type));assert parent_bits>>16&255==18 and parent_def==1765;pn,pns=struct.unpack_from('<II',meta,to+parent_def*88);assert mstring(pn)=='ItemID' and mstring(pns)=='Terraria.ID'
    verify(d);rejected=[]
    for label,mut in [('wrong_usage_index',lambda x:x['roots'][0].update(type_index=19271)),('wrong_declared_type',lambda x:x['roots'][0].update(typedef_index=1765)),('wrong_static_offset',lambda x:x['declared_static_field'].update(native_static_offset=8)),('changed_instruction',lambda x:x['instruction_fragments'][0].update(bytes='00'*28)),('wrong_relocation',lambda x:x['relocations_independently_reparsed'][0].update(value='0x0'))]:
        bad=copy.deepcopy(d);mut(bad)
        try:verify(bad)
        except (AssertionError,ValueError,KeyError):rejected.append(label)
        else:raise AssertionError('Negative accepted '+label)
    result={'integrity_passed':True,'auditor_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'evidence_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'original_source_identity_verified':True,'fresh_ELF_and_metadata_parsing':True,'producer_or_ELF_parser_imported':False,'fragments_verified':len(d['instruction_fragments']),'source_bytes_verified':sum(len(bytes.fromhex(x['bytes'])) for x in d['instruction_fragments']),'class_usage_roots_verified':2,'static_field_offset_verified':0,'negative_controls_rejected':rejected,'runtime_execution_proven':False}
    (out/'independent-audit.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8');print(json.dumps(result))

if __name__=='__main__':main()
