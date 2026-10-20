"""Independent low-memory ELF/metadata/source-byte audit of NPC Factory extension."""
import argparse,copy,hashlib,json,mmap,pathlib,struct

def sha(p):
    with p.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);a=ap.parse_args();lab=a.lab;out=lab/'npc-static-field-roots-20261015';p=out/'npc-static-field-roots.json';d=json.loads(p.read_text());binary=lab/'native/libil2cpp.so';metadata=lab/'native/global-metadata.dat'
    assert sha(binary)==d['elf_sha256']=='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5' and sha(metadata)==d['metadata_sha256']=='4c904c49d168913d28ef547c4f461e539d926d2ed27c0253ed53a2954e9585f7';bf=binary.open('rb');raw=mmap.mmap(bf.fileno(),0,access=mmap.ACCESS_READ);meta=metadata.read_bytes()
    def unpack(fmt,offset):return struct.unpack_from(fmt,raw,offset)
    ph=unpack('<Q',32)[0];width,count=unpack('<HH',54);segments=[unpack('<IIQQQQQQ',ph+i*width) for i in range(count)]
    def location(va,n=8):
        offsets=[s[2]+va-s[3] for s in segments if s[0]==1 and s[3]<=va and va+n<=s[3]+s[5]];assert len(offsets)==1;return offsets[0]
    sh=unpack('<Q',40)[0];sw,sc=unpack('<HH',58);sections=[unpack('<IIQQQQIIQQ',sh+i*sw) for i in range(sc)]
    selected={int(r['slot'],16) for r in d['pointer_proofs']};rel={}
    for sec in sections:
        if sec[1]!=4:continue
        for off in range(sec[4],sec[4]+sec[5],sec[9]):
            slot,info,add=unpack('<QQq',off)
            if slot in selected:assert slot not in rel and info&0xffffffff==1027;rel[slot]=(off,add)
    def pointer(slot):return rel[slot][1]
    def instruction(va):return unpack('<I',location(va,4))[0]
    def target(va):
        w=instruction(va);assert w&0x7c000000==0x14000000;imm=w&0x3ffffff;imm-=1<<26 if imm&1<<25 else 0;return va+imm*4
    to,ts=struct.unpack_from('<II',meta,160);fo,fs=struct.unpack_from('<II',meta,96);so,ss=struct.unpack_from('<II',meta,24)
    def name(index):assert 0<=index<ss;return meta[so+index:meta.index(b'\0',so+index,so+ss)].decode()
    def verify(doc):
        for dep,h in doc['dependencies'].items():assert sha(lab/dep)==h
        modelpath=lab/'static-field-roots-20261015/static-field-roots.json';assert sha(modelpath)=='22f6f7fd1eba05ae5c284adcc4adb856296122133ff5050d8e9a553459ef02e3';model=json.loads(modelpath.read_text())
        for f in model['instruction_fragments']+doc['instruction_fragments']:
            start=int(f['start'],16);end=int(f['end_exclusive'],16);pos=location(start,end-start);b=raw[pos:pos+end-start];assert b.hex()==f['bytes'] and hashlib.sha256(b).hexdigest()==f['sha256']
            assert len(f['instructions'])*4==len(b)
            for i,ins in enumerate(f['instructions']):assert ins['address']==hex(start+i*4) and ins['raw_bytes']==b[i*4:i*4+4].hex()
        for r in doc['pointer_proofs']:
            slot=int(r['slot'],16);off,value=rel[slot];assert r['target']==hex(value) and r['relocation_file_offset']==hex(off) and r['relocation_bytes']==raw[off:off+24].hex() and r['in_place_bytes']==raw[location(slot):location(slot)+8].hex()
        assert pointer(0x306f9c0)==0x2fdb588 and pointer(0x2fdb5c0)==0x2ff5128 and pointer(0x3087cf0)==0x310de38
        r=doc['root'];slot=int(r['usage_slot'],16);assert slot==0x310de38;encoded=unpack('<Q',location(slot))[0];assert encoded==0x20009943 and encoded&1 and encoded>>29&7==1 and (encoded>>1)&0xfffffff==r['type_index']==19617 and r['encoded_word']==hex(encoded) and r['encoded_bytes']==raw[location(slot):location(slot)+8].hex()
        tp=pointer(0x2ff5128+19617*8);td,bits=unpack('<QI',location(tp,12));assert td==r['typedef_index']==1789 and bits>>16&255==18 and r['type_pointer']==hex(tp) and r['native_type_bytes']==raw[location(tp):location(tp)+12].hex();off=to+td*88;assert off+88<=to+ts and r['metadata_record_file_offset']==hex(off) and r['metadata_record_bytes']==meta[off:off+88].hex();ni,nsi,byval,parent=struct.unpack_from('<IIii',meta,off);assert name(ni)=='Sets' and byval==19617 and struct.unpack_from('<i',meta,off+32)[0]==31552
        pp=pointer(0x2ff5128+parent*8);pd,pb=unpack('<QI',location(pp,12));assert pd==1790 and pb>>16&255==18 and r['nested_parent_typedef_index']==pd and r['nested_parent_type_pointer']==hex(pp);pn,pns=struct.unpack_from('<II',meta,to+pd*88);assert name(pn)=='NPCID' and name(pns)=='Terraria.ID'
        f=doc['field'];off=fo+31552*12;ni,fti,token=struct.unpack_from('<IiI',meta,off);assert off+12<=fo+fs and f['field_index']==31552 and name(ni)==f['name']=='Factory' and f['type_index']==fti and f['metadata_record_file_offset']==hex(off) and f['metadata_record_bytes']==meta[off:off+12].hex();fp=pointer(0x2ff5128+fti*8);fd,fb=unpack('<QI',location(fp,12));assert fd==1808 and fb>>16&255==18 and fb&16 and f['static'] is True and f['native_type_pointer']==hex(fp) and f['native_type_bytes']==raw[location(fp):location(fp)+12].hex()
        offsets=pointer(0x2fdb588+88);native_slot=pointer(offsets+1789*8);assert f['native_offset_slot']==hex(native_slot) and unpack('<i',location(native_slot,4))[0]==f['static_offset']==0 and f['native_offset_bytes']==raw[location(native_slot):location(native_slot)+4].hex()
        assert target(0x1aaeb6c)==0x6ff5ac and target(0x1aaf3bc)==0x1ac5848
        assert instruction(0x1aaf3b0)==0x52805721 and instruction(0x1aaf3b8)==0xaa0003f3 and instruction(0x1aaf3c0)==0xf94002e8 and instruction(0x1aaf3c4)==0xf9405d08 and instruction(0x1aaf3c8)==0xf9000113
        method_base,method_size=struct.unpack_from('<II',meta,48)
        for label,index,owner,method_name in [('constructor',16857,1808,'.ctor'),('initializer',16807,1789,'.cctor')]:
            off=method_base+index*36;assert off+36<=method_base+method_size;record=doc['metadata_method_declarations'][label];assert record['index']==index and record['record_file_offset']==hex(off) and record['record_bytes']==meta[off:off+36].hex();ni,declaring=struct.unpack_from('<Ii',meta,off);assert declaring==owner and name(ni)==method_name
    verify(d);rejected=[]
    for label,mutate in [('wrong_type_index',lambda x:x['root'].update(type_index=19618)),('wrong_typedef',lambda x:x['root'].update(typedef_index=1790)),('wrong_offset',lambda x:x['field'].update(static_offset=8)),('wrong_rel_target',lambda x:x['pointer_proofs'][0].update(target='0x0')),('changed_store_bytes',lambda x:x['instruction_fragments'][1].update(bytes='00'*44))]:
        bad=copy.deepcopy(d);mutate(bad)
        try:verify(bad)
        except (AssertionError,ValueError,KeyError):rejected.append(label)
        else:raise AssertionError('Negative accepted: '+label)
    result={'integrity_passed':True,'auditor_sha256':sha(pathlib.Path(__file__)),'evidence_sha256':sha(p),'producer_or_ELF_parser_imported':False,'mmap_low_memory':True,'new_instruction_bytes_verified':56,'frozen_bootstrap_fragments_rebound':13,'NPC_class_usage_root_verified':True,'declared_static_Factory_offset_verified':0,'negative_controls_rejected':rejected,'runtime_execution_proven':False}
    (out/'independent-audit.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8');print(json.dumps(result));raw.close();bf.close()

if __name__=='__main__':main()
