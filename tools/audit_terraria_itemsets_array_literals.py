"""Fresh mmap ELF/metadata audit, no producer or previous ELF-parser imports."""
import argparse,copy,hashlib,json,mmap,pathlib,struct

def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);a=ap.parse_args();lab=a.lab;out=lab/'itemsets-array-literals-20261015';p=out/'array-literals.json';d=json.loads(p.read_text());binary=lab/'native/libil2cpp.so';metadata=lab/'native/global-metadata.dat';assert sha(binary)==d['elf_sha256']=='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5' and sha(metadata)==d['metadata_sha256']=='4c904c49d168913d28ef547c4f461e539d926d2ed27c0253ed53a2954e9585f7';bf=binary.open('rb');r=mmap.mmap(bf.fileno(),0,access=mmap.ACCESS_READ);m=metadata.read_bytes()
    def un(fmt,p):return struct.unpack_from(fmt,r,p)
    ph=un('<Q',32)[0];pw,pn=un('<HH',54);segments=[un('<II6Q',ph+i*pw) for i in range(pn)]
    def locate(va,n=8):
        hits=[s[2]+va-s[3] for s in segments if s[0]==1 and s[3]<=va and va+n<=s[3]+s[5]];assert len(hits)==1;return hits[0]
    sh=un('<Q',40)[0];sw,sn=un('<HH',58);sections=[un('<IIQQQQIIQQ',sh+i*sw) for i in range(sn)];wanted={int(x['slot'],16) for x in d['pointer_proofs']};rel={}
    for s in sections:
        if s[1]==4:
            for off in range(s[4],s[4]+s[5],s[9]):
                slot,info,add=un('<QQq',off)
                if slot in wanted:assert slot not in rel and info&0xffffffff==1027;rel[slot]=(off,add)
    def ptr(slot):return rel[slot][1] if slot in rel else un('<Q',locate(slot))[0]
    def word(va):return un('<I',locate(va,4))[0]
    def target(va):
        w=word(va);assert w&0x7c000000==0x14000000;i=w&0x3ffffff;i-=1<<26 if i&1<<25 else 0;return va+i*4
    to,ts=struct.unpack_from('<II',m,160);fo,fs=struct.unpack_from('<II',m,96);ro,rs=struct.unpack_from('<II',m,184);do,ds=struct.unpack_from('<II',m,64);bo,bs=struct.unpack_from('<II',m,72);so,ss=struct.unpack_from('<II',m,24)
    def text(i):assert 0<=i<ss;return m[so+i:m.index(b'\0',so+i,so+ss)].decode()
    def native_type(i):p=ptr(0x2ff5128+8*i);data,bits=un('<QI',locate(p,12));return p,data,bits
    def record_equal(x,key,off,n):assert x[key]==m[off:off+n].hex()
    def verify(doc):
        for dep,h in doc['dependencies'].items():assert sha(lab/dep)==h
        mp=lab/'static-field-roots-20261015/static-field-roots.json';assert sha(mp)=='22f6f7fd1eba05ae5c284adcc4adb856296122133ff5050d8e9a553459ef02e3';model=json.loads(mp.read_text())
        for f in doc['instruction_fragments']+model['instruction_fragments']:
            start=int(f['start'],16);end=int(f['end_exclusive'],16);b=r[locate(start,end-start):locate(start,end-start)+end-start];assert f['bytes']==b.hex() and f['sha256']==hashlib.sha256(b).hexdigest() and len(f['instructions'])*4==len(b)
            for i,t in enumerate(f['instructions']):assert t['address']==hex(start+i*4) and t['raw_bytes']==b[i*4:i*4+4].hex()
        for proof in doc['pointer_proofs']:
            slot=int(proof['slot'],16);off,value=rel[slot];assert proof['target']==hex(value) and proof['relocation_file_offset']==hex(off) and proof['relocation_bytes']==r[off:off+24].hex()
        assert r[locate(0x2a32735,1)]==16 and word(0x74bbb0)==0xb980b908 and word(0x74bbb8)==0x8b344d14 and word(0x74bbcc)==0x8b091500
        for x,ref,count,field,default,offset,fieldname in zip(doc['arrays'],[705,1134,558],[3,98,8],[43866,44295,43719],[0,0,-1],[24,32,48],['DualEquipArmor','AllowSmartInteractOnCursorItem','AccessoryIncompatibilityType']):
            assert x['fieldref_index']==ref and x['caller_allocation_count']==count and x['source_field_index']==field and x['SetFactory_default_argument']==default
            usage=int(x['handle_usage_slot'],16);got=int(x['handle_GOT'],16);encoded=un('<Q',locate(usage))[0];assert ptr(got)==usage and encoded&1 and encoded>>29&7==4 and (encoded>>1)&0xfffffff==ref and x['initial_usage_word']==hex(encoded) and x['initial_usage_bytes']==r[locate(usage):locate(usage)+8].hex()
            rp=ro+ref*8;assert rp+8<=ro+rs and x['fieldref_record_offset']==hex(rp);record_equal(x,'fieldref_record_bytes',rp,8);ti,local=struct.unpack_from('<ii',m,rp);ownerp,owner,bits=native_type(ti);assert bits>>16&255==18 and owner==3812 and x['private_owner_typedef']==owner and x['private_owner_type_index']==ti and x['private_owner_native_type_pointer']==hex(ownerp);ot=struct.unpack_from('<IIiiiiIIiiiiiiii8HII',m,to+owner*88);assert text(ot[0])=='<PrivateImplementationDetails>' and 0<=local<ot[18] and ot[8]+local==field
            fp=fo+field*12;assert fp+12<=fo+fs and x['metadata_field_record_offset']==hex(fp);record_equal(x,'metadata_field_record_bytes',fp,12);name,typ,token=struct.unpack_from('<IiI',m,fp);assert text(name)==x['source_field_name'] and typ==x['field_type_index'];tp,td,tbits=native_type(typ);assert td==x['literal_typedef_index'] and tbits>>16&255==17 and tbits&0x100 and x['field_native_type_pointer']==hex(tp) and x['field_native_type_bytes']==r[locate(tp):locate(tp)+12].hex();tdp=to+td*88;assert tdp+88<=to+ts and x['literal_metadata_record_offset']==hex(tdp);record_equal(x,'literal_metadata_record_bytes',tdp,88);tr=struct.unpack_from('<IIiiiiIIiiiiiiii8HII',m,tdp);assert tr[7]&0x18==0x10 and text(tr[0])==x['literal_type_name']
            sizep=ptr(ptr(0x2fdb588+104)+td*8);native_size=un('<4i',locate(sizep,16));assert native_size[1]==x['literal_byte_length']==count*4 and x['native_size_record_pointer']==hex(sizep) and x['native_size_record_bytes']==r[locate(sizep):locate(sizep)+16].hex()
            dp=int(x['field_default_record_offset'],16);assert do<=dp and dp+12<=do+ds and (dp-do)%12==0;record_equal(x,'field_default_record_bytes',dp,12);di,dt,dx=struct.unpack_from('<iii',m,dp);dtp,dtd,dtbits=native_type(dt);assert di==field and dtd==td and dtbits>>16&255==17 and dt==x['field_default_type_index'] and x['field_default_native_type_pointer']==hex(dtp) and dx==x['default_data_index'] and 0<=dx and dx+count*4<=bs
            blob=m[bo+dx:bo+dx+count*4];assert x['blob_metadata_file_offset']==hex(bo+dx) and x['blob_bytes']==blob.hex() and x['blob_sha256']==hashlib.sha256(blob).hexdigest() and x['serialized_little_endian_Int32_values']==list(struct.unpack('<'+'i'*count,blob)) and text(name)==hashlib.sha256(blob).hexdigest().upper()
            out=x['conditional_result_static_field'];idx=30109+offset//8;op=fo+idx*12;on,ot,token=struct.unpack_from('<IiI',m,op);os=ptr(ptr(0x2fdb588+88)+1764*8)+(idx-30109)*4;assert text(on)==out['name']==fieldname and out['index']==idx and out['offset']==offset and out['metadata_record_offset']==hex(op) and out['metadata_record_bytes']==m[op:op+12].hex() and out['native_offset_slot']==hex(os) and un('<i',locate(os,4))[0]==offset
            alloc=int(x['allocation_call'],16);init=int(x['InitializeArray_call'],16);setcall=int(x['SetFactory_call'],16);store=int(x['result_store'],16);assert target(alloc)==0x6ff5f4 and target(init)==0x22bca34 and target(setcall)==int(x['SetFactory_callee'],16) and (word(alloc-20)>>5)&65535==count and word(store)&0xffc003ff==0xf9000100 and ((word(store)>>10)&4095)*8==offset
        singleton=doc['direct_singleton'];assert singleton['caller_allocation_count']==1 and singleton['Int32_literal']==2342 and singleton['SetFactory_default_argument']==1 and word(0x1a89d60)==0x528124c8 and word(0x1a89d64)==0xb9002008 and target(0x1a89d80)==0x1acf484 and word(0x1a89d90)==0xf9001500
        sf=singleton['declared_target'];sp=fo+30114*12;sn,st,token=struct.unpack_from('<IiI',m,sp);sslot=ptr(ptr(0x2fdb588+88)+1764*8)+20;assert sf['field_index']==30114 and text(sn)=='ReceivesDiagonalCorrectionAsFakeFish' and sf['metadata_record_offset']==hex(sp) and sf['metadata_record_bytes']==m[sp:sp+12].hex() and sf['native_offset_slot']==hex(sslot) and sf['native_offset_bytes']==r[locate(sslot):locate(sslot)+4].hex() and un('<i',locate(sslot,4))[0]==40
        assert doc['arrays'][0]['serialized_little_endian_Int32_values']==[205,5004,4955] and doc['arrays'][2]['serialized_little_endian_Int32_values']==[6168,6168,6169,6168,6194,6168,6193,6168]
    verify(d);reject=[]
    for label,mut in [('wrong_fieldref',lambda x:x['arrays'][0].update(fieldref_index=706)),('wrong_blob_value',lambda x:x['arrays'][0]['serialized_little_endian_Int32_values'].__setitem__(0,206)),('wrong_native_size',lambda x:x['arrays'][1].update(literal_byte_length=388)),('wrong_default_index',lambda x:x['arrays'][2].update(default_data_index=81121)),('wrong_static_output',lambda x:x['arrays'][0]['conditional_result_static_field'].update(offset=32)),('wrong_singleton',lambda x:x['direct_singleton'].update(Int32_literal=2341))]:
        bad=copy.deepcopy(d);mut(bad)
        try:verify(bad)
        except (AssertionError,ValueError,KeyError):reject.append(label)
        else:raise AssertionError('Negative accepted '+label)
    result={'integrity_passed':True,'auditor_sha256':sha(pathlib.Path(__file__)),'evidence_sha256':sha(p),'producer_or_ELF_parser_imported':False,'fresh_mmap_ELF_metadata_parsing':True,'serialized_blobs_verified':3,'serialized_Int32_values_verified':109,'literal_blob_bytes_verified':436,'new_native_instruction_bytes_verified':1096,'negative_controls_rejected':reject,'runtime_array_contents_or_set_membership_proven':False}
    (out/'independent-audit.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8');print(json.dumps(result));r.close();bf.close()

if __name__=='__main__':main()
