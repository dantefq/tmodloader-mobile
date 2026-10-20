"""Bounded field-RVA serialized vectors and their ItemID.Sets call sites.

Deliberately does not claim runtime memcpy equivalence or complete set membership.
"""
import argparse,hashlib,json,mmap,pathlib,struct,sys

ELF_SHA='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
META_SHA='4c904c49d168913d28ef547c4f461e539d926d2ed27c0253ed53a2954e9585f7'
MODEL_SHA='22f6f7fd1eba05ae5c284adcc4adb856296122133ff5050d8e9a553459ef02e3'
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def need(ok,msg):
    if not ok:raise ValueError(msg)
def signed(x,b):return x-(1<<b) if x&(1<<(b-1)) else x
def branch(w,pc):need(w&0x7c000000==0x14000000,'Direct branch');return pc+signed(w&0x3ffffff,26)*4
def page(w,pc):need(w&0x9f000000==0x90000000,'ADRP');return (pc&~4095)+(signed(((w>>29)&3)|(((w>>5)&0x7ffff)<<2),21)<<12)
def memory(w):need(w&0xffc00000 in (0xf9400000,0xf9000000),'X memory');return w&31,(w>>5)&31,((w>>10)&4095)*8
def movz(w):need(w&0xffe00000==0x52800000,'W MOVZ');return w&31,(w>>5)&65535

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);a=ap.parse_args();lab=a.lab;binary=lab/'native/libil2cpp.so';metadata=lab/'native/global-metadata.dat';need(sha(binary)==ELF_SHA and sha(metadata)==META_SHA,'Source SHA');fh=binary.open('rb');raw=mmap.mmap(fh.fileno(),0,access=mmap.ACCESS_READ);meta=metadata.read_bytes()
    def un(fmt,p):return struct.unpack_from(fmt,raw,p)
    po=un('<Q',32)[0];ps,pn=un('<HH',54);segments=[un('<II6Q',po+i*ps) for i in range(pn)]
    def at(va,n=8):
        hits=[s[2]+va-s[3] for s in segments if s[0]==1 and s[3]<=va and va+n<=s[3]+s[5]];need(len(hits)==1,'PT_LOAD bounds');return hits[0]
    def read(va,n):p=at(va,n);return raw[p:p+n]
    def word(va):return int.from_bytes(read(va,4),'little')
    so=un('<Q',40)[0];ss,sn=un('<HH',58);sections=[un('<IIQQQQIIQQ',so+i*ss) for i in range(sn)];proofs=[];cache={}
    def pointer(slot):
        if slot in cache:return cache[slot]
        found=[]
        for sec in sections:
            if sec[1]==4:
                for p in range(sec[4],sec[4]+sec[5],sec[9]):
                    target,info,add=un('<QQq',p)
                    if target==slot:found.append((p,info,add))
        if found:
            need(len(found)==1 and found[0][1]&0xffffffff==1027,'RELATIVE pointer');p,info,value=found[0];proofs.append({'slot':hex(slot),'target':hex(value),'relocation_file_offset':hex(p),'relocation_bytes':raw[p:p+24].hex()})
        else:value=int.from_bytes(read(slot,8),'little')
        cache[slot]=value;return value
    modelpath=lab/'static-field-roots-20261015/static-field-roots.json';need(sha(modelpath)==MODEL_SHA,'Frozen class-root model');model=json.loads(modelpath.read_text());modelauditpath=modelpath.parent/'independent-audit.json';modelaudit=json.loads(modelauditpath.read_text());need(modelaudit['integrity_passed'] and modelaudit['evidence_sha256']==MODEL_SHA,'Model audit');need(sha(modelpath.parent/'tools/terraria_static_field_root_evidence.py')==model['producer_sha256'] and sha(modelpath.parent/'tools/audit_terraria_static_field_roots.py')==modelaudit['auditor_sha256'],'Frozen tool SHA')
    for f in model['instruction_fragments']:
        b=read(int(f['start'],16),int(f['end_exclusive'],16)-int(f['start'],16));need(b.hex()==f['bytes'],'Model source bytes')
    # Kind4 is not inferred from a C locator: original native switch index3 byte16.
    need(read(0x2a32732+3,1)[0]==16 and 0x74bb5c+16*4==0x74bb9c,'Field usage case');need(word(0x74bbb0)==0xb980b908 and word(0x74bbb8)==0x8b344d14 and word(0x74bbbc)==0xb9400280 and branch(word(0x74bbc0),0x74bbc0)==0x74bcb0 and word(0x74bbcc)==0x8b091500,'FieldRef decoder shape')
    to,ts=struct.unpack_from('<II',meta,160);fo,fs=struct.unpack_from('<II',meta,96);ro,rs=struct.unpack_from('<II',meta,184);do,ds=struct.unpack_from('<II',meta,64);bo,bs=struct.unpack_from('<II',meta,72);stro,strs=struct.unpack_from('<II',meta,24)
    def string(i):need(0<=i<strs,'String bounds');return meta[stro+i:meta.index(b'\0',stro+i,stro+strs)].decode()
    def typedef(index):p=to+88*index;need(index>=0 and p+88<=to+ts,'Typedef bounds');return p,struct.unpack_from('<IIiiiiIIiiiiiiii8HII',meta,p)
    types=pointer(0x2fdb588+56);sizes=pointer(0x2fdb588+104);field_offsets=pointer(0x2fdb588+88);owner_offsets=pointer(field_offsets+1764*8);need(types==0x2ff5128,'Type registration')
    def type_record(index):p=pointer(types+index*8);data,bits=struct.unpack('<QI',read(p,12));return p,data,bits
    arrays=[]
    # Each tuple fixes one small, source-reproducible caller/blob scope.
    for refindex,got,usage_slot,expected_field,length,allocpc,initpc,setpc,storepc,staticoffset,default,callee in [(705,0x3057450,0x3134bd0,43866,3,0x1a89cc4,0x1a89cd4,0x1a89cf4,0x1a89d04,24,0,0x1acf484),(1134,0x3088bb8,0x3135938,44295,98,0x1a89d10,0x1a89d20,0x1a89d38,0x1a89d48,32,0,0x1acf484),(558,0x3043008,0x3134738,43719,8,0x1a89d9c,0x1a89dac,0x1a89dcc,0x1a89ddc,48,-1,0x1ac5a30)]:
        need(pointer(got)==usage_slot,'FieldHandle GOT');encoded=int.from_bytes(read(usage_slot,8),'little');need(encoded&1 and encoded>>29&7==4 and (encoded>>1)&0xfffffff==refindex,'Encoded FieldInfo usage')
        rp=ro+refindex*8;need(rp+8<=ro+rs,'FieldRef bounds');owner_type,local=struct.unpack_from('<ii',meta,rp);op,owner,ownerbits=type_record(owner_type);need(ownerbits>>16&255==18 and owner==3812,'PrivateImplementationDetails type');otp,ot=typedef(owner);need(string(ot[0])=='<PrivateImplementationDetails>' and 0<=local<ot[18],'Owner field bounds');field=ot[8]+local;need(field==expected_field,'Field ownership/index');fp=fo+field*12;fname,ftype,token=struct.unpack_from('<IiI',meta,fp);tp,td,tb=type_record(ftype);need(tb>>16&255==17 and tb&0x100,'RVA field valuetype');tdp,tt=typedef(td);need(tt[7]&0x18==0x10,'ExplicitLayout literal type');sizep=pointer(sizes+td*8);sizeinfo=struct.unpack('<4i',read(sizep,16));n=sizeinfo[1];need(n==length*4,'Native literal size vs caller count')
        matches=[p for p in range(do,do+ds,12) if struct.unpack_from('<i',meta,p)[0]==field];need(len(matches)==1,'Unique field default');dp=matches[0];di,dtype,dindex=struct.unpack_from('<iii',meta,dp);dtp,dtd,dtbits=type_record(dtype);need(dtd==td and dtbits>>16&255==17,'Default type same structure');need(0<=dindex and dindex+n<=bs,'Blob bounds');blob=meta[bo+dindex:bo+dindex+n];values=list(struct.unpack('<'+'i'*length,blob))
        need(movz(word(allocpc-20))==(1,length),'Caller allocation count');need(branch(word(allocpc),allocpc)==0x6ff5f4 and branch(word(initpc),initpc)==0x22bca34 and branch(word(setpc),setpc)==callee,'Caller branch targets');need(memory(word(storepc))==(0,8,staticoffset),'Static store offset');need(memory(word(storepc-4))==(8,8,184),'Static storage load')
        need(string(fname)==hashlib.sha256(blob).hexdigest().upper(),'Blob SHA256 does not match actual declared literal field name')
        argbase=21 if refindex==1134 else 20;need(memory(word(initpc-12))==(1,argbase,0) and word(initpc-4)==0xaa0003f4 and word(setpc-8)==0xaa1403e2,'Input handle/array register flow')
        if default==0:need(word(setpc-12)==0x2a1f03e1,'Boolean false argument')
        else:need(word(setpc-16)==0x12800001,'Int32 minus-one argument')
        fieldindex=30109+staticoffset//8;outp=fo+fieldindex*12;outname,outtype,outtoken=struct.unpack_from('<IiI',meta,outp);need(int.from_bytes(read(owner_offsets+(fieldindex-30109)*4,4),'little',signed=True)==staticoffset,'Declared static field offset');outtp,outtd,outbits=type_record(outtype);need(outbits&16,'Static output field flag')
        arrays.append({'fieldref_index':refindex,'fieldref_record_offset':hex(rp),'fieldref_record_bytes':meta[rp:rp+8].hex(),'handle_GOT':hex(got),'handle_usage_slot':hex(usage_slot),'initial_usage_word':hex(encoded),'initial_usage_bytes':read(usage_slot,8).hex(),'private_owner_typedef':owner,'private_owner_type_index':owner_type,'private_owner_native_type_pointer':hex(op),'source_field_index':field,'source_field_name':string(fname),'metadata_field_record_offset':hex(fp),'metadata_field_record_bytes':meta[fp:fp+12].hex(),'field_type_index':ftype,'field_native_type_pointer':hex(tp),'field_native_type_bytes':read(tp,12).hex(),'literal_typedef_index':td,'literal_metadata_record_offset':hex(tdp),'literal_metadata_record_bytes':meta[tdp:tdp+88].hex(),'literal_type_name':string(tt[0]),'native_size_record_pointer':hex(sizep),'native_size_record_bytes':read(sizep,16).hex(),'literal_byte_length':n,'field_default_record_offset':hex(dp),'field_default_record_bytes':meta[dp:dp+12].hex(),'field_default_type_index':dtype,'field_default_native_type_pointer':hex(dtp),'default_data_index':dindex,'blob_metadata_file_offset':hex(bo+dindex),'blob_bytes':blob.hex(),'blob_sha256':hashlib.sha256(blob).hexdigest(),'serialized_little_endian_Int32_values':values,'caller_allocation_count':length,'allocation_call':hex(allocpc),'InitializeArray_call':hex(initpc),'SetFactory_call':hex(setpc),'SetFactory_callee':hex(callee),'SetFactory_default_argument':default,'result_store':hex(storepc),'conditional_result_static_field':{'index':fieldindex,'name':string(outname),'offset':staticoffset,'metadata_record_offset':hex(outp),'metadata_record_bytes':meta[outp:outp+12].hex(),'native_offset_slot':hex(owner_offsets+(fieldindex-30109)*4)},'full_runtime_array_contents_proven':False,'full_set_membership_proven':False})
    # Direct singleton input is a separate source literal, not a field-RVA blob.
    need(movz(word(0x1a89d40))==(1,1) and branch(word(0x1a89d54),0x1a89d54)==0x6ff5f4 and movz(word(0x1a89d60))==(8,2342) and word(0x1a89d64)==0xb9002008 and movz(word(0x1a89d74))==(1,1) and branch(word(0x1a89d80),0x1a89d80)==0x1acf484 and memory(word(0x1a89d90))==(0,8,40),'Direct true singleton shape')
    for pc,loadpc,base,expectedgot in [(0x1a89c64,0x1a89c6c,20,0x3057450),(0x1a89cdc,0x1a89ce0,21,0x3088bb8),(0x1a89d6c,0x1a89d70,20,0x3043008)]:
        rt,rn,disp=memory(word(loadpc));need(rt==rn==base and page(word(pc),pc)+disp==expectedgot,'Handle root register acquisition')
    need(branch(word(0x22bca9c),0x22bca9c)==0x6ab73c and branch(word(0x6ab7bc),0x6ab7bc)==0x6e1fc8 and branch(word(0x6e1fec),0x6e1fec)==0x6ee4e4 and branch(word(0x6ee4e4),0x6ee4e4)==0x74be44,'InitializeArray field-data path')
    sys.path.insert(0,str(lab/'python-analysis'));from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;fragments=[];dual=0
    for label,start,end in [('fieldref_usage_case',0x74bb9c,0x74bbd8),('caller_blob_handles',0x1a89c60,0x1a89c70),('first_four_set_calls',0x1a89cac,0x1a89de0),('InitializeArray_wrapper',0x22bca34,0x22bcaa0),('InitializeArray_native',0x6ab73c,0x6ab7e0),('field_data_access',0x6e1fc8,0x6e1ff8),('field_default_lookup',0x74be44,0x74bf34),('BoolSet_fill_and_flip',0x1acf484,0x1acf51c)]:
        b=read(start,end-start);ins=list(cs.disasm(b,start));need(len(ins)*4==len(b),'Disassembly coverage')
        for i in ins:
            w=int.from_bytes(i.bytes,'little')
            if w&0x7c000000==0x14000000:need(i.operands[0].imm==branch(w,i.address),'Branch decoder agreement');dual+=1
            elif w&0x9f000000==0x90000000:need(i.operands[1].imm==page(w,i.address),'ADRP decoder agreement');dual+=1
            elif w&0xffc00000 in (0xf9400000,0xf9000000):
                rt,rn,disp=memory(w);rnname='sp' if rn==31 else 'x'+str(rn);rtname='xzr' if rt==31 else 'lr' if rt==30 else 'fp' if rt==29 else 'x'+str(rt);need(i.reg_name(i.operands[0].reg)==rtname and i.reg_name(i.operands[1].mem.base)==rnname and i.operands[1].mem.disp==disp,'Memory decoder agreement '+hex(i.address));dual+=1
        fragments.append({'label':label,'start':hex(start),'end_exclusive':hex(end),'bytes':b.hex(),'sha256':hashlib.sha256(b).hexdigest(),'instructions':[{'address':hex(i.address),'raw_bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str} for i in ins]})
    controls=[]
    for label,test in [('bad_kind',lambda:need(0x20000583>>29&7==4,'Field usage kind')),('bad_ref_index',lambda:need((0x80000585>>1)&0xfffffff==705,'Fieldref index')),('bad_native_size',lambda:need(12==4*4,'Literal size')),('wrong_result_offset',lambda:need(memory(0xf9001100)==(0,8,24),'Result offset')),('wrong_singleton',lambda:need(movz(0x528124a8)==(8,2342),'Singleton value'))]:
        try:test()
        except ValueError:controls.append(label)
        else:raise ValueError('Negative accepted '+label)
    out=lab/'itemsets-array-literals-20261015';out.mkdir(exist_ok=True)
    doc={'profile':'itemsets-field-RVA-serialized-vectors-and-call-sites-v1','elf_sha256':ELF_SHA,'metadata_sha256':META_SHA,'producer_sha256':sha(pathlib.Path(__file__)),'dependencies':{'static-field-roots-20261015/static-field-roots.json':MODEL_SHA,'static-field-roots-20261015/independent-audit.json':sha(modelauditpath)},'arrays':arrays,'direct_singleton':{'caller_allocation_count':1,'Int32_literal':2342,'SetFactory_default_argument':1,'SetFactory_call':'0x1a89d80','conditional_result_static_field':'Terraria.ID.ItemID+Sets.ReceivesDiagonalCorrectionAsFakeFish','static_offset':40,'result_store':'0x1a89d90'},'pointer_proofs':proofs,'instruction_fragments':fragments,'dual_decoder_checked_instructions':dual,'negative_controls_rejected':controls,'conditions':model['conditions']+['The shown caller fragments execute and helper calls return normally, preserving AAPCS64 callee-saved registers.','FieldHandle kind4 resolution follows the decoded case and returns FieldInfo for the corresponding original metadata field reference.','Global class/fieldhandle roots and static storage pointers remain stable through the recorded calls/stores.'],'limitations':['The three recovered vectors are observed serialized metadata blobs interpreted as little-endian Int32, not proof of actual runtime InitializeArray output.','The native FieldData helper and copy path are retained as evidence, but complete field-cache construction, bsearch comparator, PLT memcpy binding, element-size evaluation and bootstrap reachability were not independently audited here.','Output static field attribution concerns the return value of the named SetFactory call; full table membership and IntSet input-pair semantics are not asserted.','BoolSet native body conditionally fills default then writes inverted default at supplied indices; allocation/cache validity and full execution are not established.','No complete original C# or full initializer reconstruction.'],'baseline_modified':False,'low_memory_processing':True}
    singleton_field=30114;sp=fo+singleton_field*12;sn,st,stok=struct.unpack_from('<IiI',meta,sp);sslot=owner_offsets+(singleton_field-30109)*4;need(string(sn)=='ReceivesDiagonalCorrectionAsFakeFish' and int.from_bytes(read(sslot,4),'little',signed=True)==40,'Singleton output field source')
    doc['direct_singleton']['declared_target']={'field_index':singleton_field,'metadata_record_offset':hex(sp),'metadata_record_bytes':meta[sp:sp+12].hex(),'native_offset_slot':hex(sslot),'native_offset_bytes':read(sslot,4).hex()}
    doc['all_literal_field_names_match_blob_SHA256']=True
    methods_path=lab/'metadata/methods.jsonl';wanted={16864:('CreateBoolSet','0x1acf484'),16866:('CreateIntSet','0x1ac5a30'),36334:('InitializeArray','0x22bca34')};aliases=[]
    for line in methods_path.open(encoding='utf8'):
        method=json.loads(line)
        if method['index'] not in wanted:continue
        expected_name,expected_address=wanted[method['index']];need(method['name']==expected_name and method['native_address']==expected_address,'Prior native method binding changed');aliases.append({k:method[k] for k in ('index','owner_type','name','native_address','display_signature','flags')})
    need(len(aliases)==3,'Method aliases incomplete');doc['dependencies']['metadata/methods.jsonl']=sha(methods_path);doc['method_aliases_from_hashed_prior_native_catalog']=aliases
    doc['limitations'].append('Native method names reuse the hashed prior method-address catalog; this extension independently checks native instructions and source metadata fields, not the entire code-registration method-pointer recovery.')
    (out/'array-literals.json').write_text(json.dumps(doc,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    (out/'REPORT.ru.md').write_text('# Три литеральных вектора ItemID.Sets\n\nПо исходным kind4 field handles, fieldrefs, объявленным RVA-полям, field-default records и нативным размерам ExplicitLayout-структур подтверждены три сериализованных Int32-вектора: 3 значения `[205, 5004, 4955]`, 98 значений (полный список в JSON) и 8 значений `[6168, 6168, 6169, 6168, 6194, 6168, 6193, 6168]`. Размеры исходных blobs: 12, 392 и 32 байта.\n\nОни связаны с handles, передаваемыми InitializeArray в первых трёх соответствующих вызовах. Возвращаемые значения последующих SetFactory-вызовов условно записываются в DualEquipArmor (default false), AllowSmartInteractOnCursorItem (default false), AccessoryIncompatibilityType (default -1). Отдельно подтверждён прямой singleton input2342/default true перед записью результата в ReceivesDiagonalCorrectionAsFakeFish.\n\nЭто проверенные сериализованные данные и caller/store association. Полное фактическое содержимое runtime-массивов и membership не заявляются: цепь FieldData/copy сохранена, но полный cache lookup, bsearch/memcpy binding и element-size исполнение не доказаны. Полные исходные байты, метаданные, значения, зависимости и ограничения находятся в `array-literals.json`.\n',encoding='utf8')
    print(json.dumps({'output':str(out),'blobs':3,'serialized_Int32_values':sum(len(x['serialized_little_endian_Int32_values']) for x in arrays),'literal_bytes':sum(x['literal_byte_length'] for x in arrays),'source_instruction_bytes':sum(len(bytes.fromhex(x['bytes'])) for x in fragments),'dual_decoder_instructions':dual,'negative_controls':len(controls)}));raw.close();fh.close()

if __name__=='__main__':main()
