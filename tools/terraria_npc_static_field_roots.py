"""Low-memory NPCID.Sets.Factory attribution, depending on frozen bootstrap proof."""
import argparse,hashlib,json,mmap,pathlib,struct,sys

ELF_SHA='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
META_SHA='4c904c49d168913d28ef547c4f461e539d926d2ed27c0253ed53a2954e9585f7'
MODEL_SHA='22f6f7fd1eba05ae5c284adcc4adb856296122133ff5050d8e9a553459ef02e3'
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def need(ok,msg):
    if not ok:raise ValueError(msg)
def signed(v,b):return v-(1<<b) if v&(1<<(b-1)) else v
def raw_branch(w,pc):need(w&0x7c000000==0x14000000,'Branch encoding');return pc+4*signed(w&0x3ffffff,26)
def raw_page(w,pc):need(w&0x9f000000==0x90000000,'ADRP encoding');return (pc&~4095)+(signed(((w>>29)&3)|(((w>>5)&0x7ffff)<<2),21)<<12)
def raw_mem(w):need(w&0xffc00000 in (0xf9400000,0xf9000000),'Memory encoding');return w&31,(w>>5)&31,((w>>10)&4095)*8

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);a=ap.parse_args();lab=a.lab
    binary=lab/'native/libil2cpp.so';metadata=lab/'native/global-metadata.dat';need(sha(binary)==ELF_SHA and sha(metadata)==META_SHA,'Source identity');f=binary.open('rb');raw=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ);meta=metadata.read_bytes()
    modelpath=lab/'static-field-roots-20261015/static-field-roots.json';auditpath=modelpath.parent/'independent-audit.json';need(sha(modelpath)==MODEL_SHA,'Frozen model changed');model=json.loads(modelpath.read_text());audit=json.loads(auditpath.read_text());need(audit['integrity_passed'] and audit['evidence_sha256']==MODEL_SHA,'Frozen model audit')
    need(sha(modelpath.parent/'tools/terraria_static_field_root_evidence.py')==model['producer_sha256'] and sha(modelpath.parent/'tools/audit_terraria_static_field_roots.py')==audit['auditor_sha256'],'Frozen model tools changed')
    def un(fmt,off):return struct.unpack_from(fmt,raw,off)
    po=un('<Q',32)[0];ps,pn=un('<HH',54);segments=[un('<II6Q',po+i*ps) for i in range(pn)]
    def at(va,n=8):
        found=[s[2]+va-s[3] for s in segments if s[0]==1 and s[3]<=va and va+n<=s[3]+s[5]];need(len(found)==1,'PT_LOAD bounds');return found[0]
    def read(va,n):off=at(va,n);return raw[off:off+n]
    def word(va):return int.from_bytes(read(va,4),'little')
    so=un('<Q',40)[0];ss,sn=un('<HH',58);sections=[un('<IIQQQQIIQQ',so+i*ss) for i in range(sn)];pointers=[]
    def pointer(slot):
        hits=[]
        for sec in sections:
            if sec[1]!=4:continue
            for off in range(sec[4],sec[4]+sec[5],sec[9]):
                target,info,add=un('<QQq',off)
                if target==slot:hits.append((off,info,add))
        need(len(hits)==1 and hits[0][1]&0xffffffff==1027,'Expected unique RELATIVE relocation');off,info,value=hits[0];pointers.append({'slot':hex(slot),'target':hex(value),'relocation_file_offset':hex(off),'relocation_bytes':raw[off:off+24].hex(),'in_place_bytes':read(slot,8).hex()});return value
    # Rebind frozen bootstrap proof to this exact original ELF, without a new global scan.
    for fragment in model['instruction_fragments']:
        b=read(int(fragment['start'],16),int(fragment['end_exclusive'],16)-int(fragment['start'],16));need(b.hex()==fragment['bytes'] and hashlib.sha256(b).hexdigest()==fragment['sha256'],'Model byte mismatch')
    to,ts=struct.unpack_from('<II',meta,160);fo,fs=struct.unpack_from('<II',meta,96);stro,strs=struct.unpack_from('<II',meta,24)
    def string(i):need(0<=i<strs,'String bounds');return meta[stro+i:meta.index(b'\0',stro+i,stro+strs)].decode()
    registration=pointer(0x306f9c0);need(registration==0x2fdb588,'Registration');types=pointer(registration+56);need(types==0x2ff5128,'Types table')
    got=0x3087cf0;slot=pointer(got);need(slot==0x310de38,'NPC class slot');encoded=int.from_bytes(read(slot,8),'little');index=(encoded>>1)&0xfffffff;need(encoded==0x20009943 and encoded&1 and encoded>>29&7==1 and index==19617,'NPC usage encoding')
    typeptr=pointer(types+index*8);data,bits=struct.unpack('<QI',read(typeptr,12));need(data==1789 and bits>>16&255==18,'NPC type record');off=to+data*88;need(off+88<=to+ts,'Type metadata bounds');typ=struct.unpack_from('<IIiiiiIIiiiiiiii8HII',meta,off);need(string(typ[0])=='Sets' and typ[2]==19617 and typ[8]==31552,'Sets owner identity')
    parentptr=pointer(types+typ[3]*8);parentdef,parentbits=struct.unpack('<QI',read(parentptr,12));parentoff=to+parentdef*88;parentname,parentns=struct.unpack_from('<II',meta,parentoff);need(parentbits>>16&255==18 and parentdef==1790 and string(parentname)=='NPCID' and string(parentns)=='Terraria.ID','Nested NPCID owner')
    fieldoff=fo+31552*12;need(fieldoff+12<=fo+fs,'Field bounds');name,fieldtype,token=struct.unpack_from('<IiI',meta,fieldoff);need(string(name)=='Factory','Factory field name');fieldptr=pointer(types+fieldtype*8);fielddef,fieldbits=struct.unpack('<QI',read(fieldptr,12));need(fielddef==1808 and fieldbits>>16&255==18 and fieldbits&16,'Static SetFactory field type')
    offsets=pointer(registration+88);fieldslot=pointer(offsets+1789*8);need(int.from_bytes(read(fieldslot,4),'little',signed=True)==0,'Factory native offset')
    # Actual caller root initialization, receiver capture, constructor and static store.
    need(raw_page(word(0x1aaeb64),0x1aaeb64)==0x3087000 and raw_mem(word(0x1aaeb68))==(0,0,0xcf0) and raw_branch(word(0x1aaeb6c),0x1aaeb6c)==0x6ff5ac,'Usage init suffix')
    need(raw_page(word(0x1aaf3a0),0x1aaf3a0)==0x3087000 and raw_mem(word(0x1aaf3a8))==(23,23,0xcf0),'Root acquisition')
    need(word(0x1aaf3b0)==0x52805721 and word(0x1aaf3b4)==0xaa1f03e2 and word(0x1aaf3b8)==0xaa0003f3 and raw_branch(word(0x1aaf3bc),0x1aaf3bc)==0x1ac5848,'Constructor 697 suffix')
    need(raw_mem(word(0x1aaf3c0))==(8,23,0) and raw_mem(word(0x1aaf3c4))==(8,8,184) and raw_mem(word(0x1aaf3c8))==(19,8,0),'Static receiver store')
    sys.path.insert(0,str(lab/'python-analysis'));from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;fragments=[];dual=0
    for label,start,end in [('NPC_usage_init',0x1aaeb64,0x1aaeb70),('NPC_factory_receiver_store',0x1aaf3a0,0x1aaf3cc)]:
        b=read(start,end-start);code=list(cs.disasm(b,start));need(len(code)*4==len(b),'Capstone coverage')
        for i in code:
            w=int.from_bytes(i.bytes,'little')
            if w&0x7c000000==0x14000000:need(i.operands[0].imm==raw_branch(w,i.address),'BL decoder agreement');dual+=1
            elif w&0x9f000000==0x90000000:need(i.operands[1].imm==raw_page(w,i.address),'ADRP decoder agreement');dual+=1
            elif w&0xffc00000 in (0xf9400000,0xf9000000):
                rt,rn,disp=raw_mem(w);need(i.reg_name(i.operands[0].reg)=='x'+str(rt) and i.reg_name(i.operands[1].mem.base)=='x'+str(rn) and i.operands[1].mem.disp==disp,'Memory decoder agreement');dual+=1
        fragments.append({'label':label,'start':hex(start),'end_exclusive':hex(end),'bytes':b.hex(),'sha256':hashlib.sha256(b).hexdigest(),'instructions':[{'address':hex(i.address),'raw_bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str} for i in code]})
    controls=[]
    for label,check in [('wrong_usage_type',lambda:need(((0x20009945>>1)&0xfffffff)==19617,'Usage index')),('wrong_kind',lambda:need((0x40009943>>29)&7==1,'Usage kind')),('wrong_store_offset',lambda:need(raw_mem(0xf9000513)==(19,8,0),'Store offset')),('wrong_receiver_register',lambda:need(raw_mem(0xf9000114)==(19,8,0),'Receiver register')),('wrong_ctor_target',lambda:need(raw_branch(0x94000000,0x1aaf3bc)==0x1ac5848,'Constructor target'))]:
        try:check()
        except ValueError:controls.append(label)
        else:raise ValueError('Negative accepted '+label)
    out=lab/'npc-static-field-roots-20261015';out.mkdir(exist_ok=True)
    doc={'profile':'conditional-npcsets-factory-static-assignment-v1','elf_sha256':ELF_SHA,'metadata_sha256':META_SHA,'producer_sha256':sha(pathlib.Path(__file__)),'dependencies':{'static-field-roots-20261015/static-field-roots.json':MODEL_SHA,'static-field-roots-20261015/independent-audit.json':sha(auditpath)},'bootstrap_fragments_rebound':len(model['instruction_fragments']),'root':{'got_slot':hex(got),'usage_slot':hex(slot),'encoded_word':hex(encoded),'encoded_bytes':read(slot,8).hex(),'usage_kind':1,'type_index':index,'type_pointer':hex(typeptr),'native_type_bytes':read(typeptr,12).hex(),'typedef_index':data,'declared_type':'Terraria.ID.NPCID+Sets','metadata_record_file_offset':hex(off),'metadata_record_bytes':meta[off:off+88].hex(),'nested_parent_type_pointer':hex(parentptr),'nested_parent_typedef_index':parentdef,'nested_parent_metadata_record_offset':hex(parentoff)},'field':{'field_index':31552,'name':'Factory','type_index':fieldtype,'native_type_pointer':hex(fieldptr),'native_type_bytes':read(fieldptr,12).hex(),'metadata_record_file_offset':hex(fieldoff),'metadata_record_bytes':meta[fieldoff:fieldoff+12].hex(),'native_offset_slot':hex(fieldslot),'native_offset_bytes':read(fieldslot,4).hex(),'static_offset':0,'static':True},'pointer_proofs':pointers,'instruction_fragments':fragments,'dual_decoder_checked_instructions':dual,'negative_controls_rejected':controls,'source_bound_inference':'Subject to the frozen bootstrap/ABI/global-state premises, the receiver passed to SetFactory::.ctor(size=697) is assigned to Terraria.ID.NPCID+Sets.Factory at0x1aaf3c8.','conditions':model['conditions']+['For this extension kind1/type19617 publishes NPCID.Sets class into usage slot0x310de38; that slot/static-storage pointer remain stable through the store.','Constructor0x1ac5848 returns normally and preserves X19/X23 according to AAPCS64.'],'limitations':['Conditional source evidence, not actual runtime execution, complete CFG reachability, concurrency or arbitrary helper side-effect proof.','Bootstrap/usage/ClassFromType/static-storage getter semantics reuse the exact frozen source-bound model by SHA; the extension does not claim an independent new bootstrap recovery.','No full static initializer, array contents or exact original C# recovered.'],'baseline_modified':False,'low_memory_processing':'Read-only mmap ELF; no Ghidra, no full relocation dictionary.'}
    # Replace ItemID-specific premise with the extension-specific case rather than silently inheriting it.
    doc['conditions']=[s for s in doc['conditions'] if '19270' not in s and '0x310d958' not in s]
    ctorpath=lab/'initializer-refinement-20261015/setfactory-size.json';ctorproof=json.loads(ctorpath.read_text());need(ctorproof['elf_sha256']==ELF_SHA and ctorproof['metadata_sha256']==META_SHA and ctorproof['constructor_identity']['index']==16857 and ctorproof['constructor_identity']['native_address']=='0x1ac5848','Prior constructor binding')
    doc['dependencies']['initializer-refinement-20261015/setfactory-size.json']=sha(ctorpath)
    mo,ms=struct.unpack_from('<II',meta,48);co=mo+16857*36;ci=struct.unpack_from('<IiiIiiI4H',meta,co);io=mo+16807*36;ir=struct.unpack_from('<IiiIiiI4H',meta,io)
    need(string(ci[0])=='.ctor' and ci[1]==1808 and ci[-1]==1 and not ci[7]&16,'Constructor metadata declaration');need(string(ir[0])=='.cctor' and ir[1]==1789 and ir[7]&16 and typ[9]<=16807<typ[9]+typ[16],'Initializer metadata declaration')
    doc['metadata_method_declarations']={'constructor':{'index':16857,'record_file_offset':hex(co),'record_bytes':meta[co:co+36].hex()},'initializer':{'index':16807,'record_file_offset':hex(io),'record_bytes':meta[io:io+36].hex()}}
    (out/'npc-static-field-roots.json').write_text(json.dumps(doc,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    (out/'REPORT.ru.md').write_text('# Условная атрибуция NPCID.Sets.Factory\n\nSlot `0x310de38` содержит `0x20009943`: kind1, type19617, CLASS18, typedef1789. Исходная запись метаданных и её вложенный владелец подтверждают `Terraria.ID.NPCID+Sets`; поле31552 называется Factory, объявлено static SetFactory и имеет нативное смещение0.\n\nВызов metadata-init находится `0x1aaeb6c`. Фрагмент `0x1aaf3a0..0x1aaf3c8` получает тот же class root через GOT `0x3087cf0`, сохраняет receiver в X19, вызывает SetFactory-конструктор с size697 и записывает X19 через `[class+0xb8]` по offset0. При явно перечисленных условиях это присваивание `NPCID.Sets.Factory`.\n\nМодель bootstrap/usage/ClassFromType/static-storage getter взята из неизменённого доказательства `static-field-roots-20261015` по SHA256; все13 её фрагментов повторно связаны с исходным ELF. Дополнительные байты и метаданные проверены отдельно. Runtime этого присваивания не наблюдался; нормальный возврат конструктора, AAPCS64 и сохранность корня остаются предпосылками.\n',encoding='utf8')
    print(json.dumps({'output':str(out),'NPC_root':hex(slot),'type_index':index,'field_index':31552,'size':697,'new_instruction_bytes':sum(len(bytes.fromhex(x['bytes'])) for x in fragments),'dual_checked':dual,'negative_controls':len(controls)}));raw.close();f.close()

if __name__=='__main__':main()
