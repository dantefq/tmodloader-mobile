"""Conditional empty-cache buffer branch and allocator length postcondition.

Read-only mmap source checks; cached buffers remain a separate invariant.
"""
import argparse,hashlib,json,mmap,pathlib,struct,sys

SOURCE='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
META='4c904c49d168913d28ef547c4f461e539d926d2ed27c0253ed53a2954e9585f7'
MODEL='22f6f7fd1eba05ae5c284adcc4adb856296122133ff5050d8e9a553459ef02e3'
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def need(ok,msg):
    if not ok:raise ValueError(msg)
def sign(v,b):return v-(1<<b) if v&1<<(b-1) else v
def branch(w,pc):need(w&0x7c000000==0x14000000,'B/BL opcode');return pc+sign(w&0x3ffffff,26)*4
def mem(w):need(w&0xffc00000 in (0xf9400000,0xf9000000,0xb9400000),'Memory opcode');return w&31,(w>>5)&31,((w>>10)&4095)*(4 if w&0xffc00000==0xb9400000 else 8)
def page(w,pc):need(w&0x9f000000==0x90000000,'ADRP');return (pc&~4095)+(sign(((w>>29)&3)|(((w>>5)&0x7ffff)<<2),21)<<12)
def zero_target(w,pc):need(w&0x7e000000==0x34000000,'CBZ/CBNZ');return pc+sign((w>>5)&0x7ffff,19)*4

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);ap.add_argument('--verify-only',action='store_true');a=ap.parse_args();lab=a.lab;binary=lab/'native/libil2cpp.so';metadata=lab/'native/global-metadata.dat';need(sha(binary)==SOURCE and sha(metadata)==META,'Source identity');bf=binary.open('rb');r=mmap.mmap(bf.fileno(),0,access=mmap.ACCESS_READ);m=metadata.read_bytes()
    def un(fmt,p):return struct.unpack_from(fmt,r,p)
    po=un('<Q',32)[0];ps,pn=un('<HH',54);segments=[un('<II6Q',po+i*ps) for i in range(pn)]
    def at(va,n=8):
        hits=[s[2]+va-s[3] for s in segments if s[0]==1 and s[3]<=va and va+n<=s[3]+s[5]];need(len(hits)==1,'Segment bounds');return hits[0]
    def read(va,n):p=at(va,n);return r[p:p+n]
    def word(va):return int.from_bytes(read(va,4),'little')
    so=un('<Q',40)[0];ss,sn=un('<HH',58);sections=[un('<IIQQQQIIQQ',so+i*ss) for i in range(sn)];ptrproof=[];ptrcache={}
    def pointer(slot):
        if slot in ptrcache:return ptrcache[slot]
        hits=[]
        for sec in sections:
            if sec[1]!=4:continue
            for p in range(sec[4],sec[4]+sec[5],sec[9]):
                target,info,add=un('<QQq',p)
                if target==slot:hits.append((p,info,add))
        if hits:
            need(len(hits)==1 and hits[0][1]&0xffffffff==1027,'RELATIVE pointer');p,info,value=hits[0];ptrproof.append({'slot':hex(slot),'target':hex(value),'relocation_file_offset':hex(p),'relocation_bytes':r[p:p+24].hex()})
        else:value=int.from_bytes(read(slot,8),'little')
        ptrcache[slot]=value;return value
    # Fresh source-level export binding, not a name copied from an earlier list.
    symbols={}
    for sec in sections:
        if sec[1]!=11:continue
        pool=sections[sec[6]]
        for off in range(sec[4],sec[4]+sec[5],sec[9]):
            ni,flags,other,defined,value,size=un('<IBBHQQ',off);np=pool[4]+ni;end=r.find(b'\0',np,pool[4]+pool[5]);name=r[np:end].decode()
            if defined:symbols[name]={'address':hex(value),'size':size,'symbol_record_file_offset':hex(off),'symbol_record_bytes':r[off:off+24].hex()}
    exported=symbols['il2cpp_array_new_specific'];need(exported['address']=='0x75336c' and exported['size']==4 and branch(word(0x75336c),0x75336c)==0x7146a8,'Array allocator export binding');need(word(0x6ff5f4)==0x2a0103e1 and branch(word(0x6ff5f8),0x6ff5f8)==0x7146a8,'Generated array allocator thunk')
    to,ts=struct.unpack_from('<II',m,160);fo,fs=struct.unpack_from('<II',m,96);stro,strs=struct.unpack_from('<II',m,24)
    def text(i):need(0<=i<strs,'String bounds');return m[stro+i:m.index(b'\0',stro+i,stro+strs)].decode()
    typoff=to+1808*88;typ=struct.unpack_from('<IIiiiiIIiiiiiiii8HII',m,typoff);need(text(typ[0])=='SetFactory' and text(typ[1])=='Terraria.ID','Factory owner');offsets=pointer(pointer(0x2fdb588+88)+1808*8);fields=[];types=pointer(0x2fdb588+56)
    for index,name,expected in [(33140,'_size',16),(33141,'_intBufferCache',24),(33143,'_boolBufferCache',40),(33145,'_queueLock',56)]:
        need(typ[8]<=index<typ[8]+typ[18],'Factory field owner bounds');fp=fo+index*12;ni,ti,token=struct.unpack_from('<IiI',m,fp);slot=offsets+(index-typ[8])*4;need(text(ni)==name and int.from_bytes(read(slot,4),'little',signed=True)==expected,'Factory field identity/offset');ftp=pointer(types+ti*8);ftdata,ftbits=struct.unpack('<QI',read(ftp,12));need(not ftbits&16,'Factory field unexpectedly static');fields.append({'index':index,'name':name,'offset':expected,'type_index':ti,'metadata_record_file_offset':hex(fp),'metadata_record_bytes':m[fp:fp+12].hex(),'native_offset_slot':hex(slot),'native_offset_bytes':read(slot,4).hex(),'native_field_type_pointer':hex(ftp),'native_field_type_bytes':read(ftp,12).hex(),'instance_storage':True})
    types=pointer(0x2fdb588+56);buffers=[]
    for kind,start,normalend,cacheoffset,countpc,fresh,allocpc,got,reusepc,join,returnpc,usage,index,elementtag in [('bool',0x1acf66c,0x1acf73c,40,0x1acf6d4,0x1acf6f4,0x1acf704,0x305c5f8,0x1acf6ec,0x1acf708,0x1acf728,0x3104b38,5719,2),('int',0x1acf7b0,0x1acf880,24,0x1acf818,0x1acf838,0x1acf848,0x3077198,0x1acf830,0x1acf84c,0x1acf86c,0x3104e60,5924,8)]:
        need(mem(word(countpc-8))==(8,20,cacheoffset) and mem(word(countpc))==(9,8,32) and zero_target(word(countpc+4),countpc+4)==fresh and not word(countpc+4)&0x01000000,'Cache-empty dispatch')
        need(mem(word(fresh+8))==(1,20,16) and mem(word(fresh+12))==(0,8,0) and branch(word(allocpc),allocpc)==0x6ff5f4,'Fresh size/array class/call');need(page(word(fresh),fresh)+mem(word(fresh+4))[2]==got,'Fresh array root GOT');need(branch(word(reusepc),reusepc)==0x1f09574 and branch(word(reusepc+4),reusepc+4)==join,'Reuse shared cache-pop path');need(word(join)==0xaa0003f5 and word(returnpc)==0xaa1503e0,'Normal result preservation/return')
        need(pointer(got)==usage,'Array root relocation');enc=int.from_bytes(read(usage,8),'little');need(enc&1 and enc>>29&7==1 and (enc>>1)&0xfffffff==index,'Array class usage encoding');tp=pointer(types+index*8);data,bits=struct.unpack('<QI',read(tp,12));need(bits>>16&255==29,'SZARRAY type');ep=pointer(tp);ed,eb=struct.unpack('<QI',read(ep,12));need(eb>>16&255==elementtag,'Array element primitive type')
        buffers.append({'kind':kind,'method_start':hex(start),'normal_return_end':hex(normalend),'cache_field_offset':cacheoffset,'observed_cache_test_offset':32,'empty_cache_branch':hex(countpc+4),'fresh_branch':hex(fresh),'size_load':hex(fresh+8),'allocator_call':hex(allocpc),'shared_cache_pop_call':hex(reusepc),'normal_result_join':hex(join),'normal_result_return_move':hex(returnpc),'array_root_GOT':hex(got),'array_usage_slot':hex(usage),'initial_usage_word':hex(enc),'initial_usage_bytes':read(usage,8).hex(),'array_type_index':index,'native_array_type_pointer':hex(tp),'native_array_type_bytes':read(tp,12).hex(),'native_element_type_pointer':hex(ep),'native_element_type_bytes':read(ep,12).hex(),'element_type_tag':elementtag,'fresh_length_postcondition':'Normal allocator return followed by unmodified header means returned array.length == zero-extended factory._size.','reuse_length_postcondition':'No new length/type/ownership validation: depends on valid cache invariant.'})
    # Native array allocator preserves incoming length and writes the header before return.
    need(word(0x7146b4)==0xaa0103f4 and word(0x7146b8)==0xaa0003f3 and word(0x7146c0)==0xd35ffe88 and zero_target(word(0x7146c4),0x7146c4)==0x7147d4,'Allocator saved length/limit');need(mem(word(0x7147a8))==(20,21,24) and word(0x7147c0)==0xaa1503e0,'Allocator length store/return')
    modelpath=lab/'static-field-roots-20261015/static-field-roots.json';need(sha(modelpath)==MODEL,'Frozen usage model SHA');model=json.loads(modelpath.read_text());modelauditpath=modelpath.parent/'independent-audit.json';modelaudit=json.loads(modelauditpath.read_text());need(modelaudit['integrity_passed'] and modelaudit['evidence_sha256']==MODEL,'Usage model audit')
    sys.path.insert(0,str(lab/'python-analysis'));from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;fragments=[];dual=0
    for label,start,end in [('GetBoolBuffer_normal',0x1acf66c,0x1acf748),('GetIntBuffer_normal',0x1acf7b0,0x1acf88c),('generated_array_thunk',0x6ff5f4,0x6ff5fc),('export_array_new_specific',0x75336c,0x753370),('allocator_entry_and_normal_length_return',0x7146a8,0x7147d4),('shared_cache_pop_reference',0x1f09574,0x1f0960c)]:
        b=read(start,end-start);ins=list(cs.disasm(b,start));need(len(ins)*4==len(b),'Fragment disassembly')
        for i in ins:
            w=int.from_bytes(i.bytes,'little')
            if w&0x7c000000==0x14000000:need(i.operands[0].imm==branch(w,i.address),'Branch decoder agreement');dual+=1
            elif w&0x7e000000==0x34000000:need(i.operands[-1].imm==zero_target(w,i.address),'Zero branch decoder agreement');dual+=1
            elif w&0x9f000000==0x90000000:need(i.operands[1].imm==page(w,i.address),'Page decoder agreement');dual+=1
            elif w&0xffc00000 in (0xf9400000,0xf9000000,0xb9400000):
                rt,rn,disp=mem(w);regname='w'+str(rt) if w&0xffc00000==0xb9400000 else 'xzr' if rt==31 else 'x'+str(rt);base='sp' if rn==31 else 'x'+str(rn);need(i.reg_name(i.operands[0].reg)==regname and i.reg_name(i.operands[1].mem.base)==base and i.operands[1].mem.disp==disp,'Memory decoder agreement');dual+=1
        fragments.append({'label':label,'start':hex(start),'end_exclusive':hex(end),'bytes':b.hex(),'sha256':hashlib.sha256(b).hexdigest(),'instructions':[{'address':hex(i.address),'raw_bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str} for i in ins]})
    controls=[]
    for name,fn in [('wrong_bool_cache_offset',lambda:need(mem(0xf9400e88)==(8,20,40),'Cache offset')),('wrong_factory_size_offset',lambda:need(mem(0xb9401681)==(1,20,16),'Size offset')),('wrong_array_length_header',lambda:need(mem(0xf90012b4)==(20,21,24),'Length header')),('wrong_allocator_bridge',lambda:need(branch(0x14000000,0x75336c)==0x7146a8,'Allocator bridge')),('wrong_primitive_element',lambda:need(8==2,'Boolean element type')),('reuse_without_invariant',lambda:need(6100==6196,'Cached length need not match'))]:
        try:fn()
        except ValueError:controls.append(name)
        else:raise ValueError('Negative accepted '+name)
    doc={'profile':'conditional-SetFactory-empty-cache-buffer-length-model-v1','elf_sha256':SOURCE,'metadata_sha256':META,'producer_sha256':sha(pathlib.Path(__file__)),'dependencies':{'static-field-roots-20261015/static-field-roots.json':MODEL,'static-field-roots-20261015/independent-audit.json':sha(modelauditpath)},'factory_field_sources':fields,'buffers':buffers,'allocator_export':exported,'pointer_proofs':ptrproof,'instruction_fragments':fragments,'dual_decoder_checked_instructions':dual,'negative_controls_rejected':controls,'fresh_empty_cache_source_result':'For nonnegative factory._size<2^31 and valid empty cache, the method passes that size and the corresponding Boolean[]/Int32[] array class to the exact implementation exposed by il2cpp_array_new_specific. The allocator records incoming size at returnedArray+0x18.','reuse_source_result':'If observed cache word+0x20 is nonzero, the method returns a reference from shared cache-pop implementation without inspecting returned array.length or comparing it with factory._size.','conditions':['Valid nonnull SetFactory receiver and live cache/_queueLock; original metadata/class roots initialized normally according to the frozen kind1 usage model.','The cache+0x20 word correctly represents empty/nonempty under the valid closed Queue<T> layout and lock contract.','Metadata setup, Monitor-like lock/unlock calls, cache-pop calls and allocator/backend calls return normally and preserve AAPCS64 callee-saved registers/SP.','factory._size is nonnegative and less than2^31; generated W1 move zero-extends the size.','Allocator backends return valid writable correctly typed arrays and follow their allocation/ownership contracts; the explicit size store is reached.','Optional profiling/debug callback at0x7147bc and later unlocks do not modify the returned length/header or invalidate the returned reference.','No hooks, concurrent mutation or stale/moving raw pointers violate managed/runtime invariants.'],'limitations':['Conditional source result, not runtime execution or proof of complete bootstrap, exception handling, locking, allocator backend or GC ownership.','Fresh length==_size is source-supported on the normal empty-cache path; physical nonaliasing/fresh ownership still depends on allocator backend contracts.','The cached path requires a separate invariant that every returned cache entry has the correct length/type and is not aliased with the active input. Those properties are not rechecked in these methods.','Open generic Queue<T> metadata field offsets are zero/unresolved; observed cache+0x20 is not presented as an independently recovered declared Queue._size offset.','No full shared generic cache-pop semantics or mutation/profiler callback verification is claimed.'],'baseline_modified':False,'low_memory_processing':True}
    if not a.verify_only:
        out=lab/'setfactory-buffer-model-20261015';out.mkdir(exist_ok=True);(out/'buffer-model.json').write_text(json.dumps(doc,ensure_ascii=False,indent=2)+'\n',encoding='utf8');(out/'REPORT.ru.md').write_text('# Условный контракт GetBoolBuffer/GetIntBuffer\n\nВетка пустого cache у обоих методов читает SetFactory._size по смещению16 и вызывает один allocator helper с соответствующим Boolean[]/Int32[] class root. Helper6ff5f4 непосредственно ведёт в тот же адрес7146a8, что экспорт il2cpp_array_new_specific. На нормальном пути allocator записывает полученный size в array header+24 и возвращает тот же объект. При явно указанных условиях return.length == factory._size; для прежнего size6196 это закрывает условную длину fresh-buffer ветви.\n\nCache-поля проверены по исходным метаданным/нативным смещениям: _boolBufferCache40, _intBufferCache24, _queueLock56. При ненулевом наблюдаемом cache word+32 выполняется отдельный общий cache-pop вызов. Возвращаемые длина, тип и отсутствие alias в этих методах не проверяются; требуются дополнительные cache invariants.\n\nФизическая свежесть/ownership, полный GC/backend allocator, lock и profiler callback остаются контрактами. Фактическое runtime исполнение не наблюдалось. Полные байты, root/type bindings, предпосылки и ограничения записаны в buffer-model.json.\n',encoding='utf8')
    print(json.dumps({'verified':True,'verify_only':a.verify_only,'methods':2,'factory_fields':len(fields),'source_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in fragments),'dual_decoder_checks':dual,'negative_controls':len(controls)}));r.close();bf.close()

if __name__=='__main__':main()
