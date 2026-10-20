"""Source-bound conditional ItemID.Sets.Factory attribution; no runtime execution."""
import argparse,hashlib,json,pathlib,struct,sys
from terraria_native_map import ELF
from terraria_metadata_catalog import TABLES

SOURCE='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
META='4c904c49d168913d28ef547c4f461e539d926d2ed27c0253ed53a2954e9585f7'
def sha(b):return hashlib.sha256(b).hexdigest()
def need(ok,msg):
    if not ok:raise ValueError(msg)
def signed(v,bits):return v-(1<<bits) if v&(1<<(bits-1)) else v
def branch(w,pc):
    need(w&0x7c000000==0x14000000,'Expected direct branch');return pc+signed(w&0x3ffffff,26)*4
def adrp(w,pc):
    need(w&0x9f000000==0x90000000,'Expected ADRP');return (pc&~4095)+(signed(((w>>29)&3)|(((w>>5)&0x7ffff)<<2),21)<<12)
def memory(w):
    need(w&0xffc00000 in (0xf9400000,0xf9000000),'Expected X unsigned load/store');return w&31,(w>>5)&31,((w>>10)&4095)*8
def usage(w):
    need(w<1<<32 and w&1 and (w>>29)&7==1,'Expected encoded type-class usage');return (w>>1)&0xfffffff

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',required=True,type=pathlib.Path);a=ap.parse_args();lab=a.lab
    raw=(lab/'native/libil2cpp.so').read_bytes();meta=(lab/'native/global-metadata.dat').read_bytes();need(sha(raw)==SOURCE and sha(meta)==META,'Original identity mismatch');e=ELF(raw)
    sys.path.insert(0,str(lab/'python-analysis'));from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    def read(va,n):return raw[e.file_offset(va):e.file_offset(va)+n]
    def word(va):return int.from_bytes(read(va,4),'little')
    def expect(va,w):need(word(va)==w,'Opcode differs '+hex(va))
    # Second ELF view parses section relocation records without using e.pointer.
    shoff=struct.unpack_from('<Q',raw,40)[0];shsize,shcount=struct.unpack_from('<HH',raw,58)
    sections=[struct.unpack_from('<IIQQQQIIQQ',raw,shoff+i*shsize) for i in range(shcount)]
    rel={}
    for sec in sections:
        if sec[1]==4:
            for off in range(sec[4],sec[4]+sec[5],sec[9]):
                slot,info,add=struct.unpack_from('<QQq',raw,off)
                if info&0xffffffff==1027:rel[slot]={'file_offset':hex(off),'bytes':raw[off:off+24].hex(),'addend':add}
    pointers=[]
    def pointer(slot):
        need(slot in rel,'Expected explicit RELATIVE relocation '+hex(slot));value=rel[slot]['addend'];need(e.pointer(slot)==value,'ELF decoders disagree');pointers.append({'slot':hex(slot),'value':hex(value),'relocation':rel[slot]});return value
    # Exact static registration thunk -> metadata registration global.
    need(adrp(word(0x5f5074),0x5f5074)==0x306f000 and memory(word(0x5f5078))==(1,1,0x9c0),'Registration load shape')
    registration=pointer(0x306f9c0);need(registration==0x2fdb588,'Registration address')
    for pc,target in [(0x5f508c,0x6ff5a8),(0x6ff5a8,0x6eee44),(0x6eee58,0x74b928)]:need(branch(word(pc),pc)==target,'Registration branch')
    need(adrp(word(0x74b92c),0x74b92c)+memory(word(0x74b934))[2]==0x3214f08 and memory(word(0x74b934))[:2]==(1,9),'Registration global store')
    types_table=pointer(registration+0x38);types_count=int.from_bytes(read(registration+0x30,8),'little');need(types_table==0x2ff5128 and types_count==23420,'Types registration')
    # Actual usage helper decoding, including resolved switch case1.
    for pc,target in [(0x6ff5b0,0x6f0b58),(0x6f0b5c,0x74bb0c),(0x74bb78,0x74bcb0)]:need(branch(word(pc),pc)==target,'Usage resolver branch')
    expect(0x74bb30,0xd35d7c08);expect(0x74bb54,0x53017014)
    need(((word(0x74bb30)>>16)&63, (word(0x74bb30)>>10)&63)==(29,31),'Kind extraction')
    need(((word(0x74bb54)>>16)&31, (word(0x74bb54)>>10)&31)==(1,28),'Index extraction')
    casebyte=read(0x2a32732,1)[0];need(0x74bb5c+4*casebyte==0x74bb70,'Usage type case target')
    expect(0x74bb74,0x2a1403e0);expect(0x74bc80,0xf9000260)
    # Resolver loads the original registered types table and converts Class type.
    need(adrp(word(0x74bd7c),0x74bd7c)+memory(word(0x74bd80))[2]==0x3214f08,'Resolver registration load')
    need(memory(word(0x74bd84))==(8,8,0x38),'Resolver table offset');expect(0x74bd88,0xf8777900)
    need(branch(word(0x74bd90),0x74bd90)==0x6ea7ec,'ClassFromType call')
    primitive_byte=read(0x2a087e0+17,1)[0];class_byte=read(0x2a087d0+3,1)[0]
    need(0x6ea90c+4*primitive_byte==0x6eaa10 and word(0x6eaa10)==0xd65f03c0,'CLASS primitive path returns zero')
    need(0x6ea810+4*class_byte==0x6ea840,'CLASS dispatch target')
    for pc,target in [(0x6ea84c,0x6d1fa8),(0x6d1fa8,0x6f0938),(0x6f093c,0x74ca34),(0x74ca64,0x74c5f8)]:need(branch(word(pc),pc)==target,'Class definition resolver chain')
    expect(0x74ca44,0xf940000a);expect(0x74ca48,0xb980a108);expect(0x74ca50,0xcb080148);expect(0x74ca58,0xd343fd08);expect(0x74ca60,0x1b097d00)
    need((11*0xba2e8ba3)&0xffffffff==1,'Type record division inverse')
    # Original initialization fixes each CLASS.data index to a metadata record pointer.
    expect(0x74ba64,0x52800b0a);expect(0x74ba8c,0xb980018d);expect(0x74baa0,0xb980a1ce);expect(0x74baa8,0x9b0a39ad);expect(0x74bae0,0xf900018d)
    fixmask=0x13467ffe;need(fixmask&(1<<18),'CLASS excluded from fixup mask')
    expect(0x74ba58,0x528fffc9);expect(0x74ba60,0x72a268c9)
    # Exported static-storage getter is native evidence for Il2CppClass+0xb8.
    export=next(s for s in e.symbols if s['name']=='il2cpp_class_get_static_field_data' and s['defined'])
    need(export['address']=='0x753450' and export['size']==8,'Static getter export')
    need(memory(word(0x753450))==(0,0,184) and word(0x753454)==0xd65f03c0,'Static getter body')
    class_exports=[s for s in e.symbols if s['name'] in ('il2cpp_class_from_type','il2cpp_class_from_il2cpp_type') and s['defined']]
    need(len(class_exports)==2,'ClassFromType exports')
    for item in class_exports:
        pc=int(item['address'],16);expect(pc,0x52800021);need(branch(word(pc+4),pc+4)==0x6ea7ec,'Export ClassFromType bridge')
    # Source metadata records and native type records, no name inference from caller.
    spans={name:struct.unpack_from('<II',meta,8+i*8) for i,(name,_,_) in enumerate(TABLES)}
    def record(name,index):
        _,fmt,keys=next(r for r in TABLES if r[0]==name);off,size=spans[name];width=struct.calcsize(fmt);p=off+index*width;need(index>=0 and p+width<=off+size,'Metadata bounds');return p,dict(zip(keys.split(),struct.unpack_from(fmt,meta,p)))
    def string(index):
        off,size=spans['strings'];need(0<=index<size,'String bounds');return meta[off+index:meta.index(b'\0',off+index,off+size)].decode()
    roots=[]
    def root(slot,expected_index,expected_def,name):
        encoded=int.from_bytes(read(slot,8),'little');index=usage(encoded);need(index==expected_index,'Wrong usage index');typeptr=pointer(types_table+index*8);data,bits=struct.unpack('<QI',read(typeptr,12));need((bits>>16)&255==18 and data==expected_def,'CLASS type definition mismatch');mp,tr=record('types',data);need(tr['byval_type_index']==index,'Type byval crosscheck')
        row={'slot':hex(slot),'initial_word':hex(encoded),'initial_bytes':read(slot,8).hex(),'usage_kind':1,'type_index':index,'native_type_pointer':hex(typeptr),'native_type_bytes':read(typeptr,12).hex(),'typedef_index':data,'metadata_type_record_file_offset':hex(mp),'metadata_type_record_bytes':meta[mp:mp+88].hex(),'declared_name':name,'type_record_name':string(tr['name_index']),'namespace':string(tr['namespace_index']),'conditional_fixup_result':'loaded metadata base + types table offset + '+str(data)+' * 88'};roots.append(row);return tr
    sets=root(0x310d958,19270,1764,'Terraria.ID.ItemID+Sets');factory=root(0x310ad70,14457,1808,'Terraria.ID.SetFactory')
    need(string(sets['name_index'])=='Sets' and string(factory['name_index'])=='SetFactory' and string(factory['namespace_index'])=='Terraria.ID','Names mismatch')
    parentptr=pointer(types_table+sets['declaring_type_index']*8);parentdef,parentbits=struct.unpack('<QI',read(parentptr,12));pp,pr=record('types',parentdef);need((parentbits>>16)&255==18 and string(pr['name_index'])=='ItemID' and string(pr['namespace_index'])=='Terraria.ID','Nested owner mismatch')
    fp,fr=record('fields',sets['field_start']);need(string(fr['name_index'])=='Factory','First declared field not Factory')
    fieldtype=pointer(types_table+fr['type_index']*8);fd,fbits=struct.unpack('<QI',read(fieldtype,12));need(fd==1808 and (fbits>>16)&255==18 and fbits&16,'Factory not declared static SetFactory')
    offsets=pointer(registration+0x58);field_offsets=pointer(offsets+1764*8);need(int.from_bytes(read(field_offsets,4),'little',signed=True)==0,'Factory offset differs')
    # Receiver constructor argument and store into exact resolved class storage+0.
    need(adrp(word(0x1a894f4),0x1a894f4)==0x3053000 and memory(word(0x1a894f8))==(0,0,192) and branch(word(0x1a894fc),0x1a894fc)==0x6ff5ac,'Class root init call')
    need(pointer(0x30530c0)==0x310d958,'Class root GOT')
    need(adrp(word(0x1a899d0),0x1a899d0)==0x3053000 and memory(word(0x1a899d8))==(23,23,192),'Store root load')
    expect(0x1a899e0,0x52830681);expect(0x1a899e8,0xaa0003f3);need(branch(word(0x1a899ec),0x1a899ec)==0x1ac5848,'Ctor call')
    need(memory(word(0x1a899f0))==(8,23,0) and memory(word(0x1a899f4))==(8,8,184) and memory(word(0x1a899f8))==(19,8,0),'Factory store shape')
    fragments=[];dual_checked=0
    for label,start,end in [('register_thunk',0x5f5074,0x5f5090),('register_wrapper',0x6eee44,0x6eee5c),('register_globals',0x74b928,0x74b93c),('usage_wrapper',0x6ff5ac,0x6ff5c0),('usage_decode',0x74bb18,0x74bb84),('usage_result_store',0x74bc78,0x74bc94),('registered_type_resolver',0x74bd7c,0x74bdb0),('class_dispatch',0x6ea7f4,0x6ea850),('class_fixup_loop',0x74ba58,0x74baf8),('class_to_typedef_index',0x74ca34,0x74ca68),('static_storage_getter',0x753450,0x753458),('class_root_init',0x1a894f4,0x1a89500),('factory_store',0x1a899d0,0x1a899fc)]:
        b=read(start,end-start);ins=list(cs.disasm(b,start));need(len(ins)*4==len(b),'Capstone fragment coverage')
        for i in ins:
            w=int.from_bytes(i.bytes,'little')
            if w&0x7c000000==0x14000000:
                need(i.mnemonic in ('b','bl') and i.operands[0].imm==branch(w,i.address),'Branch decoder disagreement');dual_checked+=1
            elif w&0x9f000000==0x90000000:
                need(i.mnemonic=='adrp' and i.operands[1].imm==adrp(w,i.address),'ADRP decoder disagreement');dual_checked+=1
            elif w&0xffc00000 in (0xf9400000,0xf9000000):
                rt,rn,offset=memory(w);reg=lambda n:'fp' if n==29 else 'lr' if n==30 else 'x'+str(n)
                need(i.mnemonic==('ldr' if w&0x00400000 else 'str') and i.reg_name(i.operands[0].reg)==reg(rt) and i.reg_name(i.operands[1].mem.base)==reg(rn) and i.operands[1].mem.disp==offset,'Memory decoder disagreement');dual_checked+=1
        fragments.append({'label':label,'start':hex(start),'end_exclusive':hex(end),'sha256':sha(b),'bytes':b.hex(),'instructions':[{'address':hex(i.address),'instruction':i.mnemonic+' '+i.op_str,'raw_bytes':i.bytes.hex()} for i in ins]})
    controls=[]
    for name,fn in [('even_usage',lambda:usage(0x2000968c)),('wrong_usage_kind',lambda:usage(0x4000968d)),('wrong_usage_type_index',lambda:need(usage(0x2000968f)==19270,'Index mismatch')),('wrong_switch_case',lambda:need(0x74bb5c+4*6==0x74bb70,'Case mismatch')),('wrong_static_getter_offset',lambda:need(memory(0xf9406000)==(0,0,184),'Getter mismatch'))]:
        try:fn()
        except ValueError:controls.append(name)
        else:raise ValueError('Negative control accepted')
    out=lab/'static-field-roots-20261015';out.mkdir(exist_ok=True)
    doc={'profile':'conditional-itemsets-factory-static-assignment-v1','elf_sha256':SOURCE,'metadata_sha256':META,'producer_sha256':sha(pathlib.Path(__file__).read_bytes()),'roots':roots,'nested_parent':{'native_type_pointer':hex(parentptr),'metadata_definition_index':parentdef,'metadata_record_file_offset':hex(pp),'name':'Terraria.ID.ItemID'},'declared_static_field':{'index':sets['field_start'],'name':'Factory','metadata_record_file_offset':hex(fp),'metadata_record_bytes':meta[fp:fp+12].hex(),'type_index':fr['type_index'],'native_type_bytes':read(fieldtype,12).hex(),'native_field_offset_slot':hex(field_offsets),'native_field_offset_bytes':read(field_offsets,4).hex(),'native_static_offset':0},'relocations_independently_reparsed':pointers,'instruction_fragments':fragments,'static_storage_getter_export':export,'source_bound_inference':'Under the initialization and ABI premises, the receiver passed to SetFactory::.ctor(size=6196) is assigned to the declared static field Terraria.ID.ItemID+Sets.Factory at0x1a899f8.','conditions':['The original code registration thunk executes with normal ELF RELATIVE relocation semantics.','The original metadata file is the one loaded by bootstrap; CLASS type-data fixup completes normally before class usage resolution.','Metadata usage kind1 resolution follows the decoded case, returns the class for registered type19270, and publishes that result in slot0x310d958.','The shown initializer store fragment executes in order; constructor returns normally and preserves X19/X23 under AAPCS64.','No helper/concurrent actor replaces the class-root slot or its static storage pointer between the proven resolution and store.'],'limitations':['Conditional source-derived field association; not proof of actual runtime execution, global reachability or complete initialization equivalence.','No full analysis of runtime class cache/allocation, synchronization, bootstrap metadata loading or unusual interposition.','Prior method-address binding reused for constructor identity; source size evidence remains in separate initializer-refinement-20261015.','Original C# code, comments and complete set array contents are not recovered.'],'class_from_type_exports':class_exports,'dual_decoder_checked_instructions':dual_checked,'negative_controls_rejected':controls,'baseline_modified':False}
    (out/'static-field-roots.json').write_text(json.dumps(doc,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    (out/'REPORT.ru.md').write_text('# Условная атрибуция ItemID.Sets.Factory\n\nИсходный slot `0x310d958` содержит `0x2000968d`: actual native decoder выделяет kind1 и индекс19270. Нативная таблица типов даёт CLASS18, typedef1764; исходные метаданные называют его вложенным `Terraria.ID.ItemID+Sets`. Slot `0x310ad70` аналогично соответствует `Terraria.ID.SetFactory`. Связь установлена по байтам и метаданным, а не по имени вызывающего метода.\n\nПроверен оригинальный bootstrap: registration thunk передаёт relocation-backed указатель `0x2fdb588`; цикл fixup переводит CLASS.data из индекса в указатель на 88-байтовую запись типов. Декодер usage разрешает индекс через ту же таблицу регистрации.\n\nЭкспорт `il2cpp_class_get_static_field_data` напрямую возвращает `[klass+0xb8]`. Поле Factory объявлено static, имеет тип SetFactory и проверенное нативное смещение0. Фрагмент `0x1a899d0..0x1a899f8` вызывает конструктор с size6196 и записывает сохранённый receiver в static storage декодированного ItemID.Sets по смещению0.\n\nПоэтому при перечисленных в JSON условиях нормальной инициализации, возврата конструктора и сохранности глобального корня это **присваивание ItemID.Sets.Factory**, а не только безымянная запись по указателю. Исполнение данного участка в runtime не наблюдалось. Полный bootstrap, все пути и содержимое наборов не доказаны.\n\n`static-field-roots.json` содержит исходные байты, адреса, метаданные, RELATIVE relocations, два вида ARM64-декодирования для ключевых операций и пять отклонённых отрицательных примеров.\n',encoding='utf8')
    print(json.dumps({'output':str(out),'roots':len(roots),'source_bytes':sum(len(bytes.fromhex(x['bytes'])) for x in fragments),'relative_pointer_checks':len(pointers),'negative_controls':len(controls)}))

if __name__=='__main__':main()
