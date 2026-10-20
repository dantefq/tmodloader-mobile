"""Bounded SetFactory constructor argument and instance _size evidence.

Does not associate initializer stores with any declared static field.
"""
import argparse, hashlib, json, pathlib, struct, sys
from terraria_flow_islands import Elf
from terraria_metadata_catalog import TABLES

ELF_SHA='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
META_SHA='4c904c49d168913d28ef547c4f461e539d926d2ed27c0253ed53a2954e9585f7'
CTOR=0x1ac5848

def digest(b):return hashlib.sha256(b).hexdigest()
def need(test,message):
    if not test:raise ValueError(message)
def raw_dest(w):
    """Independent whitelist of writes in constructor save-to-store interval."""
    if w&0x7fe0ffe0==0x2a0003e0:return w&31 # ORR register MOV alias
    if w&0x9f000000==0x90000000:return w&31 # ADRP
    if w&0xffc00000 in (0xf9400000,0x39400000):return w&31
    if w&0xffc00000 in (0xf9000000,0x39000000):return None
    if w&0x7f800000==0x52800000:return w&31
    if w&0xfc000000==0x94000000:return None # BL; ABI preservation is explicit premise
    if w&0x7e000000 in (0x34000000,0x36000000):return None
    raise ValueError('Unrecognized raw write decoder instruction '+hex(w))

def validate_call(raw,start,size):
    words=struct.unpack('<4I',raw)
    need(words[0]&0xffe0001f==0x52800001,'W1 MOVZ expected')
    need((words[0]>>5)&65535==size,'Constructor size differs')
    need(words[1]==0xaa1f03e2 and words[2]==0xaa0003f3,'Call suffix shape differs')
    w=words[3];imm=w&0x3ffffff;imm=imm-(1<<26) if imm&(1<<25) else imm
    need(w&0xfc000000==0x94000000 and start+12+imm*4==CTOR,'Wrong BL target')

def validate_body(raw,start):
    words=struct.unpack('<'+'I'*(len(raw)//4),raw)
    need(start==0x1ac5864 and words[:2]==(0x2a0103f3,0xaa0003f4),'Wrong parameter saves')
    need(words[-1]==0xb9001293,'Wrong _size STR word')
    for w in words[2:-1]:need(raw_dest(w) not in (19,20),'Saved parameter register overwritten')
    need(words[-2]==0x340000f3,'Expected nonzero guard')

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',required=True,type=pathlib.Path);a=ap.parse_args();lab=a.lab
    sys.path.insert(0,str(lab/'python-analysis'));from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
    elf=Elf(lab/'native/libil2cpp.so');metadata=(lab/'native/global-metadata.dat').read_bytes()
    need(digest(elf.raw)==ELF_SHA and digest(metadata)==META_SHA,'Original identity differs')
    spans={name:struct.unpack_from('<II',metadata,8+i*8) for i,(name,_,_) in enumerate(TABLES)}
    def record(table,index):
        name,fmt,keys=next(t for t in TABLES if t[0]==table);off,length=spans[name];width=struct.calcsize(fmt);p=off+width*index
        need(index>=0 and p+width<=off+length,'Metadata bounds');return p,dict(zip(keys.split(),struct.unpack_from(fmt,metadata,p)))
    def string(index):
        off,length=spans['strings'];need(0<=index<length,'String bounds');return metadata[off+index:metadata.index(b'\0',off+index,off+length)].decode()
    field=next(json.loads(l) for l in (lab/'metadata/fields.jsonl').open(encoding='utf8') if json.loads(l)['owner_type']=='Terraria.ID.SetFactory' and json.loads(l)['name']=='_size')
    fp,fr=record('fields',field['index']);tp,tr=record('types',field['owner_type_index'])
    need(string(fr['name_index'])=='_size' and string(tr['name_index'])=='SetFactory' and string(tr['namespace_index'])=='Terraria.ID','Field identity')
    local=field['index']-tr['field_start'];need(0<=local<tr['field_count'],'Owner field bounds')
    layout=json.loads((lab/'native/type-layouts.json').read_text())[field['owner_type_index']]
    slot=int(layout['field_offsets_pointer'],16)+4*local;offset=elf.at(slot)
    need(struct.unpack_from('<i',elf.raw,offset)[0]==16 and field['native_field_offset_scope']=='instance_storage','Native field offset')
    methods={json.loads(l)['index']:json.loads(l) for l in (lab/'metadata/methods.jsonl').open(encoding='utf8')}
    ctor=methods[16857];mp,mr=record('methods',16857)
    need(string(mr['name_index'])=='.ctor' and mr['declaring_type']==field['owner_type_index'] and mr['parameter_count']==1 and not mr['flags']&16,'Ctor metadata')
    pp,pr=record('parameters',mr['parameter_start']);need(string(pr['name_index'])=='size' and ctor['native_address']==hex(CTOR),'Ctor argument/name address')
    def read(start,count):return elf.raw[elf.at(start):elf.at(start)+count]
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    body=read(0x1ac5864,0x1ac59c4-0x1ac5864);validate_body(body,0x1ac5864)
    decoded=list(cs.disasm(body,0x1ac5864));need(len(decoded)*4==len(body),'Capstone coverage')
    for ins in decoded[2:-1]:
        raw_write=raw_dest(int.from_bytes(ins.bytes,'little'))
        actual={ins.reg_name(r) for r in ins.regs_access()[1]}-{'nzcv','x30','lr'}
        expected=set() if raw_write is None else {('w' if ins.mnemonic in ('ldrb',) or ins.op_str.startswith('w') else 'x')+str(raw_write)}
        need(actual==expected,'Decoder disagreement '+hex(ins.address)+' '+str(actual)+' '+str(expected))
    rows=[]
    rangepath=lab/'native/unwind-function-ranges.tsv';ranges={int(l.split('\t')[0],16):int(l.split('\t')[1],16) for l in rangepath.read_text().splitlines()}
    for owner,start,size in [('Terraria.ID.ItemID+Sets',0x1a899e0,6196),('Terraria.ID.NPCID+Sets',0x1aaf3b0,697)]:
        raw=read(start,16);validate_call(raw,start,size)
        callcode=list(cs.disasm(raw,start));need(len(callcode)==4 and callcode[0].mnemonic=='mov' and callcode[0].op_str=='w1, #'+hex(size) and callcode[-1].mnemonic=='bl' and callcode[-1].operands[0].imm==CTOR,'Call decoder disagreement')
        init=next(m for m in methods.values() if m.get('owner_type')==owner and m['name']=='.cctor')
        ip,ir=record('methods',init['index']);init_start=int(init['native_address'],16);need(string(ir['name_index'])=='.cctor' and ir['flags']&16 and init_start<=start and start+16<=ranges[init_start],'Initializer identity differs')
        rows.append({'initializer_type':owner,'call_site':hex(start+12),'constructor':hex(CTOR),'argument_parameter':'size','W1_signed_Int32':size,'suffix_start':hex(start),'suffix_bytes':raw.hex(),'capstone':[i.mnemonic+' '+i.op_str for i in cs.disasm(raw,start)],'conditional_instance_field_result':{'field':'Terraria.ID.SetFactory::_size','offset':16,'value':size}})
    negative=[]
    for label,fn in [('wrong_size',lambda:validate_call(read(0x1a899e0,16),0x1a899e0,6195)),('wrong_BL_target',lambda:validate_call(read(0x1a899e0,12)+struct.pack('<I',0x94000000),0x1a899e0,6196)),('wrong_store_offset',lambda:validate_body(body[:-4]+struct.pack('<I',0xb9001693),0x1ac5864)),('clobbered_saved_size',lambda:validate_body(body[:8]+struct.pack('<I',0x2a0203f3)+body[12:],0x1ac5864)),('clobbered_saved_receiver',lambda:validate_body(body[:8]+struct.pack('<I',0xaa0203f4)+body[12:],0x1ac5864))]:
        try:fn()
        except ValueError:negative.append(label)
        else:raise ValueError('Negative fixture accepted: '+label)
    out=lab/'initializer-refinement-20261015';out.mkdir(exist_ok=True)
    doc={'profile':'setfactory-constructor-size-v1','elf_sha256':ELF_SHA,'metadata_sha256':META_SHA,'producer_sha256':digest(pathlib.Path(__file__).read_bytes()),'inputs':{str(p.relative_to(lab)):digest(p.read_bytes()) for p in [lab/'metadata/methods.jsonl',lab/'metadata/fields.jsonl',lab/'native/type-layouts.json',rangepath]},'constructor_identity':ctor,'metadata_method_record_offset':hex(mp),'metadata_parameter_record_offset':hex(pp),'field_source':{'metadata_type_record':hex(tp),'metadata_field_record':hex(fp),'native_offset_slot':hex(slot),'native_offset_bytes':elf.raw[offset:offset+4].hex()},'constructor_save_to_store_fragment':{'start':hex(0x1ac5864),'end_exclusive':hex(0x1ac59c4),'sha256':digest(body),'bytes':body.hex(),'instructions':[{'address':hex(i.address),'raw_bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str} for i in decoded]},'results':rows,'audit':{'two_decoders_agree_instructions':len(decoded)-3,'negative_fixtures_rejected':negative},'conditions':['Each recorded caller suffix executes contiguously before its BL.','Instance IL2CPP ABI supplies receiver in X0 and System.Int32 size in W1; metadata/native-address binding reused from hashed original catalog.','Execution follows the constructor entry, all preceding helper calls return normally and preserve X19/X20 and SP under AAPCS64.','Execution reaches the nonzero-size store at 0x1ac59c0; no full reachability, success or exception-path proof is claimed.'],'limitations':['Neither static ItemID.Sets.Factory nor NPCID.Sets.Factory assignment is established: the global class-root metadata-usage association and global state across helper calls have not been independently resolved.','No array contents, set membership, complete static initializer, runtime observation or restored original C# is claimed.']}
    (out/'setfactory-size.json').write_text(json.dumps(doc,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    (out/'REPORT.ru.md').write_text('# Ограниченное уточнение SetFactory\n\nВ двух статических инициализаторах подтверждены аргументы `SetFactory::.ctor(size)`: ItemID.Sets — **6196**, NPCID.Sets — **697**. Исходные ARM64-байты конструктора сохраняют W1 в W19 и X0 в X20; при достижении ненулевой ветви записывают W19 по `[X20+16]`. Имя экземплярного поля `_size` и смещение 16 проверены по исходным метаданным и нативной таблице смещений.\n\nЭто условный результат: требуется нормальный возврат предыдущих вызовов и соблюдение AAPCS64, а также достижение записи. Реальное исполнение этого участка не наблюдалось. Присваивание определённому статическому полю Factory не доказано: связь глобального корня класса с метаданными и состояние через вспомогательные вызовы остаются неразрешёнными. Содержимое наборов и полный C# не восстановлены.\n\nПроверка: независимый декодер битовых полей ARM64 сопоставлен с Capstone; пять изменённых отрицательных примеров отклонены. Полные байты, адреса, хеши и предпосылки находятся в `setfactory-size.json`.\n',encoding='utf8')
    print(json.dumps({'output':str(out),'constructor_sizes':[6196,697],'bytes_checked':len(body)+32,'negative_controls':len(negative)}))

if __name__=='__main__':main()
