"""Bounded aiStyle routing evidence from original ARM64; no game execution."""
import hashlib,json,mmap,pathlib,struct,sys
LAB=pathlib.Path('C:/Temp/terraria-re-20261012')
SPANS=[(0x14236f4,0x1423858),(0x1423868,0x142388c),(0x142389c,0x14238c0),(0x14238d0,0x14238f4),(0x1423904,0x1423948),(0x14239ac,0x14239f0),(0x1423e60,0x1423e98),(0x1424088,0x14240ac)]
ELF_SHA='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
META_SHA='4c904c49d168913d28ef547c4f461e539d926d2ed27c0253ed53a2954e9585f7'
def sha(b):return hashlib.sha256(b).hexdigest()
def need(v,m):
    if not v:raise ValueError(m)
def sx(n,b):return n-(1<<b) if n&(1<<(b-1)) else n
class Source:
    def __init__(self):
        self.f=(LAB/'native/libil2cpp.so').open('rb');self.b=mmap.mmap(self.f.fileno(),0,access=mmap.ACCESS_READ)
        need(sha(self.b)==ELF_SHA,'ELF identity');self.loads=[]
        p=struct.unpack_from('<Q',self.b,32)[0];z,n=struct.unpack_from('<HH',self.b,54)
        for k in range(n):
            t,fl,o,a,_,sz,_,_=struct.unpack_from('<II6Q',self.b,p+k*z)
            if t==1:self.loads.append((a,a+sz,o))
    def read(self,a,n):
        for lo,hi,o in self.loads:
            if lo<=a and a+n<=hi:return self.b[o+a-lo:o+a-lo+n]
        raise ValueError('unmapped source')
    def relocation(self,target):
        p=struct.unpack_from('<Q',self.b,40)[0];z,n=struct.unpack_from('<HH',self.b,58);found=[]
        for k in range(n):
            s=struct.unpack_from('<II4QII2Q',self.b,p+k*z)
            if s[1]==4:
                for o in range(s[4],s[4]+s[5],s[9] or 24):
                    a,i,d=struct.unpack_from('<QQq',self.b,o)
                    if a==target:need(i==1027,'relative relocation expected');found.append(d)
        need(len(found)==1,'unique relocation expected');return found[0]
def raw_decode(w,a):
    rd=w&31;rn=(w>>5)&31
    if a==SPANS[0][0]:need(w==0xb9409a68,'aiStyle source load');return ('style',8)
    if w&0xff00001f==0x7100001f:return ('cmp',rn,(w>>10)&4095)
    if w&0xff000010==0x54000000:
        need(w&15 in (8,13),'only HI/LE guards');return ('cond',w&15,a+4*sx((w>>5)&0x7ffff,19))
    if w&0xffc00000==0x51000000:return ('sub',rd,rn,(w>>10)&4095)
    if w&0x9f000000==0x90000000:return ('adrp',rd,(a&~4095)+(sx(((w>>5)&0x7ffff)*4+((w>>29)&3),21)<<12))
    if w&0x9f000000==0x10000000:return ('adr',rd,a+sx(((w>>5)&0x7ffff)*4+((w>>29)&3),21))
    if w&0xffc00000==0x91000000:return ('addimm',rd,rn,(w>>10)&4095)
    if w&0xffc00000==0xf9400000:return ('opaque_load',rd,rn,(w>>10&4095)*8)
    if w&0xffe0ffe0==0xaa0003e0:return ('mov',rd,(w>>16)&31)
    if w&0xffe01fe0==0x1e201000:return ('fmov',)
    if w&0xffe0fc00==0x78607800:return ('ldrh',rd,rn,(w>>16)&31)
    if w&0xffe0fc00==0x8b000800:return ('addshift',rd,rn,(w>>16)&31,2)
    if w&0xfffffc1f==0xd61f0000:return ('br',rn)
    raise ValueError('raw whitelist rejected '+hex(a)+' '+hex(w))
def cap_decode(i):
    from capstone.arm64 import ARM64_OP_REG,ARM64_OP_IMM,ARM64_OP_MEM
    def r(o):
        s=i.reg_name(o.reg);s={'fp':'x29','lr':'x30'}.get(s,s);need(s[:1] in ('x','w') and s[1:].isdigit(),'integer register required');return int(s[1:])
    q=i.operands;m=i.mnemonic
    if i.address==SPANS[0][0]:need(m=='ldr' and i.op_str=='w8, [x19, #0x98]','Capstone field load');return ('style',8)
    if m=='cmp':return ('cmp',r(q[0]),q[1].imm)
    if m in ('b.hi','b.le'):return ('cond',8 if m=='b.hi' else 13,q[0].imm)
    if m=='sub':return ('sub',r(q[0]),r(q[1]),q[2].imm)
    if m in ('adr','adrp'):return (m,r(q[0]),q[1].imm)
    if m=='ldr':return ('opaque_load',r(q[0]),int({'fp':'x29','lr':'x30'}.get(i.reg_name(q[1].mem.base),i.reg_name(q[1].mem.base))[1:]),q[1].mem.disp)
    if m=='mov':return ('mov',r(q[0]),r(q[1]))
    if m=='fmov':need(i.op_str.startswith('s') and q[1].type!=ARM64_OP_REG,'only FP immediate');return ('fmov',)
    if m=='ldrh':
        need(q[1].shift.value==1,'halfword index scale');return ('ldrh',r(q[0]),int(i.reg_name(q[1].mem.base)[1:]),int(i.reg_name(q[1].mem.index)[1:]))
    if m=='add':
        if q[2].type==ARM64_OP_IMM:return ('addimm',r(q[0]),r(q[1]),q[2].imm)
        need(q[2].shift.value==2,'branch offset scale');return ('addshift',r(q[0]),r(q[1]),r(q[2]),2)
    if m=='br':return ('br',r(q[0]))
    raise ValueError('Capstone whitelist rejected '+m)
def route(style,code,read):
    p=SPANS[0][0];regs={};cmp=None;path=[];table=None
    for _ in range(200):
        if p not in code:return {'kind':'guard_fallback','target':hex(p),'path':path}
        path.append(hex(p));op,*q=code[p];n=p+4
        if op=='style':regs[q[0]]=style&0xffffffff
        elif op=='cmp':cmp=(regs[q[0]]&0xffffffff,q[1])
        elif op=='cond':
            l,r=cmp
            if (l>r if q[0]==8 else sx(l,32)<=sx(r,32)):n=q[1]
        elif op=='sub':regs[q[0]]=(regs[q[1]]-q[2])&0xffffffff
        elif op in ('adr','adrp'):regs[q[0]]=q[1]
        elif op=='addimm':regs[q[0]]=None if regs.get(q[1]) is None else regs[q[1]]+q[2]
        elif op=='opaque_load':regs[q[0]]=None
        elif op=='mov':regs[q[0]]=regs.get(q[1])
        elif op=='fmov':pass
        elif op=='ldrh':
            table=(regs[q[1]],regs[q[2]])
            regs[q[0]]=int.from_bytes(read(table[0]+table[1]*2,2),'little')
        elif op=='addshift':regs[q[0]]=regs[q[1]]+(regs[q[2]]<<q[3])
        elif op=='br':return {'kind':'table','target':hex(regs[q[0]]),'table':hex(table[0]),'index':table[1],'branch':hex(p),'path':path}
        else:raise ValueError('unsupported evaluator operation')
        p=n
    raise ValueError('route instruction limit')
def main():
    sys.path.insert(0,str(LAB/'python-analysis'));from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
    from terraria_metadata_catalog import TABLES
    e=Source();cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;rawcode={};capcode={};fragments=[]
    for lo,hi in SPANS:
        b=e.read(lo,hi-lo);ins=list(cs.disasm(b,lo));need(len(ins)*4==len(b),'disassembly coverage')
        fragments.append({'start':hex(lo),'end_exclusive':hex(hi),'bytes':b.hex(),'sha256':sha(b)})
        for i in ins:
            w=int.from_bytes(i.bytes,'little');r=raw_decode(w,i.address);c=cap_decode(i);need(r==c,'decoder disagreement '+hex(i.address)+str((r,c)));rawcode[i.address]=r;capcode[i.address]=c
    meta=(LAB/'native/global-metadata.dat').read_bytes();need(sha(meta)==META_SHA,'metadata identity')
    def record(name,index):
        k=next(k for k,t in enumerate(TABLES) if t[0]==name);_,fmt,keys=TABLES[k];off,length=struct.unpack_from('<II',meta,8+k*8);size=struct.calcsize(fmt);need(0<=index and (index+1)*size<=length,'metadata bounds');p=off+index*size;return p,dict(zip(keys.split(),struct.unpack_from(fmt,meta,p)))
    def string(index):
        k=next(k for k,t in enumerate(TABLES) if t[0]=='strings');off,n=struct.unpack_from('<II',meta,8+k*8);need(0<=index<n,'string bounds');return meta[off+index:meta.index(b'\0',off+index,off+n)].decode()
    fp,f=record('fields',15933);tp,t=record('types',1193);need(string(f['name_index'])=='aiStyle' and string(t['name_index'])=='Projectile' and string(t['namespace_index'])=='Terraria','fresh metadata field identity');local=15933-t['field_start'];need(0<=local<t['field_count'],'owner field range')
    fieldtable=e.relocation(0x2fdb588+0x58);offsets=e.relocation(fieldtable+1193*8);off=int.from_bytes(e.read(offsets+local*4,4),'little');need(off==0x98,'original field offset')
    types=e.relocation(0x2fdb588+0x38);native_type=e.relocation(types+f['type_index']*8);type_bytes=e.read(native_type,16);need((int.from_bytes(type_bytes[8:12],'little')>>16)&255==8,'field native type I4')
    switches=LAB/'hard-switches-v2/switches.json';sdoc=json.loads(switches.read_text());m=next(x for x in sdoc['methods'] if x['address']=='0x1423370');tabs={x['branch']:x for x in m['switch_candidates']};need(len(tabs)==8,'eight dispatch tables')
    for row in tabs.values():need(e.read(int(row['table'],16),2*row['count']).hex()==row['table_raw_bytes'],'source table mismatch')
    rows=[];samples=list(range(1,211))+[-2147483648,-2147483647,-65536,-211,-1,0,211,212,65535,2147483646,2147483647]
    for style in samples:
        r=route(style,rawcode,e.read);need(r==route(style,capcode,e.read),'route decoder comparison')
        if r['kind']=='table':
            tab=tabs[r['branch']];need(r['table']==tab['table'] and 0<=r['index']<tab['count'] and r['target']==tab['entries'][r['index']]['target'],'catalog route comparison')
        rows.append({'aiStyle_signed_Int32':style,**r})
    # Independent arithmetic reference chooses signed upper partitions then unsigned SUB bounds.
    refs=[(25,1,25,0x1423888,0x1444428),(50,26,24,0x14238bc,0x1424078),(75,51,24,0x14238f0,0x1425bf8),(100,76,23,0x1423944,0x1427e6c),(125,101,24,0x14239ec,0x142b8c8),(150,126,24,0x1423e94,0x1431ee0),(175,151,24,0x14240a8,0x1436150),(2147483647,176,35,0x1423854,0x1444428)]
    for r in rows:
        v=r['aiStyle_signed_Int32'];_,bias,count,br,fallback=next(x for x in refs if v<=x[0]);idx=(v-bias)&0xffffffff
        if idx>=count:need(r['kind']=='guard_fallback' and r['target']==hex(fallback),'reference fallback')
        else:need(r['kind']=='table' and r['branch']==hex(br) and r['index']==idx,'reference table index')
    negative=[]
    for address,word in [(0x14236f4,0xb9409e68),(0x14236fc,0x54000000),(0x142384c,0x3868782b),(0x1423850,0x8b0b054a),(0x1423854,0xd63f0140)]:
        try:raw_decode(word,address)
        except ValueError:negative.append({'address':hex(address),'word':hex(word),'rejected':True})
        else:raise ValueError('negative mutation accepted')
    # First-call previews are checked afresh, stopping on any control flow other than BL.
    named={};catalog=LAB/'metadata/methods.jsonl'
    for line in catalog.open(encoding='utf8'):
        z=json.loads(line)
        if z.get('native_address'):named.setdefault(z['native_address'],[]).append({'metadata_method_index':z['index'],'label':z['owner_type']+'::'+z['name']})
    previews={}
    for r in rows:
        if r['kind']!='table' or r['target'] in previews:continue
        a=int(r['target'],16);preview=[];call=None;stop='32_instruction_bound'
        for i in cs.disasm(e.read(a,128),a):
            w=int.from_bytes(i.bytes,'little')
            if w&0xfc000000==0x94000000:
                dest=i.address+4*sx(w&0x3ffffff,26);need(i.mnemonic=='bl' and i.operands[0].imm==dest,'raw BL disagreement');call={'site':hex(i.address),'target':hex(dest),'catalog_labels':named.get(hex(dest),[])};preview.append({'address':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str});stop='first_direct_BL';break
            if any(i.group(g) for g in (1,2,3,4,5,6)):stop='control_flow_before_BL';break
            preview.append({'address':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str})
        previews[r['target']]={'instructions':preview,'first_BL':call,'stop':stop,'runtime_observed':False}
    out=LAB/'projectile-ai-dispatch-20261015';out.mkdir(exist_ok=True)
    doc={'profile':'Projectile-AI-aiStyle-bounded-router-v1','producer_sha256':sha(pathlib.Path(__file__).read_bytes()),'elf_sha256':ELF_SHA,'metadata_sha256':META_SHA,'switch_catalog_sha256':sha(switches.read_bytes()),'method_catalog_sha256':sha(catalog.read_bytes()),'metadata_parser_sha256':sha(pathlib.Path(__file__).with_name('terraria_metadata_catalog.py').read_bytes()),'field':{'index':15933,'owner':1193,'name':'Terraria.Projectile::aiStyle','metadata_record_file_offset':fp,'field_type_index':f['type_index'],'native_field_offset':off,'registration_anchor':'0x2fdb588','field_offset_pointer_table':hex(fieldtable),'owner_offset_array':hex(offsets),'local_index':local,'native_type_pointer':hex(native_type),'native_type_bytes':type_bytes.hex(),'native_type_code':8},'dependencies':[{'relative_lab_path':'hard-switches-v2/switches.json','sha256':sha(switches.read_bytes())},{'relative_lab_path':'metadata/methods.jsonl','sha256':sha(catalog.read_bytes())}],'fragments':fragments,'router_instruction_count':len(rawcode),'tables':list(tabs.values()),'routes':rows,'first_BL_previews':previews,'negative_controls':negative,'sample_count':len(rows),'table_routes_1_to_210':sum(r['kind']=='table' and 1<=r['aiStyle_signed_Int32']<=210 for r in rows),'guard_fallback_styles_1_to_210':[r['aiStyle_signed_Int32'] for r in rows if r['kind']=='guard_fallback' and 1<=r['aiStyle_signed_Int32']<=210],'premises':['Execution reaches 0x14236f4 along the original recorded route; X19 is the intended Projectile receiver.','Original metadata registration anchor, field offset table and read-only switch bytes remain unchanged.','Ordinary memory reads succeed; no hooks, asynchronous register/PC changes or alternate entry into the recorded route.','Routing stops at its first indirect table target or guard fallback; inline game mechanics beyond that point are not simulated.'],'limits':['221 concrete Int32 samples, not an exhaustive enumeration of all 2^32 field values.','Raw and Capstone decoders are independently implemented, but share one evaluator; independent piecewise arithmetic reference checks routing selection.','Metadata names for first BL targets use prior verified native method catalog; this run hashes it and source-checks BL bytes, without reconstructing every method registration anew.','The registration anchor is inherited from prior verified mapping; original RELATIVE entries and selected offset are checked afresh.','First BL previews are straight-line source observations; memory effects/earlier synchronous faults or runtime execution are not proven.'],'runtime_verified':False}
    (out/'dispatch.json').write_text(json.dumps(doc,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    calls=sum(p['first_BL'] is not None for p in previews.values());labels=sum(bool(p['first_BL'] and p['first_BL']['catalog_labels']) for p in previews.values())
    report=['# Диспетчер Projectile.AI по полю aiStyle','','Исходная инструкция 0x14236f4 читает поле Terraria.Projectile::aiStyle по смещению 0x98. Имя и владелец сверены с исходной metadata; смещение — с исходной таблицей fieldOffsets через RELATIVE relocations.',f'Проверено {len(rawcode)} инструкций маршрутизатора двумя декодерами, восемь таблиц и {len(rows)} конкретных значений Int32. Для aiStyle от 1 до 210: 203 маршрута через таблицу; 50, 75, 99, 100, 125, 150, 175 выходят на отдельные guard-fallback адреса. Это отдельные ветки, их поведение здесь не выводится.',f'Для {len(previews)} разных табличных целей собраны ограниченные straight-line previews; {calls} доходят до первого прямого BL, у {labels} есть имена из проверенного каталога. Полная логика этих веток и выполнение в игре не доказаны.','','Условия: X19 указывает на нужный Projectile, достигнуто начало записанного маршрута, исходные таблицы и регистрация не изменены, чтения памяти успешны, нет hooks/смены PC. Проверка останавливается на первой цели BR или guard-fallback. Примеры за диапазоном и границы Int32 включены; все 2^32 значения не перебирались.','','[Исходные байты, таблицы, маршруты, BL и точные ограничения](dispatch.json).']
    (out/'REPORT.ru.md').write_text('\n\n'.join(report)+'\n',encoding='utf8');print(json.dumps({'instructions':len(rawcode),'samples':len(rows),'tables':len(tabs),'first_BL_previews':calls,'named_previews':labels,'negative_controls':len(negative)}))
if __name__=='__main__':main()
