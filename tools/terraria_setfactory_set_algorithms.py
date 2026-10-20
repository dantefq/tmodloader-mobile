"""Conditional SetFactory output modeling by executing a bounded raw ARM64 whitelist.

Only pure post-buffer-helper loops are interpreted. No game/native target runs.
"""
import argparse,collections,hashlib,json,mmap,pathlib,struct,sys

SOURCE='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
LITERALS='6fe84f649ecd9f9872106f4776b586a223a0593b6d19096dee9ca25264ca37fa'
N=6196;MASK=(1<<64)-1
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def need(ok,msg):
    if not ok:raise ValueError(msg)
def s(v,b):return (v&((1<<b)-1))-(1<<b) if v&(1<<(b-1)) else v&((1<<b)-1)

class Machine:
    def __init__(self,code,start,stop,kind,inputs,default):
        need(kind in ('bool','int'),'Kind');need(all(isinstance(x,int) and -(1<<31)<=x<1<<31 for x in inputs),'Int32 inputs');need(kind!='int' or len(inputs)%2==0,'Even IntSet input length');indices=inputs if kind=='bool' else inputs[::2];need(all(0<=i<N for i in indices),'Indices in modeled output bounds')
        self.code=code;self.start=start;self.stop=stop;self.pc=start;self.reg=[0]*32;self.reg[0]=0x200000;self.reg[19]=0x100000;self.reg[20]=default&0xffffffff;self.lt=False;self.steps=0;self.visits=collections.Counter();self.width=1 if kind=='bool' else 4
        self.mem={0x100000:bytearray(32+len(inputs)*4),0x200000:bytearray(32+N*self.width)}
        struct.pack_into('<Q',self.mem[0x100000],24,len(inputs));struct.pack_into('<Q',self.mem[0x200000],24,N)
        for i,v in enumerate(inputs):struct.pack_into('<i',self.mem[0x100000],32+i*4,v)
        self.mem[0x200000][32:]=bytes([0x5a])*(N*self.width)
    def get(self,i):return self.reg[i] if i!=31 else 0
    def put(self,i,v,bits=64):
        if i!=31:self.reg[i]=v&((1<<bits)-1)
    def load(self,a,n,signed=False):
        for base,b in self.mem.items():
            if base<=a and a+n<=base+len(b):return int.from_bytes(b[a-base:a-base+n],'little',signed=signed)
        raise ValueError('Memory load out of contract '+hex(a))
    def store(self,a,n,v):
        base=0x200000;b=self.mem[base];need(base+32<=a and a+n<=base+len(b),'Output store outside valid payload');b[a-base:a-base+n]=(v&((1<<(n*8))-1)).to_bytes(n,'little')
    def run(self):
        while self.pc!=self.stop:
            need(self.start<=self.pc<self.stop and self.pc%4==0,'Control flow left bounded normal-return region');need(self.steps<200000,'Loop bound');w=int.from_bytes(self.code[self.pc-self.start:self.pc-self.start+4],'little');pc=self.pc;self.pc+=4;self.steps+=1;self.visits[hex(pc)]+=1;rd=w&31;rn=(w>>5)&31;rm=(w>>16)&31;bits=64 if w>>31 else 32;mask=(1<<bits)-1
            if w&0x7e000000==0x34000000:
                zero=(self.get(rd)&mask)==0;take=not zero if w&0x01000000 else zero
                if take:self.pc=pc+s((w>>5)&0x7ffff,19)*4
            elif w&0xff000010==0x54000000:
                need(w&15==11,'Only B.LT supported')
                if self.lt:self.pc=pc+s((w>>5)&0x7ffff,19)*4
            elif w&0x7fe0ffe0 in (0x2a0003e0,0x2a2003e0):
                val=self.get(rm);self.put(rd,~val if w&0x00200000 else val,bits)
            elif w&0x7ffffc00==0x12000000:self.put(rd,self.get(rn)&1,bits)
            elif w&0xfffffc00==0x93407c00:self.put(rd,s(self.get(rn),32))
            elif w&0xfffffc00==0xd3607c00:self.put(rd,self.get(rn)<<32)
            elif w&0x7f000000==0x11000000:
                self.put(rd,self.get(rn)+(((w>>10)&4095)<<(12 if w&0x00400000 else 0)),bits)
            elif w&0x7fe00000==0x0b000000:
                need((w>>22)&3==0,'Only LSL ADD register');self.put(rd,self.get(rn)+(self.get(rm)<<((w>>10)&63)),bits)
            elif w&0x7f80001f==0x7100001f:
                right=((w>>10)&4095)<<(12 if w&0x00400000 else 0);self.lt=s(self.get(rn),bits)<s(right,bits)
            elif w&0x7fe0fc1f==0x6b00001f:self.lt=s(self.get(rn),bits)<s(self.get(rm),bits)
            elif w&0xffc00000 in (0xf9400000,0xb9400000,0xb9000000,0x39400000,0x39000000):
                form=w&0xffc00000;n=8 if form==0xf9400000 else 4 if form in (0xb9400000,0xb9000000) else 1;addr=(self.get(rn)+((w>>10)&4095)*n)&MASK
                if form in (0xb9000000,0x39000000):self.store(addr,n,self.get(rd))
                else:self.put(rd,self.load(addr,n),64 if n==8 else 32)
            elif w&0xffe00c00 in (0x38200800,0xb8200800,0xb8600800,0xb8a00800):
                form=w&0xffe00c00;option=(w>>13)&7;shift=(w>>12)&1;need(option in (3,6),'Register offset extension');index=self.get(rm) if option==3 else s(self.get(rm),32);n=1 if form==0x38200800 else 4;addr=(self.get(rn)+(index<<(0 if n==1 else 2 if shift else 0)))&MASK
                if form in (0x38200800,0xb8200800):self.store(addr,n,self.get(rd))
                else:self.put(rd,self.load(addr,n,signed=form==0xb8a00800),64 if form==0xb8a00800 else 32)
            else:raise ValueError('Unsupported opcode '+hex(w)+' at '+hex(pc))
        need(self.reg[0]==0x200000,'Output register changed');return bytes(self.mem[0x200000][32:])

def model(kind,inputs,default):
    if kind=='bool':
        values=[default&1]*N
        for index in inputs:values[index]=(default^1)&1
        return bytes(values),values
    values=[default]*N
    for index,value in zip(inputs[::2],inputs[1::2]):values[index]=value
    return struct.pack('<'+'i'*N,*values),values

def capstone_check(ins):
    """Check raw-whitelist operation/address fields against the second decoder."""
    w=int.from_bytes(ins.bytes,'little');rd=w&31;rn=(w>>5)&31;rm=(w>>16)&31
    if w&0x7e000000==0x34000000:
        need(ins.mnemonic==('cbnz' if w&0x01000000 else 'cbz') and ins.operands[-1].imm==ins.address+s((w>>5)&0x7ffff,19)*4,'CBZ decoder mismatch');return
    if w&0xff000010==0x54000000:need(ins.mnemonic=='b.lt' and ins.operands[0].imm==ins.address+s((w>>5)&0x7ffff,19)*4,'B.LT decoder mismatch');return
    expected=None
    if w&0x7fe0ffe0 in (0x2a0003e0,0x2a2003e0):expected='mvn' if w&0x00200000 else 'mov'
    elif w&0x7ffffc00==0x12000000:expected='and'
    elif w&0xfffffc00==0x93407c00:expected='sxtw'
    elif w&0xfffffc00==0xd3607c00:expected='lsl'
    elif w&0x7f000000==0x11000000 or w&0x7fe00000==0x0b000000:expected='add'
    elif w&0x7f80001f==0x7100001f or w&0x7fe0fc1f==0x6b00001f:expected='cmp'
    elif w&0xffc00000 in (0xf9400000,0xb9400000,0xb9000000,0x39400000,0x39000000):
        expected={0xf9400000:'ldr',0xb9400000:'ldr',0xb9000000:'str',0x39400000:'ldrb',0x39000000:'strb'}[w&0xffc00000];scale=8 if w&0xffc00000==0xf9400000 else 4 if w&0xffc00000 in (0xb9400000,0xb9000000) else 1;need(ins.reg_name(ins.operands[1].mem.base)=='x'+str(rn) and ins.operands[1].mem.disp==((w>>10)&4095)*scale,'Unsigned memory decoder mismatch')
    elif w&0xffe00c00 in (0x38200800,0xb8200800,0xb8600800,0xb8a00800):
        expected={0x38200800:'strb',0xb8200800:'str',0xb8600800:'ldr',0xb8a00800:'ldrsw'}[w&0xffe00c00];option=(w>>13)&7;need(ins.reg_name(ins.operands[1].mem.base)=='x'+str(rn) and ins.reg_name(ins.operands[1].mem.index)==('w' if option==6 else 'x')+str(rm),'Indexed memory decoder mismatch')
    need(expected is not None and ins.mnemonic==expected,'Operation decoder mismatch '+hex(ins.address))

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);ap.add_argument('--verify-only',action='store_true');a=ap.parse_args();lab=a.lab;binary=lab/'native/libil2cpp.so';need(sha(binary)==SOURCE,'ELF identity');bf=binary.open('rb');r=mmap.mmap(bf.fileno(),0,access=mmap.ACCESS_READ);po=struct.unpack_from('<Q',r,32)[0];ps,pn=struct.unpack_from('<HH',r,54);segments=[struct.unpack_from('<II6Q',r,po+i*ps) for i in range(pn)]
    def read(va,n):
        hits=[z[2]+va-z[3] for z in segments if z[0]==1 and z[3]<=va and va+n<=z[3]+z[5]];need(len(hits)==1,'PT_LOAD bounds');return r[hits[0]:hits[0]+n]
    def word(pc):return int.from_bytes(read(pc,4),'little')
    dep=lab/'itemsets-array-literals-20261015/array-literals.json';need(sha(dep)==LITERALS,'Frozen literal evidence');literal=json.loads(dep.read_text());auditp=dep.parent/'independent-audit.json';audit=json.loads(auditp.read_text());need(audit['integrity_passed'] and audit['evidence_sha256']==LITERALS,'Literal audit binding')
    # Callee-saved input/default capture, even-input guard, buffer helper calls.
    need(word(0x1acf48c)==0xaa0203f3 and word(0x1acf490)==0x2a0103f4,'Bool saved inputs');need(word(0x1ac5a40)==0xaa0203f3 and word(0x1ac5a48)==0x2a0103f4 and word(0x1ac5a3c)==0x39406048 and word(0x1ac5a44)==0x37000408,'Int parity/input saves')
    sys.path.insert(0,str(lab/'python-analysis'));from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;functions=[];dual_checked=0
    for name,start,end,body,stop,helperpc,helper in [('CreateBoolSet',0x1acf484,0x1acf51c,0x1acf498,0x1acf50c,0x1acf494,0x1acf66c),('CreateIntSet',0x1ac5a30,0x1ac5ac4,0x1ac5a50,0x1ac5ab4,0x1ac5a4c,0x1acf7b0)]:
        raw=read(start,end-start);code=list(cs.disasm(raw,start));need(len(code)*4==len(raw),'Capstone coverage');hw=word(helperpc);need(hw&0xfc000000==0x94000000 and helperpc+s(hw&0x3ffffff,26)*4==helper,'Buffer helper BL')
        for ins in code:
            if body<=ins.address<stop:capstone_check(ins);dual_checked+=1
        functions.append({'name':name,'start':hex(start),'end_exclusive':hex(end),'body_start':hex(body),'normal_loop_stop':hex(stop),'buffer_helper_call':hex(helperpc),'buffer_helper_target':hex(helper),'bytes':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'address':hex(i.address),'raw_bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str} for i in code]})
    fixtures=[]
    for x in literal['arrays']:
        fixtures.append((x['conditional_result_static_field']['name'],'bool' if x['SetFactory_callee']=='0x1acf484' else 'int',x['serialized_little_endian_Int32_values'],x['SetFactory_default_argument']))
    fixtures.append(('ReceivesDiagonalCorrectionAsFakeFish','bool',[literal['direct_singleton']['Int32_literal']],1));results=[]
    for name,kind,inputs,default in fixtures:
        fn=functions[0 if kind=='bool' else 1];start=int(fn['body_start'],16);stop=int(fn['normal_loop_stop'],16);m=Machine(read(start,stop-start),start,stop,kind,inputs,default);native=m.run();reference,values=model(kind,inputs,default);need(native==reference,'Native-whitelist/reference mismatch')
        edits=[{'index':i,'value':v} for i,v in enumerate(values) if v!=(default&1 if kind=='bool' else default)];results.append({'conditional_static_field':name,'kind':kind,'input_values':inputs,'default':default,'assumed_output_length':N,'output_byte_length':len(native),'modeled_output_sha256':hashlib.sha256(native).hexdigest(),'sparse_edits_from_default':edits,'unique_edited_indices':len(edits),'true_count':sum(values) if kind=='bool' else None,'false_count':N-sum(values) if kind=='bool' else None,'native_whitelist_steps':m.steps,'instruction_visit_counts':dict(m.visits),'all_input_indices_in_bounds':all(0<=i<N for i in (inputs if kind=='bool' else inputs[::2])),'reference_agrees':True,'actual_runtime_observed':False})
    controls=[]
    for label,fn in [('odd_IntSet_input',lambda:Machine(b'',0,0,'int',[1,2,3],-1)),('negative_index',lambda:Machine(b'',0,0,'bool',[-1],0)),('index_equal_length',lambda:Machine(b'',0,0,'bool',[N],0)),('wrong_flip_model',lambda:need(model('bool',[205],0)[0]==bytes(N),'Flipping omitted')),('wrong_pair_stride',lambda:need(model('int',[6168,6168,6169,6168],-1)[1][6169]==-1,'Pairs not applied'))]:
        try:fn()
        except ValueError:controls.append(label)
        else:raise ValueError('Negative accepted '+label)
    doc={'profile':'conditional-SetFactory-set-algorithms-and-native-byte-whitelist-fixtures-v1','elf_sha256':SOURCE,'producer_sha256':sha(pathlib.Path(__file__)),'dependencies':{'itemsets-array-literals-20261015/array-literals.json':LITERALS,'itemsets-array-literals-20261015/independent-audit.json':sha(auditp)},'functions':functions,'results':results,'negative_controls_rejected':controls,'algorithm':{'bool':'Fill all output bytes with defaultState&1; for every signed Int32 input index, write (~defaultState)&1. Repeated indices overwrite the same value.','int':'Require nonnull input and even input length; fill each output Int32 with default; process consecutive (index,value) pairs and assign output[index]=value. Repeated indices take last value.'},'conditions':['Inputs use valid IL2CPP array headers: length at+0x18, payload at+0x20; input values are exactly the frozen serialized vectors (conditional on correct InitializeArray copying) or direct singleton.','SetFactory entry ABI uses X0 receiver, W1 default, X2 input; saved X19/W20 hold the input/default across normal buffer helper return.','The relevant buffer helper returns a nonnull writable output array with length6196, correct bool/Int32 element storage, and no alias with the input/code/headers.','Helpers preserve AAPCS64 callee-saved registers and SP, return normally, and do not alter the input or introduce hooks/concurrent mutation.','All modeled input indices are in[0,6196); IntSet input length is even.','Execution follows the recorded normal-return loops and does not enter exception/helper paths.'],'limitations':['These are conditional source algorithms and modeled output hashes; actual runtime array content, cache correctness, bootstrap reachability and full global state are not established.','The byte interpreter intentionally covers only the bounded post-buffer-helper normal loops, not a general ARM64 emulator.','No bounds check appears between input index load and output store in these loops; modeled bounds are an explicit input contract.','Complete exception-path behavior and nullguard nonreturn status are not claimed.'],'baseline_modified':False}
    doc['raw_vs_Capstone_normal_loop_instructions_checked']=dual_checked
    if not a.verify_only:
        out=lab/'setfactory-set-algorithms-20261015';out.mkdir(exist_ok=True);(out/'set-algorithms.json').write_text(json.dumps(doc,ensure_ascii=False,indent=2)+'\n',encoding='utf8');(out/'REPORT.ru.md').write_text('# Условные алгоритмы SetFactory\n\nИсходные ARM64-циклы CreateBoolSet и CreateIntSet смоделированы на трёх подтверждённых литеральных векторах и прямом singleton2342. BoolSet сначала заполняет буфер default&1, затем пишет противоположное значение по каждому входному индексу. IntSet проверяет чётность длины входа, заполняет буфер default и применяет пары index,value.\n\nПри явно принятом контракте корректного независимого буфера длины6196 и правильных входных массивов DualEquipArmor получает3 true, AllowSmartInteractOnCursorItem — указанные в JSON true-индексы, ReceivesDiagonalCorrectionAsFakeFish — false только по индексу2342. AccessoryIncompatibilityType получает четыре изменения:6168→6168,6169→6168,6194→6168,6193→6168; остальные значения -1.\n\nЭто условная модель по исходным байтам, не наблюдение runtime. Выполнение ограниченного ARM64-интерпретатора сопоставлено с отдельной прямой моделью; полные хеши6196-элементных результатов, посещения инструкций и sparse edits сохранены в JSON. Корректность cache/allocation helper и полного bootstrap не заявляется.\n',encoding='utf8')
    print(json.dumps({'verified':True,'verify_only':a.verify_only,'functions':2,'source_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in functions),'modeled_arrays':len(results),'output_hashes':{x['conditional_static_field']:x['modeled_output_sha256'] for x in results},'negative_controls':len(controls)}));r.close();bf.close()

if __name__=='__main__':main()
