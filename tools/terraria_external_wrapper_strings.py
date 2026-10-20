"""Bounded offline interpretation of registration string construction.

No game machine code is executed. A small explicit ARM64 operation model reads
the ELF bytes, models fresh guard initialization, and stops on unknown opcodes.
"""
import argparse, hashlib, json, struct, sys
from pathlib import Path
from terraria_jni_bindings import ELF, resolve_local_abs64, imported_thunks, disassemble


class Model:
    def __init__(self,elf,cs):
        self.elf=elf;self.cs=cs;self.mem={};self.reg={**{'x'+str(i):0 for i in range(19,31)},'sp':0x700000000};self.vec={};self.trace=[];self.calls=[];self.classes={};self.flags={};self.steps=0
        self.env=0x600000000;self.vtable=self.env+0x1000;self.reg['x0']=self.env
        self.put(self.env,8,self.vtable)
        for offset in (48,168,1720):self.put(self.vtable+offset,8,self.env+0x10000+offset)
        self.imports=imported_thunks(elf)
        self.guard_functions={}
        # Resolve defined guard functions by ELF symbols, then verify their PLT pointer.
        names={}
        for section in elf.sections:
            if section['type'] not in (2,11):continue
            strings=elf.sections[section['link']];pool=elf.data[strings['offset']:strings['offset']+strings['size']]
            for off in range(section['offset'],section['offset']+section['size'],section['entsize'] or 24):
                name,attrs,other,defined,value,size=struct.unpack_from('<IBBHQQ',elf.data,off)
                label=pool[name:pool.find(b'\0',name)].decode('ascii',errors='replace')
                if defined and label in ('__cxa_guard_acquire','__cxa_guard_release'):names[value]=label
        for va in (0xff4d0,0xff4e0):
            body=disassemble(elf,va,16);assert [x['op'] for x in body]==['adrp','ldr','addi','br']
            slot=body[0]['value']+body[1]['imm'];target=elf.pointer(slot)
            if target not in names:
                for section in elf.sections:
                    if section['type']!=4:continue
                    symbols=elf.sections[section['link']]
                    for off in range(section['offset'],section['offset']+section['size'],section['entsize'] or 24):
                        address,info,addend=struct.unpack_from('<QQq',elf.data,off)
                        if address!=slot or info&0xffffffff not in (1026,1025):continue
                        record=symbols['offset']+(info>>32)*(symbols['entsize'] or 24)
                        _,_,_,defined,value,_=struct.unpack_from('<IBBHQQ',elf.data,record)
                        if defined:target=value+addend
            assert target in names
            self.guard_functions[va]={'name':names[target],'resolved_function':hex(target),'instructions':body}
    def get(self,name):
        name={'fp':'x29','lr':'x30'}.get(name,name)
        if name in ('wzr','xzr'):return 0
        key='x'+name[1:] if name.startswith('w') else name
        if key not in self.reg:raise ValueError('unknown register '+name)
        return self.reg[key]&((1<<(32 if name.startswith('w') else 64))-1)
    def set(self,name,value):
        name={'fp':'x29','lr':'x30'}.get(name,name)
        if name in ('xzr','wzr'):return
        self.reg['x'+name[1:] if name.startswith('w') else name]=value&((1<<(32 if name.startswith('w') else 64))-1)
    def read(self,address,size):
        out=[]
        for a in range(address,address+size):
            if a in self.mem:out.append(self.mem[a]);continue
            found=False
            for reloc,value in self.elf.relocations.items():
                if reloc<=a<reloc+8:out.append((value>>(8*(a-reloc)))&255);found=True;break
            if found:continue
            try:out.append(self.elf.data[self.elf.file_offset(a)])
            except ValueError:
                if any(s['type']==1 and s['vaddr']<=a<s['vaddr']+s['memsz'] for s in self.elf.segments):out.append(0)
                else:raise ValueError('unmapped read '+hex(a))
        return bytes(out)
    def put(self,address,size,value):
        b=value if isinstance(value,bytes) else (value&((1<<(size*8))-1)).to_bytes(size,'little')
        assert len(b)==size
        for i,v in enumerate(b):self.mem[address+i]=v
    def string(self,address):
        out=bytearray()
        for i in range(1024):
            b=self.read(address+i,1)[0]
            if not b:return out.decode('ascii')
            out.append(b)
        raise ValueError('unterminated string')
    def run(self,start):
        from capstone.arm64 import ARM64_OP_REG,ARM64_OP_IMM,ARM64_OP_MEM
        pc=start;returns=[]
        while True:
            self.steps+=1
            if self.steps>25000:raise ValueError('step budget exceeded')
            ins=next(self.cs.disasm(self.elf.data[self.elf.file_offset(pc):self.elf.file_offset(pc)+4],pc,count=1))
            m=ins.mnemonic;ops=ins.operands;names=[ins.reg_name(o.reg) if o.type==ARM64_OP_REG else None for o in ops]
            self.trace.append({'pc':hex(pc),'bytes':ins.bytes.hex(),'mnemonic':m,'operands':ins.op_str});nxt=pc+4
            def val(i):return self.get(names[i]) if ops[i].type==ARM64_OP_REG else ops[i].imm
            if m in ('nop','hint'):pass
            elif m=='mrs':self.set(names[0],0x710000000);self.put(0x710000028,8,0x12345678)
            elif m in ('adr','adrp','mov','movz','movn','movk'):
                v=val(1)
                if m=='movk':v=(self.get(names[0])&~(65535<<ops[1].shift.value))|(v<<ops[1].shift.value)
                elif ops[1].shift.value:v<<=ops[1].shift.value
                if m=='movn':v=~v
                self.set(names[0],v)
            elif m in ('add','sub','subs','eor','orr','and','cmp','tst'):
                if names[0] and names[0].startswith('v'):
                    size=16 if '.16b' in ins.op_str else 8
                    left=self.vec[int(names[1][1:])];right=self.vec[int(names[2][1:])]
                    assert m=='eor';self.vec[int(names[0][1:])]=bytes(x^y for x,y in zip(left[:size],right[:size]))+bytes(16-size)
                else:
                    a=val(0 if m in ('cmp','tst') else 1);b=val(1 if m in ('cmp','tst') else 2)
                    v=a+b if m=='add' else a-b if m in ('sub','subs','cmp') else a^b if m=='eor' else a|b if m=='orr' else a&b
                    if m in ('cmp','subs','tst'):self.flags={'eq':v==0,'ne':v!=0}
                    if m not in ('cmp','tst'):self.set(names[0],v)
            elif m.startswith(('ldr','ldur','str','stur','ldar')) or m in ('ldp','stp'):
                pair=m in ('ldp','stp');oi=2 if pair else 1;memop=ops[oi];assert memop.type==ARM64_OP_MEM
                base=ins.reg_name(memop.mem.base);baseval=self.get(base);address=baseval+memop.mem.disp
                if memop.mem.index:raise ValueError('indexed load not modeled')
                load=m.startswith(('ld','ldr'))
                for j in range(2 if pair else 1):
                    name=names[j];name={'fp':'x29','lr':'x30'}.get(name,name);size=16 if name.startswith('q') else 8 if name.startswith(('x','d')) else 4 if name.startswith(('w','s')) else 2 if name.startswith('h') else 1
                    if m.endswith('b'):size=1
                    elif m.endswith('h'):size=2
                    addr=address+j*size
                    if name.startswith(('q','d','s','h','b')) and name not in ('sp',):
                        vi=int(name[1:])
                        if load:self.vec[vi]=self.read(addr,size)+bytes(16-size)
                        else:self.put(addr,size,self.vec[vi][:size])
                    elif load:self.set(name,int.from_bytes(self.read(addr,size),'little'))
                    else:self.put(addr,size,self.get(name))
                if ins.writeback:self.set(base,baseval+(ops[oi+1].imm if len(ops)>oi+1 else memop.mem.disp))
            elif m=='ushll':
                assert ops[2].imm==0 and '.8h' in ins.op_str
                b=self.vec[int(names[1][1:])][:8];self.vec[int(names[0][1:])]=b''.join(bytes((x,0)) for x in b)
            elif m=='uzp1':
                assert '.8b' in ins.op_str
                a=self.vec[int(names[1][1:])][:8];b=self.vec[int(names[2][1:])][:8]
                self.vec[int(names[0][1:])]=a[::2]+b[::2]+bytes(8)
            elif m in ('cbz','cbnz','tbz','tbnz'):
                a=val(0);take=(a==0) if m=='cbz' else (a!=0) if m=='cbnz' else not(a&(1<<val(1))) if m=='tbz' else bool(a&(1<<val(1)))
                if take:nxt=val(len(ops)-1)
            elif m.startswith('b.'):
                cond=m[2:]
                if cond not in self.flags:raise ValueError('condition not modeled '+cond)
                if self.flags[cond]:nxt=val(0)
            elif m in ('bl','blr','b','br'):
                target=val(0);link=m in ('bl','blr')
                if target in self.guard_functions:
                    g=self.guard_functions[target];addr=self.get('x0');self.calls.append({'pc':hex(pc),'guard_model':g,'address':hex(addr)})
                    for r in range(19):self.reg.pop('x'+str(r),None)
                    self.flags={}
                    for r in list(self.vec):
                        if r<8 or r>=16:self.vec.pop(r)
                    if g['name']=='__cxa_guard_acquire':self.set('w0',1)
                    else:self.put(addr,1,1)
                elif target in self.imports:
                    label=self.imports[target]['name'];self.calls.append({'pc':hex(pc),'import':label})
                    result=None
                    if label=='__cxa_atexit':result=0
                    elif label=='memcpy':
                        size=self.get('x2');assert size<16384;result=self.get('x0');self.put(result,size,self.read(self.get('x1'),size))
                    else:raise ValueError('unmodeled external '+label)
                    for r in range(19):self.reg.pop('x'+str(r),None)
                    self.flags={}
                    for r in list(self.vec):
                        if r<8 or r>=16:self.vec.pop(r)
                    self.set('x0',result)
                elif target>=self.env:
                    offset=target-self.env-0x10000
                    assert self.get('x0')==self.env
                    if offset==48:
                        cls=self.string(self.get('x1'));fake=self.env+0x20000+len(self.classes)*0x100;self.classes[fake]=cls
                        self.calls.append({'pc':hex(pc),'operation':'FindClass','class':cls})
                        for r in range(19):self.reg.pop('x'+str(r),None)
                        self.flags={}
                        for r in list(self.vec):
                            if r<8 or r>=16:self.vec.pop(r)
                        self.set('x0',fake)
                    elif offset==1720:
                        cls=self.classes[self.get('x1')];table=self.get('x2');count=self.get('w3');assert 0<count<=64
                        rows=[]
                        for i in range(count):
                            p=[int.from_bytes(self.read(table+i*24+j*8,8),'little') for j in range(3)]
                            assert self.elf.executable(p[2]);rows.append({'name':self.string(p[0]),'signature':self.string(p[1]),'function_address':hex(p[2])})
                        self.calls.append({'pc':hex(pc),'operation':'RegisterNatives','class':cls,'rows':rows,'runtime_success_proven':False});return
                    else:raise ValueError('unmodeled JNI slot '+hex(offset))
                else:
                    if link:returns.append(pc+4)
                    nxt=target
            elif m=='ret':
                if not returns:return
                nxt=returns.pop()
            else:raise ValueError(f'unmodeled {pc:x} {m} {ins.op_str}')
            pc=nxt


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--native-dir',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--capstone-dir',type=Path,required=True)
    a=ap.parse_args();sys.path.insert(0,str(a.capstone_dir));from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
    data=(a.native_dir/'libexternal_wrapper.so').read_bytes();elf=ELF(data);resolve_local_abs64(elf);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    a.output.mkdir(parents=True,exist_ok=True);results=[]
    for start in (0x89400,0x89f08,0x8a1f4,0x8a578):
        model=Model(elf,cs);error=None
        try:model.run(start)
        except Exception as exc:error=repr(exc)
        result={'entry':hex(start),'library_sha256':hashlib.sha256(data).hexdigest(),'steps':model.steps,'error':error,'calls':model.calls,'trace':model.trace,
          'scope':'Bounded offline interpreter, fresh guards; assumes success of JNI FindClass and RegisterNatives; never executes APK.'}
        (a.output/(hex(start)+'-external_wrapper-model.json')).write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf8');results.append({'entry':hex(start),'steps':model.steps,'error':error,'registrations':[x for x in model.calls if x.get('operation')=='RegisterNatives']})
    unresolved=json.loads((a.native_dir/'unresolved-dex-native-declarations.json').read_text(encoding='utf8'))
    descriptors=[]
    for flow in results:
        for reg in flow['registrations']:
            for row in reg['rows']:
                descriptor='L'+reg['class']+';->'+row['name']+row['signature'];assert descriptor in str(unresolved)
                row['dex_descriptor']=descriptor;descriptors.append(descriptor)
    assert len(descriptors)==len(set(descriptors))
    (a.output/'external_wrapper-model-summary.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf8');print(json.dumps(results))


if __name__=='__main__':main()
