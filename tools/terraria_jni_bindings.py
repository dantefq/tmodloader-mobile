"""Bounded ARM64 JNI call-site inspection; never executes APK libraries.

This is deliberately a partial instruction decoder, not a CPU emulator.
Unknown register-writing instructions invalidate symbolic state.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct
from terraria_native_map import ELF


def signed(value,bits):
    return value-(1<<bits) if value&(1<<(bits-1)) else value


def decode(word,pc):
    d={'pc':hex(pc),'word':hex(word)}
    rd=word&31;rn=(word>>5)&31;rm=(word>>16)&31
    if word&0x1f000000==0x10000000:
        imm=signed(((word>>5)&0x7ffff)<<2 | ((word>>29)&3),21)
        page=bool(word>>31)
        return {**d,'op':'adrp' if page else 'adr','rd':rd,'value':((pc&~4095)+(imm<<12)) if page else pc+imm}
    if word&0x1f000000==0x11000000:
        imm=((word>>10)&4095)<<(12 if word&(1<<22) else 0)
        return {**d,'op':'subi' if word&(1<<30) else 'addi','rd':rd,'rn':rn,'imm':imm,'bits':64 if word>>31 else 32,'sets_flags':bool(word&(1<<29))}
    if word&0x7fe0ffe0==0x2a0003e0:
        return {**d,'op':'mov','rd':rd,'rm':rm,'bits':64 if word>>31 else 32}
    if word&0x1f800000==0x12000000 and rn==31 and ((word>>29)&3)==1:
        n=(word>>22)&1;imms=(word>>10)&63;immr=(word>>16)&63
        length=((n<<6)|((~imms)&63)).bit_length()-1
        if length>=1:
            levels=(1<<length)-1;size=1<<length;s=imms&levels;r=immr&levels
            if s!=levels:
                bits=64 if word>>31 else 32;mask=(1<<size)-1;elem=(1<<(s+1))-1
                elem=((elem>>r)|(elem<<(size-r)))&mask
                value=sum(elem<<i for i in range(0,bits,size))
                return {**d,'op':'movmask','rd':rd,'value':value,'bits':bits}
    if word&0x1f800000==0x12800000:
        opc=(word>>29)&3
        return {**d,'op':{0:'movn',2:'movz',3:'movk'}.get(opc,'unknown'),'rd':rd,'imm':(word>>5)&65535,'shift':16*((word>>21)&3),'bits':64 if word>>31 else 32}
    if word&0x3f800000==0x3d800000:
        return {**d,'op':'ldrq' if word&(1<<22) else 'strq','qt':rd,'rn':rn,'imm':((word>>10)&4095)*16,'size':16}
    if word&0x3fa00000==0x3c800000:
        return {**d,'op':'ldrq' if word&(1<<22) else 'strq','qt':rd,'rn':rn,'imm':signed((word>>12)&511,9),'size':16,'mode':(word>>10)&3}
    if word&0x3e000000==0x2c000000 and word&(1<<31):
        return {**d,'op':'ldpq' if word&(1<<22) else 'stpq','qt':rd,'qt2':(word>>10)&31,'rn':rn,'imm':signed((word>>15)&127,7)*16,'size':16,'mode':(word>>23)&3}
    if word&0x3b000000==0x39000000 and not word&(1<<26):
        size=1<<((word>>30)&3)
        return {**d,'op':'ldr' if word&(1<<22) else 'str','rt':rd,'rn':rn,'imm':((word>>10)&4095)*size,'size':size}
    if word&0x3b200000==0x38000000 and not word&(1<<26):
        return {**d,'op':'ldr' if word&(1<<22) else 'str','rt':rd,'rn':rn,'imm':signed((word>>12)&511,9),'size':1<<((word>>30)&3),'mode':(word>>10)&3}
    if word&0x3a000000==0x28000000 and not word&(1<<26):
        size=8 if word&(1<<31) else 4
        return {**d,'op':'ldp' if word&(1<<22) else 'stp','rt':rd,'rt2':(word>>10)&31,'rn':rn,'imm':signed((word>>15)&127,7)*size,'size':size,'mode':(word>>23)&3}
    if word&0x3b000000==0x18000000 and not word&(1<<26):
        return {**d,'op':'ldrlit','rt':rd,'address':pc+(signed((word>>5)&0x7ffff,19)<<2),'size':8 if word&(1<<30) else 4}
    if word&0x7c000000==0x14000000:
        return {**d,'op':'bl' if word>>31 else 'b','target':pc+(signed(word&0x3ffffff,26)<<2)}
    if word&0xff000010==0x54000000:
        return {**d,'op':'bcond','condition':word&15,'target':pc+(signed((word>>5)&0x7ffff,19)<<2)}
    if word&0x7e000000==0x34000000:
        return {**d,'op':'cbnz' if word&(1<<24) else 'cbz','rt':rd,'target':pc+(signed((word>>5)&0x7ffff,19)<<2)}
    if word&0x7e000000==0x36000000:
        return {**d,'op':'tbnz' if word&(1<<24) else 'tbz','rt':rd,'bit':((word>>19)&31)|((word>>26)&32),'target':pc+(signed((word>>5)&0x3fff,14)<<2)}
    if word&0xfffffc1f==0xd63f0000: return {**d,'op':'blr','rn':rn}
    if word&0xfffffc1f==0xd61f0000: return {**d,'op':'br','rn':rn}
    if word&0xfffffc1f==0xd65f0000: return {**d,'op':'ret','rn':rn}
    if word in (0xd503201f,0xd503233f,0xd50323bf) or word&0xfffff01f==0xd503201f:
        return {**d,'op':'hint'}
    return {**d,'op':'unknown','possible_rd':rd}


def disassemble(elf,start,size):
    result=[]
    for pc in range(start,start+size,4):
        try: word=struct.unpack_from('<I',elf.data,elf.file_offset(pc))[0]
        except (ValueError,struct.error): break
        result.append(decode(word,pc))
    return result


def instruction_xrefs(elf,candidates,class_strings):
    wanted={int(c['table_address'],16):{'kind':'method_table','name':c['name'],'signature':c['signature']} for c in candidates}
    for entry in class_strings:
        for address in entry['addresses']: wanted[int(address,16)]={'kind':'class_string','class':entry['class']}
    refs=[];register_loads=[]
    for section in elf.sections:
        if not section['flags']&4 or section['type']==8: continue
        values={}
        for off in range(section['offset'],section['offset']+section['size']-3,4):
            pc=section['vaddr']+off-section['offset'];word=struct.unpack_from('<I',elf.data,off)[0]
            d=decode(word,pc);op=d['op'];value=None
            if op in ('adr','adrp'):
                value=d['value'];values[d['rd']]=(value,pc)
            elif op=='addi':
                before=values.get(d['rn'])
                if before and pc-before[1]<=32:
                    value=before[0]+d['imm'];values[d['rd']]=(value,pc)
                else: values.pop(d['rd'],None)
            elif op=='mov':
                if d['rm'] in values: values[d['rd']]=values[d['rm']]
                else: values.pop(d['rd'],None)
            elif op in ('ldr','ldp','ldrlit'):
                values.pop(d.get('rt'),None)
                if op=='ldp':values.pop(d['rt2'],None)
                if op=='ldr' and d['size']==8 and d['imm'] in (0x6b8,0x30):
                    register_loads.append({'pc':hex(pc),'offset':hex(d['imm']),'rn':d['rn'],'rt':d['rt'],
                                           'context':disassemble(elf,max(section['vaddr'],pc-32),68)})
            elif op in ('b','bl','blr','br','ret','bcond','cbz','cbnz','tbz','tbnz'):
                values.clear()
            elif op in ('subi','movz','movn','movk','unknown'):
                values.pop(d.get('rd',d.get('possible_rd')),None)
            if value in wanted:
                refs.append({'pc':hex(pc),'address':hex(value),'rd':d['rd'],**wanted[value]})
    return refs,register_loads


def imported_thunks(elf):
    slots={}
    for section in elf.sections:
        if section['type']!=4:continue
        symbols=elf.sections[section['link']];strings=elf.sections[symbols['link']]
        pool=elf.data[strings['offset']:strings['offset']+strings['size']]
        for off in range(section['offset'],section['offset']+section['size'],section['entsize'] or 24):
            target,info,addend=struct.unpack_from('<QQq',elf.data,off)
            typ=info&0xffffffff;index=info>>32
            if typ not in (1025,1026,257) or not index:continue
            name,attrs,other,defined,value,size=struct.unpack_from('<IBBHQQ',elf.data,symbols['offset']+index*(symbols['entsize'] or 24))
            if defined:continue
            end=pool.find(b'\0',name);slots[target]=pool[name:end].decode('ascii',errors='replace')
    thunks={}
    for section in elf.sections:
        if section['name']!='.plt':continue
        for start in range(section['vaddr'],section['vaddr']+section['size']-15,4):
            ins=disassemble(elf,start,16)
            if len(ins)!=4 or [d['op'] for d in ins]!=['adrp','ldr','addi','br']:continue
            adr,load,add,branch=ins
            if load['rn']!=adr['rd'] or branch['rn']!=load['rt']:continue
            slot=adr['value']+load['imm']
            if slot in slots:thunks[start]={'name':slots[slot],'slot':hex(slot),'instructions':ins}
    return thunks


def resolve_local_abs64(elf):
    for section in elf.sections:
        if section['type']!=4:continue
        symbols=elf.sections[section['link']]
        for off in range(section['offset'],section['offset']+section['size'],section['entsize'] or 24):
            target,info,addend=struct.unpack_from('<QQq',elf.data,off)
            if info&0xffffffff!=257:continue
            index=info>>32
            record=symbols['offset']+index*(symbols['entsize'] or 24)
            if record+24>symbols['offset']+symbols['size']:raise ValueError('ABS64 symbol index out of range')
            name,attrs,other,defined,value,size=struct.unpack_from('<IBBHQQ',elf.data,record)
            if defined:elf.relocations[target]=value+addend


def jni_header_evidence(path):
    data=path.read_bytes();text=data.decode('utf8')
    result={'path':str(path),'sha256':hashlib.sha256(data).hexdigest(),'size':len(data),'pointer_size':8,'tables':{}}
    for table in ('JNINativeInterface_','JNIInvokeInterface_'):
        start=text.index('struct '+table+' {');end=text.index('\n};',start)+3
        body=text[start:end]
        fields=[]
        for match in re.finditer(r'void\s*\*\s*(reserved\d+)\s*;|\(\s*JNICALL\s*\*\s*(\w+)\s*\)',body):
            fields.append({'name':match.group(1) or match.group(2),'index':len(fields),'offset':hex(len(fields)*8),
                           'line':text.count('\n',0,start+match.start())+1})
        result['tables'][table]={'first_line':text.count('\n',0,start)+1,'last_line':text.count('\n',0,end)+1,
                                 'field_count':len(fields),'selected_fields':[f for f in fields if f['name'] in ('FindClass','RegisterNatives','NewGlobalRef','DeleteLocalRef','AttachCurrentThread','GetEnv','ThrowNew')]}
    actual={f['name']:f['index'] for table in result['tables'].values() for f in table['selected_fields']}
    if actual.get('FindClass')!=6 or actual.get('RegisterNatives')!=215 or actual.get('AttachCurrentThread')!=4 or actual.get('GetEnv')!=6:
        raise ValueError('Local JNI header field indices differ from expected ABI')
    return result


def symbolic_registration(elf,start,limit=0x4000,initial_env=True,branch_choices=None,initial_memory=None,initial_registers=None,initial_stack=None,inline_calls=None):
    """Follow only the normal fall-through path; retain explicit branch guards.

    Proof records require JNIEnv provenance, FindClass result provenance and
    complete resolved triplets passed to its RegisterNatives slot.
    """
    regs={31:('stack',0)};qregs={};stack=dict(initial_stack or {});memory=dict(initial_memory or {});calls=[];guards=[];unknown=[];env_slots={};thunks=imported_thunks(elf);skip_until=0
    if initial_env:regs[0]=('env',)
    else:regs[0]=('vm',)
    if initial_registers:regs.update(initial_registers)
    def plus(value,amount):
        if value and value[0] in ('stack','const'):return(value[0],value[1]+amount)
        return None
    def string_at(value):
        if not value or value[0]!='const':return None
        try:
            off=elf.file_offset(value[1]);end=elf.data.find(b'\0',off,min(len(elf.data),off+512))
            return elf.data[off:end].decode('ascii') if end>=0 else None
        except (ValueError,UnicodeDecodeError):return None
    def readmem(addr):
        if addr is None:return None
        if addr[0]=='stack':return stack.get(addr[1])
        if addr[0]=='const':
            if addr[1] in memory:return memory[addr[1]]
            try:return('const',elf.pointer(addr[1]))
            except (ValueError,struct.error):return None
        return None
    def store(addr,value):
        if addr and addr[0]=='stack':stack[addr[1]]=value
        elif addr and addr[0]=='const':memory[addr[1]]=value
    def load(base,imm):
        if base and base[0] in ('env','vm') and imm==0:return('vtable',base[0])
        if base and base[0]=='vtable':return('jni_fn',base[1],imm)
        return readmem(plus(base,imm))
    for d in disassemble(elf,start,limit):
        pc=int(d['pc'],16);op=d['op']
        if pc<skip_until:continue
        if op in ('adr','adrp'):regs[d['rd']]=('const',d['value'])
        elif op=='movmask':regs[d['rd']]=('const',d['value'])
        elif op in ('addi','subi'):
            if d['sets_flags'] and d['rd']==31:continue
            regs[d['rd']]=plus(regs.get(d['rn']),d['imm']*(-1 if op=='subi' else 1))
        elif op=='mov':regs[d['rd']]=('const',0) if d['rm']==31 else regs.get(d['rm'])
        elif op in ('movz','movn','movk'):
            value=d['imm']<<d['shift'];mask=(1<<d['bits'])-1
            if op=='movn':value=(~value)&mask
            elif op=='movk':
                previous=regs.get(d['rd'])
                value=((previous[1]&~(65535<<d['shift']))|value)&mask if previous and previous[0]=='const' else None
            regs[d['rd']]=('const',value) if value is not None else None
        elif op in ('ldr','str','ldp','stp','ldrq','strq','ldpq','stpq'):
            base=regs.get(d['rn']);mode=d.get('mode',2);delta=d['imm']
            address=plus(base,0 if mode==1 else delta)
            if op=='ldr':regs[d['rt']]=load(base,0 if mode==1 else delta)
            elif op=='str':store(address,('const',0) if d['rt']==31 else regs.get(d['rt']))
            elif op=='ldp':
                regs[d['rt']]=readmem(address);regs[d['rt2']]=readmem(plus(address,d['size']))
            elif op=='stp':
                store(address,('const',0) if d['rt']==31 else regs.get(d['rt']))
                store(plus(address,d['size']),('const',0) if d['rt2']==31 else regs.get(d['rt2']))
            elif op in ('ldrq','ldpq'):
                qregs[d['qt']]=(readmem(address),readmem(plus(address,8)))
                if op=='ldpq':qregs[d['qt2']]=(readmem(plus(address,16)),readmem(plus(address,24)))
            elif op in ('strq','stpq'):
                values=qregs.get(d['qt'],(None,None));store(address,values[0]);store(plus(address,8),values[1])
                if op=='stpq':
                    values=qregs.get(d['qt2'],(None,None));store(plus(address,16),values[0]);store(plus(address,24),values[1])
            if mode in (1,3):regs[d['rn']]=plus(base,delta)
        elif op=='blr':
            fn=regs.get(d['rn']);args=[regs.get(i) for i in range(4)];result=None
            entry={'pc':d['pc'],'target':fn,'args':args,'path_guards':list(guards)}
            if fn and fn[0]=='jni_fn' and fn[1]=='env' and args[0]==('env',):
                if fn[2]==48:
                    cls=string_at(args[1]);result=('class',cls,d['pc']) if cls else None
                    entry.update(operation='FindClass',class_name=cls)
                elif fn[2]==168:
                    result=args[1] if args[1] and args[1][0]=='class' else None
                    entry['operation']='NewGlobalRef'
                elif fn[2]==1720:
                    cls=args[1][1] if args[1] and args[1][0]=='class' else None
                    count=args[3][1] if args[3] and args[3][0]=='const' else None
                    table=args[2];triplets=[]
                    if isinstance(count,int) and 0<count<=512:
                        for i in range(count):
                            nameptr=readmem(plus(table,i*24));sigptr=readmem(plus(table,i*24+8));function=readmem(plus(table,i*24+16))
                            name=string_at(nameptr);sig=string_at(sigptr)
                            valid=bool(name and sig and function and function[0]=='const' and elf.executable(function[1]))
                            triplets.append({'name':name,'signature':sig,'function_address':hex(function[1]) if function and function[0]=='const' else None,'valid':valid})
                    entry.update(operation='RegisterNatives',class_name=cls,count=count,table=table,triplets=triplets,
                                 proven_static_arguments=bool(cls and count==len(triplets) and all(t['valid'] for t in triplets)),runtime_success_proven=False)
                else:entry['operation']='JNI_slot_'+hex(fn[2])
            elif fn and fn[0]=='jni_fn' and fn[1]=='vm' and fn[2] in (32,48) and args[0]==('vm',):
                if args[1] and args[1][0]=='stack':env_slots[args[1][1]]=True;store(args[1],('env',))
                entry['operation']='AttachCurrentThread' if fn[2]==32 else 'GetEnv'
            calls.append(entry)
            for i in range(19):regs.pop(i,None)
            qregs.clear()
            regs[0]=result
        elif op=='bl':
            entry={'pc':d['pc'],'operation':'direct_call','target':hex(d['target']),'args':[regs.get(i) for i in range(4)]}
            imported=thunks.get(d['target'])
            result=None
            if inline_calls and d['target'] in inline_calls:
                config=inline_calls[d['target']]
                nested=symbolic_registration(elf,d['target'],config['limit'],False,config.get('branch_choices'),memory,
                                             dict(regs),stack)
                entry.update(modeled_effect='bounded selected-path inline call',inline_flow=nested)
                stack={int(k):tuple(v) if v else None for k,v in nested['final_stack_state'].items()}
                memory={int(k,16):tuple(v) if v else None for k,v in nested['global_memory_state'].items()}
                result=nested['final_registers'].get('0')
                if result:result=tuple(result)
            elif imported:
                entry['import']=imported
                if imported['name']=='memcpy':
                    dest,src,length=regs.get(0),regs.get(1),regs.get(2)
                    if dest and src and length and length[0]=='const' and 0<length[1]<=16384 and length[1]%8==0:
                        for i in range(0,length[1],8):store(plus(dest,i),readmem(plus(src,i)))
                        entry['modeled_effect']='bounded memcpy pointer values'
            else:
                body=disassemble(elf,d['target'],12)
                if len(body)==3 and [i['op'] for i in body]==['adrp','ldr','ret'] and body[1]['rn']==body[0]['rd'] and body[1]['rt']==0:
                    global_address=body[0]['value']+body[1]['imm']
                    result=memory.get(global_address)
                    if result:entry.update(modeled_effect='three-instruction global getter',global_address=hex(global_address),return_value=result)
            calls.append(entry)
            for i in range(19):regs.pop(i,None)
            qregs.clear()
            regs[0]=result
        elif op in ('bcond','cbz','cbnz','tbz','tbnz'):
            taken=bool(branch_choices and branch_choices.get(pc))
            guards.append({'pc':d['pc'],'op':op,'target':hex(d['target']),'path':'taken' if taken else 'fallthrough',
                           'tested_register':d.get('rt'),'tested_symbolic_value':regs.get(d.get('rt')),
                           'condition_code':d.get('condition'),'bit':d.get('bit')})
            if taken:
                if d['target']<=pc:
                    unknown.append({'pc':d['pc'],'reason':'backward_branch_not_followed'});break
                skip_until=d['target']
        elif op=='b':
            if d['target']==pc+4:continue
            unknown.append({'pc':d['pc'],'reason':'unconditional_branch_stops_path','target':hex(d['target'])});break
        elif op in ('ret','br'):break
        elif op=='unknown':
            unknown.append(d)
            if d['possible_rd']!=31:regs.pop(d['possible_rd'],None)
        elif op=='ldrlit':regs[d['rt']]=readmem(('const',d['address']))
    registrations=[c for c in calls if c.get('operation')=='RegisterNatives']
    return {'entry':hex(start),'initial_argument':'JNIEnv*' if initial_env else 'JavaVM*','calls':calls,'registrations':registrations,
            'proven_static_registration_count':sum(c['proven_static_arguments'] for c in registrations),
            'global_memory_state':{hex(k):v for k,v in memory.items()},
            'final_stack_state':{str(k):v for k,v in stack.items()},'final_registers':{str(k):v for k,v in regs.items()},
            'unmodeled_instructions_or_flow':unknown,'path_policy':'normal fallthrough with explicitly selected forward conditional branches; branches recorded as guards; unconditional branches terminate path except b pc+4'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-dir',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--bindings-only',action='store_true',help='Reuse address inventory; only analyze selected registration paths')
    parser.add_argument('--jni-header',type=Path,default=Path('C:/Program Files/Java/jdk-21.0.12.1/include/jni.h'))
    parser.add_argument('--dex-catalog',type=Path,default=Path('C:/Temp/terraria-re-20261012/android/classes.dex.json'))
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1];output=args.output.resolve()
    if output.is_relative_to(root):raise ValueError('Derived instructions must stay outside repository')
    output.mkdir(parents=True,exist_ok=True)
    if args.bindings_only:
        final=build_bindings(args.native_dir,output,args.jni_header,args.dex_catalog)
        print(json.dumps(final['summary'],ensure_ascii=False))
        return
    summary=[]
    for name in ('libmain.so','libpdaprotect.so','libunity.so'):
        path=args.native_dir/name;data=path.read_bytes();elf=ELF(data)
        cat=json.loads(path.with_name(name+'.json').read_text(encoding='utf8'))
        refs,loads=instruction_xrefs(elf,cat['plaintext_jni_candidates'],cat['native_declaring_class_strings'])
        onloads=[]
        for symbol in cat['onload_exports']:
            start=int(symbol['address'],16)
            onloads.append({'symbol':symbol['name'],'address':symbol['address'],'size':symbol['size'],'instructions':disassemble(elf,start,symbol['size'])})
        report={'library':name,'sha256':hashlib.sha256(data).hexdigest(),'onloads':onloads,'address_xrefs':refs,'jni_vtable_offset_loads':loads,
                'limitations':['Partial ARM64 instruction decoder; unknown instructions are retained as raw words.',
                               'Address xrefs prove constant materialization, not successful JNI registration.',
                               'JNI offset 0x30 can describe FindClass or JavaVM.GetEnv; base provenance must be checked.',
                               'No target code was executed.']}
        (output/(name+'.static-bindings.json')).write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf8')
        summary.append({'library':name,'onload_count':len(onloads),'address_xref_count':len(refs),'vtable_offset_load_count':len(loads),'possible_register_natives_load_count':sum(l['offset']=='0x6b8' for l in loads)})
    (output/'static-bindings-summary.json').write_text(json.dumps(summary,indent=2),encoding='utf8')
    print(json.dumps(summary))


def build_bindings(native_dir,output,header,dex_catalog):
    abi=jni_header_evidence(header)
    (output/'jni-header-evidence.json').write_text(json.dumps(abi,indent=2),encoding='utf8')
    dex=json.loads(dex_catalog.read_text(encoding='utf8'))
    native_decls={d['name'] for d in dex['methods'] if d['native']}
    flows=[];bindings=[];inputs=[]
    def save_flow(library,label,flow,env_scope,caller=None):
        flow.update(library=library,label=label,jni_env_provenance_scope=env_scope,caller=caller)
        flows.append(flow)
        for registration in flow['registrations']:
            if not registration['proven_static_arguments']:continue
            for triple in registration['triplets']:
                descriptor='L'+registration['class_name']+';->'+triple['name']+triple['signature']
                bindings.append({'library':library,'registration_entry':flow['entry'],'register_natives_call':registration['pc'],
                                 'class':registration['class_name'],'name':triple['name'],'signature':triple['signature'],
                                 'function_address':triple['function_address'],'dex_descriptor':descriptor,
                                 'matches_dex_native_declaration':descriptor in native_decls,
                                 'jni_env_provenance_scope':env_scope,'runtime_success_proven':False})
    for name in ('libmain.so','libpdaprotect.so','libunity.so'):
        data=(native_dir/name).read_bytes();elf=ELF(data)
        inputs.append({'library':name,'sha256':hashlib.sha256(data).hexdigest(),'size':len(data)})
        if name=='libmain.so':
            flow=symbolic_registration(elf,0x96c,144,False)
            save_flow(name,'JNI_OnLoad',flow,'JavaVM.AttachCurrentThread output in local stack slot')
        elif name=='libpdaprotect.so':
            on=symbolic_registration(elf,0x2555c,652,False,{0x255a0:True})
            save_flow(name,'JNI_OnLoad GetEnv success path',on,'JavaVM.GetEnv output, conditional success path')
            sites=[c for c in on['calls'] if c.get('operation')=='direct_call' and c.get('target')=='0x25f74' and c['args'][0]==('env',)]
            if len(sites)!=1:raise ValueError('Expected one proven JNIEnv argument to pdaprotect registration helper')
            flow=symbolic_registration(elf,0x25f74)
            save_flow(name,'bulk registration helper',flow,'caller JNI_OnLoad passes GetEnv output',sites[0]['pc'])
        else:
            on=symbolic_registration(elf,0x2f1b20,156,False)
            save_flow(name,'JNI_OnLoad',on,'JavaVM.AttachCurrentThread output in local stack slot')
            for call in on['calls']:
                if call.get('operation')=='direct_call' and call['args'][0]==('env',):
                    flow=symbolic_registration(elf,int(call['target'],16))
                    save_flow(name,'JNI_OnLoad registration helper',flow,'caller JNI_OnLoad passes AttachCurrentThread output',call['pc'])
            memory={int(k,16):tuple(v) for k,v in on['global_memory_state'].items()}
            flow=symbolic_registration(elf,0x80de30,0x300,False,{0x80de70:True},memory)
            save_flow(name,'FMOD init registration',flow,'VM global written by JNI_OnLoad; GetEnv non-detached success hypothesis')
            caller=symbolic_registration(elf,0x346f50,0x34,False,initial_memory=memory,
                                        inline_calls={0x2e1b6c:{'limit':0x68,'branch_choices':{0x2e1ba4:True}}})
            save_flow(name,'ReflectionHelper wrapper caller',caller,'VM global; wrapper GetEnv success hypothesis')
            links=[c for c in caller['calls'] if c.get('target')=='0x346f84' and c['args'][0]==('env',)]
            if len(links)!=1:raise ValueError('ReflectionHelper wrapper did not produce a verified JNIEnv output path')
            flow=symbolic_registration(elf,0x346f84)
            save_flow(name,'ReflectionHelper registration helper',flow,'VM global; wrapper GetEnv success hypothesis',links[0]['pc'])
    exact={b['dex_descriptor'] for b in bindings if b['matches_dex_native_declaration']}
    contract_only={b['dex_descriptor'] for b in bindings if 'contract only' in b['jni_env_provenance_scope']}
    summary={'input_libraries':inputs,'dex_native_declarations':len(native_decls),
             'registration_sites_with_complete_static_class_table_count':sum(f['proven_static_registration_count'] for f in flows),
             'static_binding_rows':len(bindings),'distinct_dex_native_declarations_bound_under_recorded_contracts':len(exact),
             'declarations_with_onload_or_vm_global_provenance':len(exact-contract_only),
             'declarations_with_entry_jnienv_contract_only':len(contract_only),
             'unresolved_dex_native_declarations':len(native_decls-exact),
             'non_dex_native_rows':sum(not b['matches_dex_native_declaration'] for b in bindings),
             'bindings_by_library':dict(Counter(b['library'] for b in bindings)),
             'runtime_registration_proven':False}
    result={'summary':summary,'jni_abi':abi,'flows':flows,'bindings':bindings,
            'unresolved_dex_native_declarations':sorted(native_decls-exact),
            'limitations':['Static symbolic call arguments do not establish runtime success or method execution.',
                'Only selected forward paths are analyzed; alternate branches, exception/ThrowNew fallbacks and backward loops remain untraversed.',
                'Unknown instructions invalidate a possible destination register; this is a partial ARM64 decoder, not a whole-program verifier.',
                'External calls clobber caller-saved registers; their arbitrary memory effects are not globally modeled.',
                'memcpy effects are modeled only after resolving the imported function via ELF relocation and PLT instructions.',
                'ReflectionHelper wrapper is analyzed on a selected successful GetEnv non-detached path; attach fallback is separately documented but not traversed.',
                'FMOD assumes a successful GetEnv along the selected non-detached branch; failure and attach fallback are not runtime-validated.']}
    (output/'static-registration-bindings.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf8')
    (output/'static-registration-summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf8')
    audit_remaining(native_dir,output,result['unresolved_dex_native_declarations'])
    return result


def audit_remaining(native_dir,output,unresolved):
    """Static path/byte-presence evidence for the remaining native declarations."""
    libraries={p.name:p.read_bytes() for p in native_dir.glob('*.so')}
    string_evidence=[]
    for descriptor in unresolved:
        cls,rest=descriptor[1:].split(';->',1);name,sig=rest.split('(',1);sig='('+sig
        item={'dex_descriptor':descriptor,'libraries':[]}
        for library,data in libraries.items():
            observed={}
            for label,text in (('class_slash',cls),('class_dot',cls.replace('/','.')),('name',name),('signature',sig)):
                needle=text.encode('ascii')+b'\0';start=0;offsets=[]
                while True:
                    start=data.find(needle,start)
                    if start<0:break
                    offsets.append(hex(start));start+=1
                observed[label]={'occurrence_count':len(offsets),'first_32_file_offsets':offsets[:32]}
            if any(v['occurrence_count'] for v in observed.values()):item['libraries'].append({'library':library,**observed})
        string_evidence.append(item)
    elf=ELF(libraries['libexternal_wrapper.so']);resolve_local_abs64(elf)
    onload=symbolic_registration(elf,0x8a83c,164,False,{0x8a8a0:True})
    helper_specs=[(0x89400,0xb08),(0x89f08,0x2ec),(0x8a1f4,0x384),(0x8a578,0x2c4)]
    flows=[]
    for start,size in helper_specs:
        flow=symbolic_registration(elf,start,size)
        flow['instructions']=disassemble(elf,start,size)
        flows.append(flow)
    summary={'still_unresolved_dex_declarations':len(unresolved),
             'external_wrapper_registration_calls_with_jni_env_base':sum(len(f['registrations']) for f in flows),
             'external_wrapper_total_requested_methods':sum(c['count'] or 0 for f in flows for c in f['registrations']),
             'external_wrapper_fully_resolved_class_table_bindings':sum(f['proven_static_registration_count'] for f in flows),
             'reflection_wrapper_entry_contract_remaining':False,
             'runtime_registration_proven':False}
    result={'summary':summary,'external_wrapper_onload_flow':onload,'external_wrapper_helper_flows':flows,'string_presence':string_evidence,
            'external_wrapper_observed_string_transform_instruction_windows':[
                {'entry':'0x8943c','instructions':disassemble(elf,0x8943c,0x40)},
                {'entry':'0x89a10','instructions':disassemble(elf,0x89a10,0x60)},
                {'entry':'0x8b418','instructions':disassemble(elf,0x8b418,0x4c)}],
            'limitations':['Null-terminated exact byte occurrence does not prove a string is a JNI binding.',
                'external_wrapper has guard-controlled global/stack string construction and scalar/SIMD transforms that this bounded decoder does not model.',
                'Counts6+1+1+1 do not independently identify the methods or class names.',
                'JNI bridge and task-callback declarations can require runtime/generated/external registration; absence from static plaintext does not prove they are unused.']}
    bridge_elf=ELF(libraries['libunity.so']);resolve_local_abs64(bridge_elf)
    code=disassemble(bridge_elf,0x7a8790,0xf0)
    name_values={};stack_bytes={}
    for ins in code:
        op=ins['op']
        if op=='movz':name_values[ins['rd']]=ins['imm']<<ins['shift']
        elif op=='movk' and ins['rd'] in name_values:
            name_values[ins['rd']]=(name_values[ins['rd']]&~(65535<<ins['shift']))|(ins['imm']<<ins['shift'])
        elif op=='str' and ins['rn']==31 and ins['rt'] in name_values and ins['size']==4:
            for i,b in enumerate(struct.pack('<I',name_values[ins['rt']]&0xffffffff)):stack_bytes[ins['imm']+i]=b
    name=bytes(stack_bytes[i] for i in range(24,31))
    sig='(JLjava/lang/Class;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;'
    sig_va=bridge_elf.va(bridge_elf.data.index(sig.encode()+b'\0'))
    signature_bytes=bridge_elf.data[bridge_elf.file_offset(sig_va):bridge_elf.file_offset(sig_va)+80]+bytes(stack_bytes[i] for i in range(144,148))
    if name!=b'invoke\0' or signature_bytes.split(b'\0')[0].decode()!=sig:raise ValueError('JNIBridge stack literal reconstruction mismatch')
    fn=bridge_elf.pointer(12087296+1352)
    if not bridge_elf.executable(fn):raise ValueError('JNIBridge pointer is not executable')
    result['jni_bridge_stack_table_evidence']={'registration_function_entry':'0x7a8790','register_natives_call':'0x7a8854',
         'wrapper_class_string_va':'0x9d2d8d','wrapper_class_string':'bitter/jnibridge/JNIBridge',
         'name_constructed_from_overlapping_immediate_stores':name[:-1].decode(),'signature_constructed_from_simd_copy_and_tail_store':sig,
         'function_address':hex(fn),'count':1,'table_stack_offset':0,'name_stack_offset':24,'signature_stack_offset':64,
         'class_wrapper_constructor':'0x7a60e4','class_accessor':'0x78820c','env_getter':'0x7a6ac4',
         'env_getter_instructions':disassemble(bridge_elf,0x7a6ac4,0x38),'instructions':code,
         'triplet_values_reconstructed':True,'complete_class_wrapper_provenance':False,'runtime_registration_proven':False}
    (output/'remaining-native-audit.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf8')


if __name__=='__main__':main()
