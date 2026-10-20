"""Describe strict, short straight-line behaviors of previously unnamed FDEs.

Structural behavior is distinct from game/runtime purpose. No inferred function
prototype, reachability, object type or original source name is claimed.
"""
import argparse, collections, hashlib, json, pathlib, struct, sys
from terraria_flow_islands import Elf
from terraria_native_map import ELF

ELF_SHA='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def describe(code):
    from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM, ARM64_SFT_LSL
    if not code or len(code)>16:return None
    final=code[-1]
    if final.mnemonic not in ('b','br','ret'):return None
    if final.mnemonic=='ret' and final.op_str not in ('','x30'):return None
    regs={f'x{i}':{'kind':'input_register','register':f'x{i}'} for i in range(31)}
    effects=[]
    def reg(ins,op):return ins.reg_name(op.reg)
    def canonical(name):return 'x'+name[1:] if name.startswith('w') else name
    def read(name):
        if name in ('wzr','xzr'):value={'kind':'constant','value':0}
        elif canonical(name) in regs:value=regs[canonical(name)]
        else:raise ValueError('unsupported_register')
        return {'kind':'low32','value':value} if name.startswith('w') and name!='wzr' else value
    def write(name,value):
        if name in ('wzr','xzr'):return
        if canonical(name) not in regs:raise ValueError('unsupported_destination')
        regs[canonical(name)]={'kind':'zero_extend32','value':value} if name.startswith('w') else {'kind':'low64','value':value}
    try:
        for ins in code[:-1]:
            op=ins.operands;mn=ins.mnemonic
            if ins.update_flags: return None
            if mn=='nop':continue
            if mn in ('adr','adrp') and len(op)==2 and op[1].type==ARM64_OP_IMM:
                write(reg(ins,op[0]),{'kind':'constant','value':op[1].imm})
            elif mn=='mov' and len(op)==2 and op[0].type==ARM64_OP_REG:
                value=read(reg(ins,op[1])) if op[1].type==ARM64_OP_REG else {'kind':'constant','value':op[1].imm} if op[1].type==ARM64_OP_IMM else None
                if value is None:return None
                write(reg(ins,op[0]),value)
            elif mn in ('add','sub','and') and len(op)==3 and op[1].type==ARM64_OP_REG and op[2].type==ARM64_OP_IMM and not op[2].shift.value:
                write(reg(ins,op[0]),{'kind':mn,'lhs':read(reg(ins,op[1])),'rhs':op[2].imm})
            elif mn=='add' and len(op)==3 and all(x.type==ARM64_OP_REG for x in op) and op[2].shift.type==ARM64_SFT_LSL and 0<=op[2].shift.value<=63 and not op[2].ext:
                write(reg(ins,op[0]),{'kind':'scaled_add','lhs':read(reg(ins,op[1])),'rhs':read(reg(ins,op[2])),'shift':op[2].shift.value})
            elif mn=='ldp' and len(op)==3 and op[0].type==ARM64_OP_REG and op[1].type==ARM64_OP_REG and op[2].type==ARM64_OP_MEM:
                mem=op[2].mem
                if ins.writeback or mem.index or op[2].ext or op[2].shift.value:return None
                n0,n1=reg(ins,op[0]),reg(ins,op[1])
                if n0[0] not in ('x','w') or n0[0]!=n1[0] or n0==n1:return None
                size=8 if n0[0]=='x' else 4;base=read(ins.reg_name(mem.base))
                for index,name in enumerate((n0,n1)):
                    value={'kind':'memory_load','base':base,'offset':mem.disp+index*size,'address_bits':64,'bytes':size,'signed':False,'result_bits':size*8}
                    effects.append({'address':hex(ins.address),'memory_read':value});write(name,value)
            elif mn in ('ldr','ldrb','ldrh','ldrsb','ldrsh','ldrsw') and len(op)==2 and op[0].type==ARM64_OP_REG and op[1].type==ARM64_OP_MEM:
                mem=op[1].mem
                if ins.writeback or mem.index or op[1].ext or op[1].shift.value:return None
                name=reg(ins,op[0])
                if name[0] not in ('x','w'):return None
                size={'ldrb':1,'ldrh':2,'ldrsb':1,'ldrsh':2,'ldrsw':4}.get(mn,8 if name.startswith('x') else 4)
                value={'kind':'memory_load','base':read(ins.reg_name(mem.base)),'offset':mem.disp,'address_bits':64,'bytes':size,'signed':mn in ('ldrsb','ldrsh','ldrsw'),'result_bits':64 if name.startswith('x') else 32}
                effects.append({'address':hex(ins.address),'memory_read':value})
                write(name,value)
            else:return None
        if final.mnemonic=='ret':
            behavior='straight_line_return'
            transfer={'kind':'return','address_register':'x30','entry_x30_preserved':regs['x30']=={'kind':'input_register','register':'x30'},'x0_expression':regs['x0']}
            # A RET after writing LR is not an ordinary return description.
            if not transfer['entry_x30_preserved']:return None
        elif final.mnemonic=='b':
            behavior='direct_branch_forwarder';transfer={'kind':'direct_branch','target':hex(final.operands[0].imm)}
        else:
            behavior='indirect_branch_forwarder';transfer={'kind':'indirect_branch','target_expression':read(reg(final,final.operands[0]))}
        changed={name:value for name,value in regs.items() if value!={'kind':'input_register','register':name}}
        return {'structural_behavior':behavior,'transfer':transfer,'register_changes':changed,'ordered_memory_reads':effects,
                'conditions':['function entered at recorded FDE start and all loads complete successfully','original instruction bytes unchanged'],
                'writes_memory':False,'contains_calls_or_conditional_branches':False,'game_or_runtime_role':'unknown','runtime_observed':False,'function_prototype_recovered':False}
    except (ValueError,KeyError):return None


def plt_imports(raw):
    """Original relocation + dynsym binding, not a claim about runtime interposition."""
    elf=ELF(raw);plt=next(s for s in elf.sections if s['name']=='.plt');bindings={};evidence=[]
    relocations={}
    for section in elf.sections:
        if section['name']!='.rela.plt':continue
        symbols=elf.sections[section['link']];strings=elf.sections[symbols['link']]
        pool=raw[strings['offset']:strings['offset']+strings['size']]
        for p in range(section['offset'],section['offset']+section['size'],section['entsize']):
            slot,info,addend=struct.unpack_from('<QQq',raw,p)
            if info&0xffffffff!=1026:raise ValueError('Unexpected PLT relocation')
            symbol=symbols['offset']+(info>>32)*symbols['entsize'];n,attrs,other,defined,value,size=struct.unpack_from('<IBBHQQ',raw,symbol)
            name=pool[n:pool.index(b'\0',n)].decode('utf8');relocations[slot]=(name,p,info>>32,defined,value,addend)
    for va in range(plt['vaddr']+32,plt['vaddr']+plt['size'],16):
        off=elf.file_offset(va);a,b,c,d=struct.unpack_from('<IIII',raw,off)
        if a&0x9f00001f!=0x90000010 or b&0xffc003ff!=0xf9400211 or c&0xffc003ff!=0x91000210 or d!=0xd61f0220:raise ValueError('Unsupported PLT stub')
        imm=((a>>29)&3)|(((a>>5)&0x7ffff)<<2)
        if imm&(1<<20):imm-=1<<21
        page=(va&~4095)+(imm<<12);slot=page+((b>>10)&4095)*8
        if page+((c>>10)&4095)!=slot or slot not in relocations:raise ValueError('PLT/GOT mismatch')
        name,r,sym,defined,value,addend=relocations[slot];bindings[va]=name
        evidence.append({'address':hex(va),'got_slot':hex(slot),'relocation_file_offset':hex(r),'dynsym_index':sym,'symbol_name':name,
                         'symbol_defined':bool(defined),'symbol_value':hex(value),'relocation_addend':addend,'raw_bytes':raw[off:off+16].hex()})
    if len(bindings)!=len(relocations):raise ValueError('PLT coverage mismatch')
    return bindings,evidence


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);a=ap.parse_args()
    sys.path.insert(0,str(a.lab/'python-analysis'))
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
    elf=Elf(a.lab/'native/libil2cpp.so');cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    if hashlib.sha256(elf.raw).hexdigest()!=ELF_SHA:raise ValueError('Wrong original ELF')
    prior=a.lab/'unknown-native-behaviors-v1/behaviors.json';old=json.loads(prior.read_text());remaining=set(old['unclassified_addresses'])
    catalog=json.loads((a.lab/'native/unmapped-fde-classification.json').read_text());found=[];unclassified=[];rejects=collections.Counter()
    for row in catalog:
        if row['address'] not in remaining:continue
        start=int(row['address'],16);end=int(row['end_exclusive'],16)
        if end-start>128:unclassified.append(row['address']);continue
        raw=elf.raw[elf.at(start):elf.at(end-4)+4];code=list(cs.disasm(raw,start))
        if len(code)*4!=len(raw):raise ValueError('Incomplete decode')
        # Exact prologue/epilogue encodings avoid hidden SP or LR mutations.
        if len(code)<6 or int.from_bytes(code[0].bytes,'little')!=0xf81f0ffe or code[1].mnemonic!='cbz' or code[1].op_str.split(',')[0]!='x1':
            unclassified.append(row['address']);continue
        if int.from_bytes(code[-3].bytes,'little')!=0xf84107fe or code[-2].mnemonic not in ('br','b','ret') or code[-1].mnemonic!='bl' or code[1].operands[1].imm!=code[-1].address:
            rejects['suffix_or_guard_target']+=1;unclassified.append(row['address']);continue
        body=code[2:-3]+[code[-2]];desc=describe(body)
        if desc is None or 'x30' in desc['register_changes']:
            rejects['unsupported_normal_path']+=1;unclassified.append(row['address']);continue
        found.append({'address':row['address'],'end_exclusive':row['end_exclusive'],'source_bytes_sha256':hashlib.sha256(raw).hexdigest(),
            'instructions':[{'address':hex(i.address),'raw_bytes':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str} for i in code],
            'guard':{'register':'x1','condition':'equals_zero','address':hex(code[1].address),'zero_target':hex(code[-1].address),'nonnull_target':hex(code[2].address)},
            'stack':{'entry_sp_delta_after_spill':-16,'saved_entry_x30_offset_from_entry_sp':-16,'nonnull_sp_delta_at_transfer':0,'nonnull_entry_x30_restored':True},
            'nonnull_path':desc,
            'zero_path':{'call_site':hex(code[-1].address),'direct_call_target':hex(code[-1].operands[0].imm),'sp_delta_at_call':-16,'link_register_after_call_instruction':hex(end),
                         'if_callee_returns_next_address':hex(end),'return_continuation_outside_recorded_fde':True,'callee_noreturn_proven':False},
            'conditions':['entry SP is valid for 16-byte spill and the spill does not alias any memory read by normal body','all normal-path loads complete successfully','execution begins at recorded FDE start'],
            'runtime_observed':False,'game_or_runtime_role':'unknown','valid_C':False})
    if len(found)+len(unclassified)!=len(remaining):raise ValueError('Incomplete partition')
    out=a.lab/'guarded-native-behaviors-v1';out.mkdir(exist_ok=True)
    doc={'profile':'unknown-native-nullguard-spill-tail-transfer-v1','elf_sha256':ELF_SHA,'prior_behavior_sha256':sha(prior),'producer_sha256':sha(pathlib.Path(__file__)),
         'prior_remaining':len(remaining),'new_descriptions':len(found),'remaining':len(unclassified),'cumulative_descriptions':old['structurally_described']+len(found),
         'semantic_role_still_unknown':8140,'results':found,'unclassified_addresses':unclassified,'rejection_reasons':dict(rejects),'baseline_modified':False}
    (out/'behaviors.json').write_text(json.dumps(doc,ensure_ascii=False,indent=2),encoding='utf8')
    print(json.dumps({k:v for k,v in doc.items() if k not in ('results','unclassified_addresses')}))


if __name__=='__main__':main()
