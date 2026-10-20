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
    from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM
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
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);ap.add_argument('--out',type=pathlib.Path,required=True);a=ap.parse_args()
    sys.path.insert(0,str(a.lab/'python-analysis'))
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
    elf=Elf(a.lab/'native/libil2cpp.so')
    if hashlib.sha256(elf.raw).hexdigest()!=ELF_SHA:raise ValueError('Source ELF identity mismatch')
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    catalog_path=a.lab/'native/unmapped-fde-classification.json';catalog=json.loads(catalog_path.read_text())
    unknown=[x for x in catalog if x['category']=='unknown']
    if len(unknown)!=8140:raise ValueError('Unexpected unknown scope')
    all_ranges={int(x.split('\t')[0],16):int(x.split('\t')[1],16) for x in (a.lab/'native/unwind-function-ranges.tsv').read_text().splitlines()}
    imports,import_evidence=plt_imports(elf.raw)
    names=collections.defaultdict(set);input_hashes={'libil2cpp.so':ELF_SHA,'unmapped-fde-classification.json':sha(catalog_path)}
    for filename in ('method-addresses.json','generic-method-addresses.json','elf-symbols.json'):
        p=a.lab/'native'/filename;input_hashes[filename]=sha(p)
        for r in json.loads(p.read_text()):
            if not r.get('address') or r['address']=='0x0':continue
            if filename=='elf-symbols.json':
                if r['defined']:names[int(r['address'],16)].add(r['name'])
            else:names[int(r['address'],16)].add(r['type']+'::'+r['name'])
    results=[];unclassified=[]
    for row in unknown:
        start=int(row['address'],16);end=int(row['end_exclusive'],16)
        if row['size']>64:unclassified.append(row['address']);continue
        raw=elf.raw[elf.at(start):elf.at(end-4)+4];code=list(cs.disasm(raw,start))
        if len(code)*4!=len(raw):raise ValueError('Incomplete ARM64 decode')
        desc=describe(code)
        if desc is None:unclassified.append(row['address']);continue
        if desc['structural_behavior']=='direct_branch_forwarder':
            target=int(desc['transfer']['target'],16)
            # A B into the same FDE is a loop, not a forwarding wrapper.
            if start<=target<end or (target not in all_ranges and target not in imports):unclassified.append(row['address']);continue
            desc['transfer']['target_names']=sorted(names.get(target,[]));desc['transfer']['target_is_exact_fde_start']=target in all_ranges
            chain=[];seen=set();endpoint=target
            while endpoint in all_ranges and not names.get(endpoint) and endpoint not in imports and len(chain)<16:
                if endpoint in seen:break
                seen.add(endpoint)
                if all_ranges[endpoint]-endpoint!=4:break
                word=elf.word(endpoint)
                if word&0xfc000000!=0x14000000:break
                imm=word&0x3ffffff
                if imm&(1<<25):imm-=1<<26
                next_target=endpoint+imm*4
                chain.append({'address':hex(endpoint),'raw_bytes':word.to_bytes(4,'little').hex(),'target':hex(next_target)})
                endpoint=next_target
            desc['transfer']['pure_B_chain']=chain
            desc['transfer']['endpoint']={'address':hex(endpoint),'managed_or_elf_names':sorted(names.get(endpoint,[])),
                                         'plt_relocation_symbol_name':imports.get(endpoint),'runtime_binding_verified':False}
        results.append({'address':row['address'],'end_exclusive':row['end_exclusive'],'source_bytes_sha256':hashlib.sha256(raw).hexdigest(),
                        'instructions':[{'address':hex(i.address),'raw_bytes':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str} for i in code],**desc})
    counts=collections.Counter(r['structural_behavior'] for r in results)
    doc={'profile':'unknown8140-short-straight-line-behaviors-v1','inputs':input_hashes,'producer_sha256':sha(pathlib.Path(__file__)),
         'scope_unknown_FDEs':8140,'short_function_limit_bytes':64,'structurally_described':len(results),'structurally_unclassified':len(unclassified),
         'semantic_role_still_unknown':8140,'behavior_counts':dict(counts),'results':results,'unclassified_addresses':unclassified,
         'verified_plt_stubs':import_evidence,
         'named_forwarding_endpoints':sum(r['structural_behavior']=='direct_branch_forwarder' and bool(r['transfer']['endpoint']['managed_or_elf_names'] or r['transfer']['endpoint']['plt_relocation_symbol_name']) for r in results),
         'complete_semantics_or_original_source_proven':False,'baseline_modified':False}
    a.out.mkdir(parents=True,exist_ok=True);(a.out/'behaviors.json').write_text(json.dumps(doc,ensure_ascii=False,indent=2),encoding='utf8')
    print(json.dumps({k:v for k,v in doc.items() if k not in ('results','unclassified_addresses','inputs','verified_plt_stubs')}))


if __name__=='__main__':main()
