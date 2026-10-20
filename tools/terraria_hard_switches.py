"""Recover conditional ARM64 switch-table candidates from original ELF bytes.

Only straight-line guarded unsigned byte/halfword tables are accepted. No DB
mutation, runtime execution, semantic equivalence or whole-CFG claim is made.
"""
import argparse, collections, hashlib, json, pathlib, struct, sys

from terraria_flow_islands import Elf

ELF_SHA = '9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'


def canon(name):
    return 'x'+name[1:] if name.startswith('w') else name


def recover(code, pos, elf, start, end):
    from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM, ARM64_SFT_LSL
    window = code[max(0,pos-24):pos+1]
    definitions=[]
    def reg(ins, operand): return canon(ins.reg_name(operand.reg))
    def writes(ins): return {canon(ins.reg_name(r)) for r in ins.regs_access()[1]}
    def definition(name, before):
        return next((j for j in range(before-1,-1,-1) if name in writes(window[j])), None)
    def constant(name, before):
        j=definition(name,before)
        if j is None: raise ValueError('base_definition_outside_window')
        definitions.append(j)
        ins=window[j]; op=ins.operands
        if ins.mnemonic in ('adr','adrp') and len(op)==2 and op[1].type==ARM64_OP_IMM:
            return op[1].imm
        if ins.mnemonic=='add' and len(op)==3 and op[1].type==ARM64_OP_REG and op[2].type==ARM64_OP_IMM and not op[2].shift.value:
            return constant(reg(ins,op[1]),j)+op[2].imm
        raise ValueError('unsupported_constant_definition')
    final=window[-1]
    dest=reg(final,final.operands[0]); addpos=definition(dest,len(window)-1)
    if addpos is None: raise ValueError('no_target_definition')
    add=window[addpos]; op=add.operands
    if add.mnemonic!='add' or len(op)!=3 or any(x.type!=ARM64_OP_REG for x in op) or op[2].shift.value!=2 or op[2].shift.type!=ARM64_SFT_LSL or op[2].ext:
        raise ValueError('not_scaled_relative_table')
    anchor=constant(reg(add,op[1]),addpos)
    offsetreg=reg(add,op[2]); loadpos=definition(offsetreg,addpos)
    if loadpos is None: raise ValueError('no_load_definition')
    load=window[loadpos]; lop=load.operands
    if load.mnemonic not in ('ldrb','ldrh') or len(lop)!=2 or lop[1].type!=ARM64_OP_MEM:
        raise ValueError('unsupported_table_load')
    width={'ldrb':1,'ldrh':2}[load.mnemonic]; mem=lop[1].mem
    if not mem.index or mem.disp or lop[1].shift.value!={1:0,2:1}[width] or lop[1].ext:
        raise ValueError('unsupported_index_expression')
    index=canon(load.reg_name(mem.index)); table=constant(canon(load.reg_name(mem.base)),loadpos)
    guardpos=next((j for j in range(loadpos-1,-1,-1) if window[j].mnemonic.startswith('b.')),None)
    if guardpos is None or window[guardpos].mnemonic!='b.hi': raise ValueError('no_unsigned_upper_guard')
    cmppos=next((j for j in range(guardpos-1,-1,-1) if 'nzcv' in writes(window[j])),None)
    if cmppos is None: raise ValueError('no_compare')
    cmp=window[cmppos]; cop=cmp.operands
    if cmp.mnemonic!='cmp' or len(cop)!=2 or cop[0].type!=ARM64_OP_REG or cop[1].type!=ARM64_OP_IMM or reg(cmp,cop[0])!=index:
        raise ValueError('guard_index_not_direct_cmp')
    if cop[1].shift.value or not cmp.reg_name(cop[0].reg).startswith('w'):
        raise ValueError('unsupported_compare_width_or_shift')
    count=cop[1].imm+1
    if not 1<=count<=4096: raise ValueError('table_size_outside_bound')
    evidence_start=min([cmppos]+definitions)
    for j in range(evidence_start,len(window)-1):
        ins=window[j]
        if j>cmppos and index in writes(ins): raise ValueError('index_changed_after_compare')
        if j!=guardpos and (ins.mnemonic.startswith('b') or ins.mnemonic in ('ret','eret','svc')):
            raise ValueError('nonlinear_candidate_path')
    matches=[(va,off,flags) for va,limit,off,flags in elf.segments if va<=table and table+count*width<=limit]
    if len(matches)!=1 or matches[0][2]&2: raise ValueError('table_not_unique_readonly_file_bytes')
    va,off,flags=matches[0]; raw=elf.raw[off+table-va:off+table-va+count*width]
    values=[int.from_bytes(raw[i:i+width],'little') for i in range(0,len(raw),width)]
    targets=[anchor+v*4 for v in values]
    if any(t%4 or not start<=t<end for t in targets): raise ValueError('target_outside_origin_fde')
    # Validate executable file-backed bytes for every target independently.
    entries=[{'index':i,'encoded_offset':v,'target':hex(t),'target_raw_bytes':struct.pack('<I',elf.word(t)).hex()} for i,(v,t) in enumerate(zip(values,targets))]
    return {'branch':hex(final.address),'index_register':index,'guard_compare':hex(cmp.address),'guard_branch':hex(window[guardpos].address),
            'default_target':hex(window[guardpos].operands[0].imm),'table':hex(table),'width':width,'count':count,'anchor':hex(anchor),
            'table_raw_bytes':raw.hex(),'table_sha256':hashlib.sha256(raw).hexdigest(),'entries':entries,
            'straight_line_evidence':[{'address':hex(x.address),'raw_bytes':bytes(x.bytes).hex(),'instruction':x.mnemonic+' '+x.op_str} for x in window[evidence_start:]],
            'preconditions':['execution follows entire recorded straight-line evidence, including constant definitions, compare and guard fallthrough, to BR without alternate entry', '64-bit table index equals the compared unsigned 32-bit value: upper 32 bits are zero', 'original read-only table bytes remain unchanged'],
            'runtime_reachability_proven':False,'all_incoming_paths_proven':False}


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);ap.add_argument('--out',type=pathlib.Path,required=True);a=ap.parse_args()
    sys.path.insert(0,str(a.lab/'python-analysis'))
    import capstone
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
    elf=Elf(a.lab/'native/libil2cpp.so')
    if hashlib.sha256(elf.raw).hexdigest()!=ELF_SHA: raise ValueError('Wrong original ELF')
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    names=collections.defaultdict(set)
    for name in ('method-addresses.json','generic-method-addresses.json'):
        for r in json.loads((a.lab/'native'/name).read_text()):
            if r.get('address'): names[int(r['address'],16)].add(r['type']+'::'+r['name'])
    rows=[json.loads(x) for x in (a.lab/'hard-functions-raw-ir/results.jsonl').read_text().splitlines()]
    methods=[];reasons=collections.Counter()
    for row in rows:
        if row['address'] in ('0x1448f04','0xef9bdc'):continue
        start=int(row['address'],16);end=int(row['compiler_end_exclusive'],16)
        code=list(cs.disasm(elf.raw[elf.at(start):elf.at(end-4)+4],start))
        if len(code)*4!=end-start:raise ValueError('Incomplete disassembly')
        found=[];unresolved=[]
        for pos,ins in enumerate(code):
            if ins.mnemonic!='br':continue
            try: found.append(recover(code,pos,elf,start,end))
            except ValueError as ex: reasons[str(ex)]+=1;unresolved.append({'branch':hex(ins.address),'reason':str(ex)})
        by_address={x.address:x for x in code}
        for table in found:
            snippets=[]
            for target in sorted({int(e['target'],16) for e in table['entries']}):
                pc=target;seen=set();evidence=[];calls=[];stop='instruction_budget'
                for step in range(64):
                    if pc in seen:stop='cycle';break
                    seen.add(pc);ins=by_address.get(pc)
                    if ins is None:stop='outside_origin_fde';break
                    evidence.append({'address':hex(pc),'raw_bytes':bytes(ins.bytes).hex(),'instruction':ins.mnemonic+' '+ins.op_str})
                    if ins.mnemonic=='bl':
                        dst=ins.operands[0].imm;calls.append({'site':hex(pc),'target':hex(dst),'managed_names':sorted(names.get(dst,[]))})
                        stop='first_direct_call';break
                    if ins.mnemonic=='b':pc=ins.operands[0].imm;continue
                    if ins.mnemonic.startswith('b.') or ins.mnemonic in ('cbz','cbnz','tbz','tbnz','br','blr','ret','eret','svc'):
                        stop='control_flow_boundary';break
                    pc+=4
                snippets.append({'target':hex(target),'instructions':evidence,'first_direct_calls':calls,'stop':stop,'runtime_executed':False})
            table['destination_previews']=snippets
        methods.append({'method':row['method'],'address':row['address'],'end_exclusive':hex(end),'switch_candidates':found,'unresolved_BR':unresolved})
    result={'profile':'hard18-guarded-relative-switches-v1','elf_sha256':ELF_SHA,'capstone_version':capstone.__version__,
            'producer_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'methods':methods,
            'summary':{'methods':len(methods),'tables':sum(len(m['switch_candidates']) for m in methods),'entries':sum(t['count'] for m in methods for t in m['switch_candidates']),
            'unresolved_BR':sum(len(m['unresolved_BR']) for m in methods),'rejection_reasons':dict(reasons)},
            'complete_semantic_CFG_proven':False,'valid_C':False,'database_modified':False}
    a.out.mkdir(parents=True,exist_ok=True)
    (a.out/'switches.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf8')
    lines=['# Таблицы переходов оставшихся 18 методов','', 'Условный статический разбор исходных ARM64-байтов. Полный C и достижимость ветвей не доказаны. Предпосылки: исполнение всей записанной последовательности без альтернативного входа, неизменные байты таблицы, нулевые старшие 32 бита индексного регистра X. CMP W сам по себе не обнуляет X. Индекс — значение регистра после возможного преобразования исходного ID; это не обязательно ID предмета/NPC.','', '| Метод / адрес | Таблиц | Записей | Неразрешённых BR |','|---|---:|---:|---:|']
    for m in methods:
        lines.append(f"| {m['method']} / {m['address']} | {len(m['switch_candidates'])} | {sum(t['count'] for t in m['switch_candidates'])} | {len(m['unresolved_BR'])} |")
        detail=[f"# {m['method']} ({m['address']})",'','Предпосылки для каждой таблицы: исполнение всей записанной последовательности без альтернативного входа; неизменные байты таблицы; нулевые старшие 32 бита X-индекса. CMP W сам по себе не обнуляет X. Альтернативные входы не исключены.','']
        for t in m['switch_candidates']:
            detail += [f"## BR {t['branch']}: {t['count']} записей",f"Индекс {t['index_register']}; table {t['table']}; anchor {t['anchor']}; default {t['default_target']}",'','| Индекс | Цель |','|---:|---|']
            detail += [f"| {e['index']} | {e['target']} |" for e in t['entries']]
            detail.append('')
            for preview in t['destination_previews']:
                for call in preview['first_direct_calls']:
                    labels=' / '.join(call['managed_names']) or call['target']
                    detail.append(f"От {preview['target']} первый прямой вызов до условного перехода: {labels} ({call['site']}). Статический путь, исполнение не проверено.")
            detail.append('')
        (a.out/(m['address']+'.md')).write_text('\n'.join(detail),encoding='utf8')
    lines += ['', 'Полные записи, байты таблиц, инструкции guards и ограничения: [switches.json](switches.json).']
    (a.out/'README.ru.md').write_text('\n'.join(lines),encoding='utf8')
    print(json.dumps(result['summary']))


if __name__=='__main__':main()
