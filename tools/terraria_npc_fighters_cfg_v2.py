"""Conditional intraprocedural CFG; raw ARM64 branches checked against Capstone."""
import collections,hashlib,json,pathlib,sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from terraria_flow_islands import Elf
sys.path.insert(0,'C:/Temp/terraria-re-20261012/python-analysis')
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN

LAB=pathlib.Path('C:/Temp/terraria-re-20261012')
def sha(data):return hashlib.sha256(data).hexdigest()
def signed(value,bits):return value-(1<<bits) if value&(1<<(bits-1)) else value
def normalized_writes(ins):
    # Capstone 5.0.7 reports spurious W destinations on flag-only aliases.
    if ins.mnemonic in ('cmp','cmn','tst','ccmp','ccmn','fcmp','fcmpe','fccmp','fccmpe'):
        return set()
    return {ins.reg_name(r) for r in ins.regs_access()[1]}
def raw_flow(word,address):
    if word&0x7c000000==0x14000000:
        return ('bl' if word&0x80000000 else 'b',[address+signed(word&0x3ffffff,26)*4])
    if word&0xff000010==0x54000000:return ('conditional',[address+signed((word>>5)&0x7ffff,19)*4])
    if word&0x7e000000==0x34000000:return ('conditional',[address+signed((word>>5)&0x7ffff,19)*4])
    if word&0x7e000000==0x36000000:return ('conditional',[address+signed((word>>5)&0x3fff,14)*4])
    if word&0xfffffc1f==0xd61f0000:return ('br',[])
    if word&0xfffffc1f==0xd63f0000:return ('blr',[])
    if word&0xfffffc1f==0xd65f0000:return ('ret',[])
    return ('ordinary',[])
def reachable(edges,start,blocked=None):
    seen=set();todo=[start]
    while todo:
        node=todo.pop()
        if node==blocked or node in seen:continue
        seen.add(node);todo.extend(edges[node])
    return seen
def main():
    elf=Elf(LAB/'native/libil2cpp.so');assert sha(elf.raw)=='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
    maps=LAB/'hard-switches-v2/switches.json';method=next(m for m in json.loads(maps.read_text())['methods'] if m['address']=='0x117a464')
    start,end=int(method['address'],16),int(method['end_exclusive'],16)
    switches={int(s['branch'],16):s for s in method['switch_candidates']}
    data=b''.join(elf.word(a).to_bytes(4,'little') for a in range(start,end,4));cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    instructions=list(cs.disasm(data,start));assert len(instructions)*4==len(data)
    # Known detached two-instruction continuation, verified afresh from ELF.
    island_bytes=b''.join(elf.word(a).to_bytes(4,'little') for a in (0x118d934,0x118d938))
    assert island_bytes.hex()=='a00240f9b4e1ff17'
    assert raw_flow(elf.word(0x118d938),0x118d938)==('b',[0x1186008])
    instructions+=list(cs.disasm(island_bytes,0x118d934))
    modeled_addresses={i.address for i in instructions}
    edges={};exits=[];calls=[];counts=collections.Counter();unresolved=[];checked=0
    for ins in instructions:
        address=ins.address;kind,targets=raw_flow(elf.word(address),address);counts[kind]+=1
        if kind in ('b','bl','conditional'):
            assert ins.mnemonic in ('b','bl','cbz','cbnz','tbz','tbnz') or ins.mnemonic.startswith('b.')
            assert int(ins.op_str.split(',')[-1].strip().removeprefix('#'),16)==targets[0];checked+=1
        elif kind in ('br','blr','ret'):assert ins.mnemonic==kind;checked+=1
        else:
            assert not (ins.mnemonic in ('b','bl','br','blr','ret','cbz','cbnz','tbz','tbnz','eret','drps','brk','hlt','svc','hvc','smc') or ins.mnemonic.startswith('b.')), (hex(address),ins.mnemonic)
        if kind=='br':
            if address in switches:targets=sorted({int(e['target'],16) for e in switches[address]['entries']})
            else:unresolved.append(hex(address))
        elif kind in ('bl','blr'):
            calls.append({'site':hex(address),'kind':kind,'target':hex(targets[0]) if targets else None});targets=[address+4]
        elif kind not in ('b','ret'):targets+=[address+4]
        local=[]
        for target in targets:
            if target in modeled_addresses:
                assert target%4==0;local.append(target)
            else:exits.append({'site':hex(address),'target':hex(target),'kind':kind})
        edges[address]=local
    assert not unresolved
    seen=reachable(edges,start);checks=[]
    predecessors={a:[] for a in edges}
    for a,targets in edges.items():
        for target in targets:predecessors[target].append(a)
    upper_zero={}
    for reg in ('8','9'):
        # Must-analysis: start at top then monotonically remove unsupported facts.
        incoming={a:True for a in edges};outgoing={a:True for a in edges}
        transfer={}
        for ins in instructions:
            writes=normalized_writes(ins)
            if ins.mnemonic in ('bl','blr'):transfer[ins.address]=False
            elif 'w'+reg in writes:transfer[ins.address]=True
            elif 'x'+reg in writes:transfer[ins.address]=False
            else:transfer[ins.address]=None
        todo=collections.deque(edges);pending=set(edges)
        while todo:
            a=todo.popleft();pending.remove(a)
            value=a!=start and bool(predecessors[a]) and all(outgoing[p] for p in predecessors[a])
            incoming[a]=value;new=value if transfer[a] is None else transfer[a]
            if outgoing[a]!=new:
                outgoing[a]=new
                for target in edges[a]:
                    if target not in pending:todo.append(target);pending.add(target)
        upper_zero[reg]=incoming
    for br,s in switches.items():
        proof=[]
        for point in ('guard_compare','guard_branch'):
            guard=int(s[point],16);without=reachable(edges,start,guard)
            proof.append({'point':point,'address':hex(guard),'reachable_from_entry':guard in seen,'dominates_BR_in_model':br in seen and br not in without,'reachable_nodes_with_point_removed':len(without)})
        register=s['index_register'].removeprefix('x')
        checks.append({'branch':hex(br),'reachable_from_entry':br in seen,'index_register':s['index_register'],'index_high32_known_zero_at_BR_in_model':upper_zero[register][br],'checks':proof})
    # Graph-level falsification controls ensure blocking test distinguishes a bypass.
    assert 3 not in reachable({0:[1],1:[3],3:[]},0,1)
    assert 3 in reachable({0:[1,2],1:[3],2:[3],3:[]},0,1)
    assert raw_flow(0x14000002,0x100)[1]==[0x108]
    assert raw_flow(0x17ffffff,0x100)[1]==[0xfc]
    for raw in ('1f1d0071','3f0d0071','3f1d0071','1f010031','1f010072'):
        ins=next(cs.disasm(bytes.fromhex(raw),0x100))
        assert ins.mnemonic in ('cmp','cmn','tst') and not normalized_writes(ins)
    out=LAB/'npc-fighters-cfg-v2';out.mkdir(exist_ok=True)
    result={'profile':'NPC-AI003-conditional-intraprocedural-CFG-v2','elf_sha256':sha(elf.raw),'switch_maps_sha256':sha(maps.read_bytes()),'producer_sha256':sha(pathlib.Path(__file__).read_bytes()),'address':hex(start),'end_exclusive':hex(end),'function_bytes_sha256':sha(data),'detached_continuation':{'start':'0x118d934','bytes':island_bytes.hex(),'return':'0x1186008'},'instruction_count':len(instructions),'raw_control_decodes_checked_against_capstone':checked,'instruction_kinds':dict(counts),'edges':{hex(k):[hex(v) for v in values] for k,values in edges.items()},'reachable_instruction_nodes':len(seen),'external_exits':exits,'call_sites':calls,'unresolved_BR_in_scope':unresolved,'guard_checks':checks,'falsification_controls_passed':4,'assumptions':['Entry is the FDE entry only; no external or exceptional re-entry.','Recorded conditional switch destinations are complete and table/index preconditions hold.','Calls return to the next instruction with ordinary control flow; callee behavior is not analyzed.','Exception/signal edges not modeled.'],'limits':['Dominance holds only in this explicit model, not an unconditional global/runtime proof.','No argument dataflow or branch feasibility proof.'],'runtime_verified':False,'saved_project_modified':False}
    result['supersedes']='npc-fighters-cfg-v1: upper32 transfer incorrectly trusted Capstone CMP destination writes; corrected alias handling and negative controls in v2.'
    result['flag_only_alias_negative_controls_passed']=5
    result['upper32_analysis_decoder']='Capstone write sets with flag-only alias normalization; conditional on the recorded CFG.'
    (out/'cfg.json').write_text(json.dumps(result,indent=2)+'\n')
    (out/'REPORT.ru.md').write_text('# Условный граф NPC.AI_003_Fighters\n\n'+f'Декодировано {len(instructions)} инструкций; {checked} управляющих инструкций независимо сопоставлены с Capstone. В модель включены три ранее условно восстановленные таблицы.\n\n'+json.dumps(checks,ensure_ascii=False,indent=2)+'\n\nРезультат зависит от полноты switch-карт, единственного входа FDE, обычного возврата вызовов и отсутствия исключительных/внешних повторных входов. Это не безусловное доказательство глобального доминирования или достижимости в игре. Полный граф и исходные SHA: [cfg.json](cfg.json).\n',encoding='utf8')
    print(json.dumps({k:result[k] for k in ('instruction_count','raw_control_decodes_checked_against_capstone','reachable_instruction_nodes','guard_checks','external_exits')}))
if __name__=='__main__':main()
