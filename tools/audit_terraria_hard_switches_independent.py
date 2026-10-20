"""Independent table-byte audit; deliberately imports no producer modules."""
import hashlib, json, pathlib, struct, sys

lab=pathlib.Path(sys.argv[1]); out=lab/'hard-switches-v1'
sys.path.insert(0,str(lab/'python-analysis'))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM, ARM64_SFT_LSL
elf=(lab/'native/libil2cpp.so').read_bytes()
assert hashlib.sha256(elf).hexdigest()=='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
segments=[]
ph=struct.unpack_from('<Q',elf,32)[0]; sz,n=struct.unpack_from('<HH',elf,54)
for i in range(n):
    kind,flags,off,va,_,fs,_,_=struct.unpack_from('<IIQQQQQQ',elf,ph+i*sz)
    if kind==1:segments.append((va,va+fs,off,flags))
def get(a,n,executable=False):
    hits=[(s,e,o,f) for s,e,o,f in segments if s<=a and a+n<=e and (not executable or f&1)]
    assert len(hits)==1,(hex(a),n)
    s,e,o,f=hits[0]; return elf[o+a-s:o+a-s+n]
cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
doc=json.loads((out/'switches.json').read_text(encoding='utf8'))
labels={}; label_hashes={}
for filename in ('method-addresses.json','generic-method-addresses.json'):
    blob=(lab/'native'/filename).read_bytes();label_hashes[filename]=hashlib.sha256(blob).hexdigest()
    for item in json.loads(blob):
        if item.get('address'):labels.setdefault(int(item['address'],16),set()).add(item['type']+'::'+item['name'])
tables=entries=branches=preview_count=preview_instructions=preview_calls=0
for m in doc['methods']:
    a=int(m['address'],16); b=int(m['end_exclusive'],16)
    actual={p for p in range(a,b,4) if int.from_bytes(get(p,4),'little')&0xfffffc1f==0xd61f0000}
    claimed=[int(t['branch'],16) for t in m['switch_candidates']]+[int(t['branch'],16) for t in m['unresolved_BR']]
    assert len(claimed)==len(set(claimed)) and set(claimed)==actual
    branches+=len(actual)
    for t in m['switch_candidates']:
        tables+=1; count=t['count']; width=t['width']; table=int(t['table'],16); anchor=int(t['anchor'],16)
        raw=get(table,count*width)
        assert raw.hex()==t['table_raw_bytes'] and hashlib.sha256(raw).hexdigest()==t['table_sha256']
        assert len(t['entries'])==count
        for i,x in enumerate(t['entries']):
            v=int.from_bytes(raw[i*width:(i+1)*width],'little'); target=anchor+4*v
            assert x['index']==i and x['encoded_offset']==v and int(x['target'],16)==target
            assert a<=target<b and target%4==0 and get(target,4,True).hex()==x['target_raw_bytes']
        entries+=count
        evidence=t['straight_line_evidence']; expected=int(evidence[0]['address'],16)
        for row in evidence:
            p=int(row['address'],16); assert p==expected;expected+=4
            assert get(p,4,True).hex()==row['raw_bytes']
            ins=list(cs.disasm(get(p,4),p)); assert len(ins)==1
            assert ins[0].mnemonic+' '+ins[0].op_str==row['instruction']
        cp=int(t['guard_compare'],16); gp=int(t['guard_branch'],16); br=int(t['branch'],16)
        cmp=list(cs.disasm(get(cp,4),cp))[0]; guard=list(cs.disasm(get(gp,4),gp))[0]
        assert cmp.mnemonic=='cmp' and guard.mnemonic=='b.hi'
        assert cmp.operands[1].type==ARM64_OP_IMM and cmp.operands[1].shift.value==0
        assert cmp.operands[1].imm+1==count
        assert guard.operands[0].imm==int(t['default_target'],16)
        # Verify the decoded target-register ADD uses LSL, not another shift.
        tail=list(cs.disasm(get(max(a,br-96),br-max(a,br-96)+4),max(a,br-96)))
        final=tail[-1]; dest=final.reg_name(final.operands[0].reg)
        def canon(n):return 'x'+n[1:] if n.startswith('w') else n
        def writes(ins):return {canon(ins.reg_name(r)) for r in ins.regs_access()[1]}
        add=next(z for z in reversed(tail[:-1]) if canon(dest) in writes(z))
        assert add.mnemonic=='add' and add.operands[2].shift.type==ARM64_SFT_LSL and add.operands[2].shift.value==2
        assert evidence[-1]['address']==t['branch']
        # Independent forward finite-value propagation along declared path.
        # Unknown operations invalidate their writes. Only concrete PC constants,
        # ADD-immediate, the guarded index and table load/ADD are modelled.
        state={}; index_values=list(range(count)); reached=False
        for row in evidence:
            p=int(row['address'],16); ins=list(cs.disasm(get(p,4),p))[0]; op=ins.operands
            before=dict(state)
            for name in writes(ins):state.pop(name,None)
            def name(operand):return canon(ins.reg_name(operand.reg))
            if p==cp:
                state[name(op[0])]=index_values
            elif ins.mnemonic in ('adr','adrp'):
                state[name(op[0])]=op[1].imm
            elif ins.mnemonic=='add' and len(op)==3:
                lhs=before.get(name(op[1]));rhs=op[2].imm if op[2].type==ARM64_OP_IMM else before.get(name(op[2]))
                shift=op[2].shift.value
                if isinstance(lhs,int) and isinstance(rhs,int):state[name(op[0])]=lhs+(rhs<<shift)
                elif isinstance(lhs,int) and isinstance(rhs,list):state[name(op[0])]=[lhs+(v<<shift) for v in rhs]
            elif ins.mnemonic in ('ldrb','ldrh') and len(op)==2 and op[1].type==ARM64_OP_MEM:
                mem=op[1].mem;base=before.get(canon(ins.reg_name(mem.base)));ix=before.get(canon(ins.reg_name(mem.index)))
                if isinstance(base,int) and ix==index_values:
                    item_width=1 if ins.mnemonic=='ldrb' else 2
                    assert base==table and item_width==width
                    state[name(op[0])]=[int.from_bytes(get(base+(v<<op[1].shift.value),item_width),'little') for v in ix]
            elif ins.mnemonic=='br':
                assert before.get(name(op[0]))==[int(x['target'],16) for x in t['entries']],hex(p)
                reached=True
        assert reached
        previews=t['destination_previews']
        assert [int(z['target'],16) for z in previews]==sorted({int(z['target'],16) for z in t['entries']})
        for preview in previews:
            preview_count+=1;pc=int(preview['target'],16);seen=set();expected_rows=[];expected_calls=[];stop='instruction_budget'
            for step in range(64):
                if pc in seen:stop='cycle';break
                seen.add(pc)
                if not a<=pc<b:stop='outside_origin_fde';break
                raw4=get(pc,4,True);ins=list(cs.disasm(raw4,pc))[0]
                expected_rows.append({'address':hex(pc),'raw_bytes':raw4.hex(),'instruction':ins.mnemonic+' '+ins.op_str})
                if ins.mnemonic=='bl':
                    dst=ins.operands[0].imm;expected_calls.append({'site':hex(pc),'target':hex(dst),'managed_names':sorted(labels.get(dst,set()))})
                    stop='first_direct_call';break
                if ins.mnemonic=='b':pc=ins.operands[0].imm;continue
                if ins.mnemonic.startswith('b.') or ins.mnemonic in ('cbz','cbnz','tbz','tbnz','br','blr','ret','eret','svc'):
                    stop='control_flow_boundary';break
                pc+=4
            assert preview['instructions']==expected_rows and preview['first_direct_calls']==expected_calls and preview['stop']==stop
            assert preview['runtime_executed'] is False
            preview_instructions+=len(expected_rows);preview_calls+=len(expected_calls)
assert tables==doc['summary']['tables'] and entries==doc['summary']['entries']
assert branches==121 and branches-tables==doc['summary']['unresolved_BR']
result={'integrity_passed':True,'methods':len(doc['methods']),'BR_instructions':branches,'tables':tables,'entries':entries,
 'destination_previews':preview_count,'preview_instruction_rows_verified':preview_instructions,'first_direct_call_labels_verified':preview_calls,
 'call_label_source_hashes':label_hashes,
 'finite_index_model_precondition':'The X register used for table indexing equals the compared unsigned W-register value; upper32bits are zero. CMP itself does not zero them.',
 'scope':'Independent ELF program-header translation, every table byte/entry/target byte, BR partition, recorded instruction bytes/disassembly, unsigned guard count and forward finite-value propagation from PC constants and guarded index through table load/ADD to BR. Conditional on the recorded path; not a global CFG or reachability proof.',
 'producer_output_sha256':hashlib.sha256((out/'switches.json').read_bytes()).hexdigest(),
 'audit_tool_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()}
(out/'independent-audit.json').write_text(json.dumps(result,indent=2),encoding='utf8');print(json.dumps(result))
