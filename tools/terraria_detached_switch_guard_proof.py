"""Independent original-ELF evidence for four detached switch dispatch paths."""
import hashlib, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from terraria_flow_islands import Elf, branch
sys.path.insert(0, r'C:\Temp\terraria-re-20261012\python-analysis')
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

lab = pathlib.Path(r'C:\Temp\terraria-re-20261012')
elf = Elf(lab / 'native/libil2cpp.so')
sha = hashlib.sha256(elf.raw).hexdigest()
assert sha == '9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

def evidence(lo, hi):
    raw = b''.join(elf.word(a).to_bytes(4, 'little') for a in range(lo, hi, 4))
    return [{'address': hex(i.address), 'bytes': bytes(i.bytes).hex(), 'instruction': i.mnemonic+' '+i.op_str} for i in cs.disasm(raw, lo)]

specs = [
    (0x1182fc4, 0x1182fac, 0x1182df0, 0x1182df4, 0x1182df8, 4, 0x27ad680, 0x1182fc8, 0x117a464, 0x118d930),
    (0x11cf9dc, 0x11cf9c8, 0x11ce8a8, 0x11ce8ac, 0x11ce8b0, 12, 0x27ae006, 0x11ca7fc, 0x11b1bf4, 0x11ed19c),
    (0x11d79dc, 0x11d79c8, None, 0x11d6b78, 0x11d6b7c, 17, 0x27ae0b8, 0x11d2f14, 0x11b1bf4, 0x11ed19c),
    (0x11d7e3c, 0x11d7e24, 0x11d3b30, 0x11d3b34, 0x11d3b38, 13, 0x27ae09e, 0x11d2f14, 0x11b1bf4, 0x11ed19c),
]
rows = []
for br, block, norm, cmp, guard, count, table, anchor, start, end in specs:
    assert branch(elf.word(guard), guard)[1] == block
    ins = list(cs.disasm(elf.word(guard).to_bytes(4, 'little'), guard))[0]
    assert ins.mnemonic == 'b.ls'
    cmp_ins = list(cs.disasm(elf.word(cmp).to_bytes(4, 'little'), cmp))[0]
    assert cmp_ins.mnemonic == 'cmp' and cmp_ins.op_str == 'w9, #'+ ('0x%x'%(count-1) if count-1 >=10 else str(count-1))
    raw = b''.join(elf.word(a).to_bytes(4, 'little') for a in range(table & ~3, (table+count*2+3)&~3, 4))
    raw = raw[table%4:table%4+count*2]
    targets = [anchor+int.from_bytes(raw[i:i+2], 'little')*4 for i in range(0,len(raw),2)]
    assert all(t%4 == 0 for t in targets)
    incoming = []
    for a in range(start, end, 4):
        flow = branch(elf.word(a), a)
        if flow and block <= flow[1] <= br:
            incoming.append({'source':hex(a),'kind':flow[0],'target':hex(flow[1])})
    rows.append({'br':hex(br),'table_block':hex(block),'cmp':hex(cmp),'guard':hex(guard),
                 'normalization':hex(norm) if norm else None, 'count':count,'table':hex(table),'anchor':hex(anchor),
                 'guard_evidence':evidence(norm or cmp,guard+4),'taken_block_evidence':evidence(block,br+4),
                 'direct_incoming_to_dispatch_block_within_selected_fde':incoming,
                 'table_bytes':raw.hex(),'table_sha256':hashlib.sha256(raw).hexdigest(),
                 'entries':[{'index':i,'target':hex(t),'inside_origin_fde':start <= t < end,'source_target_bytes':elf.word(t).to_bytes(4,'little').hex()} for i,t in enumerate(targets)],
                 'conditions':['Recorded B.LS is taken after recorded CMP W9 without intervening NZCV mutation.',
                               'Execution enters dispatch at recorded block start and follows all instructions to BR.',
                               'X9 high 32 bits are zero when table loads; SUB W9 ensures this only for rows with recorded normalization.',
                               'Original readonly table bytes remain unchanged.'],
                 'not_proved':['runtime reachability','absence of indirect alternate entry','global W9 definition for row whose normalization is null']})
out = lab/'hard-switches-v2/detached-guards-proof.json'
out.parent.mkdir(exist_ok=True)
out.write_text(json.dumps({'source_sha256':sha,'profile':'independent-detached-guards-original-elf-v1',
                         'scan_scope':'Only direct branches in the containing selected FDE; fallthrough and indirect edges not enumerated.',
                         'switches':rows},indent=2)+'\n',encoding='utf-8')
print(json.dumps({'file':str(out),'sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'switches':len(rows),'entries':sum(r['count'] for r in rows)}))
