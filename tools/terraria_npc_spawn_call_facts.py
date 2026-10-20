"""Bounded NPC Type constants before direct SpawnNPC calls; no spawn-condition equivalence claim."""
import argparse, collections, hashlib, json, pathlib, struct, sys
from terraria_flow_islands import Elf, branch
from terraria_initializer_call_constants import operation, evaluate
from audit_terraria_initializer_call_constants import execute


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);a=ap.parse_args();lab=a.lab;repo=pathlib.Path(__file__).parent
    sys.path.insert(0,str(lab/'python-analysis'))
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
    source=lab/'native/libil2cpp.so';e=Elf(source)
    if sha(source)!='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5':raise ValueError('Source identity mismatch')
    start,end,target=0x12e2cb8,0x12f53e8,0x1413a20
    ranges={int(s.split('\t')[0],16):int(s.split('\t')[1],16) for s in (lab/'native/unwind-function-ranges.tsv').read_text().splitlines()}
    if ranges[start]!=end:raise ValueError('FDE mismatch')
    aliases=[]
    with (lab/'metadata/methods.jsonl').open(encoding='utf8') as f:
        for line in f:
            r=json.loads(line)
            if r.get('native_address')==hex(target):aliases.append(r)
    if len(aliases)!=1 or aliases[0]['owner_type']!='Terraria.NPC+Spawner' or aliases[0]['name']!='SpawnNPC' or aliases[0]['flags']&16 or aliases[0]['parameter_names'][:3]!=['X','Y','Type']:raise ValueError('Callee instance/parameter identity mismatch')
    names=collections.defaultdict(list);id_path=lab/'metadata/constants.Terraria.ID.NPCID.json'
    for r in json.loads(id_path.read_text()):
        if r['status']=='decoded' and isinstance(r.get('value'),int):names[r['value']].append(r['name'])
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;raw=e.raw[e.at(start):e.at(end-4)+4];code=list(cs.disasm(raw,start))
    if len(code)*4!=len(raw):raise ValueError('Incomplete decode')
    leaders={start}
    for ins in code:
        flow=branch(int.from_bytes(ins.bytes,'little'),ins.address)
        if flow and start<=flow[1]<end:leaders.add(flow[1])
    maps=lab/'hard-switches-v2/switches.json'
    for m in json.loads(maps.read_text())['methods']:
        if m['address']==hex(start):
            for table in m['switch_candidates']:leaders|={int(x['target'],16) for x in table['entries']}
    ops=[operation(i) for i in code];rows=[];calls=0
    for pos,ins in enumerate(code):
        if ins.mnemonic!='bl' or ins.operands[0].imm!=target:continue
        calls+=1;begin=pos
        if ins.address in leaders:continue
        while begin>0 and pos-begin<16 and ops[begin-1] is not None:
            if begin<pos and code[begin].address in leaders:break
            begin-=1
        facts=evaluate(ops[begin:pos])
        if 'x3' not in facts:continue
        words=[int.from_bytes(i.bytes,'little') for i in code[begin:pos]]
        independent=execute(words)
        if independent!=facts:raise ValueError('Independent raw evaluator mismatch')
        w=int.from_bytes(ins.bytes,'little');imm=w&0x3ffffff
        if imm&(1<<25):imm-=1<<26
        if w&0xfc000000!=0x94000000 or ins.address+imm*4!=target:raise ValueError('Raw BL target mismatch')
        ident=facts['x3']['signed_low32']
        rows.append({'call_site':hex(ins.address),'window_start':hex(code[begin].address),'Type_W3':ident,'NPCID_name_candidates':names[ident],
                     'register_constants':facts,'instructions':[{'address':hex(i.address),'bytes':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str} for i in code[begin:pos+1]],
                     'conditions':['Entire recorded suffix executes consecutively before this BL','AArch64 instance receiver uses X0; first three integer parameters X,Y,Type use W1,W2,W3'],
                     'runtime_observed':False,'spawn_conditions_recovered':False})
    out=lab/'npc-spawn-call-facts-v1';out.mkdir(exist_ok=True)
    doc={'profile':'SpawnAnNPC-local-SpawnNPC-Type-W3-v1','elf_sha256':sha(source),'source_start':hex(start),'source_end_exclusive':hex(end),'source_bytes_sha256':hashlib.sha256(raw).hexdigest(),
         'producer_sha256':sha(pathlib.Path(__file__)),'constant_producer_helper_sha256':sha(repo/'terraria_initializer_call_constants.py'),
         'independent_raw_helper_sha256':sha(repo/'audit_terraria_initializer_call_constants.py'),'NPCID_catalog_sha256':sha(id_path),'switch_maps_sha256':sha(maps),
         'methods_catalog_sha256':sha(lab/'metadata/methods.jsonl'),'callee_signature':aliases[0]['display_signature'],'direct_calls_to_callee':calls,'calls_with_known_Type':len(rows),'rows':rows,
         'interpretation_limit':'Local encoded Type arguments only. Branch probabilities, eligibility, loop counts, complete spawned-NPC set and runtime behavior are not recovered.'}
    p=out/'calls.json';p.write_text(json.dumps(doc,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    audit={'integrity_passed':True,'independent_raw_argument_evaluator_used':True,'calls_sha256':sha(p),'known_Type_calls':len(rows),'all_direct_calls_to_callee':calls,
           'scope':'Original ELF BL opcodes and bounded suffix constants checked with a different raw ARM64 evaluator. Source code/ABI assumptions and reachability are not proven.'}
    (out/'audit.json').write_text(json.dumps(audit,indent=2)+'\n',encoding='utf8')
    lines=['# Числовые Type перед вызовами Spawner.SpawnNPC','',f"В SpawnAnNPC найдено {calls} прямых BL к Spawner.SpawnNPC; для {len(rows)} локально задан W3 (параметр Type). Это не полный список возможных NPC: другие значения вычисляются, передаются общими путями или требуют более длинного анализа.",'','| Адрес вызова | Type W3 | Совпадение NPCID |','|---|---:|---|']
    lines += [f"| {r['call_site']} | {r['Type_W3']} | {', '.join(r['NPCID_name_candidates']) or '—'} |" for r in rows]
    lines += ['','[Исходные инструкции и условия](calls.json) · [Проверка констант другим raw-декодером](audit.json).','',doc['interpretation_limit']]
    (out/'REPORT.ru.md').write_text('\n'.join(lines)+'\n',encoding='utf8');print(json.dumps({'direct_calls':calls,'known_Type':len(rows),'out':str(out)}))


if __name__=='__main__':main()
