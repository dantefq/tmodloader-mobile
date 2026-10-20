"""Conditional local BL register facts for AI_003_Fighters, no recovered-AI claim."""
import argparse, collections, hashlib, json, pathlib, struct, sys
from terraria_flow_islands import Elf, branch
from terraria_initializer_call_constants import operation, evaluate
from audit_terraria_initializer_call_constants import execute, direct_target

START=0x117a464
SIZE=79052
ELF_SHA='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def names_at(lab):
    names=collections.defaultdict(list)
    for line in (lab/'metadata/methods.jsonl').open(encoding='utf8'):
        r=json.loads(line)
        if r.get('native_address'):names[int(r['native_address'],16)].append({'method_index':r['index'],'signature':r['display_signature'],'parameter_names':r['parameter_names'],'flags':r['flags']})
    return names

def audit(doc,lab):
    """No Capstone interpretation is used here; rescan words and independent evaluator."""
    assert doc['producer_sha256']==sha(pathlib.Path(__file__))
    assert doc['constant_helper_sha256']==sha(pathlib.Path(__file__).with_name('terraria_initializer_call_constants.py'))
    for name,digest in doc['inputs'].items():assert sha(lab/name)==digest
    elf=Elf(lab/'native/libil2cpp.so');assert hashlib.sha256(elf.raw).hexdigest()==ELF_SHA==doc['elf_sha256']
    assert doc['start']==hex(START) and doc['end_exclusive']==hex(START+SIZE)
    raw=elf.raw[elf.at(START):elf.at(START+SIZE-4)+4]
    assert len(raw)==SIZE and hashlib.sha256(raw).hexdigest()==doc['function_sha256']
    names=names_at(lab);leaders={START};calls=[]
    for i,(word,) in enumerate(struct.iter_unpack('<I',raw)):
        pc=START+4*i;target=direct_target(word,pc)
        if word&0xfc000000==0x94000000:
            calls.append((pc,target))
        elif target is not None and START<=target<START+SIZE:leaders.add(target)
    assert doc['direct_BL_sites']==len(calls)
    named=[(p,t) for p,t in calls if names.get(t)]
    assert [(int(r['call_site'],16),int(r['direct_target'],16)) for r in doc['named_calls']]==named
    assert doc['method_aliases']==names[START]
    proof=set();facts=0
    for row in doc['named_calls']:
        pc=int(row['call_site'],16);target=int(row['direct_target'],16)
        assert row['target_aliases']==names[target]
        begin=int(row['window_start'],16)
        assert START<=begin<=pc and pc-begin<=64 and (pc-begin)%4==0
        assert not(set(range(begin+4,pc+1,4))&leaders) or begin==pc
        suffix=elf.raw[elf.at(begin):elf.at(pc)+4]
        words=list(struct.unpack('<'+'I'*(len(suffix)//4),suffix))
        assert direct_target(words[-1],pc)==target and words[-1]&0xfc000000==0x94000000
        assert len(row['instructions'])==len(words)
        for i,ins in enumerate(row['instructions']):
            assert ins['address']==hex(begin+4*i) and ins['bytes']==suffix[4*i:4*i+4].hex()
        assert execute(words[:-1])==row['register_constants']
        assert row['runtime_observed'] is False and row['full_call_signature_abi_proven'] is False
        if row['register_constants']:proof.update(range(begin,pc+4));facts+=len(row['register_constants'])
    assert doc['sites_with_constants']==sum(bool(r['register_constants']) for r in doc['named_calls'])
    assert doc['register_constant_facts']==facts
    return {'integrity_passed':True,'function_bytes_checked':SIZE,'named_BL_sites_checked':len(named),'unique_constant_proof_bytes_checked':len(proof),'constant_register_facts_checked':facts,'raw_evaluator_sha256':sha(pathlib.Path(__file__).with_name('audit_terraria_initializer_call_constants.py')),'scope':'Independent raw-word BL rescan and suffix evaluator; metadata names remain source-catalog labels, execution and full ABI semantics not proven.'}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',required=True,type=pathlib.Path);a=ap.parse_args();lab=a.lab
    sys.path.insert(0,str(lab/'python-analysis'))
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
    elf=Elf(lab/'native/libil2cpp.so');assert hashlib.sha256(elf.raw).hexdigest()==ELF_SHA
    ranges={int(s.split('\t')[0],16):int(s.split('\t')[1],16) for s in (lab/'native/unwind-function-ranges.tsv').read_text().splitlines()};assert ranges[START]==START+SIZE
    names=names_at(lab);assert any('AI_003_Fighters' in r['signature'] for r in names[START])
    raw=elf.raw[elf.at(START):elf.at(START+SIZE-4)+4];cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    code=list(cs.disasm(raw,START));assert len(code)*4==SIZE
    leaders={START}
    for ins in code:
        flow=branch(int.from_bytes(ins.bytes,'little'),ins.address)
        if flow and START<=flow[1]<START+SIZE:leaders.add(flow[1])
    ops=[operation(i) for i in code];rows=[];calls=0
    for pos,ins in enumerate(code):
        if ins.mnemonic!='bl':continue
        calls+=1;target=ins.operands[0].imm
        if not names.get(target):continue
        begin=pos
        if ins.address not in leaders:
            while begin>0 and pos-begin<16 and ops[begin-1] is not None:
                if begin<pos and code[begin].address in leaders:break
                begin-=1
        constants=evaluate(ops[begin:pos])
        rows.append({'call_site':hex(ins.address),'direct_target':hex(target),'target_aliases':names[target],'window_start':hex(code[begin].address),'register_constants':constants,'instructions':[{'address':hex(i.address),'bytes':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str} for i in code[begin:pos+1]],'runtime_observed':False,'full_call_signature_abi_proven':False})
    doc={'profile':'NPC-AI003-Fighters-local-named-BL-v1','elf_sha256':ELF_SHA,'start':hex(START),'end_exclusive':hex(START+SIZE),'function_sha256':hashlib.sha256(raw).hexdigest(),'method_aliases':names[START],'producer_sha256':sha(pathlib.Path(__file__)),'inputs':{str(p.relative_to(lab)):sha(p) for p in (lab/'metadata/methods.jsonl',lab/'native/unwind-function-ranges.tsv')},'constant_helper_sha256':sha(pathlib.Path(__file__).with_name('terraria_initializer_call_constants.py')),'direct_BL_sites':calls,'named_BL_sites':len(rows),'sites_with_constants':sum(bool(r['register_constants']) for r in rows),'register_constant_facts':sum(len(r['register_constants']) for r in rows),'named_calls':rows,'limitations':['Each fact is conditional on the entire recorded suffix executing consecutively before BL; unknown indirect/external entries and reachability are not proven.','Window is at most 16 pure integer instructions. Calls, loads, stores, flags updates and unsupported operations stop it. No constant is propagated across any call.','Only X0-X7 integer register facts. Floating-point, stack arguments, hidden arguments, full ABI and argument-to-gameplay meaning are not recovered.','Named BL catalog excludes unnamed direct calls and indirect calls. Presence of an encoded BL does not establish runtime execution.','This is not complete NPC AI, source C#, complete control flow or semantic-equivalence evidence.']}
    result=audit(doc,lab)
    import copy
    negatives=[]
    for label,mutate in [('changed_function_hash',lambda d:d.__setitem__('function_sha256','0'*64)),('wrong_call_count',lambda d:d.__setitem__('direct_BL_sites',d['direct_BL_sites']+1)),('changed_BL_target',lambda d:d['named_calls'][0].__setitem__('direct_target','0x0')),('changed_proof_bytes',lambda d:d['named_calls'][0]['instructions'][0].__setitem__('bytes','00000000')),('false_runtime_claim',lambda d:d['named_calls'][0].__setitem__('runtime_observed',True)),('changed_constant',lambda d:next(r for r in d['named_calls'] if r['register_constants'])['register_constants'].__setitem__('x7',{'unsigned64':0,'low32':0,'signed_low32':0}))]:
        bad=copy.deepcopy(doc);mutate(bad)
        try:audit(bad,lab)
        except (AssertionError,ValueError):negatives.append({'fixture':label,'rejected':True})
        else:raise ValueError('Negative fixture accepted: '+label)
    out=lab/'npc-ai003-call-facts-v1';out.mkdir(exist_ok=True);p=out/'calls.json';p.write_text(json.dumps(doc,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    result['calls_sha256']=sha(p);result['negative_fixtures']=negatives
    (out/'audit.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    tally=collections.Counter(r['target_aliases'][0]['signature'] for r in rows)
    lines=['# Локальные вызовы NPC.AI_003_Fighters','',f"Проверены {SIZE:,} байт FDE {hex(START)}. Найдено {calls} прямых BL, из них {len(rows)} именованы по метаданным; {doc['sites_with_constants']} имеют локальные константы X0–X7 ({doc['register_constant_facts']} отдельных фактов). Это статический каталог условных фактов, а не восстановленный полный AI.",'','| Сигнатура цели | Число BL |','|---|---:|']
    lines += [f'| `{name}` | {count} |' for name,count in tally.most_common()]
    lines += ['','Исходные адреса, инструкции и значения: [calls.json](calls.json). Независимая raw-проверка всех BL и суффиксов, шесть отклонённых отрицательных образцов: [audit.json](audit.json).','',*['- '+s for s in doc['limitations']]]
    (out/'REPORT.ru.md').write_text('\n'.join(lines)+'\n',encoding='utf8')
    print(json.dumps({'out':str(out),'direct_calls':calls,'named_calls':len(rows),'sites_with_constants':doc['sites_with_constants'],'facts':doc['register_constant_facts'],'calls_sha256':sha(p)}))
if __name__=='__main__':main()
