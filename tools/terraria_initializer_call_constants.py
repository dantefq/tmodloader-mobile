"""Conservative local constant-register facts before BL in five giant initializers.

No data flow crosses calls, loads, stores, flags writes, branches or unsupported
instructions. Facts are conditional on execution of the entire recorded suffix.
"""
import argparse,collections,hashlib,json,pathlib,sys
from terraria_flow_islands import Elf,branch

STARTS=(0x1635538,0x19cba0c,0x1a893ac,0x1aae9b4,0xb1ab78)
ELF_SHA='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def operation(ins):
    from capstone.arm64 import ARM64_OP_REG,ARM64_OP_IMM
    if ins.update_flags:return None
    ops=ins.operands;mn=ins.mnemonic
    if mn=='nop':return ('nop',)
    if not ops or ops[0].type!=ARM64_OP_REG:return None
    dest=ins.reg_name(ops[0].reg)
    if dest not in {f'{size}{i}' for size in ('w','x') for i in range(31)}:return None
    bits=64 if dest[0]=='x' else 32;d=int(dest[1:])
    if mn=='mov' and len(ops)==2:
        if ops[1].type==ARM64_OP_IMM:return ('imm',d,bits,ops[1].imm)
        if ops[1].type==ARM64_OP_REG:
            name=ins.reg_name(ops[1].reg)
            if name in ('xzr','wzr'):return ('imm',d,bits,0)
            if name[0]==dest[0] and name[1:].isdigit():return ('copy',d,bits,int(name[1:]))
    if mn=='movk' and len(ops)==2 and ops[1].type==ARM64_OP_IMM:
        return ('keep',d,bits,ops[1].imm,ops[1].shift.value)
    if mn in ('add','sub','and') and len(ops)==3 and ops[1].type==ARM64_OP_REG and ops[2].type==ARM64_OP_IMM and not ops[2].shift.value:
        name=ins.reg_name(ops[1].reg)
        if name[0]==dest[0] and name[1:].isdigit():return (mn,d,bits,int(name[1:]),ops[2].imm)
    return None

def evaluate(ops):
    known={}
    for op in ops:
        kind=op[0]
        if kind=='nop':continue
        _,d,bits,*args=op;mask=(1<<bits)-1
        value=None
        if kind=='imm':value=args[0]
        elif kind=='copy':value=known.get(args[0])
        elif kind=='keep':
            if d in known:value=(known[d]&~(65535<<args[1]))|(args[0]<<args[1])
        elif args[0] in known:
            left=known[args[0]]&mask;right=args[1]
            value=left+right if kind=='add' else left-right if kind=='sub' else left&right
        if value is None:known.pop(d,None)
        else:known[d]=value&mask
    return {f'x{i}':{'unsigned64':known[i],'low32':known[i]&0xffffffff,'signed_low32':(known[i]&0xffffffff)-(1<<32) if known[i]&0x80000000 else known[i]&0xffffffff} for i in range(8) if i in known}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',required=True,type=pathlib.Path);args=ap.parse_args();lab=args.lab
    sys.path.insert(0,str(lab/'python-analysis'));from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;elf=Elf(lab/'native/libil2cpp.so')
    assert hashlib.sha256(elf.raw).hexdigest()==ELF_SHA
    rangepath=lab/'native/unwind-function-ranges.tsv';ranges={int(x.split('\t')[0],16):int(x.split('\t')[1],16) for x in rangepath.read_text().splitlines()}
    metapath=lab/'metadata/methods.jsonl';names=collections.defaultdict(list)
    for line in metapath.open(encoding='utf8'):
        r=json.loads(line)
        if r.get('native_address'):names[int(r['native_address'],16)].append({'method_index':r['index'],'signature':r['display_signature'],'parameter_names':r['parameter_names'],'flags':r['flags']})
    idpath=lab/'metadata/constants.Terraria.ID.ItemID.json';ids=collections.defaultdict(list)
    for r in json.loads(idpath.read_text()):
        if r['status']=='decoded' and isinstance(r.get('value'),int):ids[r['value']].append(r['name'])
    functions=[];result=[]
    for start in STARTS:
        end=ranges[start];raw=elf.raw[elf.at(start):elf.at(end-4)+4];code=list(cs.disasm(raw,start));assert len(code)*4==len(raw)
        leaders={start};calls=0;namedcalls=0;kept=0
        for ins in code:
            decoded=branch(int.from_bytes(ins.bytes,'little'),ins.address)
            if decoded and start<=decoded[1]<end:leaders.add(decoded[1])
        ops=[operation(ins) for ins in code]
        for index,ins in enumerate(code):
            if ins.mnemonic!='bl':continue
            calls+=1;target=ins.operands[0].imm
            if not names.get(target):continue
            namedcalls+=1;begin=index
            if ins.address in leaders:continue
            while begin>0 and index-begin<16 and ops[begin-1] is not None:
                if begin<index and code[begin].address in leaders:break
                begin-=1
            if begin==index:continue
            constants=evaluate(ops[begin:index])
            if not constants:continue
            row={'function_start':hex(start),'call_site':hex(ins.address),'direct_target':hex(target),'target_aliases':names[target],
                'window_start':hex(code[begin].address),'window_end_inclusive':hex(ins.address),
                'instructions':[{'address':hex(t.address),'raw_bytes':bytes(t.bytes).hex(),'instruction':t.mnemonic+' '+t.op_str} for t in code[begin:index+1]],
                'register_constants':constants,'unresolved_argument_registers':[f'x{i}' for i in range(8) if f'x{i}' not in constants],
                'conditions':['The complete recorded straight-line instruction suffix executes in address order immediately before the BL.','No hidden indirect entry into the middle of the recorded suffix is assumed.'],
                'runtime_observed':False,'full_call_signature_abi_proven':False,'recipe_membership_proven':False}
            if target==0xf51d50 and 'x1' in constants:
                value=constants['x1']['signed_low32'];row['item_id_constant_name_candidates']=ids[value]
                row['item_id_annotation_limit']='Numerical ItemID match for W1 preceding named Item.SetDefaults; no recipe output/ingredient association proved.'
            result.append(row);kept+=1
        functions.append({'address':hex(start),'end_exclusive':hex(end),'source_bytes_sha256':hashlib.sha256(raw).hexdigest(),'method_aliases':names[start],'instruction_slots':len(code),'direct_BL_sites':calls,'named_direct_BL_sites':namedcalls,'sites_with_constant_facts':kept,'local_branch_targets':sorted(hex(t) for t in leaders)})
    out=lab/'initializer-call-constants-v1';out.mkdir(exist_ok=True)
    doc={'profile':'five-hard-initializer-local-BL-register-constants-v1','elf_sha256':ELF_SHA,'producer_sha256':sha(pathlib.Path(__file__)),
         'inputs':{'unwind-function-ranges.tsv':sha(rangepath),'methods.jsonl':sha(metapath),'constants.Terraria.ID.ItemID.json':sha(idpath)},
         'window_limit_instructions_before_BL':16,'functions':functions,'results':result,'sites_with_constant_facts':len(result),
         'constant_register_facts':sum(len(r['register_constants']) for r in result),'baseline_modified':False,'valid_C':False,
         'limitations':['Conditional local instruction facts, not complete initializers or recovered recipe data.','Any load, store, branch, call, flags update or unsupported instruction ends the suffix; no constants survive a call.','Only local direct branch targets split windows; unknown indirect or external entries are excluded by explicit conditional execution premise.','Register constants include hidden/runtime arguments and must not all be interpreted as gameplay values.']}
    (out/'calls.json').write_text(json.dumps(doc,ensure_ascii=False,indent=2),encoding='utf8')
    print(json.dumps({'functions':[{k:v for k,v in r.items() if k not in ('local_branch_targets','method_aliases')} for r in functions],'sites':len(result),'facts':doc['constant_register_facts']},ensure_ascii=False))

if __name__=='__main__':main()
