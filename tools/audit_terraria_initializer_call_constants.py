"""Independent raw ARM64 constant evaluator for bounded initializer call facts.

Does not import the producer, Capstone, or its operation/evaluate functions.
"""
import argparse,collections,hashlib,json,pathlib,struct
from terraria_flow_islands import Elf

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def sx(v,n):return v-(1<<n) if v&(1<<(n-1)) else v
def logical_mask(w,bits):
    n=(w>>22)&1;s=(w>>10)&63;r=(w>>16)&63;length=((n<<6)|((~s)&63)).bit_length()-1
    if length<1 or (bits==32 and n):raise ValueError('reserved logical mask')
    levels=(1<<length)-1;s&=levels;r&=levels;esize=1<<length
    if s==levels:raise ValueError('reserved logical mask')
    val=(1<<(s+1))-1;val=((val>>r)|(val<<(esize-r)))&((1<<esize)-1)
    return sum(val<<j for j in range(0,bits,esize))

def execute(words):
    values=[None]*31
    for w in words:
        bits=64 if w>>31 else 32;mask=(1<<bits)-1;d=w&31;n=(w>>5)&31;m=(w>>16)&31
        if w==0xd503201f:continue
        if d==31:raise ValueError('discard/SP destination excluded')
        if w&0x7fe0ffe0==0x2a0003e0:
            values[d]=0 if m==31 else None if values[m] is None else values[m]&mask;continue
        wide=w&0x7f800000
        if wide in (0x12800000,0x52800000,0x72800000):
            shift=((w>>21)&3)*16
            if shift>=bits:raise ValueError('bad wide shift')
            imm=((w>>5)&65535)<<shift
            if wide==0x72800000:
                values[d]=None if values[d] is None else ((values[d]&~(65535<<shift))|imm)&mask
            else:values[d]=((~imm) if wide==0x12800000 else imm)&mask
            continue
        if w&0x1f000000==0x11000000 and not w&0x20400000:
            if n==31:raise ValueError('SP input')
            imm=(w>>10)&4095
            values[d]=None if values[n] is None else ((values[n]&mask)+(-imm if w&0x40000000 else imm))&mask;continue
        if w&0x7f800000==0x12000000:
            if n==31:raise ValueError('unsupported AND alias')
            imm=logical_mask(w,bits);values[d]=None if values[n] is None else values[n]&imm&mask;continue
        if w&0x7f8003e0==0x320003e0:
            values[d]=logical_mask(w,bits);continue
        raise ValueError('instruction outside pure constant subset '+hex(w))
    return {f'x{i}':{'unsigned64':values[i],'low32':values[i]&0xffffffff,'signed_low32':sx(values[i]&0xffffffff,32)} for i in range(8) if values[i] is not None}

def direct_target(w,pc):
    if w&0x7c000000==0x14000000:return pc+sx(w&0x3ffffff,26)*4
    if w&0xff000010==0x54000000 or w&0x7e000000==0x34000000:return pc+sx((w>>5)&0x7ffff,19)*4
    if w&0x7e000000==0x36000000:return pc+sx((w>>5)&0x3fff,14)*4
    return None

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',required=True,type=pathlib.Path);args=ap.parse_args();lab=args.lab
    source=lab/'initializer-call-constants-v1/calls.json';d=json.loads(source.read_text());elf=Elf(lab/'native/libil2cpp.so')
    assert hashlib.sha256(elf.raw).hexdigest()==d['elf_sha256']=='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
    assert sha(pathlib.Path(__file__).with_name('terraria_initializer_call_constants.py'))==d['producer_sha256']
    pathmap={'unwind-function-ranges.tsv':lab/'native/unwind-function-ranges.tsv','methods.jsonl':lab/'metadata/methods.jsonl','constants.Terraria.ID.ItemID.json':lab/'metadata/constants.Terraria.ID.ItemID.json'}
    for name,digest in d['inputs'].items():assert sha(pathmap[name])==digest
    names=collections.defaultdict(list)
    for line in pathmap['methods.jsonl'].open(encoding='utf8'):
        r=json.loads(line)
        if r.get('native_address'):names[int(r['native_address'],16)].append({'method_index':r['index'],'signature':r['display_signature'],'parameter_names':r['parameter_names'],'flags':r['flags']})
    ids=collections.defaultdict(list)
    for r in json.loads(pathmap['constants.Terraria.ID.ItemID.json'].read_text()):
        if r['status']=='decoded' and isinstance(r.get('value'),int):ids[r['value']].append(r['name'])
    ranges={int(t.split('\t')[0],16):int(t.split('\t')[1],16) for t in pathmap['unwind-function-ranges.tsv'].read_text().splitlines()}
    allfunctions={int(r['address'],16):r for r in d['functions']};assert set(allfunctions)=={0x1635538,0x19cba0c,0x1a893ac,0x1aae9b4,0xb1ab78}
    leaders={};counts=collections.Counter();namedcounts=collections.Counter();sourcebytes=0;proofbytes=set();seen=set();factcount=0;annotations=0
    for start,r in allfunctions.items():
        end=int(r['end_exclusive'],16);assert end==ranges[start]
        raw=elf.raw[elf.at(start):elf.at(end-4)+4];assert hashlib.sha256(raw).hexdigest()==r['source_bytes_sha256'] and len(raw)==end-start==r['instruction_slots']*4
        leaders[start]={start};sourcebytes+=len(raw)
        for i,(w,) in enumerate(struct.iter_unpack('<I',raw)):
            pc=start+i*4;target=direct_target(w,pc)
            # Producer local leader inventory covers B/conditional branches; BL
            # self-recursion is also a transfer boundary, excluded from windows.
            if target is not None and start<=target<end and w&0xfc000000!=0x94000000:leaders[start].add(target)
            if w&0xfc000000==0x94000000:
                counts[start]+=1
                if names.get(target):namedcounts[start]+=1
        assert r['direct_BL_sites']==counts[start] and r['named_direct_BL_sites']==namedcounts[start] and r['method_aliases']==names[start]
        assert r['local_branch_targets']==sorted(hex(t) for t in leaders[start])
    rowcounts=collections.Counter()
    for r in d['results']:
        start=int(r['function_start'],16);pc=int(r['call_site'],16);begin=int(r['window_start'],16);end=ranges[start]
        assert start<=begin<pc<end and (pc-begin)%4==0 and (pc-begin)//4<=16 and r['window_end_inclusive']==hex(pc)
        assert not(set(range(begin+4,pc+1,4))&leaders[start]) and (start,pc) not in seen;seen.add((start,pc))
        raw=elf.raw[elf.at(begin):elf.at(pc)+4];assert len(raw)==pc-begin+4==len(r['instructions'])*4
        words=list(struct.unpack('<'+'I'*(len(raw)//4),raw));assert words[-1]&0xfc000000==0x94000000
        target=pc+sx(words[-1]&0x3ffffff,26)*4;assert r['direct_target']==hex(target) and r['target_aliases']==names[target]
        for j,ins in enumerate(r['instructions']):
            assert ins['address']==hex(begin+4*j) and ins['raw_bytes']==raw[4*j:4*j+4].hex();proofbytes.update(range(begin+4*j,begin+4*j+4))
        actual=execute(words[:-1]);assert actual==r['register_constants'] and actual,(hex(pc),actual,r['register_constants'])
        assert r['unresolved_argument_registers']==[f'x{i}' for i in range(8) if f'x{i}' not in actual]
        assert r['conditions']==['The complete recorded straight-line instruction suffix executes in address order immediately before the BL.','No hidden indirect entry into the middle of the recorded suffix is assumed.']
        for key in ('runtime_observed','full_call_signature_abi_proven','recipe_membership_proven'):assert r[key] is False
        if target==0xf51d50 and 'x1' in actual:
            assert r['item_id_constant_name_candidates']==ids[actual['x1']['signed_low32']];annotations+=1
        else:assert 'item_id_constant_name_candidates' not in r
        factcount+=len(actual);rowcounts[start]+=1
    assert d['sites_with_constant_facts']==len(seen)==len(d['results']) and d['constant_register_facts']==factcount
    assert d['baseline_modified'] is False and d['valid_C'] is False and d['window_limit_instructions_before_BL']==16
    for start,r in allfunctions.items():assert r['sites_with_constant_facts']==rowcounts[start]
    negative={'call':0x94000000,'load':0xf9400000,'store':0xf9000000,'conditional_branch':0xb4000001,'flags':0xb1000400,'SP_add':0x910003e0,'indirect_call':0xd63f0000}
    for name,word in negative.items():
        try:execute([0xd2802460,word])
        except ValueError:continue
        raise AssertionError('Forbidden opcode accepted '+name)
    # W writes zero-extend; MOVK without a prior constant remains unknown;
    # copying an unknown register invalidates the destination's old constant.
    assert execute([0x12800000])['x0']['unsigned64']==0xffffffff
    assert execute([0xf2800020])=={}
    assert execute([0xd2802460,0xaa0103e0])=={}
    report={'integrity_passed':True,'audit_profile':'independent-raw-ARM64-local-register-constant-v1','auditor_sha256':sha(pathlib.Path(__file__)),'calls_sha256':sha(source),'functions':len(allfunctions),'sites':len(seen),'constant_register_facts':factcount,'verified_full_function_source_bytes':sourcebytes,'verified_unique_proof_instruction_bytes':len(proofbytes),'item_SetDefaults_numerical_ID_annotations':annotations,'direct_BL_sites_in_selected_FDEs':sum(counts.values()),'named_BL_sites_in_selected_FDEs':sum(namedcounts.values()),'negative_controls_rejected':list(negative),'producer_decoder_imported':False,'limitations':['Conditional local suffix execution only; no full initializer, recipe association, runtime execution or original source equivalence.','Unsupported instructions terminate evidence; no volatile register survives a call.','Raw instruction classification does not prove reachability.']}
    (source.parent/'independent-audit.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))

if __name__=='__main__':main()
