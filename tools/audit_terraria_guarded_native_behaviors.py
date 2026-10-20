"""Independent raw-encoding audit for conditional LR-saving native wrappers.

Never imports the producer. Exact byte masks decode control and selected body
semantics; caller supplies the source-bound result document.
"""
import argparse, collections, hashlib, json, pathlib, struct
from terraria_flow_islands import Elf

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def sx(v,n):return v-(1<<n) if v&(1<<(n-1)) else v

def raw_body(words,start):
    regs={i:{'kind':'input_register','register':'x'+str(i)} for i in range(31)};reads=[]
    initial=dict(regs)
    def rd(n,bits=64):
        v={'kind':'constant','value':0} if n==31 else regs[n]
        return {'kind':'low32','value':v} if bits==32 and n!=31 else v
    def wr(n,bits,v):
        if n in (30,31):raise ValueError('body writes LR or SP/ZR')
        regs[n]={'kind':'zero_extend32' if bits==32 else 'low64','value':v}
    def load(pc,d,n,offset,size,bits,base=None):
        if n==31:raise ValueError('body stack read')
        val={'kind':'memory_load','base':rd(n) if base is None else base,'offset':offset,'address_bits':64,'bytes':size,'signed':False,'result_bits':bits}
        reads.append({'address':hex(pc),'memory_read':val});wr(d,bits,val)
    for index,w in enumerate(words):
        pc=start+index*4;d=w&31;n=(w>>5)&31;m=(w>>16)&31;bits=64 if w>>31 else 32
        if w==0xd503201f:continue
        if w&0x7fe0ffe0==0x2a0003e0:wr(d,bits,rd(m,bits));continue
        if w&0x7f800000==0x12000000:
            N=(w>>22)&1;s=(w>>10)&63;r=(w>>16)&63
            length=((N<<6)|((~s)&63)).bit_length()-1
            if length<1 or (bits==32 and N):raise ValueError('bad logical immediate')
            levels=(1<<length)-1;s&=levels;r&=levels;e=1<<length
            if s==levels:raise ValueError('reserved logical immediate')
            value=(1<<(s+1))-1;value=((value>>r)|(value<<(e-r)))&((1<<e)-1)
            value=sum(value<<j for j in range(0,bits,e))
            wr(d,bits,{'kind':'and','lhs':rd(n,bits),'rhs':value});continue
        if w&0xffe00000==0x8b000000:
            shift=(w>>10)&63
            if n==31 or m==31:raise ValueError('unsupported ADD input')
            wr(d,64,{'kind':'scaled_add','lhs':rd(n),'rhs':rd(m),'shift':shift});continue
        if w&0xffc00000 in (0xf9400000,0xb9400000,0x79400000,0x39400000):
            size=1<<((w>>30)&3);load(pc,d,n,((w>>10)&4095)*size,size,64 if size==8 else 32);continue
        if w&0xffc00000==0xa9400000:
            t=(w>>10)&31;offset=sx((w>>15)&127,7)*8
            if d==t:raise ValueError('overlapping LDP destinations')
            base=rd(n)
            load(pc,d,n,offset,8,64,base);load(pc,t,n,offset+8,8,64,base);continue
        raise ValueError('unsupported body opcode '+hex(w))
    return {'x'+str(n):v for n,v in regs.items() if v!=initial[n]},reads,regs

def raw_wrapper(words,start):
    if len(words)<6 or words[0]!=0xf81f0ffe:raise ValueError('not LR-saving prefix')
    guard=words[1];last=start+4*(len(words)-1)
    if guard&0xff00001f!=0xb4000001 or start+4+sx((guard>>5)&0x7ffff,19)*4!=last:raise ValueError('not exact X1 null guard to trailing BL')
    if words[-3]!=0xf84107fe or words[-2]&0xfffffc1f!=0xd61f0000:raise ValueError('not restore LR + BR')
    if words[-1]&0xfc000000!=0x94000000:raise ValueError('not trailing BL')
    changes,reads,regs=raw_body(words[2:-3],start+8)
    rn=(words[-2]>>5)&31
    if rn in (30,31):raise ValueError('unsupported BR register')
    return changes,reads,regs[rn],last+sx(words[-1]&0x3ffffff,26)*4

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);args=ap.parse_args();lab=args.lab
    source=lab/'guarded-native-behaviors-v1/behaviors.json';doc=json.loads(source.read_text())
    priorpath=lab/'unknown-native-behaviors-v1/behaviors.json';prior=json.loads(priorpath.read_text())
    catalogpath=lab/'native/unmapped-fde-classification.json';catalog=json.loads(catalogpath.read_text())
    rangepath=lab/'native/unwind-function-ranges.tsv'
    ranges={int(x.split('\t')[0],16):int(x.split('\t')[1],16) for x in rangepath.read_text().splitlines()}
    elf=Elf(lab/'native/libil2cpp.so')
    assert hashlib.sha256(elf.raw).hexdigest()==doc['elf_sha256']=='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
    assert doc['prior_behavior_sha256']==sha(priorpath)
    assert doc['producer_sha256']==sha(pathlib.Path(__file__).with_name('terraria_guarded_native_behaviors.py'))
    unknown={r['address']:r for r in catalog if r['category']=='unknown'}
    remaining=set(prior['unclassified_addresses']);prior_done={r['address'] for r in prior['results']}
    assert len(unknown)==8140 and len(remaining)==6812 and not remaining&prior_done and remaining|prior_done==unknown.keys()
    described={r['address'] for r in doc['results']};excluded=set(doc['unclassified_addresses'])
    assert len(described)==len(doc['results']) and len(excluded)==len(doc['unclassified_addresses'])
    assert not described&excluded and described|excluded==remaining
    bytecount=0;loads=0;targets=collections.Counter();decoded_scope=set()
    for address in remaining:
        entry=unknown[address];start=int(address,16);end=int(entry['end_exclusive'],16)
        if end-start>128:continue
        code=elf.raw[elf.at(start):elf.at(end-4)+4];words=struct.unpack('<'+'I'*(len(code)//4),code)
        try:raw_wrapper(words,start)
        except ValueError:continue
        decoded_scope.add(address)
    assert decoded_scope==described,('Raw decoder coverage mismatch',decoded_scope^described)
    for r in doc['results']:
        entry=unknown[r['address']];start=int(r['address'],16);end=int(r['end_exclusive'],16)
        assert entry['end_exclusive']==r['end_exclusive'] and entry['size']==end-start==ranges[start]-start and end-start<=128
        code=elf.raw[elf.at(start):elf.at(end-4)+4];assert len(code)==end-start and hashlib.sha256(code).hexdigest()==r['source_bytes_sha256']
        assert len(r['instructions'])*4==len(code)
        for j,ins in enumerate(r['instructions']):assert ins['address']==hex(start+4*j) and ins['raw_bytes']==code[j*4:j*4+4].hex()
        words=struct.unpack('<'+'I'*(len(code)//4),code);changes,reads,transfer,target=raw_wrapper(words,start);last=end-4
        assert r['guard']=={'register':'x1','condition':'equals_zero','address':hex(start+4),'zero_target':hex(last),'nonnull_target':hex(start+8)}
        assert r['stack']=={'entry_sp_delta_after_spill':-16,'saved_entry_x30_offset_from_entry_sp':-16,'nonnull_sp_delta_at_transfer':0,'nonnull_entry_x30_restored':True}
        n=r['nonnull_path'];assert n['structural_behavior']=='indirect_branch_forwarder'
        assert n['transfer']=={'kind':'indirect_branch','target_expression':transfer} and n['register_changes']==changes and n['ordered_memory_reads']==reads
        assert n['writes_memory'] is False and n['contains_calls_or_conditional_branches'] is False and n['function_prototype_recovered'] is False and n['runtime_observed'] is False and n['game_or_runtime_role']=='unknown'
        assert r['zero_path']=={'call_site':hex(last),'direct_call_target':hex(target),'sp_delta_at_call':-16,'link_register_after_call_instruction':hex(end),'if_callee_returns_next_address':hex(end),'return_continuation_outside_recorded_fde':True,'callee_noreturn_proven':False}
        assert r['conditions']==['entry SP is valid for 16-byte spill and the spill does not alias any memory read by normal body','all normal-path loads complete successfully','execution begins at recorded FDE start']
        assert r['runtime_observed'] is False and r['game_or_runtime_role']=='unknown' and r['valid_C'] is False
        bytecount+=len(code);loads+=len(reads);targets[hex(target)]+=1
    assert doc['prior_remaining']==6812 and doc['new_descriptions']==len(described)==411 and doc['remaining']==len(excluded)==6401
    assert doc['cumulative_descriptions']==len(prior_done)+len(described)==1739 and doc['semantic_role_still_unknown']==8140 and doc['baseline_modified'] is False
    # Synthetic complete wrapper with one MOV. Mutants must all be rejected.
    fixture=[0xf81f0ffe,0xb4000081,0xaa0103e0,0xf84107fe,0xd61f0060,0x94000000]
    raw_wrapper(fixture,0x1000)
    mutations={'wrong_spill':(0,0xf81e0ffe),'guard_w1':(1,0x34000081),'guard_x2':(1,0xb4000082),'wrong_guard_target':(1,0xb4000061),'wrong_restore':(3,0xf8410ffe),'body_BLR':(2,0xd63f0060),'body_store':(2,0xf9000020),'body_write_lr':(2,0xaa0103fe),'flags_write':(2,0xb1000400),'BL_as_B':(5,0x14000000)}
    for label,(index,word) in mutations.items():
        modified=list(fixture);modified[index]=word
        try:raw_wrapper(modified,0x1000)
        except ValueError:continue
        raise AssertionError('Rejected control accepted: '+label)
    result={'integrity_passed':True,'audit_profile':'independent-raw-arm64-null-guard-spill-symbolic-v1','auditor_sha256':sha(pathlib.Path(__file__)),'behaviors_sha256':sha(source),'catalog_sha256':sha(catalogpath),'unwind_ranges_sha256':sha(rangepath),'new_descriptions':len(described),'remaining':len(excluded),'cumulative_descriptions':1739,'verified_source_instruction_bytes':bytecount,'ordered_body_loads':loads,'zero_path_call_targets':dict(targets),'negative_controls_rejected':list(mutations),'producer_decoder_imported':False,'limitations':['Static conditional wrapper semantics; no game/runtime purpose or reachability proved.','All loads/spills must succeed; spill nonalias precondition retained.','Trailing BL callee return behavior unknown; continuation outside FDE explicitly preserved.','Whole FDE memory write includes LR spill; writes_memory=false refers only to recorded nonnull body.']}
    (source.parent/'independent-audit.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))

if __name__=='__main__':main()
