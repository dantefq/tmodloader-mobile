"""Independent raw-word validation of SIMD callback loops (no Capstone/matcher).

Register IDs32..63 denote D0..D31 in stack operations, never X registers.
"""
import argparse, collections, hashlib, json, pathlib, struct
from terraria_flow_islands import Elf
SOURCE_SHA='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def sx(n,b):return n-(1<<b) if n&(1<<(b-1)) else n

def op(w,pc):
    d=w&31;n=w>>5&31
    if w&0xffe0fc00==0x4ea01c00:
        m=w>>16&31
        assert m==n
        return ('vmove',d,n)
    if w==0xd65f03c0:return ('ret',)
    if w&0xfffffc1f==0xd63f0000:return ('call_register',n)
    if w&0xff000000==0xb4000000:return ('zero_branch',d,pc+sx(w>>5&0x7ffff,19)*4)
    if w&0xff00001f==0x54000001:return ('nonzero_branch',pc+sx(w>>5&0x7ffff,19)*4)
    if w&0xfc000000==0x14000000:return ('branch',pc+sx(w&0x3ffffff,26)*4)
    if w&0xffe0ffe0 in (0xaa0003e0,0x2a0003e0):return ('move',64 if w>>31 else 32,d,w>>16&31)
    if w&0xffc00000==0x91000000:return ('add',d,n,w>>10&4095)
    if w&0xffc00000==0xf1000000:return ('subtract_flags',d,n,w>>10&4095)
    # AND W0,W0,#1: fixed instruction permits no altered bit masks/registers.
    if w==0x12000000:return ('mask_return_bit',)
    if w&0xffc00000 in (0xf9400000,0xf9000000):return ('load' if w&0x400000 else 'store',8,d,n,(w>>10&4095)*8,'offset')
    if w&0xffc00000 in (0xfd400000,0xfd000000):return ('load' if w&0x400000 else 'store',8,d+32,n,(w>>10&4095)*8,'offset')
    if w&0xffe00c00 in (0xf8400400,0xf8000c00):return ('load' if w&0x400000 else 'store',8,d,n,sx(w>>12&511,9),'post' if w&0xc00==0x400 else 'pre')
    if w&0xffe00c00 in (0xfc400400,0xfc000c00):return ('load' if w&0x400000 else 'store',8,d+32,n,sx(w>>12&511,9),'post' if w&0xc00==0x400 else 'pre')
    head=w&0xffc00000
    if head in (0xa9800000,0xa9000000,0xa8c00000,0xa9400000):
        kind='load_pair' if head in (0xa8c00000,0xa9400000) else 'store_pair'
        return (kind,8,d,w>>10&31,n,sx(w>>15&127,7)*8,{0xa9800000:'pre',0xa9000000:'offset',0xa8c00000:'post',0xa9400000:'offset'}[head])
    if head in (0x6d800000,0x6d000000,0x6cc00000,0x6d400000):
        return ('load_pair' if head in (0x6cc00000,0x6d400000) else 'store_pair',8,d+32,(w>>10&31)+32,n,sx(w>>15&127,7)*8,{0x6d800000:'pre',0x6d000000:'offset',0x6cc00000:'post',0x6d400000:'offset'}[head])
    raise ValueError(f'Unapproved raw instruction {w:#x} at {pc:#x}')

def audit_row(r,e):
    a=int(r['address'],16);end=int(r['end_exclusive'],16);raw=e.raw[e.at(a):e.at(end-4)+4]
    assert hashlib.sha256(raw).hexdigest()==r['source_bytes_sha256']
    assert len(r['instructions'])*4==len(raw)
    decoded={}
    for ix,x in enumerate(r['instructions']):
        pc=a+ix*4;assert x['address']==hex(pc) and x['raw_bytes']==raw[ix*4:ix*4+4].hex()
        decoded[pc]=op(struct.unpack_from('<I',raw,ix*4)[0],pc)
    # Decode entry/count/cursor from raw load and ADD, then independently check
    # the supplied recurrence registers and all critical control edges.
    t=int(r['entry_table_load'],16);c=int(r['count_load'],16);z=int(r['zero_branch'],16);loop=int(r['loop_header'],16);call=int(r['call_site'],16)
    cnt=decoded[c][2];ptr=decoded[loop][3];n=ptr-20
    assert 19<=cnt<=26 and ptr==cnt+1 and 0<=n<=7
    assert r['count_register']=='x'+str(cnt) and r['cursor_register']=='x'+str(ptr)
    assert decoded[t]==('load',8,8,0,120,'offset') and c==t+4
    assert decoded[c]==('load',8,cnt,8,24,'offset') and z==c+4
    assert decoded[z]==('zero_branch',cnt,int(r['zero_target'],16))
    assert decoded[loop]==('load',8,8,ptr,8,'post')
    assert decoded[loop-4]==('add',ptr,8,32)
    assert decoded[call]==('call_register',9)
    assert decoded[call+4]==('subtract_flags',cnt,cnt,1)
    assert decoded[call+8]==('nonzero_branch',loop)
    assert r['decrement']==hex(call+4) and r['backedge']==hex(call+8)
    # Stack saves are checked by raw execution of effective addresses. Restores
    # must read the exact saved offsets and restore all bytes of every X register.
    sp=0;slots={};consumed=set()
    for pc in range(a,t,4):
        x=decoded[pc];assert x[0] in ('store','store_pair')
        if x[0]=='store':_,size,d,base,disp,mode=x;regs=[d]
        else:_,size,d,d2,base,disp,mode=x;regs=[d,d2]
        assert base==31 and mode in ('pre','offset')
        if mode=='pre':sp+=disp;off=sp
        else:off=sp+disp
        for j,reg in enumerate(regs):assert off+j*8 not in slots;slots[off+j*8]=reg
        consumed.add(pc)
    assert sp==-r['frame_bytes'] and sp%16==0
    proofslots={(x['frame_offset']+sp,x['register'],x['bytes']) for x in r['saved_register_slots']}
    assert proofslots=={(off,('x'+str(reg) if reg<32 else 'd'+str(reg-32)),8) for off,reg in slots.items()}
    saved_args={};vectors={};seen=set()
    for pc in range(z+4,loop-4,4):
        x=decoded[pc]
        if x[0]=='move':
            _,bits,d,s=x;assert 1<=s<=n and d==cnt-s and s not in saved_args;saved_args[s]=bits
        else:
            assert x[0]=='vmove';_,d,s=x;assert 8<=d<=15 and 0<=s<=7 and s not in vectors and d not in vectors.values();vectors[s]=d
        consumed.add(pc)
    assert set(saved_args)==set(range(1,n+1))
    assert vectors and set(slots.values())==set(range(19,ptr+1))|{30}|{x+32 for x in vectors.values()}
    expected=collections.Counter([('move',bits,arg,cnt-arg) for arg,bits in saved_args.items()]+[('vmove',arg,save) for arg,save in vectors.items()]+[('load',8,9,8,24,'offset'),('load',8,0,8,64,'offset'),('load',8,n+1,8,40,'offset')])
    assert collections.Counter(decoded[pc] for pc in range(loop+4,call,4))==expected
    # A context delivered in X8 overwrites the entry pointer; this must be last.
    if n+1==8:assert decoded[call-4]==('load',8,8,8,40,'offset')
    forwarded=[{'callback_register':('x' if b==64 else 'w')+str(arg),'entry_register':('x' if b==64 else 'w')+str(arg),'preserved_register':('x' if b==64 else 'w')+str(cnt-arg),'bits':b} for arg,b in sorted(saved_args.items())]
    assert r['forwarded_integer_arguments']==forwarded and r['context_register']=='x'+str(n+1)
    assert r['forwarded_vector_registers']==[{'callback_register':f'v{arg}','entry_register':f'v{arg}','saved_register':f'v{saved}','move_bits':128,'caller_stack_saved_bits':64,'low64_stable_requires':f'callback preserves d{saved}','full128_stable_requires':f'callback preserves all128 bits of v{saved}'} for arg,saved in sorted(vectors.items())]
    consumed.update(range(t,z+4,4));consumed.add(loop-4);consumed.update(range(loop,call+12,4))
    pc=call+12;zero=int(r['zero_target'],16)
    if decoded[pc][0]=='branch':
        assert zero==pc+4;target=decoded[pc][1];m=decoded[pc+4]
        assert m in [('move',64,0,31),('move',32,0,31)] and target==pc+8
        assert r['zero_path_x0']=='zero';consumed.update((pc,pc+4));pc+=8
    else:assert zero==pc and r['zero_path_x0']=='entry_x0'
    assert r['epilogue']==hex(pc);restored=set();masked=False
    while pc<end-4:
        x=decoded[pc]
        if x==('mask_return_bit',):assert not masked;masked=True
        else:
            assert x[0] in ('load','load_pair')
            if x[0]=='load':_,size,d,base,disp,mode=x;regs=[d]
            else:_,size,d,d2,base,disp,mode=x;regs=[d,d2]
            assert base==31 and mode in ('post','offset');off=sp if mode=='post' else sp+disp
            for j,reg in enumerate(regs):assert slots.get(off+j*8)==reg and reg not in restored;restored.add(reg)
            if mode=='post':sp+=disp
        consumed.add(pc);pc+=4
    assert decoded[pc]==('ret',) and sp==0 and restored==set(slots.values());consumed.add(pc)
    assert consumed==set(decoded) and masked==r['common_return_lowbit_mask']
    assert r['required_preserved_callback_registers']==['x'+str(i) for i in range(19,ptr+1)]
    assert r['zero_count_callback_calls']==0 and len(r['dependencies'])==6 and not r['runtime_observed']
    return len(raw)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);ap.add_argument('--out',type=pathlib.Path,required=True);a=ap.parse_args()
    p=a.out/'behaviors.json';doc=json.loads(p.read_text());e=Elf(a.lab/'native/libil2cpp.so');assert hashlib.sha256(e.raw).hexdigest()==SOURCE_SHA
    for rel,h in doc['inputs'].items():assert sha(a.lab/('native/libil2cpp.so' if rel=='libil2cpp.so' else rel))==h
    rem=set(json.loads((a.lab/'unknown-native-behaviors-v1/behaviors.json').read_text())['unclassified_addresses'])
    for rel in ('native-callback-loops-v1/behaviors.json','guarded-native-behaviors-v1/behaviors.json'):rem-={x['address'] for x in json.loads((a.lab/rel).read_text())['results']}
    catalog={r['address']:r for r in json.loads((a.lab/'native/unmapped-fde-classification.json').read_text())};seen=set();size=0
    for r in doc['results']:
        assert r['address'] in rem and r['address'] not in seen;seen.add(r['address']);assert r['end_exclusive']==catalog[r['address']]['end_exclusive'];size+=audit_row(r,e)
    assert len(seen)==doc['structurally_described'] and len(rem)==doc['scope_remaining_FDEs'] and len(rem)-len(seen)==doc['remaining_after_this_family']
    out={'integrity_passed':True,'profile':'independent-raw-arm64-simd-forwarding-callback-loop-audit-v2','auditor_sha256':sha(pathlib.Path(__file__)),'behaviors_sha256':sha(p),'source_elf_sha256':SOURCE_SHA,'functions_verified':len(seen),'instruction_bytes_verified':size,'instruction_rows_verified':size//4,'capstone_used':False,'producer_matcher_imported':False,'runtime_or_callee_semantics_proven':False}
    (a.out/'independent-audit.json').write_text(json.dumps(out,indent=2),encoding='utf8');print(json.dumps(out))
if __name__=='__main__':main()
