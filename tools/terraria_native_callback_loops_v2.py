"""Strict SIMD forwarding counted callback-loop family; original ELF, no DB edits.

No delegate/object layout attribution. The count and cursor recurrence is conditional
on callbacks returning and preserving the recorded callee-saved registers.
"""
import argparse, collections, hashlib, json, pathlib, re, sys
from terraria_flow_islands import Elf

ELF_SHA='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def save_restore(pointer):
    regs=list(range(pointer,18,-1))+[30]
    frame=((len(regs)*8+15)//16)*16
    groups=[]
    if len(regs)%2:groups.append(regs[:1]);regs=regs[1:]
    groups.extend(regs[i:i+2] for i in range(0,len(regs),2))
    pro=[];epi=[];slots=[]
    for index,g in enumerate(groups):
        off=index*16;rs=', '.join('x'+str(x) for x in g)
        mem=f'[sp, #-0x{frame:x}]!' if index==0 else f'[sp, #0x{off:x}]'
        pro.append(('str' if len(g)==1 else 'stp',rs+', '+mem))
        mem=f'[sp], #0x{frame:x}' if index==0 else f'[sp, #0x{off:x}]'
        epi.insert(0,('ldr' if len(g)==1 else 'ldp',rs+', '+mem))
        slots.extend({'register':'x'+str(r),'frame_offset':off+j*8,'bytes':8} for j,r in enumerate(g))
    return pro,epi,frame,slots

def stack_prefix(seq):
    p=next(i for i,x in enumerate(seq) if x==('ldr','x8, [x0, #0x78]'))
    slots=[];epi=[];frame=None;used=set()
    for i,(mn,s) in enumerate(seq[:p]):
        if mn not in ('str','stp'):raise ValueError('Non-store prologue')
        m=re.fullmatch(r'([xd]\d+)(?:, ([xd]\d+))?, \[sp, #(-?0x[0-9a-f]+|[0-9]+)\](!?)',s)
        if not m or bool(m[2])!=(mn=='stp'):raise ValueError('Unexpected save')
        regs=[m[1]]+([m[2]] if m[2] else []);off=int(m[3],0)
        if i==0:
            if not m[4] or off>=0 or off%16:raise ValueError('Stack frame')
            frame=-off;off=0;restore=f'[sp], #0x{frame:x}'
        else:
            if m[4] or off<0:raise ValueError('Unexpected writeback')
            restore=s[s.index('[sp'):]
        for j,reg in enumerate(regs):
            if off+j*8 in used or off+j*8+8>frame:raise ValueError('Overlapping saves')
            used.add(off+j*8);slots.append({'register':reg,'frame_offset':off+j*8,'bytes':8})
        epi.insert(0,('ldr' if mn=='str' else 'ldp',', '.join(regs)+', '+restore))
    return p,epi,frame,slots

def match(code):
    seq=[(x.mnemonic,x.op_str) for x in code]
    try:p,epi,frame,slots=stack_prefix(seq)
    except (ValueError,StopIteration):return None
    for ptr in range(20,28):
        n=ptr-20;cnt=ptr-1
        if seq[p:p+2]!=[('ldr','x8, [x0, #0x78]'),('ldr',f'x{cnt}, [x8, #0x18]')]:continue
        k=p+2
        if seq[k][0]!='cbz' or seq[k][1].split(', ')[0]!=f'x{cnt}':continue
        zero=int(seq[k][1].split('#')[1],16);k+=1
        widths={};vectors={};ok=True
        while seq[k][0]=='mov':
            m=re.fullmatch(r'([xw])(\d+), ([xw])(\d+)',seq[k][1])
            v=re.fullmatch(r'v(\d+)\.16b, v(\d+)\.16b',seq[k][1])
            if m and m[1]==m[3] and 1<=int(m[4])<=n and int(m[2])==cnt-int(m[4]) and int(m[4]) not in widths:
                widths[int(m[4])]=m[1]
            elif v and 8<=int(v[1])<=15 and 0<=int(v[2])<=7 and int(v[2]) not in vectors and int(v[1]) not in vectors.values():vectors[int(v[2])]=int(v[1])
            else:ok=False;break
            k+=1
        if not ok or set(widths)!=set(range(1,n+1)) or not vectors or seq[k]!=('add',f'x{ptr}, x8, #0x20'):continue
        if {s['register'] for s in slots}!={f'x{i}' for i in range(19,ptr+1)}|{'x30'}|{f'd{i}' for i in vectors.values()}:continue
        k+=1;loop=k
        if seq[k]!=('ldr',f'x8, [x{ptr}], #8'):continue
        k+=1
        expected=[('mov',f'{widths[a]}{a}, {widths[a]}{cnt-a}') for a in range(1,n+1)]
        expected += [('mov',f'v{arg}.16b, v{saved}.16b') for arg,saved in vectors.items()]
        expected += [('ldr','x9, [x8, #0x18]'),('ldr','x0, [x8, #0x40]'),('ldr',f'x{n+1}, [x8, #0x28]')]
        body=seq[k:k+len(expected)]
        if collections.Counter(body)!=collections.Counter(expected):continue
        if n+1==8 and body[-1]!=('ldr','x8, [x8, #0x28]'):continue
        # All register forwarding precedes BLR; no expected operation overwrites x8/x9.
        k+=len(expected);call=k
        if seq[k:k+3]!=[('blr','x9'),('subs',f'x{cnt}, x{cnt}, #1'),('b.ne',f'#{code[loop].address:#x}')]:continue
        k+=3;nonzero=k;zero_value=None
        if seq[k][0]=='b':
            endzero=int(seq[k][1][1:],16);k+=1
            if code[k].address!=zero or seq[k] not in [('mov','x0, xzr'),('mov','w0, wzr')]:continue
            zero_value=seq[k][1];k+=1
            if code[k].address!=endzero:continue
        elif code[k].address!=zero:continue
        epistart=k
        # AND W0 is emitted among restoration loads in some boolean-shaped wrappers.
        suffix=seq[k:];mask=[i for i,x in enumerate(suffix) if x==('and','w0, w0, #1')]
        if len(mask)>1:continue
        if mask:suffix=[x for x in suffix if x!=('and','w0, w0, #1')]
        if suffix!=epi+[('ret','')]:continue
        return {'count_register':f'x{cnt}','cursor_register':f'x{ptr}',
                'entry_table_load':hex(code[p].address),'count_load':hex(code[p+1].address),
                'zero_branch':hex(code[p+2].address),'zero_target':hex(zero),
                'loop_header':hex(code[loop].address),'call_site':hex(code[call].address),
                'decrement':hex(code[call+1].address),'backedge':hex(code[call+2].address),
                'epilogue':hex(code[epistart].address),'frame_bytes':frame,'saved_register_slots':slots,
                'forwarded_integer_arguments':[{'callback_register':widths[a]+str(a),'entry_register':widths[a]+str(a),'preserved_register':widths[a]+str(cnt-a),'bits':64 if widths[a]=='x' else 32} for a in range(1,n+1)],
                'forwarded_vector_registers':[{'callback_register':f'v{arg}','entry_register':f'v{arg}','saved_register':f'v{saved}','move_bits':128,'caller_stack_saved_bits':64,'low64_stable_requires':f'callback preserves d{saved}','full128_stable_requires':f'callback preserves all128 bits of v{saved}'} for arg,saved in sorted(vectors.items())],
                'context_register':'x'+str(n+1),'zero_path_x0':'entry_x0' if zero_value is None else 'zero',
                'common_return_lowbit_mask':bool(mask),
                'required_preserved_callback_registers':[f'x{i}' for i in range(19,ptr+1)],
                'callback_argument_loads':{'target':'u64(entry_pointer + 0x18)','x0':'u64(entry_pointer + 0x40)','context':'u64(entry_pointer + 0x28)'},
                'recurrence':{'initial_count':'u64(u64(entry_x0+0x78)+0x18)','initial_cursor':'u64(entry_x0+0x78)+0x20','count_after_return':'(count_before_call-1) mod 2^64','cursor_increment_bytes':8,'repeat_condition':'count_after_return != 0'},
                'zero_count_callback_calls':0,'nonzero_count_callback_calls':'initial unsigned 64-bit count, only under listed dependencies',
                'dependencies':['entry at recorded FDE start; original bytes unchanged','all loads/stores complete; valid aligned stack; stack save slots not corrupted','each indirect callback returns normally to the instruction after BLR','each callback preserves the listed X19..Xcursor registers and SP; no concurrent register changes','future callback targets, X0 and context are loaded afresh; callbacks may mutate table memory','stable low64 vector forwarding requires preservation of listed D8..D15; stable full128 forwarding needs stronger all128 preservation, not implied by usual AAPCS64'],
                'claims_not_made':['runtime reachability','callback termination','unconditional finite loop','gameplay role or delegate/object type','full callee ABI or callback prototype','semantic equivalence with original source'],
                'game_or_runtime_role':'unknown','runtime_observed':False}
    return None

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);ap.add_argument('--out',type=pathlib.Path,required=True);a=ap.parse_args()
    sys.path.insert(0,str(a.lab/'python-analysis'))
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
    source=a.lab/'native/libil2cpp.so';e=Elf(source)
    if sha(source)!=ELF_SHA:raise ValueError('ELF source mismatch')
    baseline=a.lab/'unknown-native-behaviors-v1/behaviors.json';b=json.loads(baseline.read_text());rem=set(b['unclassified_addresses'])
    v1=a.lab/'native-callback-loops-v1/behaviors.json';guard=a.lab/'guarded-native-behaviors-v1/behaviors.json'
    for path in (v1,guard):rem-={x['address'] for x in json.loads(path.read_text())['results']}
    catalog=a.lab/'native/unmapped-fde-classification.json';rows=json.loads(catalog.read_text());cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
    results=[]
    for r in rows:
        if r['address'] not in rem or r['size']>256 or r['size']<48:continue
        start=int(r['address'],16);end=int(r['end_exclusive'],16);raw=e.raw[e.at(start):e.at(end-4)+4];c=list(cs.disasm(raw,start))
        if len(c)*4!=len(raw):continue
        try:d=match(c)
        except (IndexError,ValueError):continue
        if d:results.append({'address':r['address'],'end_exclusive':r['end_exclusive'],'source_bytes_sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'address':hex(x.address),'raw_bytes':bytes(x.bytes).hex(),'instruction':x.mnemonic+' '+x.op_str} for x in c],**d})
    doc={'profile':'unknown-native-counted-simd-forwarding-callback-loops-v2','producer_sha256':sha(pathlib.Path(__file__)),'inputs':{'libil2cpp.so':ELF_SHA,'unknown-native-behaviors-v1/behaviors.json':sha(baseline),'native/unmapped-fde-classification.json':sha(catalog),'native-callback-loops-v1/behaviors.json':sha(v1),'guarded-native-behaviors-v1/behaviors.json':sha(guard)},'scope_remaining_FDEs':len(rem),'structurally_described':len(results),'remaining_after_this_family':len(rem)-len(results),'results':results,'baseline_modified':False,'all_callback_dependencies_runtime_verified':False}
    a.out.mkdir(parents=True,exist_ok=True);(a.out/'behaviors.json').write_text(json.dumps(doc,indent=2),encoding='utf8');print(json.dumps({k:v for k,v in doc.items() if k not in ('results','inputs')}))
if __name__=='__main__':main()
