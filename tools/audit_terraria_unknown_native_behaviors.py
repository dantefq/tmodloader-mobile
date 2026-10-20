"""Independent raw ARM64 decoder audit; never imports the producer's describe."""
import argparse, collections, hashlib, json, pathlib, struct
from terraria_flow_islands import Elf
from terraria_native_map import ELF

MASK=(1<<64)-1
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def sx(x,n):return x-(1<<n) if x>>(n-1) else x
def const(v):return {'kind':'constant','value':v}
def initial(n):return {'kind':'input_register','register':'x'+str(n)}

def decode(words,start):
    regs={i:initial(i) for i in range(31)};reads=[]
    def rd(n,bits):
        v=const(0) if n==31 else regs[n]
        return {'kind':'low32','value':v} if bits==32 and n!=31 else v
    def wr(n,bits,v):
        if n!=31:regs[n]={'kind':'zero_extend32' if bits==32 else 'low64','value':v}
    for index,w in enumerate(words[:-1]):
        pc=start+index*4;bits=64 if w>>31 else 32;d=w&31;n=(w>>5)&31
        if w==0xd503201f:continue
        if w&0x9f000000==0x90000000:
            v=(pc&~4095)+(sx(((w>>29)&3)|(((w>>5)&0x7ffff)<<2),21)<<12)
            wr(d,64,const(v));continue
        if w&0x9f000000==0x10000000:
            wr(d,64,const(pc+sx(((w>>29)&3)|(((w>>5)&0x7ffff)<<2),21)));continue
        if w&0x7fe0ffe0==0x2a0003e0:
            wr(d,bits,rd((w>>16)&31,bits));continue
        if w&0x7f800000 in (0x52800000,0x12800000):
            shift=((w>>21)&3)*16;assert shift<bits
            v=((w>>5)&65535)<<shift
            if w&0x7f800000==0x12800000:v=(~v)&((1<<bits)-1)
            # Capstone prints MOVN aliases with signed immediate.
            if w&0x7f800000==0x12800000 and v>>(bits-1):v-=1<<bits
            wr(d,bits,const(v));continue
        if w&0x1f000000==0x11000000 and not w&0x20000000:
            assert not w&0x00400000 and d!=31 and n!=31
            wr(d,bits,{'kind':'sub' if w&0x40000000 else 'add','lhs':rd(n,bits),'rhs':(w>>10)&4095});continue
        if w&0x7f800000==0x12000000:
            N=(w>>22)&1;imms=(w>>10)&63;immr=(w>>16)&63
            length=((N<<6)|((~imms)&63)).bit_length()-1
            assert length>=1 and (bits==64 or N==0)
            levels=(1<<length)-1;S=imms&levels;R=immr&levels;esize=1<<length
            assert S!=levels
            elem=(1<<(S+1))-1;elem=((elem>>R)|(elem<<(esize-R)))&((1<<esize)-1)
            imm=sum(elem<<j for j in range(0,bits,esize))
            wr(d,bits,{'kind':'and','lhs':rd(n,bits),'rhs':imm});continue
        if w&0x3b000000==0x39000000 and not w&0x04000000:
            size=1<<((w>>30)&3);opc=(w>>22)&3
            assert opc in (1,2,3) and n!=31
            if opc==1:dest=64 if size==8 else 32;signed=False
            else:
                assert size<8 and not(opc==3 and size>=4)
                dest=64 if opc==2 else 32;signed=True
            v={'kind':'memory_load','base':rd(n,64),'offset':((w>>10)&4095)*size,'address_bits':64,'bytes':size,'signed':signed,'result_bits':dest}
            reads.append({'address':hex(pc),'memory_read':v});wr(d,dest,v);continue
        raise ValueError('unsupported raw opcode '+hex(w)+' at '+hex(pc))
    pc=start+(len(words)-1)*4;w=words[-1]
    if w&0xfc000000==0x14000000:kind='direct_branch_forwarder';transfer={'kind':'direct_branch','target':hex(pc+sx(w&0x3ffffff,26)*4)}
    elif w&0xfffffc1f==0xd61f0000:kind='indirect_branch_forwarder';transfer={'kind':'indirect_branch','target_expression':rd((w>>5)&31,64)}
    elif w==0xd65f03c0:
        assert regs[30]==initial(30)
        kind='straight_line_return';transfer={'kind':'return','address_register':'x30','entry_x30_preserved':True,'x0_expression':regs[0]}
    else:raise ValueError('unsupported final '+hex(w))
    return kind,transfer,{'x'+str(n):v for n,v in regs.items() if v!=initial(n)},reads

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);a=ap.parse_args()
    native=a.lab/'native';out=a.lab/'unknown-native-behaviors-v1';source=out/'behaviors.json';d=json.loads(source.read_text())
    elf=Elf(native/'libil2cpp.so');raw=elf.raw;layout=ELF(raw)
    assert hashlib.sha256(raw).hexdigest()=='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
    assert d['producer_sha256']==sha(pathlib.Path(__file__).with_name('terraria_unknown_native_behaviors.py'))
    for name,digest in d['inputs'].items():assert sha(native/name)==digest
    catalog=json.loads((native/'unmapped-fde-classification.json').read_text());unknown={r['address']:r for r in catalog if r['category']=='unknown'}
    ranges={int(z.split('\t')[0],16):int(z.split('\t')[1],16) for z in (native/'unwind-function-ranges.tsv').read_text().splitlines()}
    described={r['address'] for r in d['results']};unclassified=set(d['unclassified_addresses'])
    assert len(unknown)==8140 and len(described)==len(d['results']) and len(unclassified)==len(d['unclassified_addresses'])
    assert not described&unclassified and described|unclassified==unknown.keys()
    names=collections.defaultdict(set)
    for fn in ('method-addresses.json','generic-method-addresses.json','elf-symbols.json'):
        for r in json.loads((native/fn).read_text()):
            addr=int(r.get('address') or '0',16)
            if not addr:continue
            if fn=='elf-symbols.json':
                if r['defined']:names[addr].add(r['name'])
            else:names[addr].add(r['type']+'::'+r['name'])
    # Rebuild relocation identity from section records and original dynsym bytes.
    sec={s['name']:s for s in layout.sections};rela=sec['.rela.plt'];syms=layout.sections[rela['link']];strings=layout.sections[syms['link']]
    pool=raw[strings['offset']:strings['offset']+strings['size']];got={}
    for offset in range(rela['offset'],rela['offset']+rela['size'],24):
        slot,info,addend=struct.unpack_from('<QQq',raw,offset);assert info&0xffffffff==1026
        idx=info>>32;n,attrs,other,shndx,value,size=struct.unpack_from('<IBBHQQ',raw,syms['offset']+idx*24)
        name=pool[n:pool.index(b'\0',n)].decode();assert slot not in got
        got[slot]=(offset,idx,name,bool(shndx),value,addend)
    bindings={}
    for ev in d['verified_plt_stubs']:
        addr=int(ev['address'],16);off=layout.file_offset(addr);code=raw[off:off+16];assert code.hex()==ev['raw_bytes']
        w0,w1,w2,w3=struct.unpack('<4I',code)
        assert w0&0x9f00001f==0x90000010 and w1&0xffc003ff==0xf9400211 and w2&0xffc003ff==0x91000210 and w3==0xd61f0220
        page=(addr&~4095)+(sx(((w0>>29)&3)|(((w0>>5)&0x7ffff)<<2),21)<<12)
        slot=page+((w1>>10)&4095)*8;assert page+((w2>>10)&4095)==slot
        offset,idx,name,defined,value,addend=got[slot]
        assert ev=={'address':hex(addr),'got_slot':hex(slot),'relocation_file_offset':hex(offset),'dynsym_index':idx,'symbol_name':name,'symbol_defined':defined,'symbol_value':hex(value),'relocation_addend':addend,'raw_bytes':code.hex()}
        assert addr not in bindings;bindings[addr]=name
    assert set(bindings)==set(range(sec['.plt']['vaddr']+32,sec['.plt']['vaddr']+sec['.plt']['size'],16)) and len(bindings)==len(got)==560
    # Ensure this auditor refuses side effects and flow excluded by the profile.
    negative_controls={'store':0xf9000020,'call':0x94000000,'conditional_branch':0x54000000,
                       'flags_update':0xb1000400,'stack_register_arithmetic':0x910003e0}
    for label,word in negative_controls.items():
        try:decode([word,0xd65f03c0],0x1000)
        except (AssertionError,ValueError):pass
        else:raise AssertionError('Auditor accepted forbidden '+label)
    counts=collections.Counter();bytecount=0;named=0
    for r in d['results']:
        entry=unknown[r['address']];start=int(r['address'],16);end=int(r['end_exclusive'],16)
        assert r['end_exclusive']==entry['end_exclusive'] and end-start==entry['size'] and ranges[start]==end and 4<=end-start<=64
        code=raw[elf.at(start):elf.at(end-4)+4];assert len(code)==end-start and hashlib.sha256(code).hexdigest()==r['source_bytes_sha256']
        assert len(r['instructions'])*4==len(code)
        for j,ins in enumerate(r['instructions']):assert ins['address']==hex(start+4*j) and ins['raw_bytes']==code[j*4:j*4+4].hex()
        words=struct.unpack('<'+'I'*(len(code)//4),code);kind,transfer,changes,reads=decode(words,start)
        assert r['structural_behavior']==kind and r['register_changes']==changes and r['ordered_memory_reads']==reads,hex(start)
        for key,val in transfer.items():assert r['transfer'][key]==val,(hex(start),key)
        assert r['writes_memory'] is False and r['contains_calls_or_conditional_branches'] is False and r['game_or_runtime_role']=='unknown' and r['runtime_observed'] is False and r['function_prototype_recovered'] is False
        if kind=='direct_branch_forwarder':
            t=r['transfer'];target=int(t['target'],16);assert not start<=target<end and (target in ranges or target in bindings)
            assert t['target_names']==sorted(names[target]) and t['target_is_exact_fde_start']==(target in ranges)
            endpoint=target;seen=set();chain=[]
            while endpoint in ranges and not names[endpoint] and endpoint not in bindings and len(chain)<16:
                if endpoint in seen or ranges[endpoint]-endpoint!=4:break
                seen.add(endpoint);w=elf.word(endpoint)
                if w&0xfc000000!=0x14000000:break
                dest=endpoint+sx(w&0x3ffffff,26)*4;chain.append({'address':hex(endpoint),'raw_bytes':struct.pack('<I',w).hex(),'target':hex(dest)});endpoint=dest
            assert t['pure_B_chain']==chain and t['endpoint']=={'address':hex(endpoint),'managed_or_elf_names':sorted(names[endpoint]),'plt_relocation_symbol_name':bindings.get(endpoint),'runtime_binding_verified':False}
            named+=bool(names[endpoint] or bindings.get(endpoint))
        counts[kind]+=1;bytecount+=len(code)
    assert counts==d['behavior_counts'] and named==d['named_forwarding_endpoints']
    assert d['structurally_described']==len(described) and d['structurally_unclassified']==len(unclassified) and d['semantic_role_still_unknown']==8140
    result={'integrity_passed':True,'audit_profile':'independent-raw-arm64-symbolic-expression-audit-v1','auditor_sha256':sha(pathlib.Path(__file__)),'behaviors_sha256':sha(source),'described_functions':len(described),'unclassified_functions':len(unclassified),'semantic_role_still_unknown':8140,'behavior_counts':dict(counts),'named_endpoints':named,'verified_source_instruction_bytes':bytecount,'verified_plt_stubs':len(bindings),'negative_controls_rejected':list(negative_controls),'verification':'Exact raw-decoded symbolic expressions, register widths, load sizes/sign extension, ordered memory reads, original FDE partition, relocation/dynsym endpoints. No producer decoder imported.','limitations':['Static instruction semantics only; reachability and runtime role remain unknown.','Expression arithmetic uses explicitly declared low64/zero_extend32 truncation and 64-bit memory addresses; memory loads can fault.','Excluded addresses are partition-checked, not asserted impossible to classify.']}
    (out/'independent-audit.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))

if __name__=='__main__':main()
