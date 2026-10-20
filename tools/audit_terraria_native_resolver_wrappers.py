"""Independent raw ARM64 encodings for strict wrapper forms; no matcher/Capstone.

Expected encodings are assembled here from ARM64 integer instruction fields and
compared with every source word. This validates only the two stated templates.
"""
import argparse,copy,hashlib,json,pathlib,struct
from terraria_flow_islands import Elf
SOURCE='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def mov(d,s,b=64):return (0xaa0003e0 if b==64 else 0x2a0003e0)|(s<<16)|d
def mem(load,d,n,off=0,half=False):
    scale=2 if half else 8;assert off>=0 and off%scale==0 and off//scale<4096
    return (0x79400000 if half else 0xf9400000 if load else 0xf9000000)|((off//scale)<<10)|(n<<5)|d
def pair(load,d,e,off):
    assert off%8==0 and -512<=off<512
    return (0xa9400000 if load else 0xa9000000)|(((off//8)&127)<<15)|(e<<10)|(31<<5)|d
def rel(pc,target,bits):
    delta=target-pc;assert delta%4==0 and -(1<<(bits-1))<=delta//4<1<<(bits-1);return delta//4&((1<<bits)-1)
def words(a,n,bits,mask):
    frame=32 if n==0 else 48
    out=[0xd10003ff|(frame<<10)]
    if n:out.append(mem(False,20,31,16))
    out.append(pair(False,19,30,16 if n==0 else 32));guard=len(out);out.append(0)
    if not n:out += [mem(True,9,2,80,True),mem(True,10,1),mov(8,2),mov(19,1),0x910003e2,0x8b000000|(9<<16)|(4<<10)|(10<<5)|9,mem(True,0,9,320),mov(1,8)]
    else:out += [mem(True,8,3,80,True),mem(True,9,1),mov(19,2,bits),mov(20,1),0x910003e2,0x8b000000|(8<<16)|(4<<10)|(9<<5)|8,mem(True,0,8,320),mov(1,3)]
    helper=len(out);out.append(0x94000000|rel(a+helper*4,0x6ff684,26));loaded=len(out)
    out += [pair(True,8,n+1,0),mov(0,19 if n==0 else 20)]
    if n:out.append(mov(1,19,bits))
    indirect=len(out);out.append(0xd63f0100);out.append(pair(True,19,30,16 if n==0 else 32))
    if n:out.append(mem(True,20,31,16))
    if mask:out.append(0x12000000)
    out += [0x910003ff|(frame<<10),0xd65f03c0]
    zero=len(out);out.append(0x94000000|rel(a+zero*4,0x6ff6ac,26));out[guard]=0xb4000001|(rel(a+guard*4,a+zero*4,19)<<5)
    return out,frame,guard,helper,loaded,indirect
def audit_row(r,e):
    start=int(r['address'],16);end=int(r['end_exclusive'],16);n=r['integer_arguments_forwarded'];bits=r['forwarded_argument_bits'];mask=r['common_return_lowbit_mask'];assert (n,bits) in ((0,0),(1,32),(1,64)) and type(mask) is bool
    expected,frame,guard,helper,loaded,indirect=words(start,n,bits,mask);raw=e.raw[e.at(start):e.at(end-4)+4]
    assert len(raw)==len(expected)*4 and hashlib.sha256(raw).hexdigest()==r['source_bytes_sha256'] and list(struct.unpack('<'+'I'*len(expected),raw))==expected
    assert len(r['instructions'])==len(expected)
    for ix,item in enumerate(r['instructions']):assert item['address']==hex(start+ix*4) and item['raw_bytes']==raw[ix*4:ix*4+4].hex()
    assert r['frame_bytes']==frame and r['zero_guard']==hex(start+guard*4) and r['zero_branch_call_site']==hex(end-4) and r['zero_branch_call_target']=='0x6ff6ac' and r['zero_call_return_continuation']==hex(end) and r['zero_call_is_noreturn_proven'] is False
    assert r['nonzero_helper_call_site']==hex(start+helper*4) and r['nonzero_helper_call_target']=='0x6ff684' and r['nonzero_helper_inputs']=={'x0':f'u64(u64(entry_x1) + (u16(entry_x{n+2}+0x50)<<4) + 0x140)','x1':f'entry_x{n+2}','x2':'frame_sp'}
    assert r['after_helper_pair_load']==hex(start+loaded*4) and r['after_helper_stack_reads']==[{'register':'x8','address':'frame_sp','bytes':8,'value':'unknown post-helper memory'},{'register':'x'+str(n+1),'address':'frame_sp+8','bytes':8,'value':'unknown post-helper memory'}]
    assert r['indirect_call_site']==hex(start+indirect*4) and r['indirect_call_target']=='post_helper_u64(frame_sp)' and r['indirect_call_x0']=='entry_x1'
    assert r['indirect_forwarded_argument']==(None if n==0 else {'register':'x1' if bits==64 else 'w1','entry_register':'x2' if bits==64 else 'w2','bits':bits})
    assert r['required_preserved_X_registers']==(['x19'] if n==0 else ['x19','x20']) and r['post_helper_volatile_register_values']=='unknown except explicit subsequent writes'
    assert r['helper_memory_writes']=='unknown' and r['indirect_callee_memory_writes']=='unknown' and r['helper_semantics']=='unknown' and r['target_initialization_by_helper_proven'] is False and r['runtime_observed'] is False and len(r['dependencies'])==5
    return len(raw)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);ap.add_argument('--out',type=pathlib.Path,required=True);a=ap.parse_args();p=a.out/'behaviors.json';d=json.loads(p.read_text());e=Elf(a.lab/'native/libil2cpp.so');assert hashlib.sha256(e.raw).hexdigest()==SOURCE
    for rel,h in d['inputs'].items():assert sha(a.lab/rel)==h
    catalog={r['address']:r for r in json.loads((a.lab/'native/unmapped-fde-classification.json').read_text())};remaining={address for address,row in catalog.items() if row['category']=='unknown'}
    for rel in d['inputs']:
        if rel.endswith('/behaviors.json'):remaining-={r['address'] for r in json.loads((a.lab/rel).read_text())['results']}
    seen=set();size=0
    for r in d['results']:
        assert r['address'] in remaining and r['address'] not in seen and r['end_exclusive']==catalog[r['address']]['end_exclusive'];seen.add(r['address']);size+=audit_row(r,e)
    assert len(remaining)==d['scope_remaining_FDEs'] and len(seen)==d['structurally_described'] and len(remaining)-len(seen)==d['remaining_after_this_family']
    sample=next(r for r in d['results'] if r['integer_arguments_forwarded']==1);checks=[]
    mutations=[('false_noreturn',lambda r:r.update(zero_call_is_noreturn_proven=True)),('invented_helper_write',lambda r:r.update(helper_memory_writes='initializes target')),('false_stack_read',lambda r:r['after_helper_stack_reads'][0].update(address='frame_sp+16')),('invented_helper_input',lambda r:r['nonzero_helper_inputs'].update(x0='entry_x0')),('false_forwarded_width',lambda r:r.update(forwarded_argument_bits=64 if r['forwarded_argument_bits']==32 else 32)),('missing_instruction',lambda r:r['instructions'].pop())]
    for label,mutate in mutations:
        changed=copy.deepcopy(sample);mutate(changed)
        try:audit_row(changed,e)
        except (AssertionError,ValueError,IndexError,KeyError):checks.append({'case':label,'rejected':True})
        else:raise AssertionError('Negative fixture was accepted: '+label)
    class ChangedELF:at=e.at
    for label,address,word in [('wrong_indirect_register',int(sample['indirect_call_site'],16),0xd63f0120),('wrong_final_zero_helper',int(sample['zero_branch_call_site'],16),0x94000000)]:
        altered=ChangedELF();altered.raw=bytearray(e.raw);struct.pack_into('<I',altered.raw,e.at(address),word);changed=copy.deepcopy(sample);start=int(changed['address'],16);end=int(changed['end_exclusive'],16);changed['instructions'][(address-start)//4]['raw_bytes']=struct.pack('<I',word).hex();changed['source_bytes_sha256']=hashlib.sha256(altered.raw[e.at(start):e.at(end-4)+4]).hexdigest()
        try:audit_row(changed,altered)
        except (AssertionError,ValueError,IndexError,KeyError):checks.append({'case':label,'rejected':True})
        else:raise AssertionError('Negative raw fixture was accepted: '+label)
    (a.out/'negative-audit-checks.json').write_text(json.dumps({'passed':True,'auditor_sha256':sha(pathlib.Path(__file__)),'cases':checks,'original_source_or_proof_modified':False},indent=2),encoding='utf8')
    result={'integrity_passed':True,'profile':'independent-exact-arm64-template-encoding-wrapper-audit-v1','auditor_sha256':sha(pathlib.Path(__file__)),'behaviors_sha256':sha(p),'source_sha256':SOURCE,'functions_verified':len(seen),'instruction_bytes_verified':size,'instruction_rows_verified':size//4,'capstone_used':False,'producer_matcher_imported':False,'helper_side_effects_or_callee_behavior_proven':False}
    (a.out/'independent-audit.json').write_text(json.dumps(result,indent=2),encoding='utf8');print(json.dumps(result))
if __name__=='__main__':main()
