"""Two strictly bounded staged helper/indirect-call wrapper forms.

Helper names and side effects are unknown. Stack pair reads after the helper are
not asserted to be initialized by it. Final zero-path BL is not assumed noreturn.
"""
import argparse,hashlib,json,pathlib,sys
from terraria_flow_islands import Elf
SOURCE='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
PRIOR=['unknown-native-behaviors-v1','guarded-native-behaviors-v1','native-callback-loops-v1','native-callback-loops-v2']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def template(a,end,n,width,mask):
    if n==0:
        frame=32;pro=[('sub','sp, sp, #0x20'),('stp','x19, x30, [sp, #0x10]')]
        before=[('ldrh','w9, [x2, #0x50]'),('ldr','x10, [x1]'),('mov','x8, x2'),('mov','x19, x1'),('mov','x2, sp'),('add','x9, x10, x9, lsl #4'),('ldr','x0, [x9, #0x140]'),('mov','x1, x8')]
        after=[('ldp','x8, x1, [sp]'),('mov','x0, x19'),('blr','x8')]
        restores=[('ldp','x19, x30, [sp, #0x10]')]
    else:
        frame=48;pro=[('sub','sp, sp, #0x30'),('str','x20, [sp, #0x10]'),('stp','x19, x30, [sp, #0x20]')];w='x' if width==64 else 'w'
        before=[('ldrh','w8, [x3, #0x50]'),('ldr','x9, [x1]'),('mov',f'{w}19, {w}2'),('mov','x20, x1'),('mov','x2, sp'),('add','x8, x9, x8, lsl #4'),('ldr','x0, [x8, #0x140]'),('mov','x1, x3')]
        after=[('ldp','x8, x2, [sp]'),('mov','x0, x20'),('mov',f'{w}1, {w}19'),('blr','x8')]
        restores=[('ldp','x19, x30, [sp, #0x20]'),('ldr','x20, [sp, #0x10]')]
    seq=pro+[('cbz',f'x1, #{end-4:#x}')]+before+[('bl','#0x6ff684')]+after+restores+([('and','w0, w0, #1')] if mask else [])+[('add',f'sp, sp, #0x{frame:x}'),('ret',''),('bl','#0x6ff6ac')]
    return seq,frame,len(pro),len(pro)+1+len(before)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);ap.add_argument('--out',type=pathlib.Path,required=True);a=ap.parse_args();sys.path.insert(0,str(a.lab/'python-analysis'));from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
    source=a.lab/'native/libil2cpp.so';assert sha(source)==SOURCE;e=Elf(source);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);catalog=a.lab/'native/unmapped-fde-classification.json';rows=json.loads(catalog.read_text());remaining={x['address'] for x in rows if x['category']=='unknown'};inputs={'native/libil2cpp.so':SOURCE,'native/unmapped-fde-classification.json':sha(catalog)}
    for name in PRIOR:
        path=a.lab/name/'behaviors.json';inputs[name+'/behaviors.json']=sha(path);remaining-={x['address'] for x in json.loads(path.read_text())['results']}
    results=[]
    for row in rows:
        if row['address'] not in remaining or not 76<=row['size']<=96:continue
        start=int(row['address'],16);end=int(row['end_exclusive'],16);raw=e.raw[e.at(start):e.at(end-4)+4];c=list(cs.disasm(raw,start));seq=[(x.mnemonic,x.op_str) for x in c]
        found=False
        for n,width in [(0,0),(1,32),(1,64)]:
            for mask in (False,True):
                expected,frame,guard,helper=template(start,end,n,width,mask)
                if seq!=expected:continue
                pair=helper+1;indirect=pair+2+n
                results.append({'address':row['address'],'end_exclusive':row['end_exclusive'],'source_bytes_sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'address':hex(x.address),'raw_bytes':bytes(x.bytes).hex(),'instruction':x.mnemonic+' '+x.op_str} for x in c],
                    'integer_arguments_forwarded':n,'forwarded_argument_bits':width,'common_return_lowbit_mask':mask,'frame_bytes':frame,
                    'zero_guard':hex(c[guard].address),'zero_branch_call_site':hex(end-4),'zero_branch_call_target':'0x6ff6ac','zero_call_return_continuation':hex(end),'zero_call_is_noreturn_proven':False,
                    'nonzero_helper_call_site':hex(c[helper].address),'nonzero_helper_call_target':'0x6ff684','nonzero_helper_inputs':{'x0':f'u64(u64(entry_x1) + (u16(entry_x{n+2}+0x50)<<4) + 0x140)','x1':f'entry_x{n+2}','x2':'frame_sp'},
                    'after_helper_pair_load':hex(c[pair].address),'after_helper_stack_reads':[{'register':'x8','address':'frame_sp','bytes':8,'value':'unknown post-helper memory'},{'register':'x'+str(n+1),'address':'frame_sp+8','bytes':8,'value':'unknown post-helper memory'}],
                    'indirect_call_site':hex(c[indirect].address),'indirect_call_target':'post_helper_u64(frame_sp)','indirect_call_x0':'entry_x1','indirect_forwarded_argument':None if n==0 else {'register':'x1' if width==64 else 'w1','entry_register':'x2' if width==64 else 'w2','bits':width},
                    'required_preserved_X_registers':['x19'] if n==0 else ['x19','x20'],'post_helper_volatile_register_values':'unknown except explicit subsequent writes','helper_memory_writes':'unknown','indirect_callee_memory_writes':'unknown','helper_semantics':'unknown','target_initialization_by_helper_proven':False,
                    'dependencies':['entry at exact recorded FDE start and unchanged original bytes','loads/stores complete successfully and SP points to a valid aligned frame','helper returns normally and preserves SP plus listed X registers and stack save slots','indirect target returns normally and preserves SP and original saved stack slots','zero branch helper behavior and return are unknown; if it returns, execution continues beyond selected FDE'],
                    'game_or_runtime_role':'unknown','runtime_observed':False,'baseline_modified':False});found=True;break
            if found:break
    doc={'profile':'strict-two-staged-helper-indirect-wrappers-v1','producer_sha256':sha(pathlib.Path(__file__)),'inputs':inputs,'scope_remaining_FDEs':len(remaining),'structurally_described':len(results),'remaining_after_this_family':len(remaining)-len(results),'results':results,'baseline_modified':False}
    a.out.mkdir(parents=True,exist_ok=True);(a.out/'behaviors.json').write_text(json.dumps(doc,indent=2),encoding='utf8');print(json.dumps({k:doc[k] for k in ('scope_remaining_FDEs','structurally_described','remaining_after_this_family')}))
if __name__=='__main__':main()
