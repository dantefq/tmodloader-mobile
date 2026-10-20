"""Independent source/result integrity audit, not observation of Ghidra internals.

Use on a fresh run from a disposable read-only project copy. No producer imports.
--self-test runs only synthetic manifest/encoding controls, never Ghidra.
"""
import argparse,copy,hashlib,json,mmap,pathlib,struct
ELF='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
ENGINE='1fd85827247f1ff1417fa412db26a53066d050c59017db98dd23ff196751521e'
PARENT='65f3e4f2fbc3c2965c9b2a49dced2c6e5042a2b156eaccc2badc42a4a60ceecb'
PROOF='04d8474fa751442c6fc2f01e1d11c40bba282e6e1ea04222e62a9a38e7f78245'
MODEL='conditional-standard-cxx-throw-noreturn-aggregate-unsplit-typed-v4-stack32-v1'
HELPERS={0x6ff6ac,0x741278,0x74128c,0x7411e0}
HEADER='/* ADDITIONAL CONDITIONAL MODEL: standard __cxa_throw has no normal return; no exceptional/nonlocal wrapper reentry; four helper NoReturn annotations plus aggregate-copy splitting disabled. ABI contract is assumed. Not original source, global-guard-dominance, runtime or semantic-equivalence proof. */\n'
def sha(b):return hashlib.sha256(b).hexdigest()
def integer(value):return int(value,0) if isinstance(value,str) else int(value)
def need(ok,message):
    if not ok:raise ValueError(message)
def check_annotations(r):
    need(r['profile']==MODEL,'model profile')
    for k in ('noreturn_contract_is_assumption','nullguard_has_noreturn_annotation_expected_during_parent','outer_annotation_rollback_requested','read_only_disposable_project_lifecycle_required','annotation_transaction_close_returned','explicit_annotation_restoration_verified'):need(r[k] is True,k)
    for k in ('factory_0x74129c_before_no_return','factory_0x74129c_during_no_return','factory_0x74129c_after_no_return','factory_0x74129c_marked_noreturn','runtime_verified','semantic_equivalence_verified','global_guard_dominance_verified'):need(r[k] is False,k)
    need('ephemeral_transaction_rolled_back' not in r,'Do not claim observed hint rollback')
    annotations=r['conditional_noreturn_annotations'];need(len(annotations)==4,'four annotations only')
    need({int(x['address'],16) for x in annotations}==HELPERS,'annotation addresses')
    for item in annotations:
        need(item['before_no_return'] is False,'unannotated starting helper')
        for k in ('during_no_return','explicitly_restored_before_close','original_no_return_restored'):need(item[k] is True,'helper '+k)
        need('restoration_error' not in item,'restoration error')
def check_table(read,switch,start,end):
    branch=int(switch['branch'],16);need(int.from_bytes(read(branch,4),'little')&0xfffffc1f==0xd61f0000,'BR source opcode')
    width,count=switch['width'],switch['count'];need(width in (1,2,4) and count>0,'table dimensions')
    raw=read(int(switch['table'],16),width*count);need(raw.hex()==switch['table_raw_bytes'],'table source bytes')
    need(len(switch['entries'])==count,'table entry count');targets=[]
    for index,row in enumerate(switch['entries']):
        need(row['index']==index,'entry index ordering');value=int.from_bytes(raw[index*width:(index+1)*width],'little');dest=int(row['target'],16)
        need(dest==int(switch['anchor'],16)+4*value,'relative table arithmetic');need(start<=dest<end,'local target');need(read(dest,4).hex()==row['target_raw_bytes'],'target source bytes');targets.append(hex(dest))
    return {'branch':switch['branch'],'targets':targets}
def self_test():
    assert integer('0x100')==256 and integer(256)==256 and integer('256')==256
    r={'profile':MODEL,'conditional_noreturn_annotations':[{'address':hex(a),'before_no_return':False,'during_no_return':True,'explicitly_restored_before_close':True,'original_no_return_restored':True} for a in sorted(HELPERS)]}
    for k in ('noreturn_contract_is_assumption','nullguard_has_noreturn_annotation_expected_during_parent','outer_annotation_rollback_requested','read_only_disposable_project_lifecycle_required','annotation_transaction_close_returned','explicit_annotation_restoration_verified'):r[k]=True
    for k in ('factory_0x74129c_before_no_return','factory_0x74129c_during_no_return','factory_0x74129c_after_no_return','factory_0x74129c_marked_noreturn','runtime_verified','semantic_equivalence_verified','global_guard_dominance_verified'):r[k]=False
    check_annotations(r);rejected=[]
    for label,mutate in [('factory_annotation',lambda x:x.__setitem__('factory_0x74129c_during_no_return',True)),('wrong_helper',lambda x:x['conditional_noreturn_annotations'][0].__setitem__('address','0x74129c')),('unrestored_helper',lambda x:x['conditional_noreturn_annotations'][0].__setitem__('original_no_return_restored',False)),('rollback_overclaim',lambda x:x.__setitem__('ephemeral_transaction_rolled_back',True)),('runtime_overclaim',lambda x:x.__setitem__('runtime_verified',True))]:
        changed=copy.deepcopy(r);mutate(changed)
        try:check_annotations(changed)
        except ValueError:rejected.append(label)
        else:raise ValueError('synthetic mutation accepted '+label)
    memory={0x100:(0xd61f0140).to_bytes(4,'little'),0x200:b'\x01\x00',0x304:b'\x1f\x20\x03\xd5'}
    def read(a,n):need(a in memory and len(memory[a])==n,'fixture address');return memory[a]
    s={'branch':'0x100','table':'0x200','anchor':'0x300','width':2,'count':1,'table_raw_bytes':'0100','entries':[{'index':0,'target':'0x304','target_raw_bytes':'1f2003d5'}]};check_table(read,s,0x100,0x400)
    bad=copy.deepcopy(s);bad['entries'][0]['target']='0x308'
    try:check_table(read,bad,0x100,0x400)
    except ValueError:rejected.append('table_destination')
    else:raise ValueError('synthetic table mutation accepted')
    print(json.dumps({'self_test_passed':True,'synthetic_only':True,'ghidra_invoked':False,'negative_controls_rejected':rejected}));return rejected
def main():
    ap=argparse.ArgumentParser();ap.add_argument('lab',type=pathlib.Path,nargs='?');ap.add_argument('producer',type=pathlib.Path,nargs='?');ap.add_argument('folder',nargs='?');ap.add_argument('address',nargs='?');ap.add_argument('--self-test',action='store_true');a=ap.parse_args()
    if a.self_test:self_test();return
    need(all((a.lab,a.producer,a.folder,a.address)),'lab producer folder address-or-transaction-smoke required')
    need(a.folder.startswith('pseudocode-noreturn-coarse-') and pathlib.Path(a.folder).name==a.folder and '/' not in a.folder and '\\' not in a.folder,'distinct child output folder')
    out=a.lab/a.folder;rpath=out/'result.json';r=json.loads(rpath.read_text());check_annotations(r)
    need(sha(a.producer.read_bytes())==r['script_sha256'],'producer source SHA');need(a.producer.name=='TerrariaNoreturnCoarseProbe.java','producer filename')
    parent=a.producer.with_name('TerrariaCoarseCopiesProbe.java');need(sha(parent.read_bytes())==r['parent_helper_sha256']==PARENT,'frozen parent source SHA')
    proofpath=a.lab/'nullguard-noreturn-model-20261015/evidence.json';proofbytes=proofpath.read_bytes();proof=json.loads(proofbytes)
    need(sha(proofbytes)==r['noreturn_model_evidence_sha256']==PROOF,'frozen model evidence SHA');need(proof['integrity_passed'] is True and proof['elf_sha256']==ELF,'proof source identity')
    need({int(v,16) for v in proof['conditional_noreturn_entry_points']}==HELPERS,'proof four-entry scope');need(r['additional_ABI_assumptions']==proof['assumptions'],'ABI assumptions preserved')
    proofauditor=a.producer.with_name('audit_terraria_nullguard_noreturn_model.py');need(sha(proofauditor.read_bytes())==r['noreturn_model_auditor_sha256']==proof['auditor_sha256'],'proof auditor source identity')
    with (a.lab/'native/libil2cpp.so').open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as elf:
        need(sha(elf)==r['elf_sha256']==ELF,'ELF original SHA');need(elf[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<H',elf,18)[0]==183,'ELF64 ARM64')
        p=struct.unpack_from('<Q',elf,32)[0];z,n=struct.unpack_from('<HH',elf,54);segments=[]
        for i in range(n):
            t,_,o,v,_,s,_,_=struct.unpack_from('<II6Q',elf,p+i*z)
            if t==1:segments.append((v,v+s,o))
        def read(v,n):
            for lo,hi,o in segments:
                if lo<=v and v+n<=hi:return elf[o+v-lo:o+v-lo+n]
            raise ValueError('unmapped source interval')
        helperbytes=0
        for record in proof['source_functions']:
            lo,hi=int(record['entry'],16),int(record['end_exclusive'],16);raw=read(lo,hi-lo);need(raw.hex()==record['raw_bytes'] and sha(raw)==record['sha256'],'proof helper source');helperbytes+=len(raw)
        need(helperbytes==proof['verified_source_bytes']==124,'proof source coverage')
        plt=proof['independently_decoded_throw_PLT'];need(read(int(plt['entry'],16),16).hex()==plt['raw_bytes'],'throw PLT source bytes');ro=integer(plt['relocation_file_offset']);need(elf[ro:ro+24].hex()==plt['relocation_bytes'],'throw relocation source bytes')
        need(sha(pathlib.Path(r['actual_engine_path']).read_bytes())==r['actual_engine_sha256']==ENGINE,'actual stack32 engine identity')
        scope=json.loads((out/'model-scope.json').read_text());need(scope['profile']==MODEL and scope['script_sha256']==r['script_sha256'] and scope['parent_helper_sha256']==PARENT and scope['noreturn_model_evidence_sha256']==PROOF,'pre-parent model scope')
        need(scope['outer_annotation_rollback_requested'] is False,'scope recorded before close')
        if a.address=='transaction-smoke':
            need(r['status']=='annotation_transaction_smoke' and r['decompiler_invoked'] is False,'smoke-only result');need(not list(out.glob('*.c')),'no C in smoke');start=end=0;expected=[]
        else:
            need(r['status'] in ('decompile_failed','decompiled_conditional_candidate'),'actual supported decompiler result')
            need(r['parent_recorded_profile']=='aggregate-copy-unsplit-typed-v4-stack32-v1','parent model profile')
            need(r['nullguard_has_noreturn_annotation'] is True,'parent observed conditional NoReturn flag')
            need(r['parent_ephemeral_transaction_rollback_requested'] is True,'parent requested hint transaction abort')
            for k in ('split_structures','split_arrays','split_pointers','saved_project_modified','canonical_journals_modified'):need(r[k] is False,k)
            need(r['timeout_seconds']==600 and r['max_instructions']==250000 and r['max_payload_mb']==256,'parent decompiler options')
            maps=a.lab/'hard-switches-v2/switches.json';mapbytes=maps.read_bytes();need(sha(mapbytes)==r['switch_maps_sha256'],'switch maps SHA');allmaps=json.loads(mapbytes);need(allmaps['elf_sha256']==ELF,'switch source identity')
            start=int(r['address'],16);end=int(r['end_exclusive'],16);need(start==int(a.address,16),'selected address');method=next(m for m in allmaps['methods'] if int(m['address'],16)==start)
            need(end==int(method['end_exclusive'],16) and r['method']==method['method'],'method catalog scope')
            need(sha(read(start,end-start))==r['function_source_sha256'] and end-start==r['function_source_bytes_verified'],'source method bytes')
            expected=[check_table(read,s,start,end) for s in method['switch_candidates']]
            need(r['applied_hints']==expected and r['applied_hint_count']==len(expected) and r['applied_entry_count']==sum(len(x['targets']) for x in expected),'recorded hint equality')
            if r['status']=='decompiled_conditional_candidate':
                c=out/r['file'];need(c.resolve().parent==out.resolve(),'C direct child path');b=c.read_bytes();need(sha(b)==r['c_sha256'] and len(b)==r['c_bytes'],'conditional C SHA/size');need(b.startswith(HEADER.encode()),'explicit conditional ABI C header');need(HEADER.encode()+b'/* GHIDRA C CANDIDATE; aggregate-copy splitting disabled;'==b[:len(HEADER.encode())+len(b'/* GHIDRA C CANDIDATE; aggregate-copy splitting disabled;')],'parent C header preserved')
            else:need(not list(out.glob('*.c')),'failed attempt has no C candidate')
    audit={'integrity_passed':True,'producer_status':r['status'],'profile':'independent-conditional-NoReturn-unsplit-source-result-v1','evidence_sha256':sha(rpath.read_bytes()),'result_sha256':sha(rpath.read_bytes()),'auditor_sha256':sha(pathlib.Path(__file__).read_bytes()),'verified_function_bytes':end-start,'verified_model_source_bytes':helperbytes,'verified_switches':len(expected),'verified_entries':sum(len(x['targets']) for x in expected),'semantic_equivalence_verified':False,'global_guard_dominance_verified':False,'runtime_verified':False,'rollback_execution_independently_observed':False,'limits':['Fresh original ELF/PT_LOAD/source bytes, map arithmetic, tool/engine/model hashes and recorded annotation lifecycle are checked.','No independent observation of Ghidra annotation/override internals or final persistence; read-only disposable project lifecycle is an external requirement.','The conditional proof and standard C++ throw contract are inherited explicitly; this audit does not reprove exceptional-control-flow absence or turn ABI assumptions into runtime facts.']}
    (out/'independent-audit.json').write_text(json.dumps(audit,indent=2)+'\n');print(json.dumps(audit))
if __name__=='__main__':main()
