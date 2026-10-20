"""Unexecuted bounded angr experiment skeleton. Root must review installed APIs/source first.
No installation, native target execution, type erasure, or automatic coverage updates.
"""
import argparse,hashlib,importlib.util,inspect,json,mmap,os,re,sys,threading,time,traceback
from pathlib import Path
ELF='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
MAPS='88cb4795b3cf12a4ac25ed00937898aceeddb29791838194b587778192664da3'
FLOWS='90b0af285f5f171c8876a6eb09208bf004cd09359d00f92c4759d5aa4e8ceb7d'
RAW_AUDITOR='8f36f217503ea7b1deaa36aed7371127a8bc16afd7d6780ab0f9343ea5989dc6'
VERSION='10.0.4.post1'
WHEEL='1232f2ca66df874554bd25b14df302e6bf0309dfed074ee49f18cf37fd41a0ec'
HARD={0xf6954c,0xf9a914,0xfcbda0,0x11242ec,0x1484e54,0x911f1c,0xb1ab78,0x1635538}
SMOKE=0x74129c
SMOKE_FOLDER='pseudocode-angr-bounded-smoke-20261016'
PROFILE='angr-VEX-AIL-bounded-conditional-switch-v1'
FORBIDDEN_C=('UnresolvableJumpTarget','UnresolvableCallTarget','Unsupported','unimplemented','???')
def sha(b):return hashlib.sha256(b).hexdigest()
def filehash(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def union(rows):
    result=[]
    for a,b in sorted(rows):
        if result and a<=result[-1][1]:result[-1][1]=max(result[-1][1],b)
        else:result.append([a,b])
    return result

def gate(r):
    return bool(r.get('real_codegen_object') and r.get('nonempty_C') and not r.get('analysis_errors') and not r.get('scope_violations') and not r.get('missing_mapped_BR') and not r.get('unmapped_native_BR') and not r.get('forbidden_C_markers') and r.get('covered_region_bytes')==r.get('allowed_region_bytes') and r.get('closed_internal_graph') is True)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('lab',type=Path);ap.add_argument('folder');ap.add_argument('address',type=lambda s:int(s,16));ap.add_argument('--smoke',action='store_true');a=ap.parse_args();lab=a.lab.resolve();tools=Path(__file__).resolve().parent
    assert a.address in HARD|{SMOKE} and a.smoke is (a.address==SMOKE)
    assert Path(a.folder).name==a.folder and a.folder.startswith('pseudocode-angr-bounded-')
    if a.smoke:assert a.folder==SMOKE_FOLDER
    out=lab/a.folder;assert not out.exists(),'fresh attempt required'
    runtime=lab/'angr-runtime-20261016';review_path=runtime/'source-review.json';review=json.loads(review_path.read_text())
    assert review['angr_version']==VERSION and review['primary_angr_wheel_sha256']==WHEEL
    assert review['CFGFast_options_and_resolver_API_reviewed'] is True and review['VEX_lift_scope_guards_reviewed'] is True and review['AAPCS64_limitations_not_type_erased'] is True
    for row in review['files']:
        f=(runtime/row['path']).resolve();assert f.is_relative_to(runtime.resolve()) and filehash(f)==row['sha256']
    required={'angr/analyses/cfg/cfg_fast.py','angr/analyses/cfg/indirect_jump_resolvers/resolver.py','angr/analyses/decompiler/decompiler.py','angr/analyses/decompiler/clinic.py','angr/calling_conventions.py','angr/factory.py','angr/block.py','angr/engines/vex/lifter.py','angr/analyses/cfg/cfg_base.py','cle/backends/elf/elf.py','cle/backends/elf/metaelf.py'}
    assert required<={row['path'] for row in review['files']}
    if not a.smoke:
        sm=lab/SMOKE_FOLDER;sr=json.loads((sm/'result.json').read_text());sa=json.loads((sm/'audit.json').read_text());assert sr['status']=='real_C_candidate_scope_gates_passed' and sr['smoke'] is True and sr['producer_sha256']==filehash(Path(__file__)) and sa['integrity_passed'] and sa['result_sha256']==filehash(sm/'result.json') and sa['auditor_sha256']==filehash(tools/'audit_terraria_angr_bounded.py')
    assert filehash(lab/'hard-switches-v2/switches.json')==MAPS and filehash(lab/'native/flow-islands.json')==FLOWS
    helper=tools/'audit_terraria_extended_noreturn.py';assert filehash(helper)==RAW_AUDITOR
    spec=importlib.util.spec_from_file_location('frozen_raw_source',helper);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    sys.path.insert(0,str(runtime));import angr,cle,pyvex,archinfo
    assert angr.__version__==VERSION and all(Path(mod.__file__).resolve().is_relative_to(runtime.resolve()) for mod in (angr,cle,pyvex,archinfo))
    from angr.analyses.cfg.indirect_jump_resolvers.resolver import IndirectJumpResolver
    with (lab/'native/libil2cpp.so').open('rb') as fh,mmap.mmap(fh.fileno(),0,access=mmap.ACCESS_READ) as raw:
        source=module.Source(lab,raw);start=a.address;end=next(hi for lo,hi in source.fdes if lo==start)
        method=next((m for m in source.maps['methods'] if int(m['address'],16)==start),None)
        maps=[] if method is None else method['switch_candidates'];paths=[r for r in source.flows if int(r['fde_start'],16)==start and r['proven_encoded_path']]
        for path in paths:source.path(path)
        regions=union([(start,end)]+[(int(r['target'],16),int(r['target'],16)+8) for r in paths]);expected=source.hints(method) if method else []
        targets={int(h['branch'],16):[int(s,16) for s in h['targets']] for h in expected};native_BRs=[]
        for lo,hi in regions:
            for pc in range(lo,hi,4):
                if source.word(pc)&0xfffffc1f==0xd61f0000:native_BRs.append(pc)
        rec=dict(profile=PROFILE,status='preparing',smoke=a.smoke,address=hex(start),end_exclusive=hex(end),elf_sha256=ELF,maps_sha256=MAPS,flow_sha256=FLOWS,producer_sha256=filehash(Path(__file__)),runtime_review_sha256=filehash(review_path),runtime_root=str(runtime),runtime_review_file=str(review_path),version=VERSION,raw_auditor_sha256=RAW_AUDITOR,source_sha256=sha(source.read(start,end-start,True)),allowed_regions=regions,allowed_region_bytes=sum(hi-lo for lo,hi in regions),mapped_switches=expected,native_BR_addresses=[hex(x) for x in native_BRs],unmapped_native_BR=[hex(x) for x in native_BRs if x not in targets],resolver_calls=[],lift_requests=[],lifted_blocks=[],scope_violations=[],analysis_errors=[],eligible_for_C_coverage=False,runtime_execution=False,semantic_equivalence_verified=False,ABI_scalar_erasure_used=False,NoReturn_annotations_added=False)
        out.mkdir();(out/'scope.json').write_text(json.dumps(rec,indent=2)+'\n')
        def bounds(addr):
            for lo,hi in regions:
                if lo<=addr<hi:return hi
            raise RuntimeError('lift outside allowed source region: '+hex(addr))
        begin=time.monotonic();budget=60 if a.smoke else 600;rec['wallclock_budget_seconds']=budget
        def expire():
            (out/'timeout.json').write_text(json.dumps({'status':'timeout_partial_attempt','budget_seconds':budget,'producer_sha256':rec['producer_sha256'],'eligible_for_C_coverage':False})+'\n')
            os._exit(124)  # owned analysis process only; parent watchdog still required for native GIL stalls
        deadline=threading.Timer(budget,expire);deadline.daemon=True;deadline.start()
        try:
            if rec['unmapped_native_BR']:raise RuntimeError('unmapped source BR; do not manufacture opaque C')
            class MetadataOnlyELF(cle.ELF):
                def _load_plt(self):self._plt={}  # suppress CLE's otherwise unbounded PLT instruction lifting
            project=angr.Project(str(lab/'native/libil2cpp.so'),auto_load_libs=False,use_system_libs=False,main_opts={'base_addr':0,'backend':MetadataOnlyELF},perform_relocations=True)
            rec['automatic_PLT_code_scan_disabled']=True;rec['outside_calls_metadata_only']=True;rec['dropped_external_jobs']=[]
            assert project.arch.name=='AARCH64' and project.loader.main_object.mapped_base==0
            assert not [obj for obj in project.loader.all_objects if getattr(obj,'binary',None) and Path(str(obj.binary)).is_file() and Path(str(obj.binary)).resolve()!=(lab/'native/libil2cpp.so').resolve()]
            for lo,hi in regions:assert project.loader.memory.load(lo,hi-lo)==source.read(lo,hi-lo,True),'code bytes transformed unexpectedly'
            rec['loader_options']={'auto_load_libs':False,'use_system_libs':False,'base_addr':0,'perform_relocations':True}
            old_block=project.factory.block;block_signature=inspect.signature(old_block)
            def block_guard(*args,**kwargs):
                call=block_signature.bind_partial(*args,**kwargs);addr=call.arguments.get('addr')
                try:
                    assert isinstance(addr,int);limit=bounds(addr)-addr;size=call.arguments.get('size');maximum=call.arguments.get('max_size')
                    cap=min(limit,maximum) if maximum is not None else limit;call.arguments['size']=min(cap,size) if size is not None else cap;call.arguments['max_size']=cap
                    rec['lift_requests'].append({'address':addr,'max_bytes':call.arguments['size']})
                    b=old_block(*call.args,**call.kwargs);irsb=b.vex;assert irsb.size<=call.arguments['size'] and b.addr==addr and b.size==irsb.size
                    rec['lifted_blocks'].append({'address':addr,'bytes':irsb.size});return b
                except Exception as e:rec['scope_violations'].append(str(e));raise
            project.factory.block=block_guard
            engine=project.factory.default_engine;assert any('angr.engines.vex' in cls.__module__ for cls in type(engine).__mro__)
            old_lift=engine.lift_vex;lift_signature=inspect.signature(old_lift)
            def lift_guard(*args,**kwargs):
                call=lift_signature.bind_partial(*args,**kwargs);addr=call.arguments.get('addr');state=call.arguments.get('state')
                if addr is None and state is not None:addr=state.addr
                try:
                    assert isinstance(addr,int);limit=bounds(addr)-addr;size=call.arguments.get('size');call.arguments['size']=min(limit,size) if size is not None else limit
                    rec['lift_requests'].append({'address':addr,'max_bytes':call.arguments['size'],'guard':'lift_vex'})
                    irsb=old_lift(*call.args,**call.kwargs);assert irsb.addr==addr and 0<irsb.size<=call.arguments['size'];rec['lifted_blocks'].append({'address':addr,'bytes':irsb.size,'guard':'lift_vex'});return irsb
                except Exception as e:rec['scope_violations'].append(str(e));raise
            engine.lift_vex=lift_guard
            class ProvenResolver(IndirectJumpResolver):
                def __init__(self):super().__init__(project,timeless=True)
                def key(self,block):
                    if hasattr(block,'vex'):block=block.vex
                    addresses=[s.addr+s.delta for s in block.statements if s.tag=='Ist_IMark'];return addresses[-1] if addresses else None
                def filter(self,cfg,addr,func_addr,block,jumpkind):return func_addr==start and jumpkind=='Ijk_Boring' and self.key(block) in targets
                def resolve(self,cfg,addr,func_addr,block,jumpkind,func_graph_complete=True,**kwargs):
                    key=self.key(block);assert self.filter(cfg,addr,func_addr,block,jumpkind)
                    rec['resolver_calls'].append({'block':addr,'branch':key,'targets':targets[key]});return True,targets[key]
            from angr.analyses.cfg.cfg_fast import CFGFast
            from angr.errors import AngrSkipJobNotice
            class BoundedCFGFast(CFGFast):
                def _pre_job_handling(self,job):
                    if self._inside_regions(job.addr):return super()._pre_job_handling(job)
                    self._deregister_analysis_job(job.func_addr,job)
                    rec['dropped_external_jobs'].append({'address':job.addr,'jumpkind':job.jumpkind,'source':getattr(job.src_node,'addr',None)})
                    if job.jumpkind=='Ijk_Call':job.apply_function_edges(self,clear=True)
                    else:rec['scope_violations'].append('external non-call CFG transfer '+hex(job.addr))
                    raise AngrSkipJobNotice
            cfg_opts=dict(regions=regions,function_starts=[start],start_at_entry=False,symbols=False,function_prologues=False,eh_frame=False,exceptions=False,force_smart_scan=False,force_complete_scan=False,data_references=False,cross_references=False,normalize=True,resolve_indirect_jumps=True,indirect_jump_resolvers=[ProvenResolver()],detect_tail_calls=False,skip_specific_regions=False,exclude_sparse_regions=False,drop_bad_funcs=False,treat_functions_as_complete=False)
            rec['cfg_options']={k:v for k,v in cfg_opts.items() if k!='indirect_jump_resolvers'};cfg=project.analyses[BoundedCFGFast].prep(fail_fast=True)(**cfg_opts)
            rec['analysis_errors'] += [repr(e) for e in cfg.errors]
            function=cfg.kb.functions.get_by_addr(start);blocks=[]
            for addr in sorted(function.block_addrs_set):
                b=project.factory.block(addr);blocks.append((addr,addr+b.size))
            rec['function_blocks']=blocks;rec['covered_region_bytes']=sum(hi-lo for lo,hi in union(blocks));rec['missing_mapped_BR']=[hex(br) for br in targets if br not in {x['branch'] for x in rec['resolver_calls']}]
            internal=set(function.block_addrs_set);edges=[];closed=True
            for node in function.transition_graph:
                if getattr(node,'addr',None) not in internal:continue
                for successor in function.transition_graph.successors(node):
                    kind=function.transition_graph[node][successor].get('type');dst=getattr(successor,'addr',None);edges.append({'source':node.addr,'target':dst,'type':kind})
                    if kind not in ('call','syscall','return') and dst not in internal:closed=False
            rec['function_edges']=edges;rec['closed_internal_graph']=closed
            if rec['covered_region_bytes']!=rec['allowed_region_bytes'] or not closed or rec['missing_mapped_BR'] or rec['analysis_errors']:raise RuntimeError('CFG incomplete or not closed: preserve evidence, no C coverage')
            dec=project.analyses.Decompiler(function,cfg=cfg.model,preset='basic',use_cache=False,update_cache=False,update_memory_data=False,generate_code=True,want_full_graph=True)
            rec['analysis_errors'] += [repr(e) for e in dec.errors];rec['codegen_class']=type(dec.codegen).__module__+'.'+type(dec.codegen).__name__;rec['real_codegen_object']=rec['codegen_class']=='angr.analyses.decompiler.structured_codegen.c.CStructuredCodeGenerator'
            text=dec.codegen.text if dec.codegen else '';rec['nonempty_C']=bool(text and text.strip());rec['forbidden_C_markers']=[s for s in FORBIDDEN_C if s in text];rec['structuring_failures']=repr(getattr(dec,'structuring_failures',None));rec['ABI_limitations_note']='AAPCS64 aggregates/wide arguments not erased; errors are fatal. NoReturn propagation uses engine defaults, not new annotations.'
            if rec['nonempty_C']:
                c=out/'independent_candidate.c';c.write_text('/* Independent angr VEX/AIL C candidate; same conditional switch and bounded-source premises; NOT original source or equivalence proof. */\n'+text,encoding='utf8');rec['C_file']=c.name;rec['C_sha256']=filehash(c);rec['C_bytes']=c.stat().st_size;rec['C_warning_lines']=[line for line in text.splitlines() if re.search(r'warning|unsupported|unknown',line,re.I)]
            rec['status']='real_C_candidate_scope_gates_passed' if gate(rec) else 'C_returned_but_scope_or_analysis_gates_failed'
        except Exception as e:
            rec['status']='probe_failed';rec['exception']=repr(e);rec['traceback']=traceback.format_exc()
        finally:
            rec['elapsed_analysis_seconds']=time.monotonic()-begin;deadline.cancel();(out/'result.json').write_text(json.dumps(rec,indent=2)+'\n')
        print(json.dumps({'folder':a.folder,'status':rec['status'],'eligible_for_C_coverage':False}));return 0 if rec['status']=='real_C_candidate_scope_gates_passed' else 2
if __name__=='__main__':sys.exit(main())
