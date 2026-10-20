"""Fresh mmap/raw-source audit. No producer, Capstone or REA parser imports.

Lifecycle fields attest producer observations, not independently observed Ghidra state.
Known ownership is catalogue-scoped; unknown/indirect incoming edges remain unproved.
"""
import argparse
import bisect
import copy
import hashlib
import json
import mmap
from pathlib import Path
import struct

ELF='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
ENGINE='1fd85827247f1ff1417fa412db26a53066d050c59017db98dd23ff196751521e'
FDES='8b238f458b7a0505138fc56ea70ffe59c21d46a6b83ea2e4106f6f896a3f7756'
PROOF='04d8474fa751442c6fc2f01e1d11c40bba282e6e1ea04222e62a9a38e7f78245'
PARENT='65f3e4f2fbc3c2965c9b2a49dced2c6e5042a2b156eaccc2badc42a4a60ceecb'
PROFILE='verified-known-islands-conditional-noreturn-aggregate-unsplit-v4-stack32-v1'
HELPERS={0x6ff6ac,0x741278,0x74128c,0x7411e0}
ROOTS={0xf6954c,0xf9a914,0xfcbda0,0x11242ec,0x11b1bf4,0x1484e54,0x911f1c}

def sha(b):return hashlib.sha256(b).hexdigest()
def integer(s):return int(s,16)
def branch(w,pc):
    assert w>>26==5,'not unconditional B'
    v=w&0x3ffffff
    return pc+4*(v-0x4000000 if v&0x2000000 else v)
def merge_ranges(points):
    result=[]
    for lo,hi in sorted(points):
        if result and lo<=result[-1][1]:result[-1][1]=max(hi,result[-1][1])
        else:result.append([lo,hi])
    return [{'start':hex(lo),'end_exclusive':hex(hi)} for lo,hi in result]
def rejects(f):
    try:f()
    except (AssertionError,ValueError,KeyError):return
    raise AssertionError('negative control accepted')

class Source:
    def __init__(self,lab,raw):
        self.raw=raw
        assert sha(raw)==ELF and raw[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<H',raw,18)[0]==183
        ph=struct.unpack_from('<Q',raw,32)[0];size,count=struct.unpack_from('<HH',raw,54);assert size>=56 and ph+size*count<=len(raw)
        self.segments=[]
        for i in range(count):
            ty,flags,off,va,_,filesz,_,_=struct.unpack_from('<IIQQQQQQ',raw,ph+i*size)
            if ty==1:
                assert off+filesz<=len(raw)
                self.segments.append((va,va+filesz,off,flags))
        rb=(lab/'native/unwind-function-ranges.tsv').read_bytes();assert sha(rb)==FDES
        self.fdes=[tuple(integer(v) for v in line.split()) for line in rb.decode().splitlines()]
        assert len(self.fdes)==123152 and all(a<b and (a|b)%4==0 and (i==0 or a>=self.fdes[i-1][1]) for i,(a,b) in enumerate(self.fdes))
        self.starts=[a for a,b in self.fdes]
        self.flows=json.loads((lab/'native/flow-islands.json').read_text())
        self.maps=json.loads((lab/'hard-switches-v2/switches.json').read_text());assert self.maps['elf_sha256']==ELF
    def read(self,va,size,executable=False):
        found=[off+va-lo for lo,hi,off,flags in self.segments if lo<=va and va+size<=hi and (not executable or flags&1)]
        assert len(found)==1,'not unique file-backed PT_LOAD'
        return self.raw[found[0]:found[0]+size]
    def word(self,a):return struct.unpack('<I',self.read(a,4,True))[0]
    def owner(self,a):
        i=bisect.bisect_right(self.starts,a)-1
        return self.fdes[i][0] if i>=0 and a<self.fdes[i][1] else None
    def path(self,r):
        root,end,origin,target=map(integer,(r['fde_start'],r['fde_end_exclusive'],r['origin'],r['target']))
        assert (root,end) in self.fdes and root<=origin<origin+4<end and not(origin%4 or target%4)
        assert branch(self.word(origin),origin)==target
        assert self.read(origin,4,True).hex()==r['origin_raw_bytes']
        assert r['proven_encoded_path'] is True and r['classification']=='structurally_verified_out_and_back'
        assert len(r['steps'])==2
        for index,s in enumerate(r['steps']):
            pc=integer(s['address']);assert pc==target+4*index and self.owner(pc) is None
            assert self.read(pc,4,True).hex()==s['raw_bytes']
        assert self.word(target)&0xffc00000==0xf9400000,'not LDR X unsigned-immediate'
        assert branch(self.word(target+4),target+4)==integer(r['return_target'])==origin+4
        assert r['returns_to_origin_plus_four'] is True
        for other in self.flows:
            if other['proven_encoded_path'] and integer(other['fde_start'])!=root:
                assert all(integer(s['address']) not in (target,target+4) for s in other['steps']),'known shared owner'
    def paths(self,root):
        rows=[r for r in self.flows if integer(r['fde_start'])==root]
        assert rows and all(r['proven_encoded_path'] for r in rows)
        for r in rows:self.path(r)
        return rows
    def hints(self,method):
        root,end=integer(method['address']),integer(method['end_exclusive']);expected=[]
        for s in method['switch_candidates']:
            br=integer(s['branch']);assert self.word(br)&0xfffffc1f==0xd61f0000
            raw=self.read(integer(s['table']),s['width']*s['count']);assert raw.hex()==s['table_raw_bytes'] and sha(raw)==s['table_sha256']
            targets=[];assert len(s['entries'])==s['count']
            for index,e in enumerate(s['entries']):
                assert e['index']==index
                encoded=int.from_bytes(raw[index*s['width']:(index+1)*s['width']],'little');target=integer(e['target'])
                assert target==integer(s['anchor'])+encoded*4 and root<=target<end
                assert self.read(target,4,True).hex()==e['target_raw_bytes']
                targets.append(hex(target))
            expected.append({'branch':s['branch'],'targets':targets})
        return expected

ANGR_VERSION='10.0.4.post1'
ANGR_WHEEL='1232f2ca66df874554bd25b14df302e6bf0309dfed074ee49f18cf37fd41a0ec'
MAPS_SHA='88cb4795b3cf12a4ac25ed00937898aceeddb29791838194b587778192664da3'
FLOWS_SHA='90b0af285f5f171c8876a6eb09208bf004cd09359d00f92c4759d5aa4e8ceb7d'
RAW_HELPER='8f36f217503ea7b1deaa36aed7371127a8bc16afd7d6780ab0f9343ea5989dc6'
ANGR_PROFILE='angr-VEX-AIL-bounded-conditional-switch-v1'
ALLOWED={0xf6954c,0xf9a914,0xfcbda0,0x11242ec,0x1484e54,0x911f1c,0xb1ab78,0x1635538,0x74129c}
MARKERS=('UnresolvableJumpTarget','UnresolvableCallTarget','Unsupported','unimplemented','???')
SMOKE_NAME='pseudocode-angr-bounded-smoke-20261016'
def check_record(r):
    assert r['eligible_for_C_coverage'] is False and r['runtime_execution'] is False and r['semantic_equivalence_verified'] is False and r['ABI_scalar_erasure_used'] is False and r['NoReturn_annotations_added'] is False
    if r['status']=='real_C_candidate_scope_gates_passed':
        assert r['real_codegen_object'] is True and r['nonempty_C'] is True
        assert r['codegen_class']=='angr.analyses.decompiler.structured_codegen.c.CStructuredCodeGenerator'
        assert all(not r[k] for k in ('analysis_errors','scope_violations','missing_mapped_BR','unmapped_native_BR','forbidden_C_markers'))
        assert r['covered_region_bytes']==r['allowed_region_bytes'] and r['closed_internal_graph'] is True
    else:assert r['status'] in ('probe_failed','C_returned_but_scope_or_analysis_gates_failed')

def source_guard(text):
    for fragment in ('auto_load_libs=False','use_system_libs=False',"main_opts={'base_addr':0,'backend':MetadataOnlyELF}","perform_relocations=True",'project.factory.block=block_guard','class MetadataOnlyELF(cle.ELF):','def _load_plt(self):self._plt={}','class BoundedCFGFast(CFGFast):','engine.lift_vex=lift_guard',"preset='basic'",'use_cache=False','generate_code=True','eligible_for_C_coverage=False'):
        assert fragment in text
    for setting in ('start_at_entry','symbols','function_prologues','eh_frame','exceptions','force_smart_scan','force_complete_scan','data_references','cross_references'):
        assert setting+'=False' in text
    assert 'scalar_erasure_used=True' not in text and 'optimization_passes=[]' not in text

def selftest(producer):
    good=dict(eligible_for_C_coverage=False,runtime_execution=False,semantic_equivalence_verified=False,ABI_scalar_erasure_used=False,NoReturn_annotations_added=False,status='real_C_candidate_scope_gates_passed',real_codegen_object=True,nonempty_C=True,codegen_class='angr.analyses.decompiler.structured_codegen.c.CStructuredCodeGenerator',analysis_errors=[],scope_violations=[],missing_mapped_BR=[],unmapped_native_BR=[],forbidden_C_markers=[],covered_region_bytes=40,allowed_region_bytes=40,closed_internal_graph=True)
    check_record(good);count=0
    for key,value in [('eligible_for_C_coverage',True),('runtime_execution',True),('ABI_scalar_erasure_used',True),('real_codegen_object',False),('nonempty_C',False),('analysis_errors',['ABI failure']),('scope_violations',['outside']),('missing_mapped_BR',['0x1']),('unmapped_native_BR',['0x2']),('forbidden_C_markers',['???']),('covered_region_bytes',36),('closed_internal_graph',False),('codegen_class','Dummy')]:
        bad=copy.deepcopy(good);bad[key]=value;rejects(lambda bad=bad:check_record(bad));count+=1
    source_guard(producer.read_text())
    for setting in ('auto_load_libs','force_smart_scan','force_complete_scan','symbols','eh_frame'):
        rejects(lambda setting=setting:source_guard(producer.read_text().replace(setting+'=False',setting+'=True')));count+=1
    return count

def main():
    ap=argparse.ArgumentParser();ap.add_argument('lab',type=Path);ap.add_argument('producer',type=Path);ap.add_argument('folder',nargs='?');ap.add_argument('--self-test',action='store_true');a=ap.parse_args();negative=selftest(a.producer)
    if a.self_test and not a.folder:print(json.dumps(dict(integrity_passed=True,negative_controls_rejected=negative,auditor_sha256=sha(Path(__file__).read_bytes()))));return
    assert a.folder and Path(a.folder).name==a.folder and a.folder.startswith('pseudocode-angr-bounded-')
    out=a.lab/a.folder;rb=(out/'result.json').read_bytes();r=json.loads(rb);scope=json.loads((out/'scope.json').read_text());check_record(r)
    assert r['wallclock_budget_seconds']==(60 if r['smoke'] else 600)
    assert r['profile']==ANGR_PROFILE and r['producer_sha256']==sha(a.producer.read_bytes()) and r['version']==ANGR_VERSION and r['raw_auditor_sha256']==RAW_HELPER
    assert r['maps_sha256']==MAPS_SHA==sha((a.lab/'hard-switches-v2/switches.json').read_bytes()) and r['flow_sha256']==FLOWS_SHA==sha((a.lab/'native/flow-islands.json').read_bytes())
    start=int(r['address'],16);assert start in ALLOWED and r['smoke'] is (start==0x74129c)
    if r['smoke']:assert a.folder==SMOKE_NAME
    review_path=Path(r['runtime_review_file']);assert review_path.resolve()==(a.lab/'angr-runtime-20261016/source-review.json').resolve()
    assert sha(review_path.read_bytes())==r['runtime_review_sha256'];review=json.loads(review_path.read_text());assert review['angr_version']==ANGR_VERSION and review['primary_angr_wheel_sha256']==ANGR_WHEEL
    for row in review['files']:
        path=(a.lab/'angr-runtime-20261016'/row['path']).resolve();assert path.is_relative_to((a.lab/'angr-runtime-20261016').resolve()) and sha(path.read_bytes())==row['sha256']
    with (a.lab/'native/libil2cpp.so').open('rb') as fh,mmap.mmap(fh.fileno(),0,access=mmap.ACCESS_READ) as raw:
        source=Source(a.lab,raw);end=next(hi for lo,hi in source.fdes if lo==start);assert hex(end)==r['end_exclusive'] and sha(source.read(start,end-start,True))==r['source_sha256']
        paths=[x for x in source.flows if int(x['fde_start'],16)==start and x['proven_encoded_path']]
        for path in paths:source.path(path)
        regions=merge_ranges([(start,end)]+[(int(x['target'],16),int(x['target'],16)+8) for x in paths]);expected_regions=[[int(x['start'],16),int(x['end_exclusive'],16)] for x in regions]
        assert r['allowed_regions']==expected_regions and r['allowed_region_bytes']==sum(b-a for a,b in expected_regions)
        def contained(lo,hi):return any(a<=lo<=hi<=b for a,b in expected_regions)
        method=next((m for m in source.maps['methods'] if int(m['address'],16)==start),None);hints=source.hints(method) if method else [];assert r['mapped_switches']==hints
        brs=[pc for lo,hi in expected_regions for pc in range(lo,hi,4) if source.word(pc)&0xfffffc1f==0xd61f0000]
        assert r['native_BR_addresses']==[hex(x) for x in brs] and r['unmapped_native_BR']==[hex(x) for x in brs if x not in {int(h['branch'],16) for h in hints}]
        for request in r['lift_requests']:assert contained(request['address'],request['address']+request['max_bytes'])
        for block in r['lifted_blocks']:assert contained(block['address'],block['address']+block['bytes'])
        if 'loader_options' in r:
            assert r['automatic_PLT_code_scan_disabled'] is True and r['outside_calls_metadata_only'] is True
            assert all(job['jumpkind']=='Ijk_Call' for job in r['dropped_external_jobs']) if r['status']=='real_C_candidate_scope_gates_passed' else True
            assert r['loader_options']==dict(auto_load_libs=False,use_system_libs=False,base_addr=0,perform_relocations=True)
        if 'cfg_options' in r:
            opts=r['cfg_options'];assert opts['regions']==expected_regions and opts['function_starts']==[start]
            assert all(opts[k] is False for k in ('start_at_entry','symbols','function_prologues','eh_frame','exceptions','force_smart_scan','force_complete_scan','data_references','cross_references','detect_tail_calls'))
        if 'function_blocks' in r:
            blocks=r['function_blocks'];assert all(contained(lo,hi) for lo,hi in blocks)
            merged=merge_ranges(blocks);assert r['covered_region_bytes']==sum(int(x['end_exclusive'],16)-int(x['start'],16) for x in merged)
            targets={int(h['branch'],16):[int(x,16) for x in h['targets']] for h in hints}
            for call in r['resolver_calls']:assert call['branch'] in targets and call['targets']==targets[call['branch']] and any(lo<=call['branch']<hi and lo==call['block'] for lo,hi in blocks)
            assert r['missing_mapped_BR']==[hex(br) for br in targets if br not in {x['branch'] for x in r['resolver_calls']}]
            nodes={lo for lo,hi in blocks};closed=all(edge['target'] in nodes or edge['type'] in ('call','syscall','return') for edge in r['function_edges']);assert r['closed_internal_graph'] is closed
        if 'C_file' in r:
            c=(out/r['C_file']).resolve();assert c.parent==out.resolve() and sha(c.read_bytes())==r['C_sha256'] and c.stat().st_size==r['C_bytes']
            text=c.read_text();assert text.startswith('/* Independent angr VEX/AIL C candidate;') and r['forbidden_C_markers']==[s for s in MARKERS if s in text]
        if not r['smoke']:
            sm=a.lab/SMOKE_NAME;sr=json.loads((sm/'result.json').read_text());sa=json.loads((sm/'audit.json').read_text());assert sr['status']=='real_C_candidate_scope_gates_passed' and sr['producer_sha256']==r['producer_sha256'] and sa['integrity_passed'] and sa['result_sha256']==sha((sm/'result.json').read_bytes()) and sa['auditor_sha256']==sha(Path(__file__).read_bytes())
        for key in ('producer_sha256','allowed_regions','mapped_switches','source_sha256','runtime_review_sha256'):assert r[key]==scope[key]
    audit=dict(integrity_passed=True,result_sha256=sha(rb),auditor_sha256=sha(Path(__file__).read_bytes()),status=r['status'],smoke=r['smoke'],negative_controls_rejected=negative,eligible_for_C_coverage=False,notes='Fresh source/layout/record checks. Graph/lifter observations are producer records, not independent execution; root review required before any coverage integration.')
    (out/'audit.json').write_text(json.dumps(audit,indent=2)+'\n');print(json.dumps(audit))
if __name__=='__main__':main()
