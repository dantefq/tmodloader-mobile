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
import re

ELF='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
ENGINE='1fd85827247f1ff1417fa412db26a53066d050c59017db98dd23ff196751521e'
FDES='8b238f458b7a0505138fc56ea70ffe59c21d46a6b83ea2e4106f6f896a3f7756'
PROOF='04d8474fa751442c6fc2f01e1d11c40bba282e6e1ea04222e62a9a38e7f78245'
PARENT='65f3e4f2fbc3c2965c9b2a49dced2c6e5042a2b156eaccc2badc42a4a60ceecb'
PROFILE='verified-known-islands-conditional-noreturn-branch-preserving-C-v4-stack32-v1'
HELPERS={0x6ff6ac,0x741278,0x74128c,0x7411e0}
EXTENDED_BASE='2855837418f2d00493efa3b5a03347dd636bd8a6a05cad0ad137f457e67973e6'
ROOTS={0xf6954c,0xf9a914,0xfcbda0,0x11242ec,0x1484e54,0x911f1c,0xb1ab78,0x1635538,0x74129c}
UNTYPED_BASE='4caba66f21b937c30a2f8af10692d22af3acca8e7a25b8b98989ee56f1749ad2'
DISABLED_GROUPS=['typerecovery','conditionalexe','nodejoin','returnsplit']
SMOKE=0x74129c
SMOKE_FOLDER='pseudocode-branch-preserving-c-smoke-20261016'

def model_record(r):
    assert r['simplification_style']=='decompile' and r['typerecovery_enabled'] is False
    assert r['retained_final_groups']=='merge,casts,cleanup,blockrecovery'
    assert r['disabled_action_groups']==DISABLED_GROUPS and r['only_recorded_additional_action_groups_disabled'] is True
    assert r['derived_from_untyped_sha256']==UNTYPED_BASE
    assert r['action_toggle_count_before_decompile']==4*r['option_injection_count_before_decompile']
    assert r['action_toggle_count_after_decompile']==4*r['option_injection_count_after_decompile']
    assert r['open_program_accepted'] is True and r['options_accepted_after_open'] is True
    assert isinstance(r['option_injection_count_before_decompile'],int) and r['option_injection_count_before_decompile']>=2
    assert r['option_injection_count_after_decompile']>=r['option_injection_count_before_decompile']
    assert r['decompiler_invoked'] is True and isinstance(r['c_smoke'],bool)
    assert r['timeout_seconds']==(60 if r['c_smoke'] else 600)
    assert r['status'] in ('decompiled_conditional_candidate','decompile_failed')
    if r['status']=='decompiled_conditional_candidate':
        assert r['decompile_completed'] is True and r['actual_C_object_returned'] is True and r['timed_out'] is False
    else:assert not(r['decompile_completed'] is True and r['actual_C_object_returned'] is True)

def source_protocol(text):
    assert 'static class BranchPreservingOptions extends DecompileOptions' in text
    assert 'super.encode(wrapper,iface);' in text and 'args[0]==ELEM_OPTIONSLIST' in text
    declarations=re.findall(r'static final String\[\] DISABLED_GROUPS=\{([^}]+)\};',text)
    assert len(declarations)==1 and re.findall(r'"([a-z]+)"',declarations[0])==DISABLED_GROUPS
    assert 'for(String group:DISABLED_GROUPS){' in text
    assert 'content(encoder,ELEM_PARAM1,"decompile");content(encoder,ELEM_PARAM2,group);content(encoder,ELEM_PARAM3,"off");' in text
    assert 'encoder.closeElement(ELEM_CURRENTACTION);toggleInjections++;' in text
    assert '"merge,casts,cleanup,blockrecovery"' in text
    assert 'options.toggleInjections!=4*options.injections' in text
    assert text.count('encoder.openElement(ELEM_CURRENTACTION);')==1
    assert 'setSimplificationStyle("normalize")' not in text


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
        assert all(r['proven_encoded_path'] for r in rows)
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

def main():
    p=argparse.ArgumentParser();p.add_argument('lab',type=Path);p.add_argument('producer',type=Path);p.add_argument('folder',nargs='?');p.add_argument('address',nargs='?',type=integer);p.add_argument('--self-test',action='store_true');a=p.parse_args()
    assert a.producer.name=='TerrariaBranchPreservingCProbe.java'
    assert sha(a.producer.with_name('TerrariaCoarseCopiesProbe.java').read_bytes())==PARENT
    assert sha(a.producer.with_name('TerrariaExtendedNoreturnProbe.java').read_bytes())==EXTENDED_BASE
    assert sha(a.producer.with_name('TerrariaUntypedCProbe.java').read_bytes())==UNTYPED_BASE
    source_protocol(a.producer.read_text())
    with (a.lab/'native/libil2cpp.so').open('rb') as fh,mmap.mmap(fh.fileno(),0,access=mmap.ACCESS_READ) as raw:
        source=Source(a.lab,raw);negative=0;count=0
        good=dict(disabled_action_groups=DISABLED_GROUPS,only_recorded_additional_action_groups_disabled=True,derived_from_untyped_sha256=UNTYPED_BASE,action_toggle_count_before_decompile=8,action_toggle_count_after_decompile=8,simplification_style='decompile',typerecovery_enabled=False,retained_final_groups='merge,casts,cleanup,blockrecovery',open_program_accepted=True,options_accepted_after_open=True,option_injection_count_before_decompile=2,option_injection_count_after_decompile=2,decompiler_invoked=True,c_smoke=False,timeout_seconds=600,status='decompiled_conditional_candidate',decompile_completed=True,actual_C_object_returned=True,timed_out=False)
        model_record(good)
        for key,value in [('simplification_style','normalize'),('typerecovery_enabled',True),('options_accepted_after_open',False),('option_injection_count_before_decompile',0),('actual_C_object_returned',False),('decompile_completed',False),('timed_out',True),('retained_final_groups','merge'),('timeout_seconds',60),('disabled_action_groups',['typerecovery']),('disabled_action_groups',['typerecovery','conditionalexe','nodejoin','merge']),('only_recorded_additional_action_groups_disabled',False),('action_toggle_count_before_decompile',7),('action_toggle_count_after_decompile',4),('derived_from_untyped_sha256','0'*64)]:
            bad=copy.deepcopy(good);bad[key]=value;rejects(lambda:model_record(bad));negative+=1
        for old,new in [('"typerecovery","conditionalexe","nodejoin","returnsplit"','"typerecovery","conditionalexe","nodejoin","merge"'),('ELEM_PARAM3,"off"','ELEM_PARAM3,"on"'),('args[0]==ELEM_OPTIONSLIST','args[0]==ELEM_CURRENTACTION')]:
            rejects(lambda old=old,new=new:source_protocol(a.producer.read_text().replace(old,new)));negative+=1

        # Fresh integrity/shape controls against original mmap bytes, not producer output.
        for group in DISABLED_GROUPS:
            changed=a.producer.read_text().replace('"'+group+'"','"merge"')
            rejects(lambda changed=changed:source_protocol(changed));negative+=1
            bad=copy.deepcopy(good);bad['disabled_action_groups']=[('casts' if x==group else x) for x in DISABLED_GROUPS]
            rejects(lambda bad=bad:model_record(bad));negative+=1
        for root in sorted(ROOTS):
            for r in source.paths(root):
                count+=1
                for key,value in [('target',hex(integer(r['target'])+4)),('return_target',hex(integer(r['return_target'])+4)),('origin_raw_bytes','00000000')]:
                    bad=copy.deepcopy(r);bad[key]=value;rejects(lambda:source.path(bad));negative+=1
                bad=copy.deepcopy(r);bad['steps'][0]['raw_bytes']='c0035fd6';rejects(lambda:source.path(bad));negative+=1
        rejects(lambda:branch(0x94000000,0));negative+=1
        rejects(lambda:branch(0xd65f03c0,0));negative+=1
        selftest={'integrity_passed':True,'verified_known_islands':count,'negative_controls_rejected':negative,'auditor_sha256':sha(Path(__file__).read_bytes()),'new_islands_discovered':False}
        if a.self_test and not a.folder:print(json.dumps(selftest));return
        assert a.folder and a.address in ROOTS and a.folder.startswith('pseudocode-branch-preserving-c-') and Path(a.folder).name==a.folder
        out=a.lab/a.folder;r=json.loads((out/'result.json').read_text());scope=json.loads((out/'scope.json').read_text())
        assert r['profile']==PROFILE and integer(r['address'])==a.address
        model_record(r);assert r['c_smoke'] is (a.address==SMOKE) and r['derived_from_extended_sha256']==EXTENDED_BASE
        if r['c_smoke']:assert a.folder==SMOKE_FOLDER
        else:
            assert r['prerequisite_C_smoke_folder']==SMOKE_FOLDER
            sd=a.lab/SMOKE_FOLDER;sr=json.loads((sd/'result.json').read_text());sa=json.loads((sd/'audit.json').read_text());model_record(sr)
            assert sr['c_smoke'] is True and sr['status']=='decompiled_conditional_candidate' and sr['script_sha256']==sha(a.producer.read_bytes())
            assert sa['integrity_passed'] is True and sa['c_smoke'] is True and sa['eligible_for_new_C_coverage'] is False
            assert sa['auditor_sha256']==sha(Path(__file__).read_bytes()) and sa['result_sha256']==sha((sd/'result.json').read_bytes())==r['prerequisite_C_smoke_result_sha256']
            assert sha((sd/'audit.json').read_bytes())==r['prerequisite_C_smoke_audit_sha256']
            assert sha((sd/sr['file']).read_bytes())==sr['c_sha256']

        assert r['script_sha256']==sha(a.producer.read_bytes()) and r['derived_from_parent_sha256']==PARENT
        for rel,key in [('native/flow-islands.json','flow_islands_sha256'),('native/unwind-function-ranges.tsv','fde_catalogue_sha256'),('hard-switches-v2/switches.json','switch_maps_sha256'),('nullguard-noreturn-model-20261015/evidence.json','noreturn_model_evidence_sha256')]:assert sha((a.lab/rel).read_bytes())==r[key]
        assert r['elf_sha256']==ELF and r['fde_catalogue_sha256']==FDES and r['noreturn_model_evidence_sha256']==PROOF
        assert r['actual_engine_sha256']==ENGINE==sha(Path(r['actual_engine_path']).read_bytes())
        proof=json.loads((a.lab/'nullguard-noreturn-model-20261015/evidence.json').read_text());assert proof['integrity_passed'] and proof['elf_sha256']==ELF and {integer(x) for x in proof['conditional_noreturn_entry_points']}==HELPERS
        assert r['additional_ABI_assumptions']==proof['assumptions']
        assert r['noreturn_model_auditor_sha256']==proof['auditor_sha256']==sha(a.producer.with_name('audit_terraria_nullguard_noreturn_model.py').read_bytes())
        for row in proof['source_functions']:assert source.read(integer(row['entry']),integer(row['end_exclusive'])-integer(row['entry']),True).hex()==row['raw_bytes']
        if a.address==SMOKE:
            end=next(b for lo,b in source.fdes if lo==SMOKE);method=dict(address=hex(SMOKE),end_exclusive=hex(end),method='small-native-factory-0x74129c-C-smoke',switch_candidates=[])
        else:method=next(m for m in source.maps['methods'] if integer(m['address'])==a.address)
        start,end=a.address,integer(method['end_exclusive']);assert end==integer(r['end_exclusive']) and r['method']==method['method']
        assert sha(source.read(start,end-start,True))==r['function_source_sha256'] and end-start==r['function_source_bytes_verified']
        paths=source.paths(start);assert r['known_islands']==paths
        expected_body=merge_ranges([(start,end)]+[(integer(x['target']),integer(x['target'])+8) for x in paths]);assert r['original_body_ranges']==merge_ranges([(start,end)]) and r['extended_body_ranges']==expected_body
        assert r['island_instruction_count_verified']==2*len(paths) and 0<=r['bounded_island_disassembly_count']<=2*len(paths)
        expected=source.hints(method);assert r['applied_hints']==expected and r['applied_hint_count']==len(expected) and r['applied_entry_count']==sum(len(x['targets']) for x in expected)
        for key in ('original_body_exact_fde_verified','islands_previously_unowned_in_saved_program_verified','islands_single_known_catalogue_owner_verified','islands_outside_all_catalogue_fdes_verified','extended_body_applied_verified','original_body_explicitly_restored_before_close','original_body_restored_after_close_check','outer_transaction_rollback_requested','transaction_close_returned','explicit_model_restoration_verified','read_only_disposable_project_lifecycle_required'):assert r[key] is True
        for key in ('factory_0x74129c_before_no_return','factory_0x74129c_during_no_return','factory_0x74129c_after_no_return','saved_project_modified','canonical_journals_modified','runtime_verified','semantic_equivalence_verified','split_structures','split_arrays','split_pointers'):assert r[key] is False
        assert {integer(x['address']) for x in r['conditional_noreturn_annotations']}==HELPERS and len(r['conditional_noreturn_annotations'])==4
        for item in r['conditional_noreturn_annotations']:assert item['before_no_return'] is False and all(item[k] is True for k in ('during_no_return','explicitly_restored_before_close','original_no_return_restored'))
        assert r['max_instructions']==250000 and r['max_payload_mb']==256
        for key in ('script_sha256','flow_islands_sha256','known_islands','original_body_ranges','extended_body_ranges','applied_hints'):assert r[key]==scope[key]
        if r['status']=='decompiled_conditional_candidate':
            c=out/r['file'];assert c.resolve().parent==out.resolve() and sha(c.read_bytes())==r['c_sha256'] and c.read_text().startswith('/* CONDITIONAL BRANCH-PRESERVING GHIDRA C:') and c.stat().st_size==r['c_bytes'] and r['c_bytes']>230 and r['decompiler_invoked'] is True
        else:
            assert r['status']=='decompile_failed' and not list(out.glob('*.c'))
            assert r['decompiler_invoked'] is True
        audit=dict(selftest,result_sha256=sha((out/'result.json').read_bytes()),producer_status=r['status'],c_smoke=r['c_smoke'],eligible_for_new_C_coverage=(not r['c_smoke'] and r['status']=='decompiled_conditional_candidate'),verified_function_bytes=end-start,verified_extended_island_bytes=8*len(paths),verified_switches=len(expected),semantic_equivalence_verified=False,runtime_verified=False,global_incoming_or_CFG_completeness_verified=False,note='Lifecycle/body/annotation checks validate producer records; not independent observation of Ghidra internal state. Only known catalogue ownership and source paths are checked. Rollback requested, not independently observed.')
        (out/'audit.json').write_text(json.dumps(audit,indent=2)+'\n');print(json.dumps(audit))

if __name__=='__main__':main()
