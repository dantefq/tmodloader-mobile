"""Separately qualify completed conditional C exports; preserve diagnostic audits."""
import copy
import hashlib
import json
from pathlib import Path

LAB=Path(r'C:\Temp\terraria-re-20261012')
TOOLS=Path(__file__).resolve().parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
AUDITOR='a9f53530ef31f57ca348c8a721780a35bc3ff25f381dca2a62e56bdca9071360'
ENGINE='d64bd049b88d8d2f9452b92079705d4e95b71abb0aad018f596f143246f9f67a'
ELF='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
def check(r,a,v):
    assert r['status']=='decompiled_conditional_candidate'
    assert r['decompile_completed'] is True and r['actual_C_object_returned'] is True
    assert r['timed_out'] is False and r['actual_engine_sha256']==ENGINE and r['elf_sha256']==ELF
    assert r['diagnostic_only'] is True and r['semantic_equivalence_verified'] is False
    assert r['explicit_model_restoration_verified'] is True
    assert r['original_body_explicitly_restored_before_close'] is True
    assert r['original_body_restored_after_close_check'] is True
    assert a['integrity_passed'] is True and a['negative_controls_rejected']==104
    assert a['auditor_sha256']==AUDITOR and a['eligible_for_new_C_coverage'] is False
    assert a['diagnostic_candidate_returned'] is True
    assert not v['contains_NUL'] and not v['lexical_errors']
    assert not v['delimiter_mismatches'] and not v['unclosed_delimiters'] and not v['missing_goto_labels']
    assert all(n==0 for n in v['selected_markers'].values())
    assert a['verified_function_bytes']==r['function_source_bytes_verified']
    assert a['verified_switches']==r['applied_hint_count']
    assert all(('Switch is manually overridden' in w['text'] or 'Subroutine does not return' in w['text']) for w in v['warnings'])

qualifications=[]
for target,address,size in [('kill','0x1484e54',257528),('drawnpc1','0xf6954c',197576),('drawnpc2','0xf9a914',197772)]:
    selected=None
    for attempt in ('','-mem8','-commit8','-commit12'):
        folder=LAB/f'pseudocode-copy-rule-off-c-{target}{attempt}-20261019'
        review=LAB/f'copy-rule-off-{target}{attempt}-c-review-20261019.json'
        if (folder/'audit.json').exists() and review.exists():
            selected=(folder,review,attempt);break
    if selected is None:continue
    folder,review,attempt=selected
    r=json.loads((folder/'result.json').read_text());a=json.loads((folder/'audit.json').read_text());v=json.loads(review.read_text())
    check(r,a,v)
    assert r['address']==address and r['function_source_bytes_verified']==size
    assert a['result_sha256']==v['result_sha256']==sha(folder/'result.json')
    assert v['audit_sha256']==sha(folder/'audit.json')
    assert r['c_sha256']==v['c_sha256']==sha(folder/r['file'])
    assert r['script_sha256']==sha(LAB/'copy-rule-off-sources-20261019/TerrariaCopyRuleOffProbe.java')
    assert sha(LAB/'copy-rule-off-sources-20261019/audit_terraria_copy_rule_off.py')==AUDITOR
    negative=0
    for section,key,value in [('r','actual_C_object_returned',False),('r','timed_out',True),('r','explicit_model_restoration_verified',False),('r','actual_engine_sha256','0'*64),('a','integrity_passed',False),('a','eligible_for_new_C_coverage',True),('v','missing_goto_labels',['missing']),('v','lexical_errors',['bad'])]:
        rr,aa,vv=copy.deepcopy((r,a,v)); {'r':rr,'a':aa,'v':vv}[section][key]=value
        try:check(rr,aa,vv)
        except AssertionError:negative+=1
        else:raise AssertionError('Negative control accepted')
    qualifications.append(dict(target=target,attempt=attempt,address=address,FDE_bytes=size,C_bytes=r['c_bytes'],C_sha256=r['c_sha256'],
        result_sha256=sha(folder/'result.json'),audit_sha256=sha(folder/'audit.json'),lexical_review_sha256=sha(review),
        producer_sha256=r['script_sha256'],auditor_sha256=AUDITOR,engine_sha256=ENGINE,
        accepted_for_separate_conditional_export_metric=True,original_diagnostic_audit_unchanged=True,
        qualifier_negative_controls_rejected=negative))
assert qualifications
total=sum(r['FDE_bytes'] for r in qualifications)
record=dict(metric='FDE address/bytes associated with completed conditional C exports, including prior conditional candidates',
    qualifier_sha256=sha(Path(__file__)),independent_source_review_sha256=sha(TOOLS/'TERRARIA_COPY_RULE_OFF_REVIEW.md'),
    qualifications=qualifications,baseline_addresses=123149,baseline_bytes=34520124,
    conditional_C_export_addresses=123149+len(qualifications),total_FDE_addresses=123152,
    conditional_C_export_FDE_bytes=34520124+total,total_FDE_bytes=35173000,
    percent_conditional_C_export_FDE_bytes=100*(34520124+total)/35173000,
    canonical_manifest_modified=False,original_Csharp_recovered=False,compilation_verified=False,semantic_equivalence_verified=False,
    conditions='Exact producer/engine pins; typerecovery/conditionalexe/nodejoin/returnsplit off; requested propagatecopy off. Known islands, manual switches, conditional NoReturn ABI/no exceptional reentry assumptions retained. Incomplete incoming edges/CFG, unresolved types/prototypes/registers. Diagnostic C header omits the extra rule request; this notice supplies it. This metric does not establish all native executable code, original source, reachability, correctness or buildability.')
output=LAB/f'copy-rule-off-conditional-export-qualification-{len(qualifications)}-20261019.json'
assert not output.exists(),'Preserve previous qualification'
output.write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record))
