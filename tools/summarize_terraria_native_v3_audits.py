"""Consolidate disjoint per-library final audits without summing overlapping profiles."""
import collections
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

LAB=Path(r'C:\Temp\terraria-re-20261012')
digest=lambda p: hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    manifests=LAB/'other-native-range-v3-manifests-20261019'
    inventory=json.loads((manifests/'summary.json').read_text())
    preferences=json.loads((Path(__file__).parent/'terraria_apk_scope_preferences.json').read_text())
    excluded=set(preferences['excluded_native_libraries'])
    rows=[]; issues=[]; inputs=[]
    for entry in inventory:
        library=entry['library']; slug=library.removesuffix('.so').replace('+','p')
        manifest=manifests/(library+'.manifest.json')
        assert digest(manifest)==entry['manifest_sha256']
        inputs.append(dict(path=str(manifest),sha256=digest(manifest)))
        audit=LAB/(f'other-native-{slug}-final-v3-audit-20261019.json' if library!='libmain.so'
                   else 'other-native-libmain-smoke-v3-audit-20261019.json')
        prefix_audit=LAB/'other-native-external_wrapper-restored-prefix1553-v3-audit-20261019.json'
        if library=='libexternal_wrapper.so' and not audit.exists() and prefix_audit.exists():
            audit=prefix_audit
        row=dict(library=library,queue_rows=entry['rows'],queued_input_bytes=entry['queued_bytes'],
                 requested_scope=library not in excluded,
                 independently_audited_attempts=0,C_texts=0,remaining_queue_rows=entry['rows'],
                 failed_exports=0,marker_flagged_C_texts=0,retained_pcode_outside_rows=0)
        if audit.exists():
            data=json.loads(audit.read_text())
            assert data['integrity_passed'] and not data['preflight_only']
            assert data['total_manifest_rows']==entry['rows']
            assert data['manifest_sha256']==entry['manifest_sha256']
            inputs.append(dict(path=str(audit),sha256=digest(audit)))
            counts=data['status_counts']; attempted=data['attempted_rows']; texts=counts.get('decompiled',0)
            row.update(independently_audited_attempts=attempted,C_texts=texts,
                       audit_path=str(audit),all_manifest_rows_audited=data['all_rows_attempted'],
                       remaining_queue_rows=entry['rows']-attempted,
                       failed_exports=attempted-texts,
                       marker_flagged_C_texts=texts-data['C_text_rows_without_detected_truncation_markers'],
                       retained_pcode_outside_rows=data['C_text_rows_with_retained_pcode_outside_extent'],
                       marker_free_and_retained_scope_inside_rows=data['conditional_export_rows_without_detected_truncation_and_with_retained_scope_inside'])
            for text in data['C_text_scans']:
                if text['truncation_or_unimplemented_marker_detected'] or text['retained_high_pcode_scope']['outside_instruction_addresses']:
                    issues.append(dict(library=library,address=text['address'],c_sha256=text['c_sha256'],
                                       marker_flagged=text['truncation_or_unimplemented_marker_detected'],
                                       marker_counts=text['limited_marker_counts'],
                                       outside_instruction_addresses=text['retained_high_pcode_scope']['outside_instruction_addresses']))
        rows.append(row)
    totals={k:sum(r.get(k,0) for r in rows) for k in ('queue_rows','queued_input_bytes','independently_audited_attempts','C_texts','remaining_queue_rows','failed_exports','marker_flagged_C_texts','retained_pcode_outside_rows')}
    assert totals['queue_rows']==51420
    assert totals['independently_audited_attempts']+totals['remaining_queue_rows']==totals['queue_rows']
    assert totals['C_texts']+totals['failed_exports']==totals['independently_audited_attempts']
    requested_totals={k:sum(r.get(k,0) for r in rows if r['requested_scope']) for k in totals}
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out=LAB/('other-native-v3-audited-checkpoint-'+stamp);out.mkdir()
    summary=dict(created_UTC=stamp,scope='Seven disjoint explicit native queues, not all executable bytes or original source',
                 libraries=rows,totals=totals,requested_scope_totals=requested_totals,
                 excluded_native_libraries=sorted(excluded),inputs=inputs,producer_sha256=digest(Path(__file__)),
                 semantic_equivalence_verified=False,original_source_recovered=False,whole_APK_percent=None)
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf8')
    (out/'C-review-issues.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in issues),encoding='utf8')
    print(json.dumps(dict(checkpoint=str(out),totals=totals,requested_scope_totals=requested_totals)))

if __name__=='__main__':main()
