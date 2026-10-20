"""Freeze a narrowly selected V3-derived retry profile; no Java/native execution."""
import hashlib
import json
from pathlib import Path
import shutil
import difflib

LAB = Path('C:/Temp/terraria-re-20261012')
WORK = Path(__file__).resolve().parent
DEST = WORK / 'apk-native-cpp-timeout120-20261020'
PRIVATE = LAB / 'other-native-cpp-timeout120-20261020'
PROFILE = 'apk-native-bounded-range-C-v4-cpp-timeout120-selected7'
SELECTED = ['0xa3f28', '0xb25c0', '0xc3238', '0xc3920', '0xc3d08', '0xc3e34', '0xc421c']
BASE_MANIFEST = LAB / 'other-native-range-v3-manifests-20261019/libc++_shared.so.manifest.json'
BASE_MANIFEST_SHA = 'fb6e63a17459d06cc00cbb5835e00268e2e4ae78825b47c0faedda35c8551f10'
BASE_SOURCE_SHA = '2abbe851f83a5bcde7864dda26652cdb7083d10634fea796bf9506e375cea3a0'
BASE_AUDIT_SHA = '90d8b5371f848e67c1b628fb3fc3c5485553aff21bf8bb4ea384881056f9ed7f'
sha = lambda b: hashlib.sha256(b).hexdigest()


def checked(path, expected):
    raw = path.read_bytes()
    assert sha(raw) == expected, str(path)
    return raw


def replace(text, old, new):
    assert text.count(old) == 1, (old, text.count(old))
    return text.replace(old, new)


def fresh(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as f:
        f.write(raw)


def main():
    assert not DEST.exists() and not PRIVATE.exists(), 'Fresh versioned directories required'
    source = checked(WORK / 'apk-native-v3/ApkNativeRangeExport.java', BASE_SOURCE_SHA).decode()
    audit = checked(WORK / 'apk-native-v3/audit_apk_native_range_export_v3.py', BASE_AUDIT_SHA).decode()
    base_raw = checked(BASE_MANIFEST, BASE_MANIFEST_SHA)
    base = json.loads(base_raw)
    assert len(base['rows']) == 2275
    failures_raw = (LAB / 'native-export-failures-20261019/failures.json').read_bytes()
    failures = [x for x in json.loads(failures_raw) if x['library'] == 'libc++_shared.so']
    assert [x['original_manifest_row']['address'] for x in failures] == SELECTED
    rows = {r['address']: r for r in base['rows']}
    for f in failures:
        assert f['timed_out'] is True and f['configured_timeout_seconds'] == 20
        raw = checked(Path(f['result_path']), f['result_sha256'])
        r = json.loads(raw)
        assert r['status'] == 'decompile_failed' and r['timed_out'] is True and r['timeout_seconds'] == 20
        assert r['profile'] == base['profile'] and r['manifest_sha256'] == BASE_MANIFEST_SHA
        assert f['original_manifest_row'] == rows[r['address']]

    oldprofile = 'apk-native-bounded-range-C-v3-conditional-stackchk'
    v4 = source.replace(oldprofile, PROFILE)
    v4 = replace(v4, 'static final int TIMEOUT=20,MAX_INS=100000,MAX_PAYLOAD=64;',
                 'static final int TIMEOUT=120,MAX_INS=100000,MAX_PAYLOAD=64;\n'
                 '    static final List<String> EXPECTED_SELECTED=List.of(' + ','.join('"'+x+'"' for x in SELECTED) + ');\n'
                 '    final Set<String> selected=new LinkedHashSet<>();')
    v4 = replace(v4, 'p.addProperty("not_attempted_rows",rows.size()-done.size());p.addProperty("all_rows_attempted",done.size()==rows.size());',
                 'p.addProperty("not_attempted_rows",rows.size()-done.size());p.addProperty("all_rows_attempted",done.size()==rows.size());\n'
                 '        p.addProperty("selected_export_rows",selected.size());p.addProperty("not_attempted_selected_rows",selected.size()-done.size());\n'
                 '        p.addProperty("all_selected_rows_attempted",done.size()==selected.size());')
    v4 = replace(v4, 'require(row!=null&&!done.containsKey(address),"Unknown or duplicate journal row");',
                 'require(row!=null&&selected.contains(address)&&!done.containsKey(address),"Unselected, unknown or duplicate journal row");')
    v4 = replace(v4, 'require(!rows.isEmpty(),"Empty manifest");int max=rows.size();boolean resume=false;',
                 'require(rows.size()==2275,"Expected full libc++ boundary universe");\n'
                 '        JsonArray selection=m.getAsJsonArray("export_addresses");require(selection!=null&&selection.size()==EXPECTED_SELECTED.size(),"Exact export selection required");\n'
                 '        for(int i=0;i<selection.size();i++){String a=selection.get(i).getAsString();require(a.equals(EXPECTED_SELECTED.get(i))&&rows.containsKey(a)&&selected.add(a),"Wrong/duplicate/unbounded export selection");}\n'
                 '        int max=selected.size();boolean resume=false;')
    v4 = replace(v4, 'identity.addProperty("normal_decompile_action",true);identity.addProperty("default_imported_types",true);identity.addProperty("workers",1);',
                 'identity.addProperty("normal_decompile_action",true);identity.addProperty("default_imported_types",true);identity.addProperty("workers",1);\n'
                 '        identity.add("export_addresses",m.get("export_addresses"));identity.addProperty("selected_export_rows",selected.size());identity.addProperty("total_manifest_rows",rows.size());')
    v4 = replace(v4, 'if(done.containsKey(item.getKey()))continue;if(attempted>=max)break;monitor.checkCancelled();',
                 'if(!selected.contains(item.getKey())||done.containsKey(item.getKey()))continue;if(attempted>=max)break;monitor.checkCancelled();')
    v4 = replace(v4, 'progress(done.size()==rows.size()?"all_rows_attempted":"bounded_subset_returned");',
                 'progress(done.size()==selected.size()?"all_selected_rows_attempted":"bounded_selected_subset_returned");')
    producer_sha = sha(v4.encode())

    v4audit = audit.replace(oldprofile, PROFILE).replace(BASE_SOURCE_SHA, producer_sha)
    v4audit = v4audit.replace('timeout_seconds=20', 'timeout_seconds=120')
    v4audit = replace(v4audit, 'def main():',
        'EXPECTED_SELECTED = ' + repr(SELECTED) + '\n'
        'BASE_MANIFEST_SHA = ' + repr(BASE_MANIFEST_SHA) + '\n\n'
        'def selection(m, rows):\n'
        '    check(len(rows)==2275,"Full boundary universe must contain 2275 rows")\n'
        '    check(m["export_addresses"]==EXPECTED_SELECTED,"Exact ordered selected seven required")\n'
        '    check(len(set(m["export_addresses"]))==7 and all(a in rows for a in m["export_addresses"]),"Selection outside boundary universe")\n'
        '    return set(m["export_addresses"])\n\n'
        'def selected_commits(commits, selected):\n'
        '    check(all(c["address"] in selected for c in commits),"Unselected journal address")\n\n'
        'def selection_controls(m, rows):\n'
        '    rejected=[]\n'
        '    for label, changed in [("selection_duplicate",EXPECTED_SELECTED[:-1]+[EXPECTED_SELECTED[0]]), ("selection_outside_universe",EXPECTED_SELECTED[:-1]+["0x0"]), ("selection_wrong_known_row",EXPECTED_SELECTED[:-1]+[next(a for a in rows if a not in EXPECTED_SELECTED)]), ("selection_partial",EXPECTED_SELECTED[:-1]), ("selection_reordered",list(reversed(EXPECTED_SELECTED)))]:\n'
        '        bad=copy.deepcopy(m);bad["export_addresses"]=changed\n'
        '        try: selection(bad,rows)\n'
        '        except ValueError: rejected.append(label)\n'
        '        else: raise ValueError("Selection negative accepted: "+label)\n'
        '    try: selected_commits([dict(address=next(a for a in rows if a not in EXPECTED_SELECTED))],set(EXPECTED_SELECTED))\n'
        '    except ValueError: rejected.append("unselected_committed_row")\n'
        '    else: raise ValueError("Unselected commit accepted")\n'
        '    return rejected\n\n\n'
        'def main():')
    v4audit = replace(v4audit, "loads = executable_loads(elf_raw); rows = work_rows(m['rows'], elf_raw, loads)",
        "loads = executable_loads(elf_raw); rows = work_rows(m['rows'], elf_raw, loads)\n"
        "    selected=selection(m,rows)\n"
        "    baseline_raw=Path(m['baseline_manifest_file']).read_bytes();digest_matches(baseline_raw,BASE_MANIFEST_SHA)\n"
        "    baseline=parse(baseline_raw)\n"
        "    check(m['baseline_manifest_sha256']==BASE_MANIFEST_SHA,'Wrong baseline identity')\n"
        "    expected=copy.deepcopy(baseline);expected['profile']=PROFILE;expected['limits']['timeout_seconds']=120\n"
        "    expected.update(export_addresses=EXPECTED_SELECTED,baseline_manifest_file=m['baseline_manifest_file'],baseline_manifest_sha256=BASE_MANIFEST_SHA)\n"
        "    check(m==expected,'Unreviewed manifest change from frozen V3 baseline')")
    v4audit = replace(v4audit, "controls = negatives(elf_raw, loads, m['rows'][0], args.output_dir)",
                         "controls = negatives(elf_raw, loads, m['rows'][0], args.output_dir)+selection_controls(m,rows)")
    v4audit = replace(v4audit, 'preflight_only=args.preflight_only, original_source_recovered=False, semantic_equivalence_verified=False)',
                        'preflight_only=args.preflight_only, selected_export_rows=len(selected), export_addresses=EXPECTED_SELECTED, original_source_recovered=False, semantic_equivalence_verified=False)')
    v4audit = replace(v4audit, "root = args.output_dir.resolve(); run = parse(artifact(root, 'run.json').read_bytes())",
        "root = args.output_dir.resolve(); run = parse(artifact(root, 'run.json').read_bytes())\n"
        "        check(run['export_addresses']==EXPECTED_SELECTED and run['selected_export_rows']==7 and run['total_manifest_rows']==2275,'Run selection/universe mismatch')")
    v4audit = replace(v4audit, "journal_raw = artifact(root, 'journal.jsonl').read_bytes(); commits = journal_rows(journal_raw)",
        "journal_raw = artifact(root, 'journal.jsonl').read_bytes(); commits = journal_rows(journal_raw);selected_commits(commits,selected)\n"
        "        progress=parse(artifact(root,'progress.json').read_bytes())\n"
        "        expected_progress=dict(profile=PROFILE,total_manifest_rows=2275,attempted_rows=len(commits),not_attempted_rows=2275-len(commits),all_rows_attempted=len(commits)==2275,selected_export_rows=7,not_attempted_selected_rows=7-len(commits),all_selected_rows_attempted=len(commits)==7,semantic_equivalence_verified=False,original_source_recovered=False)\n"
        "        for k,v in expected_progress.items():check(type(progress[k]) is type(v) and progress[k]==v,'Progress mismatch: '+k)")
    v4audit = replace(v4audit, 'all_rows_attempted=len(commits)==len(rows), status_counts=dict(counts), C_text_scans=texts,',
        'all_rows_attempted=len(commits)==len(rows), all_selected_rows_attempted=len(commits)==len(selected),\n'
        '                       not_attempted_selected_rows=len(selected)-len(commits), status_counts=dict(counts), C_text_scans=texts,')
    v4audit = replace(v4audit, "expected_artifacts = {c['result_file'] for c in commits}",
        "check(progress['successful_C_rows']==counts['decompiled'],'Progress successful C count mismatch')\n"
        "        expected_artifacts = {c['result_file'] for c in commits}")
    compile(v4audit, 'audit_cpp_timeout120.py', 'exec')

    manifest = json.loads(base_raw)
    manifest['profile'] = PROFILE
    manifest['limits']['timeout_seconds'] = 120
    manifest.update(export_addresses=SELECTED, baseline_manifest_file=str(BASE_MANIFEST), baseline_manifest_sha256=BASE_MANIFEST_SHA)
    fresh(DEST/'ApkNativeRangeExport.java', v4.encode())
    fresh(DEST/'audit_cpp_timeout120.py', v4audit.encode())
    fresh(DEST/'producer-from-v3.patch', ''.join(difflib.unified_diff(source.splitlines(True),v4.splitlines(True),fromfile='V3',tofile='V4')).encode())
    fresh(DEST/'auditor-from-v3.patch', ''.join(difflib.unified_diff(audit.splitlines(True),v4audit.splitlines(True),fromfile='V3',tofile='V4')).encode())
    fresh(PRIVATE/'libc++_shared.so.manifest.json', (json.dumps(manifest,indent=2)+'\n').encode())
    fresh(PRIVATE/'baseline.manifest.json', base_raw)
    fresh(PRIVATE/'selected-original-failures.json', (json.dumps(failures,indent=2)+'\n').encode())
    source_dir=PRIVATE/'sources'
    fresh(source_dir/'ApkNativeRangeExport.java', v4.encode())
    fresh(source_dir/'tools/profile/audit_cpp_timeout120.py', v4audit.encode())
    for name in ['prove_apk_stackchk_imports.py','prove_libmain_stackchk_import.py']:
        fresh(source_dir/'tools'/name,(WORK/name).read_bytes())
    record=dict(profile=PROFILE,prepared_only=True,native_engine_or_JVM_run=False,selected_export_rows=7,total_boundary_universe_rows=2275,
        selected_addresses=SELECTED,producer_sha256=producer_sha,auditor_sha256=sha(v4audit.encode()),
        baseline_producer_sha256=BASE_SOURCE_SHA,baseline_auditor_sha256=BASE_AUDIT_SHA,
        baseline_manifest_sha256=BASE_MANIFEST_SHA,manifest_sha256=sha((PRIVATE/'libc++_shared.so.manifest.json').read_bytes()),
        failure_inventory_sha256=sha(failures_raw),source_failure_result_sha256={f['original_manifest_row']['address']:f['result_sha256'] for f in failures},
        behavioral_changes=['versioned profile','per-function timeout 20 to120 seconds','export selected seven only; all2275 boundaries still prepared'],
        source=str(source_dir/'ApkNativeRangeExport.java'),auditor=str(source_dir/'tools/profile/audit_cpp_timeout120.py'),
        manifest=str(PRIVATE/'libc++_shared.so.manifest.json'),output=str(PRIVATE/'output'),audit_output=str(PRIVATE/'final-audit.json'),
        source_not_compiled=True,semantic_equivalence_verified=False,original_source_recovered=False)
    fresh(PRIVATE/'preparation.json',(json.dumps(record,indent=2)+'\n').encode())
    print(json.dumps(record,indent=2))


if __name__=='__main__':main()
