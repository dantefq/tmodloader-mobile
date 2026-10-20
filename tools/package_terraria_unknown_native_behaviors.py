"""Package an independently audited private addendum, preserving prior artifacts."""
import argparse, hashlib, json, pathlib, shutil


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);ap.add_argument('--delivery',type=pathlib.Path,required=True);a=ap.parse_args()
    repo=pathlib.Path(__file__).resolve().parents[1];source=a.lab/'unknown-native-behaviors-v1';root=a.delivery.resolve();out=root/source.name
    if out.is_relative_to(repo) or out==source.resolve():raise ValueError('Separate private delivery required')
    baseline=root/'artifact-manifest.json';before=sha(baseline)
    if before!='94cae77db018fee38c09e3b69f203b5fc0fbfd55b40c4aabbb935e30c61b391a':raise ValueError('Unexpected prior delivery')
    doc=json.loads((source/'behaviors.json').read_text());audit=json.loads((source/'independent-audit.json').read_text())
    if audit.get('integrity_passed') is not True or audit['behaviors_sha256']!=sha(source/'behaviors.json'):raise ValueError('Stale/failed audit')
    if len(audit.get('negative_controls_rejected',[]))!=5 or audit['described_functions']!=doc['structurally_described']:raise ValueError('Incomplete audit scope')
    if audit['auditor_sha256']!=sha(repo/'tools/audit_terraria_unknown_native_behaviors.py') or doc['producer_sha256']!=sha(repo/'tools/terraria_unknown_native_behaviors.py'):raise ValueError('Changed analysis tools')
    for name,digest in doc['inputs'].items():
        if pathlib.Path(name).name!=name or sha(a.lab/'native'/name)!=digest:raise ValueError('Changed source input')
    provenance=json.loads((source/'report-provenance.json').read_text())
    if provenance['behavior_source_sha256']!=sha(source/'behaviors.json') or provenance['report_tool_sha256']!=sha(repo/'tools/report_terraria_unknown_native_behaviors.py'):raise ValueError('Stale report')
    selected={r['address'] for r in doc['results']};verified=set()
    with (a.lab/'native-ranges-pseudocode/coverage.jsonl').open(encoding='utf8') as stream:
        for line in stream:
            r=json.loads(line)
            if r['address'] not in selected:continue
            rel=pathlib.PurePosixPath(r['file'])
            if rel.is_absolute() or '..' in rel.parts:raise ValueError('Unsafe linked C path')
            src=a.lab/'native-ranges-pseudocode'/rel;dst=root/'native-ranges-pseudocode'/rel
            if not src.resolve().is_relative_to((a.lab/'native-ranges-pseudocode').resolve()) or not dst.resolve().is_relative_to((root/'native-ranges-pseudocode').resolve()):raise ValueError('Unconfined linked C')
            if sha(src)!=r['file_sha256'] or sha(dst)!=r['file_sha256']:raise ValueError('Prior linked C changed')
            verified.add(r['address'])
    if verified!=selected:raise ValueError('Incomplete prior C link checks')
    out.mkdir(parents=True,exist_ok=True)
    for p in source.iterdir():
        if p.is_file() and p.name!='addendum-manifest.json':shutil.copy2(p,out/p.name)
    tools=out/'tools';tools.mkdir(exist_ok=True)
    for name in ('terraria_unknown_native_behaviors.py','audit_terraria_unknown_native_behaviors.py','report_terraria_unknown_native_behaviors.py','package_terraria_unknown_native_behaviors.py','terraria_flow_islands.py','terraria_native_map.py','terraria-analysis-requirements.txt'):
        shutil.copy2(repo/'tools'/name,tools/name)
    rows=[{'path':p.relative_to(out).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(out.rglob('*')) if p.is_file() and p.name!='addendum-manifest.json']
    result={'profile':'unknown-native-behaviors-private-addendum-v1','prior_delivery_manifest_sha256':before,'source_elf_sha256':doc['inputs']['libil2cpp.so'],
            'described':doc['structurally_described'],'structurally_unclassified':doc['structurally_unclassified'],'semantic_role_still_unknown':8140,
            'verified_existing_C_links':len(verified),'files':rows,'file_count':len(rows),'scope':'File identity and conditional structural descriptions; not original source or recovered semantic purpose.'}
    (out/'addendum-manifest.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    for row in rows:
        if sha(out/row['path'])!=row['sha256']:raise ValueError('Delivery hash mismatch')
    if sha(baseline)!=before:raise ValueError('Prior manifest changed')
    print(json.dumps({'out':str(out),'files':len(rows),'existing_C_links_verified':len(verified),'prior_manifest_unchanged':True,'manifest_sha256':sha(out/'addendum-manifest.json')},ensure_ascii=False))


if __name__=='__main__':main()
