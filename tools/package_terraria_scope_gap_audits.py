"""Preserve source-bound denominator and executable-gap audits without C additions."""
import hashlib,json,pathlib,shutil
LAB=pathlib.Path('C:/Temp/terraria-re-20261012')
ROOT=pathlib.Path('C:/Private/Documents/ChatGPT/Terraria-Reverse-20261012')
REPO=pathlib.Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    baseline=ROOT/'artifact-manifest.json'
    assert sha(baseline)=='94cae77db018fee38c09e3b69f203b5fc0fbfd55b40c4aabbb935e30c61b391a'
    specifications=[('fde-byte-scope-audit-20261016','audit_terraria_fde_byte_scope.py','5588a08e9b8691aed171d75e1417ae0dae64f87a89103dd749617b41455075d5'),('executable-gap-patterns-20261016','audit_terraria_executable_gap_patterns.py','41325d484645e73d11bcc96104a485d2d7ec857df4a5fe6be17ea293645bc1d4')]
    documents=[]
    for folder,tool,pinned in specifications:
        source=LAB/folder
        assert sha(source/'evidence.json')==pinned
        evidence=json.loads((source/'evidence.json').read_text())
        repeated=json.loads((source/'root-recheck.json').read_text())
        assert evidence['integrity_passed'] and evidence['auditor_sha256']==sha(REPO/'tools'/tool)
        for doc in (evidence,repeated):
            doc.pop('audit_time_UTC',None);doc.pop('coverage_snapshot_path',None)
        assert evidence==repeated
        if folder.startswith('fde-'):assert sha(source/'coverage-snapshot.json')==evidence['coverage_snapshot_sha256']
        shutil.copytree(source,ROOT/folder,dirs_exist_ok=True)
        documents.append(evidence)
    scope,gaps=documents
    assert gaps['parent_evidence_sha256']==specifications[0][2]
    assert sum(gaps['deduplicated_partition_bytes'].values())==gaps['gap_total_bytes']==480092
    crt=LAB/'crt-gap-bridge-20261016'
    assert sha(crt/'evidence.json')=='bf7883667b798d8045777c0744df455ee8e98498b9f62df8359dae406a8c20ef'
    crt_doc=json.loads((crt/'evidence.json').read_text())
    assert crt_doc==json.loads((crt/'root-recheck.json').read_text())
    assert crt_doc['integrity_passed'] and crt_doc['auditor_sha256']==sha(REPO/'tools/audit_terraria_crt_gap_bridge.py')
    assert sha(crt/'manual_conditional_ABI_model.c')=='225b892bed86912e58823bf43fb425a90a649a9ecff6ac2a3c28ef4085d06383'
    for row in json.loads((crt/'manifest.json').read_text()):
        file=crt/row['path'];assert file.resolve().parent==crt.resolve() and sha(file)==row['sha256'] and file.stat().st_size==row['bytes']
    shutil.copytree(crt,ROOT/crt.name,dirs_exist_ok=True)
    stage=ROOT/'scope-gap-continuation-20261016';stage.mkdir(exist_ok=True)
    summary={'C_coverage_addition':0,'historical_remaining_without_C':scope['remaining_without_C_count'],'FDE_union_bytes':scope['FDE_union_bytes'],'executable_sections_union_bytes':scope['executable_sections_union_bytes'],'executable_section_bytes_outside_FDE':gaps['gap_total_bytes'],'gap_partition_bytes':gaps['deduplicated_partition_bytes'],'runtime_or_semantic_equivalence_verified':False}
    (stage/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    (stage/'REPORT.ru.md').write_text('# Границы метрики покрытия и байты вне FDE\n\nСнимок при восьми оставшихся методах: 95,0979% исходных FDE-байтов имеют C-представления с условными кандидатами. Это не процент восстановленного исходного проекта или семантической эквивалентности.\n\nПолный FDE-каталог занимает 35 173 000 байтов без перекрытий; исполняемые секции — 35 653 092 байта. Вне FDE: 480 092 байта, из них PLT 8 992, известные внешние блоки 1 712, нулевые слова 468 868, остаток 520. Кодировка и флаги секций не доказывают назначение или достижимость этих байтов.\n\n[Аудит знаменателя и сохранённый снимок](../fde-byte-scope-audit-20261016/REPORT.ru.md) · [Классификация промежутков](../executable-gap-patterns-20261016/REPORT.ru.md). Оба аудита повторно выполнены; исходный комплект результатов не изменён. Новых C-адресов нет.\n',encoding='utf8')
    tools=stage/'tools';tools.mkdir(exist_ok=True)
    with (stage/'REPORT.ru.md').open('a',encoding='utf8') as report:report.write('\n60-байтный остаток связан с CRT/atexit-мостами: импорты, GOT и fini_array проверены отдельно. [Регистровые факты и ручная условная ABI-модель](../crt-gap-bridge-20261016/REPORT.ru.md). Эта модель не является Ghidra C и не увеличивает покрытие.\n')
    for name in ('package_terraria_scope_gap_audits.py','audit_terraria_crt_gap_bridge.py',*[s[1] for s in specifications]):shutil.copy2(REPO/'tools'/name,tools/name)
    folders=[s[0] for s in specifications]+[crt.name,stage.name]
    rows=[{'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)} for folder in folders for p in sorted((ROOT/folder).rglob('*')) if p.is_file() and p.name!='addendum-manifest.json']
    (stage/'addendum-manifest.json').write_text(json.dumps({'prior_manifest_sha256':sha(baseline),'files':rows},indent=2)+'\n')
    for row in rows:assert sha(ROOT/row['path'])==row['sha256']
    print(json.dumps({'report':str(stage/'REPORT.ru.md'),'C_coverage_addition':0,'files':len(rows)}))
if __name__=='__main__':main()
