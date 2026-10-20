"""Checkpoint separately audited semantic refinements without changing C coverage."""
import hashlib,json,pathlib,shutil
LAB=pathlib.Path('C:/Temp/terraria-re-20261012')
ROOT=pathlib.Path('C:/Private/Documents/ChatGPT/Terraria-Reverse-20261012')
REPO=pathlib.Path(__file__).resolve().parents[1]
SPECS=[('npc-static-field-roots-20261015','npc-static-field-roots.json','independent-audit.json',
        'terraria_npc_static_field_roots.py','audit_terraria_npc_static_field_roots.py',
        'Условное присваивание NPCID.Sets.Factory: конструктор size 697, static offset 0.'),
       ('class-usage-root-catalog-20261015','catalog.json','independent-audit.json',
        'terraria_class_usage_root_catalog_20261015.py','audit_terraria_class_usage_roots_20261015.py',
        'Каталог 4 650 структурных class-root кандидатов; 4 580 имеют точные исходные вызовы resolver.'),
       ('projectile-ai-dispatch-20261015','dispatch.json','independent-audit.json',
        'terraria_projectile_ai_dispatch.py','audit_terraria_projectile_ai_dispatch.py',
        'Projectile.AI: поле aiStyle, восемь таблиц и 203 маршрута; inline-механики после переходов не проверены.'),
       ('itemsets-array-literals-20261015','array-literals.json','independent-audit.json',
        'terraria_itemsets_array_literals.py','audit_terraria_itemsets_array_literals.py',
        'ItemID.Sets: три сериализованных вектора (109 Int32) и связи вызовов с четырьмя статическими полями; runtime membership пока не доказан.'),
       ('initialize-array-copy-model-20261015','copy-model.json','independent-audit.json',
        'terraria_initialize_array_copy_model.py','audit_terraria_initialize_array_copy_model.py',
        'InitializeArray: условная цепь bsearch/memcpy для 436 байтов; cache/layout/element size остаются предпосылками.'),
       ('setfactory-set-algorithms-20261015','set-algorithms.json','independent-audit.json',
        'terraria_setfactory_set_algorithms.py','audit_terraria_setfactory_set_algorithms.py',
        'CreateBoolSet/CreateIntSet: исходные циклы и четыре условные модели массивов длины 6196, без наблюдения runtime.'),
       ('setfactory-buffer-model-20261015','buffer-model.json','independent-audit.json',
        'terraria_setfactory_buffer_model.py','audit_terraria_setfactory_buffer_model.py',
        'GetBoolBuffer/GetIntBuffer: условный length==_size на пустом cache; повторно используемые буферы требуют отдельных invariants.')]
def sha(p):
    with p.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def main():
    prior=ROOT/'artifact-manifest.json'
    assert sha(prior)=='94cae77db018fee38c09e3b69f203b5fc0fbfd55b40c4aabbb935e30c61b391a'
    out=LAB/'semantic-continuation-20261015';out.mkdir(exist_ok=True)
    verified=[];folders=[];tools={pathlib.Path(__file__).name}
    for folder,filename,auditname,producer,auditor,description in SPECS:
        source=LAB/folder
        if not (source/filename).exists() or not (source/auditname).exists():continue
        d=json.loads((source/filename).read_text(encoding='utf8'));a=json.loads((source/auditname).read_text(encoding='utf8'))
        assert a['integrity_passed'] and a['evidence_sha256']==sha(source/filename)
        assert d['producer_sha256']==sha(REPO/'tools'/producer) and a['auditor_sha256']==sha(REPO/'tools'/auditor)
        dependencies=d.get('dependencies',{})
        pairs=dependencies.items() if isinstance(dependencies,dict) else [(r['relative_lab_path'],r['sha256']) for r in dependencies]
        for dep,digest in pairs:
            p=LAB/dep;assert p.resolve().is_relative_to(LAB.resolve()) and sha(p)==digest
            assert sha(ROOT/dep)==digest, 'Deliver the frozen dependency before its extension'
        if folder=='class-usage-root-catalog-20261015':
            assert sha(source/'roots.jsonl')==d['roots_jsonl_sha256'] and sha(source/'exact-init-calls.jsonl')==d['exact_calls_jsonl_sha256']
            assert a['roots_verified']==4650 and a['exact_calls_verified']==67009 and len(a['negative_controls_rejected'])==11
        if folder=='projectile-ai-dispatch-20261015':
            assert d['router_instruction_count']==a['router_instruction_count']==173 and d['table_routes_1_to_210']==203
            assert len(d['tables'])==8 and d['runtime_verified'] is False
        if folder=='itemsets-array-literals-20261015':
            assert a['serialized_blobs_verified']==len(d['arrays'])==3 and a['serialized_Int32_values_verified']==109
            assert a['literal_blob_bytes_verified']==436 and a['runtime_array_contents_or_set_membership_proven'] is False
            assert len(a['negative_controls_rejected'])==6
        if folder=='initialize-array-copy-model-20261015':
            assert a['sorted_unique_default_records']==29227 and a['conditional_copy_bytes']==436 and a['arrays_verified']==3
            assert d['runtime_verified'] is False and d['full_set_membership_proven'] is False and len(a['negative_controls_rejected'])==10
        if folder=='setfactory-set-algorithms-20261015':
            assert a['native_instruction_bytes_verified']==300 and a['modeled_arrays_verified']==len(d['results'])==4
            assert a['unique_sparse_edits']==[3,95,4,1] and a['actual_runtime_execution_proven'] is False
            assert len(a['negative_controls_rejected'])==6
        if folder=='setfactory-buffer-model-20261015':
            assert a['source_instruction_bytes_verified']==904 and a['factory_fields_verified']==4 and a['array_roots_verified']==2
            assert a['native_length_header_store_verified'] and a['runtime_execution_proven'] is False
            assert a['full_cached_length_or_ownership_invariant_proven'] is False and len(a['negative_controls_rejected'])==6
        verified.append({'folder':folder,'description':description,'evidence_sha256':sha(source/filename),'audit_sha256':sha(source/auditname),'C_coverage_addition':0})
        folders.append(folder);tools|={producer,auditor}
    assert verified
    summary={'date':'2026-10-15','verified_refinements':verified,'C_coverage_addition':0,'runtime_equivalence_verified':False,'original_Csharp_recovered':False}
    (out/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    lines=['# Уточнения связей и поведения Terraria','','Эти отдельные доказательства уточняют метаданные и исходные инструкции. Они не увеличивают счётчик C-представлений. Предпосылки нормального исполнения и ограничения указаны в каждом отчёте.','']
    lines += [f"- [{r['description']}](../{r['folder']}/REPORT.ru.md)" for r in verified]
    lines += ['', '[Сводка и хеши](summary.json). Исходный APK и прежний корпус сохранены.']
    (out/'REPORT.ru.md').write_text('\n'.join(lines)+'\n',encoding='utf8');folders.append(out.name)
    for folder in folders:shutil.copytree(LAB/folder,ROOT/folder,dirs_exist_ok=True)
    dest=ROOT/out.name;(dest/'tools').mkdir(exist_ok=True)
    for name in sorted(tools):shutil.copy2(REPO/'tools'/name,dest/'tools'/name)
    rows=[{'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)} for folder in folders for p in sorted((ROOT/folder).rglob('*')) if p.is_file() and p.name!='addendum-manifest.json']
    (dest/'addendum-manifest.json').write_text(json.dumps({'prior_manifest_sha256':sha(prior),'files':rows},indent=2)+'\n')
    for r in rows:assert sha(ROOT/r['path'])==r['sha256']
    print(json.dumps({'report':str(dest/'REPORT.ru.md'),'refinements':len(verified),'files':len(rows)},ensure_ascii=False))
if __name__=='__main__':main()
