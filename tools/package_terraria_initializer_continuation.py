"""Checkpoint completed isolated initializers and independently audited API links."""
import hashlib,json,pathlib,shutil
LAB=pathlib.Path('C:/Temp/terraria-re-20261012')
ROOT=pathlib.Path('C:/Private/Documents/ChatGPT/Terraria-Reverse-20261012')
REPO=pathlib.Path(__file__).resolve().parents[1]
TARGETS={'pseudocode-itemsets-isolated-20261015':'0x1a893ac','pseudocode-bestiary-isolated-20261015':'0xb1ab78','pseudocode-npcsets-isolated-20261015':'0x1aae9b4','pseudocode-tileinit-isolated-20261015':'0x19cba0c'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    prior=ROOT/'artifact-manifest.json';assert sha(prior)=='94cae77db018fee38c09e3b69f203b5fc0fbfd55b40c4aabbb935e30c61b391a'
    baseline=json.loads((ROOT/'selected-continuation-20261015/summary.json').read_text());assert baseline['remaining_hard_methods_without_C']==13
    folders=[];attempts=[];candidates=[];pending=[]
    for folder,address in TARGETS.items():
        source=LAB/folder
        if not (source/'result.json').exists() or not (source/'audit.json').exists():pending.append({'folder':folder,'address':address});continue
        r=json.loads((source/'result.json').read_text());a=json.loads((source/'audit.json').read_text())
        assert r['address']==address and a['integrity_passed'] and a['result_sha256']==sha(source/'result.json')
        assert r['script_sha256']==sha(REPO/'tools/TerrariaHardSelectedProbe.java') and a['auditor_sha256']==sha(REPO/'tools/audit_terraria_initializer_isolated.py')
        assert r['ephemeral_transaction_rolled_back'] is True and r['saved_project_modified'] is False
        attempts.append({'method':r['method'],'address':address,'status':r['status'],'seconds':r['elapsed_seconds'],'folder':folder});folders.append(folder)
        if r['status']=='decompiled_conditional_candidate':
            p=source/r['file'];assert p.parent==source and sha(p)==r['c_sha256']
            candidates.append({'method':r['method'],'address':address,'file':'../'+folder+'/'+r['file'],'bytes':p.stat().st_size,'sha256':sha(p),'warnings':p.read_text().count('WARNING:')})
    bridges=LAB/'native-export-bridges-20261015';b=json.loads((bridges/'bridges.json').read_text());ba=json.loads((bridges/'audit.json').read_text())
    assert ba['integrity_passed'] and ba['bridges_sha256']==sha(bridges/'bridges.json')
    assert b['producer_sha256']==sha(REPO/'tools/terraria_native_export_bridges_20261015.py') and ba['auditor_sha256']==sha(REPO/'tools/audit_terraria_native_export_bridges_20261015.py')
    refinement=LAB/'initializer-refinement-20261015';ref=json.loads((refinement/'setfactory-size.json').read_text());assert ref['producer_sha256']==sha(REPO/'tools/terraria_setfactory_size_evidence.py')
    assert len(ref['audit']['negative_fixtures_rejected'])==5
    folders.extend([bridges.name,refinement.name])
    roots=LAB/'static-field-roots-20261015';rd=json.loads((roots/'static-field-roots.json').read_text());ra=json.loads((roots/'independent-audit.json').read_text())
    assert ra['integrity_passed'] and ra['evidence_sha256']==sha(roots/'static-field-roots.json')
    assert rd['producer_sha256']==sha(REPO/'tools/terraria_static_field_root_evidence.py') and ra['auditor_sha256']==sha(REPO/'tools/audit_terraria_static_field_roots.py')
    assert ra['class_usage_roots_verified']==2 and ra['source_bytes_verified']==648 and len(ra['negative_controls_rejected'])==5
    assert rd['declared_static_field']['name']=='Factory' and rd['declared_static_field']['native_static_offset']==0
    folders.append(roots.name)
    noreturn=LAB/'nullguard-noreturn-model-20261015';nr=json.loads((noreturn/'evidence.json').read_text())
    assert nr['integrity_passed'] and nr['auditor_sha256']==sha(REPO/'tools/audit_terraria_nullguard_noreturn_model.py')
    folders.append(noreturn.name)
    old=json.loads((ROOT/'native-continuation-20261014/summary.json').read_text());remaining_behavior=set(old['remaining_addresses']);rtti=set(json.loads((LAB/'native-rtti-continuation-v1/rtti-links.json').read_text())['unique_original_unknown_FDE_addresses']);api=set(b['original_unknown_FDE_entries_linked'])
    source_unknown={r['address'] for r in json.loads((LAB/'native/unmapped-fde-classification.json').read_text()) if r['category']=='unknown'}
    assert api<=source_unknown and len(source_unknown)==8140
    remaining=[m for m in baseline['remaining_methods'] if m['address'] not in {r['address'] for r in candidates}]
    assert len(remaining)==13-len(candidates)
    summary={'date':'2026-10-15','conditional_candidates':candidates,'attempts':attempts,'pending_or_unaudited':pending,'finished_all_four':not pending,'remaining_hard_methods_without_C':len(remaining),'remaining_methods':remaining,'unique_C_addresses_including_conditional_candidates':baseline['unique_C_addresses_including_conditional_candidates']+len(candidates),'API_linked_original_unknown_entries':len(api),'API_links_outside_previous_behavior_and_RTTI':len(api&remaining_behavior-rtti),'unknown_without_behavior_RTTI_API_link':len(remaining_behavior-rtti-api),'with_behavior_RTTI_or_API_link':len(source_unknown)-len(remaining_behavior-rtti-api),'original_Csharp_recovered':False,'runtime_equivalence_verified':False,'original_unknown_categories_modified':False}
    out=LAB/'initializer-continuation-20261015';out.mkdir(exist_ok=True)
    summary['conditional_static_factory_assignment']={'owner':'Terraria.ID.ItemID+Sets','field':'Factory','store_address':'0x1a899f8','constructor_size':6196,'evidence_sha256':ra['evidence_sha256'],'runtime_execution_proven':False}
    (out/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    lines=['# Продолжение разбора инициализаторов Terraria','',f"Добавлено условных C-кандидатов: **{len(candidates)}**. Осталось **{len(remaining)}** прежних методов без полного C. Всего C-представлений, включая отдельные кандидаты: **{summary['unique_C_addresses_including_conditional_candidates']:,}** уникальных FDE-адресов.",'','| Метод | Результат | Секунд |','|---|---|---:|']
    for r in attempts:lines.append(f"| {r['method']} | {r['status']} | {r['seconds']:.2f} |")
    if pending:lines.extend(['',f"Ещё не завершены или не проверены попытки: {len(pending)}. Они не включены в успешный счётчик."])
    for r in candidates:lines.extend(['',f"[{r['method']}]({r['file']}): {r['bytes']:,} байт, предупреждений Ghidra {r['warnings']}; SHA-256 `{r['sha256']}`."])
    lines.extend(['','Все попытки изолированы, лимит 600 секунд; временные транзакции откатились, проект не сохранялся. У этих четырёх методов в прежней карте нет BR-таблиц, поэтому switch hints не добавлялись. Проверка целостности связывает исходные байты FDE, фактический движок и C; она не устанавливает семантическую эквивалентность или исходный C#.','',f"Именованные IL2CPP exports дают связи для {len(api)} прежних неизвестных FDE-entry; {summary['API_links_outside_previous_behavior_and_RTTI']} вне прежних поведенческих/RTTI-профилей. Всего {summary['with_behavior_RTTI_or_API_link']} из 8 140 имеют хотя бы такое описание или связь, {summary['unknown_without_behavior_RTTI_API_link']} ещё без них. Категории исходного каталога не изменены; наличие связи с API не равно восстановленной реализации. [Цепочки и независимый аудит](../native-export-bridges-20261015/REPORT.ru.md).",'','`il2cpp_runtime_class_init` и часто вызываемый entry 0x6ff688 ведут на общий адрес 0x6e19f4. Это подтверждённая связь исходных B-инструкций, не полный анализ помощника.','', 'В ItemID.Sets и NPCID.Sets подтверждены аргументы SetFactory size **6196** и **697**. Конструктор условно записывает их в экземплярное `_size` по смещению 16; metadata, offset slot, 384 исходных байта и отрицательные контроли сохранены. Принадлежность фабрики конкретному статическому полю остаётся неустановленной. [Доказательства и предпосылки](../initializer-refinement-20261015/REPORT.ru.md).','', '[Сводка и оставшиеся методы](summary.json). Старые корпуса и исходный APK сохранены; runtime этих новых кандидатов не проверялся.'])
    lines.extend(['','Подготовлена отдельная **условная модель отсутствия нормального возврата** для четырёх обёрток null-ошибки. Исходные 124 байта, PLT/relocation __cxa_throw и пять отрицательных контролей проверены; фабрика исключения в noreturn-список не включена. Модель требует стандартного C++ ABI и отсутствия exceptional/nonlocal повторного входа. Она не изменяет выводы прежнего корпуса. [Доказательства и первичный ABI-источник](../nullguard-noreturn-model-20261015/REPORT.ru.md).'])
    lines=[line.replace('Принадлежность фабрики конкретному статическому полю остаётся неустановленной.','В этом раннем доказательстве принадлежность конкретному статическому полю ещё не устанавливалась; следующий отдельный аудит уточняет связь.') for line in lines]
    lines.extend(['','**Уточнена условная запись `ItemID.Sets.Factory`:** исходный metadata-usage slot разрешается в тип `Terraria.ID.ItemID+Sets`, поле Factory объявлено static и имеет нативное смещение 0. Именованный IL2CPP export подтверждает указатель static storage по `klass+0xb8`; запись `0x1a899f8` сохраняет receiver конструктора с size 6196 в это поле. Свежий независимый ELF/metadata-аудит проверил 648 байтов, два class roots и отрицательные контроли. Вывод требует нормального bootstrap, возврата конструктора, сохранности регистров/глобального корня и достижения записи; исполнение в runtime не наблюдалось. [Исходные фрагменты, условия и аудит](../static-field-roots-20261015/REPORT.ru.md).'])
    (out/'REPORT.ru.md').write_text('\n'.join(lines)+'\n',encoding='utf8');folders.append(out.name)
    for folder in folders:shutil.copytree(LAB/folder,ROOT/folder,dirs_exist_ok=True)
    dest=ROOT/out.name;(dest/'tools').mkdir(exist_ok=True)
    for name in ('package_terraria_initializer_continuation.py','TerrariaHardSelectedProbe.java','audit_terraria_initializer_isolated.py','terraria_native_export_bridges_20261015.py','audit_terraria_native_export_bridges_20261015.py','terraria_setfactory_size_evidence.py','terraria_native_map.py','terraria_flow_islands.py','terraria_metadata_catalog.py','audit_terraria_nullguard_noreturn_model.py','terraria_static_field_root_evidence.py','audit_terraria_static_field_roots.py'):shutil.copy2(REPO/'tools'/name,dest/'tools'/name)
    rows=[{'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)} for folder in folders for p in sorted((ROOT/folder).rglob('*')) if p.is_file() and p.name!='addendum-manifest.json']
    (dest/'addendum-manifest.json').write_text(json.dumps({'files':rows,'prior_manifest_sha256':sha(prior)},indent=2)+'\n')
    for r in rows:assert sha(ROOT/r['path'])==r['sha256']
    print(json.dumps({'report':str(dest/'REPORT.ru.md'),'candidates':len(candidates),'remaining':len(remaining),'pending':len(pending),'files':len(rows)},ensure_ascii=False))
if __name__=='__main__':main()
