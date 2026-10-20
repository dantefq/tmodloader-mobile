"""Package completed source-bound continuation families; never copy active batches."""
import argparse, hashlib, json, pathlib, shutil


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);ap.add_argument('--delivery',type=pathlib.Path,required=True);a=ap.parse_args()
    lab=a.lab;repo=pathlib.Path(__file__).resolve().parents[1];root=a.delivery.resolve();master=lab/'native-continuation-20261014';master.mkdir(exist_ok=True)
    if root.is_relative_to(repo) or root==lab.resolve():raise ValueError('Separate private delivery required')
    old_manifest=root/'artifact-manifest.json';old_hash=sha(old_manifest)
    if old_hash!='94cae77db018fee38c09e3b69f203b5fc0fbfd55b40c4aabbb935e30c61b391a':raise ValueError('Prior delivery differs')
    families=[('unknown-native-behaviors-v1','terraria_unknown_native_behaviors.py','audit_terraria_unknown_native_behaviors.py'),
              ('guarded-native-behaviors-v1','terraria_guarded_native_behaviors.py','audit_terraria_guarded_native_behaviors.py'),
              ('native-callback-loops-v1','terraria_native_callback_loops.py','audit_terraria_native_callback_loops.py'),
              ('native-callback-loops-v2','terraria_native_callback_loops_v2.py','audit_terraria_native_callback_loops_v2.py'),
              ('native-resolver-wrappers-v1','terraria_native_resolver_wrappers.py','audit_terraria_native_resolver_wrappers.py')]
    catalog=json.loads((lab/'native/unmapped-fde-classification.json').read_text());unknown={r['address'] for r in catalog if r['category']=='unknown'}
    union=set();counts={};tools_to_copy={'package_terraria_native_continuation.py','terraria_flow_islands.py','terraria_native_map.py','terraria_metadata_catalog.py','terraria-analysis-requirements.txt'}
    for name,producer,auditor in families:
        source=lab/name;doc=json.loads((source/'behaviors.json').read_text());audit=json.loads((source/'independent-audit.json').read_text())
        if audit.get('integrity_passed') is not True or audit['behaviors_sha256']!=sha(source/'behaviors.json'):raise ValueError('Stale/failed '+name)
        if audit['auditor_sha256']!=sha(repo/'tools'/auditor) or doc['producer_sha256']!=sha(repo/'tools'/producer):raise ValueError('Changed family tools '+name)
        members={r['address'] for r in doc['results']}
        if not members<=unknown or members&union or len(members)!=len(doc['results']):raise ValueError('Family overlap/invalid source scope')
        union|=members;counts[name]=len(members);tools_to_copy|={producer,auditor}
        if name!='unknown-native-behaviors-v1':shutil.copytree(source,root/name,dirs_exist_ok=True)
    if len(unknown)!=8140:raise ValueError('Unknown scope differs')
    extra_specs=[('native-rtti-continuation-v1','rtti-links.json','rtti_links_sha256','terraria_native_rtti_continuation.py','audit_terraria_native_rtti_continuation.py'),
                 ('initializer-call-constants-v1','calls.json','calls_sha256','terraria_initializer_call_constants.py','audit_terraria_initializer_call_constants.py')]
    extras={}
    for name,filename,key,producer,auditor in extra_specs:
        source=lab/name;doc=json.loads((source/filename).read_text());audit=json.loads((source/'independent-audit.json').read_text())
        if audit.get('integrity_passed') is not True or audit[key]!=sha(source/filename) or audit['auditor_sha256']!=sha(repo/'tools'/auditor) or doc['producer_sha256']!=sha(repo/'tools'/producer):raise ValueError('Stale extra proof '+name)
        extras[name]=doc;shutil.copytree(source,root/name,dirs_exist_ok=True);tools_to_copy|={producer,auditor}
    tools_to_copy|={'check_terraria_native_rtti_audit_rejections.py','report_terraria_initializer_call_constants.py'}
    rtti_members=set(extras['native-rtti-continuation-v1']['unique_original_unknown_FDE_addresses'])
    if not rtti_members<=unknown:raise ValueError('RTTI outside source unknown scope')
    probe=lab/'pseudocode-switch-hint-probe';record=json.loads((probe/'result.json').read_text());audit=json.loads((probe/'audit.json').read_text())
    if audit.get('integrity_passed') is not True or audit['result_sha256']!=sha(probe/'result.json') or audit['auditor_sha256']!=sha(repo/'tools/audit_terraria_switch_hint_probe.py'):raise ValueError('Probe audit stale')
    if record['status']!='decompiled_conditional_candidate' or sha(probe/record['file'])!=record['c_sha256'] or record.get('ephemeral_transaction_rolled_back') is not True:raise ValueError('Probe incomplete')
    shutil.copytree(probe,root/probe.name,dirs_exist_ok=True);tools_to_copy|={'TerrariaSwitchHintProbe.java','audit_terraria_switch_hint_probe.py'}
    batch=lab/'pseudocode-switch-hint-batch';batch_progress=json.loads((batch/'progress.json').read_text());batch_audit=json.loads((batch/'audit.json').read_text())
    if batch_progress.get('finished') is not True or batch_progress.get('ephemeral_transaction_rolled_back') is not True or batch_audit.get('integrity_passed') is not True or batch_audit['journal_sha256']!=sha(batch/'results.jsonl') or batch_audit['auditor_sha256']!=sha(repo/'tools/audit_terraria_switch_hint_batch.py'):raise ValueError('Batch incomplete or stale')
    batch_rows=[json.loads(line) for line in (batch/'results.jsonl').read_text().splitlines()]
    candidates=[]
    for row in batch_rows:
        if row['script_sha256']!=sha(repo/'tools/TerrariaSwitchHintBatch.java'):raise ValueError('Batch producer changed')
        if row['status']=='decompiled_conditional_candidate':
            if pathlib.Path(row['file']).name!=row['file'] or sha(batch/row['file'])!=row['c_sha256']:raise ValueError('Candidate C changed')
            candidates.append({'address':row['address'],'file':'../'+batch.name+'/'+row['file'],'sha256':row['c_sha256']})
    if len(batch_rows)!=12 or len(candidates)!=batch_audit['conditional_c_candidates']:raise ValueError('Batch totals differ')
    shutil.copytree(batch,root/batch.name,dirs_exist_ok=True);tools_to_copy|={'TerrariaSwitchHintBatch.java','audit_terraria_switch_hint_batch.py'}
    npc=lab/'npc-spawn-call-facts-v1';npc_doc=json.loads((npc/'calls.json').read_text());npc_audit=json.loads((npc/'audit.json').read_text())
    if npc_audit.get('integrity_passed') is not True or npc_audit['calls_sha256']!=sha(npc/'calls.json') or npc_doc['producer_sha256']!=sha(repo/'tools/terraria_npc_spawn_call_facts.py'):raise ValueError('NPC facts stale')
    if npc_doc['constant_producer_helper_sha256']!=sha(repo/'tools/terraria_initializer_call_constants.py') or npc_doc['independent_raw_helper_sha256']!=sha(repo/'tools/audit_terraria_initializer_call_constants.py'):raise ValueError('NPC fact helpers changed')
    shutil.copytree(npc,root/npc.name,dirs_exist_ok=True);tools_to_copy.add('terraria_npc_spawn_call_facts.py')
    for name,tool in [('delegate-layout-offsets.json','terraria_delegate_layout_evidence.py'),('nullguard-exception-chain.json','terraria_nullguard_exception_evidence.py')]:
        proof=json.loads((master/name).read_text())
        if proof['producer_sha256']!=sha(repo/'tools'/tool):raise ValueError('Proof tool changed')
        tools_to_copy.add(tool)
    ai_summary_path=root/'ai-continuation-20261014/summary.json'
    ai_summary=json.loads(ai_summary_path.read_text()) if ai_summary_path.exists() else {'conditional_candidates':[]}
    new_ai_candidates=ai_summary['conditional_candidates']
    selected_path=root/'selected-continuation-20261015/summary.json'
    selected=json.loads(selected_path.read_text()) if selected_path.exists() else {'conditional_candidates':[]}
    selected_candidates=selected['conditional_candidates']
    initializer_path=root/'initializer-continuation-20261015/summary.json'
    initializer=json.loads(initializer_path.read_text()) if initializer_path.exists() else {'conditional_candidates':[]}
    initializer_candidates=initializer['conditional_candidates']
    coarse_path=root/'coarse-continuation-20261015/summary.json'
    coarse=json.loads(coarse_path.read_text()) if coarse_path.exists() else {'conditional_candidates':[]}
    coarse_candidates=coarse['conditional_candidates']
    noreturn_path=root/'noreturn-coarse-continuation-20261015/summary.json'
    noreturn=json.loads(noreturn_path.read_text()) if noreturn_path.exists() else {'conditional_candidates':[]}
    noreturn_candidates=noreturn['conditional_candidates']
    extended_path=root/'extended-noreturn-continuation-20261015/summary.json'
    extended=json.loads(extended_path.read_text()) if extended_path.exists() else {'conditional_candidates':[]}
    extended_candidates=extended['conditional_candidates']
    untyped_path=root/'untyped-c-continuation-20261016/summary.json'
    untyped=json.loads(untyped_path.read_text()) if untyped_path.exists() else {'conditional_candidates':[]}
    untyped_candidates=untyped['conditional_candidates']
    branch_path=root/'branch-preserving-c-continuation-20261016/summary.json'
    branch=json.loads(branch_path.read_text()) if branch_path.exists() else {'conditional_candidates':[]}
    branch_candidates=branch['conditional_candidates']
    long_path=root/'long-budget-c-continuation-20261017/summary.json'
    long_stage=json.loads(long_path.read_text()) if long_path.exists() else {'conditional_candidates':[]}
    long_candidates=long_stage['conditional_candidates']
    extra_C_addresses={r['address'] for r in new_ai_candidates+selected_candidates+initializer_candidates+coarse_candidates+noreturn_candidates+extended_candidates+untyped_candidates+branch_candidates+long_candidates}
    summary={'source_unknown_ranges':8140,'disjoint_family_counts':counts,'structural_descriptions_union':len(union),'remaining_outside_profiles':len(unknown-union),
             'additional_RTTI_membership_outside_behavior_profiles':len(rtti_members-union),'with_behavior_or_RTTI_link':len(union|rtti_members),
             'without_behavior_or_RTTI_link':len(unknown-(union|rtti_members)),
             'initializer_local_call_sites':extras['initializer-call-constants-v1']['sites_with_constant_facts'],
             'initializer_constant_register_facts':extras['initializer-call-constants-v1']['constant_register_facts'],
             'NPC_spawn_direct_calls':npc_doc['direct_calls_to_callee'],'NPC_spawn_known_Type_calls':npc_doc['calls_with_known_Type'],
             'remaining_addresses':sorted(unknown-union,key=lambda s:int(s,16)),'conditional_C_additions':[{'address':record['address'],'file':'../'+probe.name+'/'+record['file'],'sha256':record['c_sha256']}]+candidates,
             'remaining_hard_methods_without_C':18-1-len(candidates)-len(extra_C_addresses),'latest_AI_candidates':new_ai_candidates,'selected_hard_candidates_20261015':selected_candidates,'initializer_candidates_20261015':initializer_candidates,'alternative_model_candidates_20261015':coarse_candidates,'unique_C_addresses_including_candidates':123136+len(extra_C_addresses),'batch_attempted':len(batch_rows),'batch_successful_candidates':len(candidates),
             'original_Csharp_recovered':False,'semantic_purposes_fully_recovered':False,'runtime_verified':False,'baseline_modified':False}
    if initializer_candidates:
        summary['with_behavior_RTTI_or_API_link']=initializer['with_behavior_RTTI_or_API_link']
        summary['without_behavior_RTTI_or_API_link']=initializer['unknown_without_behavior_RTTI_API_link']
    summary['conditional_throw_unsplit_candidates_20261015']=noreturn_candidates
    summary['extended_body_conditional_candidates_20261015']=extended_candidates
    summary['untyped_conditional_candidates_20261016']=untyped_candidates
    summary['branch_preserving_conditional_candidates_20261016']=branch_candidates
    summary['long_budget_conditional_candidates_20261017']=long_candidates
    fde_path=lab/'native/unwind-function-ranges.tsv'
    assert sha(fde_path)=='8b238f458b7a0505138fc56ea70ffe59c21d46a6b83ea2e4106f6f896a3f7756'
    fdes=[tuple(int(x,0) for x in line.split('\t')[:2]) for line in fde_path.read_text().splitlines()]
    assert len(fdes)==123152
    hard_maps=json.loads((lab/'hard-switches-v2/switches.json').read_text())['methods']
    recovered_hard={'0x12f63e8','0x12e2cb8'}|extra_C_addresses
    missing_hard={int(m['address'],16) for m in hard_maps if m['address'] not in recovered_hard}
    assert len(missing_hard)==summary['remaining_hard_methods_without_C']
    total_fde_bytes=sum(end-start for start,end in fdes)
    missing_fde_bytes=sum(end-start for start,end in fdes if start in missing_hard)
    summary.update(fde_bytes_total=total_fde_bytes,remaining_fde_bytes_without_C=missing_fde_bytes,C_represented_fde_bytes=total_fde_bytes-missing_fde_bytes,C_FDE_byte_coverage_percent=100*(total_fde_bytes-missing_fde_bytes)/total_fde_bytes,C_FDE_address_coverage_percent=100*summary['unique_C_addresses_including_candidates']/123152)
    (master/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    lines=['# Продолжение полного разбора Terraria','', 'Актуальный индекс дополнений 14–17 октября 2026. Даты в отдельных отчётах обозначают этапы, а текущий охват приведён ниже.','',
           f"Наличие C-представлений с условными кандидатами: **{summary['C_FDE_address_coverage_percent']:.5f}% по числу FDE-адресов**, **{summary['C_FDE_byte_coverage_percent']:.3f}% по объёму исходных FDE-диапазонов**. Без C: {len(missing_hard)} диапазонов, {missing_fde_bytes:,} из {total_fde_bytes:,} байтов. Это не доказательство эквивалентности или обработки каждой исполняемой инструкции.",'',
           '**Получен дополнительный C-кандидат для Player.Update.** Применены три условные подсказки таблиц переходов (38 записей). Декомпиляция завершилась за 97,69 с. Код сохраняет предупреждения Ghidra: ручные switch overrides, распространение типов и перекрытие globals. Семантическая эквивалентность и глобальное доминирование guards не доказаны.','',
           '[C-кандидат Player.Update](../pseudocode-switch-hint-probe/Player_Update_conditional_candidate.c) · [Источник и условия модели](../pseudocode-switch-hint-probe/result.json) · [Аудит](../pseudocode-switch-hint-probe/audit.json).','',
           '**Получен C-кандидат NPC.Spawner.SpawnAnNPC:** 515 205 байт, восемь предупреждений Ghidra. Пакетный проход завершён: из 12 остальных методов с таблицами один вернул C, 11 достигли лимита 180 с. [Кандидат SpawnAnNPC](../pseudocode-switch-hint-batch/0x12e2cb8_conditional_candidate.c) · [Журнал всех попыток](../pseudocode-switch-hint-batch/results.jsonl) · [Аудит](../pseudocode-switch-hint-batch/audit.json).','',
           'В SpawnAnNPC дополнительно проверены 22 локально заданных Type (W3) из 46 прямых вызовов Spawner.SpawnNPC. NPCID сопоставлены по числовым константам; это не полный список NPC или восстановленные условия их появления. [Инструкции и значения](../npc-spawn-call-facts-v1/REPORT.ru.md).','',
           f"Без пересечений структурно описаны **{len(union):,} из 8 140** прежних неизвестных нативных диапазонов. **{len(unknown-union):,}** ещё вне этих профилей. Это охват описаний инструкций, не число полностью установленных игровых назначений.",'',
           '| Семейство | Диапазонов | Доказательства |','|---|---:|---|',
           '| Короткие прямые/динамические передачи и возвраты | 1 328 | [Отчёт](../unknown-native-behaviors-v1/REPORT.ru.md) |',
           '| Проверка null, сохранение LR, передача управления | 411 | [Выражения и два пути](../guarded-native-behaviors-v1/behaviors.json) |',
           '| Циклы вызовов с целочисленными аргументами | 460 | [Отчёт](../native-callback-loops-v1/REPORT.ru.md) |',
           '| Циклы с SIMD-переносом аргументов | 48 | [Отчёт](../native-callback-loops-v2/REPORT.ru.md) |',
           '| Вспомогательный вызов и последующий косвенный вызов | 128 | [Два пути, стек и неизвестные эффекты](../native-resolver-wrappers-v1/behaviors.json) |','',
           f"Дополнительно **{len(rtti_members)}** исходных неизвестных FDE связаны с RTTI-типами/слотами C++-таблиц; **{len(rtti_members-union)}** из них вне поведенческих профилей. Итого {len(union|rtti_members):,} диапазонов имеют хотя бы одно такое описание или связь; {len(unknown-(union|rtti_members)):,} ещё без них. [Отчёт RTTI и ограничения ABS64](../native-rtti-continuation-v1/REPORT.ru.md).",'',
           'В пяти крупных инициализаторах извлечены 11 647 мест вызова и 26 417 локальных констант регистров. В SetupRecipes есть 6 234 вызова Item.SetDefaults с известным числовым W1, 2 879 различных ID. Это условные факты аргументов, не полная таблица рецептов или исходный C. [Отчёт и CSV](../initializer-call-constants-v1/REPORT.ru.md).','',
           'Для циклов отдельно указаны условия нормального возврата callbacks, сохранения регистров/SP и успешного доступа к памяти. SIMD-варианты различают сохранение младших 64 бит и полных 128 бит; совпадение циклического рисунка само по себе не доказывает ABI или тип объекта.','',
           'В общей null-цепочке исходные инструкции передают строки System/NullReferenceException вспомогательной функции; далее наблюдается статическая связь с relocation-символом __cxa_throw. Это поддерживает интерпретацию выбрасывания null-reference исключения, при явно указанных предпосылках. [Исходные факты и ограничения](nullguard-exception-chain.json).','',
           'Имена и 14 смещений полей System.Delegate/MulticastDelegate сверены с исходными metadata и native offset slots. Совпадение смещений с кодом не устанавливает автоматически тип входного объекта. [Доказательства полей](delegate-layout-offsets.json).','',
           f"Прежние корпуса и исходный APK не изменены. После последнего дополнения {summary['remaining_hard_methods_without_C']} исходных проблемных методов пока без полного C. В совокупности C-представления доступны для {summary['unique_C_addresses_including_candidates']:,} уникальных FDE-адресов при включении отдельных кандидатов v4 и switch-hint; это не восстановленный исходный проект и не доказательство семантической эквивалентности.",'',
           'После явного разрешения управления по снимкам созданы тестовый персонаж Classic и небольшой мир. Проверены генерация, вход, Save & Exit, холодный перезапуск процесса и повторный вход; пять файлов сохранения сохранили хеши при загрузке. Это ограниченный игровой сценарий, не проверка семантики всех функций. Собственный эмулятор остановлен. [Отчёт игровых проверок](../runtime-world-20261014/REPORT.ru.md). Предыдущая попытка только с клавишами сохранена как исторический снимок.','',
           '[Сводка и остаточный список](summary.json). Отдельный манифест описывает файлы этого дополнения; исходный artifact-manifest.json остаётся снимком предыдущего этапа.']
    if new_ai_candidates:lines[4:4]=[f"Следующий этап добавил {len(new_ai_candidates)} условных C-кандидата AI и отдельные граф/каталог вызовов. [Актуальное дополнение AI](../ai-continuation-20261014/REPORT.ru.md).",'']
    if selected_candidates:lines[4:4]=[f"15 октября: ещё {len(selected_candidates)} условных C-кандидата. Исправлен producer upper32-графа NPC AI (ошибочное write-set CMP в Capstone); v2 и независимый аудит сохранены отдельно. [Последнее дополнение и исправление](../selected-continuation-20261015/REPORT.ru.md).",'']
    if initializer_candidates:lines[4:4]=[f"Новый проход инициализаторов: {len(initializer_candidates)} C-кандидатов; ещё {len(initializer.get('pending_or_unaudited',[]))} попыток не завершены/не проверены. Независимые цепочки exports дают ещё {initializer['API_links_outside_previous_behavior_and_RTTI']} API-связей вне прежних профилей; {initializer['unknown_without_behavior_RTTI_API_link']} диапазонов ещё без поведения/RTTI/API-связи. [Актуальное дополнение инициализаторов](../initializer-continuation-20261015/REPORT.ru.md).",'']
    if coarse_candidates:lines[4:4]=[f"Альтернативные настройки разбиения копий/вывода констант дали {len(coarse_candidates)} C-кандидатов. Счётчики уникальных адресов исключают пересечения моделей. [Последний проход и выполняемая очередь](../coarse-continuation-20261015/REPORT.ru.md).",'']
    if (root/'semantic-continuation-20261015/summary.json').exists():lines[4:4]=['Новые отдельно проверенные связи статических полей и исходных данных: [Уточнения семантики](../semantic-continuation-20261015/REPORT.ru.md). Эти результаты не добавляют C-адресов.','']
    if noreturn_path.exists():lines[4:4]=[f"Отдельная условная модель throw ABI и агрегатных копий: {len(noreturn_candidates)} C-кандидатов. Адреса учитываются без пересечений; ABI-предпосылки не превращены в runtime-доказательства. [Последняя модель](../noreturn-coarse-continuation-20261015/REPORT.ru.md).",'']
    if extended_path.exists():lines[4:4]=[f"Условная модель с известными внешними блоками: {len(extended_candidates)} C-кандидатов. Полнота всех входящих переходов не заявляется. [Модель расширенных тел](../extended-noreturn-continuation-20261015/REPORT.ru.md).",'']
    if untyped_path.exists():lines[4:4]=[f"Отдельный профиль без восстановления типов: {len(untyped_candidates)} C-кандидатов, учтённых по уникальным адресам. Контрольная малая функция исключена из покрытия. [Результаты профиля](../untyped-c-continuation-20261016/REPORT.ru.md).",'']
    if branch_path.exists():lines[4:4]=[f"Профиль с отключёнными необязательными преобразованиями ветвлений: {len(branch_candidates)} C-кандидатов. Контрольная функция исключена из покрытия. [Результаты профиля](../branch-preserving-c-continuation-20261016/REPORT.ru.md).",'']
    if long_path.exists():lines[4:4]=[f"Проход с увеличенным лимитом времени: {len(long_candidates)} C-кандидатов. Настройки анализа исходного Untyped-профиля сохранены; увеличен только бюджет до 1800 с. [Результаты](../long-budget-c-continuation-20261017/REPORT.ru.md).",'']
    if (root/'scope-gap-continuation-20261016/REPORT.ru.md').exists():lines[4:4]=['[Аудит границ метрики и байтов вне FDE](../scope-gap-continuation-20261016/REPORT.ru.md): 480 092 байта исполняемых секций вне FDE-каталога описаны отдельно; новые C-адреса этим аудитом не добавлены.','']
    if (root/'angr-diagnostic-continuation-20261017/REPORT.ru.md').exists():lines[4:4]=['[Отклонённый контроль angr](../angr-diagnostic-continuation-20261017/REPORT.ru.md): текст C с потерянным внешним переходом/ABI-аргументами сохранён как неуспешный; покрытие им не увеличено.','']
    if (root/'remaining-attempts-20261017/REPORT.ru.md').exists():lines[4:4]=['[Таблица проверенных попыток оставшихся методов](../remaining-attempts-20261017/REPORT.ru.md): отдельные результаты шести профилей и записи прерываний; индекс не добавляет C.','']
    (master/'REPORT.ru.md').write_text('\n'.join(lines)+'\n',encoding='utf8')
    destination=root/master.name;destination.mkdir(exist_ok=True)
    for p in master.iterdir():
        if p.is_file() and p.name!='addendum-manifest.json':shutil.copy2(p,destination/p.name)
    tools=destination/'tools';tools.mkdir(exist_ok=True)
    for name in sorted(tools_to_copy):shutil.copy2(repo/'tools'/name,tools/name)
    # Bind complete copied families plus this report, without changing earlier manifests.
    paths=[]
    for name in ('guarded-native-behaviors-v1','native-callback-loops-v1','native-callback-loops-v2','native-resolver-wrappers-v1','native-rtti-continuation-v1','initializer-call-constants-v1','npc-spawn-call-facts-v1','pseudocode-switch-hint-probe','pseudocode-switch-hint-batch','native-continuation-20261014'):
        paths.extend(p for p in (root/name).rglob('*') if p.is_file() and p.name!='addendum-manifest.json')
    rows=[{'path':p.relative_to(root).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(paths)]
    manifest={'prior_delivery_manifest_sha256':old_hash,'file_count':len(rows),'files':rows,'scope':'Completed continuation families only. File identity does not prove semantics.'}
    (destination/'addendum-manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    if sha(old_manifest)!=old_hash:raise ValueError('Prior manifest changed')
    for row in rows:
        if sha(root/row['path'])!=row['sha256']:raise ValueError('Copied file changed')
    print(json.dumps({'report':str(destination/'REPORT.ru.md'),'structural_descriptions':len(union),'remaining':len(unknown-union),'copied_files':len(rows),'prior_manifest_unchanged':True},ensure_ascii=False))


if __name__=='__main__':main()
