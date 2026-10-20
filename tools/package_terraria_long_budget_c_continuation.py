"""Checkpoint independently audited noncontiguous-body conditional C candidates."""
import datetime,hashlib,json,pathlib,shutil,subprocess,sys
LAB=pathlib.Path('C:/Temp/terraria-re-20261012')
ROOT=pathlib.Path('C:/Private/Documents/ChatGPT/Terraria-Reverse-20261012')
REPO=pathlib.Path(__file__).resolve().parents[1]
PROFILE='verified-known-islands-conditional-noreturn-long-budget-C-v4-stack32-v1'
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
    prior=ROOT/'artifact-manifest.json';assert sha(prior)=='94cae77db018fee38c09e3b69f203b5fc0fbfd55b40c4aabbb935e30c61b391a'
    folders=[];attempts=[];candidates=[];smokes=[];pending=[]
    for source in sorted(LAB.glob('pseudocode-long-budget-c-*')):
        if not source.is_dir():continue
        if not (source/'result.json').exists() or not (source/'audit.json').exists():pending.append(source.name);continue
        r=json.loads((source/'result.json').read_text());a=json.loads((source/'audit.json').read_text())
        assert a['integrity_passed'] and a['result_sha256']==sha(source/'result.json')
        assert a['auditor_sha256']==sha(REPO/'tools/audit_terraria_long_budget_c.py') and r['script_sha256']==sha(REPO/'tools/TerrariaLongBudgetCProbe.java')
        assert r['derived_from_parent_sha256']==sha(REPO/'tools/TerrariaCoarseCopiesProbe.java') and r['profile']==PROFILE
        assert r['noreturn_model_evidence_sha256']==sha(LAB/'nullguard-noreturn-model-20261015/evidence.json')
        assert r['explicit_model_restoration_verified'] and r['outer_transaction_rollback_requested'] and r['original_body_explicitly_restored_before_close']
        assert r['factory_0x74129c_after_no_return'] is False and r['runtime_verified'] is False
        folders.append(source.name)
        assert r['simplification_style']=='decompile' and r['typerecovery_enabled'] is False
        assert r['open_program_accepted'] and r['options_accepted_after_open'] and r['option_injection_count_before_decompile']>=2
        assert r['derived_from_extended_sha256']==sha(REPO/'tools/TerrariaExtendedNoreturnProbe.java')
        assert r['derived_from_untyped_sha256']==sha(REPO/'tools/TerrariaUntypedCProbe.java') and r['only_budget_changed'] is True
        assert r['baseline_hard_timeout_seconds']==600 and r['timeout_seconds']==(60 if r['c_smoke'] else 1800) and r['budget_change_is_analysis_improvement'] is False
        assert a['c_smoke'] is r['c_smoke'] and a['producer_status']==r['status']
        if r['status']=='decompiled_conditional_candidate':
            c=source/r['file'];assert c.resolve().parent==source.resolve() and sha(c)==r['c_sha256'] and c.stat().st_size==r['c_bytes']
            assert r['decompile_completed'] and r['actual_C_object_returned'] and r['timed_out'] is False
        if r['c_smoke']:
            assert source.name=='pseudocode-long-budget-c-smoke-20261017' and r['address']=='0x74129c' and a['eligible_for_new_C_coverage'] is False
            smokes.append({'folder':source.name,'status':r['status'],'C_returned':r['status']=='decompiled_conditional_candidate'});continue
        sd=LAB/'pseudocode-long-budget-c-smoke-20261017';sr=json.loads((sd/'result.json').read_text());sa=json.loads((sd/'audit.json').read_text())
        assert sr['c_smoke'] and sr['status']=='decompiled_conditional_candidate' and sr['script_sha256']==r['script_sha256']
        assert sa['integrity_passed'] and sa['result_sha256']==sha(sd/'result.json') and sa['auditor_sha256']==a['auditor_sha256']
        assert r['prerequisite_C_smoke_result_sha256']==sha(sd/'result.json') and r['prerequisite_C_smoke_audit_sha256']==sha(sd/'audit.json')
        assert sha(sd/sr['file'])==sr['c_sha256']
        assert a['eligible_for_new_C_coverage'] is (r['status']=='decompiled_conditional_candidate')
        assert r['status'] in ('decompile_failed','decompiled_conditional_candidate')
        attempts.append({'folder':source.name,'method':r['method'],'address':r['address'],'status':r['status'],'seconds':r['elapsed_seconds'],'external_island_bytes':a['verified_extended_island_bytes']})
        if r['status']=='decompiled_conditional_candidate':
            c=source/r['file'];assert c.resolve().parent==source.resolve() and sha(c)==r['c_sha256']
            candidates.append({'method':r['method'],'address':r['address'],'file':'../'+source.name+'/'+r['file'],'bytes':c.stat().st_size,'sha256':sha(c),'warnings':c.read_text().count('WARNING:'),'external_island_bytes':a['verified_extended_island_bytes'],'profile':PROFILE})
    assert folders,'No independently audited results'
    recovered={'0x12f63e8','0x12e2cb8'}
    for name in ('ai-continuation-20261014','selected-continuation-20261015','initializer-continuation-20261015','coarse-continuation-20261015','noreturn-coarse-continuation-20261015','extended-noreturn-continuation-20261015','branch-preserving-c-continuation-20261016','untyped-c-continuation-20261016'):
        p=ROOT/name/'summary.json'
        if p.exists():recovered.update(r['address'] for r in json.loads(p.read_text())['conditional_candidates'])
    added={r['address'] for r in candidates}-recovered;recovered.update(r['address'] for r in candidates)
    maps=json.loads((LAB/'hard-switches-v2/switches.json').read_text())
    remaining=[{'method':m['method'],'address':m['address']} for m in maps['methods'] if m['address'] not in recovered]
    out=LAB/'long-budget-c-continuation-20261017';out.mkdir(exist_ok=True)
    summary={'checkpoint_UTC':datetime.datetime.now(datetime.timezone.utc).isoformat(),'conditional_candidates':candidates,'attempts':attempts,'C_smokes_excluded_from_coverage':smokes,'pending_or_unaudited':pending,'new_unique_C_addresses':len(added),'remaining_hard_methods_without_C':len(remaining),'remaining_methods':remaining,'unique_C_addresses_including_candidates':123152-len(remaining),'runtime_equivalence_verified':False,'only_budget_changed':True,'hard_timeout_seconds':1800,'extra_time_is_analysis_improvement':False,'original_Csharp_recovered':False,'global_CFG_completeness_verified':False}
    plan=LAB/'long-budget-c-plan-20261017.json'
    if plan.exists():
        planned=json.loads(plan.read_text(encoding='utf-8-sig'))['addresses']
        summary['planned_addresses']=planned
        summary['not_yet_audited_planned_addresses']=sorted(set(planned)-{r['address'] for r in attempts}-recovered,key=lambda s:int(s,16))
        summary['finished_planned_attempts']=not summary['not_yet_audited_planned_addresses']
    (out/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    lines=['# Условная C-декомпиляция с увеличенным бюджетом времени','',f"C-кандидатов: {len(candidates)}; новых уникальных адресов: {len(added)}. Осталось прежних крупных методов без C: **{len(remaining)}**. Снимок `{summary['checkpoint_UTC']}`.",'','Относительно закреплённого Untyped изменён только лимит крупной функции 600→1800 секунд; smoke остаётся 60 секунд. Дополнительное время само по себе не улучшает анализ и не увеличивает покрытие. Сохранён штатный action decompile, отключена только группа typerecovery; группы merge/casts/cleanup/blockrecovery сохранены. Настоящий C smoke проверяется отдельно и не увеличивает покрытие. К точному исходному FDE добавлены только известные и побайтно проверенные B→LDR→B блоки. Они не пересекаются с полным каталогом FDE и не имеют другого известного владельца в каталоге путей. Это не доказательство отсутствия всех возможных косвенных входов.','', '| Метод | Результат | Секунд | Внешних байтов |','|---|---|---:|---:|']
    for r in attempts:lines.append(f"| {r['method']} | {r['status']} | {r['seconds']:.2f} | {r['external_island_bytes']} |")
    if 'not_yet_audited_planned_addresses' in summary:lines.extend(['',f"В плане ещё без проверенного результата: {len(summary['not_yet_audited_planned_addresses'])}."])
    for r in candidates:lines.extend(['',f"[{r['method']}]({r['file']}), {r['bytes']:,} байт C, предупреждений {r['warnings']}; SHA `{r['sha256']}`."])
    if (LAB/'long-budget-c-strategy-checkpoint-20261017.json').exists():lines.extend(['','Профиль выбран явно из текущего проверенного checkpoint с записью предыдущих планов. Предыдущие планы не объявлены завершёнными. [Смена профиля](long-budget-c-strategy-checkpoint-20261017.json).'])
    lines.extend(['','Без type recovery вывод может содержать больше числовых адресов и более слабые типы. Принятие options protocol наблюдалось по ответу движка; состав внутренних action-групп независимо не снимался. Разбиение агрегатных копий отключено; четыре обёртки имеют временные условные NoReturn-аннотации по отдельной throw-ABI модели. Перед закрытием транзакции явно восстановлены исходное тело функции и четыре флага. Для switch overrides и ограниченного disassembly записан запрос отката; фактическое внутреннее восстановление независимо не наблюдалось. Проект используется отдельной readOnly-копией.','', '[Предпосылки throw ABI](../nullguard-noreturn-model-20261015/REPORT.ru.md) · [Сводка и остаточный список](summary.json). Исходный C#, полная CFG и runtime-эквивалентность не заявляются.'])
    if (REPO/'tools/TERRARIA_RECIPES_LONG_BUDGET_REVIEW.md').exists():lines.extend(['','[Дополнительная текстовая проверка SetupRecipes](tools/TERRARIA_RECIPES_LONG_BUDGET_REVIEW.md): границы, хеши, начало/конец и предупреждения; не проверка компиляции или эквивалентности.'])
    if (REPO/'tools/TERRARIA_BESTIARY_LONG_BUDGET_REVIEW.md').exists():lines.extend(['','[Проверка C-текста Bestiary](tools/TERRARIA_BESTIARY_LONG_BUDGET_REVIEW.md): структура, предупреждения и навигация по метаданным.'])
    if (REPO/'tools/TERRARIA_PROCESSDATA_LONG_BUDGET_REVIEW.md').exists():lines.extend(['','[Проверка C-текста ProcessData](tools/TERRARIA_PROCESSDATA_LONG_BUDGET_REVIEW.md): структура, 47 предупреждений и пределы условного результата.'])
    if (REPO/'tools/TERRARIA_DRAWPROJ_LONG_BUDGET_REVIEW.md').exists():lines.extend(['','[Проверка C-текста DrawProjDirect](tools/TERRARIA_DRAWPROJ_LONG_BUDGET_REVIEW.md): 1,68 МБ, структура и сохранённые предупреждения.'])
    (out/'REPORT.ru.md').write_text('\n'.join(lines)+'\n',encoding='utf8');folders.append(out.name)
    for name in folders:shutil.copytree(LAB/name,ROOT/name,dirs_exist_ok=True)
    dest=ROOT/out.name;(dest/'tools').mkdir(exist_ok=True)
    for name in ('package_terraria_long_budget_c_continuation.py','package_terraria_remaining_attempts.py','run_terraria_long_budget_c_queue.ps1','TerrariaLongBudgetCProbe.java','audit_terraria_long_budget_c.py','TerrariaCoarseCopiesProbe.java','TerrariaExtendedNoreturnProbe.java','TerrariaUntypedCProbe.java','audit_terraria_nullguard_noreturn_model.py'):shutil.copy2(REPO/'tools'/name,dest/'tools'/name)
    if (REPO/'tools/TERRARIA_RECIPES_LONG_BUDGET_REVIEW.md').exists():shutil.copy2(REPO/'tools/TERRARIA_RECIPES_LONG_BUDGET_REVIEW.md',dest/'tools/TERRARIA_RECIPES_LONG_BUDGET_REVIEW.md')
    for name in ('TERRARIA_BESTIARY_LONG_BUDGET_REVIEW.md','TERRARIA_PROCESSDATA_LONG_BUDGET_REVIEW.md','TERRARIA_DRAWPROJ_LONG_BUDGET_REVIEW.md','TERRARIA_PROCESSDATA_INDEX_HIGHBITS_REVIEW.md','terraria_processdata_index_highbits.py','audit_terraria_processdata_index_highbits.py','review_terraria_c_text.py','review_terraria_c_text_v1.py','review_terraria_c_text_v2.py'):
        if (REPO/'tools'/name).exists():shutil.copy2(REPO/'tools'/name,dest/'tools'/name)
    review=LAB/'c-text-review-bestiary-20261017.json'
    if review.exists():shutil.copy2(review,dest/'tools'/review.name)
    review=LAB/'c-text-review-processdata-20261018.json'
    if review.exists():shutil.copy2(review,dest/'tools'/review.name)
    review=LAB/'c-text-review-processdata-v2-20261018.json'
    if review.exists():shutil.copy2(review,dest/'tools'/review.name)
    for name in ('c-text-review-drawproj-20261018.json','c-text-review-drawproj-v2-20261018.json'):
        review=LAB/name
        if review.exists():shutil.copy2(review,dest/'tools'/review.name)
    for name in ('processdata-index-highbits-20261018.json','processdata-index-highbits-independent-audit-20261018.json'):
        review=LAB/name
        if review.exists():shutil.copy2(review,dest/'tools'/review.name)
    if plan.exists():shutil.copy2(plan,dest/plan.name)
    strategy=LAB/'long-budget-c-strategy-checkpoint-20261017.json'
    if strategy.exists():shutil.copy2(strategy,dest/strategy.name)
    rows=[{'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)} for name in folders for p in sorted((ROOT/name).rglob('*')) if p.is_file() and p.name!='addendum-manifest.json']
    (dest/'addendum-manifest.json').write_text(json.dumps({'prior_manifest_sha256':sha(prior),'files':rows},indent=2)+'\n')
    for r in rows:assert sha(ROOT/r['path'])==r['sha256']
    subprocess.run([sys.executable,str(REPO/'tools/package_terraria_remaining_attempts.py')],check=True)
    print(json.dumps({'report':str(dest/'REPORT.ru.md'),'candidates':len(candidates),'remaining':len(remaining),'pending':len(pending)},ensure_ascii=False))
if __name__=='__main__':main()
