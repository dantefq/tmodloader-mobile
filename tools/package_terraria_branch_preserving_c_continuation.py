"""Checkpoint independently audited noncontiguous-body conditional C candidates."""
import datetime,hashlib,json,pathlib,shutil
LAB=pathlib.Path('C:/Temp/terraria-re-20261012')
ROOT=pathlib.Path('C:/Private/Documents/ChatGPT/Terraria-Reverse-20261012')
REPO=pathlib.Path(__file__).resolve().parents[1]
PROFILE='verified-known-islands-conditional-noreturn-branch-preserving-C-v4-stack32-v1'
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
    prior=ROOT/'artifact-manifest.json';assert sha(prior)=='94cae77db018fee38c09e3b69f203b5fc0fbfd55b40c4aabbb935e30c61b391a'
    folders=[];attempts=[];candidates=[];smokes=[];pending=[]
    for source in sorted(LAB.glob('pseudocode-branch-preserving-c-*')):
        if not source.is_dir():continue
        if not (source/'result.json').exists() or not (source/'audit.json').exists():pending.append(source.name);continue
        r=json.loads((source/'result.json').read_text());a=json.loads((source/'audit.json').read_text())
        assert a['integrity_passed'] and a['result_sha256']==sha(source/'result.json')
        assert a['auditor_sha256']==sha(REPO/'tools/audit_terraria_branch_preserving_c.py') and r['script_sha256']==sha(REPO/'tools/TerrariaBranchPreservingCProbe.java')
        assert r['derived_from_parent_sha256']==sha(REPO/'tools/TerrariaCoarseCopiesProbe.java') and r['profile']==PROFILE
        assert r['noreturn_model_evidence_sha256']==sha(LAB/'nullguard-noreturn-model-20261015/evidence.json')
        assert r['explicit_model_restoration_verified'] and r['outer_transaction_rollback_requested'] and r['original_body_explicitly_restored_before_close']
        assert r['factory_0x74129c_after_no_return'] is False and r['runtime_verified'] is False
        folders.append(source.name)
        assert r['simplification_style']=='decompile' and r['typerecovery_enabled'] is False
        assert r['open_program_accepted'] and r['options_accepted_after_open'] and r['option_injection_count_before_decompile']>=2
        assert r['derived_from_extended_sha256']==sha(REPO/'tools/TerrariaExtendedNoreturnProbe.java')
        assert r['derived_from_untyped_sha256']==sha(REPO/'tools/TerrariaUntypedCProbe.java')
        assert r['disabled_action_groups']==['typerecovery','conditionalexe','nodejoin','returnsplit'] and r['only_recorded_additional_action_groups_disabled'] is True
        assert r['action_toggle_count_before_decompile']==4*r['option_injection_count_before_decompile'] and r['action_toggle_count_after_decompile']==4*r['option_injection_count_after_decompile']
        assert r['retained_final_groups']=='merge,casts,cleanup,blockrecovery'
        assert a['c_smoke'] is r['c_smoke'] and a['producer_status']==r['status']
        if r['status']=='decompiled_conditional_candidate':
            c=source/r['file'];assert c.resolve().parent==source.resolve() and sha(c)==r['c_sha256'] and c.stat().st_size==r['c_bytes']
            assert r['decompile_completed'] and r['actual_C_object_returned'] and r['timed_out'] is False
        if r['c_smoke']:
            assert source.name=='pseudocode-branch-preserving-c-smoke-20261016' and r['address']=='0x74129c' and a['eligible_for_new_C_coverage'] is False
            smokes.append({'folder':source.name,'status':r['status'],'C_returned':r['status']=='decompiled_conditional_candidate'});continue
        sd=LAB/'pseudocode-branch-preserving-c-smoke-20261016';sr=json.loads((sd/'result.json').read_text());sa=json.loads((sd/'audit.json').read_text())
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
    for name in ('ai-continuation-20261014','selected-continuation-20261015','initializer-continuation-20261015','coarse-continuation-20261015','noreturn-coarse-continuation-20261015','extended-noreturn-continuation-20261015','untyped-c-continuation-20261016','long-budget-c-continuation-20261017'):
        p=ROOT/name/'summary.json'
        if p.exists():recovered.update(r['address'] for r in json.loads(p.read_text())['conditional_candidates'])
    added={r['address'] for r in candidates}-recovered;recovered.update(r['address'] for r in candidates)
    maps=json.loads((LAB/'hard-switches-v2/switches.json').read_text())
    remaining=[{'method':m['method'],'address':m['address']} for m in maps['methods'] if m['address'] not in recovered]
    out=LAB/'branch-preserving-c-continuation-20261016';out.mkdir(exist_ok=True)
    summary={'checkpoint_UTC':datetime.datetime.now(datetime.timezone.utc).isoformat(),'conditional_candidates':candidates,'attempts':attempts,'C_smokes_excluded_from_coverage':smokes,'pending_or_unaudited':pending,'new_unique_C_addresses':len(added),'remaining_hard_methods_without_C':len(remaining),'remaining_methods':remaining,'unique_C_addresses_including_candidates':123152-len(remaining),'runtime_equivalence_verified':False,'original_Csharp_recovered':False,'global_CFG_completeness_verified':False}
    for interrupted_name in ('interrupted-branch-preserving-kill-20261017','interrupted-branch-preserving-kill-20261017-resumed'):
        interrupted=LAB/interrupted_name
        if not interrupted.exists():continue
        note=json.loads((interrupted/'interruption.json').read_text(encoding='utf-8-sig'))
        assert note['status']=='interrupted_without_result' and note['decompiler_timeout_observed'] is False
        assert not (interrupted/'result.json').exists() and not list(interrupted.glob('*.c'))
        summary.setdefault('interrupted_attempts',[]).append({'folder':interrupted.name,'status':note['status'],'C_coverage_addition':0})
        folders.append(interrupted.name)
    plan=LAB/'branch-preserving-c-plan-20261016.json'
    if plan.exists():
        planned=json.loads(plan.read_text(encoding='utf-8-sig'))['addresses']
        summary['planned_addresses']=planned
        summary['not_yet_audited_planned_addresses']=sorted(set(planned)-{r['address'] for r in attempts}-recovered,key=lambda s:int(s,16))
        summary['finished_planned_attempts']=not summary['not_yet_audited_planned_addresses']
    (out/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    lines=['# Условная C-декомпиляция с сохранением ветвлений','',f"C-кандидатов: {len(candidates)}; новых уникальных адресов: {len(added)}. Осталось прежних крупных методов без C: **{len(remaining)}**. Снимок `{summary['checkpoint_UTC']}`.",'','Сохранён штатный action decompile, отключены ровно группы typerecovery, conditionalexe, nodejoin, returnsplit; группы merge/casts/cleanup/blockrecovery сохранены. Настоящий маленький C smoke проверяется отдельно и не увеличивает покрытие. Он подтверждает принятие протокола и наличие C, но не проверяет эффективность преобразований ветвлений на крупных методах. К точному исходному FDE добавлены только известные и побайтно проверенные B→LDR→B блоки. Они не пересекаются с полным каталогом FDE и не имеют другого известного владельца в каталоге путей. Это не доказательство отсутствия всех возможных косвенных входов.','', '| Метод | Результат | Секунд | Внешних байтов |','|---|---|---:|---:|']
    for r in attempts:lines.append(f"| {r['method']} | {r['status']} | {r['seconds']:.2f} | {r['external_island_bytes']} |")
    if 'not_yet_audited_planned_addresses' in summary:lines.extend(['',f"В плане ещё без проверенного результата: {len(summary['not_yet_audited_planned_addresses'])}."])
    for r in candidates:lines.extend(['',f"[{r['method']}]({r['file']}), {r['bytes']:,} байт C, предупреждений {r['warnings']}; SHA `{r['sha256']}`."])
    for interruption in summary.get('interrupted_attempts',[]):lines.extend(['',f"Прерванная попытка `{interruption['folder']}` сохранена отдельно без result.json. Точная причина завершения неизвестна; это не зарегистрированный таймаут и не C-кандидат. [Запись прерывания](../{interruption['folder']}/interruption.json)."])
    if (LAB/'branch-preserving-c-strategy-checkpoint-20261016.json').exists():lines.extend(['','Профиль выбран явно из текущего проверенного checkpoint с записью состояния предыдущих планов. Их завершение не заявляется. [Смена профиля](branch-preserving-c-strategy-checkpoint-20261016.json).'])
    lines.extend(['','Без type recovery вывод может содержать больше числовых адресов и более слабые типы. Принятие options protocol наблюдалось по ответу движка; состав внутренних action-групп независимо не снимался. Разбиение агрегатных копий отключено; четыре обёртки имеют временные условные NoReturn-аннотации по отдельной throw-ABI модели. Перед закрытием транзакции явно восстановлены исходное тело функции и четыре флага. Для switch overrides и ограниченного disassembly записан запрос отката; фактическое внутреннее восстановление независимо не наблюдалось. Проект используется отдельной readOnly-копией.','', '[Предпосылки throw ABI](../nullguard-noreturn-model-20261015/REPORT.ru.md) · [Сводка и остаточный список](summary.json). Исходный C#, полная CFG и runtime-эквивалентность не заявляются.'])
    (out/'REPORT.ru.md').write_text('\n'.join(lines)+'\n',encoding='utf8');folders.append(out.name)
    for name in folders:shutil.copytree(LAB/name,ROOT/name,dirs_exist_ok=True)
    dest=ROOT/out.name;(dest/'tools').mkdir(exist_ok=True)
    for name in ('package_terraria_branch_preserving_c_continuation.py','run_terraria_branch_preserving_c_queue.ps1','TerrariaBranchPreservingCProbe.java','audit_terraria_branch_preserving_c.py','TerrariaCoarseCopiesProbe.java','TerrariaExtendedNoreturnProbe.java','TerrariaUntypedCProbe.java','audit_terraria_nullguard_noreturn_model.py'):shutil.copy2(REPO/'tools'/name,dest/'tools'/name)
    if plan.exists():shutil.copy2(plan,dest/plan.name)
    strategy=LAB/'branch-preserving-c-strategy-checkpoint-20261016.json'
    if strategy.exists():shutil.copy2(strategy,dest/strategy.name)
    rows=[{'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)} for name in folders for p in sorted((ROOT/name).rglob('*')) if p.is_file() and p.name!='addendum-manifest.json']
    (dest/'addendum-manifest.json').write_text(json.dumps({'prior_manifest_sha256':sha(prior),'files':rows},indent=2)+'\n')
    for r in rows:assert sha(ROOT/r['path'])==r['sha256']
    print(json.dumps({'report':str(dest/'REPORT.ru.md'),'candidates':len(candidates),'remaining':len(remaining),'pending':len(pending)},ensure_ascii=False))
if __name__=='__main__':main()
