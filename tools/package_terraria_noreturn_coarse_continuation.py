"""Checkpoint the separate conditional throw-ABI plus unsplit-copy model."""
import datetime,hashlib,json,pathlib,shutil
LAB=pathlib.Path('C:/Temp/terraria-re-20261012')
ROOT=pathlib.Path('C:/Private/Documents/ChatGPT/Terraria-Reverse-20261012')
REPO=pathlib.Path(__file__).resolve().parents[1]
PROFILE='conditional-standard-cxx-throw-noreturn-aggregate-unsplit-typed-v4-stack32-v1'
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
    prior=ROOT/'artifact-manifest.json';assert sha(prior)=='94cae77db018fee38c09e3b69f203b5fc0fbfd55b40c4aabbb935e30c61b391a'
    folders=[];attempts=[];candidates=[];smokes=[];pending=[]
    for source in sorted(LAB.glob('pseudocode-noreturn-coarse-*')):
        if not source.is_dir():continue
        if not (source/'result.json').exists() or not (source/'independent-audit.json').exists():pending.append(source.name);continue
        r=json.loads((source/'result.json').read_text());a=json.loads((source/'independent-audit.json').read_text())
        assert a['integrity_passed'] and a['result_sha256']==sha(source/'result.json')
        assert a['auditor_sha256']==sha(REPO/'tools/audit_terraria_noreturn_coarse_probe_v2.py')
        assert r['script_sha256']==sha(REPO/'tools/TerrariaNoreturnCoarseProbe.java') and r['parent_helper_sha256']==sha(REPO/'tools/TerrariaCoarseCopiesProbe.java')
        assert r['profile']==PROFILE and r['noreturn_model_evidence_sha256']==sha(LAB/'nullguard-noreturn-model-20261015/evidence.json')
        assert r['explicit_annotation_restoration_verified'] and r['outer_annotation_rollback_requested']
        assert r['factory_0x74129c_marked_noreturn'] is False and r['runtime_verified'] is False
        assert 'ephemeral_transaction_rolled_back' not in r
        folders.append(source.name)
        if r['status']=='annotation_transaction_smoke':smokes.append(source.name);continue
        assert r['status'] in ('decompile_failed','decompiled_conditional_candidate')
        attempts.append({'folder':source.name,'method':r['method'],'address':r['address'],'status':r['status'],'seconds':r['elapsed_seconds']})
        if r['status']=='decompiled_conditional_candidate':
            c=source/r['file'];assert c.resolve().parent==source.resolve() and sha(c)==r['c_sha256']
            candidates.append({'method':r['method'],'address':r['address'],'file':'../'+source.name+'/'+r['file'],'bytes':c.stat().st_size,'sha256':sha(c),'warnings':c.read_text().count('WARNING:'),'profile':PROFILE})
    assert folders,'No independently audited results'
    recovered={'0x12f63e8','0x12e2cb8'}
    for name in ('ai-continuation-20261014','selected-continuation-20261015','initializer-continuation-20261015','coarse-continuation-20261015','extended-noreturn-continuation-20261015','untyped-c-continuation-20261016','branch-preserving-c-continuation-20261016','long-budget-c-continuation-20261017'):
        p=ROOT/name/'summary.json'
        if p.exists():recovered.update(r['address'] for r in json.loads(p.read_text())['conditional_candidates'])
    added={r['address'] for r in candidates}-recovered;recovered.update(r['address'] for r in candidates)
    maps=json.loads((LAB/'hard-switches-v2/switches.json').read_text())
    remaining=[{'method':m['method'],'address':m['address']} for m in maps['methods'] if m['address'] not in recovered]
    out=LAB/'noreturn-coarse-continuation-20261015';out.mkdir(exist_ok=True)
    summary={'checkpoint_UTC':datetime.datetime.now(datetime.timezone.utc).isoformat(),'conditional_candidates':candidates,'attempts':attempts,'transaction_smokes':smokes,'pending_or_unaudited':pending,'new_unique_C_addresses':len(added),'remaining_hard_methods_without_C':len(remaining),'remaining_methods':remaining,'unique_C_addresses_including_candidates':123152-len(remaining),'runtime_equivalence_verified':False,'original_Csharp_recovered':False,'ABI_contract_is_assumption':True}
    interrupted=LAB/'interrupted-noreturn-coarse-recipes-20261016'
    if interrupted.exists():
        note=json.loads((interrupted/'interruption.json').read_text(encoding='utf-8-sig'))
        assert note['status']=='interrupted_without_result' and note['decompiler_timeout_observed'] is False
        assert not (interrupted/'result.json').exists() and not list(interrupted.glob('*.c'))
        summary['interrupted_attempts']=[{'folder':interrupted.name,'status':note['status'],'C_coverage_addition':0}]
        folders.append(interrupted.name)
    plan=LAB/'noreturn-coarse-plan-20261015.json'
    if plan.exists():
        planned=json.loads(plan.read_text(encoding='utf-8-sig'))['addresses']
        summary['planned_addresses']=planned
        summary['not_yet_audited_planned_addresses']=sorted(set(planned)-{r['address'] for r in attempts},key=lambda s:int(s,16))
        summary['finished_planned_attempts']=not summary['not_yet_audited_planned_addresses']
    (out/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    lines=['# Условная модель throw ABI и агрегатных копий','',f"C-кандидатов: {len(candidates)}; новых уникальных адресов: {len(added)}. Осталось прежних крупных методов без полного C: **{len(remaining)}**. Снимок `{summary['checkpoint_UTC']}`.",'','Четырём ранее проверенным обёрткам временно выставлена NoReturn-аннотация, разбиение структур/массивов/указателей отключено. Фабрика исключения 0x74129c сохранена как допускающая возврат. Предположение стандартного __cxa_throw и отсутствия exceptional/nonlocal повторного входа явно унаследовано от отдельного доказательства.','', '| Метод | Результат | Секунд |','|---|---|---:|']
    for r in attempts:lines.append(f"| {r['method']} | {r['status']} | {r['seconds']:.2f} |")
    if 'not_yet_audited_planned_addresses' in summary:lines.extend(['',f"В плане ещё без проверенного результата: {len(summary['not_yet_audited_planned_addresses'])}."])
    for r in candidates:lines.extend(['',f"[{r['method']}]({r['file']}), {r['bytes']:,} байт, предупреждений {r['warnings']}; SHA `{r['sha256']}`."])
    if summary.get('interrupted_attempts'):lines.extend(['','Прерванная SetupRecipes сохранена без result.json. Точная причина завершения неизвестна; она не считается таймаутом или C-кандидатом. [Сохранённая запись](../interrupted-noreturn-coarse-recipes-20261016/interruption.json).'])
    lines.extend(['','Перед закрытием вложенной транзакции исходные четыре аннотации явно восстановлены; запись аудита связывает исходные байты, карты, движок, инструменты и результат. Это не независимое наблюдение внутреннего состояния Ghidra или доказательство полного отката switch hints. Проект запускается отдельной readOnly-копией, сохранение не запрашивается.','', '[Предпосылки модели и первичный ABI-источник](../nullguard-noreturn-model-20261015/REPORT.ru.md). Runtime, глобальное доминирование guards, исходный C# и семантическая эквивалентность не доказаны.','', '[Сводка и остаточный список](summary.json).'])
    (out/'REPORT.ru.md').write_text('\n'.join(lines)+'\n',encoding='utf8');folders.append(out.name)
    for name in folders:shutil.copytree(LAB/name,ROOT/name,dirs_exist_ok=True)
    dest=ROOT/out.name;(dest/'tools').mkdir(exist_ok=True)
    for name in ('package_terraria_noreturn_coarse_continuation.py','run_terraria_noreturn_coarse_queue.ps1','run_terraria_remaining_models_queue.ps1','TerrariaNoreturnCoarseProbe.java','audit_terraria_noreturn_coarse_probe.py','audit_terraria_noreturn_coarse_probe_v2.py','TerrariaCoarseCopiesProbe.java','audit_terraria_nullguard_noreturn_model.py'):shutil.copy2(REPO/'tools'/name,dest/'tools'/name)
    if plan.exists():shutil.copy2(plan,dest/plan.name)
    rows=[{'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)} for name in folders for p in sorted((ROOT/name).rglob('*')) if p.is_file() and p.name!='addendum-manifest.json']
    (dest/'addendum-manifest.json').write_text(json.dumps({'prior_manifest_sha256':sha(prior),'files':rows},indent=2)+'\n')
    for r in rows:assert sha(ROOT/r['path'])==r['sha256']
    print(json.dumps({'report':str(dest/'REPORT.ru.md'),'candidates':len(candidates),'remaining':len(remaining),'pending':len(pending)},ensure_ascii=False))
if __name__=='__main__':main()
