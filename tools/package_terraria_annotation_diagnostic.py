"""Preserve failed model lifecycle verification and the separate explicit-restore smoke."""
import hashlib,json,pathlib,shutil
LAB=pathlib.Path('C:/Temp/terraria-re-20261012')
ROOT=pathlib.Path('C:/Private/Documents/ChatGPT/Terraria-Reverse-20261012')
REPO=pathlib.Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    out=LAB/'model-transaction-diagnostic-20261015';attempt=LAB/'pseudocode-noreturn-processdata-20261015';smoke=LAB/'pseudocode-noreturn-transaction-smoke-20261015'
    r=json.loads((attempt/'result.json').read_text());s=json.loads((smoke/'result.json').read_text())
    assert r['status']=='decompile_failed' and r['script_sha256']==sha(out/'TerrariaNoreturnSelectedProbe.java')
    assert 'Conditional annotation not restored' in (out/'noreturn-processdata-20261015.log').read_text()
    assert s['status']=='annotation_transaction_smoke' and s['script_sha256']==sha(REPO/'tools/TerrariaNoreturnSelectedProbeV2.java')
    assert s['outer_annotation_rollback_requested'] is True
    assert len(s['conditional_noreturn_annotations'])==4
    assert all(a['before_no_return'] is False and a['during_no_return'] is True and a['explicitly_restored_before_close'] is True and a['original_no_return_restored'] is True for a in s['conditional_noreturn_annotations'])
    assert not list(attempt.glob('*.c'))
    reopen=LAB/'pseudocode-noreturn-copy-reopen-smoke-20261015/result.json';rs=json.loads(reopen.read_text())
    assert rs['status']=='annotation_transaction_smoke' and rs['script_sha256']==sha(REPO/'tools/TerrariaNoreturnSelectedProbeV2.java')
    assert len(rs['conditional_noreturn_annotations'])==4 and all(a['before_no_return'] is False and a['original_no_return_restored'] is True for a in rs['conditional_noreturn_annotations'])
    shutil.copy2(reopen,out/'copy-reopen-smoke-result.json')
    for name in ('result.json','scope.json'):shutil.copy2(attempt/name,out/('failed-'+name))
    shutil.copy2(smoke/'result.json',out/'smoke-result.json');shutil.copy2(REPO/'tools/TerrariaNoreturnSelectedProbeV2.java',out/'TerrariaNoreturnSelectedProbeV2.java')
    result={'failed_attempt_status':r['status'],'failed_attempt_seconds':r['elapsed_seconds'],'no_C_produced':True,'lifecycle_verification_error_observed':True,'explicit_restore_smoke_passed':True,'smoke_sha256':sha(smoke/'result.json'),'failed_source_sha256':sha(out/'TerrariaNoreturnSelectedProbe.java'),'fixed_source_sha256':sha(out/'TerrariaNoreturnSelectedProbeV2.java'),'model_contract_is_conditional':True,'source_project_for_failed_attempt':'separate readOnly copy','scope':'Diagnostic and annotation-lifecycle test only; no new candidate or runtime-equivalence claim.'}
    (out/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
    result['separate_copy_reopened_with_all_four_original_flags_false']=True
    result['copy_reopen_smoke_sha256']=sha(reopen)
    (out/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
    (out/'REPORT.ru.md').write_text('# Диагностика вложенных транзакций Ghidra\n\nДополнительная модель NoReturn для ProcessData не вернула C за лимит 600 с. Затем первоначальный скрипт v1 ошибочно ожидал немедленного восстановления флагов после закрытия своей вложенной транзакции, пока внешняя транзакция Ghidra ещё оставалась открытой. Проверка завершилась ошибкой. Прогон сохранён как неуспешный, никаких новых C-кандидатов из него не учтено. Он выполнялся на отдельной readOnly-копии.\n\nВ v2 перед закрытием вложенной транзакции явно восстановлены исходные значения. Отдельный короткий тест (без декомпиляции) записал: четыре исходных false → временных true → восстановленных false. Это проверка управления анализатором, не игровой runtime-тест или доказательство ABI-контракта. [Результаты и SHA](summary.json) · [Полный smoke record](smoke-result.json).\n',encoding='utf8')
    with (out/'REPORT.ru.md').open('a',encoding='utf8') as report:report.write('\nОтдельная копия проекта после неуспешного v1 открыта повторно: до временных изменений все четыре NoReturn-флага оказались false. Это дополнительная проверка отсутствия сохранённых аннотаций в копии. [Запись повторного открытия](copy-reopen-smoke-result.json).\n')
    shutil.copytree(out,ROOT/out.name,dirs_exist_ok=True)
    dest=ROOT/out.name;shutil.copy2(pathlib.Path(__file__),dest/pathlib.Path(__file__).name)
    rows=[{'path':p.relative_to(dest).as_posix(),'sha256':sha(p),'bytes':p.stat().st_size} for p in sorted(dest.rglob('*')) if p.is_file() and p.name!='addendum-manifest.json']
    (dest/'addendum-manifest.json').write_text(json.dumps({'files':rows},indent=2)+'\n')
    print(json.dumps({'report':str(dest/'REPORT.ru.md'),'smoke_passed':True,'new_C':0},ensure_ascii=False))
if __name__=='__main__':main()
