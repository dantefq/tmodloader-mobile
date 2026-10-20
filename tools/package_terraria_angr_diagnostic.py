"""Preserve a rejected independent-engine control and its reproducible dependencies."""
import hashlib,json,pathlib,shutil
LAB=pathlib.Path('C:/Temp/terraria-re-20261012')
ROOT=pathlib.Path('C:/Private/Documents/ChatGPT/Terraria-Reverse-20261012')
REPO=pathlib.Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    baseline=ROOT/'artifact-manifest.json';assert sha(baseline)=='94cae77db018fee38c09e3b69f203b5fc0fbfd55b40c4aabbb935e30c61b391a'
    source=LAB/'pseudocode-angr-bounded-smoke-20261016';r=json.loads((source/'result.json').read_text());a=json.loads((source/'audit.json').read_text())
    assert a['integrity_passed'] and a['result_sha256']==sha(source/'result.json') and a['eligible_for_C_coverage'] is False
    assert r['status']=='C_returned_but_scope_or_analysis_gates_failed' and r['eligible_for_C_coverage'] is False
    assert r['producer_sha256']==sha(REPO/'tools/terraria_angr_bounded_probe.py') and a['auditor_sha256']==sha(REPO/'tools/audit_terraria_angr_bounded.py')
    assert sha(source/r['C_file'])==r['C_sha256']
    stage=ROOT/'angr-diagnostic-continuation-20261017';stage.mkdir(exist_ok=True)
    shutil.copytree(source,ROOT/source.name,dirs_exist_ok=True)
    wheelhouse=LAB/'angr-wheelhouse-20261016'
    for row in json.loads((wheelhouse/'wheel-manifest.json').read_text(encoding='utf-8-sig')):assert sha(wheelhouse/row['file'])==row['sha256']
    shutil.copytree(wheelhouse,stage/'dependencies/wheelhouse',dirs_exist_ok=True)
    shutil.copytree(LAB/'angr-reviewed-sources-20261016',stage/'dependencies/reviewed-sources',dirs_exist_ok=True)
    shutil.copy2(LAB/'angr-runtime-20261016/source-review.json',stage/'source-review.json')
    for name in ('angr-smoke-supervisor-20261017.json','angr-smoke-v1-20261017.stdout.log','angr-smoke-v1-20261017.stderr.log'):shutil.copy2(LAB/name,stage/name)
    tools=stage/'tools';tools.mkdir(exist_ok=True)
    for name in ('package_terraria_angr_diagnostic.py','terraria_angr_bounded_probe.py','audit_terraria_angr_bounded.py','audit_terraria_extended_noreturn.py','repack_reviewed_mulpyplexer_wheel.py','repack_reviewed_arpy_wheel.py'):shutil.copy2(REPO/'tools'/name,tools/name)
    summary={'C_coverage_addition':0,'control_rejected':True,'status':r['status'],'angr_version':r['version'],'artifact_execution':False,'global_python_modified':False}
    (stage/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    (stage/'REPORT.ru.md').write_text('# Отклонённый контроль независимого C-декомпилятора\n\nangr 10.0.4.post1 вернул текст C для 40-байтной контрольной функции, но проверка отклонила его: внешний B-переход и аргументы вызовов не сохранены; присутствует вызов с числовым именем. Это не пригодный полный C-результат и не увеличение покрытия.\n\nСохранены исходный кандидат, аудит, журналы и внешнее ограничение процесса (90 секунд/2 GiB RSS). APK не исполнялся. Глобальная среда Python не менялась: 45 фиксированных wheels установлены в отдельный каталог. Два старых pure-Python модуля перепакованы без изменения байтов и без запуска setup.py; происхождение и хеши сохранены.\n\n[Результат проверки](../pseudocode-angr-bounded-smoke-20261016/audit.json) · [Фактический результат движка](../pseudocode-angr-bounded-smoke-20261016/result.json). Зависимости и locked-requirements сохранены для повторения; крупные методы этим профилем не запускались.\n',encoding='utf8')
    rows=[{'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)} for directory in (ROOT/source.name,stage) for p in sorted(directory.rglob('*')) if p.is_file() and p.name!='addendum-manifest.json']
    (stage/'addendum-manifest.json').write_text(json.dumps({'prior_manifest_sha256':sha(baseline),'files':rows},indent=2)+'\n')
    for row in rows:assert sha(ROOT/row['path'])==row['sha256']
    print(json.dumps({'report':str(stage/'REPORT.ru.md'),'C_coverage_addition':0,'files':len(rows)}))
if __name__=='__main__':main()
