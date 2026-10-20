"""Snapshot completed rule-toggle diagnostics privately, verifying copied digests."""
import hashlib
import json
import shutil
from pathlib import Path

LAB=Path(r'C:\Temp\terraria-re-20261012')
DELIVERY=Path(r'C:/Private\Documents\ChatGPT\Terraria-Reverse-20261012')
TOOLS=Path(__file__).resolve().parent
OUT=DELIVERY/'copy-rule-diagnostic-continuation-20261019'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(DELIVERY/'artifact-manifest.json')=='94cae77db018fee38c09e3b69f203b5fc0fbfd55b40c4aabbb935e30c61b391a'
rows=[]
def copy(p,relative):
    dest=OUT/relative
    assert dest.resolve().is_relative_to(OUT.resolve())
    dest.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(p,dest)
    assert sha(p)==sha(dest)
    rows.append(dict(path=relative,sha256=sha(dest),bytes=dest.stat().st_size))
for name in ('prepare_terraria_copy_rule_off.py','run_terraria_copy_rule_off.ps1',
             'run_terraria_copy_rule_memory8.ps1','qualify_terraria_copy_rule_exports.py',
             'run_terraria_copy_rule_commit8.ps1',
             'run_terraria_copy_rule_commit12.ps1',
             'sample_terraria_decompiler_rules.py','TERRARIA_COPY_RULE_OFF_REVIEW.md',
             'package_terraria_copy_rule_diagnostic.py','review_terraria_c_text.py'):
    copy(TOOLS/name,'tools/'+name)
for p in (LAB/'copy-rule-off-sources-20261019').iterdir():
    if p.is_file():copy(p,'profile/'+p.name)
for pattern in ('portable-branch-long-kill-interruption-20261019.json',
                'portable-branch-long-kill-20261019.json','portable-branch-long-kill-20261019.pid*.log',
                'branch-kill-rule-counters-*-20261019.json','copy-rule-off-kill-rule-counters-*-20261019.json',
                'copy-rule-off-*-c-review-20261019.json','copy-rule-off-*-trace-review-20261019.json',
                'copy-rule-off-qualification-source-review-*-20261019.md',
                'copy-rule-off-qualifier-source-*-20261019.py',
                'copy-rule-off-conditional-export-qualification-*-20261019.json'):
    for p in LAB.glob(pattern):copy(p,'evidence/'+p.name)
completed={}
for target in ('smoke','kill','drawnpc1','drawnpc2','drawnpc1-mem8','drawnpc2-mem8','drawnpc1-commit8','drawnpc2-commit8','drawnpc1-commit12','drawnpc2-commit12'):
    state=LAB/f'copy-rule-off-{target}-20261019.json'
    if not state.exists():continue
    record=json.loads(state.read_text(encoding='utf-8-sig'))
    if record['status'] in ('starting','running'):continue
    completed[target]=record
    for p in LAB.glob(f'copy-rule-off-{target}-20261019*'):
        if p.is_file():copy(p,target+'/'+p.name)
    folder=LAB/f'pseudocode-copy-rule-off-c-{target}-20261019'
    if folder.exists():
        for p in folder.iterdir():
            if p.is_file():copy(p,target+'/result/'+p.name)
OUT.mkdir(exist_ok=True)
(OUT/'files.json').write_text(json.dumps(rows,indent=2)+'\n')
summary=dict(completed=completed,C_coverage_addition=0,
    global_coverage_unchanged_percent_FDE_bytes=98.14381485798766,
    remaining_canonical_methods=['0xf6954c','0xf9a914','0x1484e54'],
    rule_option='universal:fullloop:mainloop:stackstall:oppool1:propagatecopy off',
    diagnostic_only=True,original_manifest_unchanged=True)
qualifiers=sorted(LAB.glob('copy-rule-off-conditional-export-qualification-*-20261019.json'))
if qualifiers:
    latest=json.loads(qualifiers[-1].read_text())
    summary['separate_qualified_conditional_export_metric']={k:latest[k] for k in ('conditional_C_export_addresses','total_FDE_addresses','conditional_C_export_FDE_bytes','total_FDE_bytes','percent_conditional_C_export_FDE_bytes')}
(OUT/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
(OUT/'REPORT.ru.md').write_text('''# Диагностика правила копирования, 19.10.2026

Предыдущая branch-preserving попытка Kill прервалась без результата; процесс отсутствует после перезагрузки. Native timeout этой попытки не подтверждён. Отдельная guard-range попытка ранее вернула настоящий таймаут 1800 секунд.

В новом изолированном профиле через официальный togglerule отключается только universal:fullloop:mainloop:stackstall:oppool1:propagatecopy. Остальные четыре отключённые группы и исходные условные предпосылки сохранены. Контрольная функция вернула C и прошла 104 отрицательных контроля. Принятие options не доказывает отключение правила; отдельно сохранены ограниченные read-only выборки флагов/счётчиков собственного декомпилятора. Владение объектами правил определяется косвенно, выборки не атомарны.

Все возвращённые тексты этого профиля — диагностические кандидаты. Их начальный унаследованный комментарий перечисляет только четыре группы и не упоминает дополнительное отключение propagatecopy; полная конфигурация задаётся profile/result и данным отчётом. Новое глобальное покрытие не засчитывается. Лексическая проверка не подтверждает компиляцию или эквивалентность. Это не восстановленный оригинальный C#.
''',encoding='utf8')
with (OUT/'REPORT.ru.md').open('a',encoding='utf8') as report:
    if qualifiers:
        report.write('\nОтдельная квалификация условного C-экспорта: '+str(latest['conditional_C_export_addresses'])+'/'+str(latest['total_FDE_addresses'])+' адресов, '+format(latest['percent_conditional_C_export_FDE_bytes'],'.6f')+'% FDE-байтов. Это учёт наличия C-текста с перечисленными предпосылками, не оценка точности исходников. Исходные диагностические audit.json и первоначальный манифест сохранены.\n')
    for target,state in completed.items():
        result=OUT/target/'result/result.json'
        if result.exists():
            rec=json.loads(result.read_text())
            if rec.get('file'):
                report.write('\n- ['+target+': C-кандидат]('+target+'/result/'+rec['file']+') — '+str(rec['c_bytes'])+' байт; [запись результата]('+target+'/result/result.json).\n')
assert all(sha(OUT/r['path'])==r['sha256'] for r in rows)
print(json.dumps(dict(files_verified=len(rows),completed=list(completed),C_coverage_addition=0)))
