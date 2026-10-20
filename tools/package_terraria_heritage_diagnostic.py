"""Package completed heritage diagnostics privately with verified copied-file hashes."""
import hashlib
import json
import shutil
from pathlib import Path


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


lab = Path(r'C:\Temp\terraria-re-20261012')
delivery = Path(r'C:/Private\Documents\ChatGPT\Terraria-Reverse-20261012')
tools = Path(__file__).resolve().parent
out = delivery / 'heritage-diagnostic-continuation-20261019'
state_path = lab / 'heritage-on-drawnpc1-20261019.json'
state = json.loads(state_path.read_text(encoding='utf-8-sig'))
assert state['status'] not in ('starting', 'running')
original = delivery / 'artifact-manifest.json'
assert sha(original) == '94cae77db018fee38c09e3b69f203b5fc0fbfd55b40c4aabbb935e30c61b391a'
rows = []


def copy(source, relative):
    dest = out / relative
    assert dest.resolve().is_relative_to(out.resolve())
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, dest)
    digest = sha(source)
    assert sha(dest) == digest
    rows.append(dict(path=relative, bytes=dest.stat().st_size, sha256=digest))


for name in ('prepare_terraria_heritage_trace.py', 'prepare_terraria_heritage_builder.py',
             'prepare_terraria_heritage_profiles.py', 'prepare_terraria_heritage_runner.py',
             'run_terraria_heritage_smokes.ps1', 'run_terraria_heritage_diagnostic.ps1',
             'review_terraria_action_trace.py', 'summarize_terraria_heritage_trace.py',
             'package_terraria_heritage_diagnostic.py'):
    copy(tools / name, 'tools/' + name)
source = lab / 'portable-decompiler-heritage-trace-source-20261018'
for f in source.iterdir():
    if f.is_file():
        copy(f, 'build/' + f.name)
for f in (source / 'incremental-build-20261018').iterdir():
    if f.suffix != '.o':
        copy(f, 'build/linked/' + f.name)
for mode in ('off', 'on'):
    for f in (lab / ('heritage-' + mode + '-sources-20261019')).iterdir():
        if f.is_file():
            copy(f, 'profiles/' + mode + '/' + f.name)
    for f in (lab / ('pseudocode-heritage-' + mode + '-c-smoke-20261017')).iterdir():
        if f.is_file():
            copy(f, 'controls/' + mode + '/' + f.name)
for pattern in ('heritage-on-smoke-20261019.pid*.log', 'heritage-on-drawnpc1-20261019*',
                'heritage-on-drawnpc1-summary-20261019.json', 'heritage-on-smoke-review-20261019.json',
                'heritage-runner-provenance-20261019.json', 'pe-review-heritage-trace-20261019.json',
                'portable-trace-diagnostic-kill-long-interruption-20261019.json'):
    for f in lab.glob(pattern):
        if f.is_file():
            copy(f, 'evidence/' + f.name)
for f in (lab / 'pseudocode-heritage-on-c-drawnpc1-20261017').iterdir():
    if f.is_file():
        copy(f, 'attempt/' + f.name)
analysis = json.loads((lab / 'heritage-on-drawnpc1-summary-20261019.json').read_text())
summary = dict(C_coverage_addition=0, C_addresses=123149, FDE_addresses=123152,
               C_FDE_bytes=34520124, FDE_bytes=35173000, percent_C_FDE_bytes=98.14381485798766,
               remaining_addresses=['0xf6954c', '0xf9a914', '0x1484e54'],
               attempt_status=state['status'], external_stop_reason=state.get('external_stop_reason'),
               timed_out_observed=state['timed_out_observed'],
               open_scopes=analysis['trace_review']['open_scopes'],
               trace_limits=analysis['trace_review']['limits'], original_manifest_unchanged=True)
out.mkdir(exist_ok=True)
(out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
(out / 'files.json').write_text(json.dumps(rows, indent=2) + '\n')
top = analysis['completed_heritage_scopes'][:6]
report = '# Подробная диагностика heritage, 19.10.2026\n\n'
report += 'Новый движок собран и прошёл PE-проверку. Контрольный метод с выключенными/включёнными метками дал побайтово одинаковый C-код; оба аудитора прошли 94 отрицательных контроля.\n\n'
report += 'Проба DrawNPCDirect: ' + state['status'] + '; причина внешней остановки: ' + str(state.get('external_stop_reason')) + '. Native timeout не наблюдён: ' + str(not state['timed_out_observed']) + '.\n\n'
report += 'Завершённые операции (включённое время; вложенные интервалы перекрываются):\n\n'
for row in top:
    report += '- ' + row['operation'] + ': ' + str(round(row['inclusive_elapsed_ns'] / 1e9, 3)) + ' с, вызовов ' + str(row['count']) + '; ' + row['function'] + '.\n'
report += '\nОткрытые операции сохранены в summary.json; их время не включено в завершённые интервалы. Новых адресов C нет: покрытие 98,144% FDE-байтов с условными кандидатами, три метода остаются. Исходный C# и семантическая эквивалентность не восстановлены.\n'
(out / 'REPORT.ru.md').write_text(report, encoding='utf8')
print(json.dumps(dict(copied_files=len(rows), status=state['status'], C_coverage_addition=0)))
