"""Hash-verify private guard range evidence; never count pending/diagnostic C as recovery."""
import hashlib
import json
import shutil
from pathlib import Path


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


lab = Path(r'C:\Temp\terraria-re-20261012')
delivery = Path(r'C:/Private\Documents\ChatGPT\Terraria-Reverse-20261012')
tools = Path(__file__).resolve().parent
out = delivery / 'guard-range-diagnostic-continuation-20261019'
original = delivery / 'artifact-manifest.json'
assert sha(original) == '94cae77db018fee38c09e3b69f203b5fc0fbfd55b40c4aabbb935e30c61b391a'
interruption = json.loads((lab / 'guard-range-on-drawnpc1-interruption-20261019.json').read_text())
assert interruption['status'] == 'interrupted_without_result' and interruption['timed_out_observed'] is False
analysis = json.loads((lab / 'guard-range-on-drawnpc1-summary-20261019.json').read_text())
rows = []


def copy(source, relative):
    dest = out / relative
    assert dest.resolve().is_relative_to(out.resolve())
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, dest)
    digest = sha(source)
    assert sha(dest) == digest
    rows.append(dict(path=relative, bytes=dest.stat().st_size, sha256=digest))


for name in ('prepare_terraria_guard_range_trace.py', 'prepare_terraria_guard_range_builder.py',
             'prepare_terraria_guard_range_runtime.py', 'prepare_terraria_guard_range_runtime_v1.py',
             'run_terraria_guard_range_smokes.ps1', 'run_terraria_guard_range_diagnostic.ps1',
             'run_terraria_guard_range_smokes_v1.ps1', 'run_terraria_guard_range_diagnostic_v1.ps1',
             'review_terraria_action_trace.py', 'summarize_terraria_guard_ranges.py',
             'audit_terraria_remaining_call_sites.py', 'TERRARIA_GUARD_RANGE_SOURCE_REVIEW.md',
             'package_terraria_guard_range_diagnostic.py'):
    copy(tools / name, 'tools/' + name)
source = lab / 'portable-decompiler-guard-range-source-20261019'
for f in source.iterdir():
    if f.is_file():
        copy(f, 'build/' + f.name)
for f in (source / 'incremental-build-20261019').iterdir():
    if f.suffix != '.o':
        copy(f, 'build/linked/' + f.name)
for mode in ('off', 'on'):
    for f in (lab / ('guard-range-' + mode + '-sources-20261019')).iterdir():
        if f.is_file():
            copy(f, 'profiles/' + mode + '/' + f.name)
    for f in (lab / ('pseudocode-guard-range-' + mode + '-c-smoke-20261017')).iterdir():
        if f.is_file():
            copy(f, 'controls/' + mode + '/' + f.name)
for pattern in ('guard-range-on-smoke-20261019.pid*.log', 'guard-range-on-drawnpc1-20261019*',
                'guard-range-on-drawnpc1-interruption-20261019.json', 'guard-range-on-drawnpc1-summary-20261019.json',
                'guard-range-runner-path-correction-20261019.json', 'guard-range-runtime-provenance-20261019.json',
                'pe-review-guard-range-20261019.json', 'remaining-method-call-sites-20261019.json'):
    for f in lab.glob(pattern):
        if f.is_file():
            copy(f, 'evidence/' + f.name)
for f in (lab / 'pseudocode-guard-range-on-c-drawnpc1-20261017').iterdir():
    if f.is_file():
        copy(f, 'drawnpc1/' + f.name)
kill_path = lab / 'guard-range-on-kill-20261019.json'
kill_status = 'not_started'
if kill_path.exists():
    kill = json.loads(kill_path.read_text(encoding='utf-8-sig'))
    kill_status = kill['status']
    if kill_status not in ('starting', 'running'):
        for f in lab.glob('guard-range-on-kill-20261019*'):
            if f.is_file():
                copy(f, 'kill/' + f.name)
        folder = lab / 'pseudocode-guard-range-on-c-kill-20261017'
        if folder.exists():
            for f in folder.iterdir():
                if f.is_file():
                    copy(f, 'kill/result/' + f.name)
summary = dict(C_coverage_addition=0, C_addresses=123149, FDE_addresses=123152,
               C_FDE_bytes=34520124, FDE_bytes=35173000, percent_C_FDE_bytes=98.14381485798766,
               remaining_addresses=['0xf6954c', '0xf9a914', '0x1484e54'],
               drawnpc1_status=interruption['status'], drawnpc1_interruption_cause='unknown',
               drawnpc1_open_scopes=analysis['trace_review']['open_scopes'],
               completed_by_space=analysis['completed_by_space'], kill_status_at_packaging=kill_status,
               original_manifest_unchanged=True)
out.mkdir(exist_ok=True)
(out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
(out / 'files.json').write_text(json.dumps(rows, indent=2) + '\n')
report = '# Адресная диагностика guard, 19.10.2026\n\n'
report += 'В прерванной пробе первой DrawNPCDirect валидированы 9728 BEGIN и 9718 завершённых пар; десять scopes остались открыты. Причина прерывания неизвестна. Native timeout и достижение порога памяти не установлены.\n\n'
report += 'Завершённые интервалы стека: guard — 543 вызова, 13,8032215 с; вложенный guardCalls — 543 вызова, 13,7662094 с. guardStores — 0,0048335 с, guardLoads — 0,0018906 с. Родительское и вложенное время перекрываются. Последний открытый guardCalls относится к stack@0xfffffffffffff640+4; это смещение в пространстве стека Ghidra, не адрес ELF.\n\n'
report += 'Статические BL-вызовы сверены с исходными словами ARM64: DrawNPCDirect_1 — 4152, DrawNPCDirect_2 — 4142, Projectile.Kill — 6971. Найдены также 8/8/1 BLR-кодировок, не представленных в исходном каталоге прямых ссылок; их достижимость и цели не установлены.\n\n'
report += 'Состояние полной пробы Kill при упаковке: ' + kill_status + '. Нового C этот диагностический этап не добавляет. Покрытие остаётся 98,144% FDE-байтов с условными кандидатами; три метода остаются. Исходный C# и семантическая эквивалентность не заявляются.\n'
(out / 'REPORT.ru.md').write_text(report, encoding='utf8')
print(json.dumps(dict(copied_files=len(rows), kill_status=kill_status, C_coverage_addition=0)))
