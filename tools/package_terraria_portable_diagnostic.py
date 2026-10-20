"""Hash-verified private evidence addendum; does not alter original manifest."""
import hashlib
import json
import shutil
from pathlib import Path


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


lab = Path(r'C:\Temp\terraria-re-20261012')
delivery = Path(r'C:/Private\Documents\ChatGPT\Terraria-Reverse-20261012')
out = delivery / 'portable-diagnostic-continuation-20261018'
tools = Path(__file__).resolve().parent
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


for name in ('TERRARIA_PORTABLE_BASELINE_RUNTIME_REVIEW.md', 'TERRARIA_RESOURCE_FALLBACK_REVIEW.md',
             'build_terraria_trace_incremental.ps1', 'deploy_terraria_portable_baseline.py',
             'prepare_terraria_trace_smokes.py', 'prepare_terraria_trace_diagnostic.py',
             'run_terraria_trace_smokes.ps1', 'run_terraria_trace_diagnostic.ps1',
             'review_terraria_action_trace.py', 'review_terraria_action_trace_v1.py',
             'selftest_terraria_action_trace.py',
             'prepare_terraria_heritage_trace.py', 'package_terraria_portable_diagnostic.py'):
    copy(tools / name, 'tools/' + name)
for name in ('pe-review-portable-baseline-20261018.json', 'pe-review-portable-trace-20261018.json',
             'pe-review-portable-baseline-readobj-20261018.log',
             'portable-baseline-deployment-20261018.json',
             'portable-four-way-smoke-C-comparison-20261018.json',
             'portable-baseline-C-smoke-comparison-20261018.json',
             'portable-trace-smoke-preparation-20261018.json',
             'portable-trace-on-smoke-review-20261018.json',
             'portable-trace-diagnostic-smoke-state-correction-20261018.json'):
    copy(lab / name, 'evidence/' + name)
copy(lab / 'action-trace-inspector-selftest-20261018.json', 'evidence/action-trace-inspector-selftest-20261018.json')
base = lab / 'portable-decompiler-baseline-prep-20261017'
for name in ('preparation-manifest.json', 'resource-error-baseline-strategy.json',
             'resource-error-baseline-build-provenance.json', 'build-baseline-after-resource-error.ps1'):
    copy(base / name, 'baseline/' + name)
for f in (base / 'baseline-build').iterdir():
    if f.suffix in ('.json', '.log', '.rsp', '.exe'):
        copy(f, 'baseline/build/' + f.name)
trace = lab / 'portable-decompiler-trace-source-20261017'
for name in ('trace-source-manifest.json', 'trace-only.patch'):
    copy(trace / name, 'trace/' + name)
heritage = lab / 'portable-decompiler-heritage-trace-source-20261018'
for name in ('heritage-source-manifest.json', 'heritage-trace-only.patch'):
    if (heritage / name).exists():
        copy(heritage / name, 'heritage-source-preparation/' + name)
for f in (trace / 'incremental-build-20261018').iterdir():
    if f.suffix in ('.json', '.log', '.rsp', '.exe'):
        copy(f, 'trace/build/' + f.name)
for name in ('libc++.dll', 'libunwind.dll'):
    copy(lab / 'ghidra-portable-trace-20261018/Ghidra/Features/Decompiler/os/win_x86_64' / name, 'runtime/' + name)
for folder in ('portable-baseline-smoke-sources-20261018', 'portable-trace-off-smoke-sources-20261018',
               'portable-trace-on-smoke-sources-20261018', 'portable-trace-diagnostic-sources-20261018'):
    for f in (lab / folder).iterdir():
        if f.is_file():
            copy(f, 'sources/' + folder + '/' + f.name)
for prefix in ('portable-baseline', 'portable-trace-off', 'portable-trace-on', 'portable-trace-diagnostic'):
    folder = 'pseudocode-' + prefix + '-c-smoke-20261017'
    for f in (lab / folder).iterdir():
        if f.is_file():
            copy(f, 'controls/' + folder + '/' + f.name)
for f in lab.glob('portable-trace-on-smoke-20261018.pid*.log'):
    copy(f, 'controls/' + f.name)
diagnostics = []
for target in ('smoke', 'drawnpc1', 'drawnpc2', 'kill', 'kill-long'):
    state = lab / ('portable-trace-diagnostic-' + target + '-20261018.json')
    if not state.exists():
        continue
    data = json.loads(state.read_text(encoding='utf-8-sig'))
    if target == 'kill-long':
        interruption = lab / 'portable-trace-diagnostic-kill-long-interruption-20261019.json'
        if interruption.exists():
            observed = json.loads(interruption.read_text())
            data['status'] = observed['status']
            copy(interruption, 'diagnostics/' + interruption.name)
    diagnostics.append(dict(target=target, status=data['status'], C_coverage_addition=0))
    # Never package an actively changing log or state as stable evidence.
    if data['status'] == 'running':
        continue
    result_folder = lab / ('pseudocode-portable-trace-diagnostic-c-' + target + '-20261017')
    if result_folder.exists():
        for f in result_folder.iterdir():
            if f.is_file():
                copy(f, 'diagnostics/' + result_folder.name + '/' + f.name)
    for f in lab.glob('portable-trace-diagnostic-' + target + '-20261018*'):
        if f.is_file():
            copy(f, 'diagnostics/' + f.name)
    for f in lab.glob('portable-trace-diagnostic-' + target + '-review*-20261018.json'):
        copy(f, 'diagnostics/' + f.name)
summary = dict(C_coverage_addition=0, C_addresses=123149, FDE_addresses=123152,
               C_FDE_bytes=34520124, FDE_bytes=35173000, percent_C_FDE_bytes=98.14381485798766,
               remaining=['0xf6954c', '0xf9a914', '0x1484e54'], diagnostics=diagnostics,
               original_manifest_unchanged=sha(original) == '94cae77db018fee38c09e3b69f203b5fc0fbfd55b40c4aabbb935e30c61b391a')
out.mkdir(exist_ok=True)
(out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
(out / 'files.json').write_text(json.dumps(rows, indent=2) + '\n')
(out / 'REPORT.ru.md').write_text(
    '# Диагностика оставшихся методов, 18.10.2026\n\n'
    'Базовый и диагностический движки собраны и проверены на малом методе. '
    'Оригинальный движок, новый базовый, трассировка off и on выдали побайтово одинаковый C-код (392 байта). '
    'Независимые аудиторы прошли 94 отрицательных контроля. Трассировка малого метода: 191 завершённая пара событий.\n\n'
    'Новых адресов игрового C-кода этот этап не добавляет. Покрытие: 123149 из 123152 адресов FDE, '
    '34520124 из 35173000 байтов FDE (98,144%), включая условные кандидаты. '
    'Остаются две DrawNPCDirect и Projectile.Kill. Это не восстановление исходного C# и не доказательство эквивалентности.\n\n'
    'Состояния диагностических проб: ' + '; '.join(r['target'] + ': ' + r['status'] for r in diagnostics) + '.\n\n'
    'Подробности: tools/TERRARIA_PORTABLE_BASELINE_RUNTIME_REVIEW.md; хеши копий: files.json. '
    'Активные трассы не копируются до завершения. Исходный artifact-manifest.json сохранён.\n', encoding='utf8')
print(json.dumps(dict(copied_files=len(rows), diagnostics=diagnostics, C_coverage_addition=0)))
