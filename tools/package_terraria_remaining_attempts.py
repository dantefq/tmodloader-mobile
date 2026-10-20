"""Index existing audited attempts; never infer a timeout from elapsed time."""
import datetime
import hashlib
import json
from pathlib import Path
import shutil

LAB = Path('C:/Temp/terraria-re-20261012')
ROOT = Path('C:/Private/Documents/ChatGPT/Terraria-Reverse-20261012')
REPO = Path(__file__).resolve().parents[1]
STAGES = (
    ('Coarse', 'coarse-continuation-20261015'),
    ('NoReturn', 'noreturn-coarse-continuation-20261015'),
    ('Extended', 'extended-noreturn-continuation-20261015'),
    ('Untyped', 'untyped-c-continuation-20261016'),
    ('Branch', 'branch-preserving-c-continuation-20261016'),
    ('1800 s', 'long-budget-c-continuation-20261017'),
)

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))

def main():
    prior = ROOT / 'artifact-manifest.json'
    assert sha(prior) == '94cae77db018fee38c09e3b69f203b5fc0fbfd55b40c4aabbb935e30c61b391a'
    latest = read(ROOT / 'long-budget-c-continuation-20261017/summary.json')
    remaining = {r['address']: r['method'] for r in latest['remaining_methods']}
    metadata_path = LAB / 'metadata/methods.jsonl'
    signatures = []
    with metadata_path.open(encoding='utf8') as stream:
        for line in stream:
            item = json.loads(line)
            if item.get('native_address') in remaining:
                signatures.append({key: item[key] for key in ('index', 'native_address', 'display_signature', 'parameter_names')})
    sources, rows = [], []
    for label, stage in STAGES:
        path = ROOT / stage / 'summary.json'
        summary = read(path)
        sources.append({'stage': stage, 'summary_sha256': sha(path)})
        for attempt in summary['attempts']:
            if attempt['address'] not in remaining:
                continue
            folder = LAB / attempt['folder']
            assert folder.resolve().parent == LAB.resolve()
            result_path = folder / 'result.json'
            audit_path = folder / 'audit.json'
            if not audit_path.exists():
                audit_path = folder / 'independent-audit.json'
            result, audit = read(result_path), read(audit_path)
            assert audit['integrity_passed'] and audit['result_sha256'] == sha(result_path)
            assert result['address'] == attempt['address'] and result['status'] == attempt['status']
            assert result['status'] == 'decompile_failed'
            rows.append({'address': result['address'], 'profile': label,
                         'status': result['status'], 'timed_out': result['timed_out'],
                         'seconds': result['elapsed_seconds'], 'budget': result['timeout_seconds'],
                         'source_bytes': result['function_source_bytes_verified'],
                         'result_path': str(result_path), 'result_sha256': sha(result_path),
                         'audit_sha256': sha(audit_path)})
    interruptions = []
    for folder in sorted(LAB.glob('interrupted-*')):
        evidence = folder / 'interruption.json'
        if not evidence.exists():
            continue
        record = read(evidence)
        interruptions.append({'folder': folder.name, 'record': record, 'sha256': sha(evidence)})
    dest = ROOT / 'remaining-attempts-20261017'
    dest.mkdir(exist_ok=True)
    snapshot = {'recorded_UTC': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'scope': 'Index of existing audits, not a new independent source/CFG audit.',
                'new_C_addresses': 0, 'remaining_methods': remaining,
                'stage_sources': sources, 'audited_attempts': rows,
                'metadata_methods_sha256': sha(metadata_path), 'metadata_signatures': signatures,
                'preserved_interruptions': interruptions,
                'active_process_observation': False}
    (dest / 'summary.json').write_text(json.dumps(snapshot, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
    lines = ['# Остаточные методы: индекс проверенных попыток', '',
             'Сводка существующих аудитов. Она не добавляет C и не заменяет исходные проверки. '
             '«Нет результата» означает отсутствие проверенной записи в этом профиле; текущий процесс по этому индексу не определяется.', '',
             '| Метод / адрес | ' + ' | '.join(label for label, _ in STAGES) + ' |',
             '|---|' + '---|' * len(STAGES)]
    for address, method in remaining.items():
        cells = []
        for label, _ in STAGES:
            found = [r for r in rows if r['address'] == address and r['profile'] == label]
            cells.append('; '.join(('таймаут' if row['timed_out'] else 'ошибка') + f" {row['seconds']:.1f} с" for row in found) if found else 'нет результата')
        lines.append(f'| {method} `{address}` | ' + ' | '.join(cells) + ' |')
    lines += ['', 'В исходном списке две DrawNPCDirect — перегрузки внутри одного APK. У адреса `0xf6954c` четыре явных параметра метаданных: SpriteBatch, NPC, behindTiles, screenPos. У `0xf9a914` к ним добавлены LightMap и Rectangle& lightRegion. Это не разные версии игры и не полная реконструкция нативного ABI.', '',
              'Прерванные попытки перечислены отдельно в JSON с исходными записями и SHA. '
              'Прерывание без result.json не считается таймаутом. Изменение бюджета 600→1800 с сохраняет алгоритм исходного профиля.', '',
              '[Записи, исходные пути и SHA](summary.json).']
    (dest / 'REPORT.ru.md').write_text('\n'.join(lines) + '\n', encoding='utf8')
    shutil.copy2(Path(__file__), dest / Path(__file__).name)
    files = [{'path': p.name, 'bytes': p.stat().st_size, 'sha256': sha(p)}
             for p in sorted(dest.iterdir()) if p.is_file() and p.name != 'addendum-manifest.json']
    (dest / 'addendum-manifest.json').write_text(json.dumps({'prior_manifest_sha256': sha(prior), 'files': files}, indent=2) + '\n')
    print(json.dumps({'remaining': len(remaining), 'indexed_audited_attempts': len(rows), 'new_C': 0}))

if __name__ == '__main__':
    main()
