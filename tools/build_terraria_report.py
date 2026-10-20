"""Assemble an evidence-linked private Russian report from actual analysis outputs."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta

ROOT = Path(__file__).resolve().parents[1]

def load(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))

def read_jsonlines(path, active=False):
    errors, tolerated, result = [], [], []
    if not path.exists():
        return result, errors, tolerated
    try:
        lines = path.read_text(encoding='utf-8').splitlines(keepends=True)
    except (UnicodeDecodeError, OSError) as error:
        return [], [{'path': str(path), 'error': str(error)}], []
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError('JSON record must be an object')
            result.append(value)
        except (json.JSONDecodeError, ValueError) as error:
            item = {'path': str(path), 'line': index + 1, 'error': str(error)}
            if active and index == len(lines) - 1 and not line.endswith(('\n', '\r')):
                tolerated.append(item)
            else:
                errors.append(item)
    return result, errors, tolerated


def jsonlines(path):
    result, errors, _ = read_jsonlines(path)
    if errors:
        raise ValueError(f'Invalid JSONL: {errors[:3]}')
    return result


def export_integrity(lab, native, progress=None):
    """Reconcile immutable carriers and recorded outputs; progress is never proof."""
    lab = lab.resolve()
    errors, expected, extents = [], {}, {}
    progress_path = lab / 'pseudocode/progress.json'
    if progress is None:
        try:
            progress = load(progress_path) if progress_path.exists() else {}
            if not isinstance(progress, dict):
                raise ValueError('Progress must be a JSON object')
        except (ValueError, OSError) as error:
            progress = {}
            errors.append({'kind': 'invalid_progress', 'error': str(error)})
    carriers = {}
    for name in ('method-seeds.tsv', 'generic-method-seeds.tsv'):
        path = lab / 'native' / name
        if not path.exists():
            errors.append({'kind': 'missing_seed_carrier', 'path': str(path)})
            continue
        carriers[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            if not line or line.startswith('#'):
                continue
            parts = line.split('\t')
            try:
                if len(parts) < 4:
                    raise ValueError('Seed row needs at least four columns')
                address = int(parts[0], 16)
                if address <= 0 or address % 4 or address in expected:
                    raise ValueError('Invalid, unaligned or duplicate seed address')
                expected[address] = {'address': hex(address), 'method': parts[2], 'image': parts[3]}
            except ValueError as error:
                errors.append({'kind': 'invalid_seed', 'path': str(path), 'line': number, 'error': str(error)})
    declared_total = native['total_unique_managed_implementation_addresses']
    if len(expected) != declared_total or declared_total != 93990:
        errors.append({'kind': 'seed_count_mismatch', 'actual': len(expected), 'native_summary': declared_total, 'required_for_this_apk': 93990})
    mapped = set()
    for name in ('method-addresses.json', 'generic-method-addresses.json'):
        path = lab / 'native' / name
        try:
            mapped.update(int(row['address'], 16) for row in load(path) if row.get('address'))
        except (ValueError, KeyError, TypeError, OSError) as error:
            errors.append({'kind': 'invalid_native_address_map', 'path': str(path), 'error': str(error)})
    if mapped != set(expected):
        errors.append({'kind': 'seed_native_map_mismatch', 'seeds_missing_from_map': len(set(expected) - mapped), 'mapped_addresses_missing_seeds': len(mapped - set(expected))})
    path = lab / 'native/unwind-function-ranges.tsv'
    previous_end = 0
    try:
        carriers[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            parts = line.split('\t')
            if len(parts) != 2:
                raise ValueError(f'Invalid FDE row {number}')
            start, end = (int(value, 16) for value in parts)
            if start >= end or start % 4 or end % 4 or start < previous_end or start in extents:
                raise ValueError(f'Invalid or overlapping FDE row {number}')
            extents[start] = end
            previous_end = end
    except (ValueError, OSError) as error:
        errors.append({'kind': 'invalid_fde_carrier', 'error': str(error)})
    if len(extents) != 123152:
        errors.append({'kind': 'fde_count_mismatch', 'actual': len(extents), 'required_for_this_apk': 123152})
    if not set(expected).issubset(extents):
        errors.append({'kind': 'seeds_without_fde', 'count': len(set(expected) - set(extents))})
    rows, json_errors, tolerated = read_jsonlines(lab / 'pseudocode/coverage.jsonl', active=progress.get('finished') is not True)
    errors.extend({'kind': 'invalid_ledger_json', **item} for item in json_errors)
    valid, seen, invalid = {}, set(), set()
    statuses = {'decompiled', 'decompile_failed', 'missing_function', 'export_error'}
    folder = (lab / 'pseudocode').resolve()
    for number, row in enumerate(rows, 1):
        row_errors = []
        address = None
        try:
            address = int(row['address'], 16)
            if address in seen:
                invalid.add(address)
                raise ValueError('Duplicate ledger address')
            seen.add(address)
            if address not in expected:
                raise ValueError('Ledger address is outside the exact seed union')
            if type(row.get('image_base')) is not int or row['image_base'] != 0:
                row_errors.append('image_base must be integer zero')
            if int(row.get('compiler_end_exclusive', '-1'), 16) != extents.get(address):
                row_errors.append('compiler_end_exclusive does not match independent FDE')
            if row.get('image') != expected[address]['image'] or row.get('method') != expected[address]['method']:
                row_errors.append('method/image identity differs from seed')
            if row.get('status') not in statuses:
                row_errors.append('unknown status')
            if type(row.get('instructions')) is not int or row['instructions'] < 0:
                row_errors.append('instructions must be a nonnegative integer')
            compiler_size = extents.get(address, address) - address
            if 'compiler_size' in row and (type(row['compiler_size']) is not int or row['compiler_size'] != compiler_size):
                row_errors.append('compiler_size differs from independent FDE extent')
            if 'instruction_bytes' in row and (type(row['instruction_bytes']) is not int or not 0 <= row['instruction_bytes'] <= compiler_size):
                row_errors.append('instruction_bytes must fit inside compiler extent')
            if 'instruction_coverage_complete' in row:
                if type(row['instruction_coverage_complete']) is not bool:
                    row_errors.append('instruction_coverage_complete must be boolean')
                elif row['instruction_coverage_complete'] and row.get('instruction_bytes') != compiler_size:
                    row_errors.append('complete instruction coverage requires byte count equal to compiler extent')
            if row.get('status') == 'decompiled':
                relative = row.get('file')
                if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
                    row_errors.append('missing or nonrelative pseudocode filename')
                else:
                    target = (folder / relative).resolve()
                    if not target.is_relative_to(folder) or not target.is_file() or target.stat().st_size == 0:
                        row_errors.append('pseudocode file is outside its folder, missing or empty')
            if row_errors:
                invalid.add(address)
                raise ValueError('; '.join(row_errors))
            valid[address] = row
        except (ValueError, KeyError, TypeError, OSError) as error:
            if address in expected:
                invalid.add(address)
            errors.append({'kind': 'invalid_ledger_record', 'record': number, 'address': row.get('address'), 'error': str(error)})
    for address in invalid:
        valid.pop(address, None)
    missing = sorted(set(expected) - seen)
    counts = Counter(row['status'] for row in valid.values())
    instruction_coverage = Counter('full' if row.get('instruction_coverage_complete') is True else
                                   'partial' if row.get('instruction_coverage_complete') is False else 'unreported'
                                   for row in valid.values())
    matches = bool(progress)
    comparisons = {'total': len(expected), 'processed': len(valid), 'decompiled': counts['decompiled'],
                   'failed': counts['decompile_failed'], 'missing': counts['missing_function']}
    if counts['export_error'] or 'export_error' in progress:
        comparisons['export_error'] = counts['export_error']
    mismatches = {key: {'progress': progress.get(key), 'validated_ledger': value} for key, value in comparisons.items()
                  if type(progress.get(key)) is not int or progress.get(key) != value}
    matches = matches and not mismatches
    # During an active pass the writer checkpoints every 100 rows; this is diagnostic,
    # not corruption. A finished flag must match every count exactly.
    if progress.get('finished') is True and mismatches:
        errors.append({'kind': 'finished_progress_count_mismatch', 'counts': mismatches})
    complete = progress.get('finished') is True and not errors and not tolerated and not missing and len(valid) == len(expected) and matches
    return {'complete': complete, 'expected_addresses': len(expected), 'ledger_records': len(rows),
            'valid_unique_records': len(valid), 'counts': dict(counts), 'not_attempted_count': len(missing),
            'not_attempted_addresses': [hex(address) for address in missing],
            'invalid_expected_addresses': [hex(address) for address in sorted(invalid & set(expected))],
            'integrity_errors': errors, 'tolerated_active_terminal_json': tolerated,
            'progress_counts_match': matches, 'progress_count_differences': mismatches,
            'instruction_extent_coverage': {key: instruction_coverage[key] for key in ('full', 'partial', 'unreported')},
            'progress': progress, 'carrier_sha256': carriers}, list(valid.values())


def bind_evidence(path, apk_path, apk_sha256, item=None):
    item = load(path) if item is None else item
    subject = item.get('subject', {})
    digest = subject.get('digest', {}).get('sha256')
    recorded_path = subject.get('local_path') or subject.get('name') or item.get('parameters', {}).get('path')
    binding = {'path': str(path), 'evidence_id': item.get('evidence_id'), 'operation': item.get('operation'),
               'recorded_apk_path': recorded_path, 'recorded_apk_sha256': digest}
    if digest:
        binding.update(bound=digest.lower() == apk_sha256.lower(), basis='recorded_sha256')
    else:
        same_path = bool(recorded_path) and Path(recorded_path).resolve() == Path(apk_path).resolve()
        binding.update(bound=False, basis='path_only_unverified' if same_path else 'unbound')
    return binding, item

def num(n):
    return f'{n:,}'.replace(',', ' ')


def filelink(label, path):
    return f'[{label}](<{path.resolve().as_posix()}>)'

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--lab', type=Path, default=Path('C:/Temp/terraria-re-20261012'))
    parser.add_argument('--reports', type=Path, default=ROOT/'reports/terraria-re-20261012')
    parser.add_argument('--native-log', type=Path, help='Optional diagnostic native-export log; never used as completion proof')
    args = parser.parse_args()
    lab, reports = args.lab, args.reports
    metadata = load(reports/'metadata-summary.json')
    native = load(reports/'native-summary.json')
    android = load(reports/'android-summary.json')
    methods = jsonlines(lab/'metadata/methods.jsonl')
    types = jsonlines(lab/'metadata/types.jsonl')
    integrity, coverage = export_integrity(lab, native)
    progress = integrity['progress']
    for name, digest in [('metadata', metadata.get('apk_sha256')), ('android', android.get('sha256'))]:
        if digest != native['apk_sha256']:
            integrity['integrity_errors'].append({'kind': 'input_apk_digest_mismatch', 'source': name, 'sha256': digest})
            integrity['complete'] = False
    counts = Counter(row['status'] for row in coverage)
    by_image = defaultdict(Counter)
    by_address = {}
    for row in coverage:
        by_image[row['image']][row['status']] += 1
        by_address[row['address']] = row
    evidence, evidence_bindings, evidence_seen = [], [], set()
    rea_class_count = None
    evidence_root = lab/'evidence' if (lab/'evidence').is_dir() else ROOT/'reports'
    notes_root = lab/'notes' if (lab/'notes').is_dir() else ROOT/'notes'
    for path in sorted(evidence_root.glob('terraria-rea-*-20261012.json'), key=lambda p: ('final' not in p.name, p.name)):
        source = load(path)
        for item in source.get('records', [source]):
            binding, item = bind_evidence(path, native['apk_path'], native['apk_sha256'], item=item)
            evidence_bindings.append(binding)
            if binding['bound'] and binding['evidence_id'] and binding['evidence_id'] not in evidence_seen:
                evidence_seen.add(binding['evidence_id'])
                evidence.append((path, item['operation'], item['evidence_id']))
                if item.get('operation') == 'inspect_android_package':
                    rea_class_count = item.get('normalized_result', {}).get('class_count')
    java_files = list((lab/'jadx/sources').rglob('*.java')) if (lab/'jadx/sources').exists() else []
    jadx_manifest = lab/'jadx/resources/AndroidManifest.xml'
    jadx = {'sources_present': bool(java_files), 'java_files_present': len(java_files),
            'manifest_present': jadx_manifest.is_file(), 'source_input_binding': 'presence_only_not_verified_by_this_report',
            'reproduction': 'JADX and REA were separate manual steps in this session; runner repeats local parser/Ghidra stages only.'}
    native_log = {'path': str(args.native_log), 'exists': args.native_log.is_file(),
                  'bytes': args.native_log.stat().st_size if args.native_log.is_file() else None} if args.native_log else None
    jni_path = reports/'jni-summary.json'
    jni = load(jni_path) if jni_path.exists() else None
    jni_bound = bool(jni and jni.get('apk_sha256') == native['apk_sha256'])
    jni_presence = {name: (lab/'android-native'/name).is_file() for name in
                    ('jni-table-candidates.json', 'dex-export-bindings.json', 'unresolved-dex-native-declarations.json')}
    disassembly_path = lab/'pseudocode/disassembly-summary.json'
    disassembly = load(disassembly_path) if disassembly_path.exists() else None
    verification_path = lab/'pseudocode/instruction-verification.json'
    verification = load(verification_path) if verification_path.exists() else None
    tail_path = lab/'pseudocode/tail-call-summary.json'
    tail_calls = load(tail_path) if tail_path.exists() else None
    terminal_path = lab/'pseudocode/terminal-call-summary.json'
    terminal_calls = load(terminal_path) if terminal_path.exists() else None
    signatures_path = lab/'pseudocode/signatures-applied-summary.json'
    signatures = load(signatures_path) if signatures_path.exists() else None
    callgraph_path = lab/'pseudocode/callgraph-summary.json'
    callgraph = load(callgraph_path) if callgraph_path.exists() else None
    audit_path = lab/'pseudocode/pseudocode-audit.json'
    audit = load(audit_path) if audit_path.exists() else None
    summary = {
        'date_local': datetime.now(timezone(timedelta(hours=3))).date().isoformat(), 'analysis_started': '2026-10-12', 'source_apk': native['apk_path'],
        'apk_sha256': native['apk_sha256'],
        'status': ('automated-reconstruction-finished-with-explicit-gaps' if integrity['complete'] else
                   'native-export-incomplete-with-integrity-errors' if integrity['integrity_errors'] else 'native-export-incomplete'),
        'metadata_types': len(types), 'metadata_methods': len(methods),
        'direct_implementation_addresses': native['unique_mapped_addresses'],
        'all_managed_implementation_addresses': native['total_unique_managed_implementation_addresses'],
        'native_export': {**dict(counts), 'not_attempted': integrity['not_attempted_count']}, 'native_export_progress': progress,
        'native_export_integrity': integrity, 'native_export_log': native_log,
        'analysis_limits': {'global_decompiler_switch_analysis_disabled': True,
                            'automatic_analysis_disabled': True,
                            'resource_limits_recorded_per_function': True,
                            'linear_instruction_decoding_does_not_prove_reachability': True,
                            'per_function_pseudocode_and_instruction_coverage_require_review': True},
        'bounded_disassembly': disassembly, 'instruction_byte_verification': verification,
        'tail_call_annotations': tail_calls,
        'terminal_call_annotations': terminal_calls, 'conservative_signatures': signatures,
        'static_callgraph': callgraph,
        'pseudocode_audit': audit,
        'rea_evidence_bindings': evidence_bindings, 'jadx_output_presence': jadx,
        'jni_catalog': {'summary_present': bool(jni), 'apk_sha256_bound': jni_bound,
                        'private_file_presence': jni_presence, 'summary_path': str(jni_path)},
        'native_export_per_image': {k:dict(v) for k,v in by_image.items()},
        'private_lab': str(lab), 'original_source_recovered': False,
        'apk_executed': False, 'rebuild_verified': False,
    }
    reports.mkdir(parents=True, exist_ok=True)
    (reports/'coverage-summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    lines = [
        '# Terraria Android: разбор предоставленного APK', '',
        'Исследование начато 12 октября 2026; дата формирования отчёта по Москве: '+summary['date_local']+'. Universal Modder использован как рабочий процесс исследования; REA — для доказательного каталога APK и статического Android-анализа; собственные проверяемые парсеры — для IL2CPP; Ghidra — для нативного псевдокода.', '',
        '## Результат и границы', '',
        'Это реконструкция из скомпилированного APK. Исходный проект разработчика, исходные C#-тела, комментарии, имена локальных переменных и build scripts в нём не восстановлены. Каркасы `.symbols.cs` содержат только комментарии с фактами из метаданных. `.c` содержит псевдокод декомпилятора, а не исходный C++ или C#.', '',
        f'Полностью перечислены {num(len(types))} определений типов, {num(len(methods))} объявлений методов, 66 527 полей, 73 245 параметров, 10 641 свойство и 178 событий. Восстановлены 23 420 IL2CPP-типов, принадлежность записей сборкам и классам, наследование, сигнатуры и сырые нативные смещения полей.', '',
        'Для 63 724 объявлений найден прямой или generic-адрес реализации. Среди оставшихся — 1 786 абстрактных объявлений и 70 конкретных объявлений без найденной реализации. Это покрытие адресов, не процент корректно восстановленного поведения.', '',
        f'В очереди нативного анализа {num(native["total_unique_managed_implementation_addresses"])} разных адресов: 60 843 обычных и 33 147 generic-реализаций.', '',
        'Всего каталог compiler FDE содержит 123 152 диапазона. C-экспорт охватывает 93 990 сопоставленных managed-реализаций; оставшиеся 29 162 диапазона не экспортировались отдельными C-телами. Их функции и инструкции присутствуют в базе Ghidra и полном bounded-disassembly каталоге; принадлежность каждого такого диапазона runtime/helper-коду здесь не установлена.', '',
        f'На момент генерации отчёта: проверено {num(len(coverage))} уникальных записей, получен псевдокод для {num(counts["decompiled"])}, ошибок декомпиляции {num(counts["decompile_failed"])}, ошибок экспорта {num(counts["export_error"])}, отсутствующих функций {num(counts["missing_function"])}, не начато {num(integrity["not_attempted_count"])}. Экспорт '+('закончен: ledger, файлы и все счётчики сверены.' if integrity['complete'] else '**не подтверждён как законченный**.'), '',
        f'Ошибок целостности: {num(len(integrity["integrity_errors"]))}; расхождения progress/ledger и полный список `not_attempted` записаны в `coverage-summary.json`. Сам флаг `finished` не подтверждает завершение. Незаконченная последняя JSON-строка допускается только при активном экспорте.', '',
        'Покрытие инструкциями compiler extents по дополнительным полям ledger: '
        f'полное {num(integrity["instruction_extent_coverage"]["full"])}, частичное {num(integrity["instruction_extent_coverage"]["partial"])}, '
        f'не сообщено {num(integrity["instruction_extent_coverage"]["unreported"])}. При частичном или не сообщённом покрытии listing не объявляется полным.', '',
        'Игра в этом исследовании не запускалась; изменения APK, сохранений и установленных приложений не выполнялись. Статический анализ не доказывает игровое поведение или возможность собрать рабочую игру из результатов.', '',
        '## Точный объект исследования', '',
        f'- APK: `{native["apk_path"]}`',
        f'- SHA-256 APK: `{native["apk_sha256"]}`',
        f'- SHA-256 libil2cpp.so: `{native["libil2cpp_sha256"]}`',
        f'- SHA-256 global-metadata.dat: `{native["metadata_sha256"]}`',
        '- Android package: `com.and.games505.TerrariaPaid`.',
        '- VersionName `1.4.5.8.6`, versionCode `301720`; версия основной managed-сборки в метаданных `1.4.5.8`.',
        '- Unity revision `2021.3.56f2`, IL2CPP metadata v31, ELF64 little-endian AArch64, ABI `arm64-v8a`.',
        '- minSdk 23, targetSdk 36; восемь native-библиотек, один DEX, 112 ZIP-записей.', '',
        'Проверен именно пользовательский `patched` APK. Без доверенного официального APK той же версии невозможно установить все отличия, внесённые сторонним патчером.', '',
        '## Устройство программы', '',
        '```mermaid',
        'flowchart TD',
        '  A[Android manifest / Java DEX] --> B[UnityPlayerActivity / JNI]',
        '  A --> P[PdaApplication / pdaprotect]',
        '  B --> U[libmain.so / libunity.so]',
        '  U --> C[libil2cpp.so: ARM64 code]',
        '  M[global-metadata.dat: names / signatures / tokens] --> C',
        '  C --> T[Assembly-CSharp: Terraria and mobile integration]',
        '  C --> F[35 managed images: .NET / XNA-compatible / Unity / libraries]',
        '  R[UnityFS / resources.resource] --> U',
        '```', '',
        'Стрелки показывают статические связи упаковки и интерфейсов; они не являются трассой выполненного запуска.', '',
        'Основная `Assembly-CSharp.dll` представлена именем managed-image и метаданными, а её машинный код находится в `libil2cpp.so`. Отдельной исходной DLL с CIL-телами здесь нет. В ней 3 813 типов, 27 424 метода, 44 525 полей. Пространство имён `Terraria` вместе с дочерними содержит 1 351 тип и 14 698 методов; остальные типы основной сборки включают мобильную интеграцию и вспомогательные компоненты.', '',
        '## Карта игровых подсистем', '',
        'Назначение ниже — ориентир по объявлениям. Конкретные алгоритмы следует проверять по псевдокоду и инструкциям; одно имя метода не доказывает его семантику.', '',
        '| Класс | Методов | Полей | Где искать |', '|---|---:|---:|---|',
    ]
    descriptions = {
        'Terraria.Main':'главное состояние, Update, UpdateTime, отрисовка, UI',
        'Terraria.Player':'игрок, ItemCheck, Hurt, KillMe, UpdateDead, Spawn',
        'Terraria.NPC':'AI, SpawnNPC/NewNPC, StrikeNPC, SetDefaults',
        'Terraria.Projectile':'AI, Update, NewProjectile, попадания',
        'Terraria.Item':'SetDefaults, характеристики и состояние предметов',
        'Terraria.WorldGen':'GenerateWorld, тайлы, размещение и разрушение',
        'Terraria.Wiring':'провода и механизмы',
        'Terraria.NetMessage':'отправка пакетов / SendData',
        'Terraria.MessageBuffer':'разбор входящих пакетов / GetData',
        'Terraria.IO.WorldFile':'чтение/запись мира, версии формата',
        'Terraria.IO.PlayerFileData':'данные файла игрока',
        'Terraria.Recipe':'рецепты и поиск подходящего крафта',
        'Terraria.Lighting':'освещение',
        'Terraria.GameContent.ItemDropRules.ItemDropResolver':'правила выпадения',
    }
    for row in metadata['subsystem_method_inventories']:
        lines.append(f'| `{row["type"]}` | {num(row["method_count"])} | {num(row["field_count"])} | {descriptions.get(row["type"], "объявления в каталоге")} |')
    lines += ['', 'В поисковом каталоге доступны и остальные классы: ввод/gamepad, локализация, UI, достижения, события, биомы, жидкости, карты, звук, rendering и вспомогательные алгоритмы.', '',
              '### Примеры точных сигнатур и адресов', '',
              '| Объявление | ELF VA | Псевдокод |', '|---|---|---|']
    wanted = {('Terraria.Player','UpdateDead'), ('Terraria.Player','KillMe'), ('Terraria.Player','Spawn'),
              ('Terraria.Item','SetDefaults'), ('Terraria.Main','UpdateTime'), ('Terraria.NetMessage','SendData'),
              ('Terraria.MessageBuffer','GetData'), ('Terraria.WorldGen','GenerateWorld'),
              ('Terraria.NPC','AI'), ('Terraria.IO.WorldFile','SaveWorld')}
    for row in methods:
        if (row['owner_type'],row['name']) not in wanted:
            continue
        address = row.get('native_address')
        observation = by_address.get(address, {})
        source = observation.get('status', 'пока не экспортирован')
        # Absolute local links survive opening the report from either destination.
        if observation.get('status') == 'decompiled':
            source = filelink('открыть', lab/'pseudocode'/observation['file'])
        lines.append(f'| `{row["display_signature"].replace("|", "&#124;")}` | `{address}` | {source} |')
    lines += ['', 'Адреса — виртуальные адреса образа ELF/смещения относительно его нулевой базы. При ASLR они не являются абсолютными адресами процесса. Границы функции определяет Ghidra отдельно; расстояние до следующего адреса не считается доказанным размером функции.', '',
        '## Android-оболочка и ресурсы', '',
        'Полный DEX содержит 1 540 определений классов, 9 004 определений методов, 8 256 методов с Dalvik-кодом и 161 native-объявление. Независимый SDK dexdump подтвердил основные количества.', '',
        f'В текущей папке Lab фактически присутствует {num(len(java_files))} Java-файлов JADX; AndroidManifest.xml '+('присутствует.' if jadx_manifest.is_file() else '**отсутствует**.')+' Число файлов после преобразования вложенных/synthetic элементов отличается от числа DEX-определений. Наличие этих файлов само по себе не связывает их с входным APK.', '',
        ('В сохранённом REA Evidence с совпадающим SHA-256 APK provider class_count равен '+str(rea_class_count)+'.' if rea_class_count is not None else 'Подходящего REA Android Evidence с подтверждённым SHA-256 APK нет; provider class_count здесь не утверждается.'), '',
        'Application в манифесте — `com.external_wrapper.PdaApplication`; его статический инициализатор загружает `pdaprotect`. `com.android.support.Main` содержит загрузку `external_wrapper`. У `UnityPlayerActivity` ряд lifecycle/input методов, включая `onCreate`, — native-объявления без Java-тела. Для их семантики требуется исследование JNI; сам DEX исходного тела не содержит.', '',
        'Сохранённые REA-результаты DocumentsProvider и мостов лицензирования/age verification используются только при совпадении хеша APK. Их наличие и статические вызовы не доказывают, что эти пути исполнились. Защиты и лицензирование не изменялись.', '',
        'UnityFS содержит 5 762 LZ4HC-блока и семь файлов; распакованы все 755 140 841 байт с проверкой размеров и SHA-256 каждого файла при повторном чтении. Прочитаны все шесть serialized-файлов и границы 6 731 объекта. В 268 TextAsset найдены 98 JSON, 84 PNG, 39 UTF-8 и 47 бинарных payload; среди JSON — конфигурации Materials/Tiles/WorldGen, Sacrifices, WordFilter и локализации. Прочитаны namespace/class/assembly всех 2 884 MonoScript: это ссылки на классы, не C#-тела. `resources.resource` в APK — отдельный файл, его нельзя смешивать с `resources.assets.resS` внутри UnityFS.', '',
        'Все 13 580 констант `Terraria.ID` в 69 классах декодированы: ItemID 6 245, NPCID 764, ProjectileID 1 137, TileID 755, BuffID 401, MessageID 165, PrefixID 97 и остальные каталоги. Всего декодированы 27 659 значений полей, 1 850 значений параметров и 16 879 строковых литералов. Неподдерживаемые initializer blobs и sentinel-значения помечены `unknown`, а не угаданы. Encoding сверено с первичными исходниками [Il2CppDumper BinaryReaderExtensions](https://github.com/Perfare/Il2CppDumper/blob/master/Il2CppDumper/Extensions/BinaryReaderExtensions.cs) и [Il2CppExecutor](https://github.com/Perfare/Il2CppDumper/blob/master/Il2CppDumper/Utils/Il2CppExecutor.cs); 12 известных ID и 23 случая декодера прошли проверки.', '',
        '## Проверки и надёжность', '',
        '- Все 112 ZIP CRC совпали, дубликатов путей нет.',
        '- Все структурированные metadata tables и связи проверены по границам. JSONL/CSV количества совпали. 11 намеренно повреждённых вариантов отвергнуты.',
        '- 65 580 записей карты методов сверены по идентичности; 9 384 определения типов сверены с native type map; field layouts объединены с сохранением специальных отрицательных значений.',
        '- Адреса восстанавливаются через ELF RELATIVE relocations, `Il2CppCodeGenModule.methodPointers` и token RID; generic-реализации — через регистрацию generic methods и method specs.',
        '- Все восемь адресов методов и 15 смещений полей из исторических проверок именно этой сборки совпали. Это историческая дополнительная проверка, не новый запуск.',
        '- Все 123 152 compiler FDE сверены с независимым индексом `.eh_frame_hdr`: ошибок и пересечений нет. Все 93 990 адресов реализаций совпадают точно с началами FDE.',
        '- Перед Ghidra-анализом проверяются нулевая база ELF и совпадение первых 16 байт всех 93 990 методов с исходным файлом. Размеры тел заданы compiler unwind ranges, а не расстоянием до соседнего метода.',
        '- Исходный APK читается без записи. Контрольная сумма фиксирует принадлежность всех выводов одному входу.', '',
        'Сырые field offsets нельзя применять без storage scope: instance/static/thread-static/особый sentinel. Размеры generic-типов могут зависеть от конкретной инстанциации; нулевой или -1 native size не подменяется придуманным размером.', '',
        'Первый диагностический Ghidra-проход исключён из результатов: стандартная база загрузки shared ELF была `0x100000`, тогда как скрипт использовал исходные ELF VA. Побайтное сравнение выявило адресную ошибку. Его файлы сохранены отдельно в `diagnostic-first-pseudocode` только как диагностика и не включены в активный атлас. Исправленный импорт использует `-loader-imagebase 0x0` и обязательную проверку всех entrypoint bytes. Дорогие эвристики GCC Exception Handlers и Non-Returning Functions - Discovered выключены; исходные unwind ranges прочитаны независимым парсером.', '',
        'Последующие проходы с правильной базой не завершили глобальные эвристики Ghidra: switch analysis и анализ констант/регистров. Финальный маршрут использует `-noanalysis`, прямое ограниченное дизассемблирование в границах FDE и четыре отдельных декомпилятора с настраиваемым лимитом (по умолчанию 30 секунд на функцию). Общая автоматическая аннотация типов, параметров и switch/CFG отключена; C-псевдокод может содержать неполные графы переходов и предположения об ABI. Все предупреждения и показатели покрытия сохраняются.', '',
        'Дизассемблирование сначала следует потокам управления внутри compiler ranges, затем линейно декодирует оставшиеся четырёхбайтовые ARM64 slots. Линейная декодируемость не доказывает достижимость или отсутствие данных среди байтов. Пропуски и существующие data units сохраняются отдельно с исходными байтами в `disassembly-gaps.tsv`.', '',
        'Результат `.c` — предположение декомпилятора с именами из метаданных; ABI, сложный control flow, switch, исключения, непрямые вызовы и generic sharing требуют проверки по ARM64-инструкциям. FDE задаёт compiler unwind coverage, не доказательство каждой исходной конструкции. Автоматический успех экспорта не доказывает эквивалентность исходному поведению.', '',
        '## REA Evidence', '',
        'Ниже включены только сохранённые записи, чей subject.digest.sha256 совпадает с исследуемым APK. Совпадение пути без хеша не считается подтверждением; исключённые записи перечислены в `coverage-summary.json`.', '',
    ]
    if disassembly:
        insertion = lines.index('## REA Evidence')
        lines[insertion:insertion] = [
            f'Ограниченное дизассемблирование: завершено `{disassembly.get("finished", False)}`, декодировано {num(disassembly.get("decoded_slots", 0))} slots, линейно добавлено {num(disassembly.get("linear_added_slots", 0))}, пропусков {num(disassembly.get("missing_slots", 0))}.', '',
        ]
    if verification:
        insertion = lines.index('## REA Evidence')
        lines[insertion:insertion] = [
            f'Независимая проверка экспортированных инструкций: `{verification.get("passed", False)}`; {num(verification.get("instruction_records", 0))} записей сверены по байтам с исходным ELF, выравниванию и границам FDE. Семантическая эквивалентность этой проверкой не утверждается.', '',
        ]
    if tail_calls:
        insertion = lines.index('## REA Evidence')
        lines[insertion:insertion] = [
            f'Хвостовые переходы: {num(tail_calls.get("marked_call_return", 0))} безусловных прямых переходов к точному началу другой FDE-функции помечены `CALL_RETURN`. Байты не изменены; это аннотация для декомпилятора, а не восстановленная исходная конструкция. Условные, косвенные и внутренние переходы сохранены. База с этими пометками сохраняется отдельно перед экспортом.', '',
        ]
    if audit:
        insertion = lines.index('## REA Evidence')
        lines[insertion:insertion] = [
            f'Аудит C-файлов: {num(audit["files_checked"])} заголовков сверены с ledger и профилем анализа, проверка `{audit["passed"]}`. В {num(audit["functions_with_decompiler_warnings"])} функциях декомпилятор оставил предупреждения; полный список — `pseudocode/decompiler-warnings.jsonl`. Успешная выдача C и отсутствие предупреждений не доказывают семантическую эквивалентность.', '',
            f'Частые предупреждения: перекрытие глобальных символов — {num(audit["warning_text_counts"].get("Globals starting with '_' overlap smaller symbols at the same address",0))}; трактовка косвенного перехода как вызова — {num(audit["warning_text_counts"].get("Treating indirect jump as call",0))}; нестабилизация распространения типов — {num(audit["warning_text_counts"].get("Type propagation algorithm not settling",0))}. Эти категории требуют осторожного чтения глобальных данных, косвенных переходов и типов; список привязан к каждой функции.', '',
        ]
    if callgraph:
        insertion = lines.index('## REA Evidence')
        lines[insertion:insertion] = [
            f'Статическая карта вызовов содержит {num(callgraph["managed_edges"])} различных связей между сопоставленными реализациями и {num(callgraph["class_edges"])} связей между типами. CSV: `pseudocode/managed-call-edges.csv`, `pseudocode/class-call-edges.csv`; исходные ссылки — `calls.tsv`. Косвенные вызовы и динамическая диспетчеризация не восстановлены; число мест вызова не является частотой исполнения.', '',
        ]
    if terminal_calls:
        insertion = lines.index('## REA Evidence')
        lines[insertion:insertion] = [
            f'Последние вызовы FDE: {num(terminal_calls.get("marked_call_return", 0))} прямых вызовов на последней инструкции диапазона помечены `CALL_RETURN`, если их стандартный fallthrough выходил ровно на конец FDE. Это ограничение модели по compiler ranges; отсутствие возврата у вызываемой функции не доказано. Исходные байты и адреса каждой пометки записаны в `terminal-call-overrides.tsv`.', '',
        ]
    if signatures:
        insertion = lines.index('## REA Evidence')
        lines[insertion:insertion] = [
            f'Применено {num(signatures.get("applied", 0))} консервативных сигнатур из IL2CPP-метаданных: примитивы, ссылки, указатели, массивы и byref. Для instance-методов добавлен `__this`, последним — скрытый `MethodInfo*`. Неизвестные структуры, enum и generic-типы исключены; их ABI не выводился. Остальные сигнатуры и локальные типы в псевдокоде приблизительны. Полный перечень и исключения — `native/signatures.tsv`, `native/signatures-summary.json`.', '',
        ]
    if jni_bound:
        libraries = jni['libraries']
        exports = sum(row['export_count'] for row in libraries)
        imports = sum(row['import_count'] for row in libraries)
        java_exports = sum(row['java_export_count'] for row in libraries)
        onload = sum(symbol['name'] == 'JNI_OnLoad' for row in libraries for symbol in row['onload_exports'])
        candidates = sum(row['plaintext_jni_candidate_count'] for row in libraries)
        activity = jni['candidate_matches_by_declaring_class'].get('com/unity3d/player/UnityPlayerActivity', 0)
        jni_lines = ['', '## Статическая JNI/ELF-карта', '',
                     f'По SHA-256 APK привязан каталог всех {jni["native_library_count"]} native-библиотек: {num(exports)} экспортируемых и {num(imports)} импортируемых dynamic symbols, {java_exports} определённых `Java_*` exports, {onload} exports `JNI_OnLoad`. Это символы разных типов, а не число восстановленных функций.', '',
                     f'Найдены {candidates} plaintext структурных кандидата `JNINativeMethod`, представляющих {jni["unique_candidate_name_signature_pairs"]} уникальных пар имени/сигнатуры. Совпадения name/signature затрагивают {jni["dex_native_declarations_with_candidate_name_signature_match"]} из {jni["dex_native_declaration_count"]} DEX native-объявлений; для {jni["dex_native_declarations_without_export_or_candidate"]} объявлений статического совпадения нет. Для всех {activity} native-объявлений `UnityPlayerActivity` имеются кандидаты в `libpdaprotect.so`.', '',
                     'Эти совпадения — кандидаты. Реальные вызовы `RegisterNatives`, аргументы класса, длины зарегистрированных таблиц и успешные runtime-привязки не установлены. Совпадающее имя/сигнатура в нескольких DEX-классах не доказывает принадлежность функции конкретному классу.', '']
        note = notes_root/'terraria-jni-20261012.md'
        if note.is_file():
            jni_lines += [filelink('Подробности JNI и границы поиска', note), '']
        for name, present in jni_presence.items():
            if present:
                jni_lines.append('- '+filelink(name, lab/'android-native'/name))
        if not any(jni_presence.values()):
            jni_lines.append('Приватные JNI-каталоги в текущей папке Lab отсутствуют; связанные числа взяты из сохранённого отчёта с совпадающим SHA-256 APK.')
        jni_lines.append('')
        insertion = lines.index('## Проверки и надёжность')
        lines[insertion:insertion] = jni_lines
    else:
        insertion = lines.index('## Проверки и надёжность')
        lines[insertion:insertion] = ['Статический JNI-каталог с подтверждённым SHA-256 текущего APK отсутствует; его количественные результаты здесь не утверждаются.', '']
    for path, operation, evidence_id in evidence:
        lines.append(f'- `{operation}`: `{evidence_id}` — {filelink(path.name, path)}.')
    switch_log = ROOT/'reports/terraria-ghidra-switch-analysis-diagnostic-20261012.log'
    if switch_log.is_file():
        lines += ['', filelink('Диагностика остановленного switch-analysis прохода', switch_log), '']
    if (ROOT/'reports/terraria-rea-inventory-final-20261012.json').is_file():
        lines += ['', 'Финальный REA inventory сохранён, сессия закрыта. Snapshot не поддерживался выбранным provider profile; это ограничение провайдера, а не признак повреждения APK.', '']
    lines += ['', 'Подключённый REA первоначально не имел JADX JAR. Официальный headless JAR 0.7.1 предоставлен локально; Android-операции выполнены отдельным REA CLI с временными переменными окружения, без изменения настроек Codex. Windows-провайдер Ghidra в REA 6.4.0 допускает только x86/x64 PE; ARM64 ELF здесь анализируется непосредственно официальным Ghidra. Его результаты не объявляются REA Evidence.', '',
        '## Файлы и воспроизведение', '',
        '- '+filelink('Поиск и навигация по коду', lab/'index.html')+'.',
        '- '+filelink('Полные metadata JSONL/CSV', lab/'metadata/README.txt')+'.',
        '- '+filelink('Обычные адреса', lab/'native/method-addresses.csv')+'; '+filelink('generic-адреса', lab/'native/generic-method-addresses.csv')+'.',
        '- '+filelink('Журнал покрытия нативного экспорта', lab/'pseudocode/coverage.jsonl')+'.',
        ('- '+filelink('AndroidManifest.xml', jadx_manifest)+'; Java-код в `jadx/sources/`.' if jadx_manifest.is_file() else '- AndroidManifest.xml JADX в текущей папке Lab отсутствует.'),
        '- '+filelink('Подробности Android/UnityFS', notes_root/'terraria-android-shell-20261012.md')+'.',
        '- '+filelink('Разбор алгоритмов Player, NPC, Item, WorldGen', notes_root/'terraria-core-code-20261012.md')+'.',
        '- '+filelink('Классификация 70 объявлений без сопоставленного entrypoint', notes_root/'terraria-implementation-gaps-20261012.md')+'.',
        '- Собственные воспроизводимые инструменты: `tools/terraria_android_catalog.py`, `tools/terraria_native_map.py`, `tools/terraria_metadata_catalog.py`, `tools/TerrariaSeedMethods.java`, `tools/TerrariaExportMethods.java`, `tools/build_terraria_explorer.py`, `tools/build_terraria_report.py`.', '',
        '`tools/run_terraria_reverse.ps1` повторяет этапы локальных парсеров и Ghidra. JADX, SDK dexdump и REA выполнялись отдельными командами в этой сессии и не запускаются этим runner автоматически. Сохранённые REA-записи используются повторно только после проверки SHA-256; файлы JADX проверяются на наличие, без заявления о свежем повторном выполнении.', '',
        'Игровые файлы, извлечённые ресурсы и реконструированный код находятся вне Git-репозитория в локальной приватной папке. Публикация или отправка на внешние сервисы не выполнялась.'+(' `C:/Temp` может очищаться системой; каталог следует сохранить в постоянное место, если он нужен надолго.' if lab.resolve().is_relative_to(Path('C:/Temp').resolve()) else ''), '',
        'Дистрибутивы инструментов и SHA-256: '+filelink('tool provenance', lab/'tools/tool-provenance.json' if (lab/'tools/tool-provenance.json').is_file() else ROOT/'.tools/terraria-re/tools.json')+'. Первичные источники: [Ghidra 12.1.4](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build), [JADX 1.5.6](https://github.com/skylot/jadx/releases/tag/v1.5.6), [JADX headless MCP 0.7.1](https://github.com/1013503897/jadx-headless-mcp/releases/tag/v0.7.1).', '',
        '## Незакрытые вопросы', '',
        '1. Исходный C# проект и воспроизводимая сборка из него не восстановлены.',
        '2. Для 70 concrete declarations не найден прямой/generic entrypoint; абстрактные объявления собственного тела не имеют.',
        '3. Ошибки декомпиляции/экспорта, не начатые адреса и ошибки целостности отражены в coverage-summary.json; их нельзя считать восстановленными.',
        '4. Статические JNI-кандидаты не устанавливают фактические RegisterNatives/class bindings; семантика native Android-тел и весь внутренний код Unity/сторонних `.so` полностью не восстановлены.',
        '5. Без официального APK той же версии точная атрибуция изменений стороннего патчера остаётся неизвестной.',
        '6. Runtime-эквивалентность реконструкции и совместимость произвольных ПК-модов этим разбором не проверялись.', '',
    ]
    unresolved = [r for r in coverage if r['status'] != 'decompiled']
    if unresolved:
        gap_lines = ['## Функции без полученного C-тела', '',
                     'Эти функции учтены в общем проходе, но их тело не считается восстановленным. Инструкции и причины сохранены в общем журнале. При наличии `max_instructions` и `timeout_seconds` использованные лимиты указаны в записи функции.', '',
                     '| Метод | ELF VA | Байт в FDE | Причина |', '|---|---|---:|---|']
        for r in unresolved:
            message = ' '.join((r.get('message') or r['status']).split()).replace('|','&#124;')
            name = r['method'].replace('|','&#124;')
            gap_lines.append(f'| `{name}` | `{r["address"]}` | {r.get("compiler_size", "?")} | {message} |')
        gap_lines.append('')
        insertion = lines.index('## Android-оболочка и ресурсы')
        lines[insertion:insertion] = gap_lines
    text = '\n'.join(lines)
    (reports/'REPORT.ru.md').write_text(text, encoding='utf-8')
    (lab/'REPORT.ru.md').write_text(text, encoding='utf-8')
    print(json.dumps({'status': summary['status'], 'native_export': summary['native_export'],
                      'integrity_error_count': len(integrity['integrity_errors']), 'report': str(reports/'REPORT.ru.md')}, ensure_ascii=False, indent=2))

if __name__ == '__main__':
    main()
