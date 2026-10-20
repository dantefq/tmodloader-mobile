"""Report new evidence without relabelling the immutable managed-v3 corpus."""
import argparse,json
from collections import Counter
from pathlib import Path
from datetime import datetime,timezone
p=argparse.ArgumentParser();p.add_argument('--lab',type=Path,default=Path('C:/Temp/terraria-re-20261012'));a=p.parse_args();lab=a.lab.resolve()
def load(relative):
    path=lab/relative
    return json.loads(path.read_text(encoding='utf-8-sig')) if path.exists() else None
classification=load('native/unmapped-fde-classification-summary.json')
native=load('native-ranges-pseudocode/progress.json')
native_rows=[json.loads(line) for line in (lab/'native-ranges-pseudocode/coverage.jsonl').read_text(encoding='utf-8').splitlines()]
assert len({r['address'] for r in native_rows})==len(native_rows)
native_counts=Counter(r['status'] for r in native_rows)
audit=load('native/native-ranges-export-audit.json')
islands=load('native/flow-islands-summary.json')
hard_islands=load('native/flow-islands-hard20-review.json')
abi=load('abi-control-probe-v4/attempt-1791904902576/verification.json')
retry=load('pseudocode-stack32-retry/retry-progress.json')
typed=load('pseudocode-v4-hard/retry-progress.json')
typed_audit=load('pseudocode-v4-hard/audit.json')
ir=load('hard-functions-ir/progress.json')
ir_audit=load('hard-functions-ir/audit.json')
raw_ir=load('hard-functions-raw-ir/progress.json')
raw_ir_audit=load('hard-functions-raw-ir/audit.json')
preflight=load('runtime-preflight.json')
bridge=load('android-native/jni-remaining-20261013/jnibridge-provenance.json')
jni_continuation=load('android-native/jni-remaining-20261013/continuation-summary.json')
stamp=datetime.now(timezone.utc).isoformat()
scope={'generated_utc':stamp,'classification':classification,'native_export_progress':native,'native_journal_counts':dict(native_counts),
       'native_audit':audit,'flow_islands':islands,'hard20_islands':hard_islands,
       'abi_controls':abi,'stack_retry':retry,'typed_retry':typed,'typed_candidate_audit':typed_audit,'hard_ir':ir,'hard_ir_audit':ir_audit,'hard_raw_ir':raw_ir,'hard_raw_ir_audit':raw_ir_audit,'runtime_preflight':preflight,
       'jni_bridge_supplement_available':bridge is not None,'jni_continuation':jni_continuation,
       'original_Csharp_project_recovered':False,'whole_game_behavior_verified':False}
(lab/'phase2-evidence-summary.json').write_text(json.dumps(scope,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
lines=['# Дополнительный разбор Terraria APK',f'Снимок доказательств: {stamp}.',
       'Исходный APK SHA-256: `1f8e2ba7ddabaee961a1b2552d44bc0c281c9b5122480642b018779bcbf2fe8e`.',
       'Этот этап расширяет первоначальный корпус 93 970 успешных C-представлений из 93 990 managed-адресов. '
       'Псевдокод Ghidra и восстановленные типы не являются оригинальным C#-проектом.']
if audit and audit.get('passed') and typed_audit and typed_audit.get('passed'):
    available=93970+native_counts['decompiled']+typed_audit['decompiled_candidates']
    lines+=[f'**Доступен C-псевдокод для {available:,} уникальных адресов из 123 152 FDE-диапазонов libil2cpp.so.** '
            f"Из них {typed_audit['decompiled_candidates']} — дополнительные кандидаты ABI v4; "
            f"без C-представления остаются {123152-available}. Это игровые методы и нативные служебные функции, не только игровой код."]
if classification:
    lines+=['## Дополнительные нативные диапазоны',
       f"Из 29 162 дополнительных FDE-диапазонов классифицированы {classification['classified_count']:,}; "
       f"роль {classification['unknown_count']:,} остаётся неизвестной.",
       '[Структурные доказательства](native/unmapped-fde-classification.json).']
if native:
    lines+=[f"Сохранённый журнал содержит {native_counts.get('decompiled',0):,} успешных C-представлений; ошибок: {len(native_rows)-native_counts.get('decompiled',0)}; "
            f"состояние сборки: `{native['phase']}`. Независимый аудит: "+('пройден.' if audit and audit.get('passed') else 'ещё не завершён.')]
if (lab/'native-ranges.html').exists():lines+=['[Поиск по дополнительному нативному коду](native-ranges.html).']
if islands:
    lines+=['## Код за границами unwind-диапазонов',
        f"Найдены {islands['structurally_verified_out_and_back_associations']} проверенных прямых выходов в отдельные участки и возвратов; "
        f"{islands['unique_extra_instructions']} дополнительных инструкций ({islands['unique_extra_bytes']} байт), "
        f"связанных с {islands['extended_fde_candidates']} основными диапазонами.",
        'Для 12 из 20 сложных методов это 34 пути, 68 инструкций и 272 байта. '
        'Декомпилятор может следовать за пределы listing body; первоначальная проверка байтов FDE не доказывает полноту управляющего графа. '
        'Косвенные переходы и 722 выхода с неподдержанным этим консервативным декодером продолжением остаются открытыми.',
        '[Доказательства](native/flow-islands.json).']
if abi:
    lines+=['## Типы и ARM64 ABI',
        'В отдельной копии проекта применены 55 524 сигнатуры, 12 плоских структур и 1 021 enum с проверенным базовым типом. '
        'На десяти контрольных методах получен C-псевдокод, проверены 728 исходных машинных байт и примеры register storage для Vector2 и Rectangle. '
        'Это проверка примеров, а не доказательство корректности всех сигнатур.',
        '[Контроль ABI](abi-control-probe-v4/attempt-1791904902576/verification.json).']
for caption,state,path in [('Исходная модель с увеличенным стеком',retry,'pseudocode-stack32-retry'),('Модель типов v4',typed,'pseudocode-v4-hard')]:
    if state:lines+=[f"{caption}: попыток {state['attempted']}/{state['retry_total']}, "
                    f"успешных C {state['decompiled']}, ошибок {state['failed']}, завершено: {state['finished']}. "
                    f'[Журнал]({path}/retry-results.jsonl).']
if typed_audit and typed_audit.get('passed'):
    for item in typed_audit['files']:
        lines+=[f"Дополнительный C-кандидат `{item['address']}`: [открыть](pseudocode-v4-hard/{item['file']}); "
                f"размер {item['bytes']:,} байт, предупреждений {item['warnings']}."]
if (lab/'native/ai001-static-branch-evidence.json').is_file():
    lines+=['Для AI_001 отдельно проверены ветви BeeArrow, BoneShard, PurpleLaser и GreenLaser: имена ID и поля сверены с metadata, '
            'условия, float32-константы и вызовы — с ARM64. [Доказательства ветвей](native/ai001-static-branch-evidence.json).']
lines+=['Подтверждён сбой Windows-декомпилятора с кодом STATUS_STACK_OVERFLOW. В отдельной копии движка резерв стека увеличен с 1 до 32 MiB; '
        'все PE sections, включая машинный код, совпадают с оригиналом. Это позволило получить промежуточное P-code представление SetupRecipes; '
        'получение C проверяется отдельно. [Проверка копии движка](ghidra-stack32-provenance.json).']
if ir:
    lines+=['## Промежуточное представление сложных функций',
            f"Полное IR получено для {ir['complete_ir']} из {ir['targets']} целевых методов; проход завершён: {ir['finished']}. "
            'Для успешных результатов сохранены все операции firstpass, basic blocks, рёбра и адреса исходных инструкций без ограничения первыми 10 000 операциями. '
            'Это диагностическое промежуточное представление Ghidra, не C-код и не доказательство исходной семантики. '
            'Независимый аудит: '+('пройден.' if ir_audit and ir_audit.get('integrity_passed') else 'ещё не завершён.'),
            '[Журнал IR](hard-functions-ir/results.jsonl).']
if raw_ir:
    lines+=[f"Для {raw_ir['complete']} из 20 сложных методов дополнительно сохранено полное низкоуровневое SLEIGH/P-code представление "
            'каждой инструкции внутри FDE и проверенных внешних участков. Этот проход не использует высокоуровневый декомпилятор. '
            'Исходные ветвления сохранены без применения аннотаций CALL_RETURN; прежние flow overrides записаны отдельно. '
            'Это не SSA, не C-код и не доказательство полного семантического управляющего графа. '
            'Независимый аудит: '+('пройден.' if raw_ir_audit and raw_ir_audit.get('integrity_passed') else 'ещё не завершён.'),
            '[Низкоуровневый IR](hard-functions-raw-ir/results.jsonl).']
lines+=['## JNI']
if not jni_continuation:
    lines+=['Для 150 из 161 DEX native-деклараций прослежены class/table/function arguments и происхождение JNIEnv. Остальные связи проверяются отдельно.']
if bridge:lines+=['Дополнительный анализ JNIBridge.invoke сохранён отдельно; его условные статические связи не означают наблюдённую runtime-регистрацию. '
                 '[Доказательство](android-native/jni-remaining-20261013/jnibridge-provenance.json).']
if jni_continuation:
    assert jni_continuation['combined_distinct_dex_descriptors']==160
    lines+=['**Статически связаны 160 из 161 native-деклараций.** Для ReflectionHelper прослежена цепочка JavaVM/GetEnv/AttachCurrentThread. '
            'Статически воспроизведены преобразования строк девяти external_wrapper-регистраций и цепочка JNIBridge. '
            'Проверены 1 877 исходных инструкций; повторный прогон дал идентичные трассы, неподдержанных операций в этих трассах нет. '
            'Предпосылки успешных JNI-вызовов и начального состояния guards явно сохранены. '
            'Остался NativeOnCompleteListener.nativeOnComplete: конкретная локальная native-функция не установлена. '
            'Проверка всех 8 256 DEX code methods нашла вызов из onComplete, но не прямых DEX-вызовов createAndAddCallback. '
            'Это не исключает reflection/native/generated callers и не доказывает недостижимость. '
            '[Сводная таблица](android-native/jni-remaining-20261013/combined-static-bindings.json).']
if (lab/'runtime-evidence/initial/screen.png').exists():
    lines+=['## Проверка запуска',
       'APK установлен в отдельный чистый Android 14 AVD. SHA установленного base.apk совпал с исходным. '
       'ARM64-код исполнялся через libndk_translation.so на x86_64, авиарежим включён, Wi-Fi/data отключены, маршрутов перед запуском не было. '
       'Activity запустилась, процесс работал и отрисовал главное меню; после сбора доказательств приложение и временный эмулятор остановлены.',
       'На экране: **v1.4.5.8.1 Build 1720**; Android package versionName: **1.4.5.8.6**. '
       'Это наблюдаемое различие; причина без эталонного официального APK не установлена.',
       'В app-logcat видны JNI_OnLoad, LoadContent/Initialize и DrawSplash/DoDraw. '
       'В захваченном crash buffer нет записей; присутствуют предупреждения загрузки ресурсов и EGL, поэтому отсутствие любых ошибок не заявляется. '
       'Игровые механики, сеть, сохранение и корректность псевдокода этим запуском не проверены.',
       '![Главное меню](runtime-evidence/initial/screen.png)',
       '[Снимок и хеши](runtime-evidence/initial/capture.json), [лог запуска](runtime-start.txt), '
       '[итоговый app-logcat](runtime-final-app-logcat.txt).']
lines+=['## Что остаётся',
       'Получение читаемого C для оставшихся больших методов, уточнение типов и косвенного control flow, '
       'роль 8 140 неназванных диапазонов, остаточные JNI-связи и проверка конкретных игровых сценариев. '
       'Исходные комментарии, имена локальных переменных и точный исходный C# из IL2CPP однозначно не восстанавливаются.']
(lab/'PHASE2.ru.md').write_text('\n\n'.join(lines)+'\n',encoding='utf-8')
print(json.dumps({'report':str(lab/'PHASE2.ru.md'),'native_decompiled':native_counts.get('decompiled',0),'native_audit_passed':bool(audit and audit.get('passed'))}))
