"""Render the completed isolated switch-hint experiment without merging baseline counts."""
import argparse
import json
from pathlib import Path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('lab', type=Path)
    args = parser.parse_args()
    out = args.lab / 'pseudocode-switch-hint-batch'
    audit = json.loads((out / 'audit.json').read_text())
    assert audit['integrity_passed']
    probe = json.loads((args.lab / 'pseudocode-switch-hint-probe/result.json').read_text())
    assert json.loads((args.lab / 'pseudocode-switch-hint-probe/audit.json').read_text())['integrity_passed']
    rows = [json.loads(line) for line in (out / 'results.jsonl').read_text().splitlines()]
    lines = ['# Условные карты переходов: новые попытки C-декомпиляции', '',
             f"Для Player.Update `0x12f63e8` получен [условный C-кандидат](../pseudocode-switch-hint-probe/Player_Update_conditional_candidate.c) за {probe['elapsed_seconds']:.2f} с; три явных override содержат 38 записей. Файл — 439 117 байт. Остаются предупреждения о неустановившемся распространении типов и перекрывающихся глобальных символах.", '',
             f"Отдельная серия однократных попыток остальных 12 методов с непустыми картами завершена: {audit['conditional_c_candidates']} дополнительных C-кандидатов. Применены {audit['verified_switches']} override, {audit['verified_entries']} записей; {audit['verified_function_bytes']:,} байт диапазонов независимо сопоставлены с исходным ELF.", '',
             'Уже успешный Player.Update и пять методов без таблиц BR не повторялись. Два декомпилятора работали с одной неизменяемой после подготовки моделью; лимит каждой попытки — 180 с, 250 000 инструкций, 256 MB полезной нагрузки. База открыта readOnly/noanalysis. Все override находились в отдельной транзакции в памяти; после серии транзакция отменена. Канонические базы и журналы v3/v4 не переписывались.', '',
             '| Метод | Адрес | Результат | Время, с |', '|---|---|---|---:|']
    for row in rows:
        status = f"[C-кандидат]({row['file']})" if row['status'] == 'decompiled_conditional_candidate' else ('таймаут' if row.get('timed_out') else row['status'])
        lines.append(f"| {row['method']} | `{row['address']}` | {status} | {row['elapsed_seconds']:.2f} |")
    lines += ['',
              'Проверка целостности связывает фактически выбранный движок stack32, исходный ELF, Java-производитель, его общий helper, карты переходов, байты функций и таблиц, арифметику целей и C-файлы по SHA-256. Независимый аудит не наблюдает внутреннее хранилище JumpTable Ghidra отдельно от Java-скрипта.', '',
              'Предпосылки каждой карты: вся записанная последовательность исполняется без альтернативного входа; таблица неизменна; старшие 32 бита индексного регистра нулевые. Глобальное доминирование проверок, достижимость ветвей и семантическая эквивалентность не доказаны. ABI v4 также остаётся моделью-кандидатом. Декомпилятор может следовать закодированным переходам за пределы FDE. Это восстановленный псевдокод, не оригинальный C#; игровая проверка этих методов не проводилась.', '',
              'Артефакты серии: [scope.json](scope.json), [results.jsonl](results.jsonl), [progress.json](progress.json), [audit.json](audit.json). Единственная попытка Player.Update и её отдельный аудит находятся в соседней папке `pseudocode-switch-hint-probe`.', '',
              f"С учётом {1 + audit['conditional_c_candidates']} новых условных кандидатов из прежних 18 методов остаются {17 - audit['conditional_c_candidates']} без возвращённого полного C. Канонические исторические счётчики не изменены; условные кандидаты не являются подтверждённым восстановлением семантики."]
    (out / 'REPORT.ru.md').write_text('\n'.join(lines)+'\n', encoding='utf-8')
    print(out / 'REPORT.ru.md')

if __name__ == '__main__':
    main()
