"""Render audited initializer local call facts without promoting them to recipes."""
import argparse,collections,csv,hashlib,json,pathlib
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',required=True,type=pathlib.Path);args=ap.parse_args();out=args.lab/'initializer-call-constants-v1'
    d=json.loads((out/'calls.json').read_text());audit=json.loads((out/'independent-audit.json').read_text())
    assert audit['integrity_passed'] and audit['calls_sha256']==sha(out/'calls.json')
    columns=['function_start','call_site','direct_target','target_signatures',*[f'x{i}_unsigned64' for i in range(8)],'ItemID_numerical_name_candidates','window_start']
    with (out/'calls.csv').open('w',encoding='utf-8-sig',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=columns);writer.writeheader()
        for r in d['results']:
            row={k:r[k] for k in ('function_start','call_site','direct_target','window_start')};row['target_signatures']=' | '.join(a['signature'] for a in r['target_aliases'])
            row.update({k+'_unsigned64':v['unsigned64'] for k,v in r['register_constants'].items()});row['ItemID_numerical_name_candidates']=' | '.join(r.get('item_id_constant_name_candidates',[]));writer.writerow(row)
    counts=collections.Counter(r['target_aliases'][0]['signature'] for r in d['results']);itemrows=[r for r in d['results'] if 'item_id_constant_name_candidates' in r]
    lines=['# Локальные константы перед вызовами в пяти крупных инициализаторах','',
           f"Исходный ARM64 ELF: SHA-256 `{d['elf_sha256']}`. Проверка выполнена по неизменённым байтам, без изменения базовой базы Ghidra.",'',
           f"Найдено **{len(d['results']):,} мест вызова** с **{d['constant_register_facts']:,} константами регистров X0–X7**. Это условные факты непосредственно перед BL, если весь показанный фрагмент исполняется последовательно. Читаемый полный C для этих методов не восстановлен.",'',
           '| Метод | Начало | Все BL | Именованные BL | BL с локальными константами |','|---|---|---:|---:|---:|']
    for r in d['functions']:
        lines.append(f"| {r['method_aliases'][0]['signature']} | `{r['address']}` | {r['direct_BL_sites']} | {r['named_direct_BL_sites']} | {r['sites_with_constant_facts']} |")
    lines+=['','## Практические наблюдения','',
            f"В `Recipe.SetupRecipes` отмечено **{len(itemrows)}** вызовов именованного `Item.SetDefaults` с локальной константой W1, содержащих **{len({r['register_constants']['x1']['signed_low32'] for r in itemrows})}** различных числовых значений. Имена ItemID сопоставлены с константами извлечённых метаданных; принадлежность предмета выходу рецепта или ингредиентам здесь не установлена.",'',
            '| Адрес BL | W1 | Числовое совпадение ItemID |','|---|---:|---|']
    for r in itemrows[:10]:lines.append(f"| `{r['call_site']}` | {r['register_constants']['x1']['signed_low32']} | {', '.join(r['item_id_constant_name_candidates'])} |")
    lines+=['','Частые именованные цели среди сохранённых мест вызова:','']
    for name,count in counts.most_common(12):lines.append(f'- `{name}`: {count}.')
    lines+=['','## Проверка и ограничения','',
            f"Независимый декодер ARM64 проверил все сохранённые выражения регистров, границы локальных ветвей и имена целей по метаданным. Проверено {audit['verified_unique_proof_instruction_bytes']:,} различных байт фрагментов; полные выбранные FDE занимают {audit['verified_full_function_source_bytes']:,} байт. Проверка хешей не доказывает достижимость кода или эквивалентность всей функции.",'',
            'Каждый фрагмент содержит максимум 16 инструкций перед BL. Загрузка, запись памяти, вызов, переход, изменение флагов или неподдерживаемая инструкция обрывает восстановление констант. Значения не переносятся через вызовы. Неизвестные X0–X7 указаны явно; часть известных регистров может относиться к скрытым аргументам IL2CPP.',
            '', 'Предполагается последовательное исполнение всего фрагмента; возможный неизвестный косвенный вход в его середину не проверен. Нет результатов запуска этих сценариев, полной таблицы рецептов, связанных объектов, восстановленной ABI для всех аргументов или полного исходного кода.',
            '', 'Файлы: [машинные доказательства](calls.json), [таблица поиска](calls.csv), [независимая проверка](independent-audit.json).','']
    (out/'REPORT.ru.md').write_text('\n'.join(lines),encoding='utf8')
    provenance={'reporter_sha256':sha(pathlib.Path(__file__)),'calls_sha256':sha(out/'calls.json'),'audit_sha256':sha(out/'independent-audit.json'),'report_sha256':sha(out/'REPORT.ru.md'),'csv_sha256':sha(out/'calls.csv')}
    (out/'report-provenance.json').write_text(json.dumps(provenance,indent=2)+'\n');print(json.dumps(provenance))
if __name__=='__main__':main()
