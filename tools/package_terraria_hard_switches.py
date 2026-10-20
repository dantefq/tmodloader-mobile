"""Deliver a source-bound addendum without altering phase2 artifacts/manifest."""
import argparse, hashlib, json, pathlib, shutil


def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);ap.add_argument('--delivery',type=pathlib.Path,required=True);a=ap.parse_args()
    source=a.lab/'hard-switches-v1';root=a.delivery.resolve();out=root/'hard-switches-v1';repo=pathlib.Path(__file__).resolve().parents[1]
    if out.is_relative_to(repo) or source.resolve()==out:raise ValueError('Private separate destination required')
    old_manifest=root/'artifact-manifest.json';old_hash=sha(old_manifest)
    if old_hash!='94cae77db018fee38c09e3b69f203b5fc0fbfd55b40c4aabbb935e30c61b391a':raise ValueError('Unexpected baseline delivery manifest')
    doc=json.loads((source/'switches.json').read_text(encoding='utf8'));audit=json.loads((source/'independent-audit.json').read_text(encoding='utf8'))
    if audit.get('integrity_passed') is not True:raise ValueError('Independent audit did not pass')
    if sha(repo/'tools/terraria_hard_switches.py')!=doc['producer_sha256']:raise ValueError('Producer changed since generation')
    if audit.get('producer_output_sha256')!=sha(source/'switches.json'):raise ValueError('Audit does not bind current switches.json')
    if audit.get('audit_tool_sha256')!=sha(repo/'tools/audit_terraria_hard_switches_independent.py'):raise ValueError('Auditor changed since audit')
    for name,digest in audit['call_label_source_hashes'].items():
        if pathlib.Path(name).name!=name or sha(a.lab/'native'/name)!=digest:raise ValueError('Call metadata changed')
    out.mkdir(parents=True,exist_ok=True)
    for p in source.iterdir():
        if p.is_file():shutil.copy2(p,out/p.name)
    tools=out/'tools';tools.mkdir(exist_ok=True)
    for name in ('terraria_hard_switches.py','terraria_flow_islands.py','audit_terraria_hard_switches_independent.py','package_terraria_hard_switches.py'):
        shutil.copy2(repo/'tools'/name,tools/name)
    snippets=[p for m in doc['methods'] for t in m['switch_candidates'] for p in t['destination_previews']]
    calls=[c for p in snippets for c in p['first_direct_calls']]
    report=['# Продолжение разбора: таблицы переходов','', 'Дата: 14 октября 2026.','',
            f"В оставшихся 18 крупных методах проверен 121 ARM64 BR. Для 102 построены условные карты таблиц: 1 712 записей. Ещё 19 BR этим проходом не разрешены.",
            f"Для целей переходов сохранены {len(snippets)} фрагментов до первого вызова или управляющего перехода; в {len(calls)} фрагментах найден первый прямой вызов, его имя сопоставлено с сохранённым metadata-каталогом.",'',
            'Независимый анализ повторно прочитал байты таблиц и инструкций из исходного ELF и вычислил адреса назначения. Условия анализа перечислены в каждом результате: вся записанная последовательность исполнена без альтернативного входа, старшие 32 бита индексного регистра X нулевые, таблица не изменена. Достижимость и доминирование guard не доказаны.','',
            'Это дополнение к предыдущему результату. Число методов без полного C осталось 18; новых C-представлений этот проход не создавал. Пять методов вообще не содержат BR, поэтому поиск таблиц не решает их проблему. Исходный APK и прежние результаты не менялись.','',
            '[Сводка по методам](README.ru.md) · [Projectile.AI](0x1423370.md) · [NPC.HitEffect](0x11b1bf4.md) · [Полные доказательства](switches.json) · [Независимая проверка](independent-audit.json).','',
            'Манифест этого дополнения находится в addendum-manifest.json. Старый artifact-manifest.json продолжает описывать прежний снимок и не включает новое дополнение.']
    (out/'REPORT.ru.md').write_text('\n'.join(report)+'\n',encoding='utf8')
    rows=[{'path':p.relative_to(out).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(out.rglob('*')) if p.is_file() and p.name!='addendum-manifest.json']
    result={'profile':'hard18-switch-addendum-v1','original_elf_sha256':doc['elf_sha256'],'prior_delivery_manifest_sha256':old_hash,
            'summary':doc['summary'],'files':rows,'file_count':len(rows),'scope':'Separate conditional static-analysis addendum. Hash identity does not prove semantics.'}
    (out/'addendum-manifest.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    if sha(old_manifest)!=old_hash:raise ValueError('Prior delivery manifest changed')
    for row in rows:
        if sha(out/row['path'])!=row['sha256']:raise ValueError('Delivered file mismatch')
    print(json.dumps({'out':str(out),'files':len(rows),'manifest_sha256':sha(out/'addendum-manifest.json'),'previous_manifest_unchanged':True,'previews':len(snippets),'first_calls':len(calls)},ensure_ascii=False))


if __name__=='__main__':main()
