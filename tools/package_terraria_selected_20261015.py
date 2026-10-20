"""Private snapshot of the October 15 selected hard-method attempts."""
import hashlib,json,pathlib,shutil
LAB=pathlib.Path('C:/Temp/terraria-re-20261012')
ROOT=pathlib.Path('C:/Private/Documents/ChatGPT/Terraria-Reverse-20261012')
REPO=pathlib.Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    prior=ROOT/'artifact-manifest.json';assert sha(prior)=='94cae77db018fee38c09e3b69f203b5fc0fbfd55b40c4aabbb935e30c61b391a'
    attempts=[];candidates=[];folders=[]
    for name in ('pseudocode-displaydoll-long-20261015','pseudocode-processdata-long-20261015'):
        source=LAB/name
        if not (source/'result.json').exists():continue
        r=json.loads((source/'result.json').read_text());a=json.loads((source/'audit.json').read_text())
        assert a['integrity_passed'] and a['result_sha256']==sha(source/'result.json')
        assert a['auditor_sha256']==sha(REPO/'tools/audit_terraria_hard_selected_probe.py')
        assert r['script_sha256']==sha(REPO/'tools/TerrariaHardSelectedProbe.java')
        assert r['ephemeral_transaction_rolled_back'] is True and r['saved_project_modified'] is False
        attempts.append({'method':r['method'],'address':r['address'],'status':r['status'],'elapsed_seconds':r['elapsed_seconds'],'switches':r['applied_hint_count'],'entries':r['applied_entry_count']});folders.append(name)
        if r['status']=='decompiled_conditional_candidate':
            c=source/r['file'];assert c.parent==source and sha(c)==r['c_sha256']
            candidates.append({'method':r['method'],'address':r['address'],'file':'../'+name+'/'+r['file'],'bytes':c.stat().st_size,'sha256':sha(c),'warnings':c.read_text().count('WARNING:')})
    assert attempts
    cfg=LAB/'npc-fighters-cfg-v2';cfg_doc=json.loads((cfg/'cfg.json').read_text())
    assert cfg_doc['producer_sha256']==sha(REPO/'tools/terraria_npc_fighters_cfg_v2.py')
    cfg_audit=json.loads((cfg/'audit.json').read_text())
    assert cfg_audit['passed'] and cfg_audit['cfg_sha256']==sha(cfg/'cfg.json')
    assert cfg_audit['auditor_sha256']==sha(REPO/'tools/audit_terraria_npc_fighters_cfg_v2.py')
    folders.append(cfg.name)
    catalog=LAB/'selected-call-catalog-20261015'
    catalog_doc=json.loads((catalog/'calls.json').read_text())
    assert catalog_doc['producer_sha256']==sha(REPO/'tools/terraria_selected_call_catalog_20261015.py') and catalog_doc['raw_BL_vs_capstone_passed'] is True
    folders.append(catalog.name)
    previous=json.loads((ROOT/'ai-continuation-20261014/summary.json').read_text());assert previous['previous_hard_methods_without_C']==14
    old_addresses={x['address'] for x in previous['conditional_candidates']}
    assert len({r['address'] for r in candidates})==len(candidates) and not old_addresses&{r['address'] for r in candidates}
    out=LAB/'selected-continuation-20261015';out.mkdir(exist_ok=True)
    summary={'date':'2026-10-15','conditional_candidates':candidates,'attempts':attempts,'remaining_hard_methods_without_C':14-len(candidates),'unique_C_addresses_including_conditional_candidates':123138+len(candidates),'original_Csharp_recovered':False,'runtime_equivalence_verified':False,'previous_snapshot_sha256':sha(ROOT/'ai-continuation-20261014/summary.json')}
    summary['corrected_NPC_CFG']={'version':'v2','cfg_sha256':sha(cfg/'cfg.json'),'raw_slice_audit_sha256':sha(cfg/'audit.json'),'scope':'Three upper32 backward slices; not an independent reconstruction of all CFG edges.'}
    summary['direct_call_catalog_sha256']=sha(catalog/'calls.json')
    maps=json.loads((LAB/'hard-switches-v2/switches.json').read_text())
    recovered={'0x12f63e8','0x12e2cb8'}|old_addresses|{r['address'] for r in candidates}
    remaining=[{'method':m['method'],'address':m['address'],'end_exclusive':m['end_exclusive'],'function_bytes':int(m['end_exclusive'],16)-int(m['address'],16),'switch_candidates':len(m['switch_candidates'])} for m in maps['methods'] if m['address'] not in recovered]
    assert len(remaining)==summary['remaining_hard_methods_without_C']
    summary['remaining_methods']=remaining
    summary['remaining_catalog_source_sha256']=sha(LAB/'hard-switches-v2/switches.json')
    (out/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    lines=['# Продолжение разбора Terraria — 15 октября 2026','',f"Новых условных C-кандидатов: **{len(candidates)}**. Всего доступно C-представлений для **{123138+len(candidates):,}** уникальных FDE-адресов, включая отдельные условные кандидаты. **{14-len(candidates)}** прежних сложных методов пока без полного C.",'','| Метод | Результат | Секунд | Switch / записей |','|---|---|---:|---:|']
    for r in attempts:lines.append(f"| {r['method']} | {r['status']} | {r['elapsed_seconds']:.2f} | {r['switches']} / {r['entries']} |")
    lines+=['','Кандидаты:']
    for r in candidates:lines.append(f"- [{r['method']}]({r['file']}): {r['bytes']:,} байт, предупреждений {r['warnings']}; SHA-256 `{r['sha256']}`.")
    lines+=['','Каждая попытка выполнялась отдельно с лимитом 600 секунд. Исходный ELF, фактический движок, байты FDE/таблиц/целей и хеши C сверены; подсказки были временными и откатились, сохранённый проект не изменялся.','', 'Это условные результаты Ghidra с исходными предупреждениями: полнота путей, старшие биты индекса и неизменность таблиц остаются предпосылками соответствующих switch-карт. Аудит целостности не доказывает семантическую эквивалентность, исходный C# или осуществимость ветвей. Новые игровые runtime-проверки этим этапом не выполнялись.','', '**Исправление графа NPC AI:** в прежнем producer v1 Capstone 5.0.7 ошибочно помечал CMP как запись W8/W9. В v2 flag-only aliases нормализованы и добавлены отрицательные образцы; старые файлы сохранены как исторический снимок. Вывод об обнулённых старших битах трёх индексов подтверждён заново через настоящие SUB W и независимые обратные срезы, в пределах условной CFG-модели. [Исправленный граф](../npc-fighters-cfg-v2/REPORT.ru.md) · [Аудит срезов](../npc-fighters-cfg-v2/audit.json).','', '[Машиночитаемая сводка](summary.json) · [Предыдущий этап AI](../ai-continuation-20261014/REPORT.ru.md). Исходный APK и старые манифесты сохранены.']
    lines.extend(['','Дополнительно проверены 2 342 прямых BL-сайта рендера и 3 049 обработчика сообщений; raw ARM64 и Capstone совпали. [Именованный каталог вызовов](../selected-call-catalog-20261015/REPORT.ru.md). Это статические сайты внутри FDE, не runtime-частоты или полный граф вызовов.'])
    (out/'REPORT.ru.md').write_text('\n'.join(lines)+'\n',encoding='utf8')
    folders.append(out.name)
    for name in folders:shutil.copytree(LAB/name,ROOT/name,dirs_exist_ok=True)
    dest=ROOT/out.name;(dest/'tools').mkdir(exist_ok=True)
    for name in ('TerrariaHardSelectedProbe.java','audit_terraria_hard_selected_probe.py','package_terraria_selected_20261015.py','terraria_npc_fighters_cfg_v2.py','audit_terraria_npc_fighters_cfg_v2.py','terraria_selected_call_catalog_20261015.py','terraria_flow_islands.py'):shutil.copy2(REPO/'tools'/name,dest/'tools'/name)
    rows=[{'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)} for name in folders for p in sorted((ROOT/name).rglob('*')) if p.is_file() and p.name!='addendum-manifest.json']
    (dest/'addendum-manifest.json').write_text(json.dumps({'files':rows,'prior_manifest_sha256':sha(prior)},indent=2)+'\n')
    for r in rows:assert sha(ROOT/r['path'])==r['sha256']
    print(json.dumps({'report':str(dest/'REPORT.ru.md'),'candidates':len(candidates),'remaining':14-len(candidates),'files':len(rows)},ensure_ascii=False))
if __name__=='__main__':main()
