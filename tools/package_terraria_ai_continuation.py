"""Bind new conditional AI candidates and source-checked facts, preserving old snapshots."""
import hashlib,json,pathlib,shutil
LAB=pathlib.Path('C:/Temp/terraria-re-20261012')
ROOT=pathlib.Path('C:/Private/Documents/ChatGPT/Terraria-Reverse-20261012')
REPO=pathlib.Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    prior=ROOT/'artifact-manifest.json';assert sha(prior)=='94cae77db018fee38c09e3b69f203b5fc0fbfd55b40c4aabbb935e30c61b391a'
    families=['npc-ai003-call-facts-v1','npc-fighters-cfg-v1'];candidates=[];attempts=[]
    tools=['terraria_npc_ai003_call_facts.py','terraria_npc_fighters_cfg.py','TerrariaSwitchHintLongProbe.java','audit_terraria_switch_hint_long_probe.py','package_terraria_ai_continuation.py','terraria_flow_islands.py','terraria_initializer_call_constants.py','audit_terraria_initializer_call_constants.py']
    for folder,producer,auditor in [('pseudocode-switch-hint-long-probe','TerrariaSwitchHintLongProbe.java','audit_terraria_switch_hint_long_probe.py'),('pseudocode-projectile026-long-probe','TerrariaProjectile026LongProbe.java','audit_terraria_projectile026_long_probe.py')]:
        source=LAB/folder
        if not (source/'result.json').exists():continue
        record=json.loads((source/'result.json').read_text());audit=json.loads((source/'audit.json').read_text())
        assert audit['integrity_passed'] and sha(source/'result.json')==audit['result_sha256'] and sha(REPO/'tools'/auditor)==audit['auditor_sha256']
        assert sha(REPO/'tools'/producer)==record['script_sha256'] and record['ephemeral_transaction_rolled_back']
        assert record['saved_project_modified'] is False
        families.append(folder);tools.extend([producer,auditor]);attempts.append({'folder':folder,'status':record['status'],'seconds':record['elapsed_seconds']})
        if record['status']=='decompiled_conditional_candidate':
            p=source/record['file'];assert sha(p)==record['c_sha256']
            candidates.append({'method':record['method'],'address':record['address'],'file':'../'+folder+'/'+record['file'],'bytes':p.stat().st_size,'sha256':sha(p),'warnings':p.read_text().count('WARNING:')})
    facts=json.loads((LAB/'npc-ai003-call-facts-v1/calls.json').read_text());audit=json.loads((LAB/'npc-ai003-call-facts-v1/audit.json').read_text())
    assert audit['integrity_passed'] and audit['calls_sha256']==sha(LAB/'npc-ai003-call-facts-v1/calls.json')
    assert facts['producer_sha256']==sha(REPO/'tools/terraria_npc_ai003_call_facts.py')
    cfg=json.loads((LAB/'npc-fighters-cfg-v1/cfg.json').read_text());assert cfg['producer_sha256']==sha(REPO/'tools/terraria_npc_fighters_cfg.py')
    assert cfg['external_exits']==[] and cfg['instruction_count']==19765
    out=LAB/'ai-continuation-20261014';out.mkdir(exist_ok=True)
    result={'conditional_candidates':candidates,'attempts':attempts,'unique_C_addresses_including_conditional_candidates':123136+len(candidates),'previous_hard_methods_without_C':16-len(candidates),'NPC_AI003_named_call_sites':facts['named_BL_sites'],'NPC_AI003_sites_with_local_constants':facts['sites_with_constants'],'NPC_AI003_register_facts':facts['register_constant_facts'],'NPC_AI003_CFG_nodes_including_detached_continuation':cfg['instruction_count'],'runtime_equivalence_verified':False,'original_Csharp_recovered':False,'prior_corpus_modified':False}
    (out/'summary.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    lines=['# Продолжение разбора AI Terraria','',f"Добавлено условных C-кандидатов: **{len(candidates)}**. В текущем отдельном корпусе C-представления доступны для {123136+len(candidates):,} уникальных FDE-адресов; **{16-len(candidates)}** прежних проблемных методов пока без полного C. Это наличие представления, не восстановленный исходный проект или доказанная эквивалентность.",'']
    for c in candidates:lines.extend([f"- [{c['method']}]({c['file']}): {c['bytes']:,} байт, предупреждений Ghidra — {c['warnings']}. SHA-256 `{c['sha256']}`."])
    lines.extend(['','Попытки выполнялись отдельно, с лимитом 600 секунд, в readOnly-проекте; временные switch overrides откатились. Условия карт переходов и предупреждения Ghidra остаются частью модели. Причина отличия времени от прежнего параллельного прохода не установлена.','',f"Для AI_003_Fighters независимо проверены все 79 052 байта FDE и 1 864 BL; {facts['named_BL_sites']} сайтов получили имена из метаданных. У {facts['sites_with_constants']} сайтов есть {facts['register_constant_facts']} локальных фактов X0–X7. Это статические сайты и условные суффиксы, не частоты исполнения или полный AI. [Каталог вызовов](../npc-ai003-call-facts-v1/REPORT.ru.md).",'','В отдельный граф включены 19 763 инструкции FDE и две инструкции внешнего участка 0x118d934 → 0x1186008. Все 19 765 узлов достижимы в модели; внешних выходов после этого дополнения не осталось. Проверки CMP/условных ветвей доминируют над тремя BR **в данной модели**. ARM64-управление проверено собственным raw-декодером и Capstone; блокирование узлов проверяет доминирование. [Граф и ограничения](../npc-fighters-cfg-v1/REPORT.ru.md).','','Модель предполагает полноту условных switch-карт, единственный вход, обычный возврат вызовов и отсутствие исключительных/внешних повторных входов. Достижимость графа не доказывает осуществимость ветвей в игре. Исходный FDE C-кандидата не расширялся внешним участком; граф с продолжением сохранён отдельно, полной семантической эквивалентности C не заявлено.','','[Сводка](summary.json). Исходный APK, прежние журналы и проекты не изменялись.'])
    (out/'REPORT.ru.md').write_text('\n'.join(lines)+'\n',encoding='utf8')
    for folder in families+[out.name]:shutil.copytree(LAB/folder,ROOT/folder,dirs_exist_ok=True)
    dest=ROOT/out.name;(dest/'tools').mkdir(exist_ok=True)
    for name in sorted(set(tools)):shutil.copy2(REPO/'tools'/name,dest/'tools'/name)
    paths=[p for folder in families+[out.name] for p in (ROOT/folder).rglob('*') if p.is_file() and p.name!='addendum-manifest.json']
    rows=[{'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(paths)]
    (dest/'addendum-manifest.json').write_text(json.dumps({'files':rows,'prior_manifest_sha256':sha(prior)},indent=2)+'\n')
    for row in rows:assert sha(ROOT/row['path'])==row['sha256']
    print(json.dumps({'report':str(dest/'REPORT.ru.md'),'candidates':len(candidates),'remaining':16-len(candidates),'files':len(rows)},ensure_ascii=False))
if __name__=='__main__':main()
