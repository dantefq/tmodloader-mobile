"""Checkpoint unsplit-copy Ghidra C candidates, deduplicated against prior models."""
import datetime,hashlib,json,pathlib,shutil
LAB=pathlib.Path('C:/Temp/terraria-re-20261012')
ROOT=pathlib.Path('C:/Private/Documents/ChatGPT/Terraria-Reverse-20261012')
REPO=pathlib.Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    prior=ROOT/'artifact-manifest.json';assert sha(prior)=='94cae77db018fee38c09e3b69f203b5fc0fbfd55b40c4aabbb935e30c61b391a'
    candidates=[];attempts=[];folders=[];pending=[]
    expected={'pseudocode-coarse-'+name+'-20261015' for name in ('bestiary','projectileai','drawnpc1','drawnpc2','drawnormal','drawproj','hiteffect','kill','recipes')}
    expected.add('pseudocode-conservative-bestiary-20261015')
    sources={p.name:p for pattern in ('pseudocode-coarse-*','pseudocode-conservative-*') for p in LAB.glob(pattern) if p.is_dir()}
    for name in sorted(expected-set(sources)):pending.append(name)
    for source in sorted(sources.values()):
        if not source.is_dir():continue
        if not (source/'result.json').exists() or not (source/'audit.json').exists():pending.append(source.name);continue
        r=json.loads((source/'result.json').read_text());a=json.loads((source/'audit.json').read_text())
        conservative=source.name.startswith('pseudocode-conservative-')
        producer='TerrariaConservativeMemoryProbe.java' if conservative else 'TerrariaCoarseCopiesProbe.java'
        auditor='audit_terraria_conservative_memory_probe.py' if conservative else 'audit_terraria_coarse_copies_probe.py'
        profile='conservative-memory-pointer-inference-typed-v4-stack32-v1' if conservative else 'aggregate-copy-unsplit-typed-v4-stack32-v1'
        assert a['integrity_passed'] and a['result_sha256']==sha(source/'result.json') and a['auditor_sha256']==sha(REPO/'tools'/auditor)
        assert r['script_sha256']==sha(REPO/'tools'/producer) and r['ephemeral_transaction_rolled_back']
        assert r['profile']==profile and r['nullguard_has_noreturn_annotation'] is False
        if conservative:assert r['respect_read_only'] is False and r['infer_constant_pointers'] is False
        assert all(r[k] is False for k in ('split_structures','split_arrays','split_pointers'))
        attempts.append({'method':r['method'],'address':r['address'],'status':r['status'],'seconds':r['elapsed_seconds'],'folder':source.name,'profile':profile});folders.append(source.name)
        if r['status']=='decompiled_conditional_candidate':
            c=source/r['file'];assert c.parent==source and sha(c)==r['c_sha256']
            candidates.append({'method':r['method'],'address':r['address'],'file':'../'+source.name+'/'+r['file'],'sha256':sha(c),'bytes':c.stat().st_size,'warnings':c.read_text().count('WARNING:'),'profile':r['profile']})
    assert attempts
    recovered={'0x12f63e8','0x12e2cb8'}
    for name in ('ai-continuation-20261014','selected-continuation-20261015','initializer-continuation-20261015','noreturn-coarse-continuation-20261015','extended-noreturn-continuation-20261015','untyped-c-continuation-20261016','branch-preserving-c-continuation-20261016','long-budget-c-continuation-20261017'):
        p=ROOT/name/'summary.json'
        if p.exists():recovered.update(r['address'] for r in json.loads(p.read_text())['conditional_candidates'])
    added={r['address'] for r in candidates}-recovered;recovered.update(r['address'] for r in candidates)
    maps=json.loads((LAB/'hard-switches-v2/switches.json').read_text());remaining=[{'method':m['method'],'address':m['address'],'function_bytes':int(m['end_exclusive'],16)-int(m['address'],16)} for m in maps['methods'] if m['address'] not in recovered]
    out=LAB/'coarse-continuation-20261015';out.mkdir(exist_ok=True)
    summary={'conditional_candidates':candidates,'attempts':attempts,'planned_attempts':sorted(expected),'pending_or_unaudited':pending,'new_unique_C_addresses':len(added),'remaining_hard_methods_without_C':len(remaining),'remaining_methods':remaining,'unique_C_addresses_including_candidates':123152-len(remaining),'semantic_equivalence_verified':False,'original_Csharp_recovered':False,'saved_projects_modified':False}
    summary['checkpoint_UTC']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    fde_catalogue=LAB/'native/unwind-function-ranges.tsv'
    assert sha(fde_catalogue)=='8b238f458b7a0505138fc56ea70ffe59c21d46a6b83ea2e4106f6f896a3f7756'
    fdes=[tuple(int(x,0) for x in line.split('\t')[:2]) for line in fde_catalogue.read_text().splitlines()]
    assert len(fdes)==123152
    total_bytes=sum(end-start for start,end in fdes)
    remaining_bytes=sum(m['function_bytes'] for m in remaining)
    summary.update(fde_bytes_total=total_bytes,remaining_fde_bytes_without_C=remaining_bytes,C_represented_fde_bytes=total_bytes-remaining_bytes,C_FDE_byte_coverage_percent=100*(total_bytes-remaining_bytes)/total_bytes,C_FDE_address_coverage_percent=100*(123152-len(remaining))/123152)
    for interrupted_name in ('interrupted-coarse-drawproj-20261015','interrupted-coarse-recipes-20261016'):
        interrupted=LAB/interrupted_name
        if not interrupted.exists():continue
        ir=json.loads((interrupted/'interruption.json').read_text(encoding='utf-8-sig'))
        assert ir['status']=='interrupted_without_result' and ir['decompiler_timeout_observed'] is False
        assert not (interrupted/'result.json').exists() and not list(interrupted.glob('*.c'))
        summary.setdefault('interrupted_attempts',[]).append({'folder':interrupted.name,'status':ir['status'],'scope_sha256':sha(interrupted/'scope.json'),'C_coverage_addition':0})
        folders.append(interrupted.name)
    (out/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    lines=['# Декомпиляция с альтернативными настройками Ghidra','',f"C-кандидатов в моделях: {len(candidates)}, новых уникальных адресов {len(added)}. Осталось **{len(remaining)}** прежних сложных методов без полного C. Всего представлений при включении отдельных кандидатов — {123152-len(remaining):,}.",'','| Метод | Статус | Секунд |','|---|---|---:|']
    for a in attempts:lines.append(f"| {a['method']} | {a['status']} | {a['seconds']:.2f} |")
    lines.extend(['',f"Доля по числу FDE-адресов: **{summary['C_FDE_address_coverage_percent']:.5f}%**; по суммарному объёму исходных FDE-диапазонов: **{summary['C_FDE_byte_coverage_percent']:.3f}%**. Без C остаётся {remaining_bytes:,} из {total_bytes:,} байтов этих диапазонов. Это метрика наличия C-представления с условными кандидатами, а не доказательство исполнения каждой инструкции или эквивалентности."])
    if pending:lines.extend(['',f'Не завершены или не проверены: {len(pending)}; они не увеличивают успешный счётчик.'])
    lines.extend(['',f"Снимок проверенных результатов: `{summary['checkpoint_UTC']}`. Последующие результаты очереди попадут в следующий снимок.",'','| Осталось без полного C | Адрес | Байтов FDE |','|---|---|---:|'])
    for m in remaining:lines.append(f"| {m['method']} | `{m['address']}` | {m['function_bytes']:,} |")
    for c in candidates:lines.extend(['',f"[{c['method']}]({c['file']}): {c['bytes']:,} байт, предупреждений {c['warnings']}; SHA `{c['sha256']}`."])
    lines.extend(['','Использован обычный режим `decompile` с `setSplitStructures(false)`, `setSplitArrays(false)`, `setSplitPointers(false)` вместо стандартного разбиения копий. Типовая модель v4 и условные карты BR сохранены. Nullguard NoReturn-аннотация в этой модели отсутствует; она не смешивается с отдельным экспериментом C++ throw.','', 'Проверены исходные ELF/FDE/таблицы/цели и хеши результатов. Проекты открыты readOnly, временные switch overrides запрошены к откату. Целостность не доказывает исходный C#, правильность всех эвристик, полную семантическую эквивалентность или runtime-поведение.','', '[Итоги и остаточный список](summary.json). Неуспешные попытки и прежние корпуса сохранены.'])
    lines.extend(['','Для отдельного профиля `conservative-memory-pointer-inference` дополнительно отключены использование read-only флагов для константных выводов и эвристика константных указателей. Полный профиль каждого результата записан в JSON; это не дополнительные NoReturn-аннотации.'])
    for interruption in summary.get('interrupted_attempts',[]):
        lines.extend(['',f"Прерванная попытка `{interruption['folder']}` сохранена без result.json. При возобновлении процессы Java/decompiler отсутствовали; точная причина завершения неизвестна. Scope и лог сохранены отдельно; это не таймаут и не C-кандидат. [Запись прерывания](../{interruption['folder']}/interruption.json)."])
    (out/'REPORT.ru.md').write_text('\n'.join(lines)+'\n',encoding='utf8');folders.append(out.name)
    for name in folders:shutil.copytree(LAB/name,ROOT/name,dirs_exist_ok=True)
    dest=ROOT/out.name;(dest/'tools').mkdir(exist_ok=True)
    for name in ('package_terraria_coarse_continuation.py','TerrariaCoarseCopiesProbe.java','audit_terraria_coarse_copies_probe.py','TerrariaConservativeMemoryProbe.java','audit_terraria_conservative_memory_probe.py'):shutil.copy2(REPO/'tools'/name,dest/'tools'/name)
    rows=[{'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)} for name in folders for p in sorted((ROOT/name).rglob('*')) if p.is_file() and p.name!='addendum-manifest.json']
    (dest/'addendum-manifest.json').write_text(json.dumps({'files':rows,'prior_manifest_sha256':sha(prior)},indent=2)+'\n')
    for r in rows:assert sha(ROOT/r['path'])==r['sha256']
    print(json.dumps({'report':str(dest/'REPORT.ru.md'),'candidates':len(candidates),'remaining':len(remaining),'pending':len(pending)},ensure_ascii=False))
if __name__=='__main__':main()
