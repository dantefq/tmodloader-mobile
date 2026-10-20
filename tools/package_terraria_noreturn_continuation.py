"""Keep conditional standard-C++-throw model candidates separate and deduplicated."""
import hashlib,json,pathlib,shutil
LAB=pathlib.Path('C:/Temp/terraria-re-20261012')
ROOT=pathlib.Path('C:/Private/Documents/ChatGPT/Terraria-Reverse-20261012')
REPO=pathlib.Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    prior=ROOT/'artifact-manifest.json';assert sha(prior)=='94cae77db018fee38c09e3b69f203b5fc0fbfd55b40c4aabbb935e30c61b391a'
    proof=LAB/'nullguard-noreturn-model-20261015/evidence.json';doc=json.loads(proof.read_text());assert doc['integrity_passed'] and doc['auditor_sha256']==sha(REPO/'tools/audit_terraria_nullguard_noreturn_model.py')
    candidates=[];attempts=[];folders=[]
    for source in sorted(LAB.glob('pseudocode-noreturn-*')):
        if not (source/'result.json').exists() or not (source/'audit.json').exists():continue
        r=json.loads((source/'result.json').read_text());a=json.loads((source/'audit.json').read_text())
        assert a['integrity_passed'] and a['result_sha256']==sha(source/'result.json') and a['auditor_sha256']==sha(REPO/'tools/audit_terraria_noreturn_probe.py')
        assert r['script_sha256']==sha(REPO/'tools/TerrariaNoreturnSelectedProbe.java') and r['parent_helper_sha256']==sha(REPO/'tools/TerrariaHardSelectedProbe.java')
        assert r['noreturn_model_evidence_sha256']==sha(proof) and r['outer_annotation_transaction_rolled_back']
        assert all(x['original_no_return_restored'] for x in r['conditional_noreturn_annotations'])
        attempts.append({'address':r['address'],'method':r['method'],'folder':source.name,'status':r['status'],'seconds':r['elapsed_seconds']});folders.append(source.name)
        if r['status']=='decompiled_conditional_candidate':
            c=source/r['file'];assert c.parent==source and sha(c)==r['c_sha256']
            candidates.append({'address':r['address'],'method':r['method'],'file':'../'+source.name+'/'+r['file'],'sha256':sha(c),'bytes':c.stat().st_size,'warnings':c.read_text().count('WARNING:'),'additional_ABI_model':True})
    assert attempts
    recovered={'0x12f63e8','0x12e2cb8'}
    for folder in ('ai-continuation-20261014','selected-continuation-20261015','initializer-continuation-20261015'):
        p=ROOT/folder/'summary.json'
        if p.exists():recovered.update(r['address'] for r in json.loads(p.read_text())['conditional_candidates'])
    newly_added={r['address'] for r in candidates}-recovered;recovered.update(r['address'] for r in candidates)
    maps=json.loads((LAB/'hard-switches-v2/switches.json').read_text());remaining=[{'address':m['address'],'method':m['method']} for m in maps['methods'] if m['address'] not in recovered]
    out=LAB/'noreturn-continuation-20261015';out.mkdir(exist_ok=True)
    result={'conditional_candidates':candidates,'attempts':attempts,'additional_unique_C_addresses':len(newly_added),'remaining_hard_methods_without_C':len(remaining),'remaining_methods':remaining,'unique_C_addresses_including_all_conditional_candidates':123152-len(remaining),'model_evidence_sha256':sha(proof),'runtime_verified':False,'semantic_equivalence_verified':False,'saved_projects_modified':False}
    (out/'summary.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    lines=['# Условная модель C++ throw для декомпиляции Terraria','',f"C-кандидатов с дополнительной моделью: {len(candidates)}; новых уникальных адресов относительно других дополнений: {len(newly_added)}. Осталось **{len(remaining)}** прежних методов без полного C. Число представлений включая отдельные условные модели — {123152-len(remaining):,}.",'','| Метод | Результат | Секунд |','|---|---|---:|']
    for a in attempts:lines.append(f"| {a['method']} | {a['status']} | {a['seconds']:.2f} |")
    for c in candidates:lines.extend(['',f"[{c['method']}]({c['file']}): {c['bytes']:,} байт, предупреждений {c['warnings']}; SHA `{c['sha256']}`."])
    lines.extend(['','Применены только четыре временные NoReturn-аннотации: 0x6ff6ac, 0x741278, 0x74128c, 0x7411e0. Фабрика 0x74129c не изменялась. Результат требует стандартного контракта __cxa_throw, обычного BL и отсутствия exceptional/nonlocal повторного входа в обёртки. Это **предпосылки отдельной модели**, не доказанное поведение APK в рантайме. [Первичный C++ ABI §2.4.3](https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html#cxx-throw) · [Исходные инструкции и ограничения](../nullguard-noreturn-model-20261015/REPORT.ru.md).','','Проект-копия открыт readOnly. Внешняя транзакция аннотаций и внутренняя транзакция switch hints откатились; исходные значения NoReturn восстановлены. Исходный проект, прежние C-кандидаты и журналы сохранены. Ни исходный C#, ни полная семантическая эквивалентность не заявлены.','','[Сводка и остаточный список](summary.json).'])
    (out/'REPORT.ru.md').write_text('\n'.join(lines)+'\n',encoding='utf8')
    folders.extend(['nullguard-noreturn-model-20261015',out.name])
    for name in folders:shutil.copytree(LAB/name,ROOT/name,dirs_exist_ok=True)
    dest=ROOT/out.name;(dest/'tools').mkdir(exist_ok=True)
    for name in ('package_terraria_noreturn_continuation.py','TerrariaNoreturnSelectedProbe.java','TerrariaHardSelectedProbe.java','audit_terraria_noreturn_probe.py','audit_terraria_nullguard_noreturn_model.py'):shutil.copy2(REPO/'tools'/name,dest/'tools'/name)
    rows=[{'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)} for name in folders for p in sorted((ROOT/name).rglob('*')) if p.is_file() and p.name!='addendum-manifest.json']
    (dest/'addendum-manifest.json').write_text(json.dumps({'files':rows,'prior_manifest_sha256':sha(prior)},indent=2)+'\n')
    for r in rows:assert sha(ROOT/r['path'])==r['sha256']
    print(json.dumps({'report':str(dest/'REPORT.ru.md'),'candidates':len(candidates),'remaining':len(remaining)},ensure_ascii=False))
if __name__=='__main__':main()
