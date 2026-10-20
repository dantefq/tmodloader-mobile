"""Snapshot only audited durable prefixes of native exports into private delivery."""
import hashlib
import json
import shutil
from pathlib import Path
from package_terraria_native_archive_20261020 import build_archive

LAB=Path(r'C:\Temp\terraria-re-20261012')
DELIVERY=Path(r'C:/Private\Documents\ChatGPT\Terraria-Reverse-20261012')
TOOLS=Path(__file__).resolve().parent
OUT=DELIVERY/'other-native-C-continuation-20261019'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
digest=lambda b:hashlib.sha256(b).hexdigest()
assert sha(DELIVERY/'artifact-manifest.json')=='94cae77db018fee38c09e3b69f203b5fc0fbfd55b40c4aabbb935e30c61b391a'
files=[];snapshots=[]
def copy(p,relative):
    dest=OUT/relative
    assert dest.resolve().is_relative_to(OUT.resolve())
    dest.parent.mkdir(parents=True,exist_ok=True)
    expected=sha(p)
    if not (dest.is_file() and dest.stat().st_size==p.stat().st_size and sha(dest)==expected):
        shutil.copyfile(p,dest)
        assert sha(dest)==expected
    files.append(dict(path=relative,sha256=expected,bytes=dest.stat().st_size))
for name in ('ApkNativeRangeExport.java','audit_apk_native_range_export.py','APK_NATIVE_RANGE_EXPORT_NOTES.md',
             'APK_NATIVE_RANGE_AUDIT_NOTES.md','run_terraria_other_native_export.ps1',
             'run_terraria_other_native_export_v1.ps1','run_terraria_other_native_export_v2.ps1',
             'prepare_terraria_native_export_v2.py','prepare_terraria_native_export_v3.py',
             'prove_apk_stackchk_imports.py','prove_libmain_stackchk_import.py','classify_terraria_export_pcode_exits.py',
             'audit_terraria_native_v3_library.py','summarize_terraria_native_v3_audits.py',
             'run_terraria_native_v3_remaining.ps1','resume_terraria_external_wrapper_after_queue.ps1',
             'terraria_apk_scope_preferences.json','review_terraria_gns_varnode_failure.py',
             'TERRARIA_GNS_VARNODE_FAILURE_REVIEW.md','package_terraria_native_archive_20261020.py','package_terraria_other_native_exports.py'):
    copy(TOOLS/name,'tools/'+name)
for version in ('v2','v3'):
    for p in (TOOLS/('apk-native-'+version)).iterdir():
        if p.is_file():copy(p,'tools/apk-native-'+version+'/'+p.name)
for name in ('other-native-stackchk-proofs-20261019','libmain-stackchk-import-proof-20261019',
             'gns-stackchk-import-proof-20261019','other-native-range-v3-manifests-20261019',
             'gns-pcode-exit-classification-20261019-reviewed'):
    for p in (LAB/name).rglob('*'):
        if p.is_file():copy(p,'evidence/'+name+'/'+p.relative_to(LAB/name).as_posix())
checkpoints=sorted(LAB.glob('other-native-v3-audited-checkpoint-*'))
if checkpoints:
    for p in checkpoints[-1].iterdir():
        if p.is_file():copy(p,'latest-audited-queue-checkpoint/'+p.name)
for p in LAB.glob('other-native-export-*.json'):
    try:r=json.loads(p.read_text(encoding='utf-8-sig'))
    except (ValueError,UnicodeError):continue
    if r.get('status') in ('starting','running'):continue
    copy(p,'lifecycle/'+p.name)
    for suffix in ('.stdout.log','.stderr.log','.ghidra.log'):
        log=p.with_name(p.name+suffix)
        if log.exists():copy(log,'lifecycle/'+log.name)

# Explicit associations avoid inferring an output folder from a fuzzy filename.
known=[
 ('libmain-v1','other-native-range-c-libmain-smoke-20261019','other-native-libmain-smoke-audit-20261019.json'),
 ('libmain-v2','other-native-range-c-libmain-smoke-v2-20261019','other-native-libmain-smoke-v2-audit-20261019.json'),
 ('libmain-v3','other-native-range-c-libmain-smoke-v3-20261019','other-native-libmain-smoke-v3-audit-20261019.json'),
 ('GNS-v2-prefix64','other-native-range-c-libGNS_Wrapper-sample-v2-20261019','other-native-GNS-sample-v2-audit-20261019.json'),
 ('GNS-v3-prefix2000','other-native-range-c-libGNS_Wrapper-sample-v3-20261019','other-native-GNS-sample-v3-audit-20261019.json'),
 ('external_wrapper-v3-restored-prefix1553','other-native-range-c-libexternal_wrapper-sample-v3-20261019','other-native-external_wrapper-restored-prefix1553-v3-audit-20261019.json'),
]
for library in ('libGNS_Wrapper','libunity','libexternal_wrapper','libcpp_shared','libpairipcore','libpdaprotect'):
    known.append((library+'-v3-final','other-native-range-c-'+library+'-sample-v3-20261019','other-native-'+library+'-final-v3-audit-20261019.json'))
for label,folder,audit_name in known:
    audit_file=LAB/audit_name
    if not audit_file.exists():continue
    audit=json.loads(audit_file.read_text())
    assert audit['integrity_passed'] and not audit['preflight_only']
    root=LAB/folder
    lines=(root/'journal.jsonl').read_bytes().splitlines(keepends=True)
    prefix=b''.join(lines[:audit['attempted_rows']])
    assert digest(prefix)==audit['journal_sha256'],'Audited prefix changed'
    copy(audit_file,label+'/audit.json')
    for name in ('run.json','manifest.input.json','ApkNativeRangeExport.java','preparation.jsonl','restoration.json'):
        p=root/name
        if p.exists():copy(p,label+'/'+name)
    target=OUT/label/'journal.jsonl';target.write_bytes(prefix)
    files.append(dict(path=label+'/journal.jsonl',sha256=sha(target),bytes=target.stat().st_size))
    archive_paths=None
    if audit['attempted_rows']>=20000:
        archive_paths=build_archive(root,audit_file,OUT/label)
        for path in archive_paths:
            files.append(dict(path=path.relative_to(OUT).as_posix(),sha256=sha(path),bytes=path.stat().st_size))
    for line in ([] if archive_paths else prefix.splitlines()):
        commit=json.loads(line);result=root/commit['result_file']
        assert sha(result)==commit['result_sha256']
        record=json.loads(result.read_text())
        copy(result,label+'/'+result.name)
        if record['status']=='decompiled':
            c=root/record['c_file'];assert sha(c)==record['c_sha256'] and c.stat().st_size==record['c_bytes']
            copy(c,label+'/'+c.name)
    snapshots.append(dict(label=label,producer_sha256=audit.get('producer_sha256'),attempted=audit['attempted_rows'],
        total=audit['total_manifest_rows'],status_counts=audit['status_counts'],
        conditional_scope_inside_rows=audit.get('conditional_export_rows_without_detected_truncation_and_with_retained_scope_inside'),
        retained_pcode_outside_extent_rows=audit.get('C_text_rows_with_retained_pcode_outside_extent'),
        artifact_format='verified_zip_and_member_hash_index' if archive_paths else 'individual_artifacts',
        journal_sha256=audit['journal_sha256'],audited_prefix_only=True))
summary=dict(snapshots=snapshots,profiles_overlap_do_not_sum=True,original_manifest_unchanged=True,
             original_source_recovered=False,semantic_equivalence_verified=False,whole_APK_recovery_percent=None)
(OUT/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
(OUT/'files.json').write_text(json.dumps(files,indent=2)+'\n')
report='''# Остальные native-библиотеки: C-кандидаты, 19.10.2026

Здесь сохранены только независимо проверенные завершённые префиксы журналов. Продолжающийся проход может содержать больше результатов; неподтверждённые строки не добавлены в этот снимок. Разные версии и префиксы пересекаются, их количества нельзя суммировать.

V3 предварительно объявляет подтверждённые диапазоны функций и временно помечает только доказанные PLT-привязки `__stack_chk_fail` как не возвращающиеся нормально. Применимость стандартного поведения Bionic, отсутствие подмены GOT/импорта и нештатного возврата являются явными условиями, а не наблюдением исполнения. Подлинные исходные байты не менялись.

Для каждого C-текста сохранены адрес, размер и хеш исходного диапазона, хеш результата и C, фактические флаги декомпилятора. В V3 проверяются адреса сохранённых pcode-операций; это не полный список всех посещённых native-инструкций. Выходы за диапазон и признаки усечения учитываются отдельно. Отсутствие таких признаков не доказывает эквивалентность или готовность к сборке.

Часть исторического V2 GNS чрезмерно продолжала поток после неизвестной модели внешнего вызова. Этот профиль сохранён как диагностический; его C не объявляется точным восстановлением отдельной функции. [Сводка снимков](summary.json).
'''
for r in snapshots:
    report+='\n- ['+r['label']+']('+r['label']+'/audit.json): '+str(r['attempted'])+'/'+str(r['total'])+' проверенных записей; '+str(r['status_counts'])+'.\n'
    if r['artifact_format']=='verified_zip_and_member_hash_index':
        report+='  C-тексты и записи результата: [exports.zip]('+r['label']+'/exports.zip); [хеш каждого члена архива]('+r['label']+'/archive-index.json). Каждый член повторно прочитан и проверен после упаковки.\n'
(OUT/'REPORT.ru.md').write_text(report,encoding='utf8')
assert all(sha(OUT/r['path'])==r['sha256'] for r in files)
print(json.dumps(dict(files_verified=len(files),snapshots=[r['label'] for r in snapshots])))
