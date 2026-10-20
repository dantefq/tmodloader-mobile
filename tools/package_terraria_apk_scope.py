"""Deliver separate per-layer APK coverage denominators without merging claims."""
import hashlib
import json
import shutil
from pathlib import Path

LAB=Path(r'C:\Temp\terraria-re-20261012')
DELIVERY=Path(r'C:/Private\Documents\ChatGPT\Terraria-Reverse-20261012')
TOOLS=Path(__file__).resolve().parent
OUT=DELIVERY/'apk-scope-continuation-20261019'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(DELIVERY/'artifact-manifest.json')=='94cae77db018fee38c09e3b69f203b5fc0fbfd55b40c4aabbb935e30c61b391a'
rows=[]
def copy(p,relative):
    dest=OUT/relative
    assert dest.resolve().is_relative_to(OUT.resolve())
    dest.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(p,dest)
    assert sha(dest)==sha(p)
    rows.append(dict(path=relative,sha256=sha(dest),bytes=dest.stat().st_size))
for name in ('inventory_terraria_apk_native_scope.py','prepare_terraria_other_native_manifests.py',
             'terraria_native_map.py','terraria_unwind_ranges.py','inventory_terraria_java_method_evidence.py',
             'TERRARIA_JAVA_METHOD_LEDGER_20261019.md','TERRARIA_REMAINING_SCOPE_20261019.md','package_terraria_apk_scope.py'):
    copy(TOOLS/name,'tools/'+name)
for name in ('JavaSourceSpanExtractor.java','reconcile_terraria_java_spans.py','verify_terraria_java_spans.py',
             'TERRARIA_JAVA_SOURCE_SPANS_20261019.md','terraria_metadata_gap_reconciliation_20261019.py',
             'reconcile_terraria_java_aliases.py','verify_terraria_java_aliases.py','verify_terraria_java_aliases_v1.py'):
    copy(TOOLS/name,'tools/'+name)
for source,dest in [('apk-native-scope-inventory-20261019','native-inventory'),
                    ('other-native-range-manifests-20261019','native-range-manifests'),
                    ('android-java-method-ledger-20261019','java-method-ledger')]:
    for p in (LAB/source).iterdir():
        if p.is_file():copy(p,dest+'/'+p.name)
for source,dest in [('java-method-source-mapping-20261019','java-source-spans'),
                    ('java-method-source-mapping-alias-20261019','java-source-aliases-v1'),
                    ('java-method-source-mapping-alias-20261019-v2','java-source-aliases-v2'),
                    ('metadata-gap-reconciliation-20261019','metadata-gap-reconciliation')]:
    for p in (LAB/source).rglob('*'):
        if p.is_file():copy(p,dest+'/'+p.relative_to(LAB/source).as_posix())
native=json.loads((LAB/'apk-native-scope-inventory-20261019/summary.json').read_text())
java=json.loads((LAB/'android-java-method-ledger-20261019/summary.json').read_text())
summary=dict(apk_sha256=native['apk_sha256'],native_library_count=8,native_inventory=native,
             java_method_evidence=java,whole_APK_source_recovery_percent=None,
             JNI_conditionally_bound_declarations=160,JNI_declarations=161,
             concrete_metadata_declarations_without_mapped_address=70,
             original_manifest_unchanged=True,new_C_coverage_addition=0)
summary['java_syntactic_spans']=json.loads((LAB/'java-method-source-mapping-20261019/reconciled/summary.json').read_text())
summary['java_syntactic_spans_alias_refinement']=json.loads((LAB/'java-method-source-mapping-alias-20261019-v2/summary.json').read_text())
summary['metadata_gap_refinement']=json.loads((LAB/'metadata-gap-reconciliation-20261019/final/ledger.json').read_text())['summary']
latest=sorted(LAB.glob('copy-rule-off-conditional-export-qualification-*-20261019.json'))
if latest:summary['libil2cpp_conditional_C_export']=json.loads(latest[-1].read_text())
OUT.mkdir(exist_ok=True)
(OUT/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
(OUT/'files.json').write_text(json.dumps(rows,indent=2)+'\n')
report='''# Покрытие APK по отдельным слоям, 19.10.2026

Процент по FDE основной `libil2cpp.so` учитывает наличие C-псевдокода с записанными условными предпосылками. Он не включает автоматически Java, другие библиотеки, все исполняемые байты или доказательство эквивалентности исходникам. Единого подтверждённого процента восстановления исходников всего APK нет.

- [Состав и FDE всех восьми ELF](native-inventory/summary.json). Каждый файл сверен с точным ZIP-членом исходного APK, прежней извлечённой копией и каталогом символов. FDE сверены с индексом `.eh_frame_hdr`; отрицательные проверки длины записи отвергнуты.
- [Диапазоны следующего native-экспорта](native-range-manifests/summary.json). Кроме FDE, включены непересекающиеся положительные размеры динамических символов; неоднозначные случаи сохранены отдельно. Это очередь, не готовые C-тела.
- [Реестр 9004 DEX-методов](java-method-ledger/summary.json): 8256 с кодом, 161 native, 587 abstract. Возможное наличие Java-файла не подтверждает восстановление тела. Точные DEX-сигнатуры, смещения и хеши представлены в JSONL/TSV; реестр сверен с прежним независимым каталогом.
- [Оставшийся объём](tools/TERRARIA_REMAINING_SCOPE_20261019.md): неизвестные семантические роли, одна JNI-привязка, 70 объявлений без адресов реализации, байты вне FDE и остальные native-библиотеки учтены раздельно.

Все эти действия статические; код APK не запускался. Сохранённые игровые данные приватны. Исходный манифест прежних результатов не изменён.
'''
if latest:
    q=summary['libil2cpp_conditional_C_export']
    report+='\nТекущий отдельно квалифицированный C-экспорт libil2cpp: '+str(q['conditional_C_export_addresses'])+'/'+str(q['total_FDE_addresses'])+' FDE-адресов, '+format(q['percent_conditional_C_export_FDE_bytes'],'.6f')+'% FDE-байтов. [Тексты и условия](../copy-rule-diagnostic-continuation-20261019/REPORT.ru.md).\n'
report+='\n[Сопоставление Java через AST](java-source-spans/reconciled/summary.json): 6792 из 8256 методов с кодом имеют однозначные синтаксические диапазоны тел; 1274 не сопоставлены по точной сигнатуре, 190 связаны с неизвестным преобразованием инициализаторов. Четыре файла с синтаксическими ошибками исключены. Проверены 14253 хеша/границы деклараций и тел. Это сопоставление текста, не доказательство эквивалентности DEX.\n'
report+='\n[Уточнение 70 объявлений без адреса](metadata-gap-reconciliation/REPORT.md): 47 без MethodSpec в проверенных таблицах, 19 с MethodSpec без codegen-строки, четыре с явным нулевым указателем реализации. Ни одного тела не найдено. Единственная ранее не-generic запись принадлежит абстрактному WinRT-интерфейсу. Причина отсутствия тел и stripping не установлены.\n'
report+='\n[Уточнение Java по доказанным полным именам типов](java-source-aliases-v2/summary.json): теперь 6837 из 8256 методов с кодом имеют точные синтаксические диапазоны тел, 1419 остаются неизвестными. Добавлены 45 тел и одна abstract declaration; исходные сопоставления и все 9004 DEX-записи сохранены. Независимо проверены 14344 диапазона текста; 14 отрицательных проверок отвергнуты. Это не проверка семантической эквивалентности.\n'
(OUT/'REPORT.ru.md').write_text(report,encoding='utf8')
assert all(sha(OUT/r['path'])==r['sha256'] for r in rows)
print(json.dumps(dict(files_verified=len(rows),native_libraries=8,whole_APK_percent=None)))
