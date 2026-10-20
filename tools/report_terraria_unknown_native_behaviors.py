"""Render private, evidence-linked behavior descriptions; no game-derived repo output."""
import argparse, collections, hashlib, html, json, pathlib, urllib.parse


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def expression(v):
    k=v['kind']
    if k=='input_register':return v['register']+'(вход)'
    if k=='constant':return hex(v['value'])
    if k in ('low32','low64','zero_extend32'):return k+'('+expression(v['value'])+')'
    if k in ('add','sub','and'):return '('+expression(v['lhs'])+{'add':'+','sub':'−','and':'&'}[k]+hex(v['rhs'])+')'
    if k=='memory_load':return ('signed' if v['signed'] else 'unsigned')+str(v['bytes']*8)+'['+expression(v['base'])+f"{v['offset']:+#x}"+']'
    raise ValueError('Unknown expression kind')


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);a=ap.parse_args();out=a.lab/'unknown-native-behaviors-v1'
    source=out/'behaviors.json';doc=json.loads(source.read_text(encoding='utf8'))
    exports={}
    with (a.lab/'native-ranges-pseudocode/coverage.jsonl').open(encoding='utf8') as stream:
        for line in stream:
            r=json.loads(line);exports[r['address']]=r
    groups=collections.defaultdict(list)
    for r in doc['results']:groups[r['structural_behavior']].append(r)
    labels={'direct_branch_forwarder':'Прямые переходы','indirect_branch_forwarder':'Динамические переходы','straight_line_return':'Короткие возвраты'}
    for category,rows in groups.items():
        lines=['# '+labels[category],'','Условное описание исходных машинных инструкций, не восстановленное имя функции. Требуется вход с начала FDE и успешное завершение чтений памяти. Все значения регистров имеют разрядность ARM64; адреса вычисляются по модулю 2⁶⁴.','', '| Адрес / C-псевдокод | Наблюдаемое статическое поведение |','|---|---|']
        for r in rows:
            item=exports[r['address']];relative=pathlib.PurePosixPath(item['file'])
            if relative.is_absolute() or '..' in relative.parts or item['status']!='decompiled':raise ValueError('Unsafe/missing prior C link')
            file=a.lab/'native-ranges-pseudocode'/relative
            if not file.is_file():raise ValueError('Prior C file missing')
            link='../native-ranges-pseudocode/'+urllib.parse.quote(relative.as_posix(),safe='/')
            t=r['transfer']
            if t['kind']=='direct_branch':
                e=t['endpoint'];name=e['plt_relocation_symbol_name'] or ' / '.join(e['managed_or_elf_names']) or e['address']
                text=f"B → {t['target']}; конечная цель цепочки чистых B: {name} ({e['address']})"
            elif t['kind']=='indirect_branch':text='BR → '+expression(t['target_expression'])
            else:text='RET с исходным x30; x0 = '+expression(t['x0_expression'])
            text=html.escape(text).replace('|','&#124;').replace('\n',' ').replace('`','\\`').replace('[','\\[').replace(']','\\]')
            lines.append(f"| [{r['address']}]({link}) | {text} |")
        (out/(category+'.md')).write_text('\n'.join(lines)+'\n',encoding='utf8')
    summary=['# Продолжение разбора неизвестных нативных функций','', '14 октября 2026.','',
             f"Из 8 140 диапазонов, назначение которых ранее было неизвестно, для {doc['structurally_described']:,} построены проверяемые описания коротких последовательностей инструкций. {doc['structurally_unclassified']:,} не покрыты этим консервативным анализатором (лимит 64 байта).",'',
             f"Прямые передачи управления: {doc['behavior_counts']['direct_branch_forwarder']}; динамические: {doc['behavior_counts']['indirect_branch_forwarder']}; короткие возвраты: {doc['behavior_counts']['straight_line_return']}. У {doc['named_forwarding_endpoints']} прямых обёрток установлены имена конечных managed/ELF/PLT-целей. Проверены 560 PLT-записей по dynsym и relocation-таблице.",'',
             'Пример: обёртки передают управление getpid, malloc и free либо managed-методам. Имя relocation-символа описывает статическую связь; фактическое разрешение динамическим загрузчиком не наблюдалось. Динамические обёртки часто берут указатель из памяти и переставляют аргументы; это не доказывает тип объекта или его назначение.','',
             'Число неизвестных игровых/служебных назначений не заменено числом структурных описаний: исходные роли этих 8 140 диапазонов по-прежнему не установлены полностью. Новые C-представления этот этап не создавал. Исходный APK и предыдущий корпус не менялись.','',
             '[Прямые обёртки](direct_branch_forwarder.md) · [Динамические обёртки](indirect_branch_forwarder.md) · [Возвраты](straight_line_return.md) · [Байты и выражения регистров](behaviors.json) · [Независимый аудит](independent-audit.json).','',
             'В таблицах есть ссылки на ранее сохранённый C-псевдокод. Полные изменения регистров, порядок чтений памяти и исходные инструкции приведены в behaviors.json. Состав дополнения фиксируется отдельным addendum-manifest.json.']
    (out/'REPORT.ru.md').write_text('\n'.join(summary)+'\n',encoding='utf8')
    (out/'report-provenance.json').write_text(json.dumps({'behavior_source_sha256':sha(source),'report_tool_sha256':sha(pathlib.Path(__file__)),'linked_prior_C_files':len(doc['results'])},indent=2)+'\n',encoding='utf8')
    print(json.dumps({'report':str(out/'REPORT.ru.md'),'descriptions':len(doc['results'])}))


if __name__=='__main__':main()
