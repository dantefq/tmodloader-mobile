"""Build a separate, private offline explorer after the native-range audit passes."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def load(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def bound(lab, path):
    resolved = path.resolve()
    require(resolved.is_relative_to(lab), 'Artifact link escapes private lab: ' + str(path))
    require(resolved.is_file(), 'Missing artifact: ' + str(path))
    return quote(resolved.relative_to(lab).as_posix(), safe='/')


def safe_json(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).replace('&', '\\u0026').replace('<', '\\u003c').replace('>', '\\u003e').replace('\u2028', '\\u2028').replace('\u2029', '\\u2029')


HTML = r'''<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>Terraria · дополнительные нативные функции</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#101612;color:#e8efe9;font:15px/1.5 system-ui}header,footer{padding:24px;border-bottom:1px solid #314035}h1{margin:0;font-size:26px}p{max-width:1100px}.muted,small{color:#a8b8ac}.warning{padding:12px;border:1px solid #806b39;border-radius:6px;background:#332c1b}.stats,.links{display:flex;gap:18px;flex-wrap:wrap}.stat b{display:block;font-size:24px;color:#b5ed8d}main{display:grid;grid-template-columns:minmax(300px,35%) 1fr}aside,article{padding:20px;min-width:0}aside{border-right:1px solid #314035}input,select,button{font:inherit;background:#19221b;color:#e8efe9;border:1px solid #405943;border-radius:6px;padding:9px}input,select{width:100%;margin-bottom:10px}button{cursor:pointer}button:hover{border-color:#b5ed8d}.row{display:block;text-align:left;width:100%;margin:6px 0;overflow-wrap:anywhere}.row small{display:block}.row[aria-current=true]{border-color:#b5ed8d}a{color:#b5ed8d;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#19221b;padding:12px;font-size:12px}h2{overflow-wrap:anywhere}#pagination{display:flex;gap:12px;margin-top:12px}footer{font-size:12px;border-top:1px solid #314035}@media(max-width:800px){main{grid-template-columns:1fr}aside{border-right:0;border-bottom:1px solid #314035}}
</style></head><body><header><h1>Terraria — дополнительные нативные функции</h1><p>Отдельный каталог диапазонов libil2cpp.so, которым не сопоставлен адрес управляемого метода. Поиск и данные встроены в страницу; сеть не используется.</p><p class="warning">Статический C-псевдокод — результат анализа машинного кода, а не оригинальный исходный код. Категория указывает подтверждённое членство в таблице или символ; она не доказывает поведение функции. Неизвестные роли остаются неизвестными. Выполнение и корректность C не проверены этим аудитом.</p><div id="stats" class="stats"></div><p id="phase" class="muted"></p><div id="downloads" class="links"></div></header><main><aside><label for="q">Имя, адрес, категория или роль</label><input id="q" type="search" autocomplete="off" placeholder="0x5a0810, invoker, unknown…"><select id="category" aria-label="Категория"></select><select id="status" aria-label="Статус"><option value="">Все статусы</option><option value="decompiled">C-псевдокод доступен</option><option value="decompile_failed">Декомпиляция не удалась</option><option value="missing_function">Нет функции Ghidra</option><option value="export_error">Ошибка экспорта</option></select><p id="info" class="muted"></p><div id="results"></div><div id="pagination"><button id="prev">Назад</button><button id="next">Далее</button></div></aside><article id="detail"><p class="muted">Выберите функцию слева. На странице показываются сведения и ссылки на локальные C, ASM и вызовы; тела файлов не загружаются автоматически.</p></article></main><footer id="footer"></footer>
<script id="native-data" type="application/json">__DATA__</script><script>
'use strict';
const D=JSON.parse(document.getElementById('native-data').textContent),$=id=>document.getElementById(id),PAGE=150;
function el(tag,text){let e=document.createElement(tag);if(text!==undefined)e.textContent=text;return e}
function anchor(name,path){let a=el('a',name);a.href=path;return a}
function matches(row,words,category,status){let text=[row.name,row.address,row.category,...row.roles].join(' ').toLowerCase();return (!category||category===row.category)&&(!status||status===row.status)&&words.every(w=>text.includes(w))}
let page=0,selected=-1,hits=[];
for(const [n,label] of [[D.rows.length,'нативных диапазонов'],[D.counts.decompiled||0,'C-файлов'],[D.unknown,'неизвестных ролей']]){let box=el('div');box.className='stat';box.append(el('b',n.toLocaleString('ru-RU')),el('span',label));$('stats').append(box)}
$('category').append(new Option('Все категории',''));for(const c of D.categories)$('category').append(new Option(c,c));
for(const [name,path] of D.links)$('downloads').append(anchor(name,path));
if(D.phase){$('phase').textContent='Выходы за FDE: '+D.phase.associations+' структурно проверенных связей, '+D.phase.instructions+' дополнительных инструкций ('+D.phase.bytes+' байт); '+D.phase.candidates+' кандидатов расширенных тел. Эти счётчики не означают исправленную семантику или успешную декомпиляцию.'}
function search(){let words=$('q').value.trim().toLowerCase().split(/\s+/).filter(Boolean);hits=[];for(let i=0;i<D.rows.length;i++)if(matches(D.rows[i],words,$('category').value,$('status').value))hits.push(i);page=0;render()}
function render(){$('results').replaceChildren();let start=page*PAGE;for(const i of hits.slice(start,start+PAGE)){let r=D.rows[i],b=el('button');b.className='row';b.setAttribute('aria-current',String(i===selected));b.append(el('strong',r.name+' · '+r.address),el('small',r.category+' · '+r.status));b.onclick=()=>show(i);$('results').append(b)}$('info').textContent='Найдено: '+hits.length+' · '+(hits.length?start+1:0)+'–'+Math.min(start+PAGE,hits.length);$('prev').disabled=page===0;$('next').disabled=start+PAGE>=hits.length}
function show(i){selected=i;let r=D.rows[i],a=$('detail');a.replaceChildren();a.append(el('h2',r.name),el('p',r.address+' … '+r.end+' (конец не включён), '+r.size+' байт'),el('p','Категория: '+r.category+' · Роли: '+(r.roles.join(', ')||'неизвестны')),el('p','Статус: '+r.status+(r.message?' · '+r.message:'')),el('p','Профиль: '+r.profile+' · Модель: '+r.model));let links=el('div');links.className='links';for(const [label,path] of r.links)links.append(anchor(label,path));a.append(links,el('h3','Основания классификации'),el('pre',JSON.stringify(r.evidence,null,2)));location.hash='#range-'+r.address;render()}
$('q').oninput=search;$('category').onchange=search;$('status').onchange=search;$('prev').onclick=()=>{if(page){page--;render()}};$('next').onclick=()=>{if((page+1)*PAGE<hits.length){page++;render()}};
$('footer').textContent='Собрано: '+D.generated+' · SHA-256 журнала: '+D.coverage_sha256+' · SHA-256 независимого аудита: '+D.audit_sha256;
search();let initial=location.hash.match(/^#range-(0x[0-9a-f]+)$/);if(initial){let i=D.rows.findIndex(r=>r.address===initial[1]);if(i>=0)show(i)}
</script></body></html>'''


def build(lab, expected=29162):
    lab = lab.resolve()
    require(not lab.is_relative_to(ROOT), 'Game-derived output must remain outside repository')
    out = lab / 'native-ranges-pseudocode'
    summary_path = out / 'summary.json'
    audit_path = lab / 'native/native-ranges-export-audit.json'
    progress, summary, audit = load(out/'progress.json'), load(summary_path), load(audit_path)
    require(progress.get('finished') is True and progress.get('phase') == 'complete', 'Native export is unfinished')
    require(summary.get('finished') is True, 'Native summary is unfinished')
    require(audit.get('passed') is True and audit.get('partition_disjoint') is True, 'Independent native audit has not passed')
    require(audit.get('native_range_count') == expected, 'Audit range count mismatch')
    coverage_path = out / 'coverage.jsonl'
    classification_path = lab / 'native/unmapped-fde-classification.json'
    coverage_sha = digest(coverage_path)
    require(coverage_sha == summary.get('coverage_sha256') == audit['inputs']['coverage_sha256'], 'Coverage changed after audit')
    require(digest(summary_path) == audit['inputs']['summary_sha256'], 'Summary changed after audit')
    require(digest(classification_path) == audit['inputs']['classification_sha256'], 'Classification changed after audit')
    classification = load(classification_path)
    by_address = {r['address']: r for r in classification}
    require(len(by_address) == len(classification) == expected, 'Classification count/uniqueness mismatch')
    records = [json.loads(line) for line in coverage_path.read_text(encoding='utf-8').splitlines() if line.strip()]
    require(len(records) == expected and len({r['address'] for r in records}) == expected, 'Coverage count/uniqueness mismatch')
    rows = []
    for r in records:
        c = by_address.get(r['address'])
        require(c is not None and r['classification'] == c, 'Coverage classification differs')
        links = []
        for key, label in [('file', 'C-псевдокод'), ('asm_file', 'ASM TSV'), ('calls_file', 'Вызовы TSV')]:
            if r.get(key):
                links.append([label, bound(lab, out / r[key])])
        require(r['status'] != 'decompiled' or r.get('file'), 'Successful range lacks C artifact')
        rows.append(dict(address=r['address'], end=r['compiler_end_exclusive'], size=r['compiler_size'], name=r['function_name'], category=c['category'], roles=c.get('roles', []), status=r['status'], message=r.get('message', ''), profile=r['profile'], model=r['model'], evidence=c, links=links))
    rows.sort(key=lambda r: int(r['address'], 16))
    counts = dict(Counter(r['status'] for r in rows))
    require(counts == audit['status_counts'], 'Audit status counts differ')
    links = []
    for name, rel in [('Аудит нативных диапазонов', 'native/native-ranges-export-audit.json'), ('Классификация', 'native/unmapped-fde-classification.json'), ('Журнал экспорта', 'native-ranges-pseudocode/coverage.jsonl'), ('Основной атлас', 'index.html'), ('Отчёт второго этапа', 'PHASE2.ru.md'), ('JNI: статические привязки', 'android-native/static-bindings-20261013/static-bindings-summary.json'), ('ABI: проверенные контрольные функции', 'abi-control-probe-v4/attempt-1791904902576/verification.json')]:
        if (lab/rel).is_file():
            links.append([name, bound(lab, lab/rel)])
    phase = None
    phase_path = lab / 'native/flow-islands-summary.json'
    if phase_path.is_file():
        p = load(phase_path)
        fields = {'associations': 'structurally_verified_out_and_back_associations', 'instructions': 'unique_extra_instructions', 'bytes': 'unique_extra_bytes', 'candidates': 'extended_fde_candidates'}
        phase = {key: p[source] for key, source in fields.items()}
        require(all(type(n) is int and n >= 0 for n in phase.values()), 'Invalid phase2 counters')
        links.append(['Структурные связи вне FDE', bound(lab, phase_path)])
    data = dict(rows=rows, counts=counts, categories=sorted({r['category'] for r in rows}), unknown=audit['unknown_ranges'], links=links, phase=phase, coverage_sha256=coverage_sha, audit_sha256=digest(audit_path), generated=datetime.now(timezone.utc).isoformat())
    html = HTML.replace('__DATA__', safe_json(data))
    destination = lab / 'native-ranges.html'
    destination.write_text(html, encoding='utf-8', newline='\n')
    result = dict(path=str(destination), native_ranges=len(rows), status_counts=counts, linked_artifacts=sum(len(r['links']) for r in rows)+len(links), sha256=digest(destination), audit_sha256=data['audit_sha256'], coverage_sha256=coverage_sha, phase=phase)
    (lab/'native/native-explorer-build.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(build(args.lab), ensure_ascii=False, indent=2))
