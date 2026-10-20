"""Build a private, offline HTML explorer for the Terraria reverse-engineering lab.

Usage: python tools/build_terraria_explorer.py --lab C:/Temp/terraria-re-20261012
Rerun after pseudocode export to refresh body links. No server or network needed.
"""
import argparse
from collections import Counter
import hashlib
import json
import stat
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
RESOLVED_DIRECTORIES = {}


def read_jsonl(path):
    rows=[]
    with path.open(encoding='utf-8-sig') as f:
        for number,line in enumerate(f,1):
            if line.strip():
                try: rows.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ValueError(f'{path.name}:{number}: invalid JSONL') from exc
    return rows


def indexed(path):
    rows=read_jsonl(path)
    if any(r['index']!=i for i,r in enumerate(rows)):
        raise ValueError(f'{path.name}: expected consecutive unique indices')
    return rows


def bound_link(lab,path,must_exist=True):
    # Resolve directory junctions once per directory, rather than walking the
    # same Windows parents for each of 94k files. File reparse points still
    # receive a full resolution before the confinement check.
    for directory in (lab,path.parent):
        if directory not in RESOLVED_DIRECTORIES:RESOLVED_DIRECTORIES[directory]=directory.resolve()
    info=path.lstat() if path.exists() else None
    reparse=info is not None and bool(getattr(info,'st_reparse_tag',0))
    resolved=path.resolve() if reparse else RESOLVED_DIRECTORIES[path.parent]/path.name
    if not resolved.is_relative_to(RESOLVED_DIRECTORIES[lab]):
        raise ValueError('Link escapes private lab: '+str(path))
    if must_exist and (info is None or (not reparse and not stat.S_ISREG(info.st_mode)) or (reparse and not resolved.is_file())):
        raise ValueError('Link target missing: '+str(path))
    return quote(resolved.relative_to(RESOLVED_DIRECTORIES[lab]).as_posix(),safe='/')


def safe_json(value):
    return json.dumps(value,ensure_ascii=False,separators=(',',':')).replace('&','\\u0026').replace('<','\\u003c').replace('>','\\u003e').replace('\u2028','\\u2028').replace('\u2029','\\u2029')


HTML=r'''<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>Terraria · атлас кода APK</title><style>
:root{color-scheme:dark;--bg:#101612;--panel:#19221b;--line:#314035;--text:#e8efe9;--muted:#a8b8ac;--accent:#b5ed8d;--code:#122018}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,sans-serif}header{padding:28px 32px 20px;border-bottom:1px solid var(--line)}h1{margin:0 0 8px;font-size:27px;font-weight:650;letter-spacing:-.5px}.eyebrow{color:var(--accent);font-size:12px;letter-spacing:2px;text-transform:uppercase}.intro{max-width:1050px;color:var(--muted);margin:8px 0}.stats{display:flex;gap:12px;flex-wrap:wrap;margin-top:18px}.stat{background:var(--panel);border:1px solid var(--line);padding:10px 16px;border-radius:9px}.stat b{display:block;font-size:22px;color:var(--accent)}.stat span{font-size:12px;color:var(--muted)}nav{display:flex;flex-wrap:wrap;gap:7px;padding:17px 32px;border-bottom:1px solid var(--line)}button,a{color:var(--accent)}button,select,input{font:inherit}button{background:var(--panel);border:1px solid var(--line);border-radius:7px;padding:6px 11px;cursor:pointer}button:hover{border-color:var(--accent)}a{text-underline-offset:3px}main{display:grid;grid-template-columns:minmax(300px,34%) 1fr;min-height:70vh}aside{border-right:1px solid var(--line);padding:20px;min-width:0}article{padding:24px 30px;min-width:0}.filters{display:grid;gap:9px;margin-bottom:17px}input,select{width:100%;padding:10px;background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:7px}input:focus{outline:1px solid var(--accent)}.row{display:block;width:100%;text-align:left;padding:11px 10px;margin:5px 0;overflow-wrap:anywhere}.row strong{font-weight:550}.row small{display:block;color:var(--muted);font-size:12px}.row[aria-current=true]{border-color:var(--accent);background:#233322}.muted{color:var(--muted)}.small{font-size:12px}.type-title{font-size:22px;overflow-wrap:anywhere;margin:0 0 8px}.badge{display:inline-block;background:#27372a;border:1px solid #405943;color:var(--accent);padding:2px 7px;border-radius:5px;font-size:12px}.meta{display:flex;gap:14px;flex-wrap:wrap;color:var(--muted);font-size:13px;margin:14px 0}.links{display:flex;gap:14px;flex-wrap:wrap;margin:14px 0;font-size:13px}.warning{background:#332c1b;border:1px solid #6c5b30;color:#e8d7a4;padding:12px 15px;border-radius:8px;margin:16px 0}details{border-top:1px solid var(--line);padding:14px 0}summary{cursor:pointer;color:var(--accent);font-weight:600}table{border-collapse:collapse;width:100%;font-size:12px;margin:12px 0;table-layout:auto}td,th{border-bottom:1px solid #29362d;padding:8px;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{color:var(--muted);font-weight:500}code{font:12px/1.6 ui-monospace,Consolas,monospace;overflow-wrap:anywhere}.member{padding:12px 0;border-bottom:1px solid #2b382f;scroll-margin-top:12px}.member:target{background:#233322}.member .links{margin:5px 0}.variants{margin:8px 0 0 16px;color:var(--muted)}.variants summary{font-size:12px;color:var(--muted)}footer{border-top:1px solid var(--line);padding:20px 32px;color:var(--muted);font-size:12px}.empty{padding:40px 0;color:var(--muted)}.method-list{margin-top:10px}.search-info{margin-bottom:10px}.toolbar{display:flex;gap:9px;align-items:center;flex-wrap:wrap}.toolbar button{font-size:12px}@media(max-width:850px){main{grid-template-columns:1fr}aside{border-right:0;border-bottom:1px solid var(--line)}article{padding:20px}header,nav{padding-left:20px;padding-right:20px}.stats{gap:7px}.stat{padding:8px 10px}.stat b{font-size:18px}}
</style></head><body><header><div class="eyebrow">Статический разбор · Android / ARM64 / IL2CPP 31</div><h1>Terraria — атлас кода APK</h1><p class="intro">Поиск по полному каталогу типов, сигнатур и нативных адресов из предоставленного APK. Все данные встроены в страницу; подключение к сети не требуется.</p><p class="intro small">Это восстановленные объявления и доступный C-псевдокод. Оригинальные тела C#, комментарии разработчиков и имена локальных переменных не восстановлены.</p><div id="stats" class="stats"></div></header><nav id="nav" aria-label="Основные подсистемы"></nav><main><aside><div class="filters"><label for="q">Поиск типов и членов</label><input id="q" type="search" placeholder="Player, Spawn, respawnTimer, WorldFile…" autocomplete="off"><select id="assembly" aria-label="Сборка"></select><select id="scope" aria-label="Область имён"><option value="all">Все пространства имён</option><option value="terraria">Terraria и вложенные пространства</option><option value="game">Assembly-CSharp.dll</option></select><select id="mode" aria-label="Объекты поиска"><option value="all">Типы, методы и поля</option><option value="types">Только типы</option><option value="methods">Только методы</option><option value="fields">Только поля</option></select></div><div id="results-info" class="small muted search-info"></div><div id="results"></div><button id="more" hidden>Показать ещё 150</button></aside><article id="detail"><div class="empty">Выберите тип слева или откройте подсистему сверху. Поиск учитывает полные сигнатуры методов и типы полей.</div></article></main><footer id="footer"></footer>
<script id="catalog-data" type="application/json">__DATA__</script>
<script>
'use strict';
const D=JSON.parse(document.getElementById('catalog-data').textContent);
const $=id=>document.getElementById(id), fmt=n=>n.toLocaleString('ru-RU');
function node(tag,text,cls){let e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e}
function link(text,path){let a=node('a',text);a.href=path;return a}
function para(text,cls){return node('p',text,cls)}
const TYPES=D.types,METHODS=D.methods,FIELDS=D.fields;
const indexes={types:TYPES.map(t=>t[0].toLowerCase()),methods:METHODS.map(m=>m[2].toLowerCase()),fields:FIELDS.map(f=>(f[1]+' '+f[2]).toLowerCase())};
let selected=-1,limit=150,hits=[];
for(const [n,label] of [[TYPES.length,'типов'],[METHODS.length,'сигнатур методов'],[FIELDS.length,'полей'],[D.counts.implementation_addresses,'адресов реализаций'],[D.counts.pseudocode_available,'доступных C-файлов']]){let s=node('div',undefined,'stat');s.append(node('b',fmt(n)),node('span',label));$('stats').append(s)}
for(const [label,target] of D.navigation){let b=node('button',label);b.onclick=()=>{let i=TYPES.findIndex(t=>t[0]===target);if(i>=0)showType(i);else{$('q').value=target;$('mode').value='all';search()}};$('nav').append(b)}
$('assembly').append(new Option('Все сборки',''));for(const a of D.assemblies)$('assembly').append(new Option(a,a));
function allowed(i){let t=TYPES[i];return (!$('assembly').value||t[2]===$('assembly').value)&&($('scope').value==='all'||($('scope').value==='terraria'&&t[0].startsWith('Terraria.'))||($('scope').value==='game'&&t[2]==='Assembly-CSharp.dll'))}
function search(){let q=$('q').value.trim().toLowerCase(),words=q.split(/\s+/).filter(Boolean),mode=$('mode').value;hits=[];limit=150;let match=s=>words.every(w=>s.includes(w));if(mode==='all'||mode==='types')for(let i=0;i<TYPES.length;i++)if(allowed(i)&&match(indexes.types[i]))hits.push(['t',i,i]);if(q&&(mode==='all'||mode==='methods'))for(let i=0;i<METHODS.length;i++)if(allowed(METHODS[i][0])&&match(indexes.methods[i]))hits.push(['m',i,METHODS[i][0]]);if(q&&(mode==='all'||mode==='fields'))for(let i=0;i<FIELDS.length;i++)if(allowed(FIELDS[i][0])&&match(indexes.fields[i]+' '+indexes.types[FIELDS[i][0]]))hits.push(['f',i,FIELDS[i][0]]);renderResults()}
function renderResults(){$('results').replaceChildren();$('results-info').textContent=`Найдено: ${fmt(hits.length)} · показано ${fmt(Math.min(limit,hits.length))}`;for(const [kind,i,ti] of hits.slice(0,limit)){let t=TYPES[ti],b=node('button',undefined,'row');b.setAttribute('aria-current',String(ti===selected));b.append(node('strong',kind==='t'?t[0]:kind==='m'?METHODS[i][2]:FIELDS[i][2]+' '+t[0]+'::'+FIELDS[i][1]),node('small',(kind==='t'?'Тип':kind==='m'?'Метод':'Поле')+' · '+t[2]));b.onclick=()=>showType(ti,kind==='m'?'method-'+i:kind==='f'?'field-'+i:null);$('results').append(b)}$('more').hidden=limit>=hits.length}
function section(title,count,open=false){let d=node('details');d.open=open;d.append(node('summary',title+' · '+fmt(count)));return d}
function bodyLink(parent,address){let coverage=D.coverage[address];if(coverage&&coverage[0]){parent.append(link('Открыть C-псевдокод',coverage[0]));if(coverage[2])parent.append(node('span',coverage[2],'small muted'))}else parent.append(node('span',coverage?'Тело не экспортировано: '+coverage[1]:'C-псевдокод пока отсутствует','small muted'))}
function showType(i,focus){selected=i;let t=TYPES[i],article=$('detail');article.replaceChildren();article.append(node('h2',t[0],'type-title'),node('span',t[2],'badge'));let meta=node('div',undefined,'meta');meta.append(node('span','Тип #'+i),node('span','Родитель: '+(t[3]||'не указан')),node('span','Размер экземпляра: '+(t[4]??'неизвестен')+' байт'),node('span','Static / thread static: '+(t[5]??'?')+' / '+(t[6]??'?')+' байт'));article.append(meta);let l=node('div',undefined,'links');l.append(link('Типы JSONL',D.links.types),link('Методы CSV',D.links.methods),link('Поля CSV',D.links.fields));if(D.outlines[t[2]])l.append(link('Объявления сборки (.symbols.cs)',D.outlines[t[2]]));article.append(l);article.append(node('div','Файлы .symbols.cs содержат объявления в комментариях и не являются исполняемым C#. Отсутствующее тело не заменяется заглушкой. C-псевдокод отражает машинный код ARM64; его типизация и границы могут содержать ошибки анализа.','warning small'));
let fd=section('Поля',t[8]),table=node('table'),head=node('tr');for(let h of ['Поле','Тип','Смещение / область'])head.append(node('th',h));table.append(head);for(let j=t[7];j<t[7]+t[8];j++){let f=FIELDS[j],r=node('tr');r.id='field-'+j;r.append(node('td',f[1]),node('td',f[2]),node('td',(f[3]??'неизвестно')+' · '+f[4]));table.append(r)}fd.append(table);article.append(fd);
let md=section('Методы',t[10],true);md.append(para('Каждый generic-вариант имеет собственные аргументы и доступный нативный адрес. Абстрактные объявления могут не иметь тела.','small muted'));let list=node('div',undefined,'method-list');for(let j=t[9];j<t[9]+t[10];j++){let m=METHODS[j],box=node('div',undefined,'member');box.id='method-'+j;box.append(node('code',m[2]));let ml=node('div',undefined,'links');ml.append(node('span','#'+j+' · '+(m[3]||((m[4]&1024)?'abstract · тело не требуется':'прямого адреса нет')),'small muted'));if(m[3])bodyLink(ml,m[3]);box.append(ml);let variants=D.variants[j];if(variants){let vd=section('Generic-варианты',variants.length);vd.className='variants';for(let v of variants){let r=node('div',undefined,'member');r.append(node('code',(v[1]?'Тип <'+v[1]+'> · ':'')+(v[2]?'Метод <'+v[2]+'> · ':'')+(v[0]||'адрес отсутствует')));let vl=node('div',undefined,'links');if(v[0])bodyLink(vl,v[0]);else vl.append(node('span','Нет нативного указателя','small muted'));r.append(vl);vd.append(r)}box.append(vd)}else if(!m[3]&&!(m[4]&1024))box.append(para('Нативная реализация для этого объявления не сопоставлена.','small muted'));list.append(box)}md.append(list);article.append(md);
let pd=section('Свойства',t[12]);for(let j=t[11];j<t[11]+t[12];j++){let p=D.properties[j],r=node('div',undefined,'member');r.append(node('code',(p[2]||'тип не определён')+' '+p[1]));let pl=node('div',undefined,'links');for(let [caption,idx] of [['get',p[3]],['set',p[4]]])if(idx>=0){let a=node('a',caption+' #'+idx);a.href='#method-'+idx;a.onclick=e=>{e.preventDefault();showType(i,'method-'+idx)};pl.append(a)}r.append(pl);pd.append(r)}article.append(pd);
let ed=section('События',t[14]);for(let j=t[13];j<t[13]+t[14];j++){let e=D.events[j];ed.append(para(e[2]+' '+e[1],'small'))}article.append(ed);renderResults();location.hash='type-'+i+(focus?'/'+focus:'');if(focus){let target=$(focus);if(target){for(let p=target.parentElement;p;p=p.parentElement)if(p.tagName==='DETAILS')p.open=true;target.scrollIntoView({block:'center'})}}else article.scrollIntoView({block:'start'})}
let timer; $('q').oninput=()=>{clearTimeout(timer);timer=setTimeout(search,120)};for(const id of ['assembly','scope','mode'])$(id).onchange=search;$('more').onclick=()=>{limit+=150;renderResults()};
let foot=$('footer');foot.append(para('APK SHA-256: '+D.apk_sha256),para('Каталог: '+D.generated_at+' · Свежесть C-файлов соответствует моменту сборки этой страницы. Для обновления повторно запустите tools/build_terraria_explorer.py.'));let fl=node('div',undefined,'links');for(const [name,path] of Object.entries(D.downloads))fl.append(link(name,path));foot.append(fl);search();let initial=location.hash.match(/^#type-(\d+)(?:\/(method-\d+|field-\d+))?$/);if(initial&&+initial[1]<TYPES.length)showType(+initial[1],initial[2]);
</script></body></html>'''


def main():
    from datetime import datetime,timezone
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--lab',type=Path,required=True)
    args=ap.parse_args()
    lab=args.lab.resolve()
    if lab.is_relative_to(ROOT): raise ValueError('Explorer data must stay outside source repository')
    md=lab/'metadata'
    raw={name:indexed(md/(name+'.jsonl')) for name in ['types','methods','fields','properties','events']}
    types=raw['types'];methods=raw['methods'];fields=raw['fields']
    if len(types)!=9384 or len(methods)!=65580 or len(fields)!=66527:
        raise ValueError('Catalog identity/count differs from the inspected Terraria build')
    for kind in ['methods','fields','properties','events']:
        if any(not 0<=r['owner_type_index']<len(types) for r in raw[kind]):
            raise ValueError(f'{kind}: owner outside type table')
    ts=[[r['full_name'],r['namespace'],r['assembly'],r.get('parent_type_name'),r.get('native_instance_size'),r.get('native_static_fields_size'),r.get('native_thread_static_fields_size'),r['field_start'],r['field_count'],r['method_start'],r['method_count'],r['property_start'],r['property_count'],r['event_start'],r['event_count']] for r in types]
    ms=[[r['owner_type_index'],r['name'],r['display_signature'],r.get('native_address'),r['flags']] for r in methods]
    scopes={'instance_storage':'экземпляр','static_storage':'статическое хранилище','special_or_unassigned':'особое / не назначено'}
    fs=[[r['owner_type_index'],r['name'],r.get('type_name') or '?',r.get('native_field_offset_hex'),scopes.get(r.get('native_field_offset_scope'),'неизвестно')] for r in fields]
    ps=[[r['owner_type_index'],r['name'],r.get('type_name_from_getter'),r['get_method_index'],r['set_method_index']] for r in raw['properties']]
    es=[[r['owner_type_index'],r['name'],r.get('type_name') or '?'] for r in raw['events']]
    variants={}
    for r in json.loads((lab/'native/generic-method-addresses.json').read_text(encoding='utf-8')):
        i=r['method_index']
        if not 0<=i<len(methods): raise ValueError('Generic method reference outside table')
        if r['image']!=methods[i]['assembly'] or r['name']!=methods[i]['name'] or r['type']!=methods[i]['owner_type']:
            raise ValueError('Generic map method identity does not match metadata catalog')
        variants.setdefault(i,[]).append([r['address'],', '.join(r['class_arguments']),', '.join(r['method_arguments'])])
    addresses={m[3] for m in ms if m[3]}|{v[0] for vs in variants.values() for v in vs if v[0]}
    coverage={};coverage_counts=Counter();stream_partial=0
    coverage_path=lab/'pseudocode/coverage.jsonl'
    if coverage_path.exists():
        lines=coverage_path.read_text(encoding='utf-8-sig').splitlines()
        for i,line in enumerate(lines):
            if not line.strip(): continue
            try: r=json.loads(line)
            except json.JSONDecodeError:
                if i==len(lines)-1: stream_partial+=1;continue
                raise
            address=r['address'].lower();status=r.get('status','unknown');file=r.get('file');href=None
            if address not in addresses: raise ValueError('Pseudocode coverage address not in native catalog: '+address)
            if status=='decompiled' and file:
                candidate=lab/'pseudocode'/file
                # Never allow absolute paths, traversal or missing files into hrefs.
                if candidate.is_file(): href=bound_link(lab,candidate)
                else: status='decompiled_file_missing'
            coverage[address]=[href,status,r.get('message') or '']
            coverage_counts[status]+=1
    typed_audit=lab/'pseudocode-v4-hard/audit.json'
    if typed_audit.is_file():
        audit=json.loads(typed_audit.read_text(encoding='utf-8'))
        if audit.get('passed') is not True:raise ValueError('Typed candidate audit failed')
        for item in audit['files']:
            address=item['address'];candidate=lab/'pseudocode-v4-hard'/item['file']
            if hashlib.sha256(candidate.read_bytes()).hexdigest()!=item['sha256']:raise ValueError('Typed candidate file changed')
            if address not in coverage or coverage[address][0]:raise ValueError('Typed candidate does not fill a baseline gap')
            coverage_counts[coverage[address][1]]-=1;coverage_counts['decompiled_abi_v4_candidate']+=1
            coverage[address]=[bound_link(lab,candidate),'decompiled_abi_v4_candidate','Модель ABI v4: кандидат; семантическая корректность не проверена.']
    links=dict(types=bound_link(lab,md/'types.jsonl'),methods=bound_link(lab,md/'methods.csv'),fields=bound_link(lab,md/'fields.csv'))
    outlines={p.name.removesuffix('.symbols.cs'):bound_link(lab,p) for p in (md/'nonexecutable-symbol-outlines').glob('*.symbols.cs')}
    downloads={label:bound_link(lab,lab/path) for label,path in [('Типы CSV','metadata/types.csv'),('Параметры CSV','metadata/parameters.csv'),('Нативные адреса CSV','native/method-addresses.csv'),('Generic-адреса CSV','native/generic-method-addresses.csv'),('Итог каталога JSON','metadata/catalog-summary.json')]}
    if coverage_path.exists(): downloads['Покрытие C-псевдокодом JSONL']=bound_link(lab,coverage_path)
    for label,relative in [('Дополнительный нативный код','native-ranges.html'),('Дополнительный отчёт','PHASE2.ru.md'),('JNI: 160 статических связей','android-native/jni-remaining-20261013/combined-static-bindings.json'),('Графы сложных функций','hard-functions-ir/progress.json')]:
        if (lab/relative).is_file(): downloads[label]=bound_link(lab,lab/relative)
    summary=json.loads((md/'catalog-summary.json').read_text(encoding='utf-8'))
    sha=summary.get('apk_sha256') or summary.get('identity',{}).get('apk_sha256') or 'см. catalog-summary.json'
    nav=[('Main','Terraria.Main'),('Игрок','Terraria.Player'),('Предметы','Terraria.Item'),('NPC','Terraria.NPC'),('Снаряды','Terraria.Projectile'),('Генерация мира','Terraria.WorldGen'),('Сеть','Terraria.NetMessage'),('Пакеты','Terraria.MessageBuffer'),('Миры / IO','Terraria.IO.WorldFile'),('Файлы игроков','Terraria.IO.PlayerFileData'),('Рецепты','Terraria.Recipe'),('Управление','Terraria.GameInput.PlayerInput'),('Интерфейс','Terraria.UI.UserInterface')]
    counts=dict(types=len(ts),methods=len(ms),fields=len(fs),properties=len(ps),events=len(es),generic_variants=sum(map(len,variants.values())),implementation_addresses=len(addresses),pseudocode_available=sum(bool(c[0]) for c in coverage.values()),coverage_rows=len(coverage),coverage_status=dict(coverage_counts),partial_stream_records_skipped=stream_partial)
    data=dict(types=ts,methods=ms,fields=fs,properties=ps,events=es,variants=variants,coverage=coverage,counts=counts,assemblies=sorted({r['assembly'] for r in types}),navigation=nav,links=links,outlines=outlines,downloads=downloads,apk_sha256=sha,generated_at=datetime.now(timezone.utc).isoformat(timespec='seconds'))
    payload=safe_json(data)
    if '<' in payload or '>' in payload or '&' in payload or json.loads(payload)!=json.loads(json.dumps(data)):
        raise ValueError('Inline JSON escaping/roundtrip failed')
    if HTML.count('__DATA__')!=1: raise ValueError('Invalid explorer template')
    output=lab/'index.html';output.write_text(HTML.replace('__DATA__',payload),encoding='utf-8')
    all_links=list(links.values())+list(outlines.values())+list(downloads.values())+[c[0] for c in coverage.values() if c[0]]
    build=dict(output=str(output),html_bytes=output.stat().st_size,html_sha256=hashlib.sha256(output.read_bytes()).hexdigest(),counts=counts,validated_local_links=len(all_links),navigation_targets_found=sum(any(t['full_name']==target for t in types) for _,target in nav),navigation_targets_total=len(nav),checks=['all metadata indices consecutive','owners in bounds','build-specific counts validated','generic method references in bounds','coverage addresses in native catalog','all included hrefs stay inside private lab and exist','inline JSON escaped and roundtrips without losing data','no external assets/frameworks/network fetches'])
    (lab/'explorer-build.json').write_text(json.dumps(build,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(build,ensure_ascii=False,indent=2))


if __name__=='__main__': main()
