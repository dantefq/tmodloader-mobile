import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import path from 'node:path';
const lab=process.argv[2];
if(!lab)throw new Error('Usage: node smoke_terraria_explorer.mjs private-lab');
const file=path.resolve(lab,'index.html');
const html=fs.readFileSync(file,'utf8');
const payload=html.match(/<script id="catalog-data" type="application\/json">([\s\S]*?)<\/script>/)[1];
assert(!/[<>&]/.test(payload),'embedded payload contains unsafe HTML characters');
const source=html.match(/<script>\s*([\s\S]*?)<\/script>/)[1];
const ids=new Map();
class E{
 constructor(tag){this.tagName=tag.toUpperCase();this.children=[];this.textContent='';this.value='';this.open=false}
 set id(value){this._id=value;ids.set(value,this)} get id(){return this._id}
 append(...items){for(const item of items){if(typeof item==='object')item.parentElement=this;this.children.push(item)}}
 replaceChildren(...items){this.children=[];this.append(...items)}
 setAttribute(key,value){this[key]=value}
 scrollIntoView(){}
}
for(const id of ['stats','nav','assembly','scope','mode','q','results','results-info','more','detail','footer','catalog-data']){let e=new E('div');e.id=id}
ids.get('catalog-data').textContent=payload;
ids.get('scope').value='all';ids.get('mode').value='all';
const context=vm.createContext({document:{getElementById:id=>ids.get(id),createElement:tag=>new E(tag)},Option:class extends E{constructor(text,value){super('option');this.textContent=text;this.value=value}},location:{hash:''},setTimeout:f=>{f();return 1},clearTimeout:()=>{},console,fetch:()=>{throw new Error('Network forbidden')}});
vm.runInContext(source,context,{filename:'explorer-inline.js'});
assert.equal(vm.runInContext('TYPES.length',context),9384);
assert.equal(ids.get('results').children.length,150);
vm.runInContext("$('q').value='Terraria.Player::KillMe';search()",context);
assert(ids.get('results').children.length>0,'exact method signature search failed');
vm.runInContext("showType(TYPES.findIndex(t=>t[0]==='Terraria.Player'))",context);
assert(ids.get('detail').children.some(e=>e.textContent==='Terraria.Player'),'Player view failed');
vm.runInContext("$('q').value='respawnTimer';$('mode').value='fields';search()",context);
assert(ids.get('results').children.length>0,'field search failed');
vm.runInContext("$('assembly').value='System.Xml.dll';$('mode').value='types';$('q').value='';search()",context);
assert(vm.runInContext("hits.every(h=>TYPES[h[2]][2]==='System.Xml.dll')",context),'assembly filter failed');
vm.runInContext("$('assembly').value='';$('scope').value='terraria';search()",context);
assert(vm.runInContext("hits.every(h=>TYPES[h[2]][0].startsWith('Terraria.'))",context),'Terraria scope failed');
assert.equal(ids.get('nav').children.length,13);
const result={status:'passed',checks:['JS parses and initializes','initial result pagination','full signature method search','Player type view','field search','assembly filter','Terraria namespace filter','13 subsystem shortcuts','inline payload escaping'],html_bytes:Buffer.byteLength(html)};
result.scope='Node DOM shim functional smoke; visual browser rendering was not verified.';
fs.writeFileSync(path.resolve(lab,'explorer-smoke.json'),JSON.stringify(result,null,2));
console.log(JSON.stringify(result,null,2));
