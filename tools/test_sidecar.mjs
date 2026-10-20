// Host checks for binding/loss prevention, independent of the Android ABI.
import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
const context=vm.createContext({});
vm.runInContext(fs.readFileSync(new URL('../runtime/content-sidecar.js',import.meta.url),'utf8'),context);
const api=context.TMALSidecar,a='a'.repeat(64),b='b'.repeat(64),c='c'.repeat(64);
const placeholder={type:3507,damage:5,stack:1,prefix:0,favorite:false};
const item={key:api.KEY,slot:0,placeholder,data:{version:1}};
const first=api.next(null,null,a,item);
assert.equal(api.bind(first,a,placeholder).key,api.KEY);
assert.equal(api.known(item),true);
assert.throws(()=>api.bind(first,b,placeholder),/hash mismatch/);
assert.throws(()=>api.bind(first,a,{...placeholder,stack:2}),/Placeholder mismatch/);
assert.throws(()=>api.next(first,b,c,item),/Stale sidecar/);
const disabled=api.next(first,a,b,api.bind(first,a,placeholder));
assert.equal(disabled.generation,2);
assert.equal(disabled.items[0].key,api.KEY);
assert.equal(disabled.playerSha256,b);
const missing={...item,key:'MissingMod/MissingItem',data:{version:11,opaque:'retained'}};
const unknown=api.next(null,null,a,missing);
assert.equal(api.known(api.bind(unknown,a,placeholder)),false);
const retained=api.next(unknown,a,b,api.bind(unknown,a,placeholder));
assert.equal(retained.items[0].data.opaque,'retained');
assert.equal(retained.items[0].key,missing.key);
for(const bad of [
    {...first,format:'pc-tplr'}, {...first,profile:'another-profile'}, {...first,playerSha256:'bad'},
    {...first,generation:0}, {...first,items:[]},
    {...first,items:[{...item,slot:58}]}, {...first,items:[{...item,key:'../../Other'}]},
    {...first,items:[{...item,placeholder:{...placeholder,type:6196}}]},
    {...first,items:[{...item,data:{blob:'x'.repeat(4096)}}]}
]) assert.throws(()=>api.validate(bad));
console.log('Sidecar checks passed: hash/slot/template guards, disabled and unknown content retention.');
