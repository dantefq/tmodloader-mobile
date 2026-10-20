'use strict';
// Bootstrap contract tests with a fake Frida API; no Mono/game code is executed.
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const path=require('node:path'),root=path.resolve(__dirname,'..');
function fixture(options={}) {
    const calls=[];
    const nullPointer={isNull:()=>true};
    const domain={isNull:()=>false},image={isNull:()=>false};
    const context={
        Process:{pointerSize:8,getModuleByName:()=>({getExportByName:name=>name})},
        Memory:{allocUtf8String:s=>s,alloc:()=>({writePointer(){}})},
        NativeFunction:function(name) {return (...args)=>{
            calls.push({name,args});
            if(name==='mono_get_root_domain')return options.external?domain:nullPointer;
            if(name==='setenv')return options.envFailure?1:0;
            if(name==='mono_jit_init_version')return options.initFailure?nullPointer:domain;
            if(name==='mono_domain_assembly_open')return options.assemblyFailure?nullPointer:domain;
            if(name==='mono_assembly_get_image')return image;
            return domain;
        };},
        CModule:function(){return {};}
    };
    vm.createContext(context);
    function load(name){vm.runInContext(fs.readFileSync(path.join(root,'runtime',name),'utf8'),context);}
    load('mono-runtime.js');
    return {context,calls,load,domain,image};
}
const f=fixture();
f.load('managed-host.js');f.load('managed-time-host.js');
f.context.TMALTime.initialize('/lab/managed');
f.context.TMALManaged.initialize('/lab/managed');
const shared=f.context.TMALMonoRuntime.acquire('/lab/managed');
assert.equal(shared.domain,f.domain);assert.equal(shared.image,f.image);
assert.equal(f.calls.filter(c=>c.name==='mono_jit_init_version').length,1);
assert.equal(f.calls.filter(c=>c.name==='mono_domain_assembly_open').length,1);
assert.ok(f.calls.findIndex(c=>c.name==='setenv')<f.calls.findIndex(c=>c.name==='mono_jit_init_version'));
assert.throws(()=>f.context.TMALMonoRuntime.acquire('/other/managed'),/root differs/);
assert.throws(()=>f.context.TMALTime.initialize('/lab/managed'),/twice/);
for(const option of ['envFailure','initFailure','assemblyFailure','external']) {
    const bad=fixture({[option]:true});
    assert.throws(()=>bad.context.TMALMonoRuntime.acquire('/lab/managed'));
    const count=bad.calls.length;
    assert.throws(()=>bad.context.TMALMonoRuntime.acquire('/lab/managed'),/bootstrap failed/);
    assert.equal(bad.calls.length,count,'failed bootstrap must never retry native initialization');
}
for(const value of ['',null,'relative','/lab/../managed','/lab/managed/','/lab\0x']) {
    const bad=fixture();
    assert.throws(()=>bad.context.TMALMonoRuntime.acquire(value),/Invalid/);
    assert.equal(bad.calls.length,0);
}
const reversed=fixture();reversed.load('managed-host.js');reversed.load('managed-time-host.js');
reversed.context.TMALManaged.initialize('/lab/managed');reversed.context.TMALTime.initialize('/lab/managed');
assert.equal(reversed.calls.filter(c=>c.name==='mono_jit_init_version').length,1);
console.log('Shared Mono bootstrap: both host orders, domain/image reuse, root guard and terminal failures passed (mock API only).');
