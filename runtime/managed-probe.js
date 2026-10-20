'use strict';
const ROOT='/data/user/0/tm.loader.managedprobe/files/managed';
function log(message) {
    console.log('[TMAL] '+message);
    const write=new NativeFunction(Process.getModuleByName('liblog.so').getExportByName('__android_log_write'),'int',['int','pointer','pointer']);
    write(4,Memory.allocUtf8String('TMAL'),Memory.allocUtf8String(message));
}
setTimeout(()=>{
    try {
        TMALManaged.initialize(ROOT);
        const contract=TMALManaged.contract(ROOT);
        const checks=[];
        for (const [id,input,expected] of contract.checks) {
            const actual=TMALManaged.damage(id,input);
            if (actual!==expected) throw Error('C# result differs');
            checks.push({id,input,expected,actual});
        }
        const name=TMALManaged.name(contract.name_test_id||3507);
        if (name!==contract.name) throw Error('C# string result differs');
        const handlers=TMALManaged.handlers();
        if (handlers!==contract.handler_count) throw Error('Own handler count differs');
        const gcStressBytes=TMALManaged.stress();
        if (gcStressBytes!==16777216) throw Error('GC stress result differs');
        let foundationChecks=null;
        if(contract.api_revision!==undefined) {
            if(contract.api_revision!=='managed-foundation-v1'||contract.foundation_check_count!==8)throw Error('Unexpected foundation contract');
            foundationChecks=TMALManaged.foundationChecks();
            if(foundationChecks!==8)throw Error('Foundation probe failed');
        }
        const report={status:'managed-assembly-executed',mode:contract.mode,handlers,runtime:'Mono Android ARM64 8.0.31 interpreter',checks,name,gcStressBytes,threadAttachDetach:true,own_tmod_executed:['global-item','mod-item'].includes(contract.mode),arbitrary_tmod_supported:false};
        report.api_revision=contract.api_revision||null;report.foundationChecks=foundationChecks;
        File.writeAllText(ROOT+'/result.json',JSON.stringify(report));
        log('MANAGED_PROBE_OK '+JSON.stringify(report));
    } catch(error) {log('MANAGED_PROBE_FAILED '+error.stack);}
},1000);
