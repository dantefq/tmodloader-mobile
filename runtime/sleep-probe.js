'use strict';
const ROOT='/data/user/0/tm.loader.managedprobe/files/managed';
function log(message) {
    console.log('[TMAL] '+message);
    const write=new NativeFunction(Process.getModuleByName('liblog.so').getExportByName('__android_log_write'),'int',['int','pointer','pointer']);
    write(4,Memory.allocUtf8String('TMAL'),Memory.allocUtf8String(message));
}
setTimeout(()=>{
    try {
        const contract=JSON.parse(File.readAllText(ROOT+'/demo-contract.json'));
        if(contract.mode!=='time-rate'||contract.mod!=='ChangeSleepTime'||contract.version!=='2025.3.6.1')throw Error('Unexpected time contract');
        TMALTime.initialize(ROOT);
        const cases=[
            {name:'awake',input:[0,1,0,1,5],expected:[1,1,1]},
            {name:'all-sleeping',input:[0,1,1,1,5],expected:[5,5,5]},
            {name:'partially-sleeping',input:[0,2,1,1,5],expected:[1,1,1]},
            {name:'config-ten',input:[0,1,1,1,10],expected:[10,10,10]},
            {name:'menu',input:[1,1,1,1,5],expected:[1,1,1]},
            {name:'freeze',input:[2,1,1,1,5],expected:[0,0,0]},
            {name:'menu-freeze',input:[3,1,1,1,5],expected:[1,1,1]},
            {name:'creative-three',input:[0,1,1,3,5],expected:[15,15,15]},
            {name:'config-zero',input:[0,1,1,1,0],expected:[0,0,0]},
            {name:'time-only-clamp',input:[0,1,1,1000,100],expected:[86400,100000,100000]}
        ];
        for(const row of cases) {
            row.actual=TMALTime.evaluate(...row.input);
            if(JSON.stringify(row.actual)!==JSON.stringify(row.expected))throw Error('Time result differs: '+row.name);
        }
        const handlers=TMALTime.handlers(),selfTest=TMALTime.selfTest(),gcStressBytes=TMALTime.stress();
        if(handlers!==1||selfTest!==10||gcStressBytes!==16777216)throw Error('Time host self-check differs');
        let lifecycleChecks=0,contentChecks=0;
        if(contract.api_revision!==undefined) {
            if(contract.api_revision!=='managed-foundation-v2'||contract.lifecycle_check_count!==7||contract.content_check_count!==14)
                throw Error('Unified time contract differs');
            lifecycleChecks=TMALTime.lifecycle();contentChecks=TMALTime.content();
            if(lifecycleChecks!==7||contentChecks!==14)throw Error('Unified lifecycle/content checks failed');
        }
        const afterGc=TMALTime.evaluate(0,1,1,1,5);
        if(JSON.stringify(afterGc)!=='[5,5,5]')throw Error('Post-GC result differs');
        const report={status:'original-local-mod-executed-in-isolated-android-probe',mod:contract.mod,version:contract.version,
            mod_dll_sha256:contract.mod_dll_sha256,dll_recompiled_or_patched:false,cases,handlers,selfTest,gcStressBytes,afterGc,
            api_revision:contract.api_revision,lifecycleChecks,contentChecks,pc_item_dll_sha256:contract.item_contract?.mod_dll_sha256,
            runtime:'Mono Android ARM64 8.0.31 interpreter',threadAttachDetach:true,game_accessed:false,in_game_verified:false,general_tmod_support:false};
        File.writeAllText(ROOT+'/result.json',JSON.stringify(report));
        log('SLEEP_PROBE_OK '+JSON.stringify(report));
    } catch(error) {log('SLEEP_PROBE_FAILED '+error.stack);}
},1000);
