'use strict';
// Isolated app only. Original callbacks and the native JSON bridge are tested
// without accessing Terraria's process, memory, or saves.
(() => {
    const ROOT='/data/user/0/tm.loader.managedprobe/files/managed';
    function log(message) {
        const write=new NativeFunction(Process.getModuleByName('liblog.so').getExportByName('__android_log_write'),'int',['int','pointer','pointer']);
        write(4,Memory.allocUtf8String('TMAL'),Memory.allocUtf8String(message));
    }
    try {TMALRespawn.initialize(ROOT);}
    catch(error){log('RESPAWN_PROBE_FAILED '+error.stack);return;}
    setTimeout(()=>{
        try {
            const contract=JSON.parse(File.readAllText(ROOT+'/demo-contract.json'));
            if(contract.mode!=='respawn-snapshot'||contract.live_game_supported!==false||
                contract.callback_checks!==13||contract.live_snapshot_checks!==8)
                throw Error('Unexpected isolated respawn contract');
            const first=TMALRespawn.checks(),gcStressBytes=TMALRespawn.stress(),afterGc=TMALRespawn.checks();
            if(first!==13||afterGc!==13||gcStressBytes!==16777216)throw Error('Respawn callback count differs');
            const callbacks=JSON.parse(File.readAllText(ROOT+'/callback-result.json'));
            if(callbacks.live_snapshot_checks!==8)throw Error('Snapshot transport checks differ');
            if(TMALRespawn.start()!==2147483647)throw Error('Original clamp request differs');
            function snapshots(){
                const input={session:1,npcCount:2,npcs:[],direction:1,damage:100,expert:false,pvp:false,px:0,py:0};
                const cases=[['kill',3,600,true,180],['kill',61,600,true,3660],
                    ['dead',61,3660,false,3660],['dead',3,3660,true,180]];
                return cases.map(([phase,seconds,timer,adjust,expected])=>{
                    const actual=TMALRespawn.evaluate({...input,phase,seconds,timer,adjust});
                    if(actual!==expected)throw Error('Native JSON bridge returned '+actual+' instead of '+expected);
                    return {phase,seconds,timer,adjust,actual,expected};
                });
            }
            const nativeJsonBeforeGc=snapshots(),nativeJsonGcBytes=TMALRespawn.stress(),nativeJsonAfterGc=snapshots();
            if(nativeJsonGcBytes!==16777216)throw Error('JSON bridge GC stress differs');
            const report={status:'original-respawn-callbacks-executed-in-isolated-android-probe',
                mod:contract.mod,version:contract.version,dll_sha256:contract.mod_dll_sha256,
                first,afterGc,gcStressBytes,callbacks,nativeJsonBeforeGc,nativeJsonAfterGc,nativeJsonGcBytes,
                runtime:'Mono Android ARM64 8.0.31 interpreter',game_accessed:false,
                native_hook_installed:false,in_game_verified:false,general_tmod_support:false};
            File.writeAllText(ROOT+'/result.json',JSON.stringify(report));
            log('RESPAWN_PROBE_OK '+JSON.stringify(report));
        }catch(error){log('RESPAWN_PROBE_FAILED '+error.stack);}
    },1000);
})();
