'use strict';
// Laboratory bridge: normal offline world, actual frame counts, clock/tile rates.
// PC world-event scheduling and Journey Powers are not bridged to mobile yet.
(() => {
    const ROOT='/data/user/0/com.and.games505.TerrariaPaid/files/tmloader';
    let androidLog=null,enabled=false,multiplier=10,failed=false,hostReady=false,attempts=0,waitingForVm=false;
    function log(message) {
        console.log('[TMAL] '+message);
        if(androidLog===null)androidLog=new NativeFunction(Process.getModuleByName('liblog.so').getExportByName('__android_log_write'),'int',['int','pointer','pointer']);
        androidLog(4,Memory.allocUtf8String('TMAL'),Memory.allocUtf8String(message));
    }
    function readConfig() {
        try {
            const raw=File.readAllText(ROOT+'/managed-enabled.json'),config=File.readAllText(ROOT+'/sleep-config.json');
            if(raw.length>1024||config.length>1024)throw Error('Time config too large');
            const flag=JSON.parse(raw),row=JSON.parse(config);
            if(typeof flag.enabled!=='boolean'||!Number.isInteger(row.multiplier)||row.multiplier<0||row.multiplier>100)throw Error('Invalid time config');
            if(enabled!==flag.enabled||multiplier!==row.multiplier)log('TIME_CONFIG enabled='+flag.enabled+' multiplier='+row.multiplier);
            enabled=flag.enabled;multiplier=row.multiplier;
        } catch(error){enabled=false;log('TIME_CONFIG_REJECTED '+error.message);}
    }
    readConfig();setInterval(readConfig,1000);
    // Initialize Mono before attaching this scheduler thread to IL2CPP. The
    // item bridge uses this same order; crossing the two initialization scopes
    // caused a Mono thread-info assertion during Unity preload in the time lab.
    try {
        log('TIME_HOST_INIT stage=domain');
        TMALTime.initialize(ROOT+'/managed');
        log('TIME_HOST_INIT stage=self-test');
        if(TMALTime.selfTest()!==10||TMALTime.handlers()!==1)throw Error('Time host self-check failed');
        log('TIME_HOST_INIT stage=contract');
        const contract=JSON.parse(File.readAllText(ROOT+'/managed/demo-contract.json'));
        if(contract.api_revision!==undefined) {
            if(contract.api_revision!=='managed-foundation-v2'||contract.lifecycle_check_count!==7||contract.content_check_count!==14||
               TMALTime.lifecycle()!==7)throw Error('Unified time lifecycle checks failed');
            // JNI archive hashing must wait until Java's synchronous Gadget
            // load returns. Keep Mono domain/GC initialization before Unity
            // creates its preload threads, as in the validated sleep bridge.
            setTimeout(()=>{try {
                log('TIME_HOST_INIT stage=gc');
                if(TMALTime.stress()!==16777216)throw Error('Time host GC check failed');
                if(TMALTime.content()!==14)throw Error('Unified content checks failed');
                log('UNIFIED_TIME_API_READY lifecycleChecks=7 contentChecks=14 nativeItemBridge=false');
                hostReady=true;log('TIME_HOST_READY originalChangeSleepTime=true cases=10');
                if(globalThis.TMALMonoRuntime)globalThis.TMALCombinedTimeReady=true;
            }catch(error){failed=true;log('TIME_HOST_FAILED '+error.stack);}},1000);
        } else {
            if(TMALTime.stress()!==16777216)throw Error('Time host GC check failed');
            hostReady=true;log('TIME_HOST_READY originalChangeSleepTime=true cases=10');
        }
    } catch(error){failed=true;log('TIME_HOST_FAILED '+error.stack);}
    const timer=setInterval(()=>{
        if(failed||!hostReady)return;
        const lib=Process.findModuleByName('libil2cpp.so');if(lib===null)return;
        let thread=null,detach=null;
        try {
            const api=(n,r,a)=>new NativeFunction(lib.getExportByName('il2cpp_'+n),r,a);
            const str=s=>Memory.allocUtf8String(s),domain=api('domain_get','pointer',[])();if(domain.isNull())return;
            // domain_get can return a placeholder before Unity has initialized
            // IL2CPP (observed on a locked first launch). Attaching then aborts.
            // A loaded library/non-null domain alone is not a readiness signal.
            if(api('get_corlib','pointer',[])().isNull()){
                if(!waitingForVm){waitingForVm=true;log('TIME_WAITING_FOR_IL2CPP corlib=false');}
                return;
            }
            thread=api('thread_attach','pointer',['pointer'])(domain);detach=api('thread_detach','void',['pointer']);
            const count=Memory.alloc(8);count.writeU64(0);
            const assemblies=api('domain_get_assemblies','pointer',['pointer','pointer'])(domain,count);
            const imageGet=api('assembly_get_image','pointer',['pointer']),imageName=api('image_get_name','pointer',['pointer']);
            let image=ptr(0);const n=count.readU64().toNumber();if(n>2048)throw Error('Image count differs');
            for(let i=0;i<n;i++){const candidate=imageGet(assemblies.add(i*8).readPointer());if(imageName(candidate).readUtf8String()==='Assembly-CSharp.dll')image=candidate;}
            if(image.isNull())return;
            const klassGet=api('class_from_name','pointer',['pointer','pointer','pointer']);
            const main=klassGet(image,str('Terraria'),str('Main')),playerClass=klassGet(image,str('Terraria'),str('Player'));
            if(main.isNull()||playerClass.isNull())throw Error('Time classes missing');
            const methodGet=api('class_get_method_from_name','pointer',['pointer','pointer','int']);
            const methodFlags=api('method_get_flags','uint',['pointer','pointer']);
            const method=(klass,name,argc,stat=true)=>{
                const m=methodGet(klass,str(name),argc);
                if(m.isNull()||((methodFlags(m,ptr(0))&16)!==0)!==stat)throw Error('Time method differs: '+name);return m;
            };
            const invoke=api('runtime_invoke','pointer',['pointer','pointer','pointer','pointer']),unbox=api('object_unbox','pointer',['pointer']);
            function call(m) {
                const ex=Memory.alloc(8);ex.writePointer(ptr(0));const result=invoke(m,ptr(0),ptr(0),ex);
                if(!ex.readPointer().isNull())throw Error('Mobile time getter raised exception');return result;
            }
            const fieldGet=api('class_get_field_from_name','pointer',['pointer','pointer']);
            const fieldFlags=api('field_get_flags','int',['pointer']),fieldType=api('field_get_type','pointer',['pointer']);
            const kind=api('type_get_type','int',['pointer']),offset=api('field_get_offset','ulong',['pointer']);
            const get=api('field_static_get_value','void',['pointer','pointer']),set=api('field_static_set_value','void',['pointer','pointer']);
            function field(klass,name,code,stat=true) {
                const f=fieldGet(klass,str(name));
                if(f.isNull()||kind(fieldType(f))!==code||((fieldFlags(f)&16)!==0)!==stat)throw Error('Time field differs: '+name);return f;
            }
            const nested=api('class_get_nested_types','pointer',['pointer','pointer']),className=api('class_get_name','pointer',['pointer']);
            let frame=ptr(0);const it=Memory.alloc(8);it.writePointer(ptr(0));
            for(;;){const k=nested(main,it);if(k.isNull())break;if(className(k).readUtf8String()==='CurrentFrameFlags')frame=k;}
            if(frame.isNull())throw Error('Actual frame counts missing');
            const fields={day:field(main,'dayRate',8),tile:field(main,'desiredWorldTilesUpdateRate',8),time:field(main,'time',13),
                net:field(main,'netMode',8),world:field(main,'worldName',14),active:field(frame,'ActivePlayersCount',8),sleeping:field(frame,'SleepingPlayersCount',8)};
            const nameOffset=Number(offset(field(playerClass,'name',14,false)));
            if(nameOffset<16||nameOffset>16384)throw Error('Player name offset differs');
            const length=api('string_length','int',['pointer']),chars=api('string_chars','pointer',['pointer']);
            const text=p=>{if(p.isNull())return '';const n=length(p);if(n<0||n>512)throw Error('Name too long');return chars(p).readUtf16String(n);};
            const buffer=Memory.alloc(8);
            const int=f=>{buffer.writeU64(0);get(f,buffer);return buffer.readS32();};
            const string=f=>{get(f,buffer);return text(buffer.readPointer());};
            const write=(f,value)=>{buffer.writeS32(value);set(f,buffer);if(int(f)!==value)throw Error('Rate readback differs');};
            const menu=method(main,'get_gameMenu',0),gameMode=method(main,'get_GameMode',0),local=method(main,'get_LocalPlayer',0),fast=method(main,'IsFastForwardingTime',0);
            const update=method(main,'UpdateTimeRate',0),updateTime=method(main,'UpdateTime',0);
            if(!hostReady)throw Error('Time host unavailable');
            let previous=null,lastLog=0,state=null,samples=0,startTime=0,expectedAdvance=0,startWall=0,aggregateKey=null;
            function allowed() {
                if(unbox(call(menu)).readU8()!==0||int(fields.net)!==0||unbox(call(gameMode)).readS32()!==0||string(fields.world)!=='TMAL_Lab')return false;
                const profile=globalThis.TMALMonoRuntime?'TMAL_Test':'TMAL_Sleep';
                const p=call(local);return !p.isNull()&&text(p.add(nameOffset).readPointer())===profile&&unbox(call(fast)).readU8()===0;
            }
            const sceneTick=TMALSleepScene({api,klass:(ns,name)=>klassGet(image,str(ns),str(name)),method,main,playerClass,local,allowed,log,root:ROOT});
            Interceptor.attach(update.readPointer(),{onLeave(){
                if(failed)return;
                try {
                    sceneTick();
                    if(!allowed()){state=null;return;}
                    const active=int(fields.active),sleeping=int(fields.sleeping),before=[int(fields.day),int(fields.tile)];
                    if(active<1||active>256||sleeping<0||sleeping>active)throw Error('Actual frame counts invalid');
                    const key=JSON.stringify([enabled,multiplier,active,sleeping]);
                    if(key!==previous){previous=key;state=null;}
                    if(!state){
                        // In this normal-world-only lab, Journey powers cannot be active.
                        const rates=TMALTime.evaluate(0,active,sleeping,1,multiplier);
                        if(rates.some(x=>!Number.isInteger(x)||x<0||x>86400))throw Error('Mod rates outside lab limits');
                        state={enabled,multiplier,active,sleeping,before,rates};
                    }
                    if(enabled){write(fields.day,state.rates[0]);write(fields.tile,state.rates[1]);}
                    if(Date.now()-lastLog>4000||lastLog===0){lastLog=Date.now();log('TIME_BRIDGE '+JSON.stringify({...state,after:[int(fields.day),int(fields.tile)],classicOnly:true,eventRateApplied:false}));}
                } catch(error){failed=true;log('TIME_BRIDGE_FAILED '+error.stack);}
            }});
            Interceptor.attach(updateTime.readPointer(),{
                onEnter(){this.observe=!failed&&state!==null; if(!this.observe)return;this.snapshot={...state};get(fields.time,buffer);this.before=buffer.readDouble();this.rate=int(fields.day);},
                onLeave(){
                    if(!this.observe)return;get(fields.time,buffer);const after=buffer.readDouble(),delta=after-this.before;
                    // UpdateTime can call UpdateTimeRate internally. A config change
                    // during that call must not label the resulting tick with the
                    // rate captured at UpdateTime entry.
                    if(state===null||state.enabled!==this.snapshot.enabled||state.multiplier!==this.snapshot.multiplier||
                       state.active!==this.snapshot.active||state.sleeping!==this.snapshot.sleeping||int(fields.day)!==this.rate){
                        samples=0;aggregateKey=null;log('TIME_ADVANCE_TRANSITION discardedMixedRateWindow=true');return;
                    }
                    if(delta<0||delta>86400){samples=0;return;}
                    const s=this.snapshot,key=JSON.stringify([s.enabled,s.multiplier,s.active,s.sleeping,this.rate]);
                    if(key!==aggregateKey){aggregateKey=key;samples=0;}
                    if(samples===0){startTime=this.before;startWall=Date.now();expectedAdvance=0;}
                    samples++;expectedAdvance+=this.rate;
                    if(samples>=180){log('TIME_ADVANCE '+JSON.stringify({enabled:s.enabled,multiplier:s.multiplier,active:s.active,sleeping:s.sleeping,frames:samples,delta:after-startTime,expected:expectedAdvance,wallMs:Date.now()-startWall,dayRate:this.rate}));samples=0;}
                }
            });
            clearInterval(timer);log('TIME_HOOK_READY originalDLL=true normalOfflineTestWorldOnly=true clockAndTilesOnly=true');
        } catch(error){if(++attempts>=3){clearInterval(timer);failed=true;log('TIME_INIT_FAILED '+error.stack);}}
        finally{if(thread!==null&&!thread.isNull()&&detach!==null)detach(thread);}
    },3000);
})();
