'use strict';
// Experimental original-DLL bridge, restricted to a dedicated offline lab
// profile. It neither restores custom items nor exposes a general hook API.
(() => {
    const ROOT='/data/user/0/com.and.games505.TerrariaPaid/files/tmloader';
    let failed=false,ready=false,enabled=false,seconds=3,adjust=true,attempts=0,androidLog;
    let pending=null,lastNonce=null;
    function log(message){
        console.log('[TMAL] '+message);
        if(!androidLog)androidLog=new NativeFunction(Process.getModuleByName('liblog.so').getExportByName('__android_log_write'),'int',['int','pointer','pointer']);
        androidLog(4,Memory.allocUtf8String('TMAL'),Memory.allocUtf8String(message));
    }
    function config(){
        try {
            const flag=File.readAllText(ROOT+'/managed-enabled.json'),raw=File.readAllText(ROOT+'/respawn-config.json');
            if(flag.length>1024||raw.length>1024)throw Error('Respawn config too large');
            const f=JSON.parse(flag),c=JSON.parse(raw);
            if(typeof f.enabled!=='boolean'||!Number.isInteger(c.seconds)||c.seconds<0||c.seconds>3600||typeof c.adjust!=='boolean')throw Error('Respawn config invalid');
            if(enabled!==f.enabled||seconds!==c.seconds||adjust!==c.adjust)log('RESPAWN_CONFIG '+JSON.stringify({enabled:f.enabled,...c}));
            enabled=f.enabled;seconds=c.seconds;adjust=c.adjust;
        }catch(error){enabled=false;log('RESPAWN_CONFIG_REJECTED '+error.message);}
        try {
            const raw=File.readAllText(ROOT+'/respawn-command.json');if(raw.length>512)throw Error('Respawn command too large');
            const c=JSON.parse(raw);
            if(c.action!=='respawn-die'||typeof c.nonce!=='string'||! /^[0-9a-f-]{36}$/.test(c.nonce))throw Error('Respawn command invalid');
            if(c.nonce!==lastNonce){lastNonce=c.nonce;pending=c;}
        }catch(error){if(!String(error).includes('No such file'))log('RESPAWN_COMMAND_REJECTED '+error.message);}
    }
    config();setInterval(config,500);
    let clampRequest=0;
    try {
        // Domain setup must precede IL2CPP thread attachment. SHA256 checks wait
        // until synchronous Java Gadget loading has returned and JNI is ready.
        TMALRespawn.initialize(ROOT+'/managed');
        setTimeout(()=>{try {
            const c=JSON.parse(File.readAllText(ROOT+'/managed/demo-contract.json'));
            if(c.mode!=='respawn-snapshot'||c.callback_checks!==13||c.live_snapshot_checks!==8||c.live_game_supported!==false)throw Error('Respawn contract differs');
            if(TMALRespawn.checks()!==13||TMALRespawn.stress()!==16777216||TMALRespawn.checks()!==13)throw Error('Respawn host checks failed');
            clampRequest=TMALRespawn.start();if(clampRequest!==2147483647)throw Error('Original clamp request differs');
            ready=true;log('RESPAWN_HOST_READY originalDLL=true callbacks=13 transport=8');
        }catch(error){failed=true;log('RESPAWN_HOST_FAILED '+error.stack);}},1000);
    }catch(error){failed=true;log('RESPAWN_HOST_FAILED '+error.stack);}
    const timer=setInterval(()=>{
        if(failed||!ready)return;
        const lib=Process.findModuleByName('libil2cpp.so');if(lib===null)return;
        let thread=null,detach=null,mutating=false,replaced=null;
        const listeners=[];
        try {
            if(Process.arch!=='arm64'||Process.pointerSize!==8)throw Error('Respawn requires tested ARM64 layout');
            const api=(name,result,args)=>new NativeFunction(lib.getExportByName('il2cpp_'+name),result,args);
            const str=s=>Memory.allocUtf8String(s),nil=ptr(0),domain=api('domain_get','pointer',[])();
            if(domain.isNull()||api('get_corlib','pointer',[])().isNull())return;
            thread=api('thread_attach','pointer',['pointer'])(domain);detach=api('thread_detach','void',['pointer']);
            const count=Memory.alloc(8);count.writeU64(0);
            const assemblies=api('domain_get_assemblies','pointer',['pointer','pointer'])(domain,count);
            const imageGet=api('assembly_get_image','pointer',['pointer']),imageName=api('image_get_name','pointer',['pointer']);
            const n=count.readU64().toNumber();if(n>2048)throw Error('Respawn assembly count differs');
            let image=nil;
            for(let i=0;i<n;i++){const candidate=imageGet(assemblies.add(i*8).readPointer());if(imageName(candidate).readUtf8String()==='Assembly-CSharp.dll')image=candidate;}
            if(image.isNull())return;
            const klass=(ns,name)=>api('class_from_name','pointer',['pointer','pointer','pointer'])(image,str(ns),str(name));
            const player=klass('Terraria','Player'),npc=klass('Terraria','NPC'),entity=klass('Terraria','Entity'),main=klass('Terraria','Main');
            const reasonClass=klass('Terraria.DataStructures','PlayerDeathReason');
            if([player,npc,entity,main,reasonClass].some(k=>k.isNull()))throw Error('Respawn classes absent');
            const typeName=t=>api('type_get_name','pointer',['pointer'])(t).readUtf8String();
            const fieldGet=api('class_get_field_from_name','pointer',['pointer','pointer']);
            const fieldFlags=api('field_get_flags','uint',['pointer']),fieldType=api('field_get_type','pointer',['pointer']);
            const offset=api('field_get_offset','ulong',['pointer']),get=api('field_static_get_value','void',['pointer','pointer']);
            const set=api('field_static_set_value','void',['pointer','pointer']);
            function field(k,name,type,stat=false){
                const f=fieldGet(k,str(name));
                if(f.isNull()||typeName(fieldType(f))!==type||((fieldFlags(f)&16)!==0)!==stat)throw Error('Respawn field differs: '+name);
                return f;
            }
            function off(k,name,type){const result=Number(offset(field(k,name,type)));if(result<16||result>16384)throw Error('Respawn field offset differs');return result;}
            const po={timer:off(player,'respawnTimer','System.Int32'),dead:off(player,'dead','System.Boolean'),
                name:off(player,'name','System.String'),active:off(player,'active','System.Boolean'),
                difficulty:off(player,'difficulty','System.Byte'),life:off(player,'statLife','System.Int32'),
                god:off(player,'creativeGodMode','System.Boolean'),immune:off(player,'immune','System.Boolean'),immuneTime:off(player,'immuneTime','System.Int32')};
            const eo={position:off(entity,'position','Microsoft.Xna.Framework.Vector2'),width:off(entity,'width','System.Int32'),height:off(entity,'height','System.Int32')};
            const no={active:off(npc,'active','System.Boolean'),boss:off(npc,'boss','System.Boolean'),type:off(npc,'type','System.Int32')};
            if(po.timer!==1532||po.dead!==1520||eo.position!==20||eo.width!==60||eo.height!==64||no.active!==73)throw Error('Audited mobile layout differs');
            const vector=api('class_from_type','pointer',['pointer'])(fieldType(field(entity,'position','Microsoft.Xna.Framework.Vector2')));
            const align=Memory.alloc(4);
            if(api('class_value_size','int',['pointer','pointer'])(vector,align)!==8||
                Number(offset(field(vector,'X','System.Single')))!==16||Number(offset(field(vector,'Y','System.Single')))!==20)
                throw Error('Vector2 layout differs');
            const maximum=field(player,'respawnTimerMax','System.Int32',true);
            if(fieldFlags(maximum)!==54||Number(offset(maximum))!==136)throw Error('Audited clamp field differs');
            const net=field(main,'netMode','System.Int32',true),world=field(main,'worldName','System.String',true);
            const players=field(main,'player','Terraria.Player[]',true),npcs=field(main,'npc','Terraria.NPC[]',true);
            const methodGet=api('class_get_method_from_name','pointer',['pointer','pointer','int']);
            const methodFlags=api('method_get_flags','uint',['pointer','pointer']);
            function method(k,name,parameters,returns,stat=false){
                const m=methodGet(k,str(name),parameters.length);
                if(m.isNull()||((methodFlags(m,nil)&16)!==0)!==stat||typeName(api('method_get_return_type','pointer',['pointer'])(m))!==returns)throw Error('Respawn method differs: '+name);
                for(let i=0;i<parameters.length;i++)if(typeName(api('method_get_param','pointer',['pointer','uint'])(m,i))!==parameters[i])throw Error('Respawn parameter differs: '+name);
                if(m.readPointer().isNull())throw Error('Respawn native method absent: '+name);return m;
            }
            const local=method(main,'get_LocalPlayer',[],'Terraria.Player',true),menu=method(main,'get_gameMenu',[],'System.Boolean',true);
            const mode=method(main,'get_GameMode',[],'System.Int32',true),expert=method(main,'get_expertMode',[],'System.Boolean',true);
            const dead=method(player,'UpdateDead',[],'System.Void'),spawn=method(player,'Spawn',['Terraria.PlayerSpawnContext'],'System.Void');
            const kill=method(player,'KillMe',['Terraria.DataStructures.PlayerDeathReason','System.Double','System.Int32','System.Boolean'],'System.Void');
            const update=method(player,'Update',['System.Int32'],'System.Void');
            const byOther=method(reasonClass,'ByOther',['System.Int32'],'Terraria.DataStructures.PlayerDeathReason',true);
            if(dead.readPointer().sub(lib.base).toString()!=='0x134aaa8'||kill.readPointer().sub(lib.base).toString()!=='0x1353c8c')throw Error('Audited native method build differs');
            const invoke=api('runtime_invoke','pointer',['pointer','pointer','pointer','pointer']),unbox=api('object_unbox','pointer',['pointer']);
            const gcNew=api('gchandle_new','uint',['pointer','uchar']),gcFree=api('gchandle_free','void',['uint']);
            function call(m,object=nil,args=[]){
                const params=Memory.alloc(Math.max(8,args.length*8)),exception=Memory.alloc(8);exception.writePointer(nil);
                args.forEach((p,i)=>params.add(i*8).writePointer(p));const result=invoke(m,object,params,exception);
                if(!exception.readPointer().isNull())throw Error('Respawn vanilla method raised exception');return result;
            }
            const length=api('string_length','int',['pointer']),chars=api('string_chars','pointer',['pointer']);
            function text(p){if(p.isNull())return '';const size=length(p);if(size<0||size>128)throw Error('Respawn name outside bounds');return chars(p).readUtf16String(size);}
            function read(f){const p=Memory.alloc(8);get(f,p);return p;}
            function writeMax(value){const p=Memory.alloc(4);p.writeS32(value);set(maximum,p);}
            const lease=TMALRespawnClampLease(()=>read(maximum).readS32(),writeMax,clampRequest);
            if(read(maximum).readS32()!==3600)throw Error('Respawn clamp baseline differs');
            const arrayLength=api('array_length','ulong',['pointer']);
            function array(f,max){const a=read(f).readPointer();if(a.isNull())throw Error('Respawn array absent');const size=arrayLength(a).toNumber();if(size<1||size>max||a.add(24).readU64().toNumber()!==size)throw Error('Respawn array layout differs');return {a,size};}
            function eligible(p){
                if(p.isNull()||unbox(call(menu)).readU8()!==0||unbox(call(mode)).readS32()!==0||read(net).readS32()!==0||text(read(world).readPointer())!=='TMAL_Lab')return false;
                if(!call(local).equals(p)||p.add(po.active).readU8()!==1||p.add(po.difficulty).readU8()!==0||text(p.add(po.name).readPointer())!=='TMAL_Respawn')return false;
                const list=array(players,256);let active=0;
                for(let i=0;i<list.size;i++){const q=list.a.add(32+i*8).readPointer();if(!q.isNull()&&q.add(po.active).readU8()!==0)active++;}
                return active===1;
            }
            function center(p){
                const x=p.add(eo.position).readFloat()+p.add(eo.width).readS32()/2,y=p.add(eo.position+4).readFloat()+p.add(eo.height).readS32()/2;
                if(!Number.isFinite(x)||!Number.isFinite(y)||Math.abs(x)>1e9||Math.abs(y)>1e9)throw Error('Respawn center outside bounds');return [x,y];
            }
            let session=0,lastPlayer=null,death=null;
            function snapshot(p,phase,damage=0,direction=0,pvp=false){
                if(lastPlayer!==p.toString()){lastPlayer=p.toString();if(++session>2147483647)throw Error('Respawn session exhausted');}
                const list=array(npcs,512),rows=[];
                for(let i=0;i<list.size;i++){
                    const q=list.a.add(32+i*8).readPointer();if(q.isNull()||q.add(no.active).readU8()===0)continue;
                    rows.push([i,q.add(no.type).readS32(),q.add(no.boss).readU8()!==0,...center(q)]);
                }
                const [px,py]=center(p);
                return {phase,session,seconds,adjust,timer:Math.max(0,p.add(po.timer).readS32()),npcCount:list.size,npcs:rows,
                    px,py,damage,direction,pvp,expert:unbox(call(expert)).readU8()!==0};
            }
            function evaluate(p,phase,damage,direction,pvp){
                const value=TMALRespawn.evaluate(snapshot(p,phase,damage,direction,pvp));
                if(!Number.isInteger(value)||value<0||value>216000)throw Error('Respawn callback result outside lab bounds');
                p.add(po.timer).writeS32(value);return value;
            }
            function failure(error){failed=true;log('RESPAWN_BRIDGE_FAILED '+error.stack);}
            const inventory=field(player,'inventory','Terraria.Item[]'),inventoryOffset=Number(offset(inventory));
            const item=klass('Terraria','Item'),itemType=off(item,'type','System.Int32'),itemStack=off(item,'stack','System.Int32');
            // Typed forwarding preserves ARM64's separate double argument
            // register, the original reason reference, and MethodInfo argument.
            if(typeof Interceptor.replaceFast!=='function')throw Error('Typed respawn forwarding unavailable');
            let originalKill;
            const killCallback=new NativeCallback((p,reason,damage,direction,pvp,methodInfo)=>{
                originalKill(p,reason,damage,direction,pvp,methodInfo);
                if(failed)return;
                try {if(!eligible(p)||p.add(po.dead).readU8()===0)return;
                    const before=p.add(po.timer).readS32(),after=enabled?evaluate(p,'kill',damage,direction,pvp!==0):before;
                    death={start:Date.now(),frames:0,enabled,seconds,before,after};
                    log('RESPAWN_KILL '+JSON.stringify(death));
                }catch(error){failure(error);}
            },'void',['pointer','pointer','double','int','uchar','pointer']);
            mutating=true;
            const trampoline=Interceptor.replaceFast(kill.readPointer(),killCallback);replaced=kill.readPointer();
            originalKill=new NativeFunction(trampoline,'void',['pointer','pointer','double','int','uchar','pointer'],{exceptions:'propagate'});
            // Native callbacks and their trampolines must outlive initialization.
            globalThis.TMALRespawnNativeRoots={killCallback,originalKill,lease};
            listeners.push(Interceptor.attach(dead.readPointer(),{
                onEnter(args){this.p=args[0];this.lease=null;this.observe=false;
                    if(failed)return;
                    try {if(!eligible(this.p))return;this.observe=true;this.before=this.p.add(po.timer).readS32();this.enabled=enabled;
                        this.applied=this.before;
                        if(enabled&&this.before>=0){this.applied=evaluate(this.p,'dead');this.lease=lease.enter();}
                        if(death)death.frames++;
                    }catch(error){if(this.lease!==null){try{lease.exit(this.lease);}finally{this.lease=null;}}failure(error);}
                },
                onLeave(){
                    try {
                        if(this.lease!==null){const token=this.lease;this.lease=null;lease.exit(token);}
                        if(!this.observe)return;
                        const max=read(maximum).readS32();if(max!==3600)throw Error('Respawn clamp leaked outside UpdateDead');
                        const after=this.p.add(po.timer).readS32(),frames=death?death.frames:0;
                        if(frames<=5||frames%60===0||after<=0||this.applied!==this.before||after!==this.applied-1)
                            log('RESPAWN_TICK '+JSON.stringify({enabled:this.enabled,seconds,before:this.before,applied:this.applied,after,frames,clampOutside:max,dead:this.p.add(po.dead).readU8()!==0}));
                    }catch(error){failure(error);}
                }
            }));
            listeners.push(Interceptor.attach(spawn.readPointer(),{onEnter(args){this.p=args[0];},onLeave(){
                try {if(death&&eligible(this.p)&&this.p.add(po.dead).readU8()===0){
                    log('RESPAWN_COMPLETE '+JSON.stringify({...death,wallMs:Date.now()-death.start,life:this.p.add(po.life).readS32()}));death=null;
                }}catch(error){failure(error);}
            }}));
            listeners.push(Interceptor.attach(update.readPointer(),{onEnter(args){this.p=args[0];},onLeave(){
                if(failed||pending===null)return;const command=pending;pending=null;
                try {
                    const p=this.p;if(!eligible(p)||p.add(po.dead).readU8()!==0||p.add(po.life).readS32()<80)throw Error('Death QA requires healthy offline classic TMAL_Respawn in TMAL_Lab');
                    const inv=p.add(inventoryOffset).readPointer();if(inv.isNull())throw Error('Death QA inventory absent');
                    const size=arrayLength(inv).toNumber();if(size<1||size>100)throw Error('Death QA inventory size differs');
                    let copper=0;
                    for(let i=0;i<size;i++){
                        const q=inv.add(32+i*8).readPointer();if(q.isNull())continue;const id=q.add(itemType).readS32(),stack=q.add(itemStack).readS32();
                        if(id>=71&&id<=74&&stack>0)copper+=stack*Math.pow(100,id-71);
                    }
                    // This freshly created QA profile can pick up a few copper
                    // coins from enemies killed by the Guide while we inspect
                    // results. Refuse valuable inventories; vanilla death/drop
                    // semantics still apply to at most one silver of lab coins.
                    if(copper>100)throw Error('Death QA refuses more than 100 copper on the dedicated lab profile');
                    const other=Memory.alloc(4);other.writeS32(4);const reason=call(byOther,nil,[other]);if(reason.isNull())throw Error('Death QA reason absent');
                    const handle=gcNew(reason,1),god=p.add(po.god).readU8();
                    try {
                        p.add(po.god).writeU8(0);p.add(po.immune).writeU8(0);p.add(po.immuneTime).writeS32(0);
                        const amount=Memory.alloc(8),direction=Memory.alloc(4),pvp=Memory.alloc(1);amount.writeDouble(10000);direction.writeS32(0);pvp.writeU8(0);
                        call(kill,p,[reason,amount,direction,pvp]);
                        if(p.add(po.dead).readU8()===0)throw Error('Vanilla KillMe did not kill QA profile');
                        log('RESPAWN_QA_DEATH '+JSON.stringify({nonce:command.nonce,timer:p.add(po.timer).readS32(),enabled,seconds,copperBefore:copper,clampOutside:read(maximum).readS32()}));
                    }finally {p.add(po.god).writeU8(god);gcFree(handle);}
                }catch(error){log('RESPAWN_QA_REJECTED '+error.stack);}
            }}));
            clearInterval(timer);log('RESPAWN_HOOK_READY originalDLL=true profile=TMAL_Respawn offlineClassicOnly=true clampLease=true');
        }catch(error){
            if(mutating){
                for(const listener of listeners)listener.detach();
                if(replaced!==null)Interceptor.revert(replaced);
                clearInterval(timer);failed=true;log('RESPAWN_INIT_FAILED '+error.stack);
            }else if(++attempts>=3){clearInterval(timer);failed=true;log('RESPAWN_INIT_FAILED '+error.stack);}
        }
        finally{if(thread!==null&&!thread.isNull()&&detach!==null)detach(thread);}
    },3000);
})();
