'use strict';
// Observation only: no save bytes, sidecars, arguments or return values changed.
globalThis.TMALSaveTrace = (() => {
    let installed=false;
    function install(a) {
        if(installed)throw Error('Save trace already installed');
        const handles=[],contexts=new Map();let sequence=0,span=0,entries=0;
        const emit=(event,details={})=>log('SAVE_TRACE '+JSON.stringify({seq:++sequence,event,thread:Process.getCurrentThreadId(),...details}));
        const validPlayer=p=>p.compare(ptr('0x10000'))>=0&&a.stringValue(p.add(a.nameOffset).readPointer())==='TMAL_Test';
        const filePlayer=offsetFor(a.fileData,'_player',18);
        function offsetFor(klass,name,code) {
            const field=a.fieldGet(klass,a.cstr(name));
            if(field.isNull()||a.typeCode(a.fieldType(field))!==code)throw Error('Save trace field differs: '+name);
            const offset=Number(a.offset(field));
            if(offset<16||offset>16384)throw Error('Save trace offset invalid');
            return offset;
        }
        const fromFile=file=>file.isNull()?ptr(0):file.add(filePlayer).readPointer();
        const snapshot=p=>{
            const inv=p.add(a.inventoryOffset).readPointer();
            if(inv.isNull())return {inventory:false};
            const length=a.arrayLength(inv).toNumber();if(length<10||length>128)throw Error('Trace inventory length invalid');
            let custom=0,base=0;
            for(let i=0;i<length;i++) {
                const item=inv.add(a.header+i*8).readPointer();if(item.isNull())continue;
                const type=item.add(a.offsets.type).readS32();
                if(type===6196)custom++;if(type===3507)base++;
            }
            return {custom,base};
        };
        function method(klass,name,count,isStatic) {
            const m=a.methodGet(klass,a.cstr(name),count);
            if(m.isNull()||((a.methodFlags(m,ptr(0))&16)!==0)!==isStatic)throw Error('Save trace method differs: '+name);
            return m;
        }
        function observe(name,count,source,isStatic=true) {
            const m=method(a.player,name,count,isStatic);
            handles.push(Interceptor.attach(m.readPointer(),{
                onEnter(args) {
                    this.traced=false;
                    try {
                        const p=source==='file'?fromFile(args[0]):args[0];
                        if(!validPlayer(p))return;
                        this.traced=true;this.player=p;this.start=Date.now();this.id=++span;
                        this.thread=Process.getCurrentThreadId();this.previous=contexts.get(this.thread);
                        this.traceContext={id:this.id,serialized:0,customSerialized:0};
                        contexts.set(this.thread,this.traceContext);
                        emit(name+'.enter',{span:this.id,...snapshot(p)});
                    } catch(error){emit('observer.error',{method:name,message:error.message});}
                },
                onLeave() {
                    if(!this.traced)return;
                    try{emit(name+'.leave',{span:this.id,elapsedMs:Date.now()-this.start,...snapshot(this.player),...this.traceContext});}
                    catch(error){emit('observer.error',{method:name,message:error.message});}
                    finally{if(this.previous)contexts.set(this.thread,this.previous);else contexts.delete(this.thread);}
                }
            }));
        }
        try {
            observe('SavePlayer',3,'file');
            observe('InternalSavePlayerFile',1,'file');
            observe('FixLoadedData',0,'player',false);
            observe('LoadPlayer_LastMinuteFixes',1,'player');
            observe('Clone',0,'player',false);
            const load=method(a.player,'LoadPlayer',2,true);
            handles.push(Interceptor.attach(load.readPointer(),{
                onEnter(args) {
                    this.traced=false;
                    try {
                        const path=a.pathString(args[0]);
                        if(!path.endsWith('/Players/TMAL_Test.plr')||args[1].toInt32()!==0)return;
                        this.traced=true;this.start=Date.now();this.id=++span;
                        emit('LoadPlayer.enter',{span:this.id,profile:'TMAL_Test',cloud:false});
                    } catch(error){emit('observer.error',{method:'LoadPlayer',message:error.message});}
                },
                onLeave(result) {
                    if(!this.traced)return;
                    try {
                        const p=fromFile(result);
                        emit('LoadPlayer.leave',{span:this.id,elapsedMs:Date.now()-this.start,expectedPlayer:validPlayer(p),...(validPlayer(p)?snapshot(p):{})});
                    } catch(error){emit('observer.error',{method:'LoadPlayer',message:error.message});}
                }
            }));
            const serialize=method(a.item,'Serialize',2,false);
            handles.push(Interceptor.attach(serialize.readPointer(),{onEnter(args){
                const context=contexts.get(Process.getCurrentThreadId());if(!context)return;
                context.serialized++;if(args[0].add(a.offsets.type).readS32()===6196)context.customSerialized++;
            }}));
            const check=method(a.player,'ItemCheck',0,false);let previousPlayer=ptr(0);
            handles.push(Interceptor.attach(check.readPointer(),{onEnter(args){
                try {
                    if(args[0].equals(previousPlayer)||!validPlayer(args[0]))return;
                    previousPlayer=args[0];if(++entries<=20)emit('ItemCheck.player',{entry:entries,...snapshot(args[0])});
                } catch(error){emit('observer.error',{method:'ItemCheck',message:error.message});}
            }}));
            installed=true;emit('ready',{observationOnly:true,profile:'TMAL_Test'});
        } catch(error) {for(const handle of handles)handle.detach();throw error;}
    }
    return {install};
})();
