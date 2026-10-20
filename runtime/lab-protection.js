'use strict';
// User-requested QA protection, isolated from mod behavior and save content.
(() => {
    const root='/data/user/0/com.and.games505.TerrariaPaid/files/tmloader';
    let enabled=false,attempts=0,failed=false,androidLog=null,waitingForVm=false;
    function log(s){
        console.log('[TMAL] '+s);
        if(androidLog===null)androidLog=new NativeFunction(Process.getModuleByName('liblog.so').getExportByName('__android_log_write'),'int',['int','pointer','pointer']);
        androidLog(4,Memory.allocUtf8String('TMAL'),Memory.allocUtf8String(s));
    }
    function config(){
        try{const raw=File.readAllText(root+'/lab-protection.json');if(raw.length>256)throw Error('Protection config too large');
            const c=JSON.parse(raw);if(typeof c.enabled!=='boolean')throw Error('Protection flag invalid');
            if(enabled!==c.enabled)log('LAB_PROTECTION_CONFIG enabled='+c.enabled);enabled=c.enabled;
        }catch(error){enabled=false;}
    }
    config();setInterval(config,1000);
    const timer=setInterval(()=>{
        const lib=Process.findModuleByName('libil2cpp.so');if(lib===null||failed)return;
        let thread=null,detach=null;
        try{
            const api=(n,r,a)=>new NativeFunction(lib.getExportByName('il2cpp_'+n),r,a),str=s=>Memory.allocUtf8String(s),nil=ptr(0);
            const domain=api('domain_get','pointer',[])();if(domain.isNull())return;
            if(api('get_corlib','pointer',[])().isNull()){
                if(!waitingForVm){waitingForVm=true;log('LAB_PROTECTION_WAITING_FOR_IL2CPP corlib=false');}
                return;
            }
            thread=api('thread_attach','pointer',['pointer'])(domain);detach=api('thread_detach','void',['pointer']);
            const count=Memory.alloc(8);count.writeU64(0);
            const assemblies=api('domain_get_assemblies','pointer',['pointer','pointer'])(domain,count);
            const imageGet=api('assembly_get_image','pointer',['pointer']),imageName=api('image_get_name','pointer',['pointer']);
            if(count.readU64().toNumber()>2048)throw Error('Protection assembly count differs');
            let image=nil;
            for(let i=0;i<count.readU64().toNumber();i++){const candidate=imageGet(assemblies.add(i*8).readPointer());if(imageName(candidate).readUtf8String()==='Assembly-CSharp.dll')image=candidate;}
            if(image.isNull())return;
            const klass=api('class_from_name','pointer',['pointer','pointer','pointer']);
            const main=klass(image,str('Terraria'),str('Main')),player=klass(image,str('Terraria'),str('Player'));
            if(main.isNull()||player.isNull())throw Error('Protection classes missing');
            const methodGet=api('class_get_method_from_name','pointer',['pointer','pointer','int']),flags=api('method_get_flags','uint',['pointer','pointer']);
            function method(k,n,c,stat){const m=methodGet(k,str(n),c);if(m.isNull()||((flags(m,nil)&16)!==0)!==stat)throw Error('Protection method differs: '+n);return m;}
            const invoke=api('runtime_invoke','pointer',['pointer','pointer','pointer','pointer']),unbox=api('object_unbox','pointer',['pointer']);
            function call(m){const ex=Memory.alloc(8);ex.writePointer(nil);const v=invoke(m,nil,nil,ex);if(!ex.readPointer().isNull())throw Error('Protection getter failed');return v;}
            const fieldGet=api('class_get_field_from_name','pointer',['pointer','pointer']),fieldType=api('field_get_type','pointer',['pointer']),kind=api('type_get_type','int',['pointer']);
            const fieldFlags=api('field_get_flags','int',['pointer']),fieldOffset=api('field_get_offset','ulong',['pointer']),get=api('field_static_get_value','void',['pointer','pointer']);
            function field(k,n,t,stat){const f=fieldGet(k,str(n));if(f.isNull()||kind(fieldType(f))!==t||((fieldFlags(f)&16)!==0)!==stat)throw Error('Protection field differs: '+n);return f;}
            function off(n,t){const o=Number(fieldOffset(field(player,n,t,false)));if(o<16||o>16384)throw Error('Protection offset differs');return o;}
            const offsets={name:off('name',14),god:off('creativeGodMode',2),knock:off('noKnockback',2),immune:off('immune',2),immuneTime:off('immuneTime',8),life:off('statLife',8),dead:off('dead',2)};
            const net=field(main,'netMode',8,true),world=field(main,'worldName',14,true),buffer=Memory.alloc(8);
            const menu=method(main,'get_gameMenu',0,true),mode=method(main,'get_GameMode',0,true),local=method(main,'get_LocalPlayer',0,true);
            const length=api('string_length','int',['pointer']),chars=api('string_chars','pointer',['pointer']);
            function text(p){if(p.isNull())return '';const n=length(p);if(n<0||n>128)return '';return chars(p).readUtf16String(n);}
            function eligible(p){
                if(!enabled||p.isNull()||unbox(call(menu)).readU8()!==0||unbox(call(mode)).readS32()!==0)return false;
                get(net,buffer);if(buffer.readS32()!==0)return false;
                get(world,buffer);if(text(buffer.readPointer())!=='TMAL_Lab'||!call(local).equals(p))return false;
                return ['TMAL_Test','TMAL_Sleep','TMAL_Respawn'].includes(text(p.add(offsets.name).readPointer()));
            }
            let lastState=null,lastLog=0,owned=null;
            function protect(p){
                owned=p.toString();
                p.add(offsets.god).writeU8(1);p.add(offsets.knock).writeU8(1);
                p.add(offsets.immune).writeU8(1);p.add(offsets.immuneTime).writeS32(Math.max(2,p.add(offsets.immuneTime).readS32()));
            }
            const update=method(player,'Update',1,false),reset=method(player,'ResetEffects',0,false),hurt=method(player,'Hurt',8,false);
            function failure(e){failed=true;log('LAB_PROTECTION_FAILED '+e.stack);}
            Interceptor.attach(reset.readPointer(),{onEnter(args){this.p=args[0];},onLeave(){try{if(!failed&&eligible(this.p))protect(this.p);}catch(e){failure(e);}}});
            Interceptor.attach(update.readPointer(),{
                onEnter(args){this.p=args[0];try{this.active=!failed&&eligible(this.p);if(this.active)protect(this.p);
                    else if(owned===this.p.toString()){
                        this.p.add(offsets.god).writeU8(0);this.p.add(offsets.knock).writeU8(0);
                        if(this.p.add(offsets.immuneTime).readS32()<=2){this.p.add(offsets.immuneTime).writeS32(0);this.p.add(offsets.immune).writeU8(0);}
                        owned=null;log('LAB_PROTECTION_RELEASED');
                    }
                }catch(e){failure(e);}},
                onLeave(){try{if(!this.active||failed)return;protect(this.p);
                    const state={profile:text(this.p.add(offsets.name).readPointer()),god:this.p.add(offsets.god).readU8()===1,noKnockback:this.p.add(offsets.knock).readU8()===1,life:this.p.add(offsets.life).readS32(),dead:this.p.add(offsets.dead).readU8()!==0};
                    const key=JSON.stringify(state);if(key!==lastState||Date.now()-lastLog>5000){lastState=key;lastLog=Date.now();log('LAB_PROTECTION_STATE '+key);}
                }catch(e){failure(e);}}
            });
            Interceptor.attach(hurt.readPointer(),{
                onEnter(args){this.p=args[0];try{this.active=!failed&&eligible(this.p);if(this.active){protect(this.p);this.life=this.p.add(offsets.life).readS32();}}catch(e){failure(e);}},
                onLeave(){if(this.active&&!failed)log('LAB_PROTECTION_HURT '+JSON.stringify({before:this.life,after:this.p.add(offsets.life).readS32(),noKnockback:this.p.add(offsets.knock).readU8()===1}));}
            });
            clearInterval(timer);log('LAB_PROTECTION_READY offlineClassicTestProfilesOnly=true');
        }catch(error){if(++attempts>=3){clearInterval(timer);failed=true;log('LAB_PROTECTION_INIT_FAILED '+error.stack);}}
        finally{if(thread!==null&&!thread.isNull()&&detach!==null)detach(thread);}
    },3000);
})();
