'use strict';
// Root-lab diagnostic only; not included in companion APKs. All hits execute
// at Player.Update exit in the named offline/classic test world and restore
// health, immunity, position and velocity before returning to the game.
(() => {
    const lib=Process.getModuleByName('libil2cpp.so');
    const api=(n,r,a)=>new NativeFunction(lib.getExportByName('il2cpp_'+n),r,a);
    const str=s=>Memory.allocUtf8String(s),nil=ptr(0);
    const domain=api('domain_get','pointer',[])();
    if(domain.isNull()||api('get_corlib','pointer',[])().isNull())throw Error('IL2CPP not initialized');
    const thread=api('thread_attach','pointer',['pointer'])(domain);
    let pending=null,hook;
    try {
        const count=Memory.alloc(8);count.writeU64(0);
        const assemblies=api('domain_get_assemblies','pointer',['pointer','pointer'])(domain,count);
        const imageGet=api('assembly_get_image','pointer',['pointer']),imageName=api('image_get_name','pointer',['pointer']);
        const n=count.readU64().toNumber();if(n>2048)throw Error('Assembly count outside limit');
        let image=nil;
        for(let i=0;i<n;i++){const x=imageGet(assemblies.add(i*8).readPointer());if(imageName(x).readUtf8String()==='Assembly-CSharp.dll')image=x;}
        if(image.isNull())throw Error('Game assembly missing');
        const klass=(ns,name)=>api('class_from_name','pointer',['pointer','pointer','pointer'])(image,str(ns),str(name));
        const main=klass('Terraria','Main'),player=klass('Terraria','Player'),reasonClass=klass('Terraria.DataStructures','PlayerDeathReason');
        const kind=t=>api('type_get_type','int',['pointer'])(t);
        const typeName=t=>api('type_get_name','pointer',['pointer'])(t).readUtf8String();
        function method(k,name,kinds,ret,stat){
            const m=api('class_get_method_from_name','pointer',['pointer','pointer','int'])(k,str(name),kinds.length);
            if(m.isNull()||((api('method_get_flags','uint',['pointer','pointer'])(m,nil)&16)!==0)!==stat||
               kind(api('method_get_return_type','pointer',['pointer'])(m))!==ret)throw Error('Method differs: '+name);
            kinds.forEach((expected,i)=>{if(kind(api('method_get_param','pointer',['pointer','uint'])(m,i))!==expected)throw Error('Parameter differs: '+name+'/'+i);});
            return m;
        }
        const local=method(main,'get_LocalPlayer',[],18,true),menu=method(main,'get_gameMenu',[],2,true),mode=method(main,'get_GameMode',[],8,true);
        const update=method(player,'Update',[8],1,false),hurt=method(player,'Hurt',[18,8,8,2,2,2,8,2],13,false);
        const reasonFactory=method(reasonClass,'ByCustomReason',[14],18,true);
        const hurtReason=api('method_get_param','pointer',['pointer','uint'])(hurt,0);
        if(typeName(hurtReason)!=='Terraria.DataStructures.PlayerDeathReason')throw Error('Hurt reason type differs');
        const fieldGet=api('class_get_field_from_name','pointer',['pointer','pointer']),fieldType=api('field_get_type','pointer',['pointer']);
        const fieldOffset=api('field_get_offset','ulong',['pointer']),fieldFlags=api('field_get_flags','int',['pointer']);
        function field(k,name,type,stat){const f=fieldGet(k,str(name));if(f.isNull()||kind(fieldType(f))!==type||((fieldFlags(f)&16)!==0)!==stat)throw Error('Field differs: '+name);return f;}
        const net=field(main,'netMode',8,true),world=field(main,'worldName',14,true);
        const offsets={};
        for(const [name,type] of Object.entries({statLife:8,dead:2,name:14,creativeGodMode:2,noKnockback:2,immune:2,immuneTime:8,velocity:17,position:17})){
            const f=field(player,name,type,false),o=Number(fieldOffset(f));if(o<16||o>16384)throw Error('Offset differs: '+name);offsets[name]=o;
            if(type===17){const c=api('class_from_type','pointer',['pointer'])(fieldType(f));
                const layout={name:typeName(fieldType(f)),size:api('class_value_size','int',['pointer','pointer'])(c,Memory.alloc(4)),
                    x:Number(fieldOffset(field(c,'X',12,false))),y:Number(fieldOffset(field(c,'Y',12,false)))};
                // IL2CPP metadata offsets include the 16-byte boxed header;
                // the inline Entity field contains the unboxed 8-byte value.
                if(layout.name!=='Microsoft.Xna.Framework.Vector2'||layout.size!==8||layout.x!==16||layout.y!==20)throw Error('Vector layout differs: '+JSON.stringify(layout));}
        }
        const invoke=api('runtime_invoke','pointer',['pointer','pointer','pointer','pointer']),unbox=api('object_unbox','pointer',['pointer']);
        const get=api('field_static_get_value','void',['pointer','pointer']);
        const gcNew=api('gchandle_new','uint',['pointer','uchar']),gcFree=api('gchandle_free','void',['uint']);
        function call(m,obj=nil,args=[]){const params=Memory.alloc(Math.max(8,args.length*8)),ex=Memory.alloc(8);ex.writePointer(nil);
            args.forEach((p,i)=>params.add(i*8).writePointer(p));const result=invoke(m,obj,params,ex);
            if(!ex.readPointer().isNull())throw Error('Vanilla API raised exception');return result;}
        function text(p){if(p.isNull())return '';const len=api('string_length','int',['pointer'])(p);if(len<0||len>128)throw Error('String exceeds lab limit');return api('string_chars','pointer',['pointer'])(p).readUtf16String(len);}
        const int=n=>{const p=Memory.alloc(4);p.writeS32(n);return p;},bool=b=>{const p=Memory.alloc(1);p.writeU8(b?1:0);return p;};
        function snapshot(p){const o=offsets;return {life:p.add(o.statLife).readS32(),dead:p.add(o.dead).readU8()!==0,
            god:p.add(o.creativeGodMode).readU8()!==0,noKnockback:p.add(o.noKnockback).readU8()!==0,
            immune:p.add(o.immune).readU8()!==0,immuneTime:p.add(o.immuneTime).readS32(),
            velocity:[p.add(o.velocity).readFloat(),p.add(o.velocity+4).readFloat()],position:[p.add(o.position).readFloat(),p.add(o.position+4).readFloat()]};}
        function guard(p){const b=Memory.alloc(8);
            if(p.isNull()||!call(local).equals(p)||unbox(call(menu)).readU8()!==0||unbox(call(mode)).readS32()!==0)throw Error('Not an active classic local player');
            get(net,b);if(b.readS32()!==0)throw Error('Multiplayer excluded');get(world,b);if(text(b.readPointer())!=='TMAL_Lab')throw Error('Not the lab world');
            if(!['TMAL_Sleep','TMAL_Test'].includes(text(p.add(offsets.name).readPointer())))throw Error('Not a lab character');
            const s=snapshot(p);if(s.dead||s.life<80)throw Error('Lab character must be alive with at least 80 health');
            const raw=File.readAllText('/data/user/0/com.and.games505.TerrariaPaid/files/tmloader/lab-protection.json');
            if(raw.length>256)throw Error('Protection config exceeds bound');const c=JSON.parse(raw);if(typeof c.enabled!=='boolean')throw Error('Invalid protection config');
            return {...s,enabled:c.enabled};}
        function restore(p,s){const o=offsets;p.add(o.statLife).writeS32(s.life);
            for(const [name,key] of [['creativeGodMode','god'],['noKnockback','noKnockback'],['immune','immune']])p.add(o[name]).writeU8(s[key]?1:0);
            p.add(o.immuneTime).writeS32(s.immuneTime);
            for(const name of ['position','velocity']){p.add(o[name]).writeFloat(s[name][0]);p.add(o[name]+4).writeFloat(s[name][1]);}}
        function hit(p,variant,direction){const original=guard(p),o=offsets;
            if((variant==='full')!==original.enabled||original.god!==original.enabled||original.noKnockback!==original.enabled)throw Error('Protection transition not settled');
            if(!['off','knockback-only','full'].includes(variant)||![-1,1].includes(direction))throw Error('Invalid bounded hit');
            let handle=null;
            try {
                p.add(o.velocity).writeFloat(0);p.add(o.velocity+4).writeFloat(0);
                if(variant!=='full'){p.add(o.immune).writeU8(0);p.add(o.immuneTime).writeS32(0);p.add(o.noKnockback).writeU8(variant==='knockback-only'?1:0);}
                const before=snapshot(p);
                const reason=call(reasonFactory,nil,[api('string_new','pointer',['pointer'])(str('TMAL controlled protection test'))]);
                if(reason.isNull())throw Error('Death reason factory returned null');handle=gcNew(reason,0);
                const returned=call(hurt,p,[reason,int(20),int(direction),bool(false),bool(true),bool(false),int(-1),bool(false)]);
                if(returned.isNull())throw Error('Hurt returned null');const result=unbox(returned).readDouble(),after=snapshot(p);
                if(after.dead||after.life<40)throw Error('Unexpected unsafe hit outcome');
                return {variant,direction,inputDamage:20,returnedDamage:result,before,after,healthLost:before.life-after.life};
            } finally {restore(p,original);if(handle!==null)gcFree(handle);}
        }
        hook=Interceptor.attach(update.readPointer(),{onEnter(args){this.p=args[0];},onLeave(){
            if(pending===null)return;const task=pending;pending=null;
            try {const state=guard(this.p);const result=task.variant===null?state:hit(this.p,task.variant,task.direction);task.resolve({...result,restored:snapshot(this.p),pid:Process.id});}
            catch(error){task.reject(error);}
        }});
        function queue(variant,direction){if(pending!==null)throw Error('A lab observation is already pending');
            return new Promise((resolve,reject)=>{const task={variant,direction,resolve,reject};pending=task;
                setTimeout(()=>{if(pending===task){pending=null;reject(Error('No eligible Player.Update within 3 seconds'));}},3000);});}
        rpc.exports.observe=()=>queue(null,0);
        rpc.exports.hit=(variant,direction)=>queue(variant,direction);
        rpc.exports.close=()=>{if(pending!==null)throw Error('Lab task pending');hook.detach();};
    } finally {api('thread_detach','void',['pointer'])(thread);}
})();
