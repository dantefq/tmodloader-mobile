'use strict';
// Read-only IL2CPP metadata inspection; no game methods are invoked.
rpc.exports.inspect = function () {
    const lib=Process.getModuleByName('libil2cpp.so');
    const api=(n,r,a)=>new NativeFunction(lib.getExportByName('il2cpp_'+n),r,a);
    const str=s=>Memory.allocUtf8String(s),nil=ptr(0);
    const domain=api('domain_get','pointer',[])();
    if(domain.isNull()||api('get_corlib','pointer',[])().isNull())throw Error('Game runtime is not initialized');
    const thread=api('thread_attach','pointer',['pointer'])(domain);
    try {
        const count=Memory.alloc(8);count.writeU64(0);
        const assemblies=api('domain_get_assemblies','pointer',['pointer','pointer'])(domain,count);
        const imageGet=api('assembly_get_image','pointer',['pointer']),imageName=api('image_get_name','pointer',['pointer']);
        const n=count.readU64().toNumber();if(n>2048)throw Error('Assembly count outside limit');
        let image=nil;
        for(let i=0;i<n;i++){
            const candidate=imageGet(assemblies.add(i*8).readPointer());
            if(imageName(candidate).readUtf8String()==='Assembly-CSharp.dll')image=candidate;
        }
        if(image.isNull())throw Error('Game assembly absent');
        const klass=(ns,name)=>api('class_from_name','pointer',['pointer','pointer','pointer'])(image,str(ns),str(name));
        const typeName=t=>api('type_get_name','pointer',['pointer'])(t).readUtf8String();
        function fields(k,names){
            const result={};
            for(const name of names){
                const field=api('class_get_field_from_name','pointer',['pointer','pointer'])(k,str(name));
                if(field.isNull()){result[name]=null;continue;}
                result[name]={type:typeName(api('field_get_type','pointer',['pointer'])(field)),
                    flags:api('field_get_flags','int',['pointer'])(field),
                    offset:Number(api('field_get_offset','ulong',['pointer'])(field))};
            }
            return result;
        }
        function methods(k,names){
            const result=[],iterator=Memory.alloc(8);iterator.writePointer(nil);
            const next=api('class_get_methods','pointer',['pointer','pointer']);
            for(let i=0;i<10000;i++){
                const method=next(k,iterator);if(method.isNull())return result;
                const name=api('method_get_name','pointer',['pointer'])(method).readUtf8String();
                if(!names.includes(name))continue;
                const args=[],count=api('method_get_param_count','uint',['pointer'])(method);
                for(let j=0;j<count;j++)args.push(typeName(api('method_get_param','pointer',['pointer','uint'])(method,j)));
                const native=method.readPointer();
                result.push({name,parameters:args,returns:typeName(api('method_get_return_type','pointer',['pointer'])(method)),
                    flags:api('method_get_flags','uint',['pointer','pointer'])(method,nil),
                    native_module_offset:native.isNull()?null:native.sub(lib.base).toString()});
            }
            throw Error('Method inventory outside limit');
        }
        function respawnFields(k){
            const iterator=Memory.alloc(8),result=[];iterator.writePointer(nil);
            const next=api('class_get_fields','pointer',['pointer','pointer']);
            for(let i=0;i<10000;i++){
                const f=next(k,iterator);if(f.isNull())return result;
                const name=api('field_get_name','pointer',['pointer'])(f).readUtf8String();
                const offset=Number(api('field_get_offset','ulong',['pointer'])(f));
                if(!name.toLowerCase().includes('respawn')&&offset!==136)continue;
                const type=typeName(api('field_get_type','pointer',['pointer'])(f));
                const flags=api('field_get_flags','int',['pointer'])(f),row={name,type,offset,flags};
                if((flags&16)!==0&&type==='System.Int32'){
                    const value=Memory.alloc(4);api('field_static_get_value','void',['pointer','pointer'])(f,value);row.value=value.readS32();
                }
                result.push(row);
            }
            throw Error('Field inventory outside limit');
        }
        const player=klass('Terraria','Player'),npc=klass('Terraria','NPC'),entity=klass('Terraria','Entity'),main=klass('Terraria','Main');
        if([player,npc,entity,main].some(k=>k.isNull()))throw Error('Respawn classes absent');
        return {pid:Process.id,architecture:Process.arch,read_only:true,game_methods_invoked:false,
            player_fields:fields(player,['respawnTimer','dead','name','difficulty','statLife','active']),
            entity_fields:fields(entity,['active','position','width','height']),
            npc_fields:fields(npc,['boss','type','active']),main_fields:fields(main,['npc','netMode','worldName']),
            player_methods:methods(player,['KillMe','UpdateDead','Spawn']),
            entity_methods:methods(entity,['get_active','get_Center']),
            npc_methods:methods(npc,['get_active']),
            player_respawn_fields:respawnFields(player),main_respawn_fields:respawnFields(main),
            main_methods:methods(main,['get_expertMode','get_LocalPlayer','get_gameMenu','get_GameMode'])};
    }finally{api('thread_detach','void',['pointer'])(thread);}
};
