'use strict';
// One own laboratory content ID. Arrays are copied through managed Array.Copy,
// including reference/struct arrays: no raw pointer copying across the GC.
globalThis.TMALContent = (() => {
    const ID=6196, BASE=3507;
    let ready=false, started=false, apiState=null, listener=null, lease=null, lastCommand=null;
    let sidecar=null,pendingRestore=null;
    function initialize() {
        if (ready) return true;
        if (Date.now()<globalThis.TMALContentDelayUntil) return false;
        if (started) throw Error('Content initialization already attempted');
        const lib=Process.findModuleByName('libil2cpp.so');
        if (lib===null || !managedReady || managedMode!=='mod-item') return false;
        const api=(name,result,args)=>new NativeFunction(lib.getExportByName('il2cpp_'+name),result,args);
        const domain=api('domain_get','pointer',[])();
        if(domain.isNull()||api('get_corlib','pointer',[])().isNull())return false;
        const thread=api('thread_attach','pointer',['pointer'])(domain);
        const detach=api('thread_detach','void',['pointer']);
        const roots=[];
        try {
            const cstr=s=>Memory.allocUtf8String(s);
            const getImage=api('assembly_get_image','pointer',['pointer']);
            const imageName=api('image_get_name','pointer',['pointer']);
            const getClass=api('class_from_name','pointer',['pointer','pointer','pointer']);
            const count=Memory.alloc(8);count.writeU64(0);
            const assemblies=api('domain_get_assemblies','pointer',['pointer','pointer'])(domain,count);
            let image=ptr(0),arrayClass=ptr(0);
            for (let i=0;i<count.readU64().toNumber();i++) {
                const candidate=getImage(assemblies.add(i*8).readPointer());
                if (imageName(candidate).readUtf8String()==='Assembly-CSharp.dll') image=candidate;
                if (arrayClass.isNull()) arrayClass=getClass(candidate,cstr('System'),cstr('Array'));
            }
            if (image.isNull()||arrayClass.isNull()) throw Error('Content or System.Array class missing');
            const klass=(ns,name)=>getClass(image,cstr(ns),cstr(name));
            const fieldGet=api('class_get_field_from_name','pointer',['pointer','pointer']);
            const get=api('field_static_get_value','void',['pointer','pointer']);
            const set=api('field_static_set_value','void',['pointer','pointer']);
            const arrayLength=api('array_length','ulong',['pointer']);
            const value=Memory.alloc(8);
            const textures=klass('Terraria.GameContent','TextureAssets');
            const textureField=fieldGet(textures,cstr('Item'));get(textureField,value);
            if (value.readPointer().isNull()) return false;
            if (arrayLength(value.readPointer()).toNumber()!==ID) throw Error('Unexpected mobile item count');
            started=true;
            const invoke=api('runtime_invoke','pointer',['pointer','pointer','pointer','pointer']);
            const gcNew=api('gchandle_new','uint',['pointer','uchar']);
            const gcFree=api('gchandle_free','void',['uint']);
            const int=n=>{const p=Memory.alloc(4);p.writeS32(n);return p;};
            function call(method,object,args) {
                const params=Memory.alloc(Math.max(8,args.length*8));
                args.forEach((arg,i)=>params.add(i*8).writePointer(arg));
                const exception=Memory.alloc(8);exception.writePointer(ptr(0));
                const result=invoke(method,object,params,exception);
                if (!exception.readPointer().isNull()) {
                    const buffer=Memory.alloc(2048);
                    api('format_exception','void',['pointer','pointer','int'])(exception.readPointer(),buffer,2048);
                    throw Error(buffer.readUtf8String());
                }
                return result;
            }
            const methods=api('class_get_methods','pointer',['pointer','pointer']);
            const methodName=api('method_get_name','pointer',['pointer']);
            const paramCount=api('method_get_param_count','uint',['pointer']);
            const paramType=api('method_get_param','pointer',['pointer','uint']);
            const typeCode=api('type_get_type','int',['pointer']);
            const it=Memory.alloc(8);it.writePointer(ptr(0));let copy=ptr(0);
            for (;;) {
                const method=methods(arrayClass,it);if (method.isNull()) break;
                if (methodName(method).readUtf8String()==='Copy' && paramCount(method)===5 && typeCode(paramType(method,1))===8 && typeCode(paramType(method,4))===8) {copy=method;break;}
            }
            if (copy.isNull()) throw Error('Managed Array.Copy(Array,int,Array,int,int) missing');
            const fields=api('class_get_fields','pointer',['pointer','pointer']);
            const flags=api('field_get_flags','int',['pointer']);
            const fieldType=api('field_get_type','pointer',['pointer']);
            const fieldName=api('field_get_name','pointer',['pointer']);
            const objectClass=api('object_get_class','pointer',['pointer']);
            const arrayNew=api('array_new_specific','pointer',['pointer','ulong']);
            const item=klass('Terraria','Item'),main=klass('Terraria','Main'),lang=klass('Terraria','Lang'),itemID=klass('Terraria.ID','ItemID');
            const targets=[item,main,lang,textures];
            const nested=api('class_get_nested_types','pointer',['pointer','pointer']);
            const className=api('class_get_name','pointer',['pointer']);
            it.writePointer(ptr(0));
            for (;;) {const k=nested(itemID,it);if(k.isNull())break;if(className(k).readUtf8String()==='Sets')targets.push(k);}
            const replacements=[];
            for (const target of targets) {
                it.writePointer(ptr(0));
                for (;;) {
                    const field=fields(target,it);if(field.isNull())break;
                    if((flags(field)&0x10)===0 || typeCode(fieldType(field))!==29)continue;
                    get(field,value);const old=value.readPointer();
                    if(old.isNull()||arrayLength(old).toNumber()!==ID)continue;
                    const array=arrayNew(objectClass(old),ID+1);
                    if(array.isNull())throw Error('Content allocation failed');
                    roots.push(gcNew(array,0));
                    call(copy,ptr(0),[old,int(0),array,int(0),int(ID)]);
                    call(copy,ptr(0),[old,int(BASE),array,int(ID),int(1)]);
                    roots.push(gcNew(old,0));
                    replacements.push({field,array,old,name:fieldName(field).readUtf8String()});
                }
            }
            if(replacements.length!==129)throw Error('Table count differs from read-only recon: '+replacements.length);
            const methodGet=api('class_get_method_from_name','pointer',['pointer','pointer','int']);
            const offset=api('field_get_offset','size_t',['pointer']);
            const numericReaders={};
            function intOffset(name) {
                const f=fieldGet(item,cstr(name));
                if(f.isNull()||(flags(f)&0x10)!==0)throw Error('Invalid item field '+name);
                const type=fieldType(f);let code=typeCode(type);
                if(code===17) {
                    const owner=api('class_from_type','pointer',['pointer'])(type);
                    const underlying=api('class_enum_basetype','pointer',['pointer'])(owner);
                    if(underlying.isNull())throw Error('Expected an enum field: '+name);
                    code=typeCode(underlying);
                }
                if(code!==8 && !(name==='useStyle'&&code===5))throw Error('Invalid numeric item field '+name+' type='+code);
                numericReaders[name]=code===5?'readU8':'readS32';
                const n=Number(offset(f));if(n<16||n>8192)throw Error('Invalid field offset');return n;
            }
            const offsets={type:intOffset('type'),damage:intOffset('damage')};
            for(const name of ['stack','useStyle','useTime','useAnimation','shoot'])offsets[name]=intOffset(name);
            const prefixField=fieldGet(item,cstr('prefix')),favoriteField=fieldGet(item,cstr('favorited'));
            if(prefixField.isNull()||favoriteField.isNull()||![5,8].includes(typeCode(fieldType(prefixField)))||typeCode(fieldType(favoriteField))!==2)
                throw Error('Sidecar item fields differ');
            const prefixOffset=Number(offset(prefixField)),favoriteOffset=Number(offset(favoriteField));
            const prefixReader=typeCode(fieldType(prefixField))===5?'readU8':'readS32';
            const defaults=methodGet(item,cstr('SetDefaults'),2);
            const setName=methodGet(item,cstr('SetNameOverride'),1);
            const clone=methodGet(item,cstr('Clone'),0);
            const netMode=fieldGet(main,cstr('netMode'));
            const stringNew=api('string_new','pointer',['pointer']);
            if(defaults.isNull()||setName.isNull()||clone.isNull()||netMode.isNull())throw Error('Item entry points missing');
            function applyContent(object) {
                const damage=TMALManaged.damage(ID,object.add(offsets.damage).readS32());
                const name=TMALManaged.name(ID);
                if(damage!==37||name!=='PC ModItem Test Blade')throw Error('Own ModItem profile differs');
                object.add(offsets.type).writeS32(ID);object.add(offsets.damage).writeS32(damage);
                const text=stringNew(cstr(name)),handle=gcNew(text,0);
                try{call(setName,object,[text]);}finally{gcFree(handle);}
                log('MODITEM_DEFAULTS id='+ID+' damage='+damage);
            }
            // Commit after all allocation/copy checks. No new ID is used earlier.
            // IL2CPP reference-field setter accepts the object directly (unlike
            // the getter's output buffer). Verify each reference immediately.
            try {
                for (const row of replacements) {
                    set(row.field,row.array);get(row.field,value);
                    if(!value.readPointer().equals(row.array)||arrayLength(value.readPointer()).toNumber()!==ID+1)
                        throw Error('Static reference differs: '+row.name);
                }
            } catch(error) {
                for(const row of replacements)set(row.field,row.old);
                throw error;
            }
            listener=Interceptor.attach(defaults.readPointer(),{
                onEnter(args) {
                    this.custom=false;
                    if(args[1].toInt32()!==ID)return;
                    get(netMode,value);if(value.readS32()!==0)return;
                    this.custom=true;this.item=args[0];args[1]=ptr(BASE);
                },
                onLeave() {
                    if(!this.custom)return;
                    applyContent(this.item);
                }
            });
            // The mobile lookup keeps a compiled vanilla count. Alias only this
            // test item's localized tooltip; the actual item's type stays6196.
            const getTooltip=methodGet(lang,cstr('GetTooltip'),1);
            if(getTooltip.isNull())throw Error('Localized tooltip lookup missing');
            Interceptor.attach(getTooltip.readPointer(),{onEnter(args){if(args[0].toInt32()===ID)args[0]=ptr(BASE);}});
            const player=klass('Terraria','Player');
            const localPlayer=methodGet(main,cstr('get_LocalPlayer'),0),gameMenu=methodGet(main,cstr('get_gameMenu'),0);
            const playerName=fieldGet(player,cstr('name')),inventory=fieldGet(player,cstr('inventory'));
            const worldName=fieldGet(main,cstr('worldName'));
            if(player.isNull()||localPlayer.isNull()||gameMenu.isNull()||playerName.isNull()||inventory.isNull()||worldName.isNull())throw Error('Test-player guard unavailable');
            const stringChars=api('string_chars','pointer',['pointer']),stringLength=api('string_length','int',['pointer']);
            const stringValue=p=>{if(p.isNull())return '';const n=stringLength(p);if(n<0||n>64)throw Error('Lab name length invalid');return stringChars(p).readUtf16String(n);};
            const writeBarrier=api('gc_wbarrier_set_field','void',['pointer','pointer','pointer']);
            const restoreFields=['_nameOverride','_affixName','_affixType','_affixPrefix','_affixLang'].map(name=>{
                const field=fieldGet(item,cstr(name));
                if(field.isNull())throw Error('Item restoration field missing: '+name);
                const n=Number(offset(field));let code=typeCode(fieldType(field));
                if(code===17)code=typeCode(api('class_enum_basetype','pointer',['pointer'])(api('class_from_type','pointer',['pointer'])(fieldType(field))));
                if(n<16||n>8192||![5,8,14].includes(code))throw Error('Unexpected restoration field: '+name);
                return {name,offset:n,code};
            });
            const header=Number(api('array_object_header_size','size_t',[])());
            if(header<24||header>128)throw Error('Array header outside expected bounds');
            apiState={item,main,fieldGet,get,offset,typeCode,fieldType,methodGet,cstr,call,int,gcNew,gcFree,offsets,
                      objectNew:api('object_new','pointer',['pointer']),defaults,arrayLength,applyContent,clone,numericReaders,
                      arrayClass,copy,threadAttach:api('thread_attach','pointer',['pointer']),detach,domain,
                      threadCurrent:api('thread_current','pointer',[]),
                      localPlayer,gameMenu,nameOffset:Number(offset(playerName)),inventoryOffset:Number(offset(inventory)),worldName,netMode,
                      stringValue,writeBarrier,restoreFields,header,unbox:api('object_unbox','pointer',['pointer'])};
            apiState.fingerprint=object=>({type:object.add(offsets.type).readS32(),damage:object.add(offsets.damage).readS32(),
                stack:object.add(offsets.stack).readS32(),prefix:object.add(prefixOffset)[prefixReader](),favorite:object.add(favoriteOffset).readU8()!==0});
            const samples=klass('Terraria.ID','ContentSamples');
            if(samples.isNull())throw Error('Mobile ContentSamples class missing');
            const sampleFields=['ItemsByType','ItemCreativeSortingId'].map(name=>{
                const field=fieldGet(samples,cstr(name));
                if(field.isNull())throw Error('ContentSamples field missing: '+name);
                return {name,field};
            });
            const fromType=api('class_from_type','pointer',['pointer']);
            const isValueClass=api('class_is_valuetype','bool',['pointer']);
            apiState.registerSamples=()=>{
                const added=[];
                try {
                    for(const row of sampleFields) {
                        const storage=Memory.alloc(8);get(row.field,storage);const dictionary=storage.readPointer();
                        if(dictionary.isNull())throw Error('ContentSamples not initialized: '+row.name);
                        const k=objectClass(dictionary),contains=methodGet(k,cstr('ContainsKey'),1);
                        const read=methodGet(k,cstr('get_Item'),1),write=methodGet(k,cstr('set_Item'),2),remove=methodGet(k,cstr('Remove'),1);
                        if(contains.isNull()||read.isNull()||write.isNull()||remove.isNull())throw Error('Dictionary API missing');
                        const exists=apiState.unbox(call(contains,dictionary,[int(ID)])).readU8()!==0;
                        if(exists)continue;
                        const original=call(read,dictionary,[int(BASE)]);
                        if(original.isNull())throw Error('Content sample template missing');
                        let replacement=original;
                        if(row.name==='ItemsByType') {
                            replacement=call(clone,original,[]);
                            if(replacement.isNull()||replacement.equals(original))throw Error('Sample clone failed');
                            const h=gcNew(replacement,0);
                            try {applyContent(replacement);call(write,dictionary,[int(ID),replacement]);}
                            finally {gcFree(h);}
                        } else {
                            const boxed=gcNew(original,0);
                            try {
                                const valueClass=objectClass(original);
                                const argument=isValueClass(valueClass)?apiState.unbox(original):original;
                                call(write,dictionary,[int(ID),argument]);
                            } finally {gcFree(boxed);}
                        }
                        added.push({dictionary,remove});
                        if(apiState.unbox(call(contains,dictionary,[int(ID)])).readU8()===0)throw Error('Sample key readback failed');
                        log('MODITEM_SAMPLE_REGISTERED table='+row.name+' id='+ID);
                    }
                } catch(error) {
                    for(const row of added)call(row.remove,row.dictionary,[int(ID)]);
                    throw error;
                }
            };
            // Trace before restoration guards so entry/exit show the boundary.
            const fileData=klass('Terraria.IO','PlayerFileData');
            if(fileData.isNull())throw Error('PlayerFileData trace target missing');
            const traceFlags=api('method_get_flags','uint',['pointer','pointer']);
            const pathString=p=>{if(p.isNull())return '';const n=stringLength(p);if(n<0||n>1024)throw Error('Trace path length invalid');return stringChars(p).readUtf16String(n);};
            TMALSaveTrace.install({...apiState,player,fileData,methodFlags:traceFlags,pathString});
            installPersistence({...apiState,player,fileData,fileBase:klass('Terraria.IO','FileData'),pathString});
            // Restore a leased blade before either player save entry point runs.
            for(const [name,n] of [['SavePlayer',3],['InternalSavePlayerFile',1]]) {
                const method=methodGet(player,cstr(name),n);if(method.isNull())throw Error('Player save guard missing: '+name);
                Interceptor.attach(method.readPointer(),{onEnter(){restore('player-save');}});
            }
            const itemCheck=methodGet(player,cstr('ItemCheck'),0);
            if(itemCheck.isNull())throw Error('Game-thread dispatcher missing');
            let lastPoll=0;
            Interceptor.attach(itemCheck.readPointer(),{onEnter(){
                if(Date.now()-lastPoll<500)return;
                lastPoll=Date.now();poll();
            }});
            const weaponDamage=methodGet(player,cstr('GetWeaponDamage'),1);
            let useLogs=0,airLogs=0,tooltipCalls=0;
            const startUse=methodGet(player,cstr('ItemCheck_StartActualUse'),1);
            if(startUse.isNull())throw Error('Item use observer unavailable');
            Interceptor.attach(startUse.readPointer(),{onEnter(args){
                if(!args[1].isNull()&&args[1].add(offsets.type).readS32()===ID&&useLogs++<5)
                    log('MODITEM_ACTUAL_USE id='+ID+' damage='+args[1].add(offsets.damage).readS32());
            }});
            const isAir=methodGet(item,cstr('get_IsAir'),0);
            if(isAir.isNull())throw Error('Item validity observer unavailable');
            Interceptor.attach(isAir.readPointer(),{
                onEnter(args){this.custom=args[0].add(offsets.type).readS32()===ID;},
                onLeave(result){if(this.custom&&airLogs++<1)log('MODITEM_IS_AIR value='+result.toInt32());}
            });
            const linesInfo=methodGet(main,cstr('MouseText_DrawItemTooltip_GetLinesInfo'),12);
            if(!linesInfo.isNull()) {
                const methodFlags=api('method_get_flags','uint',['pointer','pointer']);
                const implFlags=Memory.alloc(4);implFlags.writeU32(0);
                const itemArg=(methodFlags(linesInfo,implFlags)&0x10)!==0?0:1;
                Interceptor.attach(linesInfo.readPointer(),{onEnter(args){
                    if(!args[itemArg].isNull()&&args[itemArg].add(offsets.type).readS32()===ID&&lease!==null) {
                        // The native mobile UI still has vanilla-only lookups.
                        // Give this formatter an isolated display object; the
                        // inventory, sample and combat objects keep their ID.
                        args[itemArg]=lease.display;
                        if(tooltipCalls++<1)log('MODITEM_TOOLTIP_DISPLAY_ALIAS actualId='+ID+' displayId='+BASE+' damage=37');
                    }
                }});
            }
            const useField=fieldGet(player,cstr('controlUseItem'));
            if(weaponDamage.isNull()||useField.isNull()||typeCode(fieldType(useField))!==2)throw Error('Combat observation unavailable');
            const useOffset=Number(offset(useField));let attackLogs=0,tooltipLogs=0;
            Interceptor.attach(weaponDamage.readPointer(),{
                onEnter(args){
                    this.custom=!args[1].isNull()&&args[1].add(offsets.type).readS32()===ID;
                    if(this.custom){this.usingItem=args[0].add(useOffset).readU8()!==0;this.input=args[1].add(offsets.damage).readS32();}
                },
                onLeave(result){
                    if(this.custom&&((this.usingItem&&attackLogs++<5)||(!this.usingItem&&tooltipLogs++<1)))
                        log('MODITEM_WEAPON_DAMAGE input='+this.input+' actual='+result.toInt32()+' usingItem='+this.usingItem);
                }
            });
            ready=true;
            log('CONTENT_TABLES_READY resized='+replacements.length+' old='+ID+' new='+(ID+1)+' textureAlias='+BASE);
            // Ephemeral object only: never inserted into inventory or saved.
            const temporary=apiState.objectNew(item),handle=gcNew(temporary,0);
            try {
                const ctor=methodGet(item,cstr('.ctor'),0);if(ctor.isNull())throw Error('Item constructor missing');
                call(ctor,temporary,[]);call(defaults,temporary,[int(ID),ptr(0)]);
                const report={id:temporary.add(offsets.type).readS32(),damage:temporary.add(offsets.damage).readS32(),inventory_changed:false};
                if(report.id!==ID||report.damage!==37)throw Error('Transient item differs: '+JSON.stringify(report));
                log('MODITEM_OBJECT_OK '+JSON.stringify(report));
            } finally {gcFree(handle);}
            return true;
        } finally {
            if(apiState)for(const handle of roots)apiState.gcFree(handle);
            else {const free=api('gchandle_free','void',['uint']);for(const handle of roots)free(handle);}
            if(!thread.isNull())detach(thread);
        }
    }
    function queueRestore(player,row) {
        if(pendingRestore!==null)apiState.gcFree(pendingRestore.handle);
        pendingRestore={player,row,handle:apiState.gcNew(player,0)};
    }
    function installPersistence(a) {
        sidecar=TMALSidecar.store();
        const offsetField=(k,name,code)=>{
            const f=a.fieldGet(k,a.cstr(name));
            if(f.isNull()||a.typeCode(a.fieldType(f))!==code)throw Error('Sidecar file field differs: '+name);
            const n=Number(a.offset(f));if(n<16||n>16384)throw Error('Sidecar file offset differs');return n;
        };
        const pOffset=offsetField(a.fileData,'_player',18),pathOffset=offsetField(a.fileBase,'_path',14),cloudOffset=offsetField(a.fileBase,'_isCloudSave',2);
        const fromFile=file=>{
            if(file.isNull()||file.add(cloudOffset).readU8()!==0||a.pathString(file.add(pathOffset).readPointer())!==TMALSidecar.PLAYER)return null;
            const p=file.add(pOffset).readPointer();
            return p.isNull()||a.stringValue(p.add(a.nameOffset).readPointer())!=='TMAL_Test'?null:p;
        };
        const slotItem=(p,index)=>{
            const inv=p.add(a.inventoryOffset).readPointer();
            if(inv.isNull()||index<0||index>=Math.min(58,a.arrayLength(inv).toNumber()))throw Error('Sidecar slot outside inventory');
            const item=inv.add(a.header+index*8).readPointer();if(item.isNull())throw Error('Sidecar placeholder absent');return item;
        };
        const saves=new Map();
        const save=a.methodGet(a.player,a.cstr('SavePlayer'),3);
        const internal=a.methodGet(a.player,a.cstr('InternalSavePlayerFile'),1);
        const load=a.methodGet(a.player,a.cstr('LoadPlayer'),2);
        const serialize=a.methodGet(a.item,a.cstr('Serialize'),2);
        for(const m of [save,internal,load,serialize])if(m.isNull())throw Error('Sidecar method missing');
        Interceptor.attach(save.readPointer(),{
            onEnter(args) {
                this.thread=Process.getCurrentThreadId();this.active=false;
                try {
                    const p=fromFile(args[0]);if(p===null)return;
                    if(saves.has(this.thread))throw Error('Nested player save rejected');
                    let item=null;
                    const previous=sidecar.read(),oldHash=sidecar.hash();
                    if(previous&&previous.playerSha256!==oldHash)throw Error('Stale sidecar retained; save rebase rejected');
                    if(lease!==null&&lease.persistent&&lease.player.equals(p)) {
                        const matches=[],length=Math.min(58,a.arrayLength(lease.inventory).toNumber());
                        for(let i=0;i<length;i++)if(lease.inventory.add(a.header+i*8).readPointer().equals(lease.blade))matches.push(i);
                        if(matches.length!==1)throw Error('Persistent blade moved outside supported inventory');
                        const placeholder=a.fingerprint(lease.original),live=a.fingerprint(lease.blade);
                        if(live.stack!==placeholder.stack||live.prefix!==placeholder.prefix||live.favorite!==placeholder.favorite)
                            throw Error('Persistent item attributes changed; snapshot rejected');
                        item={key:TMALSidecar.KEY,slot:matches[0],placeholder,data:{version:1}};
                    } else if(previous) {
                        // Includes disabled/unknown content: retain its stable identity.
                        item=TMALSidecar.bind(previous,oldHash,a.fingerprint(slotItem(p,previous.items[0].slot)));
                    }
                    if(!item)return;
                    saves.set(this.thread,{player:p,previous,oldHash,item,serialized:0,customSerialized:0});
                    this.active=true;log('SIDECAR_CAPTURE key='+item.key+' slot='+item.slot+' thread='+this.thread);
                } catch(error){log('SIDECAR_SAVE_REJECTED '+error.message);}
            },
            onLeave() {if(this.active)saves.delete(this.thread);}
        });
        Interceptor.attach(internal.readPointer(),{
            onEnter(args) {
                this.state=null;
                try {
                    const state=saves.get(Process.getCurrentThreadId()),p=fromFile(args[0]);
                    if(!state||p===null||!p.equals(state.player))return;
                    if(!TMALSidecar.samePlaceholder(state.item.placeholder,a.fingerprint(slotItem(p,state.item.slot))))
                        throw Error('Restored placeholder differs before serialization');
                    this.state=state;state.writing=true;
                } catch(error){log('SIDECAR_SAVE_REJECTED '+error.message);}
            },
            onLeave() {
                const state=this.state;if(!state)return;state.writing=false;
                try {
                    if(state.serialized<58||state.customSerialized!==0)throw Error('Unexpected item serialization boundary');
                    const row=TMALSidecar.next(state.previous,state.oldHash,sidecar.hash(),state.item);
                    sidecar.commit(row);queueRestore(state.player,row);
                    log('SIDECAR_COMMITTED generation='+row.generation+' key='+state.item.key+' slot='+state.item.slot+
                        ' serialized='+state.serialized+' customSerialized='+state.customSerialized+' enabled='+managedEnabled);
                } catch(error){log('SIDECAR_COMMIT_FAILED '+error.message);}
            }
        });
        Interceptor.attach(serialize.readPointer(),{onEnter(args){
            const state=saves.get(Process.getCurrentThreadId());if(!state||!state.writing)return;
            state.serialized++;if(args[0].add(a.offsets.type).readS32()===ID)state.customSerialized++;
        }});
        Interceptor.attach(load.readPointer(),{
            onEnter(args) {this.lab=args[1].toInt32()===0&&a.pathString(args[0])===TMALSidecar.PLAYER;},
            onLeave(result) {
                if(!this.lab)return;
                try {
                    const p=fromFile(result);if(p===null)throw Error('Expected test player absent after load');
                    const row=sidecar.read();if(!row)return;
                    const item=TMALSidecar.bind(row,sidecar.hash(),a.fingerprint(slotItem(p,row.items[0].slot)));
                    queueRestore(p,row);
                    log('SIDECAR_LOAD_VALID generation='+row.generation+' key='+item.key+' known='+TMALSidecar.known(item));
                } catch(error){log('SIDECAR_LOAD_REJECTED '+error.message);}
            }
        });
        log('SIDECAR_READY testProfile=TMAL_Test inventoryOnly=true');
    }
    function issue(player,index,original,persistent) {
        const a=apiState,inventory=player.add(a.inventoryOffset).readPointer(),slot=inventory.add(a.header+index*8);
        a.registerSamples();
        const blade=a.call(a.clone,original,[]);
        if(blade.isNull()||blade.equals(original))throw Error('Vanilla template clone failed');
        const handles=[a.gcNew(player,0),a.gcNew(inventory,0),a.gcNew(original,0),a.gcNew(blade,0)];
        try {
            a.applyContent(blade);
            if(blade.add(a.offsets.type).readS32()!==ID||blade.add(a.offsets.damage).readS32()!==37)
                throw Error('New content object differs before inventory write');
            const profile={};
            for(const field of ['stack','useStyle','useTime','useAnimation','shoot'])profile[field]=blade.add(a.offsets[field])[a.numericReaders[field]]();
            if(profile.stack!==1||profile.useStyle<=0||profile.useTime<=0)throw Error('Vanilla inventory template is not usable');
            log('MODITEM_USE_PROFILE '+JSON.stringify(profile));
            const display=a.call(a.clone,blade,[]);
            if(display.isNull()||display.equals(blade))throw Error('UI display clone failed');
            handles.push(a.gcNew(display,0));display.add(a.offsets.type).writeS32(BASE);
            a.writeBarrier(inventory,slot,blade);
            if(!slot.readPointer().equals(blade))throw Error('Inventory reference readback differs');
            lease={player,inventory,original,blade,display,handles,index,persistent,until:persistent?Infinity:Date.now()+45000};
            log((persistent?'MODITEM_PERSISTENT_STARTED':'MODITEM_LEASE_STARTED')+' player=TMAL_Test world=TMAL_Lab slot='+index+' id='+ID+' damage=37');
        } catch(error) {
            if(slot.readPointer().equals(blade))a.writeBarrier(inventory,slot,original);
            for(const handle of handles)a.gcFree(handle);throw error;
        }
    }
    function restore(reason) {
        if(lease===null)return;
        const saved=lease;
        const a=apiState;
        try {
            // Save can run on a worker. Restore the reference first and copy
            // only our changed fields; never invoke managed game code here.
            const slot=saved.inventory.add(a.header+saved.index*8);
            const slotRestored=slot.readPointer().equals(saved.blade);
            if(slotRestored)a.writeBarrier(saved.inventory,slot,saved.original);
            if(slotRestored&&!slot.readPointer().equals(saved.original))throw Error('Original slot restoration failed');
            saved.blade.add(a.offsets.type).writeS32(saved.original.add(a.offsets.type).readS32());
            saved.blade.add(a.offsets.damage).writeS32(saved.original.add(a.offsets.damage).readS32());
            for(const field of a.restoreFields) {
                const target=saved.blade.add(field.offset),source=saved.original.add(field.offset);
                if(field.code===14)a.writeBarrier(saved.blade,target,source.readPointer());
                else if(field.code===5)target.writeU8(source.readU8());
                else target.writeS32(source.readS32());
            }
            if(saved.blade.add(a.offsets.type).readS32()!==BASE)throw Error('Transient type restoration failed');
            lease=null;
            log('MODITEM_LEASE_RESTORED reason='+reason+' originalSlot='+slotRestored+' transientType='+saved.blade.add(a.offsets.type).readS32());
            for(const handle of saved.handles)a.gcFree(handle);
        } catch(error) {log('MODITEM_RESTORE_FAILED '+error.message);}
    }
    function poll() {
        if(!ready)return;
        const a=apiState,current=a.threadCurrent(),owned=current.isNull();
        const thread=owned?a.threadAttach(a.domain):current;
        try {
            if(lease!==null && (!managedEnabled||Date.now()>=lease.until))restore(managedEnabled?'timeout':'disabled');
            if(pendingRestore!==null&&lease===null&&managedEnabled) {
                const pending=pendingRestore,item=pending.row.items[0],value=Memory.alloc(8);
                if(a.unbox(a.call(a.gameMenu,ptr(0),[])).readU8()===0) {
                    a.get(a.netMode,value);const offline=value.readS32()===0;
                    a.get(a.worldName,value);const world=a.stringValue(value.readPointer());
                    const player=a.call(a.localPlayer,ptr(0),[]);
                    if(offline&&world==='TMAL_Lab'&&!player.isNull()&&player.equals(pending.player)&&TMALSidecar.known(item)) {
                        // Recheck the encrypted player file immediately before applying.
                        const inv=player.add(a.inventoryOffset).readPointer(),original=inv.add(a.header+item.slot*8).readPointer();
                        try {
                            TMALSidecar.bind(pending.row,sidecar.hash(),a.fingerprint(original));
                            issue(player,item.slot,original,true);
                            log('SIDECAR_RESTORED generation='+pending.row.generation+' key='+item.key+' id='+ID+' damage=37');
                        } finally {a.gcFree(pending.handle);pendingRestore=null;}
                    }
                }
            }
            let raw;
            try{raw=File.readAllText(MANAGED_ROOT+'/../content-command.json');}catch(_){return;}
            if(raw===lastCommand)return;
            lastCommand=raw;
            if(raw.length>256)throw Error('Own test command too large');
            const command=JSON.parse(raw);
            if(!['test-blade','persist-blade','prepare-blade'].includes(command.action)||typeof command.nonce!=='string'||!/^[a-f0-9-]{36}$/.test(command.nonce))throw Error('Invalid own test command');
            if(!managedEnabled||lease!==null)throw Error('Test disabled or already leased');
            if(a.unbox(a.call(a.gameMenu,ptr(0),[])).readU8()!==0)throw Error('Enter TMAL_Test / TMAL_Lab first');
            const value=Memory.alloc(8);a.get(a.netMode,value);if(value.readS32()!==0)throw Error('Single-player required');
            a.get(a.worldName,value);if(a.stringValue(value.readPointer())!=='TMAL_Lab')throw Error('Test world required');
            const player=a.call(a.localPlayer,ptr(0),[]);
            if(player.isNull()||a.stringValue(player.add(a.nameOffset).readPointer())!=='TMAL_Test')throw Error('Test player required');
            const inventory=player.add(a.inventoryOffset).readPointer();
            if(inventory.isNull())throw Error('Player inventory missing');
            const length=a.arrayLength(inventory).toNumber();
            if(length<10||length>128)throw Error('Unexpected inventory size');
            const matches=[];
            for(let index=0;index<length;index++) {
                const original=inventory.add(a.header+index*8).readPointer();
                if(!original.isNull()&&original.add(a.offsets.type).readS32()===BASE)matches.push({index,original});
            }
            if(matches.length!==1)throw Error('Test inventory must have exactly one Copper Shortsword');
            const {index,original}=matches[0],persistent=command.action==='persist-blade';
            if(command.action==='prepare-blade') {
                if(sidecar.read()!==null)throw Error('Existing sidecar retained; preparation forbidden');
                const before=a.fingerprint(original);
                if(before.stack!==1||before.favorite)throw Error('Preparation requires one unfavorited laboratory sword');
                a.call(a.defaults,original,[a.int(BASE),ptr(0)]);
                const after=a.fingerprint(original);
                if(after.type!==BASE||after.damage!==5||after.prefix!==0||after.stack!==1)
                    throw Error('Prepared vanilla sword differs');
                log('MODITEM_TEMPLATE_PREPARED '+JSON.stringify({slot:index,before,after}));return;
            }
            if(persistent) {
                if(sidecar.read()!==null)throw Error('Existing sidecar retained; reload instead of replacing it');
                TMALSidecar.next(null,null,sidecar.hash(),{key:TMALSidecar.KEY,slot:index,placeholder:a.fingerprint(original),data:{version:1}});
            }
            issue(player,index,original,persistent);
        } catch(error){log('MODITEM_TEST_REJECTED '+error.message);}
        finally {if(owned&&!thread.isNull())a.detach(thread);}
    }
    return {initialize,isReady:()=>ready,poll};
})();
const contentTimer=setInterval(()=>{
    try {if(TMALContent.initialize())clearInterval(contentTimer);}
    catch(error){clearInterval(contentTimer);log('CONTENT_FAILED '+error.stack);}
},3000);
// Commands run on Player.ItemCheck's game thread: the mobile game's context
// properties are not available on Frida's scheduler thread.
