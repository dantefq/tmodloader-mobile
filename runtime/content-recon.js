'use strict';
// Read-only content inspection. No arrays, IDs, inventory or saves are changed.
(() => {
    let attempts=0;
    const timer=setInterval(()=>{
        const lib=Process.findModuleByName('libil2cpp.so');
        if (lib===null) return;
        let thread=null,detach=null;
        try {
            const api=(name,result,args)=>new NativeFunction(lib.getExportByName('il2cpp_'+name),result,args);
            const domain=api('domain_get','pointer',[])();
            if (domain.isNull()) return;
            detach=api('thread_detach','void',['pointer']);
            thread=api('thread_attach','pointer',['pointer'])(domain);
            const cstr=s=>Memory.allocUtf8String(s);
            const count=Memory.alloc(8);count.writeU64(0);
            const assemblies=api('domain_get_assemblies','pointer',['pointer','pointer'])(domain,count);
            const imageGet=api('assembly_get_image','pointer',['pointer']);
            const imageName=api('image_get_name','pointer',['pointer']);
            let image=ptr(0);
            const n=count.readU64().toNumber();
            if (n>2048) throw Error('Unexpected image count');
            for (let i=0;i<n;i++) {
                const candidate=imageGet(assemblies.add(i*8).readPointer());
                if (imageName(candidate).readUtf8String()==='Assembly-CSharp.dll') image=candidate;
            }
            if (image.isNull()) return;
            const klassGet=api('class_from_name','pointer',['pointer','pointer','pointer']);
            const fieldGet=api('class_get_field_from_name','pointer',['pointer','pointer']);
            const fields=api('class_get_fields','pointer',['pointer','pointer']);
            const fieldName=api('field_get_name','pointer',['pointer']);
            const fieldType=api('field_get_type','pointer',['pointer']);
            const flags=api('field_get_flags','int',['pointer']);
            const code=api('type_get_type','int',['pointer']);
            const typeName=api('type_get_name','pointer',['pointer']);
            const free=api('free','void',['pointer']);
            const get=api('field_static_get_value','void',['pointer','pointer']);
            const length=api('array_length','ulong',['pointer']);
            const textures=klassGet(image,cstr('Terraria.GameContent'),cstr('TextureAssets'));
            const itemTextures=fieldGet(textures,cstr('Item'));
            const value=Memory.alloc(8);value.writePointer(ptr(0));get(itemTextures,value);
            if (value.readPointer().isNull()) {
                if (++attempts>=60) {clearInterval(timer);log('CONTENT_RECON_FAILED texture table not ready');}
                return;
            }
            clearInterval(timer);
            const report={architecture:Process.arch,classes:[],itemTextureLength:length(value.readPointer()).toNumber()};
            const roots=[['Terraria','Item'],['Terraria','Main'],['Terraria','Lang'],['Terraria.ID','ItemID'],['Terraria.GameContent','TextureAssets']];
            const targets=roots.map(([ns,name])=>({name:ns+'.'+name,klass:klassGet(image,cstr(ns),cstr(name))}));
            const nested=api('class_get_nested_types','pointer',['pointer','pointer']);
            const klassName=api('class_get_name','pointer',['pointer']);
            const it=Memory.alloc(8);it.writePointer(ptr(0));
            for (;;) {
                const child=nested(targets[3].klass,it);if (child.isNull()) break;
                if (klassName(child).readUtf8String()==='Sets') targets.push({name:'Terraria.ID.ItemID+Sets',klass:child});
            }
            for (const target of targets) {
                if (target.klass.isNull()) continue;
                const rows=[];const iterator=Memory.alloc(8);iterator.writePointer(ptr(0));
                for (let i=0;i<4096;i++) {
                    const field=fields(target.klass,iterator);if (field.isNull()) break;
                    const name=fieldName(field).readUtf8String();const type=fieldType(field);const kind=code(type);
                    if ((flags(field)&0x10)===0) continue;
                    if (kind!==29 && !(target.name.endsWith('ItemID')&&name==='Count')) continue;
                    const typename=typeName(type);const row={name,type:typename.readUtf8String()};free(typename);
                    value.writeU64(0);get(field,value);
                    if (kind===29) {
                        const array=value.readPointer();row.length=array.isNull()?null:length(array).toNumber();
                    } else row.constant=value.readU32();
                    rows.push(row);
                }
                report.classes.push({name:target.name,fields:rows});
            }
            // Per-class lines avoid Android log's message-size truncation.
            log('CONTENT_RECON_HEADER '+JSON.stringify({architecture:report.architecture,itemTextureLength:report.itemTextureLength}));
            for (const group of report.classes) {
                for (let start=0;start<group.fields.length;start+=12)
                    log('CONTENT_RECON_FIELDS '+JSON.stringify({class:group.name,fields:group.fields.slice(start,start+12)}));
            }
            log('CONTENT_RECON_OK classes='+report.classes.length);
        } catch(error) {clearInterval(timer);log('CONTENT_RECON_FAILED '+error.stack);}
        finally {if (thread!==null&&!thread.isNull()&&detach!==null) detach(thread);}
    },3000);
})();
