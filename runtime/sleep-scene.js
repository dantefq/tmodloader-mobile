'use strict';
// Bounded, opt-in device QA scene. Vanilla placement and sleeping APIs only.
globalThis.TMALSleepScene = function({api,klass,method,main,playerClass,local,allowed,log,root}) {
    const str=s=>Memory.allocUtf8String(s),nil=ptr(0);
    const invoke=api('runtime_invoke','pointer',['pointer','pointer','pointer','pointer']);
    const unbox=api('object_unbox','pointer',['pointer']);
    const gcNew=api('gchandle_new','uint',['pointer','uchar']),gcFree=api('gchandle_free','void',['uint']);
    const fieldGet=api('class_get_field_from_name','pointer',['pointer','pointer']);
    const fieldType=api('field_get_type','pointer',['pointer']);
    const kind=api('type_get_type','int',['pointer']);
    const fromType=api('class_from_type','pointer',['pointer']);
    const offset=api('field_get_offset','ulong',['pointer']);
    const get=api('field_static_get_value','void',['pointer','pointer']);
    const int=n=>{const p=Memory.alloc(4);p.writeS32(n);return p;};
    const bool=b=>{const p=Memory.alloc(1);p.writeU8(b?1:0);return p;};
    function call(m,obj,args=[]) {
        const params=Memory.alloc(Math.max(8,args.length*8)),ex=Memory.alloc(8);ex.writePointer(nil);
        args.forEach((p,i)=>params.add(i*8).writePointer(p));
        const result=invoke(m,obj,params,ex);
        if(!ex.readPointer().isNull())throw Error('Scene vanilla API raised an exception');
        return result;
    }
    const tileField=fieldGet(main,str('tile'));
    if(tileField.isNull())throw Error('Scene tile map missing');
    const tileKind=kind(fieldType(tileField)),mapClass=fromType(fieldType(tileField));
    if(tileKind!==17&&tileKind!==18)throw Error('Unexpected tile map type');
    let mapSize=8;
    if(tileKind===17){const align=Memory.alloc(4);mapSize=api('class_value_size','int',['pointer','pointer'])(mapClass,align);}
    if(mapSize<1||mapSize>256)throw Error('Tile map value size differs');
    const mapValue=Memory.alloc(mapSize),mapItem=method(mapClass,'get_Item',2,false);
    const tileClass=klass('Terraria','Tile'),active=method(tileClass,'active',0,false),tileType=method(tileClass,'get_type',0,false),wall=method(tileClass,'get_wall',0,false);
    function tile(x,y) {
        get(tileField,mapValue);
        const obj=tileKind===17?mapValue:mapValue.readPointer();
        if(obj.isNull())throw Error('Tile map unavailable');
        const result=call(mapItem,obj,[int(x),int(y)]);
        if(result.isNull())throw Error('Tile map returned null');
        const handle=gcNew(result,0);
        try {
            const value=unbox(result);
            return {active:unbox(call(active,value)).readU8()!==0,type:unbox(call(tileType,value)).readU16(),wall:unbox(call(wall,value)).readU16()};
        }finally{gcFree(handle);}
    }
    const worldgen=klass('Terraria','WorldGen');
    const place=method(worldgen,'PlaceTile',7),placeWall=method(worldgen,'PlaceWall',4);
    const teleport=method(playerClass,'Teleport',3,false);
    const sleeping=fieldGet(playerClass,str('sleeping'));
    if(sleeping.isNull()||kind(fieldType(sleeping))!==17)throw Error('Sleeping helper type differs');
    const sleepOffset=Number(offset(sleeping));
    if(sleepOffset<16||sleepOffset>16384)throw Error('Sleeping helper offset differs');
    const start=method(fromType(fieldType(sleeping)),'StartSleeping',3,false);
    const spawnX=method(main,'get_spawnTileX',0),spawnY=method(main,'get_spawnTileY',0);
    function staticInt(name){const f=fieldGet(main,str(name)),p=Memory.alloc(4);if(f.isNull()||kind(fieldType(f))!==8)throw Error('Scene bounds type differs');get(f,p);return p.readS32();}
    function location(){
        const x=unbox(call(spawnX,nil)).readS32()+70,y=unbox(call(spawnY,nil)).readS32()-30;
        if(x<40||y<40||x+16>=staticInt('maxTilesX')-40||y+10>=staticInt('maxTilesY')-40)throw Error('Scene outside safe bounds');
        return {x,y,bedX:x+5,bedY:y+8};
    }
    let pending=null,last=null;
    setInterval(()=>{
        let raw;
        try {raw=File.readAllText(root+'/sleep-command.json');}catch(error){return;}
        try {
            if(raw.length>512)throw Error('Scene command too large');
            const c=JSON.parse(raw);
            if(typeof c.nonce!=='string'||! /^[0-9a-f-]{36}$/.test(c.nonce)||!['prepare-room','use-bed'].includes(c.action))throw Error('Invalid scene command');
            if(c.nonce!==last){last=c.nonce;pending=c;}
        }catch(error){if(!String(error).includes('No such file'))log('SLEEP_SCENE_COMMAND_REJECTED '+error.message);}
    },1000);
    return function tick(){
        if(pending===null)return;
        const command=pending;pending=null;
        try {
            if(!allowed())throw Error('Scene requires offline classic TMAL_Lab / TMAL_Sleep');
            const {x,y,bedX,bedY}=location(),player=call(local,nil);
            const deadField=fieldGet(playerClass,str('dead'));
            if(deadField.isNull()||kind(fieldType(deadField))!==2)throw Error('Player dead flag differs');
            if(player.add(Number(offset(deadField))).readU8()!==0)throw Error('Wait for the test player to respawn before using the scene');
            if(command.action==='prepare-room'){
                // Read every target before any writes. Never clear existing blocks/walls.
                for(let i=x;i<x+16;i++)for(let j=y;j<y+10;j++){
                    const t=tile(i,j);if(t.active||t.wall!==0)throw Error('Room space occupied; no placement performed');
                }
                function put(i,j,type){
                    const ok=unbox(call(place,nil,[int(i),int(j),int(type),bool(true),bool(true),int(-1),int(0)])).readU8();
                    const t=tile(i,j);if(!ok||!t.active||t.type!==type)throw Error('Vanilla placement/readback failed at '+i+','+j);
                }
                for(let i=x;i<x+16;i++){put(i,y+9,30);put(i,y,30);}
                for(let j=y+1;j<y+9;j++){put(x,j,30);put(x+15,j,30);}
                for(let i=x+1;i<x+15;i++)for(let j=y+1;j<y+9;j++)call(placeWall,nil,[int(i),int(j),int(4),bool(true)]);
                put(bedX,bedY,79);
                log('SLEEP_SCENE_BUILT '+JSON.stringify({x,y,bedX,bedY,width:16,height:10,vanillaPlacement:true}));
            }
            const bed=tile(bedX,bedY);
            if(!bed.active||bed.type!==79)throw Error('Lab bed missing');
            const pos=Memory.alloc(8);pos.writeFloat((bedX+1)*16);pos.add(4).writeFloat((bedY-2)*16);
            call(teleport,player,[pos,int(0),int(0)]);
            if(command.action==='use-bed')call(start,player.add(sleepOffset),[player,int(bedX),int(bedY-1)]);
            log('SLEEP_SCENE_ACTION '+JSON.stringify({action:command.action,nonce:command.nonce,bedX,bedY,vanillaSleepAPI:command.action==='use-bed'}));
        }catch(error){log('SLEEP_SCENE_REJECTED '+error.stack);}
    };
};
