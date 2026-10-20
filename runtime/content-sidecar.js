'use strict';
// A single laboratory inventory item. This is our format, not PC .tplr.
globalThis.TMALSidecar = (() => {
    const KEY='PcModItemDemo/TestBlade',FORMAT='tmal-lab-item-v1';
    const PLAYER='/storage/emulated/0/Android/data/com.and.games505.TerrariaPaid/Players/TMAL_Test.plr';
    const ROOT='/data/user/0/com.and.games505.TerrariaPaid/files/tmloader';
    const digest=s=>typeof s==='string'&&/^[0-9a-f]{64}$/.test(s);
    function validate(row) {
        if(!row||row.format!==FORMAT||row.profile!=='TMAL_Test'||!digest(row.playerSha256)||
           !Number.isInteger(row.generation)||row.generation<1||row.generation>2147483646||
           !Array.isArray(row.items)||row.items.length!==1)throw Error('Unsupported laboratory sidecar');
        const item=row.items[0],p=item.placeholder;
        if(typeof item.key!=='string'||!/^[A-Za-z0-9_]{1,64}\/[A-Za-z0-9_]{1,64}$/.test(item.key)||
           !Number.isInteger(item.slot)||item.slot<0||item.slot>=58||!p||p.type!==3507||p.damage!==5||
           p.stack!==1||p.prefix!==0||typeof p.favorite!=='boolean'||!item.data||
           typeof item.data!=='object'||Array.isArray(item.data))throw Error('Unsupported laboratory item');
        if(JSON.stringify(row).length>4096)throw Error('Sidecar exceeds laboratory limit');
        return row;
    }
    const samePlaceholder=(a,b)=>!!a&&!!b&&['type','damage','stack','prefix','favorite'].every(k=>a[k]===b[k]);
    function bind(row,fileHash,placeholder) {
        validate(row);
        if(row.playerSha256!==fileHash)throw Error('Player hash mismatch; sidecar retained');
        if(!samePlaceholder(row.items[0].placeholder,placeholder))throw Error('Placeholder mismatch; sidecar retained');
        return row.items[0];
    }
    const known=item=>item.key===KEY&&item.data.version===1&&Object.keys(item.data).length===1;
    function next(previous,oldHash,newHash,item) {
        if(!digest(newHash))throw Error('Invalid player digest');
        if(previous) {validate(previous);if(previous.playerSha256!==oldHash)throw Error('Stale sidecar; no rebase');}
        const row={format:FORMAT,profile:'TMAL_Test',generation:previous?previous.generation+1:1,
                   playerSha256:newHash,items:[item]};
        return validate(row);
    }
    function store() {
        const libc=Process.getModuleByName('libc.so');
        const fn=(name,result,args)=>new NativeFunction(libc.getExportByName(name),result,args);
        const access=fn('access','int',['pointer','int']),open=fn('open','int',['pointer','int','int']);
        const write=fn('write','long',['int','pointer','ulong']),close=fn('close','int',['int']);
        const sync=fn('fsync','int',['int']),rename=fn('rename','int',['pointer','pointer']);
        const c=s=>Memory.allocUtf8String(s),path=ROOT+'/TMAL_Test.moditems.json';
        function read(file,limit,bytes=false) {
            const f=new File(file,'rb');
            try {
                f.seek(0,File.SEEK_END);const length=f.tell();
                if(length<1||length>limit)throw Error('Bounded file read rejected');
                f.seek(0,File.SEEK_SET);return bytes?f.readBytes(length):f.readText(length);
            } finally {f.close();}
        }
        function syncWrite(file,text) {
            // Linux/Bionic: O_CLOEXEC | O_NOFOLLOW | O_WRONLY | O_CREAT | O_TRUNC.
            const fd=open(c(file),524288|131072|1|64|512,384);
            if(fd<0)throw Error('Cannot open private sidecar temporary');
            try {
                const data=c(text),length=unescape(encodeURIComponent(text)).length;let done=0;
                while(done<length) {const n=Number(write(fd,data.add(done),length-done));if(n<=0)throw Error('Sidecar write failed');done+=n;}
                if(sync(fd)!==0)throw Error('Sidecar fsync failed');
            } finally {close(fd);}
        }
        function replace(temp,target) {if(rename(c(temp),c(target))!==0)throw Error('Sidecar rename failed');}
        return {
            hash:()=>Checksum.compute('sha256',read(PLAYER,2097152,true)),
            read:()=>access(c(path),0)!==0?null:validate(JSON.parse(read(path,4096))),
            commit(row) {
                const text=JSON.stringify(validate(row))+'\n';
                syncWrite(path+'.tmp',text);
                if(access(c(path),0)===0) {syncWrite(path+'.bak.tmp',read(path,4096));replace(path+'.bak.tmp',path+'.bak');}
                replace(path+'.tmp',path);
                const dir=open(c(ROOT),524288|65536,0);
                if(dir<0)throw Error('Cannot open sidecar directory');
                try {if(sync(dir)!==0)throw Error('Sidecar directory fsync failed');}finally{close(dir);}
                const actual=JSON.parse(read(path,4096));validate(actual);
                if(JSON.stringify(actual)!==JSON.stringify(row))throw Error('Sidecar readback differs');
            }
        };
    }
    return {KEY,PLAYER,validate,bind,known,next,samePlaceholder,store};
})();
