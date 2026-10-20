'use strict';
// Opt-in shared bootstrap. Include before both managed hosts in a combined build.
// A failed bootstrap is terminal: retrying mono_jit_init_version is unsafe.
globalThis.TMALMonoRuntime = (() => {
    let state='new', root=null, context=null, failure=null;
    function acquire(requestedRoot) {
        if(typeof requestedRoot!=='string'||!requestedRoot.startsWith('/')||requestedRoot.endsWith('/')||
           requestedRoot.split('/').some(part=>part==='.'||part==='..')||requestedRoot.includes('\0'))
            throw Error('Invalid managed assembly root');
        if(state==='failed')throw Error('Shared Mono bootstrap failed: '+failure);
        if(state==='starting')throw Error('Reentrant Mono bootstrap');
        if(state==='ready') {
            if(root!==requestedRoot)throw Error('Shared Mono assembly root differs');
            return context;
        }
        root=requestedRoot;state='starting';
        try {
            const lib=Process.getModuleByName('libmonosgen-2.0.so');
            const str=s=>Memory.allocUtf8String(s);
            const api=(name,result,args)=>new NativeFunction(lib.getExportByName(name),result,args,{exceptions:'propagate'});
            // Refuse to adopt a domain whose assembly path/suspension mode we did not set.
            const existing=api('mono_get_root_domain','pointer',[])();
            if(!existing.isNull())throw Error('Mono was initialized outside the shared bootstrap');
            const setenv=new NativeFunction(Process.getModuleByName('libc.so').getExportByName('setenv'),'int',['pointer','pointer','int']);
            if(setenv(str('MONO_THREADS_SUSPEND'),str('coop'),1)!==0)throw Error('Cannot select Mono cooperative suspension');
            api('mono_set_assemblies_path','void',['pointer'])(str(root));
            api('mono_set_signal_chaining','void',['int'])(1);
            api('mono_set_crash_chaining','void',['int'])(1);
            const argv=Memory.alloc(Process.pointerSize);argv.writePointer(str('--interp'));
            api('mono_jit_parse_options','void',['int','pointer'])(1,argv);
            const domain=api('mono_jit_init_version','pointer',['pointer','pointer'])(str('TerrariaMobileCombined'),str('v4.0.30319'));
            if(domain.isNull())throw Error('Shared Mono domain absent');
            const assembly=api('mono_domain_assembly_open','pointer',['pointer','pointer'])(domain,str(root+'/TerrariaMobile.ManagedDemo.dll'));
            if(assembly.isNull())throw Error('Shared managed host assembly absent');
            const image=api('mono_assembly_get_image','pointer',['pointer'])(assembly);
            if(image.isNull())throw Error('Shared managed host image absent');
            context=Object.freeze({domain,image,root});state='ready';return context;
        } catch(error) {
            failure=String(error.message||error);state='failed';throw error;
        }
    }
    return Object.freeze({acquire});
})();
