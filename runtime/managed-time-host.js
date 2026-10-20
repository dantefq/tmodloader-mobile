'use strict';
// Separate Mono host for the unchanged, hash-pinned local ChangeSleepTime DLL.
globalThis.TMALTime = (() => {
    let domain, native, evaluateMethod, selfMethod, stressMethod, handlersMethod, lifecycleMethod, contentMethod;
    let evaluateCall, intCall, foreignCall;
    const CODE = `
extern void *mono_thread_current(void);
extern void *mono_thread_attach(void *domain);
extern void mono_thread_detach(void *thread);
extern void *mono_threads_enter_gc_unsafe_region(void **stackpointer);
extern void mono_threads_exit_gc_unsafe_region(void *cookie, void **stackpointer);
extern void *mono_threads_enter_gc_safe_region(void **stackpointer);
extern void mono_threads_exit_gc_safe_region(void *cookie, void **stackpointer);
extern void *mono_runtime_invoke(void *method, void *object, void **params, void **exception);
extern unsigned mono_gchandle_new(void *object, int pinned);
extern void *mono_gchandle_get_target(unsigned handle);
extern void mono_gchandle_free(unsigned handle);
extern void *mono_object_unbox(void *object);
typedef unsigned long thread_id;
extern int pthread_create(thread_id *thread, void *attr, void *(*entry)(void *), void *arg);
extern int pthread_join(thread_id thread, void **result);
int integer(void *domain, void *method, int *error) {
    int created=mono_thread_current()==0;
    void *thread=mono_thread_attach(domain), *stackdummy=0;
    void *cookie=mono_threads_enter_gc_unsafe_region(&stackdummy), *exception=0;
    void *result=mono_runtime_invoke(method,0,0,&exception);
    int value=0; *error=0;
    if (exception||!result) *error=1;
    else {
        unsigned h=mono_gchandle_new(result,1);
        value=*(int*)mono_object_unbox(mono_gchandle_get_target(h));
        mono_gchandle_free(h);
    }
    mono_threads_exit_gc_unsafe_region(cookie,&stackdummy);
    if (created) mono_thread_detach(thread);
    return value;
}
void rates(void *domain, void *method, int flags, int active, int sleeping, int target, int multiplier, double *out, int *error) {
    int created=mono_thread_current()==0;
    void *thread=mono_thread_attach(domain), *stackdummy=0;
    void *cookie=mono_threads_enter_gc_unsafe_region(&stackdummy), *exception=0;
    void *params[5]={&flags,&active,&sleeping,&target,&multiplier};
    void *result=mono_runtime_invoke(method,0,params,&exception); *error=0;
    if (exception||!result) *error=1;
    else {
        unsigned h=mono_gchandle_new(result,1);
        double *value=(double*)mono_object_unbox(mono_gchandle_get_target(h));
        out[0]=value[0];out[1]=value[1];out[2]=value[2];
        mono_gchandle_free(h);
    }
    mono_threads_exit_gc_unsafe_region(cookie,&stackdummy);
    if (created) mono_thread_detach(thread);
}
struct worker_args {void *domain;void *method;int value;int error;};
void *worker(void *p) {struct worker_args *a=(struct worker_args*)p;a->value=integer(a->domain,a->method,&a->error);return 0;}
int foreign(void *domain, void *method, int *error) {
    struct worker_args a={domain,method,0,0};thread_id thread;
    // A registered caller waiting in pthread_join must allow the worker's GC
    // to suspend it. No managed references are read during this safe region.
    int registered=mono_thread_current()!=0;void *stackdummy=0,*unsafeDummy=0,*cookie=0,*unsafeCookie=0;
    // Exported Mono calls can leave the caller already GC-safe. Nest a balanced
    // unsafe scope first, rather than attempting DO_BLOCKING from BLOCKING.
    if (registered) {
        unsafeCookie=mono_threads_enter_gc_unsafe_region(&unsafeDummy);
        cookie=mono_threads_enter_gc_safe_region(&stackdummy);
    }
    int result=pthread_create(&thread,0,worker,&a);
    if (result==0) result=pthread_join(thread,0);
    if (registered) {
        mono_threads_exit_gc_safe_region(cookie,&stackdummy);
        mono_threads_exit_gc_unsafe_region(unsafeCookie,&unsafeDummy);
    }
    if (result!=0) {*error=3;return 0;}
    *error=a.error;return a.value;
}
`;
    function initialize(root) {
        if (domain) throw Error('Time host initialized twice');
        const lib=Process.getModuleByName('libmonosgen-2.0.so');
        const str=s=>Memory.allocUtf8String(s);
        const api=(n,r,a)=>new NativeFunction(lib.getExportByName(n),r,a,{exceptions:'propagate'});
        let image;
        if(globalThis.TMALMonoRuntime) {
            const shared=TMALMonoRuntime.acquire(root);domain=shared.domain;image=shared.image;
        } else {
            // Mono shares this process with Unity's IL2CPP collector. Make native
            // callers explicitly GC-safe in our bridge rather than allowing Mono
            // hybrid suspension to signal unrelated embedder threads.
            const setenv=new NativeFunction(Process.getModuleByName('libc.so').getExportByName('setenv'),'int',['pointer','pointer','int']);
            if(setenv(str('MONO_THREADS_SUSPEND'),str('coop'),1)!==0)throw Error('Cannot select Mono cooperative suspension');
            api('mono_set_assemblies_path','void',['pointer'])(str(root));
            api('mono_set_signal_chaining','void',['int'])(1);
            api('mono_set_crash_chaining','void',['int'])(1);
            const argv=Memory.alloc(Process.pointerSize);argv.writePointer(str('--interp'));
            api('mono_jit_parse_options','void',['int','pointer'])(1,argv);
            domain=api('mono_jit_init_version','pointer',['pointer','pointer'])(str('TerrariaMobileTime'),str('v4.0.30319'));
            if(domain.isNull())throw Error('Mono domain absent');
            const assembly=api('mono_domain_assembly_open','pointer',['pointer','pointer'])(domain,str(root+'/TerrariaMobile.ManagedDemo.dll'));
            if(assembly.isNull())throw Error('Own time host assembly absent');
            image=api('mono_assembly_get_image','pointer',['pointer'])(assembly);
        }
        const klass=api('mono_class_from_name','pointer',['pointer','pointer','pointer'])(image,str('TerrariaMobile.Managed'),str('ManagedTimeHost'));
        if(klass.isNull())throw Error('Own time host class absent');
        const method=api('mono_class_get_method_from_name','pointer',['pointer','pointer','int']);
        evaluateMethod=method(klass,str('Evaluate'),5);selfMethod=method(klass,str('SelfTest'),0);
        stressMethod=method(klass,str('StressGc'),0);handlersMethod=method(klass,str('GetHandlerCount'),0);
        lifecycleMethod=method(klass,str('GetLifecycleChecks'),0);contentMethod=method(klass,str('GetContentChecks'),0);
        for(const m of [evaluateMethod,selfMethod,stressMethod,handlersMethod])if(m.isNull())throw Error('Time host method absent');
        const imports={};
        for(const n of ['mono_thread_current','mono_thread_attach','mono_thread_detach','mono_threads_enter_gc_unsafe_region','mono_threads_exit_gc_unsafe_region','mono_threads_enter_gc_safe_region','mono_threads_exit_gc_safe_region','mono_runtime_invoke','mono_gchandle_new','mono_gchandle_get_target','mono_gchandle_free','mono_object_unbox'])imports[n]=lib.getExportByName(n);
        for(const n of ['pthread_create','pthread_join'])imports[n]=Process.getModuleByName('libc.so').getExportByName(n);
        native=new CModule(CODE,imports);
        evaluateCall=new NativeFunction(native.rates,'void',['pointer','pointer','int','int','int','int','int','pointer','pointer']);
        intCall=new NativeFunction(native.integer,'int',['pointer','pointer','pointer']);
        foreignCall=new NativeFunction(native.foreign,'int',['pointer','pointer','pointer']);
    }
    function integer(method,foreign=false) {
        if(method.isNull())throw Error('Requested time host contract is unavailable');
        const error=Memory.alloc(4),value=(foreign?foreignCall:intCall)(domain,method,error);
        if(error.readS32()!==0)throw Error('Original mod/host failed: '+error.readS32());return value;
    }
    return {
        initialize,
        evaluate(flags,active,sleeping,target,multiplier) {
            const out=Memory.alloc(24),error=Memory.alloc(4);
            evaluateCall(domain,evaluateMethod,flags,active,sleeping,target,multiplier,out,error);
            if(error.readS32()!==0)throw Error('Original time hook failed');
            return [out.readDouble(),out.add(8).readDouble(),out.add(16).readDouble()];
        },
        selfTest:()=>integer(selfMethod),handlers:()=>integer(handlersMethod),stress:()=>integer(stressMethod,true),
        lifecycle:()=>integer(lifecycleMethod),content:()=>integer(contentMethod)
    };
})();
