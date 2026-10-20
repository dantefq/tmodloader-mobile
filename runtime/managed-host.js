'use strict';
// Own native scopes keep Mono GC state and real stack pointers balanced.
globalThis.TMALManaged = (() => {
    let domain=null, api=null, native=null, intCall=null, stringCall=null, foreignCall=null;
    let damageMethod=null, nameMethod=null, stressMethod=null, handlerMethod=null, foundationMethod=null;
    const cstr=value=>Memory.allocUtf8String(value);
    const CODE=`
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
extern char *mono_string_to_utf8(void *object);
typedef unsigned long thread_id;
extern int pthread_create(thread_id *thread, void *attr, void *(*entry)(void *), void *arg);
extern int pthread_join(thread_id thread, void **result);
int managed_int(void *domain, void *method, int argc, int first, int second, int *error) {
    int created=mono_thread_current()==0;
    void *thread=mono_thread_attach(domain);
    void *stackdummy=0;
    void *cookie=mono_threads_enter_gc_unsafe_region(&stackdummy);
    void *params[2]={&first,&second};
    void *exception=0;
    void *result=mono_runtime_invoke(method,0,argc?params:0,&exception);
    int value=0;
    *error=0;
    if (exception||!result) *error=1;
    else {
        unsigned handle=mono_gchandle_new(result,1);
        value=*(int*)mono_object_unbox(mono_gchandle_get_target(handle));
        mono_gchandle_free(handle);
    }
    mono_threads_exit_gc_unsafe_region(cookie,&stackdummy);
    if (created) mono_thread_detach(thread);
    return value;
}
char *managed_string(void *domain, void *method, int first, int *error) {
    int created=mono_thread_current()==0;
    void *thread=mono_thread_attach(domain);
    void *stackdummy=0;
    void *cookie=mono_threads_enter_gc_unsafe_region(&stackdummy);
    void *params[1]={&first};
    void *exception=0;
    void *result=mono_runtime_invoke(method,0,params,&exception);
    char *value=0;
    *error=0;
    if (exception||!result) *error=1;
    else {
        unsigned handle=mono_gchandle_new(result,1);
        value=mono_string_to_utf8(mono_gchandle_get_target(handle));
        mono_gchandle_free(handle);
        if (!value) *error=2;
    }
    mono_threads_exit_gc_unsafe_region(cookie,&stackdummy);
    if (created) mono_thread_detach(thread);
    return value;
}
struct worker_args {void *domain;void *method;int value;int error;};
void *stress_worker(void *data) {
    struct worker_args *a=(struct worker_args*)data;
    a->value=managed_int(a->domain,a->method,0,0,0,&a->error);
    return 0;
}
int managed_foreign_stress(void *domain,void *method,int *error) {
    struct worker_args args={domain,method,0,0};
    thread_id thread;
    // Permit the worker's collection to suspend a registered waiting caller.
    int registered=mono_thread_current()!=0;
    void *safeDummy=0,*unsafeDummy=0,*safeCookie=0,*unsafeCookie=0;
    if (registered) {
        unsafeCookie=mono_threads_enter_gc_unsafe_region(&unsafeDummy);
        safeCookie=mono_threads_enter_gc_safe_region(&safeDummy);
    }
    int result=pthread_create(&thread,0,stress_worker,&args);
    if (result==0) result=pthread_join(thread,0);
    if (registered) {
        mono_threads_exit_gc_safe_region(safeCookie,&safeDummy);
        mono_threads_exit_gc_unsafe_region(unsafeCookie,&unsafeDummy);
    }
    if (result!=0) {*error=3;return 0;}
    *error=args.error;
    return args.value;
}
`;
    function initialize(root) {
        if (domain!==null) throw Error('Mono initialized twice');
        const lib=Process.getModuleByName('libmonosgen-2.0.so');
        api=(name,result,args)=>new NativeFunction(lib.getExportByName(name),result,args,{exceptions:'propagate'});
        let image;
        if(globalThis.TMALMonoRuntime) {
            const shared=TMALMonoRuntime.acquire(root);domain=shared.domain;image=shared.image;
        } else {
            api('mono_set_assemblies_path','void',['pointer'])(cstr(root));
            api('mono_set_signal_chaining','void',['int'])(1);
            api('mono_set_crash_chaining','void',['int'])(1);
            const argv=Memory.alloc(Process.pointerSize);argv.writePointer(cstr('--interp'));
            api('mono_jit_parse_options','void',['int','pointer'])(1,argv);
            domain=api('mono_jit_init_version','pointer',['pointer','pointer'])(cstr('TerrariaMobileManaged'),cstr('v4.0.30319'));
            if (domain.isNull()) throw Error('Mono domain is null');
            const assembly=api('mono_domain_assembly_open','pointer',['pointer','pointer'])(domain,cstr(root+'/TerrariaMobile.ManagedDemo.dll'));
            if (assembly.isNull()) throw Error('Own managed assembly missing');
            image=api('mono_assembly_get_image','pointer',['pointer'])(assembly);
        }
        const klass=api('mono_class_from_name','pointer',['pointer','pointer','pointer'])(image,cstr('TerrariaMobile.Managed'),cstr('ManagedSwordDemo'));
        if (klass.isNull()) throw Error('Own managed class missing');
        const method=api('mono_class_get_method_from_name','pointer',['pointer','pointer','int']);
        damageMethod=method(klass,cstr('GetDamage'),2);nameMethod=method(klass,cstr('GetName'),1);stressMethod=method(klass,cstr('StressGc'),0);
        handlerMethod=method(klass,cstr('GetHandlerCount'),0);
        foundationMethod=method(klass,cstr('GetFoundationChecks'),0);
        if (damageMethod.isNull()||nameMethod.isNull()||stressMethod.isNull()) throw Error('Own C# methods missing');
        const imports={};
        for (const name of ['mono_threads_enter_gc_safe_region','mono_threads_exit_gc_safe_region']) imports[name]=lib.getExportByName(name);
        for (const name of ['mono_thread_current','mono_thread_attach','mono_thread_detach','mono_threads_enter_gc_unsafe_region','mono_threads_exit_gc_unsafe_region','mono_runtime_invoke','mono_gchandle_new','mono_gchandle_get_target','mono_gchandle_free','mono_object_unbox','mono_string_to_utf8']) imports[name]=lib.getExportByName(name);
        for (const name of ['pthread_create','pthread_join']) imports[name]=Process.getModuleByName('libc.so').getExportByName(name);
        native=new CModule(CODE,imports);
        intCall=new NativeFunction(native.managed_int,'int',['pointer','pointer','int','int','int','pointer'],{exceptions:'propagate'});
        stringCall=new NativeFunction(native.managed_string,'pointer',['pointer','pointer','int','pointer'],{exceptions:'propagate'});
        foreignCall=new NativeFunction(native.managed_foreign_stress,'int',['pointer','pointer','pointer'],{exceptions:'propagate'});
    }
    function check(error) {if (error.readS32()!==0) throw Error('Own C# handler failed: '+error.readS32());}
    return {
        initialize,
        contract(root) {
            let raw;
            try {raw=File.readAllText(root+'/demo-contract.json');}
            catch (_) {return {mode:'own-csharp',name:'CSharp Test Sword',checks:[[3507,5,18],[1,5,5],[3507,7,20]],handler_count:0};}
            if (raw.length>4096) throw Error('Own contract too large');
            let value=JSON.parse(raw);
            if(globalThis.TMALMonoRuntime) {
                if(value.mode!=='time-rate'||value.api_revision!=='managed-foundation-v2'||!value.item_contract)
                    throw Error('Combined item/time contract missing');
                value={...value.item_contract,api_revision:'managed-foundation-v1',foundation_check_count:8};
            }
            const global=value.mode==='global-item' && value.name==='PC API Test Sword' && JSON.stringify(value.checks)==='[[3507,5,24],[1,5,5],[3507,7,26]]';
            const content=value.mode==='mod-item' && value.name==='PC ModItem Test Blade' && value.content_id===6196 && value.template_id===3507 && value.name_test_id===6196 && JSON.stringify(value.checks)==='[[6196,5,37],[3507,5,5],[6196,7,37]]';
            if ((!global&&!content) || value.handler_count!==1) throw Error('Unexpected own API contract');
            return value;
        },
        handlers() {if (handlerMethod.isNull()) return 0;const error=Memory.alloc(4);const value=intCall(domain,handlerMethod,0,0,0,error);check(error);return value;},
        foundationChecks() {
            if(foundationMethod.isNull())throw Error('Foundation probe method missing');
            const error=Memory.alloc(4),value=intCall(domain,foundationMethod,0,0,0,error);check(error);return value;
        },
        damage(type,vanilla) {const error=Memory.alloc(4);const value=intCall(domain,damageMethod,2,type,vanilla,error);check(error);return value;},
        name(type) {
            const error=Memory.alloc(4);const value=stringCall(domain,nameMethod,type,error);check(error);
            try {return value.readUtf8String();}finally {api('mono_free','void',['pointer'])(value);}
        },
        stress() {const error=Memory.alloc(4);const value=foreignCall(domain,stressMethod,error);check(error);return value;}
    };
})();
