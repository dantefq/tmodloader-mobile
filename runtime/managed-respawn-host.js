'use strict';
// Isolated ShorterRespawn API. Only JSON snapshots cross the native/Mono boundary.
globalThis.TMALRespawn = (() => {
    let shared, code, callInteger, callSnapshot, callForeign, initializeMethod, evaluateMethod, checksMethod, stressMethod;
    const CODE=`
extern void *mono_thread_current(void);
extern void *mono_thread_attach(void *domain);
extern void mono_thread_detach(void *thread);
extern void *mono_threads_enter_gc_unsafe_region(void **stackpointer);
extern void mono_threads_exit_gc_unsafe_region(void *cookie, void **stackpointer);
extern void *mono_threads_enter_gc_safe_region(void **stackpointer);
extern void mono_threads_exit_gc_safe_region(void *cookie, void **stackpointer);
extern void *mono_runtime_invoke(void *method, void *object, void **params, void **exception);
extern void *mono_string_new(void *domain, const char *text);
extern unsigned mono_gchandle_new(void *object, int pinned);
extern void *mono_gchandle_get_target(unsigned handle);
extern void mono_gchandle_free(unsigned handle);
extern void *mono_object_unbox(void *object);
int execute(void *domain, void *method, const char *json, int *error) {
    int created=mono_thread_current()==0;void *thread=mono_thread_attach(domain),*dummy=0;
    void *cookie=mono_threads_enter_gc_unsafe_region(&dummy),*exception=0,*params[1];
    unsigned input=0,output=0;int value=0;*error=0;
    if(json) {
        void *text=mono_string_new(domain,json);
        if(!text){*error=2;goto finish;}
        input=mono_gchandle_new(text,1);params[0]=mono_gchandle_get_target(input);
    }
    void *result=mono_runtime_invoke(method,0,json?params:0,&exception);
    if(exception||!result){*error=1;goto finish;}
    output=mono_gchandle_new(result,1);
    value=*(int*)mono_object_unbox(mono_gchandle_get_target(output));
finish:
    if(output)mono_gchandle_free(output);if(input)mono_gchandle_free(input);
    mono_threads_exit_gc_unsafe_region(cookie,&dummy);
    if(created)mono_thread_detach(thread);return value;
}
int integer(void *domain,void *method,int *error){return execute(domain,method,0,error);}
typedef unsigned long thread_id;
extern int pthread_create(thread_id *,void *,void *(*)(void *),void *);
extern int pthread_join(thread_id,void **);
struct work {void *domain;void *method;int result;int error;};
void *worker(void *p){struct work *w=(struct work*)p;w->result=integer(w->domain,w->method,&w->error);return 0;}
int foreign(void *domain,void *method,int *error){
    struct work w={domain,method,0,0};thread_id t;
    int registered=mono_thread_current()!=0;void *dummy=0,*safeDummy=0,*u=0,*s=0;
    if(registered){u=mono_threads_enter_gc_unsafe_region(&dummy);s=mono_threads_enter_gc_safe_region(&safeDummy);}
    int status=pthread_create(&t,0,worker,&w);if(!status)status=pthread_join(t,0);
    if(registered){mono_threads_exit_gc_safe_region(s,&safeDummy);mono_threads_exit_gc_unsafe_region(u,&dummy);}
    *error=status?3:w.error;return w.result;
}`;
    function initialize(root) {
        if(shared)throw Error('Respawn host initialized twice');
        shared=TMALMonoRuntime.acquire(root);
        const lib=Process.getModuleByName('libmonosgen-2.0.so'),str=s=>Memory.allocUtf8String(s);
        const api=(name,result,args)=>new NativeFunction(lib.getExportByName(name),result,args);
        const klass=api('mono_class_from_name','pointer',['pointer','pointer','pointer']);
        const find=api('mono_class_get_method_from_name','pointer',['pointer','pointer','int']);
        const live=klass(shared.image,str('TerrariaMobile.Managed'),str('LiveRespawnHost'));
        const checks=klass(shared.image,str(''),str('OriginalRespawnChecks'));
        if(live.isNull()||checks.isNull())throw Error('Respawn host class absent');
        initializeMethod=find(live,str('Initialize'),0);evaluateMethod=find(live,str('Evaluate'),1);
        checksMethod=find(checks,str('RunAndroid'),0);stressMethod=find(checks,str('StressGc'),0);
        if([initializeMethod,evaluateMethod,checksMethod,stressMethod].some(m=>m.isNull()))throw Error('Respawn host methods absent');
        const imports={};
        for(const name of ['mono_thread_current','mono_thread_attach','mono_thread_detach',
            'mono_threads_enter_gc_unsafe_region','mono_threads_exit_gc_unsafe_region',
            'mono_threads_enter_gc_safe_region','mono_threads_exit_gc_safe_region',
            'mono_runtime_invoke','mono_string_new','mono_gchandle_new','mono_gchandle_get_target','mono_gchandle_free','mono_object_unbox'])
            imports[name]=lib.getExportByName(name);
        for(const name of ['pthread_create','pthread_join'])imports[name]=Process.getModuleByName('libc.so').getExportByName(name);
        code=new CModule(CODE,imports);
        callInteger=new NativeFunction(code.integer,'int',['pointer','pointer','pointer']);
        callSnapshot=new NativeFunction(code.execute,'int',['pointer','pointer','pointer','pointer']);
        callForeign=new NativeFunction(code.foreign,'int',['pointer','pointer','pointer']);
    }
    function integer(method,foreign=false){
        const error=Memory.alloc(4),result=(foreign?callForeign:callInteger)(shared.domain,method,error);
        if(error.readS32())throw Error('Respawn managed call failed: '+error.readS32());return result;
    }
    return {initialize, checks:()=>integer(checksMethod),stress:()=>integer(stressMethod,true),
        start:()=>integer(initializeMethod),
        evaluate(row){
            const json=JSON.stringify(row);if(json.length>65536)throw Error('Respawn snapshot too large');
            const error=Memory.alloc(4),result=callSnapshot(shared.domain,evaluateMethod,Memory.allocUtf8String(json),error);
            if(error.readS32())throw Error('Original respawn callback failed: '+error.readS32());return result;
        }};
})();
