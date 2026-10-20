'use strict';
// Own isolated Mono probe endpoint. Uses the shared bootstrap and balanced GC
// regions; no IL2CPP, game methods, native texture allocation or content writes.
globalThis.TMALMonoTexture = (() => {
    let domain = null, module = null, method = null, invoke = null, monoFree = null;
    const CODE = `
extern void *mono_thread_current(void);
extern void *mono_thread_attach(void *domain);
extern void mono_thread_detach(void *thread);
extern void *mono_threads_enter_gc_unsafe_region(void **stackpointer);
extern void mono_threads_exit_gc_unsafe_region(void *cookie, void **stackpointer);
extern void *mono_runtime_invoke(void *method, void *object, void **params, void **exception);
extern void *mono_string_new(void *domain, const char *text);
extern unsigned mono_gchandle_new(void *object, int pinned);
extern void *mono_gchandle_get_target(unsigned handle);
extern void mono_gchandle_free(unsigned handle);
extern char *mono_string_to_utf8(void *object);
char *texture_request(void *domain, void *method, const char *text, int *error) {
    int created = mono_thread_current() == 0;
    void *thread = mono_thread_attach(domain), *stackdummy = 0;
    void *cookie = mono_threads_enter_gc_unsafe_region(&stackdummy);
    void *input = mono_string_new(domain, text), *exception = 0;
    char *value = 0; *error = 0;
    if (!input) *error = 1;
    else {
        unsigned input_handle = mono_gchandle_new(input, 1);
        if (!input_handle) *error = 2;
        else {
            void *params[1] = { mono_gchandle_get_target(input_handle) };
            void *result = mono_runtime_invoke(method, 0, params, &exception);
            if (exception || !result) *error = 3;
            else {
                unsigned output_handle = mono_gchandle_new(result, 1);
                if (!output_handle) *error = 4;
                else {
                    value = mono_string_to_utf8(mono_gchandle_get_target(output_handle));
                    mono_gchandle_free(output_handle);
                    if (!value) *error = 5;
                }
            }
            mono_gchandle_free(input_handle);
        }
    }
    mono_threads_exit_gc_unsafe_region(cookie, &stackdummy);
    if (created) mono_thread_detach(thread);
    return value;
}
`;
    function initialize(root) {
        if (domain !== null) throw Error('Texture probe host already initialized');
        const shared = globalThis.TMALMonoRuntime.acquire(root);
        const lib = Process.getModuleByName('libmonosgen-2.0.so');
        const str = value => Memory.allocUtf8String(value);
        const api = (name, result, args) => new NativeFunction(lib.getExportByName(name), result, args);
        const klass = api('mono_class_from_name', 'pointer', ['pointer', 'pointer', 'pointer'])(shared.image,
            str('TerrariaMobile.TextureLab'), str('AndroidTextureProbeHost'));
        if (klass.isNull()) throw Error('Own texture probe host absent');
        method = api('mono_class_get_method_from_name', 'pointer', ['pointer', 'pointer', 'int'])(klass, str('Request'), 1);
        if (method.isNull()) throw Error('Own texture probe endpoint absent');
        const imports = {};
        for (const name of ['mono_thread_current', 'mono_thread_attach', 'mono_thread_detach',
            'mono_threads_enter_gc_unsafe_region', 'mono_threads_exit_gc_unsafe_region', 'mono_runtime_invoke',
            'mono_string_new', 'mono_gchandle_new', 'mono_gchandle_get_target', 'mono_gchandle_free', 'mono_string_to_utf8'])
            imports[name] = lib.getExportByName(name);
        module = new CModule(CODE, imports);
        invoke = new NativeFunction(module.texture_request, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);
        monoFree = api('mono_free', 'void', ['pointer']); domain = shared.domain;
    }
    function request(value) {
        if (domain === null) throw Error('Texture probe host not initialized');
        const text = JSON.stringify(value);
        if (text.length > 1024) throw Error('Texture probe request exceeds budget');
        const error = Memory.alloc(4), output = invoke(domain, method, Memory.allocUtf8String(text), error);
        if (error.readS32() !== 0 || output.isNull()) throw Error('Texture managed endpoint failed: ' + error.readS32());
        try {
            const result = output.readUtf8String();
            if (result.length > 94208) throw Error('Texture managed response exceeds budget');
            return result;
        } finally { monoFree(output); }
    }
    return Object.freeze({ initialize, request });
})();
