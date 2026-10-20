'use strict';
// Metadata-only readiness probe. Never creates textures, invokes game/Unity
// methods, installs hooks, changes content tables or accesses saves.
rpc.exports.moduleinfo = function () {
    const lib = Process.getModuleByName('libil2cpp.so');
    return { architecture: Process.arch, pointer_size: Process.pointerSize, library_path: lib.path };
};
rpc.exports.inspect = function () {
    if (Process.arch !== 'arm64' || Process.pointerSize !== 8) throw Error('Native ARM64 required');
    const lib = Process.getModuleByName('libil2cpp.so');
    const api = (name, result, args) => new NativeFunction(lib.getExportByName('il2cpp_' + name), result, args);
    const nil = ptr(0), text = value => Memory.allocUtf8String(value);
    const domain = api('domain_get', 'pointer', [])();
    if (domain.isNull()) throw Error('IL2CPP domain is not ready');
    const current = api('thread_current', 'pointer', [])();
    const owned = current.isNull();
    const thread = owned ? api('thread_attach', 'pointer', ['pointer'])(domain) : current;
    if (thread.isNull()) throw Error('Metadata thread attach failed');
    try {
        const typeName = type => {
            const name = api('type_get_name', 'pointer', ['pointer'])(type);
            if (name.isNull()) throw Error('Missing metadata type name');
            try { return name.readUtf8String(); }
            finally { api('free', 'void', ['pointer'])(name); }
        };
        const count = Memory.alloc(8); count.writeU64(0);
        const assemblies = api('domain_get_assemblies', 'pointer', ['pointer', 'pointer'])(domain, count);
        const length = count.readU64().toNumber();
        if (length < 1 || length > 2048) throw Error('Unexpected image count');
        const images = new Map();
        for (let i = 0; i < length; i++) {
            const image = api('assembly_get_image', 'pointer', ['pointer'])(assemblies.add(i * 8).readPointer());
            const name = api('image_get_name', 'pointer', ['pointer'])(image).readUtf8String();
            if (images.has(name)) throw Error('Ambiguous assembly image');
            images.set(name, image);
        }
        const targets = [
            ['Assembly-CSharp.dll', 'Microsoft.Xna.Framework.Graphics', 'Texture2D', ['.ctor', 'SetData']],
            ['UnityEngine.CoreModule.dll', 'UnityEngine', 'Texture2D', ['.ctor', 'Apply', 'GetRawImageDataSize']],
            ['UnityEngine.ImageConversionModule.dll', 'UnityEngine', 'ImageConversion', ['LoadImage']],
            ['Assembly-CSharp.dll', '', 'DrPlatform', ['get_IsMainThread']]
        ];
        const classes = [];
        for (const [assembly, namespace, name, selected] of targets) {
            const image = images.get(assembly);
            if (image === undefined) { classes.push({ assembly, namespace, name, missing: true }); continue; }
            const klass = api('class_from_name', 'pointer', ['pointer', 'pointer', 'pointer'])(image, text(namespace), text(name));
            if (klass.isNull()) { classes.push({ assembly, namespace, name, missing: true }); continue; }
            const iterator = Memory.alloc(8); iterator.writePointer(nil);
            const methods = [];
            let complete = false;
            for (let i = 0; i < 8192; i++) {
                const method = api('class_get_methods', 'pointer', ['pointer', 'pointer'])(klass, iterator);
                if (method.isNull()) { complete = true; break; }
                const methodName = api('method_get_name', 'pointer', ['pointer'])(method).readUtf8String();
                if (!selected.includes(methodName)) continue;
                const parameterCount = api('method_get_param_count', 'uint', ['pointer'])(method);
                if (parameterCount > 32) throw Error('Unexpected parameter count');
                const parameters = [];
                for (let j = 0; j < parameterCount; j++)
                    parameters.push(typeName(api('method_get_param', 'pointer', ['pointer', 'uint'])(method, j)));
                // Only inspect the known MethodInfo first pointer; never invoke it.
                const native = method.readPointer();
                const range = native.isNull() ? null : Process.findModuleByAddress(native);
                methods.push({ name: methodName, parameters,
                    returns: typeName(api('method_get_return_type', 'pointer', ['pointer'])(method)),
                    flags: api('method_get_flags', 'uint', ['pointer', 'pointer'])(method, nil),
                    native_module: range === null ? null : range.name,
                    native_offset: range === null ? null : native.sub(range.base).toString() });
            }
            if (!complete) throw Error('Method enumeration exceeded bounds');
            classes.push({ assembly, namespace, name, methods });
        }
        const mainImage = images.get('Assembly-CSharp.dll');
        if (mainImage === undefined) throw Error('Game assembly missing');
        const assets = api('class_from_name', 'pointer', ['pointer', 'pointer', 'pointer'])(mainImage, text('Terraria.GameContent'), text('TextureAssets'));
        if (assets.isNull()) throw Error('TextureAssets class missing');
        const tableField = api('class_get_field_from_name', 'pointer', ['pointer', 'pointer'])(assets, text('Item'));
        if (tableField.isNull()) throw Error('Item texture table metadata missing');
        const value = Memory.alloc(8); value.writePointer(nil);
        api('field_static_get_value', 'void', ['pointer', 'pointer'])(tableField, value);
        const table = value.readPointer();
        if (table.isNull()) throw Error('Item texture table not initialized');
        const tableRoot = api('gchandle_new', 'uint', ['pointer', 'uchar'])(table, 0);
        if (!tableRoot) throw Error('Metadata table root allocation failed');
        let textureTable;
        try {
            const arrayClass = api('object_get_class', 'pointer', ['pointer'])(table);
            const element = api('class_get_element_class', 'pointer', ['pointer'])(arrayClass);
            if (element.isNull()) throw Error('Texture table element class missing');
            const methodIterator = Memory.alloc(8); methodIterator.writePointer(nil);
            const entryMethods = [];
            for (let i = 0; i < 8192; i++) {
                const m = api('class_get_methods', 'pointer', ['pointer', 'pointer'])(element, methodIterator);
                if (m.isNull()) break;
                const name = api('method_get_name', 'pointer', ['pointer'])(m).readUtf8String();
                if (!['.ctor', 'SubmitLoadedContent', 'get_IsLoaded', 'get_State', 'Dispose'].includes(name)) continue;
                const n = api('method_get_param_count', 'uint', ['pointer'])(m), parameters = [];
                if (n > 32) throw Error('Asset parameter count exceeds bound');
                for (let j = 0; j < n; j++) parameters.push(typeName(api('method_get_param', 'pointer', ['pointer', 'uint'])(m, j)));
                const pointer = m.readPointer(), module = pointer.isNull() ? null : Process.findModuleByAddress(pointer);
                entryMethods.push({ name, parameters, native_module: module === null ? null : module.name,
                    native_offset: module === null ? null : pointer.sub(module.base).toString() });
            }
            const fieldIterator = Memory.alloc(8); fieldIterator.writePointer(nil); const entryFields = [];
            for (let i = 0; i < 1024; i++) {
                const f = api('class_get_fields', 'pointer', ['pointer', 'pointer'])(element, fieldIterator);
                if (f.isNull()) break;
                entryFields.push({ name: api('field_get_name', 'pointer', ['pointer'])(f).readUtf8String(),
                    type: typeName(api('field_get_type', 'pointer', ['pointer'])(f)),
                    flags: api('field_get_flags', 'uint', ['pointer'])(f) });
            }
            textureTable = { length: api('array_length', 'ulong', ['pointer'])(table).toNumber(),
                element_type: typeName(api('class_get_type', 'pointer', ['pointer'])(element)),
                element_is_value_type: api('class_is_valuetype', 'uchar', ['pointer'])(element) !== 0,
                methods: entryMethods, fields: entryFields };
        } finally { api('gchandle_free', 'void', ['uint'])(tableRoot); }
        return { format: 'mobile-texture-capabilities-v1', architecture: Process.arch, classes, texture_table: textureTable,
            game_methods_invoked: false, texture_created: false, hooks_installed: false,
            content_tables_changed: false, saves_accessed: false, gpu_upload_verified: false };
    } finally {
        if (owned) api('thread_detach', 'void', ['pointer'])(thread);
    }
};
