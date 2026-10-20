'use strict';
// Pinned one-slot laboratory scope. Copies the known vanilla item tables before
// publishing references. No existing item, inventory or save is changed.
globalThis.TMALNativeContentTableScope = function (context) {
    const { api, klass, method, str, nil, root, get, free, call, scalar, bool,
        mainThread, isOfflineMenu, systemArray, arrayGet, arraySet, result } = context;
    const ID = 6196, BASE = 3507;
    const copy = method(systemArray, 'Copy', ['System.Array', 'System.Int32', 'System.Array', 'System.Int32', 'System.Int32'], '0x23aca54');
    const handles = [], rows = [], fields = new Map();
    let lease = null, generation = null, prepared = false, textureRow = null;
    function onThread() {
        if (!bool(call(mainThread, nil, []))) throw Error('Content-table scope requires game thread');
    }
    function read(field) {
        const out = Memory.alloc(8); out.writePointer(nil);
        api('field_static_get_value', 'void', ['pointer', 'pointer'])(field, out);
        return out.readPointer();
    }
    function keep(object) {
        const handle = root(object, 0);
        if (!handle) throw Error('Content-table scope GC root failed');
        handles.push(handle); return handle;
    }
    function length(array) { return api('array_length', 'ulong', ['pointer'])(array).toNumber(); }
    return {
        prepare(asset, expectedGeneration) {
            if (prepared || lease !== null || handles.length) throw Error('Content-table scope is single-use');
            onThread();
            if (!isOfflineMenu() || typeof expectedGeneration !== 'string' || !expectedGeneration) throw Error('Offline menu/generation required');
            generation = expectedGeneration;
            const main = klass('Assembly-CSharp.dll', 'Terraria', 'Main');
            const owners = [
                ['Terraria.Item', klass('Assembly-CSharp.dll', 'Terraria', 'Item')], ['Terraria.Main', main],
                ['Terraria.Lang', klass('Assembly-CSharp.dll', 'Terraria', 'Lang')],
                ['Terraria.GameContent.TextureAssets', klass('Assembly-CSharp.dll', 'Terraria.GameContent', 'TextureAssets')]
            ];
            const itemId = klass('Assembly-CSharp.dll', 'Terraria.ID', 'ItemID');
            const it = Memory.alloc(8); it.writePointer(nil); let sets = null, complete = false;
            for (let i = 0; i < 256; i++) {
                const type = api('class_get_nested_types', 'pointer', ['pointer', 'pointer'])(itemId, it);
                if (type.isNull()) { complete = true; break; }
                if (api('class_get_name', 'pointer', ['pointer'])(type).readUtf8String() === 'Sets') {
                    if (sets !== null) throw Error('Ambiguous item sets'); sets = type;
                }
            }
            if (!complete || sets === null) throw Error('Item sets metadata absent/incomplete');
            owners.push(['Terraria.ID.ItemID+Sets', sets]);
            for (const [ownerName, owner] of owners) {
                it.writePointer(nil); complete = false;
                for (let i = 0; i < 8192; i++) {
                    const field = api('class_get_fields', 'pointer', ['pointer', 'pointer'])(owner, it);
                    if (field.isNull()) { complete = true; break; }
                    if ((api('field_get_flags', 'uint', ['pointer'])(field) & 0x10) === 0) continue;
                    const type = api('field_get_type', 'pointer', ['pointer'])(field);
                    if (api('type_get_type', 'int', ['pointer'])(type) !== 29) continue;
                    const original = read(field);
                    if (original.isNull() || length(original) !== ID) continue;
                    const oldRoot = keep(original), arrayClass = api('object_get_class', 'pointer', ['pointer'])(get(oldRoot));
                    const replacement = api('array_new_specific', 'pointer', ['pointer', 'ulong'])(arrayClass, ID + 1);
                    if (replacement.isNull()) throw Error('Extended content table allocation failed');
                    const newRoot = keep(replacement);
                    call(copy, nil, [get(oldRoot), scalar(0), get(newRoot), scalar(0), scalar(ID)]);
                    call(copy, nil, [get(oldRoot), scalar(BASE), get(newRoot), scalar(ID), scalar(1)]);
                    const name = api('field_get_name', 'pointer', ['pointer'])(field).readUtf8String();
                    const key = ownerName + '::' + name;
                    if (fields.has(key)) throw Error('Duplicate content table');
                    fields.set(key, field);
                    const row = { key, original: get(oldRoot), replacement: get(newRoot), oldRoot, newRoot };
                    rows.push(row);
                    if (ownerName === 'Terraria.GameContent.TextureAssets' && name === 'Item') textureRow = row;
                }
                if (!complete) throw Error('Content-table field enumeration exceeded bound');
            }
            if (rows.length !== 129 || textureRow === null) throw Error('Pinned item table inventory differs');
            call(arraySet, get(textureRow.newRoot), [asset, scalar(ID)]);
            if (!call(arrayGet, get(textureRow.newRoot), [scalar(ID)]).equals(asset)) throw Error('Extended texture slot differs');
            // Reference samples catch an incorrect Copy overload/range. Value
            // arrays use the same managed Copy; no raw copying of GC references.
            for (const row of rows) {
                const element = api('class_get_element_class', 'pointer', ['pointer'])(api('object_get_class', 'pointer', ['pointer'])(get(row.oldRoot)));
                if (api('class_is_valuetype', 'uchar', ['pointer'])(element)) continue;
                for (const index of [0, BASE, ID - 1])
                    if (!call(arrayGet, get(row.oldRoot), [scalar(index)]).equals(call(arrayGet, get(row.newRoot), [scalar(index)])))
                        throw Error('Copied reference prefix differs');
            }
            lease = globalThis.TMALContentTableLease({ assertContext: onThread, generation: () => generation,
                equal: (a, b) => a.equals(b), read: key => read(fields.get(key)),
                write(key, value) {
                    result.content_tables_changed = true;
                    api('field_static_set_value', 'void', ['pointer', 'pointer'])(fields.get(key), value);
                }
            }, generation, rows);
            prepared = true;
            result.content_tables_prepared = rows.length;
        },
        install() {
            onThread(); if (!prepared || !isOfflineMenu()) throw Error('Prepared offline table scope required');
            lease.install();
            result.content_tables_changed = true;
            result.content_tables_installed = rows.length;
        },
        verify(asset) {
            onThread();
            if (!lease || lease.status().state !== 'installed' || !read(fields.get(textureRow.key)).equals(get(textureRow.newRoot)) ||
                !call(arrayGet, get(textureRow.newRoot), [scalar(ID)]).equals(asset)) throw Error('Published laboratory texture ownership differs');
        },
        release() {
            if (lease !== null) {
                lease.release();
                result.content_tables_restored = lease.status().state === 'restored';
            }
        },
        freeRoots() {
            if (lease !== null && lease.status().resources_must_be_retained) throw Error('Published content table roots must remain held');
            for (const handle of handles.splice(0)) free(handle);
            generation = null;
        },
        status: () => lease === null ? { state: 'unpublished', resources_must_be_retained: false } : lease.status()
    };
};
