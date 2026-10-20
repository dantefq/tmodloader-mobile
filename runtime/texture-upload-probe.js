'use strict';
// Bounded diagnostic: temporary Unity texture (at most 256x256). Optional lab
// item-icon mode publishes/restores copied tables. No inventory/world/save writes.
let listener = null;
const result = { phase: 'idle', texture_created: false, png_loaded: false,
    dimensions_verified: false, color_verified: false, destroy_requested: false,
    destroy_observed: false, hook_detached: false, content_tables_changed: false,
    saves_accessed: false, error: null };
rpc.exports.moduleinfo = function () {
    const lib = Process.getModuleByName('libil2cpp.so');
    return { architecture: Process.arch, pointer_size: Process.pointerSize, library_path: lib.path };
};
rpc.exports.status = () => JSON.parse(JSON.stringify(result));
rpc.exports.cancel = function () {
    result.cancel_requested = true;
    return { cleanup_scheduled: !['complete', 'failed', 'idle'].includes(result.phase) };
};
rpc.exports.retrycleanup = function () {
    if (result.phase !== 'cleanup-failed') throw Error('No failed cleanup to retry');
    result.phase = 'retry-cleanup'; return { cleanup_scheduled: true };
};
function checkedPacket(bytes, plan) {
    if (typeof globalThis.TMALTexturePacket === 'undefined') throw Error('Texture packet receiver absent');
    const packet = globalThis.TMALTexturePacket.decode(bytes, plan, data => Checksum.compute('sha256', data));
    if (plan.format !== undefined) {
        if (plan.format !== 'tmal-item-texture-transfer-v1') throw Error('Unsupported native binding plan');
        const supported = (plan.item === 'TextureBindingLab/Preview' && plan.asset === 'TextureBindingLab/Images/SourceIcon.rawimg') ||
            (plan.item === 'TextureBridgeLab/Icon' && plan.asset === 'TextureBridgeLab/Images/Icon.rawimg' && plan.width === 2 && plan.height === 2);
        if (plan.itemType !== 6196 || !supported ||
            plan.width !== packet.width || plan.height !== packet.height || typeof plan.transferId !== 'string' ||
            !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(plan.transferId) ||
            plan.transferId === '00000000-0000-0000-0000-000000000000')
            throw Error('Registry plan item/dimensions/transfer differ from laboratory allocation');
    }
    return packet;
}
rpc.exports.checkpacket = function (bytes, plan) {
    const packet = checkedPacket(bytes, plan);
    return { asset: packet.asset, generation: packet.generation, dimensions: [packet.width, packet.height],
        zlib_rows_checked_here: false, graphics_methods_invoked: false };
};
rpc.exports.beginpacket = function (bytes, plan, sample, uv, extra, wrapper, asset, slot, overlay, itemIcon) {
    const packet = checkedPacket(bytes, plan);
    const response = rpc.exports.begin(Array.from(packet.copyPng()), packet.width, packet.height, sample, uv, extra, wrapper, asset, slot, overlay, itemIcon, packet.generation);
    result.texture_packet_verified = true;
    result.packet_generation_is_synthetic_fixture = plan.format !== 'tmal-item-texture-transfer-v1';
    result.texture_transfer_id = plan.transferId || null;
    result.registration_scope_is_laboratory = true;
    result.binding_plan_format = plan.format || 'pinned-host-diagnostic';
    return response;
};
rpc.exports.begin = function (bytes, expectedWidth, expectedHeight, expectedSample, sampleUv, extraSamples, verifyWrapper, verifyAsset, verifySlot, verifyOverlay, verifyItemIcon, registrationGeneration) {
    if (result.phase !== 'idle') throw Error('Probe is single-use');
    if (Process.arch !== 'arm64' || Process.pointerSize !== 8) throw Error('Native ARM64 required');
    if (!Array.isArray(bytes) || bytes.length < 33 || bytes.length > 65536 || bytes.some(b => !Number.isInteger(b) || b < 0 || b > 255))
        throw Error('Bounded PNG byte array required');
    if (![expectedWidth, expectedHeight].every(n => Number.isInteger(n) && n > 0 && n <= 256) ||
        !Array.isArray(expectedSample) || expectedSample.length !== 4 || expectedSample.some(n => !Number.isFinite(n) || n < 0 || n > 1))
        throw Error('Bounded dimensions and reference center color required');
    if (!Array.isArray(sampleUv) || sampleUv.length !== 2 || sampleUv.some(n => !Number.isFinite(n) || n < 0 || n > 1))
        throw Error('Bounded sample UV required');
    if (!Array.isArray(extraSamples) || extraSamples.length > 7 || extraSamples.some(s =>
        !Array.isArray(s.uv) || s.uv.length !== 2 || s.uv.some(n => !Number.isFinite(n) || n < 0 || n > 1) ||
        !Array.isArray(s.rgba) || s.rgba.length !== 4 || s.rgba.some(n => !Number.isFinite(n) || n < 0 || n > 1)))
        throw Error('At most eight bounded color checks allowed');
    if (typeof verifyWrapper !== 'boolean') throw Error('Explicit wrapper phase required');
    if (typeof verifyAsset !== 'boolean' || (verifyAsset && !verifyWrapper)) throw Error('Asset phase requires XNA wrapper');
    if (typeof verifySlot !== 'boolean' || (verifySlot && (!verifyAsset || typeof globalThis.TMALTextureSlotLease !== 'function')))
        throw Error('Private slot phase requires Asset and lease helper');
    if (typeof verifyOverlay !== 'boolean' || (verifyOverlay && (!verifySlot || typeof globalThis.TMALTextureMenuOverlay !== 'function')))
        throw Error('Menu overlay requires private Asset slot phase');
    if (typeof verifyItemIcon !== 'boolean' || (verifyItemIcon && (!verifyOverlay || !registrationGeneration ||
        typeof globalThis.TMALNativeContentTableScope !== 'function' || typeof globalThis.TMALItemIconPreview !== 'function')))
        throw Error('Item icon phase requires overlay, table scope and packet generation');
    const lib = Process.getModuleByName('libil2cpp.so');
    const api = (n, r, a) => new NativeFunction(lib.getExportByName('il2cpp_' + n), r, a);
    const nil = ptr(0), str = s => Memory.allocUtf8String(s);
    const domain = api('domain_get', 'pointer', [])();
    if (domain.isNull()) throw Error('Runtime not ready');
    const current = api('thread_current', 'pointer', [])();
    const owned = current.isNull();
    const thread = owned ? api('thread_attach', 'pointer', ['pointer'])(domain) : current;
    if (thread.isNull()) throw Error('Metadata attach failed');
    try {
        const get = api('gchandle_get_target', 'pointer', ['uint']);
        const root = api('gchandle_new', 'uint', ['pointer', 'uchar']);
        const free = api('gchandle_free', 'void', ['uint']);
        const headerSize = api('array_object_header_size', 'uint', [])();
        if (headerSize !== 32) throw Error('Byte-array header layout differs');
        const count = Memory.alloc(8); count.writeU64(0);
        const assemblies = api('domain_get_assemblies', 'pointer', ['pointer', 'pointer'])(domain, count);
        const images = new Map();
        if (count.readU64().toNumber() > 2048) throw Error('Assembly count exceeds bound');
        for (let i = 0; i < count.readU64().toNumber(); i++) {
            const image = api('assembly_get_image', 'pointer', ['pointer'])(assemblies.add(i * 8).readPointer());
            images.set(api('image_get_name', 'pointer', ['pointer'])(image).readUtf8String(), image);
        }
        const klass = (image, ns, name) => {
            if (!images.has(image)) throw Error('Required assembly absent');
            const k = api('class_from_name', 'pointer', ['pointer', 'pointer', 'pointer'])(images.get(image), str(ns), str(name));
            if (k.isNull()) throw Error('Required class absent'); return k;
        };
        const typeName = t => {
            const p = api('type_get_name', 'pointer', ['pointer'])(t);
            try { return p.readUtf8String(); } finally { api('free', 'void', ['pointer'])(p); }
        };
        function method(k, name, parameters, expectedOffset) {
            const iterator = Memory.alloc(8); iterator.writePointer(nil); const found = [];
            for (let i = 0; i < 8192; i++) {
                const m = api('class_get_methods', 'pointer', ['pointer', 'pointer'])(k, iterator);
                if (m.isNull()) break;
                if (api('method_get_name', 'pointer', ['pointer'])(m).readUtf8String() !== name) continue;
                const n = api('method_get_param_count', 'uint', ['pointer'])(m);
                if (n !== parameters.length) continue;
                const actual = [];
                for (let j = 0; j < n; j++) actual.push(typeName(api('method_get_param', 'pointer', ['pointer', 'uint'])(m, j)));
                if (JSON.stringify(actual) === JSON.stringify(parameters)) found.push(m);
            }
            if (found.length !== 1 || found[0].readPointer().sub(lib.base).toString() !== expectedOffset)
                throw Error('Method signature/address differs: ' + name);
            return found[0];
        }
        const texture = klass('UnityEngine.CoreModule.dll', 'UnityEngine', 'Texture2D');
        const baseTexture = klass('UnityEngine.CoreModule.dll', 'UnityEngine', 'Texture');
        const unityObject = klass('UnityEngine.CoreModule.dll', 'UnityEngine', 'Object');
        const color = klass('UnityEngine.CoreModule.dll', 'UnityEngine', 'Color');
        const ctor = method(texture, '.ctor', ['System.Int32', 'System.Int32'], '0x271eda8');
        const load = method(klass('UnityEngine.ImageConversionModule.dll', 'UnityEngine', 'ImageConversion'), 'LoadImage', ['UnityEngine.Texture2D', 'System.Byte[]', 'System.Boolean'], '0x273bf14');
        const width = method(baseTexture, 'get_width', [], '0x271dcdc');
        const height = method(baseTexture, 'get_height', [], '0x271dd58');
        const pixel = method(texture, 'GetPixelBilinear', ['System.Single', 'System.Single'], '0x271ee48');
        const destroy = method(unityObject, 'Destroy', ['UnityEngine.Object'], '0x272d140');
        const exists = method(unityObject, 'op_Implicit', ['UnityEngine.Object'], '0x272cd30');
        const mainThread = method(klass('Assembly-CSharp.dll', '', 'DrPlatform'), 'get_IsMainThread', [], '0x7d0ca4');
        const main = klass('Assembly-CSharp.dll', 'Terraria', 'Main');
        const draw = method(main, 'Draw', ['Microsoft.Xna.Framework.GameTime'], '0x1105d70');
        const menuGetter = method(main, 'get_gameMenu', [], '0x1010618');
        const netField = api('class_get_field_from_name', 'pointer', ['pointer', 'pointer'])(main, str('netMode'));
        if (netField.isNull() || typeName(api('field_get_type', 'pointer', ['pointer'])(netField)) !== 'System.Int32' ||
            (api('field_get_flags', 'uint', ['pointer'])(netField) & 0x10) === 0) throw Error('Network mode guard metadata differs');
        function isOfflineMenu() {
            const value = Memory.alloc(8); value.writeU64(0);
            api('field_static_get_value', 'void', ['pointer', 'pointer'])(netField, value);
            return value.readS32() === 0 && bool(call(menuGetter, nil, []));
        }
        const wrapper = verifyWrapper ? klass('Assembly-CSharp.dll', 'Microsoft.Xna.Framework.Graphics', 'Texture2D') : null;
        const wrapperCtor = verifyWrapper ? method(wrapper, '.ctor', ['UnityEngine.Texture2D'], '0xef2584') : null;
        const wrapperFields = verifyWrapper ? [['Width', 'System.Int32'], ['Height', 'System.Int32'], ['_unityTexture', 'UnityEngine.Texture2D']].map(([name, type]) => {
            const field = api('class_get_field_from_name', 'pointer', ['pointer', 'pointer'])(wrapper, str(name));
            if (field.isNull() || typeName(api('field_get_type', 'pointer', ['pointer'])(field)) !== type ||
                (api('field_get_flags', 'uint', ['pointer'])(field) & 0x10) !== 0) throw Error('XNA wrapper field differs');
            return field;
        }) : [];
        let assetClass = null, assetCtor = null, assetSubmit = null, assetLoaded = null, assetDispose = null, assetValue = null, assetDisposed = null;
        if (verifyAsset) {
            const assets = klass('Assembly-CSharp.dll', 'Terraria.GameContent', 'TextureAssets');
            const field = api('class_get_field_from_name', 'pointer', ['pointer', 'pointer'])(assets, str('Item'));
            if (field.isNull()) throw Error('Texture asset table absent');
            const array = Memory.alloc(8); array.writePointer(nil);
            api('field_static_get_value', 'void', ['pointer', 'pointer'])(field, array);
            if (array.readPointer().isNull()) throw Error('Texture asset table not initialized');
            assetClass = api('class_get_element_class', 'pointer', ['pointer'])(api('object_get_class', 'pointer', ['pointer'])(array.readPointer()));
            if (assetClass.isNull() || typeName(api('class_get_type', 'pointer', ['pointer'])(assetClass)) !== 'ReLogic.Content.Asset<Microsoft.Xna.Framework.Graphics.Texture2D>')
                throw Error('Texture asset element type differs');
            assetCtor = method(assetClass, '.ctor', ['System.String'], '0x1f78b0c');
            assetSubmit = method(assetClass, 'SubmitLoadedContent', ['Microsoft.Xna.Framework.Graphics.Texture2D', 'ReLogic.Content.Sources.IContentSource'], '0x1f78c70');
            assetLoaded = method(assetClass, 'get_IsLoaded', [], '0x1f789f0');
            assetDispose = method(assetClass, 'Dispose', [], '0x1f78f00');
            assetValue = api('class_get_field_from_name', 'pointer', ['pointer', 'pointer'])(assetClass, str('Value'));
            assetDisposed = api('class_get_field_from_name', 'pointer', ['pointer', 'pointer'])(assetClass, str('<IsDisposed>k__BackingField'));
            if (assetValue.isNull() || assetDisposed.isNull() ||
                typeName(api('field_get_type', 'pointer', ['pointer'])(assetValue)) !== 'Microsoft.Xna.Framework.Graphics.Texture2D' ||
                typeName(api('field_get_type', 'pointer', ['pointer'])(assetDisposed)) !== 'System.Boolean') throw Error('Asset fields differ');
        }
        const byteClass = api('class_from_name', 'pointer', ['pointer', 'pointer', 'pointer'])(api('get_corlib', 'pointer', [])(), str('System'), str('Byte'));
        if (byteClass.isNull()) throw Error('Byte class absent');
        const systemArray = verifySlot ? klass('mscorlib.dll', 'System', 'Array') : null;
        const arrayGet = verifySlot ? method(systemArray, 'GetValue', ['System.Int32'], '0x23a2698') : null;
        const arraySet = verifySlot ? method(systemArray, 'SetValue', ['System.Object', 'System.Int32'], '0x23ac4d0') : null;
        const fields = ['r', 'g', 'b', 'a'].map(name => {
            const f = api('class_get_field_from_name', 'pointer', ['pointer', 'pointer'])(color, str(name));
            if (f.isNull() || typeName(api('field_get_type', 'pointer', ['pointer'])(f)) !== 'System.Single') throw Error('Color layout differs');
            return f;
        });
        const scalar = (value, kind) => { const p = Memory.alloc(4); kind === 'float' ? p.writeFloat(value) : p.writeS32(value); return p; };
        function call(m, object, args) {
            const argv = Memory.alloc(Math.max(8, args.length * 8)); args.forEach((v, i) => argv.add(i * 8).writePointer(v));
            const exception = Memory.alloc(8); exception.writePointer(nil);
            const value = api('runtime_invoke', 'pointer', ['pointer', 'pointer', 'pointer', 'pointer'])(m, object, argv, exception);
            if (!exception.readPointer().isNull()) throw Error('Managed exception during diagnostic call');
            return value;
        }
        const bool = value => { if (value.isNull()) throw Error('Missing Boolean result'); return api('object_unbox', 'pointer', ['pointer'])(value).readU8() !== 0; };
        let textureRoot = 0, wrapperRoot = 0, assetRoot = 0, privateArrayRoot = 0, slotLease = null, frames = 0, heldFrames = 0;
        const tableScope = verifyItemIcon ? globalThis.TMALNativeContentTableScope({ api, klass, method, str, nil, root, get, free, call, scalar, bool,
            mainThread, isOfflineMenu, systemArray, arrayGet, arraySet, result }) : null;
        const icon = verifyItemIcon ? globalThis.TMALItemIconPreview({ api, klass, method, typeName, str, nil, root, get, free, call, scalar, result,
            texture: () => get(wrapperRoot), arrayGet }) : null;
        const overlay = verifyOverlay ? globalThis.TMALTextureMenuOverlay({ api, klass, method, typeName, str, nil, root, get, free, call, scalar,
            main, mainThread, isOfflineMenu, result, allowed: () => result.phase === 'private-slot-held', texture: () => get(wrapperRoot),
            previewDraw: icon === null ? null : (batch, color) => icon.draw(batch, color) }) : null;
        function finish() {
            if (tableScope !== null) tableScope.freeRoots();
            if (privateArrayRoot) { free(privateArrayRoot); privateArrayRoot = 0; }
            if (assetRoot) { free(assetRoot); assetRoot = 0; }
            if (wrapperRoot) { free(wrapperRoot); wrapperRoot = 0; }
            if (textureRoot) { free(textureRoot); textureRoot = 0; }
            result.cleanup_root_id = 0;
            if (listener !== null) { listener.detach(); listener = null; result.hook_detached = true; }
            result.phase = result.error === null ? 'complete' : 'failed';
        }
        function cleanup() {
            if (overlay !== null) overlay.stop();
            if (icon !== null) icon.stop();
            if (tableScope !== null) {
                try { tableScope.release(); }
                catch (e) {
                    result.error = String(result.error) + '; published table rollback: ' + String(e);
                    result.phase = 'cleanup-failed';
                    return; // Keep every dependent Asset/texture/root alive.
                }
            }
            if (slotLease !== null && slotLease.status().resources_must_be_retained) {
                try { slotLease.release(); }
                catch (e) { result.error = String(result.error) + '; private array rollback: ' + String(e); }
            }
            // The diagnostic array is never published or retained by game code.
            // It can be abandoned even if its private lease failed.
            if (assetRoot) {
                try {
                    call(assetDispose, get(assetRoot), []);
                    const disposed = Memory.alloc(1); disposed.writeU8(0);
                    api('field_get_value', 'void', ['pointer', 'pointer', 'pointer'])(get(assetRoot), assetDisposed, disposed);
                    result.asset_disposal_verified = disposed.readU8() !== 0;
                    if (!result.asset_disposal_verified) result.error = 'Asset disposal state not observed';
                } catch (e) { result.error = String(e); }
            }
            if (textureRoot) {
                try {
                    if (bool(call(exists, nil, [get(textureRoot)]))) {
                        call(destroy, nil, [get(textureRoot)]); result.destroy_requested = true; result.phase = 'cleanup';
                    } else finish();
                }
                catch (e) { result.error = String(e); result.phase = 'cleanup-failed'; }
            } else finish();
        }
        result.phase = 'waiting-for-main-thread';
        listener = Interceptor.attach(draw.readPointer(), { onEnter() {
            if (result.phase === 'retry-cleanup') { cleanup(); return; }
            if (result.cancel_requested && !['complete', 'failed', 'cleanup', 'cleanup-failed'].includes(result.phase)) {
                result.error = result.error || 'Host requested cancellation';
                if (result.phase === 'waiting-for-main-thread') finish(); else cleanup();
                return;
            }
            if (result.phase === 'waiting-for-main-thread') {
                try {
                    if (!bool(call(mainThread, nil, []))) return;
                    if (!isOfflineMenu()) throw Error('Game left offline menu before probe');
                } catch (e) { result.error = String(e); finish(); return; }
                result.menu_only_verified = true;
                result.phase = 'running';
                try {
                    const object = api('object_new', 'pointer', ['pointer'])(texture);
                    if (object.isNull()) throw Error('Texture allocation failed');
                    textureRoot = root(object, 0);
                    result.cleanup_root_id = textureRoot;
                    if (!textureRoot) throw Error('Texture GC root allocation failed');
                    call(ctor, get(textureRoot), [scalar(expectedWidth), scalar(expectedHeight)]); result.texture_created = true;
                    const array = api('array_new', 'pointer', ['pointer', 'ulong'])(byteClass, bytes.length);
                    if (array.isNull()) throw Error('PNG array allocation failed');
                    const arrayRoot = root(array, 1);
                    if (!arrayRoot) throw Error('PNG GC root allocation failed');
                    try {
                        get(arrayRoot).add(headerSize).writeByteArray(bytes);
                        result.png_loaded = bool(call(load, nil, [get(textureRoot), get(arrayRoot), scalar(0)]));
                    } finally { free(arrayRoot); }
                    if (!result.png_loaded) throw Error('Unity PNG decode failed');
                    const unbox = api('object_unbox', 'pointer', ['pointer']);
                    const w = unbox(call(width, get(textureRoot), [])).readS32();
                    const h = unbox(call(height, get(textureRoot), [])).readS32();
                    result.dimensions = [w, h];
                    result.dimensions_verified = w === expectedWidth && h === expectedHeight;
                    if (!result.dimensions_verified) throw Error('Decoded texture dimensions differ');
                    result.samples = [];
                    for (const check of [{ uv: sampleUv, rgba: expectedSample }, ...extraSamples]) {
                        const box = call(pixel, get(textureRoot), [scalar(check.uv[0], 'float'), scalar(check.uv[1], 'float')]);
                        if (box.isNull()) throw Error('Missing Color result');
                        const boxRoot = root(box, 0), sample = [];
                        if (!boxRoot) throw Error('Color GC root allocation failed');
                        try {
                            for (const field of fields) {
                                const value = Memory.alloc(4);
                                api('field_get_value', 'void', ['pointer', 'pointer', 'pointer'])(get(boxRoot), field, value);
                                sample.push(value.readFloat());
                            }
                        } finally { free(boxRoot); }
                        result.samples.push({ uv: check.uv, actual: sample, expected: check.rgba,
                            matched: sample.every((v, i) => Number.isFinite(v) && Math.abs(v - check.rgba[i]) < 0.005) });
                    }
                    result.sample_rgba = result.samples[0].actual;
                    result.color_verified = result.samples.every(s => s.matched);
                    if (!result.color_verified) throw Error('Uploaded diagnostic color differs');
                    if (verifyWrapper) {
                        const object = api('object_new', 'pointer', ['pointer'])(wrapper);
                        if (object.isNull()) throw Error('XNA wrapper allocation failed');
                        wrapperRoot = root(object, 0);
                        if (!wrapperRoot) throw Error('XNA wrapper GC root allocation failed');
                        call(wrapperCtor, get(wrapperRoot), [get(textureRoot)]);
                        result.xna_wrapper_created = true;
                        const values = wrapperFields.map(field => {
                            const value = Memory.alloc(8); value.writeU64(0);
                            api('field_get_value', 'void', ['pointer', 'pointer', 'pointer'])(get(wrapperRoot), field, value);
                            return value;
                        });
                        result.xna_dimensions_verified = values[0].readS32() === expectedWidth && values[1].readS32() === expectedHeight;
                        result.xna_texture_reference_verified = values[2].readPointer().equals(get(textureRoot));
                        if (!result.xna_dimensions_verified || !result.xna_texture_reference_verified) throw Error('XNA wrapper did not bind the uploaded texture');
                    }
                    if (verifyAsset) {
                        const object = api('object_new', 'pointer', ['pointer'])(assetClass);
                        if (object.isNull()) throw Error('Asset allocation failed');
                        assetRoot = root(object, 0); if (!assetRoot) throw Error('Asset GC root allocation failed');
                        const name = api('string_new', 'pointer', ['pointer'])(str('TMAL/Diagnostic/TemporaryTexture'));
                        const nameRoot = root(name, 0); if (!nameRoot) throw Error('Asset name GC root allocation failed');
                        try { call(assetCtor, get(assetRoot), [get(nameRoot)]); } finally { free(nameRoot); }
                        call(assetSubmit, get(assetRoot), [get(wrapperRoot), nil]);
                        result.asset_loaded_verified = bool(call(assetLoaded, get(assetRoot), []));
                        const value = Memory.alloc(8); value.writePointer(nil);
                        api('field_get_value', 'void', ['pointer', 'pointer', 'pointer'])(get(assetRoot), assetValue, value);
                        result.asset_value_verified = value.readPointer().equals(get(wrapperRoot));
                        if (!result.asset_loaded_verified || !result.asset_value_verified) throw Error('Asset did not accept uploaded content');
                        if (tableScope !== null) {
                            tableScope.prepare(get(assetRoot), registrationGeneration);
                            tableScope.install();
                            tableScope.verify(get(assetRoot));
                            icon.prepare(expectedWidth, expectedHeight);
                        }
                    }
                    if (verifySlot) {
                        const array = api('array_new', 'pointer', ['pointer', 'ulong'])(assetClass, 1);
                        if (array.isNull()) throw Error('Private Asset array allocation failed');
                        privateArrayRoot = root(array, 0);
                        if (!privateArrayRoot) throw Error('Private Asset array GC root allocation failed');
                        const read = (table, index) => call(arrayGet, table, [scalar(index)]);
                        const write = (table, index, value) => call(arraySet, table, [value, scalar(index)]);
                        slotLease = globalThis.TMALTextureSlotLease({
                            assertContext() {
                                if (!bool(call(mainThread, nil, [])) || !isOfflineMenu()) throw Error('Lease left authorized main-thread menu');
                            },
                            snapshot: () => ({ table: get(privateArrayRoot), generation: 'diagnostic-one-use',
                                length: api('array_length', 'ulong', ['pointer'])(get(privateArrayRoot)).toNumber() }),
                            equal: (a, b) => a.equals(b), read, write
                        }, { generation: 'diagnostic-one-use', index: 0, expected: nil, replacement: get(assetRoot) });
                        slotLease.install();
                        result.private_slot_install_verified = read(get(privateArrayRoot), 0).equals(get(assetRoot));
                        if (!result.private_slot_install_verified) throw Error('Private Asset slot lease not observed');
                        result.phase = 'private-slot-held';
                        if (overlay !== null) overlay.start(expectedWidth, expectedHeight);
                    }
                } catch (e) { result.error = String(e); }
                finally { if (result.phase !== 'private-slot-held' || result.error !== null) cleanup(); }
            } else if (result.phase === 'private-slot-held') {
                try {
                    if (!bool(call(mainThread, nil, []))) return;
                    if (!isOfflineMenu()) throw Error('Game left menu while private slot was held');
                    if (!call(arrayGet, get(privateArrayRoot), [scalar(0)]).equals(get(assetRoot)) ||
                        !bool(call(assetLoaded, get(assetRoot), [])) || !bool(call(exists, nil, [get(textureRoot)])))
                        throw Error('Private Asset did not survive frame boundary');
                    if (tableScope !== null) tableScope.verify(get(assetRoot));
                    result.private_slot_frames_verified = ++heldFrames;
                    if (overlay !== null ? !overlay.tick() : heldFrames < 2) return;
                    slotLease.release();
                    result.private_slot_restore_verified = call(arrayGet, get(privateArrayRoot), [scalar(0)]).isNull() &&
                        !slotLease.status().resources_must_be_retained;
                    if (!result.private_slot_restore_verified) throw Error('Private Asset slot restoration not observed');
                } catch (e) { result.error = String(e); }
                cleanup();
            } else if (result.phase === 'cleanup') {
                try {
                    if (!bool(call(exists, nil, [get(textureRoot)]))) { result.destroy_observed = true; finish(); }
                    else if (++frames > 120) { result.error = 'Deferred destruction not observed'; result.phase = 'cleanup-failed'; }
                } catch (e) { result.error = String(e); result.phase = 'cleanup-failed'; }
            }
        } });
        return { phase: result.phase };
    } finally { if (owned) api('thread_detach', 'void', ['pointer'])(thread); }
};
