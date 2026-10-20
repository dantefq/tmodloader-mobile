'use strict';
// Optional, short menu diagnostic. Draws into an already active main SpriteBatch;
// never replaces a game texture, opens a world or sends input. Screenshots are private.
globalThis.TMALTextureMenuOverlay = function (context) {
    const { api, klass, method, typeName, str, nil, root, get, free, call, scalar,
        main, mainThread, isOfflineMenu, result, allowed, texture } = context;
    const batchClass = klass('Assembly-CSharp.dll', 'Microsoft.Xna.Framework.Graphics', 'SpriteBatch');
    const rectClass = klass('Assembly-CSharp.dll', 'Microsoft.Xna.Framework', 'Rectangle');
    const colorClass = klass('Assembly-CSharp.dll', 'Microsoft.Xna.Framework.Graphics', 'Color');
    const end = method(batchClass, 'End', [], '0xed50b4');
    const draw = method(batchClass, 'Draw', ['Microsoft.Xna.Framework.Graphics.Texture2D',
        'Microsoft.Xna.Framework.Rectangle', 'Microsoft.Xna.Framework.Graphics.Color'], '0xed97d8');
    function field(owner, name, type, isStatic) {
        const value = api('class_get_field_from_name', 'pointer', ['pointer', 'pointer'])(owner, str(name));
        if (value.isNull() || typeName(api('field_get_type', 'pointer', ['pointer'])(value)) !== type ||
            Boolean(api('field_get_flags', 'uint', ['pointer'])(value) & 0x10) !== isStatic)
            throw Error('Menu overlay field metadata differs');
        return value;
    }
    const batchField = field(main, 'spriteBatch', 'Microsoft.Xna.Framework.Graphics.SpriteBatch', true);
    const begunField = field(batchClass, '_beginCalled', 'System.Boolean', false);
    const rectFields = ['X', 'Y', 'Width', 'Height'].map(n => field(rectClass, n, 'System.Int32', false));
    const colorFields = ['R', 'G', 'B', 'A'].map(n => field(colorClass, n, 'System.Byte', false));
    let observer = null, rectRoot = 0, colorRoot = 0, started = 0, frame = 0, lastFrame = -1, stoppedAt = null;
    function box(owner, size) {
        const align = Memory.alloc(4); align.writeS32(0);
        if (!api('class_is_valuetype', 'uchar', ['pointer'])(owner) ||
            api('class_value_size', 'int', ['pointer', 'pointer'])(owner, align) !== size)
            throw Error('Menu overlay value type size differs');
        const data = Memory.alloc(size); data.writeByteArray(new Uint8Array(size));
        const object = api('value_box', 'pointer', ['pointer', 'pointer'])(owner, data);
        if (object.isNull()) throw Error('Menu overlay value box failed');
        const handle = root(object, 0);
        if (!handle) throw Error('Menu overlay GC root failed');
        return handle;
    }
    function stop() {
        if (observer !== null) { observer.detach(); observer = null; result.menu_overlay_hook_detached = true; }
        if (rectRoot) { free(rectRoot); rectRoot = 0; }
        if (colorRoot) { free(colorRoot); colorRoot = 0; }
    }
    return {
        start(width, height) {
            started = Date.now();
            rectRoot = box(rectClass, 16); colorRoot = box(colorClass, 4);
            const rect = [80, 80, width * 4, height * 4];
            rectFields.forEach((f, i) => api('field_set_value', 'void', ['pointer', 'pointer', 'pointer'])(get(rectRoot), f, scalar(rect[i])));
            const white = Memory.alloc(1); white.writeU8(255);
            colorFields.forEach(f => api('field_set_value', 'void', ['pointer', 'pointer', 'pointer'])(get(colorRoot), f, white));
            result.menu_overlay_rectangle = rect;
            result.menu_overlay_draw_calls = 0;
            observer = Interceptor.attach(end.readPointer(), { onEnter(args) {
                if (!allowed() || lastFrame === frame || result.error !== null) return;
                try {
                    if (api('object_unbox', 'pointer', ['pointer'])(call(mainThread, nil, [])).readU8() === 0 || !isOfflineMenu())
                        throw Error('Menu overlay left authorized main-thread menu');
                    const active = Memory.alloc(8); active.writePointer(nil);
                    api('field_static_get_value', 'void', ['pointer', 'pointer'])(batchField, active);
                    if (!args[0].equals(active.readPointer())) return;
                    const begun = Memory.alloc(1); begun.writeU8(0);
                    api('field_get_value', 'void', ['pointer', 'pointer', 'pointer'])(args[0], begunField, begun);
                    if (!begun.readU8()) return;
                    lastFrame = frame;
                    const unbox = api('object_unbox', 'pointer', ['pointer']);
                    if (context.previewDraw) context.previewDraw(args[0], get(colorRoot));
                    else call(draw, args[0], [texture(), unbox(get(rectRoot)), unbox(get(colorRoot))]);
                    result.menu_overlay_draw_calls++;
                } catch (e) { result.error = String(e); }
            } });
        },
        tick() {
            frame++;
            if (result.error !== null) throw Error(result.error);
            if (stoppedAt !== null) return frame - stoppedAt >= 2;
            if (Date.now() - started > 3000 && result.menu_overlay_draw_calls >= 3) {
                stop(); stoppedAt = frame; result.menu_overlay_submission_verified = true;
            } else if (Date.now() - started > 8000) throw Error('Active menu SpriteBatch not observed');
            return false;
        },
        stop
    };
};
