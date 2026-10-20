'use strict';
// Isolated laboratory item; it never enters inventory/saves. Its vanilla
// template is a renderer fixture, not a reimplementation of SOTS gameplay.
globalThis.TMALItemIconPreview = function (context) {
    const { api, klass, method, typeName, str, nil, root, get, free, call, scalar, result, texture, arrayGet } = context;
    const item = klass('Assembly-CSharp.dll', 'Terraria', 'Item');
    const vector = klass('Assembly-CSharp.dll', 'Microsoft.Xna.Framework', 'Vector2');
    const ctor = method(item, '.ctor', [], '0xf51cac');
    const defaults = method(item, 'SetDefaults', ['System.Int32', 'Terraria.GameContent.Items.ItemVariant'], '0xf51d50');
    const draw = method(klass('Assembly-CSharp.dll', 'Terraria.UI', 'ItemSlot'), 'DrawItemIcon', [
        'Terraria.Item', 'System.Int32', 'Microsoft.Xna.Framework.Graphics.SpriteBatch', 'Microsoft.Xna.Framework.Vector2',
        'System.Single', 'System.Single', 'Microsoft.Xna.Framework.Graphics.Color', 'System.Single', 'System.Boolean'], '0x8b28b4');
    function field(owner, name, type) {
        const f = api('class_get_field_from_name', 'pointer', ['pointer', 'pointer'])(owner, str(name));
        if (f.isNull() || typeName(api('field_get_type', 'pointer', ['pointer'])(f)) !== type ||
            (api('field_get_flags', 'uint', ['pointer'])(f) & 0x10) !== 0) throw Error('Item icon fixture field differs');
        return f;
    }
    const typeField = field(item, 'type', 'System.Int32');
    const entity = klass('Assembly-CSharp.dll', 'Terraria', 'Entity');
    const dimensions = [field(entity, 'width', 'System.Int32'), field(entity, 'height', 'System.Int32')];
    const vectorFields = [field(vector, 'X', 'System.Single'), field(vector, 'Y', 'System.Single')];
    const batchClass = klass('Assembly-CSharp.dll', 'Microsoft.Xna.Framework.Graphics', 'SpriteBatch');
    const batcherClass = klass('Assembly-CSharp.dll', 'Microsoft.Xna.Framework.Graphics', 'SpriteBatcher');
    const batchItemClass = klass('Assembly-CSharp.dll', 'Microsoft.Xna.Framework.Graphics', 'SpriteBatchItem');
    const batcherField = field(batchClass, '_batcher', 'Microsoft.Xna.Framework.Graphics.SpriteBatcher');
    const itemList = field(batcherClass, '_batchItemList', 'Microsoft.Xna.Framework.Graphics.SpriteBatchItem[]');
    const itemCount = field(batcherClass, '_batchItemCount', 'System.Int32');
    const batchTexture = field(batchItemClass, 'Texture', 'Microsoft.Xna.Framework.Graphics.Texture2D');
    let itemRoot = 0, positionRoot = 0, imageSize = 0;
    const unbox = api('object_unbox', 'pointer', ['pointer']);
    function queue(batch) {
        const value = Memory.alloc(8); value.writePointer(nil);
        const read = api('field_get_value', 'void', ['pointer', 'pointer', 'pointer']);
        read(batch, batcherField, value); const batcher = value.readPointer();
        if (batcher.isNull()) throw Error('Icon SpriteBatcher absent');
        value.writeU64(0); read(batcher, itemCount, value); const count = value.readS32();
        if (count < 0 || count > 65536) throw Error('Icon batch count outside diagnostic bound');
        if (count === 0) return { count, texture: nil };
        read(batcher, itemList, value); const list = value.readPointer();
        if (list.isNull() || api('array_length', 'ulong', ['pointer'])(list).toNumber() < count) throw Error('Icon batch array differs');
        const last = call(arrayGet, list, [scalar(count - 1)]);
        if (last.isNull()) throw Error('Icon batch entry absent');
        read(last, batchTexture, value);
        return { count, texture: value.readPointer() };
    }
    return {
        prepare(width, height) {
            const object = api('object_new', 'pointer', ['pointer'])(item);
            if (object.isNull()) throw Error('Item icon fixture allocation failed');
            itemRoot = root(object, 0); if (!itemRoot) throw Error('Item icon fixture root failed');
            call(ctor, get(itemRoot), []);
            call(defaults, get(itemRoot), [scalar(3507), nil]);
            api('field_set_value', 'void', ['pointer', 'pointer', 'pointer'])(get(itemRoot), typeField, scalar(6196));
            dimensions.forEach((f, i) => api('field_set_value', 'void', ['pointer', 'pointer', 'pointer'])(get(itemRoot), f, scalar([width, height][i])));
            const align = Memory.alloc(4); align.writeS32(0);
            if (!api('class_is_valuetype', 'uchar', ['pointer'])(vector) ||
                api('class_value_size', 'int', ['pointer', 'pointer'])(vector, align) !== 8) throw Error('Icon position layout differs');
            const data = Memory.alloc(8); data.writeU64(0);
            const position = api('value_box', 'pointer', ['pointer', 'pointer'])(vector, data);
            if (position.isNull()) throw Error('Icon position allocation failed');
            positionRoot = root(position, 0); if (!positionRoot) throw Error('Icon position root failed');
            vectorFields.forEach((f, i) => api('field_set_value', 'void', ['pointer', 'pointer', 'pointer'])(get(positionRoot), f, scalar([168, 148][i], 'float')));
            imageSize = Math.max(width, height);
            result.item_icon_calls = 0; result.item_icon_queued_texture_matches = 0;
        },
        draw(batch, color) {
            const value = Memory.alloc(4); value.writeS32(0);
            api('field_get_value', 'void', ['pointer', 'pointer', 'pointer'])(get(itemRoot), typeField, value);
            if (value.readS32() !== 6196) throw Error('Icon renderer item type was aliased');
            const before = queue(batch);
            const returned = call(draw, nil, [get(itemRoot), scalar(31), batch, unbox(get(positionRoot)),
                scalar(4, 'float'), scalar(imageSize, 'float'), unbox(color), scalar(1, 'float'), scalar(0)]);
            if (returned.isNull()) throw Error('Icon renderer returned no scale');
            const scale = unbox(returned).readFloat();
            if (!Number.isFinite(scale) || scale <= 0 || scale > 8) throw Error('Icon renderer returned an unexpected scale');
            const after = queue(batch);
            if (after.count <= before.count || !after.texture.equals(texture())) throw Error('Item icon queue growth/texture differs');
            if (result.item_icon_calls === 0) {
                if (before.texture.equals(texture())) throw Error('Icon queue control already contained the diagnostic texture');
                result.item_icon_queue_transition_verified = true;
            }
            result.item_icon_calls++; result.item_icon_queued_texture_matches++;
            result.item_icon_draw_scale = scale; result.item_icon_type = 6196;
        },
        stop() {
            if (positionRoot) { free(positionRoot); positionRoot = 0; }
            if (itemRoot) { free(itemRoot); itemRoot = 0; }
            result.item_icon_roots_released = true;
        }
    };
};
