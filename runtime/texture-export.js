'use strict';
// Read a bounded export from our trusted managed bridge. Expected registry/item
// identities must come from the caller, not from this export. No GPU calls.
globalThis.TMALTextureExport = (() => {
    const MAX_PACKET = 65536 + 613;
    const guid = value => typeof value === 'string' &&
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value) &&
        value !== '00000000-0000-0000-0000-000000000000';
    function base64(value) {
        if (typeof value !== 'string' || value.length < 136 || value.length > Math.ceil(MAX_PACKET / 3) * 4 ||
            value.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw Error('Invalid bounded packet Base64');
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;
        const count = value.length / 4 * 3 - padding;
        if (count > MAX_PACKET) throw Error('Texture export packet exceeds budget');
        const bytes = new Uint8Array(count); let index = 0;
        for (let i = 0; i < value.length; i += 4) {
            const a = alphabet.indexOf(value[i]), b = alphabet.indexOf(value[i + 1]);
            const c = value[i + 2] === '=' ? 0 : alphabet.indexOf(value[i + 2]);
            const d = value[i + 3] === '=' ? 0 : alphabet.indexOf(value[i + 3]);
            if (i + 4 === value.length && ((padding === 2 && (b & 15)) || (padding === 1 && (c & 3))))
                throw Error('Noncanonical packet Base64');
            const n = (a << 18) | (b << 12) | (c << 6) | d;
            if (index < count) bytes[index++] = n >>> 16;
            if (index < count) bytes[index++] = n >>> 8;
            if (index < count) bytes[index++] = n;
        }
        return bytes;
    }
    function decode(text, expected, sha256) {
        if (typeof text !== 'string' || text.length > 94208) throw Error('Texture export exceeds budget');
        if (!expected || !guid(expected.generation) || !Number.isSafeInteger(expected.itemType) || expected.itemType <= 0 ||
            typeof expected.item !== 'string' || !expected.item) throw Error('Expected active registry/item required');
        const value = JSON.parse(text), plan = value && value.plan;
        if (!value || value.format !== 'tmal-texture-export-v1' || !plan || plan.format !== 'tmal-item-texture-transfer-v1' ||
            plan.generation !== expected.generation || plan.itemType !== expected.itemType || plan.item !== expected.item ||
            !guid(plan.transferId)) throw Error('Texture export owner/item/transfer differs');
        const bytes = base64(value.packetBase64);
        const image = globalThis.TMALTexturePacket.decode(bytes, plan, sha256);
        if (image.width !== plan.width || image.height !== plan.height) throw Error('Texture export dimensions differ');
        return Object.freeze({ plan: Object.freeze({ ...plan }), image, copyPacket: () => bytes.slice() });
    }
    return Object.freeze({ decode });
})();
