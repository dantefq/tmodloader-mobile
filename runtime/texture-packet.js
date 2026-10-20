'use strict';
// Bounded receiver for the native diagnostic's small-texture subset of TMIT v1.
// The load plan MUST supply the digest of a PNG already row-validated by the
// managed reader. This checks framing/identity/integrity, not zlib rows or trust.
globalThis.TMALTexturePacket = (() => {
    const MAX_PNG = 65536, MAX_KEY = 512, MAX_SIDE = 256;
    const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
    function utf8(bytes) {
        let output = '';
        for (let i = 0; i < bytes.length;) {
            const first = bytes[i++];
            let point, count, minimum;
            if (first < 0x80) { point = first; count = 0; minimum = 0; }
            else if (first >= 0xc2 && first <= 0xdf) { point = first & 31; count = 1; minimum = 0x80; }
            else if (first >= 0xe0 && first <= 0xef) { point = first & 15; count = 2; minimum = 0x800; }
            else if (first >= 0xf0 && first <= 0xf4) { point = first & 7; count = 3; minimum = 0x10000; }
            else throw Error('Invalid asset UTF8');
            for (let j = 0; j < count; j++) {
                if (i >= bytes.length || (bytes[i] & 0xc0) !== 0x80) throw Error('Invalid asset UTF8');
                point = point * 64 + (bytes[i++] & 63);
            }
            if (point < minimum || point > 0x10ffff || (point >= 0xd800 && point <= 0xdfff)) throw Error('Invalid asset UTF8');
            output += String.fromCodePoint(point);
        }
        return output;
    }
    function validAsset(value) {
        return typeof value === 'string' && value.includes('/') && !/[\x00-\x1f\x7f:\\]/.test(value) &&
            value.split('/').every(part => part !== '' && part !== '.' && part !== '..');
    }
    function crc(bytes, offset, count) {
        let value = 0xffffffff;
        for (let i = offset; i < offset + count; i++) {
            value ^= bytes[i];
            for (let bit = 0; bit < 8; bit++) value = (value >>> 1) ^ ((value & 1) ? 0xedb88320 : 0);
        }
        return (value ^ 0xffffffff) >>> 0;
    }
    function decode(input, plan, sha256) {
        if (!plan || !validAsset(plan.asset) ||
            !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(plan.generation) ||
            plan.generation === '00000000-0000-0000-0000-000000000000' ||
            !/^[0-9a-f]{64}$/.test(plan.archiveSha256) || !/^[0-9a-f]{64}$/.test(plan.pngSha256) || typeof sha256 !== 'function')
            throw Error('Explicit checked texture load plan required');
        if ((!Array.isArray(input) && !(input instanceof Uint8Array)) || input.length > MAX_PNG + 613 || input.length < 102)
            throw Error('Texture packet exceeds bounded receiver scope');
        if (Array.isArray(input)) {
            for (const b of input) if (!Number.isInteger(b) || b < 0 || b > 255) throw Error('Invalid packet bytes');
        }
        const bytes = new Uint8Array(input), view = new DataView(bytes.buffer);
        let offset = 0;
        const take = count => {
            if (!Number.isSafeInteger(count) || count < 0 || count > bytes.length - offset) throw Error('Truncated texture packet');
            const part = bytes.subarray(offset, offset + count); offset += count; return part;
        };
        const integer = () => { take(4); return view.getInt32(offset - 4, true); };
        if (hex(take(5)) !== '544d495401') throw Error('Unsupported texture packet');
        const keyLength = integer();
        if (keyLength < 1 || keyLength > MAX_KEY) throw Error('Asset key exceeds budget');
        const asset = utf8(take(keyLength)), guid = take(16);
        const guidHex = hex(Uint8Array.from([guid[3], guid[2], guid[1], guid[0], guid[5], guid[4], guid[7], guid[6], ...guid.subarray(8)]));
        const generation = [guidHex.slice(0, 8), guidHex.slice(8, 12), guidHex.slice(12, 16), guidHex.slice(16, 20), guidHex.slice(20)].join('-');
        const archive = hex(take(32));
        if (!validAsset(asset) || asset !== plan.asset || generation !== plan.generation || archive !== plan.archiveSha256)
            throw Error('Texture asset, archive or generation differs');
        const width = integer(), height = integer(), count = integer(), digest = hex(take(32));
        if (width < 1 || height < 1 || width > MAX_SIDE || height > MAX_SIDE || count < 57 || count > MAX_PNG || count !== bytes.length - offset)
            throw Error('Texture dimensions or PNG length exceed receiver scope');
        const png = take(count).slice(), pngView = new DataView(png.buffer);
        if (digest !== plan.pngSha256 || sha256(png.buffer) !== digest) throw Error('Texture PNG digest differs');
        if (hex(png.subarray(0, 8)) !== '89504e470d0a1a0a' || pngView.getUint32(8) !== 13 ||
            pngView.getUint32(16) !== width || pngView.getUint32(20) !== height || hex(png.subarray(24, 29)) !== '0806000000')
            throw Error('Texture PNG header differs');
        let position = 8;
        for (const kind of ['IHDR', 'IDAT', 'IEND']) {
            if (png.length - position < 12) throw Error('Truncated PNG chunk');
            const length = pngView.getUint32(position);
            if (length > png.length - position - 12 || String.fromCharCode(...png.subarray(position + 4, position + 8)) !== kind ||
                (kind === 'IEND' && length !== 0)) throw Error('Texture PNG chunk profile differs');
            if (crc(png, position + 4, length + 4) !== pngView.getUint32(position + 8 + length)) throw Error('Texture PNG CRC differs');
            position += length + 12;
        }
        if (position !== png.length) throw Error('Texture PNG trailing bytes');
        return Object.freeze({ asset, generation, archiveSha256: archive, width, height,
            copyPng: () => png.slice(), zlib_rows_checked_here: false });
    }
    return Object.freeze({ decode });
})();
