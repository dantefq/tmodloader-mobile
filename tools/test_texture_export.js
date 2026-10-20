'use strict';
const assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path');
const vm = require('node:vm'), crypto = require('node:crypto'), zlib = require('node:zlib');
for (const name of ['texture-packet', 'texture-export'])
    vm.runInThisContext(fs.readFileSync(path.join(__dirname, '../runtime/' + name + '.js'), 'utf8'));
const sha = bytes => crypto.createHash('sha256').update(Buffer.from(bytes)).digest('hex');
const i32 = n => { const bytes = Buffer.alloc(4); bytes.writeInt32LE(n); return bytes; };
const u32 = n => { const bytes = Buffer.alloc(4); bytes.writeUInt32BE(n >>> 0); return bytes; };
function chunk(kind, bytes) {
    const body = Buffer.concat([Buffer.from(kind), bytes]); let crc = -1;
    for (const b of body) { crc ^= b; for (let i = 0; i < 8; i++) crc = (crc >>> 1) ^ (-(crc & 1) & 0xedb88320); }
    return Buffer.concat([u32(bytes.length), body, u32(crc ^ -1)]);
}
function fixture(asset = 'Own/Icon.rawimg') {
    const png = Buffer.concat([Buffer.from('89504e470d0a1a0a', 'hex'),
        chunk('IHDR', Buffer.concat([u32(2), u32(2), Buffer.from([8, 6, 0, 0, 0])])),
        chunk('IDAT', zlib.deflateSync(Buffer.from([0, 1, 2, 3, 255, 40, 50, 60, 127, 0, 7, 8, 9, 0, 9, 8, 7, 1]))),
        chunk('IEND', Buffer.alloc(0))]);
    const plan = { format: 'tmal-item-texture-transfer-v1', itemType: 6196, item: 'Own/Icon', asset,
        generation: '00112233-4455-6677-8899-aabbccddeeff', archiveSha256: 'ab'.repeat(32), pngSha256: sha(png),
        transferId: '10213243-5465-7687-98a9-bacbdcedfe0f', width: 2, height: 2 };
    const bytes = Buffer.concat([Buffer.from('TMIT\x01'), i32(Buffer.byteLength(asset)), Buffer.from(asset),
        Buffer.from('33221100554477668899aabbccddeeff', 'hex'), Buffer.from(plan.archiveSha256, 'hex'),
        i32(2), i32(2), i32(png.length), Buffer.from(plan.pngSha256, 'hex'), png]);
    return { format: 'tmal-texture-export-v1', plan, packetBase64: bytes.toString('base64') };
}
const expected = { generation: fixture().plan.generation, itemType: 6196, item: 'Own/Icon' };
const decode = (value, wanted = expected) => TMALTextureExport.decode(JSON.stringify(value), wanted, sha);
let passed = 0;
function test(name, run) { try { run(); passed++; } catch (error) { error.message = name + ': ' + error.message; throw error; } }
test('own export accepted', () => assert.equal(decode(fixture()).image.width, 2));
test('copies and plan immutable', () => {
    const value = decode(fixture()); value.copyPacket()[0] = 0;
    assert.equal(value.copyPacket()[0], 84); assert.throws(() => { value.plan.itemType = 1; }, TypeError);
});
for (const [name, key, value] of [['generation', 'generation', 'ffffffff-ffff-ffff-ffff-ffffffffffff'],
    ['item ID', 'itemType', 6197], ['item identity', 'item', 'Other/Icon']])
    test('foreign ' + name, () => { const f = fixture(); f.plan[key] = value; assert.throws(() => decode(f), /owner/); });
test('expected owner required', () => assert.throws(() => decode(fixture(), {}), /Expected/));
test('missing transfer rejected', () => { const f = fixture(); delete f.plan.transferId; assert.throws(() => decode(f), /transfer/); });
test('zero transfer rejected', () => { const f = fixture(); f.plan.transferId = '00000000-0000-0000-0000-000000000000'; assert.throws(() => decode(f), /transfer/); });
test('uppercase transfer rejected', () => { const f = fixture(); f.plan.transferId = f.plan.transferId.toUpperCase(); assert.throws(() => decode(f), /transfer/); });
test('export format rejected', () => { const f = fixture(); f.format = 'other'; assert.throws(() => decode(f), /owner/); });
test('plan format rejected', () => { const f = fixture(); f.plan.format = 'other'; assert.throws(() => decode(f), /owner/); });
test('plan dimensions checked', () => { const f = fixture(); f.plan.width = 3; assert.throws(() => decode(f), /dimensions/); });
test('Base64 whitespace rejected', () => { const f = fixture(); f.packetBase64 += '\n'; assert.throws(() => decode(f), /Base64/); });
test('Base64 padding bits checked', () => {
    let f = fixture(), suffix = '';
    while (!f.packetBase64.endsWith('==')) { suffix += 'x'; f = fixture('Own/Icon' + suffix + '.rawimg'); }
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const at = f.packetBase64.length - 3, n = alphabet.indexOf(f.packetBase64[at]);
    f.packetBase64 = f.packetBase64.slice(0, at) + alphabet[n + 1] + '==';
    assert.throws(() => decode(f), /Noncanonical/);
});
test('damaged packet rejected', () => { const f = fixture(), b = Buffer.from(f.packetBase64, 'base64'); b[b.length - 1] ^= 1; f.packetBase64 = b.toString('base64'); assert.throws(() => decode(f), /digest/); });
test('oversized packet rejected before allocation', () => { const f = fixture(); f.packetBase64 = 'A'.repeat(88200); assert.throws(() => decode(f), /budget|Base64/); });
test('oversized envelope rejected', () => assert.throws(() => TMALTextureExport.decode(' '.repeat(94209), expected, sha), /budget/));
test('malformed JSON rejected', () => assert.throws(() => TMALTextureExport.decode('{', expected, sha), SyntaxError));
console.log(JSON.stringify({ texture_export_cases: passed, passed: true, native_graphics_executed: false }));
