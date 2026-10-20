'use strict';
const assert = require('node:assert/strict'), fs = require('node:fs'), vm = require('node:vm');
const path = require('node:path'), crypto = require('node:crypto'), zlib = require('node:zlib');
vm.runInThisContext(fs.readFileSync(path.join(__dirname, '../runtime/texture-packet.js'), 'utf8'));
const sha = data => crypto.createHash('sha256').update(Buffer.from(data)).digest('hex');
const i32 = n => { const b = Buffer.alloc(4); b.writeInt32LE(n); return b; };
const u32 = n => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b; };
function crc(data) {
    let c = -1;
    for (const b of data) { c ^= b; for (let i = 0; i < 8; i++) c = (c >>> 1) ^ (-(c & 1) & 0xedb88320); }
    return (c ^ -1) >>> 0;
}
function chunk(kind, data) {
    const body = Buffer.concat([Buffer.from(kind), data]);
    return Buffer.concat([u32(data.length), body, u32(crc(body))]);
}
function png() {
    return Buffer.concat([Buffer.from('89504e470d0a1a0a', 'hex'),
        chunk('IHDR', Buffer.concat([u32(2), u32(2), Buffer.from([8, 6, 0, 0, 0])])),
        chunk('IDAT', zlib.deflateSync(Buffer.from([0, 1, 2, 3, 255, 40, 50, 60, 127, 0, 7, 8, 9, 0, 9, 8, 7, 1]))),
        chunk('IEND', Buffer.alloc(0))]);
}
function fixture(options = {}) {
    const key = options.key || 'Own/предмет😀.rawimg', image = options.png || png();
    const plan = { asset: key, generation: '00112233-4455-6677-8899-aabbccddeeff',
        archiveSha256: 'ab'.repeat(32), pngSha256: sha(image) };
    const keyBytes = options.keyBytes || Buffer.from(key);
    const prefix = Buffer.concat([Buffer.from('TMIT\x01'), i32(keyBytes.length), keyBytes,
        Buffer.from('33221100554477668899aabbccddeeff', 'hex'), Buffer.from(plan.archiveSha256, 'hex'),
        i32(options.width ?? 2), i32(2), i32(image.length), Buffer.from(sha(image), 'hex')]);
    return { bytes: Buffer.concat([prefix, image]), plan, offset: prefix.length, image };
}
const decode = f => TMALTexturePacket.decode(new Uint8Array(f.bytes), f.plan, sha);
let passed = 0;
function test(name, body) { body(); passed++; }
function reject(name, mutate, expression) { test(name, () => { const f = fixture(); mutate(f); assert.throws(() => decode(f), expression); }); }
test('C# GUID layout, Unicode key and image dimensions', () => {
    const f = fixture(), result = decode(f);
    assert.equal(result.generation, f.plan.generation); assert.equal(result.asset, f.plan.asset);
    assert.equal(result.width, 2); assert.equal(result.height, 2); assert.equal(result.zlib_rows_checked_here, false);
    assert.deepEqual(Buffer.from(result.copyPng()), f.image);
});
test('caller buffers cannot mutate checked PNG', () => {
    const f = fixture(), result = decode(f); f.bytes.fill(0); result.copyPng().fill(0);
    assert.deepEqual(Buffer.from(result.copyPng()), f.image); assert.equal(Object.isFrozen(result), true);
});
reject('unsupported version', f => { f.bytes[4] = 2; }, /Unsupported/);
reject('wrong asset', f => { f.plan.asset = 'Own/other.rawimg'; }, /asset, archive or generation/);
reject('stale generation', f => { f.plan.generation = '11112233-4455-6677-8899-aabbccddeeff'; }, /generation differs/);
reject('wrong archive', f => { f.plan.archiveSha256 = '12'.repeat(32); }, /archive or generation/);
reject('expected PNG digest must come from plan', f => { delete f.plan.pngSha256; }, /load plan/);
reject('wrong known PNG digest', f => { f.plan.pngSha256 = '00'.repeat(32); }, /digest/);
reject('payload corruption', f => { f.bytes[f.bytes.length - 1] ^= 1; }, /digest/);
reject('truncation', f => { f.bytes = f.bytes.subarray(0, -1); }, /PNG length/);
reject('trailing packet bytes', f => { f.bytes = Buffer.concat([f.bytes, Buffer.from([0])]); }, /PNG length/);
reject('negative declared PNG length', f => { f.bytes.writeInt32LE(-1, f.offset - 36); }, /PNG length/);
test('small receiver dimensions bounded', () => { assert.throws(() => decode(fixture({ width: 257 })), /dimensions/); });
test('PNG and transport dimensions must match', () => { assert.throws(() => decode(fixture({ width: 3 })), /header/); });
test('noncanonical key rejected', () => { assert.throws(() => decode(fixture({ key: 'Own/../item' })), /load plan/); });
test('key byte budget enforced', () => { assert.throws(() => decode(fixture({ key: 'Own/' + 'a'.repeat(510) })), /key exceeds/); });
test('malformed UTF8 rejected', () => { assert.throws(() => decode(fixture({ keyBytes: Buffer.from([79, 119, 110, 47, 0xc0, 0xaf]) })), /UTF8/); });
test('UTF8 surrogate rejected', () => { assert.throws(() => decode(fixture({ keyBytes: Buffer.from([79, 119, 110, 47, 0xed, 0xa0, 0x80]) })), /UTF8/); });
test('PNG CRC verified even when digests match plan', () => {
    const image = png(); image[image.length - 1] ^= 1;
    assert.throws(() => decode(fixture({ png: image })), /CRC/);
});
test('unexpected PNG chunk profile rejected', () => {
    const image = png(); image.write('tEXt', 37);
    assert.throws(() => decode(fixture({ png: image })), /profile/);
});
test('PNG trailing bytes rejected', () => { assert.throws(() => decode(fixture({ png: Buffer.concat([png(), Buffer.from([0])]) })), /trailing/); });
test('wire input byte range enforced', () => {
    const f = fixture(), bytes = Array.from(f.bytes); bytes[6] = 256;
    assert.throws(() => TMALTexturePacket.decode(bytes, f.plan, sha), /packet bytes/);
});
test('sparse byte arrays rejected', () => {
    const f = fixture(), bytes = Array.from(f.bytes); delete bytes[6];
    assert.throws(() => TMALTexturePacket.decode(bytes, f.plan, sha), /packet bytes/);
});
test('full input budget enforced before copy', () => {
    const f = fixture(); assert.throws(() => TMALTexturePacket.decode(new Uint8Array(66150), f.plan, sha), /bounded receiver/);
});
console.log(JSON.stringify({ native_packet_receiver_cases: passed, passed: true, zlib_rows_checked_here: false, game_execution: false }));
