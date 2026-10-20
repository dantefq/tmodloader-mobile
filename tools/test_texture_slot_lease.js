'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
vm.runInThisContext(fs.readFileSync(path.join(__dirname, '../runtime/texture-slot-lease.js'), 'utf8'));
let passed = 0;
function test(name, body) { body(); passed++; }
function fixture(options = {}) {
    const original = {}, replacement = {}, table = [original];
    const current = { generation: 'first', table, length: 1 };
    let writes = 0, contextAllowed = true;
    const adapter = {
        assertContext() { if (!contextAllowed) throw Error('Not on authorized thread/menu'); },
        snapshot: () => ({ ...current }), equal: (a, b) => a === b,
        read: (t, i) => t[i],
        write(t, i, v) { writes++; if (options.write) options.write(t, i, v, writes); else t[i] = v; }
    };
    const lease = TMALTextureSlotLease(adapter, { generation: 'first', index: 0, expected: original, replacement });
    return { original, replacement, table, current, adapter, lease, writes: () => writes,
        forbidContext() { contextAllowed = false; }, allowContext() { contextAllowed = true; } };
}
test('install, restore, repeated release and replay rejection', () => {
    const f = fixture(); f.lease.install(); assert.equal(f.table[0], f.replacement);
    assert.deepEqual(f.lease.status(), { state: 'installed', resources_must_be_retained: true });
    assert.equal(f.lease.release(), true); assert.equal(f.table[0], f.original);
    assert.equal(f.lease.release(), false); assert.throws(() => f.lease.install(), /single-use/);
});
test('stale generation makes no write', () => {
    const f = fixture(); f.current.generation = 'second';
    assert.throws(() => f.lease.install(), /generation/); assert.equal(f.writes(), 0);
});
test('bounds checked before write', () => {
    const f = fixture(); f.current.length = 0;
    assert.throws(() => f.lease.install(), /bounds/); assert.equal(f.writes(), 0);
});
test('unowned baseline makes no write', () => {
    const f = fixture(), foreign = {}; f.table[0] = foreign;
    assert.throws(() => f.lease.install(), /baseline/); assert.equal(f.writes(), 0); assert.equal(f.table[0], foreign);
});
test('partial installation throw restores original', () => {
    const f = fixture({ write(t, i, v, n) { t[i] = v; if (n === 1) throw Error('Partial write'); } });
    assert.throws(() => f.lease.install(), /Partial write/); assert.equal(f.table[0], f.original);
    assert.equal(f.lease.status().resources_must_be_retained, false);
});
test('silent installation failure is rejected', () => {
    const f = fixture({ write() {} }); assert.throws(() => f.lease.install(), /installation not observed/);
    assert.equal(f.table[0], f.original); assert.equal(f.lease.status().state, 'restored');
});
test('foreign writer is preserved and roots retained', () => {
    const f = fixture(), foreign = {}; f.lease.install(); f.table[0] = foreign;
    assert.throws(() => f.lease.release(), /another owner/); assert.equal(f.table[0], foreign);
    assert.equal(f.lease.status().resources_must_be_retained, true);
    f.table[0] = f.replacement; f.lease.release(); assert.equal(f.table[0], f.original);
});
test('table replacement prevents a stale rollback', () => {
    const f = fixture(); f.lease.install(); f.current.table = [{}];
    assert.throws(() => f.lease.release(), /table was replaced/); assert.equal(f.table[0], f.replacement);
    f.current.table = f.table; f.lease.release(); assert.equal(f.table[0], f.original);
});
test('generation rollover prevents a stale rollback', () => {
    const f = fixture(); f.lease.install(); f.current.generation = 'second';
    assert.throws(() => f.lease.release(), /generation/); assert.equal(f.writes(), 1);
    f.current.generation = 'first'; f.lease.release();
});
test('failed rollback can be retried without freeing resources', () => {
    const f = fixture({ write(t, i, v, n) { if (n === 2) throw Error('Retry rollback'); t[i] = v; } });
    f.lease.install(); assert.throws(() => f.lease.release(), /Retry rollback/);
    assert.equal(f.lease.status().resources_must_be_retained, true); f.lease.release();
    assert.equal(f.table[0], f.original);
});
test('thread/menu guard protects installation and rollback', () => {
    const f = fixture(); f.forbidContext(); assert.throws(() => f.lease.install(), /authorized/); assert.equal(f.writes(), 0);
    const g = fixture(); g.lease.install(); g.forbidContext();
    assert.throws(() => g.lease.release(), /authorized/); assert.equal(g.writes(), 1);
    g.allowContext(); g.lease.release();
});
test('lost ownership during installation is not overwritten', () => {
    const foreign = {}, f = fixture({ write(t, i) { t[i] = foreign; } });
    assert.throws(() => f.lease.install(), /recovery required/); assert.equal(f.table[0], foreign);
    assert.equal(f.lease.status().resources_must_be_retained, true);
});
console.log(JSON.stringify({ texture_slot_lease_cases: passed, passed: true, game_execution: false }));
