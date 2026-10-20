'use strict';
const assert = require('node:assert/strict'), fs = require('node:fs'), vm = require('node:vm'), path = require('node:path');
vm.runInThisContext(fs.readFileSync(path.join(__dirname, '../runtime/content-table-lease.js'), 'utf8'));
let passed = 0;
function test(name, body) { body(); passed++; }
function fixture(writer) {
    const rows = ['a', 'b', 'c'].map(key => ({ key, original: [key], replacement: [key, 'lab'] }));
    const fields = new Map(rows.map(r => [r.key, r.original]));
    let generation = 'one', allowed = true, writes = 0;
    const adapter = { equal: (a, b) => a === b, generation: () => generation,
        assertContext() { if (!allowed) throw Error('Wrong thread'); }, read: key => fields.get(key),
        write(key, value) { writes++; if (writer) writer(fields, key, value, writes); else fields.set(key, value); } };
    const lease = TMALContentTableLease(adapter, 'one', rows);
    return { rows, fields, lease, adapter, writes: () => writes,
        generation(value) { generation = value; }, allow(value) { allowed = value; } };
}
test('publish all then restore without changing either array', () => {
    const f = fixture(); f.lease.install();
    for (const r of f.rows) assert.equal(f.fields.get(r.key), r.replacement);
    assert.equal(f.lease.release(), true); assert.equal(f.lease.release(), false);
    for (const r of f.rows) { assert.equal(f.fields.get(r.key), r.original); assert.deepEqual(r.original, [r.key]); }
    assert.equal(f.lease.status().resources_must_be_retained, false);
    assert.throws(() => f.lease.install(), /single-use/);
});
test('late mismatched baseline rejects before first write', () => {
    const f = fixture(); f.fields.set('c', []); assert.throws(() => f.lease.install(), /baseline/); assert.equal(f.writes(), 0);
});
test('partial publication throw restores attempted rows', () => {
    const f = fixture((m, k, v, n) => { m.set(k, v); if (n === 2) throw Error('Partial publish'); });
    assert.throws(() => f.lease.install(), /Partial publish/);
    for (const r of f.rows) assert.equal(f.fields.get(r.key), r.original);
    assert.equal(f.lease.status().unresolved_rows, 0);
});
test('silent writer rejected and earlier publication undone', () => {
    const f = fixture((m, k, v, n) => { if (n !== 2) m.set(k, v); });
    assert.throws(() => f.lease.install(), /publication not observed/);
    for (const r of f.rows) assert.equal(f.fields.get(r.key), r.original);
});
test('foreign row preserved while independent owned rows restored', () => {
    const f = fixture(), foreign = []; f.lease.install(); f.fields.set('b', foreign);
    assert.throws(() => f.lease.release(), /another owner/);
    assert.equal(f.fields.get('b'), foreign); assert.equal(f.fields.get('a'), f.rows[0].original);
    assert.equal(f.fields.get('c'), f.rows[2].original); assert.equal(f.lease.status().unresolved_rows, 1);
    f.fields.set('b', f.rows[1].replacement); f.lease.release();
});
test('generation change blocks rollback and retains resources', () => {
    const f = fixture(); f.lease.install(); f.generation('two');
    assert.throws(() => f.lease.release(), /generation/); assert.equal(f.writes(), 3);
    assert.equal(f.lease.status().unresolved_rows, 3); f.generation('one'); f.lease.release();
});
test('stale install makes no writes', () => {
    const f = fixture(); f.generation('two'); assert.throws(() => f.lease.install(), /generation/); assert.equal(f.writes(), 0);
});
test('thread guard protects install and restore', () => {
    const f = fixture(); f.allow(false); assert.throws(() => f.lease.install(), /thread/); assert.equal(f.writes(), 0);
    const g = fixture(); g.lease.install(); g.allow(false); assert.throws(() => g.lease.release(), /thread/);
    assert.equal(g.writes(), 3); g.allow(true); g.lease.release();
});
test('failed rollback row can be retried', () => {
    const f = fixture((m, k, v, n) => { if (n === 4) throw Error('Rollback fault'); m.set(k, v); });
    f.lease.install(); assert.throws(() => f.lease.release(), /Rollback fault/);
    assert.equal(f.lease.status().unresolved_rows, 1); f.lease.release(); assert.equal(f.lease.status().unresolved_rows, 0);
});
test('writer throwing after restoration still safely recoverable', () => {
    const f = fixture((m, k, v, n) => { m.set(k, v); if (n === 4) throw Error('After write'); });
    f.lease.install(); assert.throws(() => f.lease.release(), /After write/); f.lease.release();
    assert.equal(f.lease.status().resources_must_be_retained, false);
});
test('lost ownership during publish is surfaced for recovery', () => {
    const foreign = [], f = fixture((m, k, v, n) => m.set(k, n === 2 ? foreign : v));
    assert.throws(() => f.lease.install(), /recovery required/); assert.equal(f.fields.get('b'), foreign);
    assert.equal(f.fields.get('a'), f.rows[0].original); assert.equal(f.lease.status().unresolved_rows, 1);
});
test('row requests copied before caller mutation', () => {
    const f = fixture(), original = f.rows[0].original; f.rows[0].original = []; f.rows[0].key = 'other';
    f.lease.install(); f.lease.release(); assert.equal(f.fields.get('a'), original);
});
test('duplicate or empty table sets rejected', () => {
    const f = fixture(); assert.throws(() => TMALContentTableLease(f.adapter, 'one', []), /Invalid/);
    assert.throws(() => TMALContentTableLease(f.adapter, 'one', [f.rows[0], f.rows[0]]), /duplicate/);
});
console.log(JSON.stringify({ content_table_lease_cases: passed, passed: true, game_execution: false }));
