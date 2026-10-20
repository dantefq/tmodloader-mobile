'use strict';
// Transaction over static array references, not their contents. Callers own GC
// roots and must serialize writers/consumers until every published row is back.
globalThis.TMALContentTableLease = function (adapter, generation, input) {
    if (typeof generation !== 'string' || !generation || !Array.isArray(input) || input.length < 1 || input.length > 256)
        throw Error('Invalid content-table lease');
    const keys = new Set();
    const rows = input.map(row => {
        if (typeof row.key !== 'string' || !row.key || keys.has(row.key) || adapter.equal(row.original, row.replacement))
            throw Error('Invalid or duplicate content-table row');
        keys.add(row.key);
        return Object.freeze({ key: row.key, original: row.original, replacement: row.replacement });
    });
    let state = 'idle';
    const held = new Set();
    function context() {
        adapter.assertContext();
        if (adapter.generation() !== generation) throw Error('Content-table generation differs');
    }
    function release() {
        if (held.size === 0) return false;
        try { context(); } catch (error) { state = 'unresolved'; throw error; }
        const errors = [];
        for (const row of [...rows].reverse()) {
            if (!held.has(row)) continue;
            try {
                const value = adapter.read(row.key);
                if (!adapter.equal(value, row.original)) {
                    if (!adapter.equal(value, row.replacement)) throw Error('Content table has another owner: ' + row.key);
                    adapter.write(row.key, row.original);
                }
                if (!adapter.equal(adapter.read(row.key), row.original)) throw Error('Content-table restoration not observed: ' + row.key);
                held.delete(row);
            } catch (error) { errors.push(String(error)); }
        }
        if (errors.length) { state = 'unresolved'; throw Error(errors.join('; ')); }
        state = 'restored'; return true;
    }
    return Object.freeze({
        install() {
            if (state !== 'idle') throw Error('Content-table lease is single-use');
            try {
                context();
                // Validate ALL baselines before publishing the first reference.
                for (const row of rows)
                    if (!adapter.equal(adapter.read(row.key), row.original)) throw Error('Content-table baseline differs: ' + row.key);
                state = 'publishing';
                for (const row of rows) {
                    held.add(row); // A throwing writer may already have changed it.
                    adapter.write(row.key, row.replacement);
                    if (!adapter.equal(adapter.read(row.key), row.replacement)) throw Error('Content-table publication not observed: ' + row.key);
                }
                state = 'installed';
            } catch (error) {
                if (held.size) {
                    try { release(); }
                    catch (cleanup) { throw Error(String(error) + '; recovery required: ' + String(cleanup)); }
                } else state = 'rejected';
                throw error;
            }
        },
        release,
        status: () => ({ state, resources_must_be_retained: held.size !== 0, unresolved_rows: held.size })
    });
};
