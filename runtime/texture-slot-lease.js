'use strict';
// Synchronous, single-use reference lease. The adapter must serialize writers on
// the game thread and keep table/original/replacement GC-rooted through release.
// An unresolved lease must retain its roots and resources for explicit recovery.
globalThis.TMALTextureSlotLease = function (adapter, request) {
    const { generation, index, expected, replacement } = request;
    if (typeof generation !== 'string' || generation.length === 0 ||
        !Number.isSafeInteger(index) || index < 0 || adapter.equal(expected, replacement))
        throw Error('Invalid texture lease request');
    let state = 'idle', table = null, held = false;
    function context() {
        adapter.assertContext();
        const current = adapter.snapshot();
        if (current.generation !== generation || !Number.isSafeInteger(current.length) || index >= current.length)
            throw Error('Texture lease generation or bounds differ');
        if (held && !adapter.equal(current.table, table)) throw Error('Texture lease table was replaced');
        return current;
    }
    function release() {
        if (!held) return false;
        try {
            context();
            const value = adapter.read(table, index);
            if (!adapter.equal(value, expected)) {
                if (!adapter.equal(value, replacement)) throw Error('Texture lease slot has another owner');
                adapter.write(table, index, expected);
            }
            if (!adapter.equal(adapter.read(table, index), expected)) throw Error('Texture lease restoration not observed');
            held = false; state = 'restored'; return true;
        } catch (error) { state = 'unresolved'; throw error; }
    }
    return Object.freeze({
        install() {
            if (state !== 'idle') throw Error('Texture lease is single-use');
            try {
                const current = context();
                if (!adapter.equal(adapter.read(current.table, index), expected)) throw Error('Texture lease baseline differs');
                table = current.table; held = true; state = 'installing';
                adapter.write(table, index, replacement);
                if (!adapter.equal(adapter.read(table, index), replacement)) throw Error('Texture lease installation not observed');
                state = 'installed';
            } catch (error) {
                if (held) {
                    try { release(); }
                    catch (cleanup) { throw Error(String(error) + '; recovery required: ' + String(cleanup)); }
                } else state = 'rejected';
                throw error;
            }
        },
        release,
        status: () => ({ state, resources_must_be_retained: held })
    });
};
