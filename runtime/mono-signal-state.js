'use strict';
// Read-only Android ARM64 diagnostic. Bionic LP64 sigaction has flags at 0
// and handler at 8; retain raw details only in private runtime evidence.
rpc.exports = {
    state() {
        if (Process.arch !== 'arm64' || Process.pointerSize !== 8 || Process.platform !== 'linux')
            throw Error('Android ARM64 signal diagnostic required');
        const libc = Process.getModuleByName('libc.so');
        const sigaction = new NativeFunction(libc.getExportByName('sigaction'), 'int', ['int', 'pointer', 'pointer']);
        const mono = Process.getModuleByName('libmonosgen-2.0.so');
        const domain = new NativeFunction(mono.getExportByName('mono_get_root_domain'), 'pointer', [])();
        return {
            mono_initialized: !domain.isNull(),
            unity_loaded: Process.findModuleByName('libil2cpp.so') !== null,
            signals: [21, 24, 30].map(signal => {
                const value = Memory.alloc(256);
                if (sigaction(signal, ptr(0), value) !== 0) throw Error('Cannot read signal disposition');
                const handler = value.add(8).readPointer(), owner = Process.findModuleByAddress(handler);
                return {signal, flags: value.readU32(), owner: owner ? owner.name : null,
                    handler_offset: owner ? handler.sub(owner.base).toString() : handler.toString()};
            })
        };
    }
};
