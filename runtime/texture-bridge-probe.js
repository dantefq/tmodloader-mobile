'use strict';
// Isolated app, fixed lab profiles only. GPU teardown ACKs below are explicitly
// simulated: this probe does not allocate or install native game resources.
rpc.exports = {
    initialize(root, profile = 'own-2x2') {
        globalThis.TMALMonoTexture.initialize(root);
        return JSON.parse(globalThis.TMALMonoTexture.request({ operation: 'initialize', profile }));
    },
    request(value) { return globalThis.TMALMonoTexture.request(value); },
    checkexport(text, expected) {
        const decoded = globalThis.TMALTextureExport.decode(text, expected, bytes => Checksum.compute('sha256', bytes));
        return { transferId: decoded.plan.transferId, generation: decoded.plan.generation,
            width: decoded.image.width, height: decoded.image.height };
    },
    run(root, profile = 'own-2x2') {
        const transcript = [], check = (value, message) => { if (!value) throw Error(message); };
        const request = value => {
            const raw = globalThis.TMALMonoTexture.request(value), parsed = JSON.parse(raw);
            transcript.push({ operation: value.operation, response: parsed });
            return { raw, parsed };
        };
        const reject = (value, error) => check(request(value).parsed.error === error, 'Expected managed rejection: ' + error);
        globalThis.TMALMonoTexture.initialize(root);
        const description = request({ operation: 'initialize', profile }).parsed;
        check(description.format === 'tmal-texture-bridge-v1' && description.pending === 0, 'Bridge initialization differs');
        const pinned = profile === 'sots-helicopterparts';
        check(profile === 'own-2x2' || pinned, 'Unknown fixed profile');
        check(description.profile === profile && description.profileChecks === 4, 'Managed profile guards differ');
        const expected = { generation: description.generation, itemType: 6196, item: pinned ? 'TextureBindingLab/Preview' : 'TextureBridgeLab/Icon' };
        const first = request({ operation: 'begin' });
        const sha = bytes => Checksum.compute('sha256', bytes);
        const decoded = globalThis.TMALTextureExport.decode(first.raw, expected, sha), id = decoded.plan.transferId;
        check(decoded.image.width === (pinned ? 44 : 2) && decoded.image.height === (pinned ? 34 : 2), 'Fixture dimensions differ');
        reject({ operation: 'begin' }, 'InvalidOperationException');
        reject({ operation: 'unload' }, 'InvalidOperationException');
        reject({ operation: 'ack', transferId: 'bad' }, 'ArgumentException');
        reject({ operation: 'ack', transferId: 'ffffffff-ffff-ffff-ffff-ffffffffffff' }, 'InvalidOperationException');
        const gc = request({ operation: 'gc' }).parsed;
        check(gc.bytes === 16777216 && gc.generation === expected.generation, 'Post-GC owner differs');
        check(request({ operation: 'read', transferId: id }).raw === first.raw, 'Post-GC export changed');
        check(request({ operation: 'ack', transferId: id }).parsed.pending === 0, 'Simulated ACK failed');
        reject({ operation: 'read', transferId: id }, 'InvalidOperationException');
        const next = request({ operation: 'begin' });
        const second = globalThis.TMALTextureExport.decode(next.raw, expected, sha);
        check(second.plan.transferId !== id, 'Transfer correlation did not change');
        reject({ operation: 'ack', transferId: id }, 'InvalidOperationException');
        reject({ operation: 'unload' }, 'InvalidOperationException');
        check(request({ operation: 'ack', transferId: second.plan.transferId }).parsed.pending === 0, 'Second simulated ACK failed');
        const unloaded = request({ operation: 'unload' }).parsed;
        check(unloaded.status === 'unloaded' && unloaded.pending === 0 && unloaded.cacheBytes === 0 && unloaded.hostChecks > 0,
            'Registry unload differs');
        reject({ operation: 'read', transferId: second.plan.transferId }, 'InvalidOperationException');
        reject({ operation: 'begin' }, 'InvalidOperationException');
        return { format: 'tmal-android-texture-bridge-probe-v1', status: 'passed', transcript,
            host_checks: unloaded.hostChecks, gc_bytes: gc.bytes, native_graphics_executed: false,
            resource_profile: profile, profile_checks: unloaded.profileChecks, pinned_original_texture_used: pinned,
            native_teardown_acknowledgements_simulated: true, original_mod_code_executed: false,
            game_files_accessed: false, packet_receiver_executed: true };
    }
};
