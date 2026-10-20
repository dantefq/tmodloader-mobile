"""Keep a pending game-thread cleanup controller alive across client detach.

Only terminal native states permit script unload. Deferred/uncertain cleanup is
retained in the target when possible; that is recovery state, never a test pass.
"""
import time

TERMINAL = {'idle', 'complete', 'failed'}


def teardown(script, max_wait=4, clock=time.monotonic, sleep=time.sleep):
    final = {'phase': 'unknown'}
    errors = []
    retained = False
    def status():
        value = script.exports_sync.status()
        if not isinstance(value, dict) or not isinstance(value.get('phase'), str):
            raise RuntimeError('Invalid native cleanup status')
        return value
    try:
        final = status()
        if final['phase'] not in TERMINAL:
            script.exports_sync.cancel()
            deadline = clock() + max_wait
            retries = 0
            while clock() < deadline:
                final = status()
                if final['phase'] in TERMINAL:
                    break
                if final['phase'] == 'cleanup-failed' and retries < 3:
                    script.exports_sync.retrycleanup(); retries += 1
                sleep(0.1)
            final = status()
        if final['phase'] in TERMINAL:
            script.unload()
        else:
            if final['phase'] == 'cleanup-failed':
                script.exports_sync.retrycleanup()
            # A paused Draw loop may resume after the host disconnects. Preserve
            # the closure holding original references and GC handles until then.
            script.eternalize(); retained = True
    except Exception as error:
        errors.append(str(error))
        # Do not deliberately discard ownership information on an uncertain
        # transport failure. A destroyed script cannot be retained again.
        try:
            if not script.is_destroyed:
                script.eternalize(); retained = True
        except Exception as retention_error:
            errors.append(str(retention_error))
    return {**final, 'controller_retained': retained, 'teardown_complete': final['phase'] in TERMINAL and not errors,
            'teardown_errors': errors}
