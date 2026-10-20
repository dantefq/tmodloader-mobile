"""Host-mocked controller lifetime tests; never pauses or attaches to a device."""
import unittest
from device_texture_teardown import teardown


class Script:
    def __init__(self, states, error=False, destroyed=False):
        self.states = list(states); self.error = error; self.is_destroyed = destroyed
        self.actions = []; self.exports_sync = self

    def status(self):
        if self.error:
            raise RuntimeError('Lost status transport')
        phase = self.states.pop(0) if len(self.states) > 1 else self.states[0]
        return {'phase': phase}

    def cancel(self): self.actions.append('cancel')
    def retrycleanup(self): self.actions.append('retry')
    def unload(self): self.actions.append('unload')
    def eternalize(self): self.actions.append('retain')


class ControllerTests(unittest.TestCase):
    def run_teardown(self, script, wait=4):
        tick = iter(range(100))
        return teardown(script, max_wait=wait, clock=lambda: next(tick), sleep=lambda _: None)

    def test_complete_unloads(self):
        script = Script(['complete']); result = self.run_teardown(script)
        self.assertEqual(script.actions, ['unload']); self.assertTrue(result['teardown_complete'])

    def test_idle_unloads(self):
        script = Script(['idle']); self.run_teardown(script)
        self.assertEqual(script.actions, ['unload'])

    def test_cancel_then_clean_failure_unloads(self):
        script = Script(['private-slot-held', 'cleanup', 'failed']); result = self.run_teardown(script)
        self.assertEqual(script.actions, ['cancel', 'unload']); self.assertTrue(result['teardown_complete'])

    def test_retry_then_complete(self):
        script = Script(['cleanup-failed', 'cleanup-failed', 'complete']); result = self.run_teardown(script)
        self.assertEqual(script.actions, ['cancel', 'retry', 'unload']); self.assertTrue(result['teardown_complete'])

    def test_paused_cleanup_retains_controller(self):
        script = Script(['private-slot-held']); result = self.run_teardown(script, wait=0)
        self.assertEqual(script.actions, ['cancel', 'retain']); self.assertTrue(result['controller_retained'])
        self.assertFalse(result['teardown_complete'])

    def test_failed_cleanup_queued_before_retaining(self):
        script = Script(['cleanup-failed']); result = self.run_teardown(script, wait=0)
        self.assertEqual(script.actions, ['cancel', 'retry', 'retain']); self.assertFalse(result['teardown_complete'])

    def test_uncertain_transport_preserves_live_controller(self):
        script = Script([], error=True); result = self.run_teardown(script)
        self.assertEqual(script.actions, ['retain']); self.assertTrue(result['teardown_errors'])
        self.assertFalse(result['teardown_complete'])

    def test_destroyed_script_is_not_treated_as_cleanup(self):
        script = Script([], error=True, destroyed=True); result = self.run_teardown(script)
        self.assertEqual(script.actions, []); self.assertFalse(result['teardown_complete'])

    def test_malformed_status_preserves_controller(self):
        script = Script(['unused']); script.status = lambda: None
        result = self.run_teardown(script)
        self.assertEqual(script.actions, ['retain']); self.assertEqual(result['phase'], 'unknown')
        self.assertFalse(result['teardown_complete'])


if __name__ == '__main__':
    unittest.main()
