"""Ensure incomplete or unsafe regression logs cannot become a verified report."""
import unittest
from verify_unified_checkpoint import parse_events, validate_events


def fixture():
    ready = ['UNIFIED_API_READY managed-foundation-v1', 'HOOK_READY', 'SIDECAR_READY']
    commit = lambda g, enabled: f'SIDECAR_COMMITTED generation={g} key=PcModItemDemo/TestBlade slot=0 serialized=90 customSerialized=0 enabled={enabled}'
    restore = lambda g: f'SIDECAR_RESTORED generation={g} key=PcModItemDemo/TestBlade id=6196 damage=37'
    first = ready + ['MODITEM_ACTUAL_USE id=6196 damage=37',
                     'MODITEM_WEAPON_DAMAGE input=37 actual=37 usingItem=true', commit(15, 'true')]
    final = ready + [restore(15), commit(16, 'true'), 'Managed demo enabled=false',
                     commit(17, 'false'), commit(18, 'false'),
                     'SIDECAR_LOAD_VALID generation=18 key=PcModItemDemo/TestBlade known=true',
                     'Managed demo enabled=true', restore(18), commit(19, 'true')]
    def rows(messages, pid, minute):
        return parse_events('\n'.join(f'10-10 22:{minute}:{i:02}.000 {pid} 3 I TMAL : {m}'
                                      for i, m in enumerate(messages)))
    return rows(first, 100, '10'), rows(final, 200, '20')


class CheckpointTests(unittest.TestCase):
    def test_noninitial_generations_and_autosaves(self):
        report = validate_events(*fixture())
        self.assertEqual([r['generation'] for r in report['commits']], [15, 16, 17, 18, 19])

    def test_rejects_same_process(self):
        first, final = fixture()
        for row in final:
            row['pid'] = 100
        with self.assertRaisesRegex(ValueError, 'restart absent'):
            validate_events(first, final)

    def test_rejects_unsafe_serialization(self):
        first, final = fixture()
        final[-1]['message'] = final[-1]['message'].replace('customSerialized=0', 'customSerialized=1')
        with self.assertRaisesRegex(ValueError, 'serialization'):
            validate_events(first, final)

    def test_rejects_missing_restart_restore(self):
        first, final = fixture()
        final = [r for r in final if 'RESTORED generation=15' not in r['message']]
        with self.assertRaisesRegex(ValueError, 'automatically restored'):
            validate_events(first, final)

    def test_rejects_missing_commit_and_loader_errors(self):
        first, final = fixture()
        for changed in (final[:4] + final[5:], final + [dict(final[-1], message='SIDECAR_COMMIT_FAILED disk full')]):
            with self.assertRaises(ValueError):
                validate_events(first, changed)

    def test_rejects_no_reenable_restore(self):
        first, final = fixture()
        final = [r for r in final if 'RESTORED generation=18' not in r['message']]
        with self.assertRaisesRegex(ValueError, 'Disabled data not restored'):
            validate_events(first, final)


if __name__ == '__main__':
    unittest.main()
