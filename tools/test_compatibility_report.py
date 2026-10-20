"""Ensure compatibility diagnostics cannot silently join different artifacts."""
import copy
import json
from pathlib import Path
import unittest
from build_compatibility_report import join


class CompatibilityReportTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1]/'reports'
        self.inputs = [json.loads((root/name).read_text('utf-8')) for name in (
            'unified-small-mod-load-plan.json','small-mod-signatures.json','small-mod-time-signatures.json')]

    def test_current_artifacts_are_diagnostics_only(self):
        report = join(*self.inputs)
        self.assertEqual(len(report['candidates']),8)
        self.assertFalse(any(r['general_loader_launch_allowed'] for r in report['candidates']))
        self.assertEqual([r['name'] for r in report['candidates'] if r['audited_route']],['ChangeSleepTime'])

    def test_tmod_hash_mismatch_rejected(self):
        self.inputs[1]['candidates'][0]['tmod_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'identity differs'):
            join(*self.inputs)

    def test_time_dll_mismatch_rejected(self):
        self.inputs[2]['candidates'][0]['assembly_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'identity differs'):
            join(*self.inputs)

    def test_loader_version_mismatch_rejected(self):
        self.inputs[1]['candidates'][0]['loader']='999.0'
        with self.assertRaisesRegex(ValueError,'identity differs'):
            join(*self.inputs)

    def test_invalid_dependency_plan_rejected(self):
        self.inputs[0]['valid']=False
        with self.assertRaisesRegex(ValueError,'Dependency plan'):
            join(*self.inputs)

    def test_unresolved_sleep_override_removes_narrow_route(self):
        row=next(r for r in self.inputs[2]['candidates'] if r['mod']=='ChangeSleepTime')
        row['override_counts']={'unsupported':1}
        self.assertFalse(any(r['audited_route'] for r in join(*self.inputs)['candidates']))


if __name__=='__main__':
    unittest.main()
