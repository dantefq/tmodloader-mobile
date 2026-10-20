"""The hit-matrix gate must distinguish immunity, knockback and restoration."""
import copy
import json
import unittest
from pathlib import Path
from verify_unified_time_checkpoint import validate_matrix

ROOT=Path(__file__).resolve().parents[1]

class ProtectionCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.report=json.loads((ROOT/'reports/android-protection-matrix-validation.json').read_text('utf-8'))

    def test_actual_sessions(self):
        first=json.loads((ROOT/'reports/android-protection-matrix-first-session.json').read_text('utf-8'))
        for report in (first,self.report):self.assertEqual(validate_matrix(report,report['pid'])['hits'],10)

    def test_knockback_only_requires_positive_damage_control(self):
        row=self.report['checks'][2];row['after']['life']=100;row['healthLost']=row['returnedDamage']=0
        with self.assertRaisesRegex(ValueError,'Damage control'):validate_matrix(self.report,self.report['pid'])

    def test_full_protection_must_not_move_player(self):
        self.report['checks'][4]['after']['velocity']=[.1,0]
        with self.assertRaisesRegex(ValueError,'Knockback control'):validate_matrix(self.report,self.report['pid'])

    def test_damage_cannot_be_claimed_without_health_delta(self):
        self.report['checks'][0]['after']['life']=100
        with self.assertRaisesRegex(ValueError,'Damage control'):validate_matrix(self.report,self.report['pid'])

    def test_restore_required(self):
        self.report['checks'][0]['restored']['life']=80
        with self.assertRaisesRegex(ValueError,'Health restoration'):validate_matrix(self.report,self.report['pid'])

    def test_new_process_cannot_reuse_old_matrix(self):
        with self.assertRaisesRegex(ValueError,'process/count'):validate_matrix(self.report,self.report['pid']+1)

if __name__=='__main__':unittest.main()
