"""Historical evidence must reject artifact substitution without freezing source."""
import copy
import json
import unittest
from pathlib import Path
from verify_sleep_observer import CHECKPOINT_SCRIPT, validate_artifact

ROOT=Path(__file__).resolve().parents[1]

class ObserverArtifactTests(unittest.TestCase):
    def setUp(self):
        self.manifest=json.loads((ROOT/'reports/sleep-observer-validation.json').read_text('utf-8'))['installed_companion']
        self.build=json.loads((ROOT/'reports/sleep-companion-build.json').read_text('utf-8'))

    def test_later_source_does_not_rewrite_historical_evidence(self):
        report=validate_artifact(self.manifest,self.build,'0'*64)
        self.assertFalse(report['current_source_matches_checkpoint'])
        self.assertTrue(validate_artifact(self.manifest,self.build,CHECKPOINT_SCRIPT,True)['current_source_matches_checkpoint'])

    def test_strict_source_mode_rejects_later_source(self):
        with self.assertRaisesRegex(ValueError,'current source'):
            validate_artifact(self.manifest,self.build,'0'*64,True)

    def test_substituted_apk_rejected_even_with_matching_build(self):
        manifest=copy.deepcopy(self.manifest);build=copy.deepcopy(self.build)
        manifest['output_sha256']=build['output_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'checkpoint'):
            validate_artifact(manifest,build,CHECKPOINT_SCRIPT)

    def test_substituted_script_rejected(self):
        manifest=copy.deepcopy(self.manifest);manifest['runtime_script_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'script'):
            validate_artifact(manifest,self.build,'0'*64)

    def test_original_dll_identity_required(self):
        manifest=copy.deepcopy(self.manifest);build=copy.deepcopy(self.build)
        manifest['own_api_bundle_files']['ChangeSleepTime.dll']='0'*64
        build['own_api_bundle_files']=manifest['own_api_bundle_files'].copy()
        with self.assertRaisesRegex(ValueError,'Original mod DLL'):
            validate_artifact(manifest,build,CHECKPOINT_SCRIPT)

if __name__=='__main__':unittest.main()
