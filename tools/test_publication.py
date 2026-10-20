"""Regression checks for private-evidence and sensitive-artifact rejection."""
import unittest
from check_publication import validate


class PublicationTests(unittest.TestCase):
    def test_public_source_and_summary(self):
        validate('runtime/demo.js', b'const example = 1;')
        validate('reports/public-validation-summary.json', b'{"scope":"prototype"}')

    def test_private_evidence_and_binaries(self):
        for name in ('notes/lab.md', 'reports/device.json', '.tools/runtime.js',
                     '../outside.md', '/absolute.md', 'build/game.apk',
                     'managed/mod.dll', 'saves/player.plr', 'key.pk8'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate(name, b'example')

    def test_identifiers_paths_and_keys(self):
        examples = ['C:' + '/Users/example/private/file', 'R58' + 'ABC12345',
                    '-----BEGIN ' + 'PRIVATE KEY-----', 'ghp_' + 'x' * 36]
        for example in examples:
            with self.subTest(example=example), self.assertRaises(ValueError):
                validate('README.md', example.encode())


if __name__ == '__main__':
    unittest.main()
