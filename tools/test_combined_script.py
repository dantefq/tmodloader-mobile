"""Verify combined script composition and lexical/module startup ordering."""
import subprocess
import unittest
from pathlib import Path
from companion_script import combined_script

ROOT = Path(__file__).resolve().parents[1]


class CombinedScriptTests(unittest.TestCase):
    def test_syntax_and_order(self):
        script = combined_script(ROOT).decode()
        result = subprocess.run(['C:/Program Files/nodejs/node.exe', '--check'],
                                input=script, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        names = ['mono-runtime.js', 'managed-time-host.js', 'managed-host.js',
                 'sleep-scene.js', 'time-loader.js', 'loader.js', 'save-trace.js',
                 'content-sidecar.js', 'moditem-content.js', 'lab-protection.js']
        positions = []
        for name in names:
            source = (ROOT / 'runtime' / name).read_bytes().decode()
            self.assertEqual(script.count(source), 1, name)
            positions.append(script.index(source))
        self.assertEqual(positions, sorted(positions))
        gate = script.index('if(globalThis.TMALCombinedTimeReady!==true)return;')
        self.assertLess(positions[4], gate)
        self.assertLess(gate, positions[5])
        self.assertIn('clearInterval(combinedTimer);', script[gate:positions[5]])


if __name__ == '__main__':
    unittest.main()
