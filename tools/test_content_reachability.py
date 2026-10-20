"""Host regression: closures must retain helper/initializer paths and uncertainty."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from audit_content_reachability import build


class ReachabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='tmal-reachability-', dir='C:/Temp')
        cls.folder = Path(cls.temp.name)
        sdk = Path('C:/Program Files/dotnet')
        cls.command, _ = build(sdk, cls.folder)
        fixture = cls.folder / 'Fixture.cs'
        fixture.write_text('''
using System;
class State { public static int Value; static State() { Value = Seed(); }
 static int Seed() { Console.WriteLine("initializer"); return 7; } }
class BaseItem { public virtual void Defaults() { Helper(); }
 static void Helper() { Console.WriteLine("inherited"); } }
class SelectedItem : BaseItem {
 public override void Defaults() { base.Defaults(); Read(State.Value); Read("x"); }
 static void Read(int x) { Console.WriteLine(x); }
 static void Read(string x) { Console.WriteLine(x); }
 public void Virtual(BaseItem x) { x.Defaults(); }
 public void GenericCalls() { var list = new System.Collections.Generic.List<int>(); list.Add(Echo<int>(4)); }
 static T Echo<T>(T x) { return x; }
 public int Switch(int n) { switch(n) { case 0:return 17; case 1:return 5;
 case 2:return 30; case 3:return 11; case 4:return 2; default:return 1; } }
}
class Unrelated { public static void Never() { Console.WriteLine("unrelated"); } }
static class ModuleStartup {
 [System.Runtime.CompilerServices.ModuleInitializer]
 public static void Start() { Console.WriteLine("must never execute during metadata audit"); }
}
''', encoding='utf-8')
        cls.dll = cls.folder / 'Fixture.dll'
        refs = sorted((sdk / 'packs/Microsoft.NETCore.App.Ref/8.0.31/ref/net8.0').glob('*.dll'))
        rsp = cls.folder / 'fixture.rsp'
        rsp.write_text('\n'.join(['-nologo', '-target:library', '-nostdlib+', f'-out:"{cls.dll}"',
            *[f'-r:"{r}"' for r in refs], f'"{fixture}"']), encoding='utf-8')
        subprocess.run([str(sdk / 'dotnet.exe'), str(sdk / 'sdk/8.0.425/Roslyn/bincore/csc.dll'),
                        '@' + str(rsp)], check=True, capture_output=True, timeout=120)

    @classmethod
    def tearDownClass(cls):
        assert cls.folder.resolve().parent == Path('C:/Temp').resolve()
        assert cls.folder.name.startswith('tmal-reachability-')
        cls.temp.cleanup()

    def test_closure_and_uncertainty(self):
        result = subprocess.run([*self.command, str(self.dll), 'SelectedItem'],
                                check=True, capture_output=True, text=True, timeout=30)
        report = json.loads(result.stdout)
        names = [m['name'] for m in report['methods']]
        for name in ('BaseItem::Helper', 'BaseItem::Defaults', 'State::.cctor', 'State::Seed'):
            self.assertIn(name, names)
        self.assertEqual(names.count('SelectedItem::Read'), 2)  # overloads retain distinct tokens
        self.assertNotIn('Unrelated::Never', names)
        self.assertTrue(any('Virtual dispatch' in b for b in report['blockers']))
        self.assertTrue(any('System.Console::WriteLine' in b for b in report['blockers']))
        self.assertFalse(report['safe_to_execute'])
        self.assertFalse(report['assembly_executed'])
        self.assertIn('Module initializer requires audit', report['blockers'])
        self.assertIn('ModuleStartup::Start', names)
        self.assertTrue(any('System.Collections.Generic.List`1<System.Int32>::Add' == e['target']
                            and e['display_signature'] == 'System.Void (!0)' for e in report['dependencies']))
        self.assertTrue(any(e['target'] == 'SelectedItem::Echo' and e['generic_signature']
                            and e['source_token'] != e['token'] for e in report['dependencies']))

    def test_root_filter_keeps_initializers_and_transitive_calls(self):
        result = subprocess.run([*self.command, str(self.dll), 'SelectedItem', 'Defaults'],
                                check=True, capture_output=True, text=True, timeout=30)
        report = json.loads(result.stdout)
        names = [m['name'] for m in report['methods']]
        self.assertNotIn('SelectedItem::Virtual', names)
        self.assertNotIn('SelectedItem::Switch', names)
        for expected in ('State::.cctor', 'State::Seed', 'BaseItem::Helper', 'ModuleStartup::Start'):
            self.assertIn(expected, names)
        self.assertEqual(report['root_methods'], ['Defaults'])

    def test_missing_type_and_bad_image_fail(self):
        bad = self.folder / 'bad.dll'
        bad.write_bytes(b'not a managed PE')
        for path, name in ((self.dll, 'Missing'), (bad, 'SelectedItem')):
            result = subprocess.run([*self.command, str(path), name], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, '')
        result = subprocess.run([*self.command, str(self.dll), 'SelectedItem', 'MissingRoot'], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
