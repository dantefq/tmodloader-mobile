"""Compile independent C# ABI fixtures; inspect only, never execute their DLLs."""
import argparse
import json
from pathlib import Path
import subprocess
import unittest

from check_mod_signatures import Assembly, Blob, Unsupported, compare


class EncodingTests(unittest.TestCase):
    def test_compressed_integers(self):
        for raw, expected in ((b'\x7f',127),(b'\x80\x80',128),(b'\xbf\xff',16383),
                              (b'\xc0\x00\x40\x00',16384),(b'\xdf\xff\xff\xff',0x1fffffff)):
            self.assertEqual(Blob(raw).uint(), expected)

    def test_truncated_or_reserved(self):
        for raw in (b'',b'\x80',b'\xc0\x00\x00',b'\xe0'):
            with self.assertRaises(Unsupported):
                Blob(raw).uint()


REFERENCE = '''namespace Terraria {
public class Contract {
 public int Field; public int ReplacedField;
 public int Return(int x) => x;
 public void Ref(ref int x) {}
 public static void Static(int x) {}
 public T Generic<T>(T x) => x;
 public void Array(int[] x) {}
 public void Matrix(int[,] x) {}
 public void Overload(string x) {} public void Overload(int x) {}
 public class Nested {} public void NestedArg(Nested x) {}
 public virtual int Hook(ref int x) => x;
}
public class Missing { public void Call() {} }
}'''

CHANGED = REFERENCE.replace('public int Field;', 'public long Field;').replace(
    'public int ReplacedField;', 'public int ReplacedField { get; set; }').replace(
    'public int Return(int x) => x;', 'public long Return(int x) => x;').replace(
    'Ref(ref int x)', 'Ref(int x)').replace('public static void Static', 'public void Static').replace(
    'public class Missing { public void Call() {} }', '')
CHANGED = CHANGED.replace('public virtual int Hook(ref int x) => x;', 'public int Hook(ref int x) => x;')

CONSUMER = '''public class Consumer : Terraria.Contract {
 public override int Hook(ref int x) => x;
 public void Run(Terraria.Contract c, Terraria.Missing m) {
 int x=c.Field; c.ReplacedField=x; x=c.Return(x); c.Ref(ref x);
 Terraria.Contract.Static(x); x=c.Generic<int>(x); c.Array(new int[1]);
 c.Matrix(new int[1,1]); c.Overload(x); c.Overload("x");
 c.NestedArg(new Terraria.Contract.Nested()); m.Call();
 }
}'''


def fixtures(dotnet, lab):
    root = Path(__file__).resolve().parents[1]
    lab = lab.resolve() / 'signature-fixtures'
    if lab.is_relative_to(root):
        raise ValueError('Keep fixture binaries outside source checkout')
    csc = dotnet / 'sdk/8.0.425/Roslyn/bincore/csc.dll'
    refs = sorted((dotnet / 'packs/Microsoft.NETCore.App.Ref/8.0.31/ref/net8.0').glob('*.dll'))
    if not csc.is_file() or not refs:
        raise ValueError('Pinned SDK/reference pack missing')

    def compile(folder, name, source, extra=()):
        folder.mkdir(parents=True, exist_ok=True)
        cs, output = folder / 'Fixture.cs', folder / (name + '.dll')
        cs.write_text(source, encoding='utf-8')
        response = folder / 'compile.rsp'
        response.write_text('\n'.join(['-nologo','-target:library','-nostdlib+','-deterministic+',
            f'-out:"{output}"', *[f'-r:"{ref}"' for ref in [*refs,*extra]], f'"{cs}"']), encoding='utf-8')
        subprocess.run([str(dotnet/'dotnet.exe'), str(csc), '@'+str(response)], check=True, timeout=60)
        return output.read_bytes(), output

    reference, ref_path = compile(lab/'reference', 'tModLoader', REFERENCE)
    changed, _ = compile(lab/'changed', 'tModLoader', CHANGED)
    consumer, _ = compile(lab/'consumer', 'Consumer', CONSUMER, [ref_path])
    good, bad = compare(consumer, reference), compare(consumer, changed)

    def find(report, name):
        return [r for r in report['member_checks'] if r['member'] == name]

    checks = []
    def require(condition, label):
        if not condition:
            raise AssertionError(label)
        checks.append(label)

    for name in ('Field','ReplacedField','Return','Ref','Static','Generic','Array','NestedArg','Overload'):
        require(all(r['status']=='exact-signature' for r in find(good,name)) and bool(find(good,name)), 'matching '+name)
    for name in ('Field','Return','Ref','Static'):
        require(find(bad,name)[0]['status']=='signature-mismatch', 'reject changed '+name)
    require(find(bad,'ReplacedField')[0]['status']=='missing-declared-member', 'field is not property')
    require(find(bad,'Call')[0]['status']=='missing-type', 'missing owner type')
    require(find(good,'Matrix')[0]['status']=='unsupported', 'multidimensional array remains unresolved')
    require(len(find(good,'Overload'))==2, 'both overloads independently checked')
    require(good['compatibility_verified'] is False and good['assembly_executed'] is False, 'no execution or compatibility claim')
    require(good['override_checks'][0]['status']=='exact-override', 'direct virtual override signature')
    require(bad['override_checks'][0]['status']=='non-overridable', 'reject nonvirtual base method')
    asm = Assembly(reference)
    try:
        for raw in (b'\x00\x00', b'\x06\x08\x00', b'\x05\x00\x01', b'\x06\x12\x00'):
            try:
                asm.signature(raw)
            except Unsupported:
                continue
            raise AssertionError('Malformed signature accepted: '+raw.hex())
        checks.append('reject malformed, trailing, vararg and invalid token encodings')
    finally:
        asm.close()
    report = dict(status='passed', checks=checks, count=len(checks), dlls_executed=False)
    (root/'reports/signature-tests.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(report))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dotnet', type=Path, default=Path('C:/Program Files/dotnet'))
    parser.add_argument('--lab', type=Path, required=True)
    args = parser.parse_args()
    result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(EncodingTests))
    if not result.wasSuccessful():
        raise SystemExit(1)
    fixtures(args.dotnet, args.lab)
