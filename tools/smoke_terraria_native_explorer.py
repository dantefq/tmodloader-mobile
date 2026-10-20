"""Exercise explorer audit gates, path confinement and offline UI on synthetic data."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('native_explorer', HERE/'build_terraria_native_explorer.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class ExplorerSmoke(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='terraria-native-explorer-smoke-')
        self.lab = Path(self.tmp.name)
        self.out = self.lab/'native-ranges-pseudocode'
        self.out.mkdir()
        (self.lab/'native').mkdir()
        self.records = []
        self.classification = []
        for i in range(151):
            address = hex(0x1000+i*4)
            c = dict(address=address, category='unknown' if i else 'invoker', roles=[])
            self.classification.append(c)
            r = dict(address=address, compiler_end_exclusive=hex(int(address, 16)+4), compiler_size=4, function_name='hostile </script><img src=x>' if i == 0 else 'native_'+str(i), classification=c, status='decompiled', profile='synthetic', model='synthetic')
            for key, suffix in [('file', '.c'), ('asm_file', '.asm.tsv'), ('calls_file', '.calls.tsv')]:
                r[key] = str(i)+suffix
                (self.out/r[key]).write_text('synthetic smoke fixture', encoding='utf-8')
            self.records.append(r)
        self.write_json(self.out/'progress.json', dict(finished=True, phase='complete'))
        self.refresh()

    def tearDown(self):
        self.tmp.cleanup()

    def write_json(self, path, obj):
        path.write_text(json.dumps(obj), encoding='utf-8')

    def refresh(self):
        coverage = self.out/'coverage.jsonl'
        coverage.write_text('\n'.join(json.dumps(r) for r in self.records)+'\n', encoding='utf-8')
        classification = self.lab/'native/unmapped-fde-classification.json'
        self.write_json(classification, self.classification)
        summary = self.out/'summary.json'
        self.write_json(summary, dict(finished=True, coverage_sha256=builder.digest(coverage)))
        self.write_json(self.lab/'native/native-ranges-export-audit.json', dict(passed=True, partition_disjoint=True, native_range_count=151, status_counts={'decompiled':151}, unknown_ranges=150, inputs=dict(coverage_sha256=builder.digest(coverage), summary_sha256=builder.digest(summary), classification_sha256=builder.digest(classification))))

    def test_offline_ui(self):
        result = builder.build(self.lab, expected=151)
        self.assertEqual(result['linked_artifacts'], 456)
        text = (self.lab/'native-ranges.html').read_text(encoding='utf-8')
        self.assertIn("connect-src 'none'", text)
        self.assertNotIn('<img src=x>', text)
        self.assertNotIn('fetch(', text)
        # Run the generated page's actual script with a small DOM, not a reimplementation.
        script = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const html=fs.readFileSync(process.argv[1],'utf8');
class Element{constructor(tag){this.tag=tag;this.children=[];this.value='';this.textContent='';this.attrs={}}append(...items){this.children.push(...items)}replaceChildren(...items){this.children=items}setAttribute(k,v){this.attrs[k]=v}}
const ids={};for(const id of ['native-data','q','category','status','stats','phase','downloads','results','info','prev','next','detail','footer'])ids[id]=new Element('div');
ids['native-data'].textContent=html.match(/<script id="native-data" type="application\/json">([\s\S]*?)<\/script>/)[1];
const context=vm.createContext({document:{getElementById:id=>ids[id],createElement:tag=>new Element(tag)},location:{hash:''},Option:function(text,value){let e=new Element('option');e.textContent=text;e.value=value;return e}});
vm.runInContext(html.match(/<script>\n([\s\S]*?)<\/script>/)[1],context);
assert.equal(ids.results.children.length,150);assert.equal(ids.prev.disabled,true);assert.equal(ids.next.disabled,false);
ids.next.onclick();assert.equal(ids.results.children.length,1);assert.equal(ids.next.disabled,true);
ids.prev.onclick();assert.equal(ids.results.children.length,150);
ids.q.value='0x1258';ids.q.oninput();assert.equal(ids.results.children.length,1);
ids.results.children[0].onclick();assert.equal(context.location.hash,'#range-0x1258');assert.equal(ids.detail.children[5].children.length,3);
ids.q.value='';ids.category.value='invoker';ids.category.onchange();assert.equal(ids.results.children.length,1);
ids.results.children[0].onclick();assert.equal(ids.detail.children[0].textContent,'hostile </script><img src=x>');
ids.status.value='decompile_failed';ids.status.onchange();assert.equal(ids.results.children.length,0);assert.equal(ids.next.disabled,true);
console.log('UI: pagination, address/name/category/status search, safe text and three local artifact links passed');
'''
        subprocess.run(['node', '-e', script, str(self.lab/'native-ranges.html')], check=True)

    def test_unfinished_refused(self):
        self.write_json(self.out/'progress.json', dict(finished=False, phase='export'))
        with self.assertRaisesRegex(ValueError, 'unfinished'):
            builder.build(self.lab, expected=151)

    def test_post_audit_coverage_change_refused(self):
        with (self.out/'coverage.jsonl').open('a') as stream:
            stream.write('\n')
        with self.assertRaisesRegex(ValueError, 'Coverage changed'):
            builder.build(self.lab, expected=151)

    def test_path_escape_refused(self):
        self.records[0]['file'] = '../../escaped.c'
        self.refresh()
        with self.assertRaisesRegex(ValueError, 'escapes'):
            builder.build(self.lab, expected=151)

    def test_missing_file_refused(self):
        (self.out/'0.c').unlink()
        with self.assertRaisesRegex(ValueError, 'Missing artifact'):
            builder.build(self.lab, expected=151)


if __name__ == '__main__':
    unittest.main()
