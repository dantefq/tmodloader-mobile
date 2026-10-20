"""Conservative DEX-to-Java syntactic association; never proves recovered semantics.

Consumes JavaSourceSpanExtractor JSONL. UTF-16 offsets are validated against the
hashed source bytes before use. No compilation, resolution or target execution.
"""
import argparse
import collections
import hashlib
import json
import re
import tempfile
from pathlib import Path


def need(ok, message):
    if not ok:
        raise ValueError(message)


def read_jsonl(path):
    with path.open(encoding='utf-8') as f:
        return [json.loads(line) for line in f if line.strip()]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def original_name(trivia):
    names = re.findall(r'/\* JADX INFO: renamed from: ([\w.$]+) \*/', trivia)
    return names[0] if len(names) == 1 else None


def erase(text):
    """Erase balanced parameterized types; reject unknown Java syntax."""
    if not isinstance(text, str) or re.search(r'\b(?:extends|super)\b', text):
        return None
    depth = 0
    out = []
    for c in text:
        if c == '<':
            depth += 1
        elif c == '>':
            depth -= 1
            if depth < 0:
                return None
        elif not depth:
            out.append(c)
    raw = re.sub(r'\s+', '', ''.join(out))
    if depth or not re.fullmatch(r'[\w$]+(?:\.[\w$]+)*(?:\[\])*', raw):
        return None
    return raw


class Resolver:
    def __init__(self, definitions, class_rows, files):
        self.known = set(c['descriptor'] for c in class_rows)
        for row in definitions:
            self.known.update(re.findall(r'L[^;]+;', row['descriptor']))
        self.by_dotted = collections.defaultdict(set)
        for desc in self.known:
            self.by_dotted[desc[1:-1].replace('/', '.')].add(desc)
            self.by_dotted[desc[1:-1].replace('/', '.').replace('$', '.')].add(desc)
        self.class_maps = {}
        self.classes = set(c['descriptor'] for c in class_rows)
        for f in files:
            mapping = {}
            # AST preorder guarantees a parent precedes its direct member types.
            for c in f['classes']:
                if c['local_or_anonymous'] or c['parent_owner'] and not mapping.get(c['parent_owner']):
                    mapping[c['owner']] = None
                    continue
                renamed = original_name(c['leading_trivia'])
                if renamed:
                    choices = self.by_dotted.get(renamed, set()) & self.classes
                elif c['parent_owner']:
                    parent = mapping.get(c['parent_owner'])
                    choices = {parent[:-1] + '$' + c['name'] + ';'} if parent else set()
                else:
                    name = (f['package'] + '.' if f['package'] else '') + c['name']
                    choices = self.by_dotted.get(name, set()) & self.classes
                choices = choices & self.classes
                value = next(iter(choices)) if len(choices) == 1 else None
                # Duplicate synthetic owner keys can never strengthen attribution.
                mapping[c['owner']] = value if c['owner'] not in mapping else None
            self.class_maps[f['path']] = mapping

    def type(self, text, f, m):
        raw = erase(text)
        if not raw:
            return None
        arrays = 0
        while raw.endswith('[]'):
            arrays += 1
            raw = raw[:-2]
        if raw in m.get('type_variables', []):
            return None
        primitive = dict(boolean='Z', byte='B', short='S', char='C', int='I', long='J', float='F', double='D', void='V')
        if raw in primitive:
            return '[' * arrays + primitive[raw] if raw != 'void' or not arrays else None
        choices = set()
        if '.' in raw or '$' in raw:
            choices |= self.by_dotted.get(raw, set())
        # Lexically declared types, walking the containing owner scopes.
        mapping = self.class_maps[f['path']]
        owner = m['owner']
        while owner:
            key = owner + '$' + raw.replace('.', '$')
            if mapping.get(key):
                choices.add(mapping[key])
            if owner.split('$')[-1] == raw and mapping.get(owner):
                choices.add(mapping[owner])
            owner = owner.rpartition('$')[0]
        if mapping.get(raw.replace('.', '$')):
            choices.add(mapping[raw.replace('.', '$')])
        explicit = [x['name'] for x in f['imports'] if not x['static'] and not x['name'].endswith('.*') and x['name'].split('.')[-1] == raw]
        for name in explicit:
            choices |= self.by_dotted.get(name, set())
        same = (f['package'] + '.' if f['package'] else '') + raw
        choices |= self.by_dotted.get(same, set()) & self.classes
        # Unknown wildcard/static imports and unresolved names remain unknown.
        if not choices and not explicit and not any(x['name'].endswith('.*') or x['static'] for x in f['imports']):
            choices |= self.by_dotted.get('java.lang.' + raw, set())
        return '[' * arrays + next(iter(choices)) if len(choices) == 1 else None


def validate_file(f, source_root):
    rel = Path(f['path'])
    need(not rel.is_absolute() and '..' not in rel.parts, 'Unsafe source path')
    root = source_root.resolve()
    path = (root / rel).resolve()
    need(path.is_relative_to(root), 'Source outside root')
    raw = path.read_bytes()
    need(sha(raw) == f['sha256'] and len(raw) == f['bytes'], 'Changed source bytes')
    utf16 = raw.decode('utf-8', 'strict').encode('utf-16-le')
    need(len(utf16) // 2 == f['utf16_length'], 'Source offset length mismatch')
    need(f['parse_only'] is True, 'Parser provenance mismatch')
    if f['parse_errors']:
        return utf16  # Recovery trees may have NOPOS; this whole file is excluded.
    for m in f['methods']:
        a, b = m['start'], m['end']
        need(isinstance(a, int) and isinstance(b, int) and 0 <= a <= b <= len(utf16) // 2, 'Invalid method span')
        if m['body_start'] is not None:
            x, y = m['body_start'], m['body_end']
            need(a <= x < y <= b, 'Body outside declaration')
            need(utf16[x*2:x*2+2] == b'{\0' and utf16[(y-1)*2:y*2] == b'}\0', 'Body braces mismatch')
    return utf16


def reconcile(rows, classes, files, source_root):
    need(len({r['descriptor'] for r in rows}) == len(rows), 'Duplicate DEX definition')
    need(len({f['path'] for f in files}) == len(files), 'Duplicate source file')
    encoded = {f['path']: validate_file(f, source_root) for f in files}
    resolver = Resolver(rows, classes, files)
    candidates = collections.defaultdict(list)
    counts = collections.Counter()
    for f in files:
        if f['parse_errors']:
            counts['files_with_parse_errors_excluded'] += 1
            continue
        for m in f['methods']:
            owner = resolver.class_maps[f['path']].get(m['owner'])
            if not owner or m['local_context']:
                counts['source_methods_owner_unknown'] += 1
                continue
            name = '<init>' if m['constructor'] else original_name(m['leading_trivia']) or m['name']
            types = [resolver.type(p['type'], f, m) for p in m['parameters']]
            ret = resolver.type(m['return_type'], f, m)
            if None in types or ret is None:
                counts['source_methods_type_unknown'] += 1
                continue
            descriptor = owner + '->' + name + '(' + ''.join(types) + ')' + ret
            candidates[descriptor].append((f, m))
    output = []
    for row in rows:
        r = dict(row)
        found = candidates.get(row['descriptor'], [])
        r.update(exact_syntactic_source_association=False, source_method_span=None,
                 source_body_span=None, semantic_equivalence_verified=False,
                 Java_method_body_recovery_verified=False,
                 syntactic_mapping_status='unknown_no_exact_signature')
        if row['method_name'] == '<clinit>':
            r['syntactic_mapping_status'] = 'unknown_initializer_transformation'
        elif len(found) > 1:
            r['syntactic_mapping_status'] = 'unknown_ambiguous_exact_signature'
        elif len(found) == 1:
            f, m = found[0]
            u = encoded[f['path']]
            def span(a, b):
                return dict(path=f['path'], source_sha256=f['sha256'], start=a, end=b,
                            offset_unit='UTF-16 code units; half-open',
                            span_utf16le_sha256=sha(u[a*2:b*2]))
            r.update(exact_syntactic_source_association=True,
                     source_method_span=span(m['start'], m['end']),
                     syntactic_mapping_status='exact_descriptor_syntactic_declaration')
            if m['body_start'] is not None:
                r['source_body_span'] = span(m['body_start'], m['body_end'])
                r['syntactic_mapping_status'] = 'exact_descriptor_syntactic_body_span'
        output.append(r)
    counts.update(r['syntactic_mapping_status'] for r in output)
    return output, dict(counts)


def self_test():
    need(erase('java.util.Map<java.lang.String, java.util.List<X>>[]') == 'java.util.Map[]', 'Generic erasure')
    for value in ['T extends X', '@A X', 'X<', 'X>', '?', 'A & B', 'X...']:
        need(erase(value) is None, 'Unsupported type accepted: ' + value)
    need(original_name('/* JADX INFO: renamed from: a */') == 'a', 'Rename control')
    need(original_name('/* renamed from: a */') is None, 'Non-JADX rename accepted')
    need(original_name('/* JADX INFO: renamed from: a */ /* JADX INFO: renamed from: b */') is None, 'Ambiguous rename accepted')
    f = dict(path='A.java', package='p', classes=[dict(owner='A', parent_owner='', name='A', local_or_anonymous=False, leading_trivia='')], imports=[])
    rows = [dict(descriptor='Lp/A;->f(Ljava/lang/String;)V')]
    r = Resolver(rows, [dict(descriptor='Lp/A;')], [f])
    m = dict(owner='A', type_variables=['T'])
    need(r.type('T', f, m) is None, 'Type variable guessed')
    need(r.type('Unknown', f, m) is None, 'Unknown type guessed')
    need(r.type('String', f, m) == 'Ljava/lang/String;', 'java.lang resolution')
    f['imports'] = [dict(name='other.*', static=False)]
    need(r.type('String', f, m) is None, 'Wildcard ambiguity guessed')
    workspace = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix='java-span-controls-', dir=workspace) as temp:
        root = Path(temp)
        need(root.resolve().is_relative_to(workspace), 'Control directory outside workspace')
        raw = b'package p; class A { void f() {} }\n'
        (root / 'A.java').write_bytes(raw)
        text = raw.decode()
        begin = text.index('void')
        body = text.index('{}')
        end = body + 2
        file = dict(path='A.java', sha256=sha(raw), bytes=len(raw), utf16_length=len(text),
                    parse_only=True, parse_errors=False, package='p', imports=[],
                    classes=f['classes'], methods=[dict(owner='A', name='f', constructor=False,
                    return_type='void', parameters=[], type_variables=[], start=begin, end=end,
                    body_start=body, body_end=end, leading_trivia='', local_context=False)])
        row = dict(descriptor='Lp/A;->f()V', method_name='f')
        classes = [dict(descriptor='Lp/A;')]
        out, _ = reconcile([row], classes, [file], root)
        need(out[0]['exact_syntactic_source_association'] and not out[0]['semantic_equivalence_verified'], 'Signature/semantic distinction')
        file['methods'].append(dict(file['methods'][0]))
        out, _ = reconcile([row], classes, [file], root)
        need(out[0]['syntactic_mapping_status'] == 'unknown_ambiguous_exact_signature', 'Overload/duplicate ambiguity promoted')
        file['methods'].pop()
        file['parse_errors'] = True
        out, _ = reconcile([row], classes, [file], root)
        need(not out[0]['exact_syntactic_source_association'], 'Parse error promoted')
        file['parse_errors'] = False
        file['methods'][0]['local_context'] = True
        out, _ = reconcile([row], classes, [file], root)
        need(not out[0]['exact_syntactic_source_association'], 'Local class promoted')
        file['methods'][0]['local_context'] = False
        file['methods'][0]['body_end'] = end + 1
        try:
            validate_file(file, root)
        except ValueError:
            pass
        else:
            raise ValueError('Invalid body span accepted')
        file['methods'][0]['body_end'] = end
        (root / 'A.java').write_bytes(raw + b' ')
        try:
            validate_file(file, root)
        except ValueError:
            pass
        else:
            raise ValueError('Changed source hash accepted')
    print(json.dumps(dict(negative_controls='passed', target_execution=False)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--ledger', type=Path)
    ap.add_argument('--ast', type=Path)
    ap.add_argument('--sources', type=Path)
    ap.add_argument('--output', type=Path)
    args = ap.parse_args()
    if args.self_test:
        self_test()
        return
    need(all((args.ledger, args.ast, args.sources, args.output)), 'Missing required paths')
    need(not args.output.exists(), 'Fresh output directory required')
    rows = read_jsonl(args.ledger / 'methods.jsonl')
    need(len(rows) == 9004 and sum(bool(x['code_offset']) for x in rows) == 8256, 'DEX universe mismatch')
    files = read_jsonl(args.ast)
    prior_files = read_jsonl(args.ledger / 'source-files.jsonl')
    need({(x['path'], x['sha256']) for x in files} == {(x['path'], x['sha256']) for x in prior_files}, 'Source universe mismatch')
    mapped, counts = reconcile(rows, read_jsonl(args.ledger / 'classes.jsonl'), files, args.sources)
    args.output.mkdir(parents=True)
    for filename, values in [('methods.jsonl', mapped), ('code-methods.jsonl', [x for x in mapped if x['code_offset']])]:
        with (args.output / filename).open('w', encoding='utf-8') as out:
            for value in values:
                out.write(json.dumps(value, ensure_ascii=True) + '\n')
    summary = dict(schema=1, scope='exact syntactic association only; no semantic recovery proof',
                   method_definitions=len(rows), code_methods=8256, source_files=len(files), counts=counts,
                   code_method_status_counts=dict(collections.Counter(x['syntactic_mapping_status'] for x in mapped if x['code_offset'])),
                   parse_error_files=[x['path'] for x in files if x['parse_errors']],
                   semantic_equivalence_verified=False, recovered_Java_method_verified=False,
                   input_ast_sha256=sha(args.ast.read_bytes()), reconciler_sha256=sha(Path(__file__).read_bytes()),
                   input_ledger_sha256={name: sha((args.ledger / name).read_bytes()) for name in ('methods.jsonl', 'classes.jsonl', 'source-files.jsonl')},
                   limitations=['Generic type variables remain unknown', 'Parse-error files excluded',
                                'Initializers, removed synthetic parameters, moved/inlined methods remain unknown',
                                'A signature/body span does not prove fidelity to DEX instructions'])
    (args.output / 'summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
