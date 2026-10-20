"""Versioned exact Java source-owner aliases; source-only, no Java execution."""
import argparse
from collections import Counter, defaultdict
import copy
import hashlib
import json
from pathlib import Path
import shutil

sha = lambda b: hashlib.sha256(b).hexdigest()
BASE_SHA = '20ffb9afd6a750ad2b012af22046053a18a3ce417a02cc2dd0ca8174c2833d14'
BASE = Path(__file__).with_name('reconcile_terraria_java_spans.py')
if sha(BASE.read_bytes()) != BASE_SHA:
    raise ValueError('Original reconciler changed')
from reconcile_terraria_java_spans import Resolver, erase, original_name, read_jsonl, need, validate_file

PINS = {
    'java-method-source-mapping-20261019/source-ast.jsonl': '69481110297d400f200ce9ee500e7a3383f5fae764d8bbcef1274a9b6dedc07b',
    'java-method-source-mapping-20261019/reconciled/methods.jsonl': '941c1b5bb986232fe58d188448c317ffd894ca3ad97c000df269bd19a1af94e8',
    'android-java-method-ledger-20261019/classes.jsonl': 'eb98cdfd3fe51217a2e101ea534c6393da314652709ebe38bb2081d2a038ded3',
    'android-java-method-ledger-20261019/methods.jsonl': '570db463827c59f749f7a9685633bb44def3a7656ecc326b416d3bcd4c642be9',
    'java-method-unmatched-triage-20261019/source-type-alias-candidates.jsonl': '0eab22b349e4fa8f99ce145489015ec37c5d528b59b22713009ee44df64e4cb6',
}


class AliasResolver(Resolver):
    def __init__(self, rows, classes, files):
        super().__init__(rows, classes, files)
        self.aliases = defaultdict(list)
        for f in files:
            if f['parse_errors']:
                continue
            for c in f['classes']:
                desc = self.class_maps[f['path']].get(c['owner'])
                if not desc or c['local_or_anonymous']:
                    continue
                prefix = f['package'] + '.' if f['package'] else ''
                for alias in sorted({prefix + c['owner'], prefix + c['owner'].replace('$', '.')}):
                    self.aliases[alias].append(dict(alias=alias, dex_class_descriptor=desc,
                        source_path=f['path'], source_sha256=f['sha256'], source_owner=c['owner'],
                        declaration_start=c['start'], declaration_end=c['end'],
                        JADX_original_class_name=original_name(c['leading_trivia']),
                        leading_trivia_sha256=sha(c['leading_trivia'].encode('utf8'))))

    def resolve_alias(self, text, f, m):
        raw = erase(text)
        if not raw:
            return None
        dims = 0
        while raw.endswith('[]'):
            dims += 1; raw = raw[:-2]
        if '.' not in raw or raw in m.get('type_variables', []):
            return None
        found = self.aliases.get(raw, [])
        if len(found) != 1:
            return None
        proof = found[0]
        # Never defeat an existing original DEX spelling with a source alias.
        existing = self.by_dotted.get(raw, set())
        if existing and existing != {proof['dex_class_descriptor']}:
            return None
        return '[' * dims + proof['dex_class_descriptor'], proof

    def resolved(self, text, f, m):
        original = super().type(text, f, m)
        if original is not None:
            return original, None
        found = self.resolve_alias(text, f, m)
        return found if found else (None, None)


def candidates(resolver, files):
    result = defaultdict(list)
    for f in files:
        if f['parse_errors']:
            continue
        for m in f['methods']:
            owner = resolver.class_maps[f['path']].get(m['owner'])
            if not owner or m['local_context']:
                continue
            parts = [resolver.resolved(p['type'], f, m) for p in m['parameters']]
            ret, ret_proof = resolver.resolved(m['return_type'], f, m)
            if any(v is None for v, proof in parts) or ret is None:
                continue
            name = '<init>' if m['constructor'] else original_name(m['leading_trivia']) or m['name']
            desc = owner + '->' + name + '(' + ''.join(v for v, proof in parts) + ')' + ret
            proofs = [dict(position='parameter_' + str(i), type_text=m['parameters'][i]['type'], **proof)
                      for i, (v, proof) in enumerate(parts) if proof]
            if ret_proof:
                proofs.append(dict(position='return', type_text=m['return_type'], **ret_proof))
            result[desc].append((f, m, proofs))
    return result


def self_test():
    c = dict(owner='Renamed', parent_owner='', name='Renamed', local_or_anonymous=False,
             leading_trivia='/* JADX INFO: renamed from: p.Original */', start=0, end=1)
    f = dict(path='p/Renamed.java', package='p', classes=[c], imports=[], parse_errors=False, sha256='test', methods=[])
    classes = [dict(descriptor='Lp/Original;')]
    rows = [dict(descriptor='Lp/Original;->f()V')]
    m = dict(owner='Renamed', type_variables=[])
    r = AliasResolver(rows, classes, [f])
    need(r.resolved('p.Renamed[][]', f, m)[0] == '[[Lp/Original;', 'Exact alias array failed')
    controls = []
    def unknown(label, resolver, text='p.Renamed', method=m):
        need(resolver.resolved(text, f, method)[0] is None, 'Unsafe alias accepted: ' + label)
        controls.append(label)
    need(r.resolve_alias('Renamed', f, m) is None, 'New alias resolver accepted an unqualified name')
    controls.append('unqualified_alias_not_added_by_new_resolver')
    unknown('unknown_alias', r, 'p.Unknown')
    unknown('unsupported_type', r, '? extends p.Renamed')
    unknown('generic_variable', r, method=dict(owner='Renamed', type_variables=['p.Renamed']))
    # Distinct duplicate declarations remain ambiguous even when both say the
    # same original descriptor. A set of descriptors alone would lose this.
    dup = copy.deepcopy(f); dup['path'] = 'other/Renamed.java'
    unknown('duplicate_alias_declaration', AliasResolver(rows, classes, [f, dup]))
    bad = copy.deepcopy(f); bad['parse_errors'] = True
    unknown('parse_error_class', AliasResolver(rows, classes, [bad]))
    bad = copy.deepcopy(f); bad['classes'][0]['local_or_anonymous'] = True
    unknown('local_class', AliasResolver(rows, classes, [bad]))
    bad = copy.deepcopy(f); bad['classes'][0]['leading_trivia'] = '/* JADX INFO: renamed from: p.Missing */'
    unknown('rename_not_in_DEX', AliasResolver(rows, classes, [bad]))
    conflict = AliasResolver(rows, classes + [dict(descriptor='Lp/Renamed;')], [f])
    need(conflict.resolve_alias('p.Renamed', f, m) is None, 'Original DEX collision bypassed')
    controls.append('existing_DEX_name_collision')
    return controls


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--lab', type=Path, default=Path('C:/Temp/terraria-re-20261012'))
    ap.add_argument('--output', type=Path)
    ap.add_argument('--include-additional', action='store_true')
    args = ap.parse_args()
    out = args.output or args.lab / ('java-method-source-mapping-alias-20261019-v2' if args.include_additional else 'java-method-source-mapping-alias-20261019')
    need(not out.exists(), 'Fresh output required')
    for rel, expected in PINS.items():
        need(sha((args.lab / rel).read_bytes()) == expected, 'Input changed: ' + rel)
    files = read_jsonl(args.lab / 'java-method-source-mapping-20261019/source-ast.jsonl')
    prior = read_jsonl(args.lab / 'java-method-source-mapping-20261019/reconciled/methods.jsonl')
    original = read_jsonl(args.lab / 'android-java-method-ledger-20261019/methods.jsonl')
    classes = read_jsonl(args.lab / 'android-java-method-ledger-20261019/classes.jsonl')
    triage = read_jsonl(args.lab / 'java-method-unmatched-triage-20261019/source-type-alias-candidates.jsonl')
    need(len(original) == len(prior) == 9004 and len(triage) == 23, 'Universe mismatch')
    encoded = {f['path']: validate_file(f, args.lab / 'jadx/sources') for f in files}
    resolver = AliasResolver(prior, classes, files)
    index = candidates(resolver, files)
    mapped = []
    promotions = []
    reviewed_set = {r['descriptor'] for r in triage}
    deferred = []
    for before in prior:
        after = copy.deepcopy(before)
        found = index.get(before['descriptor'], [])
        if not before['exact_syntactic_source_association'] and before['method_name'] != '<clinit>' and len(found) == 1:
            f, m, proofs = found[0]
            if proofs and before['descriptor'] not in reviewed_set and not args.include_additional:
                deferred.append(before['descriptor'])
                mapped.append(after)
                continue
            if proofs:
                def span(a, b):
                    return dict(path=f['path'], source_sha256=f['sha256'], start=a, end=b,
                        offset_unit='UTF-16 code units; half-open', span_utf16le_sha256=sha(encoded[f['path']][a*2:b*2]))
                after.update(exact_syntactic_source_association=True,
                    source_method_span=span(m['start'], m['end']),
                    source_body_span=span(m['body_start'], m['body_end']) if m['body_start'] is not None else None,
                    syntactic_mapping_status='exact_descriptor_alias_syntactic_body_span' if m['body_start'] is not None else 'exact_descriptor_alias_syntactic_declaration',
                    exact_source_alias_evidence=proofs)
                promotions.append(dict(descriptor=before['descriptor'], method_id=before['method_id'],
                    prior_record_sha256=sha(json.dumps(before, sort_keys=True).encode('utf8')),
                    source_method_span=after['source_method_span'], source_body_span=after['source_body_span'], aliases=proofs))
        mapped.append(after)
    # Separate verification pass: original DEX fields and every established
    # association must be unchanged, and new signatures/spans must rebind.
    prior_matched = 0
    span_count = 0
    for dex, before, after in zip(original, prior, mapped):
        need(all(after[k] == v for k, v in dex.items()), 'Original DEX fields changed')
        if before['exact_syntactic_source_association']:
            need(after == before, 'Existing source association changed')
            prior_matched += 1
        need(not after['semantic_equivalence_verified'] and not after['Java_method_body_recovery_verified']
             and not after['recovered_Java_method_verified'], 'Semantic promotion')
        for field in ['source_method_span', 'source_body_span']:
            s = after[field]
            if s is not None:
                need(sha(encoded[s['path']][s['start']*2:s['end']*2]) == s['span_utf16le_sha256'], 'Span hash mismatch')
                span_count += 1
    promoted_set = {r['descriptor'] for r in promotions}
    need(args.include_additional or promoted_set <= {r['descriptor'] for r in triage}, 'Promotion beyond reviewed alias scope')
    previous_alias_associations_preserved = None
    previous_alias_methods_sha256 = None
    if args.include_additional:
        first_root = args.lab / 'java-method-source-mapping-alias-20261019'
        first_hashes = json.loads((first_root / 'hashes.json').read_text())
        for name, expected in first_hashes.items():
            need(sha((first_root / name).read_bytes()) == expected, 'Previous alias output changed')
        first_rows = read_jsonl(first_root / 'methods.jsonl')
        need(len(first_rows) == len(mapped), 'Previous alias universe changed')
        previous_alias_associations_preserved = 0
        for a, b in zip(first_rows, mapped):
            need(a['descriptor'] == b['descriptor'], 'Previous alias order changed')
            if a['exact_syntactic_source_association']:
                need(a == b, 'Previous alias association changed')
                previous_alias_associations_preserved += 1
        previous_alias_methods_sha256 = sha((first_root / 'methods.jsonl').read_bytes())
    controls = self_test()
    summary = dict(schema=3 if args.include_additional else 2, scope='unique fully qualified renamed source-owner alias syntactic association only',
        method_definitions=len(mapped), code_methods=sum(bool(r['code_offset']) for r in mapped),
        source_files=len(files), prior_exact_associations=prior_matched,
        added_exact_associations=len(promotions), added_code_body_spans=sum(bool(r['code_offset']) and r['descriptor'] in promoted_set and r['source_body_span'] is not None for r in mapped),
        exact_associations_after=sum(r['exact_syntactic_source_association'] for r in mapped),
        unknown_code_methods_before=sum(bool(r['code_offset']) and not r['exact_syntactic_source_association'] for r in prior),
        unknown_code_methods_after=sum(bool(r['code_offset']) and not r['exact_syntactic_source_association'] for r in mapped),
        reviewed_candidates=len(triage), rejected_candidates=sorted({r['descriptor'] for r in triage} - promoted_set),
        additional_alias_candidates_deferred_outside_reviewed_scope=deferred,
        included_additional_exact_aliases=args.include_additional,
        previous_alias_exact_associations_preserved=previous_alias_associations_preserved,
        previous_alias_methods_sha256=previous_alias_methods_sha256,
        semantic_equivalence_verified=False, Java_method_body_recovery_verified=False, target_execution=False,
        JVM_or_compiler_or_native_engine_launched=False, checked_exact_spans=span_count,
        original_DEX_fields_unchanged=True, all_previous_exact_records_unchanged=True,
        negative_controls_rejected=controls, producer_sha256=sha(Path(__file__).read_bytes()), base_reconciler_sha256=BASE_SHA,
        input_sha256=PINS, status_counts=dict(Counter(r['syntactic_mapping_status'] for r in mapped)),
        limitations=['Source alias mapping and exact declaration/body spans do not prove equivalence to original DEX instructions.',
                    'Parse-error files, anonymous/local classes, type variables, ambiguous aliases and original DEX spelling collisions remain excluded.',
                    'Original mappings and original DEX ledgers are retained unchanged.'])
    out.mkdir(parents=True)
    def lines(name, rows):
        (out / name).write_text(''.join(json.dumps(r, ensure_ascii=True) + '\n' for r in rows), encoding='utf8')
    lines('methods.jsonl', mapped)
    lines('code-methods.jsonl', [r for r in mapped if r['code_offset']])
    lines('alias-promotions.jsonl', promotions)
    lines('class-aliases.jsonl', [dict(alias=k, declarations=v, unique=len(v) == 1) for k, v in sorted(resolver.aliases.items())])
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf8')
    (out / 'verification.json').write_text(json.dumps(dict(passed=True, original_DEX_fields_unchanged=True,
        previous_exact_records_unchanged=prior_matched, exact_spans_checked=span_count, negative_controls_rejected=controls,
        method_output_sha256=sha((out / 'methods.jsonl').read_bytes()), producer_sha256=summary['producer_sha256']), indent=2) + '\n', encoding='utf8')
    notes = ['# Java exact source-owner alias mapping', '',
        f"Reviewed {len(triage)} candidates; added {len(promotions)} exact syntactic associations.",
        f"Unknown code methods: {summary['unknown_code_methods_before']} -> {summary['unknown_code_methods_after']}.",
        'Every original DEX method field/hash and every previously matched row/span is unchanged.',
        'Original DEX descriptors bind explicit JADX rename metadata to the parsed source owner. Only unique full source-owner spellings are accepted.',
        '', *summary['limitations'], '', 'Python only; no JVM, compiler, native engine or target execution.']
    (out / 'NOTES.md').write_text('\n'.join(notes) + '\n', encoding='utf8')
    sources = out / ('producer-sources-v3' if args.include_additional else 'producer-sources-v2'); sources.mkdir()
    for q in [Path(__file__), BASE]:
        shutil.copyfile(q, sources / q.name)
    hashes = {p.relative_to(out).as_posix(): sha(p.read_bytes()) for p in sorted(out.rglob('*')) if p.is_file()}
    (out / 'hashes.json').write_text(json.dumps(hashes, indent=2) + '\n', encoding='utf8')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
