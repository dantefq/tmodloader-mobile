"""Independent persisted alias-output audit. Python only; no JVM or native engine."""
import argparse
from collections import defaultdict
import copy
import json
from pathlib import Path
from reconcile_terraria_java_spans import Resolver, erase, original_name, read_jsonl, sha, need, validate_file


def verify_records(original, prior, mapped, files, classes, encoded):
    need(len(original) == len(prior) == len(mapped) == 9004, 'Method universe mismatch')
    resolver = Resolver(original, classes, files)
    alias_declarations = defaultdict(list)
    ast_methods = defaultdict(list)
    for f in files:
        if f['parse_errors']:
            continue
        for c in f['classes']:
            owner = resolver.class_maps[f['path']].get(c['owner'])
            if owner and not c['local_or_anonymous']:
                prefix = f['package'] + '.' if f['package'] else ''
                for key in {prefix + c['owner'], prefix + c['owner'].replace('$', '.')}:
                    alias_declarations[key].append((f, c, owner))
        for m in f['methods']:
            ast_methods[(f['path'], m['start'], m['end'])].append((f, m))
    changed = []
    spans = 0
    for dex, before, after in zip(original, prior, mapped):
        need(all(after[k] == v for k, v in dex.items()), 'DEX identity or evidence mutation')
        need(after['descriptor'] == before['descriptor'], 'Order mutation')
        if before['exact_syntactic_source_association'] or not after['exact_syntactic_source_association']:
            need(before == after, 'Previously established or unpromoted row changed')
        need(not after['semantic_equivalence_verified'] and not after['recovered_Java_method_verified']
             and not after['Java_method_body_recovery_verified'], 'Semantic promotion')
        for field in ['source_method_span', 'source_body_span']:
            s = after[field]
            if s is None:
                continue
            need(0 <= s['start'] <= s['end'] <= len(encoded[s['path']]) // 2, 'Invalid span bounds')
            need(sha(encoded[s['path']][2*s['start']:2*s['end']]) == s['span_utf16le_sha256'], 'Span digest mismatch')
            spans += 1
        if before == after:
            continue
        s = after['source_method_span']
        declarations = ast_methods[(s['path'], s['start'], s['end'])]
        need(len(declarations) == 1, 'Ambiguous source method span')
        f, m = declarations[0]
        need(not m['local_context'] and not f['parse_errors'], 'Local or parser-error method')
        owner = resolver.class_maps[f['path']].get(m['owner'])
        name = '<init>' if m['constructor'] else original_name(m['leading_trivia']) or m['name']
        proofs = after['exact_source_alias_evidence']
        need(proofs and len({p['position'] for p in proofs}) == len(proofs), 'Missing or duplicate type proof')
        bypos = {p['position']: p for p in proofs}
        used = set()
        def resolve(text, position):
            old = resolver.type(text, f, m)
            if old is not None:
                need(position not in bypos, 'Unneeded alias promotion')
                return old
            need(position in bypos, 'Unproven type')
            p = bypos[position]
            need(p['type_text'] == text, 'Type-text proof mismatch')
            raw = erase(text)
            need(raw is not None, 'Unsupported type text')
            dims = 0
            while raw.endswith('[]'):
                dims += 1; raw = raw[:-2]
            need(raw == p['alias'] and '.' in raw and raw not in m['type_variables'], 'Alias spelling mismatch')
            bindings = alias_declarations[raw]
            need(len(bindings) == 1, 'Ambiguous alias declaration')
            target_file, c, desc = bindings[0]
            need(desc == p['dex_class_descriptor'] and target_file['path'] == p['source_path']
                 and target_file['sha256'] == p['source_sha256'] and c['owner'] == p['source_owner']
                 and c['start'] == p['declaration_start'] and c['end'] == p['declaration_end']
                 and original_name(c['leading_trivia']) == p['JADX_original_class_name'], 'Alias declaration proof mismatch')
            need(not resolver.by_dotted.get(raw) or resolver.by_dotted[raw] == {desc}, 'Existing DEX name collision')
            used.add(position)
            return '[' * dims + desc
        params = [resolve(p['type'], 'parameter_' + str(i)) for i, p in enumerate(m['parameters'])]
        ret = resolve(m['return_type'], 'return')
        need(used == set(bypos), 'Extraneous type proof')
        need(owner + '->' + name + '(' + ''.join(params) + ')' + ret == dex['descriptor'], 'Exact DEX signature mismatch')
        need(after['source_body_span']['start'] == m['body_start'] and after['source_body_span']['end'] == m['body_end'], 'Body bounds differ from AST')
        changed.append(dex['descriptor'])
    return changed, spans


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--lab', type=Path, default=Path('C:/Temp/terraria-re-20261012'))
    args = ap.parse_args()
    root = args.lab / 'java-method-source-mapping-alias-20261019'
    need(not (root / 'independent-verification.json').exists(), 'Fresh verification report required')
    hashes = json.loads((root / 'hashes.json').read_text())
    for name, expected in hashes.items():
        p = root / name
        need(p.resolve().is_relative_to(root.resolve()) and sha(p.read_bytes()) == expected, 'Persisted output hash mismatch')
    summary = json.loads((root / 'summary.json').read_text())
    for name, expected in summary['input_sha256'].items():
        need(sha((args.lab / name).read_bytes()) == expected, 'Input changed')
    original = read_jsonl(args.lab / 'android-java-method-ledger-20261019/methods.jsonl')
    prior = read_jsonl(args.lab / 'java-method-source-mapping-20261019/reconciled/methods.jsonl')
    mapped = read_jsonl(root / 'methods.jsonl')
    files = read_jsonl(args.lab / 'java-method-source-mapping-20261019/source-ast.jsonl')
    classes = read_jsonl(args.lab / 'android-java-method-ledger-20261019/classes.jsonl')
    encoded = {f['path']: validate_file(f, args.lab / 'jadx/sources') for f in files}
    changed, spans = verify_records(original, prior, mapped, files, classes, encoded)
    reviewed = {r['descriptor'] for r in read_jsonl(args.lab / 'java-method-unmatched-triage-20261019/source-type-alias-candidates.jsonl')}
    need(set(changed) == reviewed and len(changed) == 23, 'Reviewed candidate promotion mismatch')
    need(read_jsonl(root / 'code-methods.jsonl') == [r for r in mapped if r['code_offset']], 'Persisted code subset mismatch')
    controls = []
    changed_index = next(i for i, (a, b) in enumerate(zip(prior, mapped)) if a != b)
    def reject(label, mutate):
        bad = list(mapped)
        bad[changed_index] = copy.deepcopy(bad[changed_index])
        mutate(bad[changed_index])
        try:
            verify_records(original, prior, bad, files, classes, encoded)
        except (ValueError, KeyError, TypeError):
            controls.append(label)
        else:
            raise ValueError('Negative control accepted: ' + label)
    reject('original_code_hash_mutation', lambda r: r.update(instruction_bytes_sha256='0'*64))
    reject('source_span_digest_mutation', lambda r: r['source_body_span'].update(span_utf16le_sha256='0'*64))
    reject('wrong_alias_D​EX_descriptor', lambda r: r['exact_source_alias_evidence'][0].update(dex_class_descriptor='Lwrong;'))
    reject('missing_alias_proof', lambda r: r.update(exact_source_alias_evidence=[]))
    reject('semantic_claim', lambda r: r.update(semantic_equivalence_verified=True))
    result = dict(passed=True, definitions=len(mapped), checked_exact_spans=spans, reviewed_promotions=len(changed),
        original_DEX_fields_unchanged=True, all_prior_exact_rows_unchanged=True,
        persisted_hashes_verified=True, source_hashes_verified=True, full_signatures_reconstructed=True,
        negative_controls_rejected=controls, producer_sha256=sha(Path(__file__).read_bytes()),
        input_hash_manifest_sha256=sha((root / 'hashes.json').read_bytes()), target_execution=False,
        JVM_or_compiler_or_native_engine_launched=False, semantic_equivalence_verified=False)
    (root / 'independent-verification.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
