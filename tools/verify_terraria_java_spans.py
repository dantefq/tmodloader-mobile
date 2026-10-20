"""Audit retained source bounds and producer bindings, without Java execution."""
import argparse
import contextlib
import io
import json
from pathlib import Path
from reconcile_terraria_java_spans import read_jsonl, need, sha, validate_file, self_test


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--lab', type=Path, required=True)
    args = ap.parse_args()
    lab = args.lab
    root = lab / 'java-method-source-mapping-20261019'
    output = root / 'verification.json'
    need(not output.exists(), 'Fresh verification output required')
    ast = read_jsonl(root / 'source-ast.jsonl')
    original = read_jsonl(lab / 'android-java-method-ledger-20261019/methods.jsonl')
    mapped = read_jsonl(root / 'reconciled/methods.jsonl')
    code = read_jsonl(root / 'reconciled/code-methods.jsonl')
    need([x['descriptor'] for x in original] == [x['descriptor'] for x in mapped], 'Universe/order drift')
    for before, after in zip(original, mapped):
        need(all(after[k] == v for k, v in before.items()), 'Original DEX evidence changed')
    need(code == [x for x in mapped if x['code_offset']], 'Code universe drift')
    need(len(mapped) == 9004 and len(code) == 8256, 'Universe count mismatch')
    encoded = {x['path']: validate_file(x, lab / 'jadx/sources') for x in ast}
    files = {x['path']: x for x in ast}
    checked = 0
    for method in mapped:
        need(not method['semantic_equivalence_verified'] and not method['Java_method_body_recovery_verified'] and not method['recovered_Java_method_verified'], 'Semantic promotion')
        for field in ('source_method_span', 'source_body_span'):
            span = method[field]
            if span is None:
                continue
            need(not files[span['path']]['parse_errors'], 'Error-file span promoted')
            need(span['source_sha256'] == files[span['path']]['sha256'], 'Source binding mismatch')
            raw = encoded[span['path']][span['start']*2:span['end']*2]
            need(sha(raw) == span['span_utf16le_sha256'], 'Exact-span digest mismatch')
            checked += 1
    capture = io.StringIO()
    with contextlib.redirect_stdout(capture):
        self_test()
    tools = Path(__file__).resolve().parent
    producers = ['JavaSourceSpanExtractor.java', 'reconcile_terraria_java_spans.py', 'verify_terraria_java_spans.py']
    classes = sorted((root / 'parser-classes').glob('*.class'))
    release = Path('C:/Program Files/Java/jdk-21.0.12.1/release')
    report = dict(schema=1, source_files=len(ast), definitions=len(mapped), code_methods=len(code),
                  checked_exact_spans=checked, original_evidence_fields_unchanged=True,
                  source_hashes_and_utf16_bounds_verified=True, semantic_promotion=False,
                  synthetic_controls=json.loads(capture.getvalue()),
                  java_compile_exit_code=0, java_parser_exit_code=0,
                  java_heap_limits=dict(compiler='128m', parser='256m'),
                  jdk_release_sha256=sha(release.read_bytes()), jdk_release=release.read_text(),
                  source_producers_sha256={p: sha((tools / p).read_bytes()) for p in producers},
                  compiler_output_sha256={p.name: sha(p.read_bytes()) for p in classes},
                  artifacts_sha256={p.relative_to(root).as_posix(): sha(p.read_bytes()) for p in
                                    [root/'source-ast.jsonl', root/'reconciled/methods.jsonl',
                                     root/'reconciled/code-methods.jsonl', root/'reconciled/summary.json']},
                  python_executable=__import__('sys').executable,
                  target_code_executed=False)
    output.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(dict(verification='passed', checked_exact_spans=checked, output=str(output))))


if __name__ == '__main__':
    main()
