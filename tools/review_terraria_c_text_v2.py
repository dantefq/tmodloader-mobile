"""Read-only lexical review of an audited C candidate; no compilation or coverage claim."""
import argparse
import hashlib
import json
from pathlib import Path
import re


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result_path, audit_path = args.folder / 'result.json', args.folder / 'audit.json'
    result = json.loads(result_path.read_text(encoding='utf-8-sig'))
    audit = json.loads(audit_path.read_text(encoding='utf-8-sig'))
    assert audit['integrity_passed'] and audit['result_sha256'] == sha(result_path)
    assert result['status'] == 'decompiled_conditional_candidate'
    c_path = args.folder / result['file']
    assert c_path.resolve().parent == args.folder.resolve()
    raw = c_path.read_bytes()
    assert sha(c_path) == result['c_sha256'] and len(raw) == result['c_bytes']
    text = raw.decode('utf8')
    # A small C lexer, preserving positions/lines while excluding comments and literals.
    clean, index, lexical_errors = list(text), 0, []
    while index < len(text):
        start = index
        if text.startswith('//', index):
            end = text.find('\n', index)
            index = len(text) if end < 0 else end
        elif text.startswith('/*', index):
            end = text.find('*/', index + 2)
            if end < 0:
                lexical_errors.append({'offset': index, 'error': 'unterminated comment'})
                index = len(text)
            else:
                index = end + 2
        elif text[index] in ('"', "'"):
            quote = text[index]
            index += 1
            while index < len(text) and text[index] != quote:
                index += 2 if text[index] == '\\' else 1
            if index >= len(text):
                lexical_errors.append({'offset': start, 'error': 'unterminated literal'})
            index = min(index + 1, len(text))
        else:
            index += 1
            continue
        for offset in range(start, index):
            if clean[offset] != '\n':
                clean[offset] = ' '
    code = ''.join(clean)
    stack, mismatches, counts, depth, maximum = [], [], {'{': 0, '(': 0, '[': 0}, 0, 0
    for offset, character in enumerate(code):
        if character in '{([':
            stack.append((character, offset))
            counts[character] += 1
            if character == '{':
                depth += 1
                maximum = max(maximum, depth)
        elif character in '})]':
            if not stack or stack[-1][0] != {'}': '{', ')': '(', ']': '['}[character]:
                mismatches.append({'offset': offset, 'closing': character})
            else:
                stack.pop()
            if character == '}':
                depth -= 1
    labels = set(re.findall(r'(?m)^[ \t]*([A-Za-z_]\w*)\s*:', code))
    gotos = re.findall(r'\bgoto\s+([A-Za-z_]\w*)\s*;', code)
    report = dict(scope='Lexical C-text inspection only; not C syntax, CFG or semantic validation.',
                  reviewer_sha256=sha(Path(__file__)), address=result['address'],
                  c_sha256=sha(c_path), result_sha256=sha(result_path), audit_sha256=sha(audit_path),
                  bytes=len(raw), newline_count=text.count('\n'), contains_NUL='\0' in text,
                  lexical_errors=lexical_errors, delimiter_open_counts=counts,
                  delimiter_mismatches=mismatches, unclosed_delimiters=stack,
                  maximum_brace_depth=maximum, goto_count=len(gotos), labels=sorted(labels),
                  missing_goto_labels=sorted(set(gotos) - labels),
                  warnings=[{'line': n, 'text': line.strip()} for n, line in enumerate(text.splitlines(), 1) if 'WARNING:' in line],
                  selected_markers={marker: code.count(marker) for marker in ('halt_baddata', 'BADSPACE', 'UNIMPLEMENTED')},
                  compilation_verified=False, semantic_equivalence_verified=False, C_coverage_addition=0)
    if args.output.exists():
        raise FileExistsError('Preserve existing review; choose a fresh output')
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf8')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
