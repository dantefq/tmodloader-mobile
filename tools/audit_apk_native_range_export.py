"""Independent persisted-record/ELF audit; never launches the native decompiler."""
import argparse
import collections
import copy
import hashlib
import json
import re
import struct
from pathlib import Path

PROFILE = 'apk-native-bounded-range-C-v1'
ENGINE = 'd64bd049b88d8d2f9452b92079705d4e95b71abb0aad018f596f143246f9f67a'
PRODUCER = 'f4aeb31068432ed1d11c5bc71eec4e88e357ec3052967e6ffde2b41b7c87d734'
sha = lambda b: hashlib.sha256(b).hexdigest()


def check(v, message):
    if not v:
        raise ValueError(message)


def unique_object(items):
    result = {}
    for k, v in items:
        check(k not in result, 'Duplicate JSON key: ' + k)
        result[k] = v
    return result


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique_object)


def number(v):
    check(isinstance(v, (str, int)) and not isinstance(v, bool), 'Bad number type')
    return int(v, 16 if isinstance(v, str) and v.startswith('0x') else 10) if isinstance(v, str) else v


def digest_matches(raw, expected):
    check(isinstance(expected, str) and re.fullmatch('[0-9a-f]{64}', expected) is not None, 'Invalid SHA256 field')
    check(sha(raw) == expected, 'SHA256 mismatch')


def artifact(root, name):
    check(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_.-]+', name) is not None and name not in ('.', '..'), 'Unsafe artifact filename')
    p = root / name
    check(not p.is_symlink() and p.resolve().parent == root.resolve(), 'Artifact escapes output')
    return p


def executable_loads(raw):
    check(len(raw) >= 64 and raw[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', raw, 18)[0] == 183, 'Expected ELF64 LE AArch64')
    off = struct.unpack_from('<Q', raw, 32)[0]
    size, count = struct.unpack_from('<HH', raw, 54)
    check(size >= 56 and off <= len(raw) and size * count <= len(raw) - off, 'Program header bounds')
    result = []
    for n in range(count):
        kind, flags, fileoff, va, _, filesz, memsz, _ = struct.unpack_from('<II6Q', raw, off + n * size)
        if kind == 1:
            check(filesz <= memsz and fileoff <= len(raw) and filesz <= len(raw) - fileoff, 'Invalid PT_LOAD bounds')
            if flags & 1:
                result.append((va, va + filesz, fileoff))
    check(result, 'No executable file-backed load')
    return result


def work_rows(rows, raw, loads):
    check(isinstance(rows, list) and rows, 'Empty work rows')
    result = {}; previous = -1
    for r in rows:
        a, z, off = (number(r[k]) for k in ('address', 'end_exclusive', 'file_offset'))
        check(a >= 0 and z > a and a % 4 == z % 4 == 0 and a >= previous, 'Invalid/overlapping work range')
        check(r['address'] == hex(a) and r['end_exclusive'] == hex(z), 'Noncanonical address')
        check(r['evidence_kind'] in ('fde', 'defined_function_symbol'), 'Invalid extent evidence kind')
        check(0 <= off <= len(raw) and z - a <= len(raw) - off, 'Work source outside ELF')
        matches = [p + a - lo for lo, hi, p in loads if lo <= a < z <= hi]
        check(len(matches) == 1 and matches[0] == off, 'Source binding does not match executable PT_LOAD')
        digest_matches(raw[off:off + z - a], r['source_sha256'])
        check(hex(a) not in result, 'Duplicate work address')
        result[hex(a)] = r; previous = z
    return result


def journal_rows(raw):
    check(not raw or raw.endswith(b'\n'), 'Incomplete durable journal tail')
    result = []; seen = set()
    for line in raw.decode('utf8').splitlines():
        check(bool(line), 'Blank journal record')
        r = parse(line); a = r['address']
        check(a not in seen, 'Duplicate journal address'); seen.add(a); result.append(r)
    return result


def negatives(raw, loads, first, root):
    rejected = []
    def reject(label, call):
        try:
            call()
        except (ValueError, KeyError, TypeError, struct.error):
            rejected.append(label)
        else:
            raise ValueError('Negative control accepted: ' + label)
    reject('wrong_hash', lambda: digest_matches(b'x', '0' * 64))
    reject('outside_output_path', lambda: artifact(root, '../outside.c'))
    reject('absolute_output_path', lambda: artifact(root, 'C:/outside.c'))
    reject('duplicate_JSON_key', lambda: parse('{"status":1,"status":2}'))
    reject('journal_duplicate_address', lambda: journal_rows(b'{"address":"0x4"}\n{"address":"0x4"}\n'))
    reject('journal_partial_tail', lambda: journal_rows(b'{"address":"0x4"}'))
    bad = copy.deepcopy(first); bad['source_sha256'] = '0' * 64
    reject('wrong_original_range_hash', lambda: work_rows([bad], raw, loads))
    bad_offset = copy.deepcopy(first); bad_offset['file_offset'] = hex(number(first['file_offset']) + 4)
    reject('wrong_file_to_VA_binding', lambda: work_rows([bad_offset], raw, loads))
    reject('overlapping_work_rows', lambda: work_rows([first, first], raw, loads))
    bad_kind = copy.deepcopy(first); bad_kind['evidence_kind'] = 'guessed_function'
    reject('unsupported_extent_evidence', lambda: work_rows([bad_kind], raw, loads))
    reject('truncated_ELF', lambda: executable_loads(raw[:40]))
    return rejected


def main():
    p = argparse.ArgumentParser()
    for flag in ('elf', 'manifest', 'producer', 'engine', 'output-dir'):
        p.add_argument('--' + flag, type=Path, required=True)
    p.add_argument('--manifest-sha256', required=True); p.add_argument('--producer-sha256', required=True)
    p.add_argument('--audit-output', type=Path)
    p.add_argument('--preflight-only', action='store_true', help='Validate inputs and negative controls without requiring run outputs')
    args = p.parse_args()
    check(args.producer_sha256 == PRODUCER, 'Auditor only reviewed frozen producer SHA')
    digest_matches(args.producer.read_bytes(), PRODUCER); digest_matches(args.engine.read_bytes(), ENGINE)
    manifest_raw = args.manifest.read_bytes(); digest_matches(manifest_raw, args.manifest_sha256)
    m = parse(manifest_raw); check(m['schema_version'] == 1 and m['profile'] == PROFILE and m['engine_sha256'] == ENGINE, 'Manifest identity mismatch')
    check(m['limits'] == dict(timeout_seconds=20, max_instructions=100000, max_payload_mb=64), 'Manifest options mismatch')
    elf_raw = args.elf.read_bytes(); digest_matches(elf_raw, m['elf_sha256'])
    loads = executable_loads(elf_raw); rows = work_rows(m['rows'], elf_raw, loads)
    controls = negatives(elf_raw, loads, m['rows'][0], args.output_dir)
    summary = dict(integrity_passed=True, scope='Persisted artifact, explicit model and original-byte association; not C syntax/CFG/semantics proof',
                   producer_sha256=PRODUCER, engine_sha256=ENGINE, manifest_sha256=args.manifest_sha256,
                   ELF_sha256=m['elf_sha256'], total_manifest_rows=len(rows),
                   negative_controls_rejected=controls, auditor_sha256=sha(Path(__file__).read_bytes()),
                   preflight_only=args.preflight_only, original_source_recovered=False, semantic_equivalence_verified=False)
    if not args.preflight_only:
        root = args.output_dir.resolve(); run = parse(artifact(root, 'run.json').read_bytes())
        for k, v in dict(profile=PROFILE, manifest_sha256=args.manifest_sha256, script_sha256=PRODUCER, engine_sha256=ENGINE,
                         elf_sha256=m['elf_sha256'], image_base=0, timeout_seconds=20, max_instructions=100000,
                         max_payload_mb=64, normal_decompile_action=True, default_imported_types=True, workers=1,
                         language='AARCH64:LE:64:v8A').items():
            check(type(run[k]) is type(v) and run[k] == v, 'Run option mismatch: ' + k)
        check(isinstance(run['compiler_spec'], str) and run['compiler_spec'] and isinstance(run['ghidra_version'], str) and run['ghidra_version'], 'Missing compiler/version identity')
        digest_matches(artifact(root, 'manifest.input.json').read_bytes(), args.manifest_sha256)
        digest_matches(artifact(root, 'ApkNativeRangeExport.java').read_bytes(), PRODUCER)
        journal_raw = artifact(root, 'journal.jsonl').read_bytes(); commits = journal_rows(journal_raw)
        counts = collections.Counter(); texts = []; associated = 0
        for c in commits:
            check(c['address'] in rows, 'Journal references unknown row'); r = rows[c['address']]
            check(c['result_file'] == 'range_' + c['address'] + '.json', 'Wrong result filename')
            result_raw = artifact(root, c['result_file']).read_bytes(); digest_matches(result_raw, c['result_sha256']); result = parse(result_raw)
            for k, v in dict(profile=PROFILE, manifest_sha256=args.manifest_sha256, script_sha256=PRODUCER,
                             engine_sha256=ENGINE, elf_sha256=m['elf_sha256'], timeout_seconds=20,
                             new_flow_overrides_applied=False, new_NoReturn_annotations_applied=False,
                             normal_decompile_action=True, semantic_equivalence_verified=False,
                             transaction_rollback_requested=True).items():
                check(type(result[k]) is type(v) and result[k] == v, 'Result model mismatch: ' + k)
            for k in ('address', 'end_exclusive', 'source_sha256', 'evidence_kind'):
                check(result[k] == r[k], 'Result range/source mismatch')
            check(result.get('original_source_recovered', False) is False, 'Unsupported source recovery claim')
            status = result['status']; check(status in ('decompiled', 'decompile_failed', 'range_error'), 'Unexpected result status')
            expected_c = 'range_' + c['address'] + '.c'; cp = artifact(root, expected_c)
            if status != 'range_error':
                check(result['decompiler_invoked'] is True and type(result['timed_out']) is bool
                      and type(result['decompile_completed']) is bool and type(result['actual_C_object_returned']) is bool, 'Missing actual decompiler outcome flags')
                check(result['original_instruction_bytes_verified'] == number(r['end_exclusive']) - number(r['address'])
                      and result['bounded_instruction_count'] == result['original_instruction_bytes_verified'] // 4, 'Range/listing count mismatch')
                check(isinstance(result['elapsed_seconds'], (float, int)) and result['elapsed_seconds'] >= 0, 'Invalid elapsed time')
            if status == 'decompiled':
                check(result['decompile_completed'] is True and result['actual_C_object_returned'] is True and result['timed_out'] is False, 'Invalid success flags')
                check(result['c_file'] == expected_c, 'Unexpected C name'); c_raw = cp.read_bytes(); digest_matches(c_raw, result['c_sha256'])
                check(len(c_raw) == result['c_bytes'] and c_raw.startswith(b'/* GHIDRA PSEUDOCODE; NOT ORIGINAL SOURCE.'), 'C size/header mismatch')
                text = c_raw.decode('utf8', 'strict'); warnings = [dict(line=i, text=l.strip()) for i, l in enumerate(text.splitlines(), 1) if 'WARNING:' in l]
                texts.append(dict(address=c['address'], c_sha256=result['c_sha256'], bytes=len(c_raw), warning_lines=warnings,
                                  limited_marker_counts={k: len(re.findall(re.escape(k), text)) for k in ('UNIMPLEMENTED', 'halt_baddata', 'BADSPACE')},
                                  text_scan_scope='Literal text markers only; comments/literals not parsed; not a compiler or semantic check'))
                associated += number(r['end_exclusive']) - number(r['address'])
            else:
                check(not cp.exists(), 'Failure row has C artifact')
                if status == 'decompile_failed':
                    check(not (result['decompile_completed'] and result['actual_C_object_returned'] and not result['timed_out']), 'Failure contradicts successful C outcome')
                else:
                    check(isinstance(result.get('message'), str) and result['message'], 'Range error missing reason')
            counts[status] += 1
        expected_artifacts = {c['result_file'] for c in commits} | {'range_' + t['address'] + '.c' for t in texts}
        orphan = sorted(x.name for x in root.glob('range_*') if x.name not in expected_artifacts)
        summary.update(journal_sha256=sha(journal_raw), attempted_rows=len(commits), not_attempted_rows=len(rows)-len(commits),
                       all_rows_attempted=len(commits)==len(rows), status_counts=dict(counts), C_text_scans=texts,
                       successful_export_associated_input_bytes=associated, unjournaled_artifacts=orphan,
                       unjournaled_artifacts_counted_as_exports=False, saved_project_rollback_independently_verified=False,
                       program_memory_byte_comparison_independently_observed=False)
    if args.audit_output:
        check(not args.audit_output.exists(), 'Fresh audit output required')
        args.audit_output.write_text(json.dumps(summary, indent=2)+'\n', encoding='utf8')
    print(json.dumps({k:v for k,v in summary.items() if k != 'C_text_scans'}))


if __name__ == '__main__':
    main()
