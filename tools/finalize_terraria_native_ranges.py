"""Finalize an existing complete native journal, after stopping its Java writer.

No decompilation, Program reopening, ledger changes or C-file changes occur.
The separate audit_terraria_native_ranges.py must still run afterward.
"""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import uuid

MODEL = 'bounded-fde-terminal-calls-signatures-v3'
PROFILE = 'native-ranges-readonly-v3-journal-1'
ELF_SHA = '9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
TITLE = 'NATIVE RANGE PSEUDOCODE; NOT ORIGINAL SOURCE'
TOTAL, MANAGED, FDES = 29162, 93990, 123152


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load(path):
    return json.loads(path.read_text(encoding='utf-8'))


def address(value):
    require(isinstance(value, str) and re.fullmatch(r'0x[0-9a-f]+', value), 'Noncanonical address')
    return int(value, 16)


def confined(out, relative):
    require(isinstance(relative, str) and relative and '\\' not in relative, 'Invalid artifact path')
    path = (out/relative).resolve()
    require(path.is_relative_to(out) and path.is_file(), 'Missing/escaping artifact: '+relative)
    return path


def comment(value):
    return value.replace('*/', '* /').replace('\r', ' ').replace('\n', ' ')


def native_header(row):
    roles = json.dumps(row['classification']['roles'], ensure_ascii=False, separators=(',', ':'))
    # Gson's default HTML escaping is part of the original Java header identity.
    for source, target in [('&', '\\u0026'), ('<', '\\u003c'), ('>', '\\u003e'), ('=', '\\u003d'), ("'", '\\u0027')]:
        roles = roles.replace(source, target)
    roles = roles.replace('\u2028', '\\u2028').replace('\u2029', '\\u2029')
    return (f'/* {TITLE}\n * Native function label: {comment(row["function_name"])}'
            f'\n * ELF VA: {row["address"]}; image base: 0\n * Compiler FDE end-exclusive: {row["compiler_end_exclusive"]}'
            f'\n * Analysis model: {MODEL}\n * Export profile: {PROFILE}'
            f'\n * Classification: {comment(row["classification"]["category"])}; roles: {comment(roles)}'
            f'\n * Native bytes SHA256: {row["source_bytes_sha256"]}\n */\n').encode('utf-8')


def aggregate_data(data, expected_header):
    lines = data.decode('utf-8').splitlines()
    require(lines and lines[0] == expected_header, 'Per-range TSV header mismatch')
    return ''.join(line+'\r\n' for line in lines[1:]).encode('utf-8')


def check_artifacts(out, row):
    header = native_header(row)
    require(sha(header) == row['header_sha256'], 'Reconstructed header identity mismatch: '+row['address'])
    tables = []
    paths = []
    for kind, table_header in [('asm', 'range_entry\tinstruction_address\tbytes\tinstruction'), ('calls', 'caller\tsource\ttarget\ttype')]:
        path = confined(out, row[kind+'_file'])
        paths.append(path)
        data = path.read_bytes()
        require(sha(data) == row[kind+'_sha256'], 'Artifact SHA mismatch: '+str(path))
        tables.append(aggregate_data(data, table_header))
    if row['status'] == 'decompiled':
        path = confined(out, row['file'])
        paths.append(path)
        data = path.read_bytes()
        require(sha(data) == row['file_sha256'], 'C artifact SHA mismatch: '+str(path))
        require(data.startswith(header) and data[len(header):].strip(), 'C header/body invalid: '+str(path))
    else:
        require(row['file'] == row['file_sha256'] == '', 'Failed row claims C artifact')
    return tables, paths


def elf_reader(path):
    data = path.read_bytes()
    require(sha(data) == ELF_SHA, 'Original ELF SHA mismatch')
    require(data[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', data, 18)[0] == 183, 'Wrong ELF ABI')
    offset = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    segments = []
    for i in range(count):
        kind, _, file_offset, va, _, filesz, _, _ = struct.unpack_from('<II6Q', data, offset+i*size)
        if kind == 1:
            require(file_offset+filesz <= len(data), 'ELF LOAD exceeds file')
            segments.append((va, va+filesz, file_offset))
    def read(a, end):
        matches = [(lo, off) for lo, hi, off in segments if lo <= a < end <= hi]
        require(len(matches) == 1, 'FDE lacks unique original LOAD')
        lo, off = matches[0]
        return data[off+a-lo:off+end-lo]
    return read


def finalize(args):
    require(args.writer_stopped, 'Stop the Java writer first and pass --writer-stopped')
    lab = args.lab.resolve()
    out = (lab/'native-ranges-pseudocode').resolve()
    native = lab/'native'
    baseline = args.baseline.resolve()
    engine = args.engine.resolve()
    manifest_path, journal = out/'manifest.json', out/'coverage.jsonl'
    classification_path, fde_path = native/'unmapped-fde-classification.json', native/'unwind-function-ranges.tsv'
    snapshots = {p: file_sha(p) for p in [manifest_path, journal, classification_path, fde_path, baseline, engine]}
    manifest = load(manifest_path)
    for key, value in dict(schema=1, profile=PROFILE, model=MODEL, elf_sha256=ELF_SHA, total=TOTAL, language='AARCH64:LE:64:v8A', compiler_spec='default', image_base=0, workers=4, batch_size=4096, max_instructions=100000, max_payload_mb=64, header_title=TITLE, ghidra_version='12.1.4').items():
        require(manifest.get(key) == value, 'Manifest mismatch: '+key)
    require(manifest['timeout_seconds'] in (15, 30), 'Unknown producer timeout')
    require(re.fullmatch('[0-9a-f]{64}', manifest.get('program_snapshot_sha256', '')), 'Missing producer snapshot fingerprint')
    for path, key in [(classification_path, 'classification_sha256'), (fde_path, 'fde_tsv_sha256'), (baseline, 'managed_baseline_sha256'), (engine, 'decompiler_engine_sha256')]:
        require(snapshots[path] == manifest[key], 'Pinned provenance mismatch: '+key)
    read_elf = elf_reader(native/'libil2cpp.so')
    fdes = {}
    for line in fde_path.read_text(encoding='utf-8').splitlines():
        fields = line.split('\t')
        require(len(fields) == 2, 'Invalid FDE row')
        a, end = map(address, fields)
        require(a not in fdes and a < end, 'Duplicate/invalid FDE')
        fdes[a] = end
    require(len(fdes) == FDES, 'Incomplete FDE catalog')
    ordered = sorted(fdes)
    require(all(fdes[a] <= b for a, b in zip(ordered, ordered[1:])), 'Overlapping FDEs')
    managed = set()
    with baseline.open(encoding='utf-8') as stream:
        for line in stream:
            r = json.loads(line)
            a = address(r['address'])
            require(a not in managed and r['profile'] == MODEL and r['image_base'] == 0 and address(r['compiler_end_exclusive']) == fdes.get(a), 'Invalid complete managed baseline')
            managed.add(a)
    require(len(managed) == MANAGED, 'Incomplete managed baseline')
    classes = load(classification_path)
    class_map = {address(c['address']): c for c in classes}
    require(len(classes) == len(class_map) == TOTAL and class_map.keys() == fdes.keys()-managed, 'Native/managed partition mismatch')
    raw_journal = journal.read_bytes()
    require(raw_journal.endswith(b'\n'), 'Journal lacks durable final newline; no repair permitted')
    rows = {}
    statuses = Counter()
    for line in raw_journal.splitlines():
        r = json.loads(line)
        a, end = address(r['address']), address(r['compiler_end_exclusive'])
        require(a not in rows and a in class_map and end == fdes[a], 'Unexpected/duplicate journal range')
        require(r['classification'] == class_map[a] and class_map[a]['size'] == r['compiler_size'] == end-a and address(class_map[a]['end_exclusive']) == end, 'Classification/FDE identity mismatch')
        for key, value in dict(profile=PROFILE, model=MODEL, image_base=0, timeout_seconds=manifest['timeout_seconds'], max_instructions=100000).items():
            require(r.get(key) == value, 'Journal profile mismatch: '+key)
        require(r['source_bytes_sha256'] == sha(read_elf(a, end)), 'Original FDE byte SHA mismatch')
        require(r['status'] in ('decompiled', 'decompile_failed', 'missing_function', 'export_error'), 'Unknown row status')
        rows[a] = r
        statuses[r['status']] += 1
    require(rows.keys() == class_map.keys() and len(rows) == TOTAL, 'Incomplete native journal')
    staged = []
    token = '.finalize-'+uuid.uuid4().hex
    asm_path, calls_path = out/('instructions.tsv'+token), out/('calls.tsv'+token)
    staged.extend([asm_path, calls_path])
    artifacts = set()
    expected_c = set()
    try:
        with asm_path.open('wb') as asm, calls_path.open('wb') as calls, ThreadPoolExecutor(max_workers=16) as pool:
            asm.write(b'range_entry\tinstruction_address\tbytes\tinstruction\n')
            calls.write(b'caller\tsource\ttarget\ttype\n')
            # Producer aggregates in original classification order, not completion order.
            sequence = [rows[address(c['address'])] for c in classes]
            for start in range(0, TOTAL, 512):
                batch = sequence[start:start+512]
                for r, (tables, paths) in zip(batch, pool.map(lambda r: check_artifacts(out, r), batch)):
                    require(not artifacts.intersection(paths) and len(paths) == len(set(paths)), 'Artifact reused across rows')
                    artifacts.update(paths)
                    if r['status'] == 'decompiled':
                        expected_c.add(paths[-1])
                    asm.write(tables[0])
                    calls.write(tables[1])
                print(f'Validated {min(start+512,TOTAL)}/{TOTAL}', flush=True)
            asm.flush(); os.fsync(asm.fileno())
            calls.flush(); os.fsync(calls.fileno())
        require({p.resolve() for p in out.rglob('*.c')} == expected_c, 'Unreferenced C artifact')
        require(all(file_sha(p) == value for p, value in snapshots.items()), 'Pinned input changed during finalization; writer may still be active')
        info = dict(tool_sha256=file_sha(Path(__file__)), noNewDecompilation=True, program_snapshot_reopened=False, program_snapshot_fingerprint_independently_recomputed=False, engine_sha256_independently_checked=True, validation_workers=16, validation_batch_size=512, producer_manifest_sha256=snapshots[manifest_path], note='Only persisted journal/artifact identities checked; separate semantic/byte/call audit remains required.')
        counts = dict(decompiled=statuses['decompiled'], failed=statuses['decompile_failed'], missing=statuses['missing_function'], export_error=statuses['export_error'])
        summary = dict(manifest, **counts, coverage_sha256=snapshots[journal], instructions_sha256=file_sha(asm_path), calls_sha256=file_sha(calls_path), finished=True, finalizer=info)
        progress = dict(finished=True, phase='complete', profile=PROFILE, model=MODEL, workers=4, batch_size=4096, total=TOTAL, processed=TOTAL, completed=TOTAL, **counts, resumed=TOTAL, timeout_seconds=manifest['timeout_seconds'], max_instructions=100000, error='', finalizer=info)
        for name, value in [('summary.json', summary), ('progress.json', progress)]:
            path = out/(name+token)
            staged.append(path)
            with path.open('wb') as stream:
                stream.write((json.dumps(value, ensure_ascii=False, separators=(',', ':'))+'\n').encode('utf-8'))
                stream.flush(); os.fsync(stream.fileno())
        # Publish complete marker last. Ledger, manifest and per-function outputs stay untouched.
        for path, destination in zip(staged, ['instructions.tsv', 'calls.tsv', 'summary.json', 'progress.json']):
            os.replace(path, out/destination)
        return dict(complete=True, **counts, finalizer=info)
    finally:
        for path in staged:
            if path.is_file():
                path.unlink()


def self_test():
    r = dict(function_name='n*/x', address='0x10', compiler_end_exclusive='0x14', source_bytes_sha256='0'*64, classification=dict(category='unknown', roles=['a<b']))
    header = native_header(r)
    require(b'n* /x' in header and b'["a\\u003cb"]' in header, 'Header escaping regression')
    require(aggregate_data(b'a\tb\nx\ty\nz\tw\r\n', 'a\tb') == b'x\ty\r\nz\tw\r\n', 'Producer newline/order regression')
    try:
        aggregate_data(b'wrong\n', 'expected')
    except ValueError:
        pass
    else:
        raise ValueError('TSV gate failed')
    print('Self-test passed: exact header escaping and producer aggregate newline/order rules')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab', type=Path)
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--engine', type=Path)
    parser.add_argument('--writer-stopped', action='store_true')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        self_test()
    else:
        parser.error('--lab, --baseline and --engine are required') if not all([args.lab, args.baseline, args.engine]) else None
        print(json.dumps(finalize(args), indent=2))
