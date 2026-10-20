"""Read-only DEX definition universe and conservative JADX file-candidate ledger.

Never infers a recovered Java method from a file, name occurrence or warning count.
"""
import argparse
import collections
import csv
import hashlib
import json
import re
import struct
import zipfile
import zlib
from pathlib import Path

APK_SHA = '1f8e2ba7ddabaee961a1b2552d44bc0c281c9b5122480642b018779bcbf2fe8e'
DEX_SHA = '4305905906ef49bd628b86a26e3bb3b379f55715d9597132430d462c77eccb90'
sha = lambda b: hashlib.sha256(b).hexdigest()


def need(value, message):
    if not value:
        raise ValueError(message)


def uleb(data, pos):
    value = 0
    for n in range(5):
        need(pos < len(data), 'Truncated ULEB128')
        byte = data[pos]; pos += 1
        need(n != 4 or byte <= 15, 'ULEB128 overflow')
        value |= (byte & 127) << (7 * n)
        if byte < 128:
            return value, pos
    raise ValueError('Unterminated ULEB128')


def parse_dex(data):
    need(len(data) >= 112 and data[:8] == b'dex\n035\0', 'Expected complete DEX035')
    need(struct.unpack_from('<I', data, 32)[0] == len(data), 'DEX file_size mismatch')
    need(struct.unpack_from('<II', data, 36) == (112, 0x12345678), 'DEX header/endian mismatch')
    need(hashlib.sha1(data[32:]).digest() == data[12:32], 'DEX SHA1 mismatch')
    need(zlib.adler32(data[12:]) & 0xffffffff == struct.unpack_from('<I', data, 8)[0], 'DEX Adler32 mismatch')

    def bounds(off, size):
        need(0 <= off <= len(data) and 0 <= size <= len(data) - off, 'DEX range outside file')

    def uint(off):
        bounds(off, 4)
        return struct.unpack_from('<I', data, off)[0]

    tables = {}
    for name, at, stride in [('strings', 56, 4), ('types', 64, 4), ('protos', 72, 12),
                             ('fields', 80, 8), ('methods', 88, 8), ('classes', 96, 32)]:
        count, off = struct.unpack_from('<II', data, at)
        bounds(off, count * stride)
        need(not count or off >= 112, 'DEX table overlaps header')
        tables[name] = count, off

    strings = []
    for n in range(tables['strings'][0]):
        off = uint(tables['strings'][1] + n * 4)
        count, pos = uleb(data, off)
        units = []
        while True:
            bounds(pos, 1)
            b = data[pos]; pos += 1
            if b == 0:
                break
            if b < 128:
                units.append(b)
            elif 0xc0 <= b < 0xe0:
                bounds(pos, 1); c = data[pos]; pos += 1
                need(c & 0xc0 == 0x80, 'Invalid MUTF8 continuation')
                v = ((b & 31) << 6) | (c & 63)
                need(v >= 128 or (b == 0xc0 and c == 0x80), 'Invalid MUTF8 overlong')
                units.append(v)
            else:
                need(0xe0 <= b < 0xf0, 'Invalid MUTF8 lead')
                bounds(pos, 2); c, d = data[pos:pos + 2]; pos += 2
                need(c & 0xc0 == d & 0xc0 == 0x80, 'Invalid MUTF8 continuation')
                v = ((b & 15) << 12) | ((c & 63) << 6) | (d & 63)
                need(v >= 2048, 'Invalid MUTF8 overlong')
                units.append(v)
        need(len(units) == count, 'DEX string UTF16 length mismatch')
        strings.append(b''.join(struct.pack('<H', u) for u in units).decode('utf-16-le', 'surrogatepass'))

    def indexed(items, index):
        need(0 <= index < len(items), 'DEX index outside table')
        return items[index]

    types = [indexed(strings, uint(tables['types'][1] + i * 4)) for i in range(tables['types'][0])]
    protos = []
    for i in range(tables['protos'][0]):
        shorty, ret, params = struct.unpack_from('<III', data, tables['protos'][1] + i * 12)
        indexed(strings, shorty)
        args = []
        if params:
            count = uint(params); bounds(params + 4, count * 2)
            args = [indexed(types, struct.unpack_from('<H', data, params + 4 + n * 2)[0]) for n in range(count)]
        protos.append('(' + ''.join(args) + ')' + indexed(types, ret))
    refs = []
    for i in range(tables['methods'][0]):
        cls, proto, name = struct.unpack_from('<HHI', data, tables['methods'][1] + i * 8)
        refs.append((indexed(types, cls), indexed(strings, name), indexed(protos, proto)))

    definitions = []; classes = []; seen_methods = set(); seen_classes = set()
    for i in range(tables['classes'][0]):
        idx, flags, sup, interfaces, source, ann, classdata, static = struct.unpack_from('<8I', data, tables['classes'][1] + i * 32)
        owner = indexed(types, idx)
        need(owner not in seen_classes, 'Duplicate DEX class')
        seen_classes.add(owner)
        source_file = indexed(strings, source) if source != 0xffffffff else None
        classes.append(dict(descriptor=owner, access_flags=flags, source_file=source_file))
        if not classdata:
            continue
        pos = classdata; counts = []
        for _ in range(4):
            v, pos = uleb(data, pos); counts.append(v)
        for count in counts[:2]:
            field = 0
            for n in range(count):
                diff, pos = uleb(data, pos); access, pos = uleb(data, pos); field += diff
                need(field < tables['fields'][0] and (n == 0 or diff > 0), 'Invalid encoded field')
        for kind, count in zip(('direct', 'virtual'), counts[2:]):
            method_id = 0
            for n in range(count):
                diff, pos = uleb(data, pos); access, pos = uleb(data, pos); code, pos = uleb(data, pos)
                method_id += diff
                need(method_id not in seen_methods and (n == 0 or diff > 0), 'Duplicate or unordered DEX method')
                cls, name, proto = indexed(refs, method_id)
                need(cls == owner, 'Encoded method class mismatch')
                seen_methods.add(method_id)
                native, abstract = bool(access & 0x100), bool(access & 0x400)
                need(not (native and abstract), 'Native and abstract method')
                need(bool(code) == (not native and not abstract), 'Method code/access mismatch')
                r = dict(method_id=method_id, descriptor=cls + '->' + name + proto,
                         declaring_class=cls, method_name=name, proto=proto, access_flags=access,
                         definition_kind=kind, native=native, abstract=abstract,
                         concrete=not abstract, code_offset=code, dex_source_file=source_file)
                if code:
                    need(code % 4 == 0, 'Unaligned code_item')
                    bounds(code, 16)
                    registers, ins, outs, tries, debug, insns = struct.unpack_from('<4H2I', data, code)
                    bounds(code + 16, insns * 2)
                    r.update(code_units=insns, instruction_bytes_sha256=sha(data[code + 16:code + 16 + insns * 2]),
                             code_item_header_sha256=sha(data[code:code + 16]), tries_size=tries,
                             code_hash_scope='16-byte header separately; instruction array only, excluding padding/try/handler/debug data')
                definitions.append(r)
    return classes, sorted(definitions, key=lambda r: r['method_id']), tables


def seal(data):
    data = bytearray(data)
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into('<I', data, 8, zlib.adler32(data[12:]) & 0xffffffff)
    return bytes(data)


def negative_checks(data):
    controls = {}
    variants = [('truncated_header', data[:100]), ('bad_magic', b'bad!' + data[4:]),
                ('bad_SHA1', data[:12] + bytes([data[12] ^ 1]) + data[13:]),
                ('bad_Adler32', data[:8] + b'\0\0\0\0' + data[12:])]
    for label, offset, value in [('wrong_file_size', 32, len(data) + 4), ('bad_endian', 40, 0x78563412),
                                 ('string_table_outside_file', 60, len(data) - 1),
                                 ('method_table_header_overlap', 92, 0),
                                 ('class_table_outside_file', 100, len(data))]:
        bad = bytearray(data); struct.pack_into('<I', bad, offset, value)
        variants.append((label, seal(bad)))
    for label, bad in variants:
        try:
            parse_dex(bad)
        except (ValueError, struct.error):
            controls[label] = 'rejected'
        else:
            raise ValueError('Negative input accepted: ' + label)
    for label, bad in [('truncated_uleb', b'\x80'), ('overflow_uleb', b'\xff\xff\xff\xff\x10')]:
        try:
            uleb(bad, 0)
        except ValueError:
            controls[label] = 'rejected'
        else:
            raise ValueError('Negative input accepted: ' + label)
    return controls


def source_index(root):
    files = []; keys = collections.defaultdict(set)
    for p in sorted(root.rglob('*.java')):
        raw = p.read_bytes(); text = raw.decode('utf8', 'strict')
        package = re.search(r'^package\s+([\w.$]+)\s*;', text, re.M)
        pkg = package[1] if package else ''
        rel = p.relative_to(root).as_posix()
        # File evidence only; comments/name/path do not prove DEX ownership.
        warnings = [dict(line=n, text=line.strip()) for n, line in enumerate(text.splitlines(), 1) if 'JADX WARN' in line or 'JADX ERROR' in line]
        files.append(dict(path=rel, sha256=sha(raw), bytes=len(raw), declared_package=pkg,
                          candidate_key=[pkg, p.stem], warnings=warnings,
                          warning_attribution='file-only; no method attribution',
                          JADX_loaded_from_classes_dex_marker='loaded from: classes.dex' in text))
        keys[(pkg, p.stem)].add(rel)
    return files, keys


def candidates(row, keys):
    owner = row['declaring_class']
    need(owner.startswith('L') and owner.endswith(';'), 'Bad class descriptor')
    binary = owner[1:-1]; package, _, simple = binary.rpartition('/')
    package = package.replace('/', '.')
    outer = simple.split('$', 1)[0]
    matches = set(keys.get((package, simple), ())) | set(keys.get((package, outer), ()))
    source = row['dex_source_file']
    if source and source.endswith('.java') and '/' not in source and '\\' not in source:
        matches |= set(keys.get((package, source[:-5]), ()))
    return sorted(matches)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--apk', type=Path, required=True); ap.add_argument('--lab', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    need(not args.output.exists(), 'Fresh output directory required')
    apk = args.apk.read_bytes(); need(sha(apk) == APK_SHA, 'APK identity mismatch')
    dex_path = args.lab / 'android/classes.dex'; data = dex_path.read_bytes()
    need(sha(data) == DEX_SHA, 'Extracted DEX identity mismatch')
    with zipfile.ZipFile(args.apk) as z:
        need([n for n in z.namelist() if re.fullmatch(r'classes\d*\.dex', n)] == ['classes.dex'], 'Unexpected DEX universe')
        need(z.read('classes.dex') == data, 'APK/extracted DEX differ')
    classes, rows, tables = parse_dex(data)
    previous = json.loads((args.lab / 'android/classes.dex.json').read_text())
    need((len(classes), len(rows), sum(bool(r['code_offset']) for r in rows), sum(r['native'] for r in rows)) ==
         (previous['class_definition_count'], previous['method_definition_count'], previous['methods_with_code'], previous['native_method_count']), 'Prior count cross-check mismatch')
    need(len({r['descriptor'] for r in rows}) == len(rows), 'Duplicate method descriptor')
    controls = negative_checks(data)
    files, keys = source_index(args.lab / 'jadx/sources')
    for r in rows:
        found = candidates(r, keys)
        r.update(candidate_source_files=found, source_evidence_status='candidate_file_only' if found else 'no_candidate_by_bounded_key',
                 recovered_Java_method_verified=False, exact_source_method_signature_verified=False,
                 source_method_warning_attribution_verified=False,
                 matching_scope='declared package plus binary/outer/source-file stem only; no rename reversal, Java parsing, signature or body match',
                 unresolved_reason='native declaration has no DEX implementation; JNI body is separate' if r['native'] else
                 'abstract declaration has no DEX code body' if r['abstract'] else
                 'candidate file cannot establish method presence, signature or code completeness; nested/synthetic/renamed classes may be merged or moved' if found else
                 'no exact package-and-stem candidate; renaming, nested/synthetic transformations or missing output not distinguished')
    # Candidate index controls: shared outer file must not become a verified method.
    fake = dict(declaring_class='Lx/Outer$1;', dex_source_file=None)
    need(candidates(fake, {('x', 'Outer'): {'x/Outer.java'}}) == ['x/Outer.java'], 'Nested candidate positive control')
    need(not candidates(fake, {('y', 'Outer'): {'y/Outer.java'}}), 'Package mismatch candidate accepted')
    controls['candidate_wrong_package'] = 'rejected'
    controls['source_file_presence_promotion'] = 'rejected_by_all_rows_verified_false_policy'
    summary = dict(schema=1, scope='DEX method definition universe plus bounded candidate-file evidence; not Java method decompilation coverage',
                   APK_sha256=APK_SHA, DEX_sha256=DEX_SHA, APK_extracted_DEX_byte_identical=True,
                   parser_sha256=sha(Path(__file__).read_bytes()), class_definitions=len(classes), method_definitions=len(rows),
                   concrete_definitions=sum(r['concrete'] for r in rows), methods_with_code=sum(bool(r['code_offset']) for r in rows),
                   native_declarations=sum(r['native'] for r in rows), abstract_declarations=sum(r['abstract'] for r in rows),
                   method_reference_count=tables['methods'][0], prior_catalog_counts_crosschecked=True,
                   jadx_source_files=len(files), candidate_file_evidence_counts=dict(collections.Counter(r['source_evidence_status'] for r in rows)),
                   code_method_candidate_file_evidence_counts=dict(collections.Counter(r['source_evidence_status'] for r in rows if r['code_offset'])),
                   exact_signature_to_source_verified=0, Java_method_body_recovery_verified=0,
                   unknown_code_method_body_status=sum(bool(r['code_offset']) for r in rows),
                   JADX_WARN_lines=sum(sum('JADX WARN' in w['text'] for w in f['warnings']) for f in files),
                   source_files_with_warnings=sum(bool(f['warnings']) for f in files), warning_method_attribution_verified=0,
                   negative_controls=controls, semantic_equivalence_verified=False,
                   limitations=['DEX instruction hashes exclude try/handler/debug payload; not CFG/semantic analysis',
                                'No exact Java signature/body association is claimed; all concrete code method recovery statuses remain unknown',
                                'Candidate paths are hints and cannot prove original-to-renamed class identity',
                                'Warnings attributed only to source files, never to DEX methods',
                                'No new JADX execution; source-file hashes describe existing local artifacts'])
    args.output.mkdir(parents=True)
    for name, records in [('methods.jsonl', rows), ('source-files.jsonl', files), ('classes.jsonl', classes)]:
        with (args.output / name).open('w', encoding='utf8', newline='\n') as f:
            for r in records:
                f.write(json.dumps(r, ensure_ascii=True) + '\n')
    with (args.output / 'methods.tsv').open('w', encoding='utf8', newline='') as f:
        writer = csv.writer(f, delimiter='\t', lineterminator='\n')
        writer.writerow(['method_id', 'descriptor', 'flags', 'code_offset', 'native', 'abstract', 'source_evidence_status', 'candidate_source_files', 'Java_body_verified'])
        for r in rows:
            writer.writerow([r['method_id'], r['descriptor'], hex(r['access_flags']), hex(r['code_offset']), r['native'], r['abstract'], r['source_evidence_status'], json.dumps(r['candidate_source_files']), False])
    (args.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf8')
    manifest = dict(inputs=[dict(path=str(p), sha256=sha(p.read_bytes())) for p in [args.apk, dex_path, args.lab/'android/classes.dex.json', args.lab/'android/dexdump.txt', Path(__file__)]],
                    outputs=[dict(name=p.name, bytes=p.stat().st_size, sha256=sha(p.read_bytes())) for p in sorted(args.output.iterdir())])
    (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf8')
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
