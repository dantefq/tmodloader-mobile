"""Classify retained HighFunction instruction sites using original ELF bytes only.

No native engine, target execution, function extent expansion or export mutation.
"""
import argparse
import bisect
from collections import Counter
import copy
import hashlib
import json
from pathlib import Path
import struct

SHA = lambda b: hashlib.sha256(b).hexdigest()
ELF_SHA = '7e850163b92735b7b7307fb2919fb8064d5740cc0597b5e7c6a35d8454159df8'
AUDIT_SHA = '09fed5b4e833fc4ddd0503eb97809a4bd4dd734cc956f6dd680bef6d3d06a57b'
MANIFEST_SHA = 'c1ba2b0a384ed1af5ca1ae7e6d5a3eefc7aa8af6d0643370d13ae476abf9b264'
PARSER_SHA = 'b3fc8f7a171a177f97cf7b8be5d1514e312daf8d9661a32851bd800e2edffd3a'
PARSER_PATH = Path(__file__).with_name('prove_libmain_stackchk_import.py')
if SHA(PARSER_PATH.read_bytes()) != PARSER_SHA:
    raise ValueError('Pinned ELF parser changed')
from prove_libmain_stackchk_import import ELF, plt_effects


def check(ok, message):
    if not ok:
        raise ValueError(message)


def unique(pairs):
    d = {}
    for k, v in pairs:
        check(k not in d, 'Duplicate JSON key')
        d[k] = v
    return d


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique)


def bound_hash(raw, expected):
    check(SHA(raw) == expected, 'Pinned hash mismatch')


def direct_branch(word, pc):
    check(word & 0x7c000000 == 0x14000000, 'Not B/BL immediate')
    imm = word & 0x3ffffff
    imm -= (1 << 26) if imm & (1 << 25) else 0
    return pc + imm * 4


def prove_stub(elf, start):
    plt = elf.section('.plt')
    check(start >= plt['va'] + 32 and (start - plt['va'] - 32) % 16 == 0
          and start + 16 <= plt['va'] + plt['size'], 'Not exact canonical PLT entry')
    raw = elf.read(start, 16, True)
    effects = plt_effects(struct.unpack('<4I', raw), start)
    got = elf.section('.got')
    check(got['va'] <= effects['slot'] and effects['slot'] + 8 <= got['va'] + got['size'], 'Slot outside GOT')
    return dict(address=hex(start), br_instruction_address=hex(start + 12), raw_bytes=raw.hex(),
                sha256=SHA(raw), file_offset=elf.mapping(start, 16, True), **effects)


def import_contract(rel, sym):
    check(rel['type'] == 1026 and rel['addend'] == 0, 'Not zero-addend AArch64 JUMP_SLOT')
    check(sym['shndx'] == 0 and sym['value'] == 0 and sym['binding'] in (1, 2)
          and sym['type'] == 2 and bool(sym['name']), 'Not undefined function import')


def import_slots(elf):
    sec = elf.section('.rela.plt')
    check(sec['type'] == 4 and sec['entsize'] == 24 and sec['size'] % 24 == 0, 'Invalid rela.plt')
    symbols = elf.sections[sec['link']]
    check(symbols['name'] == '.dynsym' and symbols['type'] == 11 and symbols['entsize'] == 24, 'Invalid dynsym link')
    strings = elf.sections[symbols['link']]
    check(strings['name'] == '.dynstr' and strings['type'] == 3, 'Invalid dynstr link')
    pool = elf.raw[strings['offset']:strings['offset'] + strings['size']]
    slots = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', elf.raw, off)
        index = info >> 32
        check(index * 24 + 24 <= symbols['size'], 'Symbol index outside dynsym')
        so = symbols['offset'] + index * 24
        name, attrs, other, shndx, value, size = struct.unpack_from('<IBBHQQ', elf.raw, so)
        rel = dict(slot=slot, type=info & 0xffffffff, symbol_index=index, addend=addend,
                   file_offset=off, raw_bytes=elf.raw[off:off + 24].hex())
        sym = dict(name=elf.string(pool, name), binding=attrs >> 4, type=attrs & 15,
                   shndx=shndx, value=value, size=size, visibility=other & 3,
                   file_offset=so, raw_bytes=elf.raw[so:so + 24].hex(), name_string_offset=name)
        check(slot not in slots, 'Ambiguous relocation slot')
        slots[slot] = dict(relocation=rel, symbol=sym)
    return slots


def row_branches(elf, row):
    a, z = int(row['address'], 16), int(row['end_exclusive'], 16)
    check(a % 4 == 0 and z % 4 == 0, 'Unaligned row')
    result = {}
    for pc in range(a, z, 4):
        word = struct.unpack('<I', elf.read(pc, 4, True))[0]
        if word & 0x7c000000 == 0x14000000:
            target = direct_branch(word, pc)
            result.setdefault(target, []).append(dict(pc=hex(pc), word=hex(word),
                raw_bytes=elf.read(pc, 4, True).hex(), file_offset=elf.mapping(pc, 4, True),
                opcode='BL' if word >> 31 else 'B', target=hex(target)))
    return result


def justified_bridge(site, stub, branches, slots):
    check(site == int(stub['br_instruction_address'], 16), 'Site not canonical PLT BR')
    check(int(stub['address'], 16) in branches, 'No original row B/BL targets exact PLT entry')
    imported = slots[stub['slot']]
    check(imported['relocation']['slot'] == stub['slot'], 'Relocation GOT slot mismatch')
    import_contract(imported['relocation'], imported['symbol'])
    return dict(stub=stub, direct_row_branches=branches[int(stub['address'], 16)], **imported)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--lab', type=Path, default=Path('C:/Temp/terraria-re-20261012'))
    p.add_argument('--elf', type=Path, default=Path('C:/Private/Documents/ChatGPT/Terraria-Reverse-20261012/android-native/libGNS_Wrapper.so'))
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    check(not args.output.exists(), 'Fresh output required')
    audit_path = args.lab / 'other-native-GNS-sample-v3-audit-20261019.json'
    manifest_path = args.lab / 'other-native-range-v3-manifests-20261019/libGNS_Wrapper.so.manifest.json'
    export = args.lab / 'other-native-range-c-libGNS_Wrapper-sample-v3-20261019'
    audit_raw, manifest_raw, raw = audit_path.read_bytes(), manifest_path.read_bytes(), args.elf.read_bytes()
    for b, h in [(audit_raw, AUDIT_SHA), (manifest_raw, MANIFEST_SHA), (raw, ELF_SHA)]:
        bound_hash(b, h)
    audit, manifest = parse(audit_raw), parse(manifest_raw)
    check(audit['manifest_sha256'] == MANIFEST_SHA and audit['ELF_sha256'] == ELF_SHA
          and manifest['elf_sha256'] == ELF_SHA and audit['integrity_passed'] is True, 'Input binding mismatch')
    elf = ELF(raw)
    rows = manifest['rows']
    mapping = {}
    previous_end = 0
    for row in rows:
        a, z = int(row['address'], 16), int(row['end_exclusive'], 16)
        check(previous_end <= a < z and a not in mapping, 'Overlapping/duplicate work row')
        check(elf.mapping(a, z - a, True) == int(row['file_offset'], 16), 'Range VA/file mismatch')
        bound_hash(elf.read(a, z - a, True), row['source_sha256'])
        previous_end = z
        mapping[a] = row
    # The active engine may append later rows. Bind only the exact audited
    # durable prefix; its SHA must match the immutable audit, byte for byte.
    journal_observed = (export / 'journal.jsonl').read_bytes()
    journal_raw = b''.join(journal_observed.splitlines(keepends=True)[:2000])
    bound_hash(journal_raw, audit['journal_sha256'])
    check(journal_raw.endswith(b'\n'), 'Partial journal tail')
    journal = [parse(line) for line in journal_raw.splitlines()]
    journal_map = {r['address']: r for r in journal}
    check(len(journal_map) == len(journal) == 2000, 'Journal row mismatch')
    slots = import_slots(elf)
    starts = list(mapping)
    classifications = []
    row_summaries = []
    checked_artifacts = []
    proof_example = None
    for scan in audit['C_text_scans']:
        address = scan['address']
        row = mapping[int(address, 16)]
        commit = journal_map[address]
        check(commit['result_file'] == 'range_' + address + '.json', 'Unexpected result path')
        result_raw = (export / commit['result_file']).read_bytes()
        bound_hash(result_raw, commit['result_sha256'])
        result = parse(result_raw)
        check(result['manifest_sha256'] == MANIFEST_SHA and result['elf_sha256'] == ELF_SHA
              and result['address'] == address and result['source_sha256'] == row['source_sha256']
              and result['end_exclusive'] == row['end_exclusive']
              and result['script_sha256'] == audit['producer_sha256']
              and result['engine_sha256'] == audit['engine_sha256'], 'Persisted result input binding mismatch')
        scope = scan['retained_high_pcode_scope']
        check(scope == result['retained_high_pcode_scope'], 'Audit scope differs from persisted result')
        check(result['c_file'] == 'range_' + address + '.c', 'Unexpected C path')
        c_raw = (export / result['c_file']).read_bytes()
        bound_hash(c_raw, scan['c_sha256'])
        check(result['c_sha256'] == scan['c_sha256'] and len(c_raw) == scan['bytes'], 'C association mismatch')
        checked_artifacts.append(dict(address=address, result_sha256=SHA(result_raw), c_sha256=SHA(c_raw)))
        branches = row_branches(elf, row)
        outside = []
        seen = set()
        for site in scope['retained_operation_instruction_addresses']:
            s = int(site['offset'], 16)
            key = (site['space'], s)
            check(key not in seen, 'Duplicate retained site')
            seen.add(key)
            inside = site['space'] == 'ram' and int(address, 16) <= s < int(row['end_exclusive'], 16)
            check(site['inside_manifest_range'] is inside, 'Incorrect inside attestation')
            if inside:
                continue
            record = dict(row_address=address, instruction_space=site['space'], instruction_address=hex(s), classification='unknown')
            try:
                check(site['space'] == 'ram', 'Outside site in non-RAM space')
                stub = prove_stub(elf, s - 12)
                record['canonical_PLT_candidate'] = dict(stub=stub,
                    direct_row_branches=branches.get(int(stub['address'], 16), []),
                    relocation_and_symbol=slots.get(stub['slot']))
                proof = justified_bridge(s, stub, branches, slots)
                record.update(classification='justified_PLT_bridge', static_proof=proof)
                if proof_example is None:
                    proof_example = (s, stub, branches, slots)
            except (ValueError, KeyError, struct.error) as exc:
                record['PLT_bridge_rejection'] = str(exc)
                i = bisect.bisect_right(starts, s) - 1
                if site['space'] == 'ram' and i >= 0:
                    owner = mapping[starts[i]]
                    if s < int(owner['end_exclusive'], 16):
                        record.update(classification='known_other_extent_shared_tail_candidate', other_manifest_row=owner)
            classifications.append(record)
            outside.append(record)
        check(len(outside) == scope['outside_instruction_addresses'] and len(seen) == scope['unique_instruction_addresses'], 'Retained counts mismatch')
        row_summaries.append(dict(address=address, outside_sites=len(outside), classifications=dict(Counter(r['classification'] for r in outside)),
                                  all_outside_sites_justified_PLT_bridges=bool(outside) and all(r['classification'] == 'justified_PLT_bridge' for r in outside)))
    check(len(row_summaries) == len(audit['C_text_scans']) == 2000, 'Audit row count mismatch')
    controls = []
    def reject(label, fn):
        try:
            fn()
        except (ValueError, KeyError, struct.error):
            controls.append(label)
        else:
            raise ValueError('Negative control accepted: ' + label)
    reject('wrong_ELF_hash', lambda: bound_hash(raw[:-1], ELF_SHA))
    reject('wrong_audit_hash', lambda: bound_hash(audit_raw + b' ', AUDIT_SHA))
    reject('wrong_manifest_hash', lambda: bound_hash(manifest_raw + b' ', MANIFEST_SHA))
    first = rows[0]
    source = elf.read(int(first['address'], 16), int(first['end_exclusive'], 16) - int(first['address'], 16), True)
    reject('modified_original_range_byte', lambda: bound_hash(bytes([source[0] ^ 1]) + source[1:], first['source_sha256']))
    reject('duplicate_JSON_key', lambda: parse('{"x":1,"x":2}'))
    reject('nonbranch_word', lambda: direct_branch(0xd503201f, 0))
    s, stub, branches, imp_slots = proof_example
    reject('PLT_interior_entry', lambda: prove_stub(elf, int(stub['address'], 16) + 4))
    reject('no_exact_row_branch', lambda: justified_bridge(s, stub, {}, imp_slots))
    shifted = {k + 4: v for k, v in branches.items()}
    reject('row_branch_targets_PLT_interior', lambda: justified_bridge(s, stub, shifted, imp_slots))
    reject('outside_site_not_BR', lambda: justified_bridge(s - 4, stub, branches, imp_slots))
    words = list(struct.unpack('<4I', bytes.fromhex(stub['raw_bytes'])))
    for i in range(4):
        bad = words.copy(); bad[i] = 0xd503201f
        reject('wrong_PLT_word_' + str(i), lambda bad=bad: plt_effects(bad, int(stub['address'], 16)))
    bad = words.copy(); bad[2] ^= 1 << 10
    reject('LDR_ADD_disagree', lambda: plt_effects(bad, int(stub['address'], 16)))
    imported = imp_slots[stub['slot']]
    bad_slots = copy.deepcopy(imp_slots)
    bad_slots[stub['slot']]['relocation']['slot'] += 8
    reject('wrong_relocation_GOT_binding', lambda: justified_bridge(s, stub, branches, bad_slots))
    for key, value in [('type', 1025), ('addend', 8)]:
        bad = copy.deepcopy(imported['relocation']); bad[key] = value
        reject('bad_relocation_' + key, lambda bad=bad: import_contract(bad, imported['symbol']))
    for key, value in [('shndx', 1), ('value', 4), ('type', 1), ('binding', 0)]:
        bad = copy.deepcopy(imported['symbol']); bad[key] = value
        reject('bad_import_' + key, lambda bad=bad: import_contract(imported['relocation'], bad))
    counts = dict(Counter(r['classification'] for r in classifications))
    summary = dict(integrity_passed=True, scope='Static original-byte classification of retained HighFunction instruction sites outside original extents',
        audit_sha256=AUDIT_SHA, manifest_sha256=MANIFEST_SHA, ELF_sha256=ELF_SHA, producer_sha256=SHA(Path(__file__).read_bytes()),
        audited_journal_prefix_sha256=SHA(journal_raw), audited_journal_prefix_bytes=len(journal_raw),
        current_journal_snapshot_sha256=SHA(journal_observed), current_journal_snapshot_bytes=len(journal_observed),
        pinned_ELF_parser_sha256=PARSER_SHA, original_manifest_rows_hash_verified=len(rows), audited_export_rows=2000,
        outside_row_count=sum(r['outside_sites'] > 0 for r in row_summaries), outside_site_associations=len(classifications),
        distinct_outside_sites=len(set((r['instruction_space'], r['instruction_address']) for r in classifications)), classifications=counts,
        rows_with_all_outside_sites_justified_PLT_bridges=sum(r['all_outside_sites_justified_PLT_bridges'] for r in row_summaries),
        rows_without_outside_sites=sum(r['outside_sites'] == 0 for r in row_summaries), negative_controls_rejected=controls,
        C_coverage_addition=0, semantic_equivalence_verified=False, runtime_resolution_observed=False,
        function_extent_expansion_permitted=False, all_native_visited_instructions_observed=False,
        limitations=['B/BL presence in original row is a static encoded edge, not proof of reachability or of the pcode provenance path.',
                     'PLT proof requires the retained site to be the canonical BR X17, exact original-row branch to stub entry, GOT slot and undefined function JUMP_SLOT relocation.',
                     'Other manifest extent membership is only a shared-tail candidate; no control-flow or semantic legitimacy is asserted.',
                     'Input audit and manifest are immutable pinned records; no C eligibility counts are changed.'])
    args.output.mkdir(parents=True)
    def write(name, obj):
        (args.output / name).write_text(json.dumps(obj, indent=2) + '\n', encoding='utf8')
    write('summary.json', summary)
    write('classifications.json', classifications)
    write('rows.json', row_summaries)
    write('checked-export-artifacts.json', checked_artifacts)
    (args.output / 'audited-journal-prefix.jsonl').write_bytes(journal_raw)
    report = ['# GNS retained pcode exit classification', '', 'All 10,654 original manifest range hashes and VA/file mappings verified against pinned ELF.',
              'Audit, journal, persisted result scopes and all 2,000 C hashes cross-bound.', '',
              json.dumps({k: summary[k] for k in ['outside_row_count', 'outside_site_associations', 'classifications', 'rows_with_all_outside_sites_justified_PLT_bridges', 'rows_without_outside_sites']}, indent=2), '',
              'No C counts or function extents changed. No native engine or target execution.', '', *summary['limitations'], '',
              'Negative controls rejected: ' + ', '.join(controls)]
    (args.output / 'REPORT.md').write_text('\n'.join(report) + '\n', encoding='utf8')
    inputs = [audit_path, manifest_path, args.elf, Path(__file__), PARSER_PATH]
    write('hashes.json', dict(inputs=[dict(path=str(q.resolve()), sha256=SHA(q.read_bytes())) for q in inputs],
        outputs=[dict(name=q.name, sha256=SHA(q.read_bytes()), bytes=q.stat().st_size) for q in sorted(args.output.iterdir())]))
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
