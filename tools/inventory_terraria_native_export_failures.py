"""Independent raw ELF/durable-record inventory of actual native export failures.

Never executes a target or decompiler; marker-bearing successful C is excluded.
"""
import argparse
from collections import Counter, defaultdict
import copy
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct

SHA = lambda b: hashlib.sha256(b).hexdigest()
PARSER = Path(__file__).with_name('prove_libmain_stackchk_import.py')
PARSER_SHA = 'b3fc8f7a171a177f97cf7b8be5d1514e312daf8d9661a32851bd800e2edffd3a'
if SHA(PARSER.read_bytes()) != PARSER_SHA:
    raise ValueError('Pinned raw ELF parser changed')
from prove_libmain_stackchk_import import ELF

SPECS = [dict(library='libGNS_Wrapper.so', stem='libGNS_Wrapper', rows=10654, failures=2,
    elf_sha256='7e850163b92735b7b7307fb2919fb8064d5740cc0597b5e7c6a35d8454159df8',
    manifest_sha256='c1ba2b0a384ed1af5ca1ae7e6d5a3eefc7aa8af6d0643370d13ae476abf9b264',
    audit_sha256='a090f0d592d101cd301a5df134baebaf0438fe7f73fe8ee5bcebac764d8f482f'),
    dict(library='libc++_shared.so', stem='libcpp_shared', rows=2275, failures=7,
    elf_sha256='218ecc677aa79e1974f3968d2e0ecd0172c4f517188d04ebd7d45cbb285b5d03',
    manifest_sha256='fb6e63a17459d06cc00cbb5835e00268e2e4ae78825b47c0faedda35c8551f10',
    audit_sha256='e7ad4e4ae3c232109078e8c3c534ae09591f8ae88598ae5aedbd95810c6151b0')]


def need(ok, message):
    if not ok:
        raise ValueError(message)


def unique(pairs):
    out = {}
    for k, v in pairs:
        need(k not in out, 'Duplicate JSON key')
        out[k] = v
    return out


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique)


def digest(raw, expected):
    need(SHA(raw) == expected, 'SHA256 mismatch')


def journal(raw):
    need(bool(raw) and raw.endswith(b'\n'), 'Partial durable journal')
    rows = [parse(line) for line in raw.splitlines()]
    need(len({r['address'] for r in rows}) == len(rows), 'Duplicate journal address')
    for r in rows:
        need(re.fullmatch('0x[0-9a-f]+', r['address']) is not None, 'Invalid address')
        need(r['result_file'] == 'range_' + r['address'] + '.json', 'Unsafe result path')
    return rows


def source_range(elf, row):
    a, z, off = (int(row[k], 16) for k in ['address', 'end_exclusive', 'file_offset'])
    need(a % 4 == 0 and z % 4 == 0 and z > a, 'Unaligned/empty original range')
    need(elf.mapping(a, z-a, True) == off, 'Original VA/file mapping mismatch')
    raw = elf.read(a, z-a, True)
    digest(raw, row['source_sha256'])
    return a, z, off, raw


def original_symbols(elf):
    result = defaultdict(list)
    for sec in elf.sections:
        if sec['type'] not in (2, 11):
            continue
        need(sec['entsize'] == 24 and sec['size'] % 24 == 0, 'Invalid ELF symbol table')
        strings = elf.sections[sec['link']]
        need(strings['type'] == 3, 'Invalid symbol string-table link')
        pool = elf.raw[strings['offset']:strings['offset']+strings['size']]
        for off in range(sec['offset'], sec['offset']+sec['size'], 24):
            name, attrs, other, shndx, value, size = struct.unpack_from('<IBBHQQ', elf.raw, off)
            if attrs & 15 != 2 or not shndx or not value:
                continue
            result[value].append(dict(name=elf.string(pool, name), table=sec['name'],
                symbol_file_offset=off, symbol_raw_bytes=elf.raw[off:off+24].hex(),
                name_string_file_offset=strings['offset']+name, binding=attrs >> 4,
                type=attrs & 15, section_index=shndx, value=hex(value), size=size,
                end_exclusive=hex(value+size), visibility=other & 3))
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--lab', type=Path, default=Path('C:/Temp/terraria-re-20261012'))
    ap.add_argument('--delivery', type=Path, default=Path('C:/Private/Documents/ChatGPT/Terraria-Reverse-20261012'))
    ap.add_argument('--output', type=Path)
    args = ap.parse_args()
    output = args.output or args.lab / 'native-export-failures-20261019'
    need(not output.exists(), 'Fresh output required')
    failures = []
    summaries = []
    inputs = []
    for spec in SPECS:
        print('Verifying '+spec['library']+' input/final-audit bindings',flush=True)
        ep = args.delivery / 'android-native' / spec['library']
        mp = args.lab / 'other-native-range-v3-manifests-20261019' / (spec['library']+'.manifest.json')
        apath = args.lab / ('other-native-'+spec['stem']+'-final-v3-audit-20261019.json')
        need(apath.is_file(), 'Final audit not yet present: '+str(apath))
        eraw, mraw, araw = ep.read_bytes(), mp.read_bytes(), apath.read_bytes()
        for raw, key in [(eraw,'elf_sha256'), (mraw,'manifest_sha256'), (araw,'audit_sha256')]:
            digest(raw, spec[key])
        elf, manifest, audit = ELF(eraw), parse(mraw), parse(araw)
        need(audit['integrity_passed'] is True and audit['all_rows_attempted'] is True
            and audit['attempted_rows'] == spec['rows'] and audit['total_manifest_rows'] == spec['rows']
            and audit['manifest_sha256'] == spec['manifest_sha256'] and audit['ELF_sha256'] == spec['elf_sha256'], 'Final audit binding mismatch')
        root = args.lab / ('other-native-range-c-'+spec['stem']+'-sample-v3-20261019')
        jp = root / 'journal.jsonl'
        jraw = jp.read_bytes()
        digest(jraw, audit['journal_sha256'])
        commits = journal(jraw)
        mapping = {r['address']: r for r in manifest['rows']}
        need(len(mapping) == len(manifest['rows']) == len(commits) == spec['rows'], 'Manifest/journal universe mismatch')
        need({r['address'] for r in commits} == set(mapping), 'Journal universe differs')
        previous_end = 0
        for r in manifest['rows']:
            a, z, _, _ = source_range(elf, r)
            need(a >= previous_end, 'Overlapping original range')
            previous_end = z
        symbols = original_symbols(elf)
        print('Verified original ranges; checking durable results and successful C hashes',flush=True)
        statuses = Counter()
        result_bindings = []
        for ordinal, commit in enumerate(commits):
            if ordinal and ordinal % 1000 == 0:
                print(spec['library']+': checked '+str(ordinal)+' durable results',flush=True)
            rp = root / commit['result_file']
            raw = rp.read_bytes()
            digest(raw, commit['result_sha256'])
            result = parse(raw)
            row = mapping[commit['address']]
            for field in ['address','end_exclusive','source_sha256','evidence_kind']:
                need(result[field] == row[field], 'Result/original row mismatch')
            need(result['manifest_sha256'] == spec['manifest_sha256'] and result['elf_sha256'] == spec['elf_sha256']
                and result['engine_sha256'] == audit['engine_sha256'] and result['script_sha256'] == audit['producer_sha256'], 'Result producer/input binding mismatch')
            status = result['status']
            need(status in ['decompiled','decompile_failed','range_error'], 'Unknown export status')
            statuses[status] += 1
            result_bindings.append(dict(address=commit['address'], result_sha256=SHA(raw), status=status))
            cp = root / ('range_'+commit['address']+'.c')
            if status == 'decompiled':
                craw = cp.read_bytes()
                digest(craw, result['c_sha256'])
                need(len(craw) == result['c_bytes'] and result['actual_C_object_returned'] is True
                    and result['decompile_completed'] is True and result['timed_out'] is False, 'Invalid successful C record')
                continue
            need(not cp.exists(), 'Failure has C artifact')
            a, z, off, source = source_range(elf, row)
            exact_symbols = [dict(s, extent_exact=s['size'] == z-a) for s in symbols.get(a, [])]
            failure = dict(library=spec['library'], journal_ordinal_1based=ordinal+1,
                original_manifest_row=row, original_file_offset=off, original_file_end_exclusive=off+len(source),
                original_bytes=len(source), original_byte_sha256=SHA(source),
                original_defined_STT_FUNC_symbols_at_exact_entry=exact_symbols,
                symbol_name_claim_scope='Raw ELF symbol names at exact entry only; no demangling or semantic inference',
                result_path=str(rp), result_sha256=SHA(raw), status=status,
                timed_out=result.get('timed_out'), elapsed_seconds=result.get('elapsed_seconds'),
                exact_error_message=result.get('message'), decompile_completed=result.get('decompile_completed'),
                actual_C_object_returned=result.get('actual_C_object_returned'),
                high_function_returned=result.get('retained_high_pcode_scope',{}).get('high_function_returned'),
                configured_timeout_seconds=result.get('timeout_seconds'), bounded_instruction_count=result.get('bounded_instruction_count'),
                original_instruction_bytes_verified=result.get('original_instruction_bytes_verified'),
                failure_classification='timeout_reported' if result.get('timed_out') is True else 'native_recovery_error' if 'Recoverable Error:' in result.get('message','') else 'other_failure',
                semantic_equivalence_verified=False, original_source_recovered=False,
                next_step='Separate unchanged-byte per-function diagnostic with official normalize style, C off/tree on; see TERRARIA_GNS_VARNODE_FAILURE_REVIEW.md' if spec['stem']=='libGNS_Wrapper' else
                    'Separate isolated per-function decompile retry with same original extents/options and increased timeout, first 120 seconds; retain original 20-second failure and record fresh engine/profile/process identity. No guarantee of success.')
            failures.append(failure)
        need(dict(statuses) == audit['status_counts'] and sum(v for k,v in statuses.items() if k!='decompiled') == spec['failures'], 'Status totals differ from final audit')
        summaries.append(dict(library=spec['library'], final_audit_present_and_hash_bound=True,
            final_audit_sha256=SHA(araw), original_ranges_verified=spec['rows'], status_counts=dict(statuses),
            journal_sha256=SHA(jraw), result_hashes_verified=len(commits), successful_C_hashes_verified=statuses['decompiled'],
            original_ELF_sha256=SHA(eraw), manifest_sha256=SHA(mraw), result_bindings=result_bindings))
        inputs.extend(dict(path=str(p),sha256=SHA(p.read_bytes())) for p in [ep,mp,apath,jp])
    controls = []
    def reject(label, fn):
        try:
            fn()
        except (ValueError,KeyError,struct.error):
            controls.append(label)
        else:
            raise ValueError('Negative control accepted: '+label)
    reject('wrong_ELF_hash', lambda: digest(eraw[:-1],spec['elf_sha256']))
    reject('wrong_manifest_hash', lambda: digest(mraw+b' ',spec['manifest_sha256']))
    reject('wrong_final_audit_hash', lambda: digest(araw+b' ',spec['audit_sha256']))
    reject('wrong_journal_hash', lambda: digest(jraw+b' ',audit['journal_sha256']))
    reject('duplicate_JSON_key',lambda:parse('{"a":1,"a":2}'))
    reject('duplicate_journal_address',lambda:journal(b'{"address":"0x4","result_file":"range_0x4.json"}\n'*2))
    reject('partial_journal_tail',lambda:journal(b'{"address":"0x4"}'))
    reject('journal_path_escape',lambda:journal(b'{"address":"0x4","result_file":"../range_0x4.json"}\n'))
    bad=copy.deepcopy(manifest['rows'][0]);bad['source_sha256']='0'*64
    reject('wrong_original_range_hash',lambda:source_range(elf,bad))
    bad=copy.deepcopy(manifest['rows'][0]);bad['file_offset']=hex(int(bad['file_offset'],16)+4)
    reject('wrong_original_offset',lambda:source_range(elf,bad))
    output.mkdir(parents=True)
    def write(name,value):
        (output/name).write_text(json.dumps(value,indent=2)+'\n',encoding='utf8')
    write('failures.json',failures)
    for summary in summaries:
        bindings=summary.pop('result_bindings')
        write(summary['library']+'.result-bindings.json',bindings)
    summary=dict(scope='Actual durable native export failures only; successful marker-flagged C is excluded',
        libraries=summaries, total_actual_failures=len(failures), failure_classes=dict(Counter(f['failure_classification'] for f in failures)),
        negative_controls_rejected=controls, producer_sha256=SHA(Path(__file__).read_bytes()), pinned_ELF_parser_sha256=PARSER_SHA,
        target_execution=False,JVM_or_compiler_or_native_engine_launched=False,C_coverage_addition=0,
        semantic_equivalence_verified=False,source_recovery_percent_claimed=False)
    write('summary.json',summary)
    report=['# Actual native export failures', '', 'GNS and C++ final audits are present and hash-bound. All original ranges, journal/result hashes, successful C hashes and original VA/file mappings were independently checked.',
        'No marker-bearing successful C is classified as a decompile failure.', '',
        '| Library | Original extent | Bytes | Timeout | Seconds | Exact error |','|---|---|---:|---|---:|---|']
    for f in failures:
        r=f['original_manifest_row']
        report.append('| '+ ' | '.join([f['library'],r['address']+'..'+r['end_exclusive'],str(f['original_bytes']),str(f['timed_out']),str(f['elapsed_seconds']),f['exact_error_message'].strip().replace('|','\\|')])+' |')
    report.extend(['', 'The seven C++ rows report timeouts, including short original extents. Row length alone does not establish a cause or justify lowering timeouts. A fresh isolated per-function retry at 120 seconds is a proposed diagnostic, not an observed result; preserve the original failures. The two GNS rows report explicit varnode-hash recovery errors; use the documented official normalize diagnostic rather than assuming a longer timeout fixes them.',
        '', 'Raw original ELF function symbols and symbol record/file offsets are retained in failures.json. Names are not semantic proof. No engine was run; no existing export was modified; C coverage addition is zero.'])
    (output/'REPORT.md').write_text('\n'.join(report)+'\n',encoding='utf8')
    shutil.copyfile(Path(__file__),output/Path(__file__).name)
    write('hashes.json',dict(inputs=inputs,outputs=[dict(name=p.name,sha256=SHA(p.read_bytes())) for p in sorted(output.iterdir())]))
    print(json.dumps(summary,indent=2))


if __name__=='__main__':
    main()
