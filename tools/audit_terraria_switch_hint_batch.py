"""Independently validate conditional hint batch source identity and byte/table arithmetic."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

def sha(data):
    return hashlib.sha256(data).hexdigest()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('lab', type=Path)
    parser.add_argument('producer', type=Path)
    args = parser.parse_args()
    out = args.lab / 'pseudocode-switch-hint-batch'
    progress = json.loads((out / 'progress.json').read_text())
    assert progress['finished'] is True and progress['ephemeral_transaction_rolled_back'] is True
    rows = [json.loads(line) for line in (out / 'results.jsonl').read_text().splitlines()]
    maps_path = args.lab / 'hard-switches-v2/switches.json'
    maps = json.loads(maps_path.read_text())
    methods = {m['address']: m for m in maps['methods'] if m['address'] != '0x12f63e8' and m['switch_candidates']}
    assert len(rows) == len(methods) == len({r['address'] for r in rows}) == 12
    assert set(methods) == {r['address'] for r in rows}
    elf = (args.lab / 'native/libil2cpp.so').read_bytes()
    elf_hash = sha(elf)
    assert elf_hash == maps['elf_sha256'] == '9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
    phoff = struct.unpack_from('<Q', elf, 32)[0]
    phsize, phcount = struct.unpack_from('<HH', elf, 54)
    segments = []
    for index in range(phcount):
        kind, _, offset, va, _, size, _, _ = struct.unpack_from('<IIQQQQQQ', elf, phoff + phsize * index)
        if kind == 1:
            segments.append((offset, va, size))
    def read(va, size):
        for offset, start, length in segments:
            if start <= va and va + size <= start + length:
                return elf[offset + va - start:offset + va - start + size]
        raise AssertionError(f'unmapped {va:x}')
    switches = entries = source_bytes = success = warnings = 0
    for result in rows:
        method = methods[result['address']]
        assert result['elf_sha256'] == elf_hash
        assert sha(Path(result['actual_engine_path']).read_bytes()) == result['actual_engine_sha256'] == '1fd85827247f1ff1417fa412db26a53066d050c59017db98dd23ff196751521e'
        assert sha(args.producer.read_bytes()) == result['script_sha256']
        assert sha(args.producer.with_name('TerrariaSwitchHintProbe.java').read_bytes()) == result['parent_helper_sha256']
        assert sha(maps_path.read_bytes()) == result['switch_maps_sha256']
        assert method['method'] == result['method'] and method['end_exclusive'] == result['end_exclusive']
        start, end = int(result['address'], 16), int(result['end_exclusive'], 16)
        assert sha(read(start, end-start)) == result['function_source_sha256']
        assert end-start == result['function_source_bytes_verified']
        source_bytes += end-start
        expected = []
        for switch in method['switch_candidates']:
            assert struct.unpack('<I', read(int(switch['branch'], 16), 4))[0] & 0xfffffc1f == 0xd61f0000
            raw = read(int(switch['table'], 16), switch['width'] * switch['count'])
            assert raw.hex() == switch['table_raw_bytes']
            targets = []
            for item in switch['entries']:
                target = int(item['target'], 16)
                value = int.from_bytes(raw[item['index'] * switch['width']:(item['index']+1) * switch['width']], 'little')
                assert target == int(switch['anchor'], 16) + 4 * value
                assert start <= target < end and read(target, 4).hex() == item['target_raw_bytes']
                targets.append(hex(target))
            expected.append({'branch': switch['branch'], 'targets': targets})
        assert result['applied_hints'] == expected
        assert result['applied_hint_count'] == len(expected)
        count = sum(len(x['targets']) for x in expected)
        assert result['applied_entry_count'] == count
        switches += len(expected)
        entries += count
        assert result['saved_project_modified'] is False and result['canonical_journals_modified'] is False
        assert result['timeout_seconds'] == 180 and result['max_instructions'] == 250000 and result['max_payload_mb'] == 256
        if result['status'] == 'decompiled_conditional_candidate':
            path = out / result['file']
            assert path.resolve().parent == out.resolve()
            data = path.read_bytes()
            assert sha(data) == result['c_sha256'] and len(data) == result['c_bytes']
            assert data.startswith(b'/* CONDITIONAL GHIDRA C CANDIDATE;')
            assert data.count(b'WARNING:') == result['warning_count']
            success += 1
            warnings += result['warning_count']
        else:
            assert result['status'] in ('decompile_failed', 'decompile_error')
            assert not (out / (result['address'] + '_conditional_candidate.c')).exists()
    assert success == progress['conditional_c']
    assert len(list(out.glob('*.c'))) == success
    audit = {'integrity_passed': True, 'methods': len(rows), 'conditional_c_candidates': success,
             'verified_function_bytes': source_bytes, 'verified_switches': switches, 'verified_entries': entries,
             'c_warning_instances': warnings, 'journal_sha256': sha((out / 'results.jsonl').read_bytes()),
             'auditor_sha256': sha(Path(__file__).read_bytes()), 'runtime_verified': False,
             'global_guard_dominance_verified': False, 'semantic_equivalence_verified': False,
             'note': 'Input/result integrity only; no independent observation of internal Ghidra override storage.'}
    (out / 'audit.json').write_text(json.dumps(audit, indent=2)+'\n')
    print(json.dumps(audit))

if __name__ == '__main__':
    main()
