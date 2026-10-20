"""Independent input/result integrity audit for the single conditional hint experiment."""
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
    out = args.lab / 'pseudocode-projectile026-long-probe'
    result = json.loads((out / 'result.json').read_text())
    elf = (args.lab / 'native/libil2cpp.so').read_bytes()
    assert sha(elf) == result['elf_sha256'] == '9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
    assert sha(Path(result['actual_engine_path']).read_bytes()) == result['actual_engine_sha256'] == '1fd85827247f1ff1417fa412db26a53066d050c59017db98dd23ff196751521e'
    assert sha(args.producer.read_bytes()) == result['script_sha256']
    maps_path = args.lab / 'hard-switches-v2/switches.json'
    assert sha(maps_path.read_bytes()) == result['switch_maps_sha256']
    phoff = struct.unpack_from('<Q', elf, 32)[0]
    phsize, phcount = struct.unpack_from('<HH', elf, 54)
    segments = []
    for index in range(phcount):
        p = phoff + phsize * index
        kind, _, offset, va, _, size, _, _ = struct.unpack_from('<IIQQQQQQ', elf, p)
        if kind == 1:
            segments.append((offset, va, size))
    def read(va, size):
        for offset, start, length in segments:
            if start <= va and va + size <= start + length:
                return elf[offset + va - start:offset + va - start + size]
        raise AssertionError(f'unmapped {va:x}')
    start, end = int(result['address'], 16), int(result['end_exclusive'], 16)
    assert start == 0x14702c0 and end == 0x1483e54
    assert sha(read(start, end - start)) == result['function_source_sha256']
    assert end - start == result['function_source_bytes_verified'] == 80788
    method = next(m for m in json.loads(maps_path.read_text())['methods'] if int(m['address'], 16) == start)
    expected = []
    for switch in method['switch_candidates']:
        branch = int(switch['branch'], 16)
        assert struct.unpack('<I', read(branch, 4))[0] & 0xfffffc1f == 0xd61f0000
        raw = read(int(switch['table'], 16), switch['width'] * switch['count'])
        assert raw.hex() == switch['table_raw_bytes']
        targets = []
        for item in switch['entries']:
            target = int(item['target'], 16)
            value = int.from_bytes(raw[item['index'] * switch['width']:(item['index'] + 1) * switch['width']], 'little')
            assert target == int(switch['anchor'], 16) + 4 * value
            assert start <= target < end and read(target, 4).hex() == item['target_raw_bytes']
            targets.append(hex(target))
        expected.append({'branch': switch['branch'], 'targets': targets})
    assert result['applied_hints'] == expected
    assert result['applied_hint_count'] == len(expected) == 7
    assert result['applied_entry_count'] == sum(len(x['targets']) for x in expected) == 72
    assert result['ephemeral_transaction_rolled_back'] is True
    assert result['saved_project_modified'] is False and result['canonical_journals_modified'] is False
    assert result['timeout_seconds'] == 600 and result['max_instructions'] == 250000 and result['max_payload_mb'] == 256
    if result['status'] == 'decompiled_conditional_candidate':
        path = out / result['file']
        assert path.resolve().parent == out.resolve()
        assert sha(path.read_bytes()) == result['c_sha256']
        assert path.read_text().startswith('/* CONDITIONAL GHIDRA C CANDIDATE;')
    else:
        assert result['status'] == 'decompile_failed'
        assert not list(out.glob('*.c'))
    audit = {'integrity_passed': True, 'producer_status': result['status'], 'verified_function_bytes': end-start,
             'verified_switches': 7, 'verified_entries': 72, 'result_sha256': sha((out / 'result.json').read_bytes()),
             'auditor_sha256': sha(Path(__file__).read_bytes()), 'semantic_equivalence_verified': False,
             'global_guard_dominance_verified': False, 'runtime_verified': False,
             'note': 'Checks source bytes, map arithmetic and recorded hint identity; not independent observation of Ghidra internal override storage.'}
    (out / 'audit.json').write_text(json.dumps(audit, indent=2) + '\n')
    print(json.dumps(audit))

if __name__ == '__main__':
    main()
