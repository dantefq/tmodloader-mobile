"""Verify exported instruction bytes against the original ELF; no target execution."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from terraria_native_map import ELF


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--lab', type=Path, required=True)
    args = parser.parse_args()
    lab = args.lab
    binary = (lab / 'native/libil2cpp.so').read_bytes()
    elf = ELF(binary)
    ledger = {}
    for line in (lab / 'pseudocode/coverage.jsonl').read_text(encoding='utf-8').splitlines():
        row = json.loads(line)
        entry = int(row['address'], 16)
        if entry in ledger:
            raise ValueError('Duplicate function in coverage ledger')
        ledger[entry] = row
    errors, counts, sizes, last = [], Counter(), Counter(), {}
    rows = 0
    def fail(message):
        if len(errors) < 100:
            errors.append(message)
    with (lab / 'pseudocode/instructions.tsv').open(encoding='utf-8') as stream:
        if stream.readline().rstrip('\n\r') != 'function_entry\tinstruction_address\tbytes\tinstruction':
            raise ValueError('Unexpected instruction table header')
        for number, line in enumerate(stream, 2):
            parts = line.rstrip('\n\r').split('\t', 3)
            if len(parts) != 4:
                fail(f'Line {number}: malformed record')
                continue
            entry, address = int(parts[0], 16), int(parts[1], 16)
            raw = bytes.fromhex(parts[2])
            row = ledger.get(entry)
            if row is None:
                fail(f'Line {number}: function absent from ledger')
                continue
            end = int(row['compiler_end_exclusive'], 16)
            if len(raw) != 4 or address % 4 or not entry <= address < end or address + len(raw) > end:
                fail(f'Line {number}: invalid ARM64 instruction bounds')
            try:
                offset = elf.file_offset(address)
                if binary[offset:offset + len(raw)] != raw:
                    fail(f'Line {number}: bytes differ from ELF at {hex(address)}')
            except ValueError:
                fail(f'Line {number}: address outside file-backed ELF segment')
            if entry in last and address <= last[entry]:
                fail(f'Line {number}: duplicate or unordered instruction within function')
            last[entry] = address
            counts[entry] += 1
            sizes[entry] += len(raw)
            rows += 1
    for entry, row in ledger.items():
        if counts[entry] != row['instructions']:
            fail(f'{hex(entry)}: instruction count differs from ledger')
        if 'instruction_bytes' in row and sizes[entry] != row['instruction_bytes']:
            fail(f'{hex(entry)}: instruction byte count differs from ledger')
    result = {'elf_sha256': hashlib.sha256(binary).hexdigest(),
              'functions_in_ledger': len(ledger), 'instruction_records': rows,
              'instruction_bytes': sum(sizes.values()), 'errors_first_100': errors,
              'passed': not errors,
              'scope': 'Byte identity, ARM64 alignment, compiler extent bounds and ledger counts only; not semantic equivalence.'}
    path = lab / 'pseudocode/instruction-verification.json'
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))
    if errors:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
