"""Conditional instruction-path facts for ProcessData's eight table indexes.

No global CFG/dominance/runtime claim; frozen C profiles and switch maps unchanged.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

ELF = '9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
MAP = '88cb4795b3cf12a4ac25ed00937898aceeddb29791838194b587778192664da3'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def zeroing(word):
    if word & 0x1f != 8:
        return None
    if word >> 31 == 0 and (word & 0x1f000000 == 0x11000000
                             or word & 0x1f200000 == 0x0b200000):
        return 'AArch64 32-bit ADD/SUB destination W8 clears X8[63:32]'
    if word & 0xfffffc00 == 0x92401c00:
        return 'AArch64 AND X8,Xn,#0xff limits the complete X8 value to 0..255'
    return None


def preserves_x8(word, pc, guard):
    if pc == guard:
        return word & 0xff00001f == 0x54000008  # B.HI; selected fallthrough only
    if word & 0x1f000000 in (0x10000000, 0x11000000):  # ADR(P), ADD/SUB immediate
        return word & 31 != 8
    if word & 0x3b000000 == 0x39000000 and not word & (1 << 26):
        opcode = word >> 22 & 3  # only unsigned-immediate GP STR / unsigned LDR
        return opcode == 0 or (opcode == 1 and word & 31 != 8)
    return False  # unknown effects are rejected, never assumed harmless


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raw = (args.lab / 'native/libil2cpp.so').read_bytes()
    maps_raw = (args.lab / 'hard-switches-v2/switches.json').read_bytes()
    require(sha(raw) == ELF and sha(maps_raw) == MAP, 'Frozen inputs differ')
    ph = struct.unpack_from('<Q', raw, 32)[0]
    stride, count = struct.unpack_from('<HH', raw, 54)
    segments = []
    for index in range(count):
        kind, flags, offset, address, _, size, _, _ = struct.unpack_from('<IIQQQQQQ', raw, ph + index * stride)
        if kind == 1 and flags & 1:
            segments.append((address, address + size, offset))

    def read_word(address):
        hits = [offset + address - start for start, end, offset in segments if start <= address and address + 4 <= end]
        require(len(hits) == 1, 'Not unique executable file-backed word')
        return struct.unpack_from('<I', raw, hits[0])[0]

    method = next(m for m in json.loads(maps_raw)['methods'] if m['address'] == '0x11242ec')
    require(len(method['switch_candidates']) == 8 and not method['unresolved_BR'], 'Unexpected method switch inventory')
    rows = []
    for table in method['switch_candidates']:
        require(table['index_register'] == 'x8' and table['guard_path'] == 'fallthrough', 'Unexpected index/guard')
        evidence = table['straight_line_evidence']
        loads = [i for i in evidence if i['raw_bytes'] == '2b796878']
        require(len(loads) == 1, 'Expected exact LDRH W11,[X9,X8,LSL#1]')
        load = int(loads[0]['address'], 16)
        expression = table['load_index_expression']
        if expression[0] == 'definition':
            require(expression[1] == 'x8', 'Unexpected definition register')
            start = int(expression[2], 16)
        else:
            require(expression[0] == 'mask' and expression[2] == 255, 'Unexpected mask expression')
            starts = [int(i['address'], 16) for i in evidence
                      if int(i['address'], 16) < load
                      and read_word(int(i['address'], 16)) & 0xfffffc1f == 0x92401c08]
            require(len(starts) == 1, 'Expected exact AND X8,Xn,#0xff')
            start = starts[0]
        seed = read_word(start)
        reason = zeroing(seed)
        require(reason is not None and start < load, 'No recognized upper-bit-clearing seed')
        guard = int(table['guard_branch'], 16)
        words = []
        for address in range(start, load, 4):
            word = read_word(address)
            if address != start:
                require(preserves_x8(word, address, guard), 'Unproved X8 effects at ' + hex(address))
            words.append(dict(address=hex(address), raw_bytes=word.to_bytes(4, 'little').hex()))
        require(read_word(load) == 0x7868792b, 'Index load encoding differs')
        rows.append(dict(branch=table['branch'], guard=table['guard_branch'], seed=hex(start),
                         seed_reason=reason, index_load=hex(load), words=words,
                         index_load_raw_bytes='2b796878', conditional_X8_upper32_zero_at_load=True,
                         seed_is_after_guard=start > guard))
    require(not args.output.exists() and args.output.resolve().parent == args.lab.resolve(), 'Fresh output directly inside lab required')
    report = dict(schema='ProcessData-conditional-index-highbits-v1', ELF_sha256=ELF,
                  switch_map_sha256=MAP, producer_sha256=sha(Path(__file__).read_bytes()),
                  rows=rows, conditional_paths_proved=8,
                  assumptions=['Standard AArch64 instruction semantics.',
                               'Execution enters the recorded seed and completes all listed instructions in order to the indexed load; any recorded B.HI takes the fallthrough edge.',
                               'No alternate interior entry, code modification, trap/signal/nonlocal PC rewrite bypasses the seed or listed path.'],
                  all_incoming_paths_proven=False, global_guard_dominance_proven=False,
                  runtime_verified=False, semantic_equivalence_verified=False,
                  frozen_C_model_modified=False, C_coverage_addition=0)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf8')
    print(json.dumps(dict(rows=len(rows), instructions=sum(len(r['words']) for r in rows),
                          output=str(args.output), C_coverage_addition=0)))


if __name__ == '__main__':
    main()
