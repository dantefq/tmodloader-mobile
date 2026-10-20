"""Independent raw-ELF/Capstone audit; never imports or executes the producer."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys

ELF = '9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
MAP = '88cb4795b3cf12a4ac25ed00937898aceeddb29791838194b587778192664da3'
PRODUCER = '9f19df2a04e7f70a7bd86becbd969b93097143e2cfd467333ee48b42acac4aac'
BRANCHES = {0x11250b4, 0x1127b24, 0x112813c, 0x11285cc,
            0x1128650, 0x11296d4, 0x11327e0, 0x1137684}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


class RawImage:
    def __init__(self, raw):
        require(digest(raw) == ELF, 'ELF identity')
        require(raw[:6] == b'\x7fELF\x02\x01', 'ELF64 little endian')
        require(struct.unpack_from('<H', raw, 18)[0] == 183, 'AArch64 machine')
        self.raw = raw
        header = struct.unpack_from('<Q', raw, 32)[0]
        stride, count = struct.unpack_from('<HH', raw, 54)
        require(stride >= 56 and header + stride * count <= len(raw), 'program headers')
        self.loads = []
        for n in range(count):
            kind, flags, offset, address, _, length, _, _ = struct.unpack_from(
                '<IIQQQQQQ', raw, header + n * stride)
            if kind == 1 and flags & 1:
                require(offset + length <= len(raw), 'executable segment bounds')
                self.loads.append((address, address + length, offset))

    def word(self, address):
        require(address % 4 == 0, 'instruction alignment')
        hits = [offset + address - start for start, end, offset in self.loads
                if start <= address and address + 4 <= end]
        require(len(hits) == 1, 'unique executable file-backed instruction')
        return self.raw[hits[0]:hits[0] + 4]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--lab', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    sys.path.insert(0, str(args.lab / 'python-analysis'))
    import capstone
    from capstone import arm64_const as ac
    require(capstone.__version__ == '5.0.7', 'Capstone version')
    cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    cs.detail = True

    def decode(raw, address):
        ins = list(cs.disasm(raw, address))
        require(len(ins) == 1 and ins[0].size == 4, 'single AArch64 instruction')
        return ins[0]

    def seed_kind(raw, address):
        ins = decode(raw, address)
        ops = ins.operands
        require(ops and ops[0].type == ac.ARM64_OP_REG, 'seed register destination')
        dest = ins.reg_name(ops[0].reg)
        if ins.mnemonic in ('add', 'sub'):
            require(dest == 'w8', 'ADD/SUB must write W8, clearing upper X8 bits')
            require('w8' in [ins.reg_name(r) for r in ins.regs_access()[1]], 'W8 actual write')
            return 'W8_ADD_SUB'
        require(ins.mnemonic == 'and' and dest == 'x8', 'AND must write X8')
        require(len(ops) == 3 and ops[1].type == ac.ARM64_OP_REG
                and ops[2].type == ac.ARM64_OP_IMM and ops[2].imm == 255,
                'AND immediate must be exactly 0xff')
        return 'X8_AND_FF'

    def effects(raw, address, guard):
        ins = decode(raw, address)
        reported = [ins.reg_name(r) for r in ins.regs_access()[1]]
        actual = list(reported)
        correction = False
        if ins.mnemonic == 'cmp':
            # Capstone 5.0.7 incorrectly lists the first CMP operand as written.
            # These paths use CMP-immediate: SUBS (immediate) with Rd=31 (ZR).
            word = int.from_bytes(raw, 'little')
            require(word & 0x7f00001f == 0x7100001f, 'CMP is SUBS-immediate to ZR')
            require(len(ins.operands) == 2 and ins.operands[0].type == ac.ARM64_OP_REG
                    and ins.operands[1].type == ac.ARM64_OP_IMM, 'CMP immediate operands')
            actual = ['nzcv']
            correction = reported != actual
        require(not ({'x8', 'w8'} & set(actual)), 'interior instruction writes X8/W8')
        if address == guard:
            require(ins.mnemonic == 'b.hi', 'recorded guard is B.HI')
        else:
            require(ins.mnemonic in ('cmp', 'adr', 'adrp', 'add', 'sub', 'ldr', 'str'),
                    'unexpected control flow or unsupported interior opcode')
        return dict(address=hex(address), raw_bytes=raw.hex(), mnemonic=ins.mnemonic,
                    operands=ins.op_str, capstone_reported_writes=reported,
                    architectural_writes=actual, CMP_alias_correction=correction)

    def index_load(raw, address):
        require(raw == bytes.fromhex('2b796878'), 'exact indexed-load bytes')
        ins = decode(raw, address)
        ops = ins.operands
        require(ins.mnemonic == 'ldrh' and len(ops) == 2, 'LDRH load')
        require(ops[0].type == ac.ARM64_OP_REG and ins.reg_name(ops[0].reg) == 'w11', 'W11 destination')
        require(ops[1].type == ac.ARM64_OP_MEM and ins.reg_name(ops[1].mem.base) == 'x9'
                and ins.reg_name(ops[1].mem.index) == 'x8'
                and ops[1].shift.type == ac.ARM64_SFT_LSL and ops[1].shift.value == 1,
                'X9 base, complete X8 index, LSL #1')

    report_path = args.lab / 'processdata-index-highbits-20261018.json'
    report_raw = report_path.read_bytes()
    report = json.loads(report_raw)
    maps_raw = (args.lab / 'hard-switches-v2/switches.json').read_bytes()
    require(digest(maps_raw) == MAP, 'catalogue identity')
    require(digest(Path(__file__).with_name('terraria_processdata_index_highbits.py').read_bytes()) == PRODUCER,
            'producer source identity, without importing it')
    require(report['ELF_sha256'] == ELF and report['switch_map_sha256'] == MAP
            and report['producer_sha256'] == PRODUCER, 'report provenance')
    require(report['schema'] == 'ProcessData-conditional-index-highbits-v1', 'report schema')
    require(report['conditional_paths_proved'] == 8 and len(report['rows']) == 8, 'eight paths')
    for key in ('all_incoming_paths_proven', 'global_guard_dominance_proven', 'runtime_verified',
                'semantic_equivalence_verified', 'frozen_C_model_modified'):
        require(report[key] is False, 'bounded claim: ' + key)
    require(report['C_coverage_addition'] == 0 and len(report['assumptions']) == 3, 'coverage and premises')
    method = next(m for m in json.loads(maps_raw)['methods'] if m['address'] == '0x11242ec')
    tables = {int(t['branch'], 16): t for t in method['switch_candidates']}
    require(len(tables) == 8 and set(tables) == BRANCHES and not method['unresolved_BR'], 'source branch inventory')
    require({int(r['branch'], 16) for r in report['rows']} == BRANCHES, 'report branch inventory')
    image = RawImage((args.lab / 'native/libil2cpp.so').read_bytes())
    decoded_rows = []
    for row in report['rows']:
        table = tables[int(row['branch'], 16)]
        guard, start, load = (int(row[k], 16) for k in ('guard', 'seed', 'index_load'))
        require(row['guard'] == table['guard_branch'] and table['index_register'] == 'x8'
                and table['guard_path'] == 'fallthrough', 'catalogue guard/index/path')
        require(row['seed_is_after_guard'] is (start > guard)
                and row['conditional_X8_upper32_zero_at_load'] is True, 'conditional row flags')
        require(start < load and [int(w['address'], 16) for w in row['words']] == list(range(start, load, 4)),
                'complete contiguous pre-load path')
        def bind(address, recorded):
            actual = image.word(address)
            require(actual.hex() == recorded, 'raw ELF byte binding')
            return actual
        words = [bind(int(w['address'], 16), w['raw_bytes']) for w in row['words']]
        kind = seed_kind(words[0], start)
        expression = table['load_index_expression']
        if kind == 'W8_ADD_SUB':
            require(expression == ['definition', 'x8', hex(start)], 'catalogue seed definition')
            require(row['seed_reason'] == 'AArch64 32-bit ADD/SUB destination W8 clears X8[63:32]', 'seed reason')
        else:
            require(expression[0] == 'mask' and expression[2] == 255, 'catalogue mask expression')
            require(any(i['address'] == hex(start) and i['raw_bytes'] == words[0].hex()
                        for i in table['straight_line_evidence']), 'mask seed in source catalogue')
            require(row['seed_reason'] == 'AArch64 AND X8,Xn,#0xff limits the complete X8 value to 0..255', 'mask reason')
        guard_ins = decode(image.word(guard), guard)
        require(guard_ins.mnemonic == 'b.hi' and guard_ins.operands[0].imm == int(table['default_target'], 16), 'guard target')
        branch_ins = decode(image.word(int(row['branch'], 16)), int(row['branch'], 16))
        require(branch_ins.mnemonic == 'br' and branch_ins.op_str == 'x10', 'catalogue indirect branch')
        interior = [effects(raw, start + 4 * n, guard) for n, raw in enumerate(words) if n]
        index_load(bind(load, row['index_load_raw_bytes']), load)
        decoded_rows.append(dict(branch=row['branch'], seed=hex(start), seed_kind=kind,
                                 seed_disassembly=decode(words[0], start).mnemonic + ' ' + decode(words[0], start).op_str,
                                 index_load=hex(load), instructions_before_load=len(words), interior=interior,
                                 conditional_X8_upper32_zero_at_load=True))

    negatives = []
    def reject(name, fn):
        try:
            fn()
        except (ValueError, IndexError):
            negatives.append(name)
            return
        raise ValueError('negative control accepted: ' + name)
    first = report['rows'][0]
    seed = bytes.fromhex(first['words'][0]['raw_bytes'])
    def changed(raw, mask):
        return (int.from_bytes(raw, 'little') ^ mask).to_bytes(4, 'little')
    reject('seed SF flip W8 to X8', lambda: seed_kind(changed(seed, 1 << 31), 0))
    reject('seed destination W8 to W9', lambda: seed_kind(changed(seed, 1), 0))
    mask_seed = bytes.fromhex(report['rows'][3]['words'][0]['raw_bytes'])
    reject('AND mask 0xff to other immediate', lambda: seed_kind(changed(mask_seed, 1 << 10), 0))
    reject('load X8 index to X9', lambda: index_load(changed(bytes.fromhex('2b796878'), 1 << 16), 0))
    reject('load destination W11 to W10', lambda: index_load(changed(bytes.fromhex('2b796878'), 1), 0))
    reject('interior actual ADD W8 write', lambda: effects(bytes.fromhex('08050011'), 0, 4))
    reject('raw-byte tamper', lambda: bind(int(first['seed'], 16), changed(seed, 1).hex()))
    require(sum(r['instructions_before_load'] for r in decoded_rows) == 82, '82 pre-load instructions')
    require(sum(r['seed_kind'] == 'W8_ADD_SUB' for r in decoded_rows) == 6
            and sum(r['seed_kind'] == 'X8_AND_FF' for r in decoded_rows) == 2, 'seed inventory')
    result = dict(schema='ProcessData-independent-index-highbits-audit-v1', integrity_passed=True,
                  ELF_sha256=ELF, switch_map_sha256=MAP, producer_sha256=PRODUCER,
                  input_report_sha256=digest(report_raw), auditor_sha256=digest(Path(__file__).read_bytes()),
                  capstone_version=capstone.__version__, rows=decoded_rows,
                  verified_preload_instructions=82, verified_index_loads=8,
                  CMP_alias_corrections=sum(x['CMP_alias_correction'] for r in decoded_rows for x in r['interior']),
                  negative_controls_rejected=negatives, assumptions=report['assumptions'],
                  all_incoming_paths_proven=False, global_guard_dominance_proven=False,
                  runtime_verified=False, semantic_equivalence_verified=False, C_coverage_addition=0)
    require(not args.output.exists(), 'fresh audit output required')
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf8')
    print(json.dumps({k: result[k] for k in ('integrity_passed', 'verified_preload_instructions',
                     'verified_index_loads', 'CMP_alias_corrections', 'negative_controls_rejected', 'C_coverage_addition')}))


if __name__ == '__main__':
    main()
