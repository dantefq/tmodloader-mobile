"""Independent raw-byte audit of three upper32 backward slices, not the whole CFG."""
import collections
import hashlib
import json
import pathlib
import struct

LAB = pathlib.Path('C:/Temp/terraria-re-20261012')
EXPECTED_ELF = '9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'

def sha(data):
    return hashlib.sha256(data).hexdigest()

def flags_only(word):
    # ADD/SUB immediate with S=1, Rd=ZR; logical immediate ANDS Rd=ZR.
    return ((word & 0x1f000000 == 0x11000000 and word & 0x20000000 and word & 31 == 31)
            or (word & 0x7f800000 == 0x72000000 and word & 31 == 31))

# Exact additional encodings encountered in these bounded slices, destinations
# decoded from architectural ADR(P), load and ADD forms. No producer imports.
OTHER_DEST = {
    0xf000b149: 9, 0xb000f7b4: 20, 0x10ff9eca: 10,
    0x7868792b: 11, 0x8b0b094a: 10, 0xf9478e94: 20,
    0xf000b148: 8, 0x100000aa: 10, 0x7869790b: 11,
    0xb000b0f7: 23, 0xb000b10a: 10, 0x1000008b: 11,
    0x7869794c: 12, 0x8b0c096b: 11,
}

def transfer(word, register):
    if word & 0xfc000000 == 0x94000000 or word & 0xfffffc1f == 0xd63f0000:
        return False  # No volatile preservation assumed across BL/BLR.
    if flags_only(word):
        return None
    if word & 0xff000010 == 0x54000000 or word & 0xfffffc1f == 0xd61f0000:
        return None
    if word & 0x1f000000 == 0x11000000:  # ADD/SUB immediate.
        if word & 31 != register:
            return None
        return not bool(word & 0x80000000)
    if word in OTHER_DEST:
        return False if OTHER_DEST[word] == register else None
    raise AssertionError(('unrecognized raw instruction in audited slice', hex(word)))

def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value

def main():
    folder = LAB / 'npc-fighters-cfg-v2'
    cfg_path = folder / 'cfg.json'
    cfg_bytes = cfg_path.read_bytes()
    cfg = json.loads(cfg_bytes)
    raw = (LAB / 'native/libil2cpp.so').read_bytes()
    assert sha(raw) == cfg['elf_sha256'] == EXPECTED_ELF
    assert raw[:6] == b'\x7fELF\x02\x01'
    phoff = struct.unpack_from('<Q', raw, 32)[0]
    phentsize, phnum = struct.unpack_from('<HH', raw, 54)
    segments = []
    for index in range(phnum):
        ptype, _, offset, va, _, filesz, _, _ = struct.unpack_from('<IIQQQQQQ', raw, phoff + index * phentsize)
        if ptype == 1:
            segments.append((va, va + filesz, offset))
    def word(address):
        matches = [(lo, off) for lo, hi, off in segments if lo <= address and address + 4 <= hi]
        assert len(matches) == 1
        lo, off = matches[0]
        return struct.unpack_from('<I', raw, off + address - lo)[0]

    producer = pathlib.Path(__file__).with_name('terraria_npc_fighters_cfg_v2.py')
    assert sha(producer.read_bytes()) == cfg['producer_sha256']
    maps = LAB / 'hard-switches-v2/switches.json'
    assert sha(maps.read_bytes()) == cfg['switch_maps_sha256']
    edges = {int(a, 16): [int(t, 16) for t in ts] for a, ts in cfg['edges'].items()}
    pred = collections.defaultdict(list)
    for address, targets in edges.items():
        for target in targets:
            pred[target].append(address)
    expected_sources = {0x1182e24: 0x1182dfc, 0x1182fc4: 0x1182df0, 0x118c08c: 0x118c06c}
    checks = []
    audited = set()
    for check in cfg['guard_checks']:
        branch = int(check['branch'], 16)
        register = int(check['index_register'][1:])
        assert word(branch) & 0xfffffc1f == 0xd61f0000
        audited.add(branch)
        pending = list(pred[branch]); visited = set(); generators = set()
        while pending:
            address = pending.pop()
            if address in visited:
                continue
            visited.add(address); audited.add(address)
            assert address != int(cfg['address'], 16), 'unknown entry reaches slice'
            instruction = word(address)
            effect = transfer(instruction, register)
            assert effect is not False, ('unknown/X-write/call reaches slice', hex(address))
            if effect is True:
                # Each stopping definition must be a genuine SUB W immediate.
                assert instruction & 0xff000000 == 0x51000000
                generators.add(address)
                continue
            assert pred[address], ('unanchored backward path', hex(address))
            pending.extend(pred[address])
        assert generators == {expected_sources[branch]}
        assert check['index_high32_known_zero_at_BR_in_model'] is True
        # Check each visited outgoing edge against fresh raw direct-flow decode.
        # This does not independently establish completeness of the input graph.
        for address in visited:
            instruction = word(address)
            if instruction & 0xff000010 == 0x54000000:
                target = address + 4 * signed((instruction >> 5) & 0x7ffff, 19)
                assert set(edges[address]) == {address + 4, target}
            else:
                assert edges[address] == [address + 4]
        checks.append({'branch': hex(branch), 'branch_raw_bytes': word(branch).to_bytes(4, 'little').hex(),
                       'register': f'x{register}', 'upper32_zero_in_supplied_model': True,
                       'stopping_SUB_W': [hex(a) for a in sorted(generators)],
                       'backward_slice': [{'address': hex(a), 'raw_bytes': word(a).to_bytes(4, 'little').hex()} for a in sorted(visited)]})
    assert set(expected_sources) == {int(c['branch'], 16) for c in checks}
    negatives = []
    for raw_hex, register in [('1f1d0071', 8), ('3f0d0071', 9), ('3f1d0071', 9), ('1f010031', 8), ('1f010072', 8)]:
        value = int.from_bytes(bytes.fromhex(raw_hex), 'little')
        assert flags_only(value) and transfer(value, register) is None
        # Unknown incoming fact stays unknown: aliases cannot generate zero.
        unknown = False
        effect = transfer(value, register)
        assert (unknown if effect is None else effect) is False
        negatives.append({'raw_bytes': raw_hex, 'register': f'x{register}', 'unknown_remains_unknown': True})
    assert transfer(0x94000000, 8) is False
    assert transfer(0xd63f0100, 8) is False
    assert transfer(0x91000108, 8) is False  # ADD X8, X8, #0.
    result = {'profile': 'NPC-AI003-upper32-raw-backward-slice-audit-v2', 'passed': True,
              'cfg_sha256': sha(cfg_bytes), 'producer_sha256': cfg['producer_sha256'],
              'auditor_sha256': sha(pathlib.Path(__file__).read_bytes()), 'elf_sha256': sha(raw),
              'switch_maps_sha256': cfg['switch_maps_sha256'], 'checks': checks,
              'unique_source_instruction_count': len(audited), 'unique_source_bytes_checked': 4 * len(audited),
              'flag_only_negative_controls': negatives, 'call_and_X_write_negative_controls_passed': 3,
              'scope': 'Three bounded backward upper32 slices and their direct outgoing edges, using fresh ELF bytes and a raw whitelist.',
              'limits': ['The complete CFG and completeness of its predecessor sets were supplied by cfg.json and not independently reconstructed.',
                         'Dominance and global switch-path completeness are not independently audited here.',
                         'Results remain conditional on the supplied CFG, switch-table preconditions, entry/call/exception assumptions; no runtime proof.']}
    (folder / 'audit.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf8')
    print(json.dumps({'passed': True, 'slices': len(checks), 'source_bytes_checked': 4 * len(audited), 'audit_sha256': sha((folder / 'audit.json').read_bytes())}))

if __name__ == '__main__':
    main()
