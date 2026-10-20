"""Independent ELF64/dynsym and raw A64 B audit; no producer imports."""
import copy
import hashlib
import json
from pathlib import Path
import struct

LAB = Path('C:/Temp/terraria-re-20261012')
OUT = LAB / 'native-export-bridges-20261015'

def digest(data):
    return hashlib.sha256(data).hexdigest()

class Image:
    def __init__(self, raw):
        self.raw = raw
        assert raw[:7] == b'\x7fELF\x02\x01\x01'
        assert int.from_bytes(raw[18:20], 'little') == 183
        self.loads = []
        phoff, shoff = struct.unpack_from('<QQ', raw, 32)
        phsize, phnum, shsize, shnum = struct.unpack_from('<HHHH', raw, 54)
        assert phsize >= 56 and shsize >= 64
        for i in range(phnum):
            p = phoff + phsize*i
            kind, flags = struct.unpack_from('<II', raw, p)
            off, va = struct.unpack_from('<QQ', raw, p+8)
            filesz = struct.unpack_from('<Q', raw, p+32)[0]
            assert off+filesz <= len(raw)
            if kind == 1:
                self.loads.append((va, va+filesz, off, flags))
        sections = []
        for i in range(shnum):
            p = shoff+shsize*i
            kind = struct.unpack_from('<I', raw, p+4)[0]
            off, length = struct.unpack_from('<QQ', raw, p+24)
            link = struct.unpack_from('<I', raw, p+40)[0]
            stride = struct.unpack_from('<Q', raw, p+56)[0]
            sections.append((kind, off, length, link, stride))
        self.exports = []
        for kind, off, length, link, stride in sections:
            if kind != 11:
                continue
            assert stride == 24 and length % stride == 0
            _, strings_off, strings_size, _, _ = sections[link]
            strings = raw[strings_off:strings_off+strings_size]
            for p in range(off, off+length, stride):
                name_index = int.from_bytes(raw[p:p+4], 'little')
                info = raw[p+4]
                section = int.from_bytes(raw[p+6:p+8], 'little')
                value, size = struct.unpack_from('<QQ', raw, p+8)
                assert name_index < len(strings)
                name = strings[name_index:strings.index(b'\0', name_index)].decode('utf8')
                if section and info % 16 == 2 and info//16 in (1, 2) and name.startswith('il2cpp_'):
                    self.exports.append(dict(name=name, defined=True, binding=info//16,
                                             type=info%16, address=hex(value), size=size))

    def instruction(self, va):
        matches = [(off+va-start, flags) for start, end, off, flags in self.loads if start <= va and va+4 <= end]
        assert len(matches) == 1 and matches[0][1] & 1
        off = matches[0][0]
        assert va % 4 == 0
        return self.raw[off:off+4]

def branch(data, pc):
    # A64 unconditional B: opcode bits 31..26 exactly 000101.
    word = int.from_bytes(data, 'little')
    if word >> 26 != 5:
        return None
    immediate = word % (1 << 26)
    signed = immediate - (1 << 26) if immediate >= (1 << 25) else immediate
    return pc + signed*4

def expected(image, unknown):
    rows, coverage, evidence, stops = [], set(), set(), {}
    for symbol in image.exports:
        cursor = int(symbol['address'], 16)
        seen, chain = set(), []
        while True:
            if cursor in seen:
                reason = 'cycle'
                break
            if len(chain) == 8:
                reason = 'bound'
                break
            seen.add(cursor)
            raw = image.instruction(cursor)
            dest = branch(raw, cursor)
            if dest is None:
                reason = 'non_B'
                break
            image.instruction(dest)
            chain.append(dict(address=hex(cursor), raw_bytes=raw.hex(), target=hex(dest)))
            evidence.add(cursor)
            cursor = dest
        if chain:
            linked = sorted({int(s['target'], 16) for s in chain} & unknown)
            coverage.update(linked)
            rows.append(dict(symbol=symbol, direct_B_chain=chain,
                             final_observed_target=hex(cursor),
                             original_unknown_FDE_entries_on_chain=[hex(a) for a in linked],
                             stopped_before_non_B_or_after_bound=True))
            stops[reason] = stops.get(reason, 0)+1
    return rows, sorted(coverage), evidence, stops

def verify(doc, image, unknown):
    rows, linked, proof, stops = expected(image, unknown)
    assert doc['defined_IL2CPP_function_exports_scanned'] == len(image.exports)
    assert doc['exports_with_direct_B_chains'] == len(rows)
    assert doc['records'] == rows
    assert doc['original_unknown_FDE_entries_linked'] == [hex(a) for a in linked]
    assert doc['unique_branch_bytes_checked'] == len(proof)*4
    assert not stops.get('cycle'), 'Producer stop description does not cover cycles'
    export = next(r for r in rows if r['symbol']['name'] == 'il2cpp_runtime_class_init')
    helper = image.instruction(0x6ff688)
    assert branch(helper, 0x6ff688) == 0x6e19f4
    assert export['final_observed_target'] == '0x6e19f4'
    assert doc['class_init_shared_target_observation'] == dict(
        named_export_entry=export['symbol']['address'], helper_entry='0x6ff688',
        helper_raw_bytes=helper.hex(), shared_target='0x6e19f4')
    assert doc['runtime_verified'] is False
    assert doc['profile'] == 'IL2CPP-export-direct-B-bridges-v1'
    assert len(doc['limits']) == 3 and all(isinstance(x, str) and x for x in doc['limits'])
    return len(rows), len(linked), len(proof)*4, stops

def main():
    raw = (LAB/'native/libil2cpp.so').read_bytes()
    assert digest(raw) == '9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
    original = LAB/'native/unmapped-fde-classification.json'
    unknown = {int(r['address'], 16) for r in json.loads(original.read_text()) if r['category'] == 'unknown'}
    path = OUT/'bridges.json'
    doc = json.loads(path.read_text())
    assert doc['elf_sha256'] == digest(raw)
    assert doc['classification_sha256'] == digest(original.read_bytes())
    tools = Path(__file__).parent
    assert doc['producer_sha256'] == digest((tools/'terraria_native_export_bridges_20261015.py').read_bytes())
    assert doc['ELF_parser_sha256'] == digest((tools/'terraria_native_map.py').read_bytes())
    image = Image(raw)
    bridges, linked, byte_count, stops = verify(doc, image, unknown)
    controls = []
    def reject(label, mutate):
        altered = copy.deepcopy(doc)
        mutate(altered)
        try:
            verify(altered, image, unknown)
        except (AssertionError, KeyError, ValueError):
            controls.append(label)
            return
        raise AssertionError('Mutation accepted: '+label)
    reject('wrong_symbol_label', lambda d: d['records'][0]['symbol'].__setitem__('name', 'il2cpp_fiction'))
    reject('wrong_branch_target', lambda d: d['records'][0]['direct_B_chain'][0].__setitem__('target', '0x6ff688'))
    reject('wrong_raw_word', lambda d: d['records'][0]['direct_B_chain'][0].__setitem__('raw_bytes', '00000094'))
    reject('omitted_chain', lambda d: d['records'].pop())
    reject('wrong_export_scope', lambda d: d.__setitem__('defined_IL2CPP_function_exports_scanned', 238))
    reject('invented_unknown_link', lambda d: d['original_unknown_FDE_entries_linked'].append('0x1234'))
    reject('wrong_final_target', lambda d: d['records'][0].__setitem__('final_observed_target', '0x1234'))
    reject('wrong_shared_helper_target', lambda d: d['class_init_shared_target_observation'].__setitem__('shared_target', '0x6e19f8'))
    reject('invented_runtime_verification', lambda d: d.__setitem__('runtime_verified', True))
    for word in (0x94000000, 0x54000000, 0xd61f0100, 0xd65f03c0):
        assert branch(word.to_bytes(4, 'little'), 0x100) is None
    assert branch(bytes.fromhex('02000014'), 0x100) == 0x108
    assert branch(bytes.fromhex('ffffff17'), 0x100) == 0xfc
    result = dict(integrity_passed=True, independent_ELF64_PT_LOAD_dynsym_parser=True,
                  independent_raw_A64_B_decoder=True, producer_imported=False,
                  ELF_sha256=digest(raw), bridges_sha256=digest(path.read_bytes()),
                  producer_sha256=doc['producer_sha256'], classification_sha256=doc['classification_sha256'],
                  auditor_sha256=digest(Path(__file__).read_bytes()),
                  exports_scanned=len(image.exports), bridges_checked=bridges,
                  original_unknown_FDE_entries_linked=linked, unique_branch_bytes_checked=byte_count,
                  chain_stop_reasons=stops, negative_mutations_rejected=controls,
                  encoding_negative_controls_passed=4, displacement_positive_controls_passed=2,
                  runtime_verified=False,
                  limits=['Labels and direct branch encodings only; no ABI or semantic implementation inference.',
                          'Original unknown classification is source scope; no category changed.'])
    (OUT/'audit.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
