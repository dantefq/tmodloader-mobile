"""Cross-check recorded call sites against original AArch64 words for three FDEs."""
import collections
import csv
import hashlib
import json
import struct
from pathlib import Path


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def call(word, pc):
    if word & 0xfc000000 == 0x94000000:
        displacement = word & 0x3ffffff
        if displacement & 0x2000000:
            displacement -= 0x4000000
        return ('BL', pc + 4 * displacement)
    if word & 0xfffffc1f == 0xd63f0000:
        return ('BLR', (word >> 5) & 31)
    raise ValueError('Not a supported BL/BLR encoding')


assert call(0x94000002, 0x100) == ('BL', 0x108)
assert call(0x97ffffff, 0x100) == ('BL', 0xfc)
assert call(0xd63f0100, 0x100) == ('BLR', 8)
for bad in (0x14000002, 0xd65f03c0, 0xd503201f):
    try:
        call(bad, 0x100)
    except ValueError:
        pass
    else:
        raise AssertionError('Non-call instruction accepted')
lab = Path(r'C:\Temp\terraria-re-20261012')
elf_path = lab / 'native/libil2cpp.so'
raw = elf_path.read_bytes()
assert hashlib.sha256(raw).hexdigest() == '9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
assert raw[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', raw, 18)[0] == 183
phoff = struct.unpack_from('<Q', raw, 32)[0]
phsize, phcount = struct.unpack_from('<HH', raw, 54)
assert phsize == 56
segments = [struct.unpack_from('<IIQQQQQQ', raw, phoff + phsize * i) for i in range(phcount)]


def source(address, size):
    matches = [p for p in segments if p[0] == 1 and p[3] <= address and address + size <= p[3] + p[5]]
    assert len(matches) == 1
    offset = matches[0][2] + address - matches[0][3]
    return raw[offset:offset + size]


selected = {0xf6954c: 'Main.DrawNPCDirect_1', 0xf9a914: 'Main.DrawNPCDirect_2', 0x1484e54: 'Projectile.Kill'}
bounds = {}
for line in (lab / 'native/unwind-function-ranges.tsv').read_text().splitlines():
    fields = line.split('\t')
    start = int(fields[0], 16)
    if start in selected:
        bounds[start] = int(fields[1], 16)
assert len(bounds) == 3
records = collections.defaultdict(list)
with (lab / 'pseudocode/calls.tsv').open(encoding='utf8', newline='') as stream:
    reader = csv.DictReader(stream, delimiter='\t')
    assert reader.fieldnames == ['caller', 'source', 'target', 'type']
    for row in reader:
        caller = int(row['caller'], 16)
        if caller not in selected:
            continue
        pc = int(row['source'], 16)
        assert caller <= pc < bounds[caller] and pc % 4 == 0
        data = source(pc, 4)
        word = struct.unpack('<I', data)[0]
        kind, value = call(word, pc)
        if kind == 'BL':
            assert value == int(row['target'], 16)
        records[caller].append(dict(site=hex(pc), raw_bytes=data.hex(), encoding=kind,
                                    derived_target=hex(value) if kind == 'BL' else None,
                                    target_register=value if kind == 'BLR' else None,
                                    recorded_reference_type=row['type']))
methods = []
for start, name in selected.items():
    body = source(start, bounds[start] - start)
    encoded = []
    for index in range(0, len(body), 4):
        try:
            kind, value = call(struct.unpack_from('<I', body, index)[0], start + index)
        except ValueError:
            continue
        encoded.append(dict(site=hex(start + index), encoding=kind,
                            target=hex(value) if kind == 'BL' else None,
                            target_register=value if kind == 'BLR' else None))
    sites = {r['site'] for r in records[start]}
    all_sites = {r['site'] for r in encoded}
    assert sites <= all_sites
    counts = collections.Counter(r['encoding'] for r in encoded)
    methods.append(dict(name=name, address=hex(start), end_exclusive=hex(bounds[start]),
                        source_sha256=hashlib.sha256(body).hexdigest(),
                        recorded_reference_rows=len(records[start]), recorded_unique_sites=len(sites),
                        encoded_call_counts=dict(counts), encoded_calls_not_recorded=[r for r in encoded if r['site'] not in sites],
                        recorded_sites=records[start]))
out = lab / 'remaining-method-call-sites-20261019.json'
assert not out.exists()
report = dict(elf_sha256=hashlib.sha256(raw).hexdigest(), calls_table_sha256=sha(lab / 'pseudocode/calls.tsv'),
              producer_sha256=sha(Path(__file__)), methods=methods, negative_noncall_controls=3,
              scope='Recorded static call references and BL/BLR encodings in exact FDE byte ranges only. No reachability, runtime frequency, live Funcdata call count, indirect target or ABI effects are proved. Unrecorded encodings are candidates, not newly established reachable calls.',
              C_coverage_addition=0)
out.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps([dict(name=r['name'], recorded_unique_sites=r['recorded_unique_sites'], encoded_call_counts=r['encoded_call_counts'], unrecorded=len(r['encoded_calls_not_recorded'])) for r in methods]))
