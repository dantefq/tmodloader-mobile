"""Make an isolated analysis-engine copy with a larger Windows PE stack reserve."""
import argparse, hashlib, json, pathlib, shutil, struct

p = argparse.ArgumentParser()
p.add_argument('source', type=pathlib.Path)
p.add_argument('destination', type=pathlib.Path)
a = p.parse_args()
src, dst = a.source.resolve(), a.destination.resolve()
if src == dst or dst.exists():
    raise SystemExit('Destination must be new and different from source')
shutil.copytree(src, dst)
relative = pathlib.Path('Ghidra/Features/Decompiler/os/win_x86_64/decompile.exe')
original = (src / relative).read_bytes()
modified = bytearray(original)
pe = struct.unpack_from('<I', original, 0x3c)[0]
optional = pe + 24
assert original[pe:pe+4] == b'PE\0\0'
assert struct.unpack_from('<H', original, optional)[0] == 0x20b
offset = optional + 72
old = struct.unpack_from('<Q', original, offset)[0]
assert old == 1048576, old
struct.pack_into('<Q', modified, offset, 32 * 1024 * 1024)
differences = [i for i, (x, y) in enumerate(zip(original, modified)) if x != y]
assert all(offset <= i < offset + 8 for i in differences)
(dst / relative).write_bytes(modified)
assert (src / relative).read_bytes() == original
sections = []
count = struct.unpack_from('<H', original, pe + 6)[0]
optional_size = struct.unpack_from('<H', original, pe + 20)[0]
for i in range(count):
    pos = optional + optional_size + 40*i
    name = original[pos:pos+8].rstrip(b'\0').decode('ascii')
    size, location = struct.unpack_from('<II', original, pos+16)
    assert original[location:location+size] == modified[location:location+size]
    sections.append({'name': name, 'sha256': hashlib.sha256(original[location:location+size]).hexdigest()})
record = {'purpose': 'isolated decompiler stack-overflow diagnostic; target APK unchanged',
          'source': str(src / relative), 'copy': str(dst / relative),
          'original_sha256': hashlib.sha256(original).hexdigest(),
          'modified_sha256': hashlib.sha256(modified).hexdigest(),
          'stack_reserve_before': old, 'stack_reserve_after': 32*1024*1024,
          'changed_byte_offsets': differences, 'all_section_bytes_identical': True,
          'sections': sections, 'original_unchanged': True}
(dst.parent / 'ghidra-stack32-provenance.json').write_text(json.dumps(record, indent=2), encoding='utf-8')
print(json.dumps(record, indent=2))
