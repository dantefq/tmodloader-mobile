"""Run only a pinned original SOTS item's constructor/SetDefaults on host snapshots.

This explicitly executes original mod code in a separate process. No game is
launched, no mod Load/SetStaticDefaults is invoked, and Android is not tested.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import zlib
import uuid

from audit_content_reachability import build
from inspect_mod_api import assembly_bytes, dnfile
from managed_api_sources import API_SOURCES

ROOT = Path(__file__).resolve().parents[1]
TMOD_SHA = '4642380a29751664afa9122f01a8cf4491232ef9cd7bdb40e15c6d8e4e7c3790'
DLL_SHA = 'e96d7591ec56f5236454931ae0a3045be6072d2a7649f70679131bf0f0ee338f'
SOURCE_SHA = 'd9bd4e8ffc18a19de89432ac56126661b76bd57eefb164a893a790d61cbf59ef'
IMAGE_SHA = '783e86053ec749c41e1b05e89cca94a09966ff3b40423ca18dd9faf8a9494b05'
TYPE = 'SOTS.Items.HelicopterParts'
PROFILES = {
    TYPE: ('Items/HelicopterParts', SOURCE_SHA, IMAGE_SHA),
    'SOTS.Items.Pyramid.Snakeskin': ('Items/Pyramid/Snakeskin',
        '6824959d66f7f2c67bb8a32b2cb6451409ef0c79f68860ecba064d9136935408',
        'ae0bbdd03befa4eebe9bfb6767aeeeb4e8540a5e98c03e94ee8bf1ce7fa95870'),
    'SOTS.Items.Fishing.Curgeon': ('Items/Fishing/Curgeon',
        'c735626659800138474ea3b4a2b4ce9f97ea46e41ac8b90f67aad36e74295871',
        '9e9a0111f41a9dd87d374af797005e5f1929fab730bf2ee02e4d7940f307e712'),
}


def require_hash(data, expected):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('Pinned reference hash differs')


def require_scope(report, selected_type=TYPE):
    if selected_type not in PROFILES:
        raise ValueError('No reviewed defaults profile')
    if report['content_type'] != selected_type:
        raise ValueError('Content identity differs from reviewed profile')
    expected_methods = {selected_type + '::.ctor', selected_type + '::SetDefaults'}
    allowed = {'Terraria.ModLoader.ModItem::get_Item', 'Terraria.ModLoader.ModItem::.ctor',
               'Terraria.Entity::width', 'Terraria.Entity::height', 'Terraria.Item::sellPrice',
               'Terraria.Item::value', 'Terraria.Item::rare', 'Terraria.Item::maxStack'}
    if {m['name'] for m in report['methods']} != expected_methods or len(report['methods']) != 2:
        raise ValueError('Unexpected method/initializer closure')
    if report['root_methods'] != ['.ctor', 'SetDefaults']:
        raise ValueError('Unexpected root selection')
    expected_edges = Counter({
        ('Terraria.ModLoader.ModItem::get_Item', 'call', '20001255'): 5,
        ('Terraria.ModLoader.ModItem::.ctor', 'call', '200001'): 1,
        ('Terraria.Item::sellPrice', 'call', '00040808080808'): 1,
        **{(name, 'stfld', '0608'): 1 for name in (
            'Terraria.Entity::width', 'Terraria.Entity::height', 'Terraria.Item::value',
            'Terraria.Item::rare', 'Terraria.Item::maxStack')}
    })
    actual_edges = Counter((e['target'], e['opcode'], e['signature']) for e in report['dependencies'])
    if actual_edges != expected_edges:
        raise ValueError('Pinned dependency signatures or counts differ')
    for edge in report['dependencies']:
        if edge['target'] not in allowed or edge['opcode'] not in ('call', 'stfld') or edge['generic_signature']:
            raise ValueError('Unexpected dependency, dispatch or generic specialization')
    expected_blockers = {'External base lifecycle: Terraria.ModLoader.ModItem'} | {
        'External or unresolved dependency: ' + name for name in allowed}
    if set(report['blockers']) != expected_blockers:
        raise ValueError('Unexpected scope blocker')


def source_oracle(source, tml):
    # Read the shipped reference; never publish the source or copy its values into the shim.
    text = source.decode('utf-8')
    result = {}
    for name in ('width', 'height', 'maxStack'):
        matches = re.findall(r'Item\.' + name + r'\s*=\s*(\d+)\s*;', text)
        if len(matches) != 1:
            raise ValueError('Ambiguous source assignment')
        result[name] = int(matches[0])
    price = re.findall(r'Item\.value\s*=\s*Item\.sellPrice\((\d+),\s*(\d+),\s*(\d+),\s*(\d+)\)\s*;', text)
    rarity = re.findall(r'Item\.rare\s*=\s*ItemRarityID\.(\w+)\s*;', text)
    if len(price) != 1 or len(rarity) != 1:
        raise ValueError('Ambiguous price/rarity source')
    coins = list(map(int, price[0]))
    result['value'] = sum(n * scale for n, scale in zip(coins, (1000000, 10000, 100, 1))) * 5
    pe = dnfile.dnPE(str(tml))
    try:
        fields = [f.row for t in pe.net.mdtables.TypeDef.rows
                  if str(t.TypeNamespace) == 'Terraria.ID' and str(t.TypeName) == 'ItemRarityID'
                  for f in t.FieldList if str(f.row.Name) == rarity[0]]
        values = [c for c in pe.net.mdtables.Constant.rows if fields and c.Parent.row is fields[0]]
        if len(fields) != 1 or len(values) != 1 or values[0].Type != 8:
            raise ValueError('Rarity constant not uniquely resolved as Int32')
        result['rare'] = struct.unpack('<i', values[0].Value.value)[0]
    finally:
        pe.close()
    return result


def verify_png(data, width, height, rgba):
    if data[:8] != b'\x89PNG\r\n\x1a\n':
        raise ValueError('PNG signature differs')
    offset = 8; chunks = []; compressed = bytearray()
    while offset < len(data):
        if offset + 12 > len(data):
            raise ValueError('Truncated PNG chunk')
        length = struct.unpack_from('>I', data, offset)[0]
        kind = data[offset+4:offset+8]; end = offset + 8 + length
        if end + 4 > len(data):
            raise ValueError('PNG chunk outside file')
        payload = data[offset+8:end]
        if struct.unpack_from('>I', data, end)[0] != zlib.crc32(kind + payload):
            raise ValueError('PNG CRC differs')
        chunks.append(kind)
        if kind == b'IHDR' and payload != struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0):
            raise ValueError('PNG dimensions/channels differ')
        if kind == b'IDAT': compressed.extend(payload)
        if kind == b'IEND' and payload:
            raise ValueError('PNG end chunk must be empty')
        offset = end + 4
    if chunks != [b'IHDR', b'IDAT', b'IEND']:
        raise ValueError('Unexpected PNG chunk sequence')
    decoder = zlib.decompressobj()
    expected = b''.join(b'\0' + rgba[row*width*4:(row+1)*width*4] for row in range(height))
    pixels = decoder.decompress(compressed, len(expected) + 1)
    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail or pixels != expected:
        raise ValueError('PNG decoded rows differ from original RGBA')


def verify_texture_packet(data, asset, archive_sha, png, width, height):
    # Independent wire-format check; GUID bytes use the .NET mixed-endian form.
    if data[:5] != b'TMIT\x01':
        raise ValueError('Texture packet signature differs')
    key_length = struct.unpack_from('<i', data, 5)[0]
    key = data[9:9+key_length].decode('utf-8', errors='strict')
    pos = 9 + key_length
    generation = uuid.UUID(bytes_le=data[pos:pos+16]); pos += 16
    actual_archive = data[pos:pos+32].hex(); pos += 32
    actual_width, actual_height, count = struct.unpack_from('<iii', data, pos); pos += 12
    digest = data[pos:pos+32]; pos += 32
    if key != asset or actual_archive != archive_sha or str(generation) != '13fb5666-8cf1-4941-acf8-8d54eff30d10':
        raise ValueError('Texture packet identity differs from probe fixture')
    if (actual_width, actual_height, count) != (width, height, len(png)) or data[pos:] != png:
        raise ValueError('Texture packet dimensions/PNG differ')
    if digest != hashlib.sha256(png).digest():
        raise ValueError('Texture packet checksum differs')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('tmod', type=Path)
    p.add_argument('--lab', required=True, type=Path)
    p.add_argument('--type', choices=sorted(PROFILES), default=TYPE)
    p.add_argument('--dotnet', type=Path, default=Path('C:/Program Files/dotnet'))
    p.add_argument('--tml', type=Path, default=Path('C:/Program Files (x86)/Steam/steamapps/common/tModLoader/tModLoader.dll'))
    args = p.parse_args()
    require_hash(args.tmod.read_bytes(), TMOD_SHA)
    dll, _ = assembly_bytes(args.tmod, 'SOTS.dll'); require_hash(dll, DLL_SHA)
    entry, source_sha, image_sha = PROFILES[args.type]
    source, _ = assembly_bytes(args.tmod, entry + '.cs'); require_hash(source, source_sha)
    oracle = source_oracle(source, args.tml)
    command, folder = build(args.dotnet, args.lab / args.type.replace('.', '_'))
    original = folder / 'SOTS.dll'; original.write_bytes(dll)
    audit = json.loads(subprocess.check_output([*command, str(original), args.type, '.ctor,SetDefaults'], text=True, encoding='utf-8', timeout=60))
    require_scope(audit, args.type)
    (folder / 'defaults-scope.json').write_text(json.dumps(audit, indent=2), encoding='utf-8')
    refs = sorted((args.dotnet / 'packs/Microsoft.NETCore.App.Ref/8.0.31/ref/net8.0').glob('*.dll'))
    def compile(name, sources, extra=(), exe=False):
        output = folder / name
        rsp = folder / (name + '.rsp')
        rsp.write_text('\n'.join(['-nologo', '-nostdlib+', '-deterministic+', '-langversion:12',
            '-target:' + ('exe' if exe else 'library'), f'-out:"{output}"',
            *[f'-r:"{r}"' for r in [*refs, *extra]], *[f'"{ROOT / s}"' for s in sources]]), encoding='utf-8')
        subprocess.run([str(args.dotnet / 'dotnet.exe'), str(args.dotnet / 'sdk/8.0.425/Roslyn/bincore/csc.dll'), '@' + str(rsp)], check=True, timeout=120)
        return output
    shim = compile('tModLoader.dll', API_SOURCES)
    runner = compile('OriginalItemDefaultsProbe.dll', ['managed/tools/OriginalItemDefaultsProbe.cs'], [shim], True)
    runner.with_suffix('.runtimeconfig.json').write_text(json.dumps({'runtimeOptions': {
        'tfm': 'net8.0', 'framework': {'name': 'Microsoft.NETCore.App', 'version': '8.0.31'}}}), encoding='utf-8')
    result = subprocess.run([str(args.dotnet / 'dotnet.exe'), str(runner), str(original), args.type],
                            capture_output=True, text=True, encoding='utf-8', check=True, timeout=30)
    report = json.loads(result.stdout)
    if report['content_type'] != args.type or report['original_assembly_executed'] is not True or any(
            report[k] is not False for k in ('mod_lifecycle_executed', 'static_defaults_executed',
                                            'android_verified', 'rendering_verified', 'full_mod_compatible')):
        raise ValueError('Probe result phase/identity differs')
    for i, snapshot in enumerate(report['snapshots']):
        if snapshot != dict(type=6196+i, **oracle):
            raise ValueError('Original defaults differ from shipped-source oracle')
    if len(report['snapshots']) != 2:
        raise ValueError('Expected independent instances')
    require_hash(args.tmod.read_bytes(), TMOD_SHA)
    report.update(tmod_sha256=TMOD_SHA, dll_sha256=DLL_SHA, source_sha256=source_sha,
                  source_oracle_matched=True, independent_instances=2)
    image, _ = assembly_bytes(args.tmod, entry + '.rawimg'); require_hash(image, image_sha)
    image_path = folder / 'original-item.rawimg'; image_path.write_bytes(image)
    image_runner = compile('RawImageTests.dll', ['managed/tests/RawImageTests.cs'], [shim], True)
    image_runner.with_suffix('.runtimeconfig.json').write_bytes(runner.with_suffix('.runtimeconfig.json').read_bytes())
    png = folder / 'original-item.png'
    result = subprocess.run([str(args.dotnet / 'dotnet.exe'), str(image_runner), str(args.tmod), entry + '.rawimg', str(png)],
                            capture_output=True, text=True, encoding='utf-8', check=True, timeout=30)
    decoded = json.loads(result.stdout.splitlines()[-1])
    if (decoded['width'], decoded['height']) != (oracle['width'], oracle['height']):
        raise ValueError('Original item texture dimensions differ from defaults')
    if decoded['rgba_sha256'] != hashlib.sha256(image[12:]).hexdigest():
        raise ValueError('Original RGBA channels changed during decoding')
    verify_png(png.read_bytes(), decoded['width'], decoded['height'], image[12:])
    verify_texture_packet(Path(str(png) + '.tmit').read_bytes(), 'SOTS/' + entry + '.rawimg', TMOD_SHA,
                          png.read_bytes(), decoded['width'], decoded['height'])
    # Fixture includes alpha 0/1/127/255 and distinct rows; no visual transformation is allowed.
    verify_png(Path(str(png) + '.fixture.png').read_bytes(), 2, 2,
               bytes([1, 2, 3, 255, 40, 50, 60, 127, 7, 8, 9, 0, 9, 8, 7, 1]))
    report.update(image_sha256=image_sha, cpu_image_decode=decoded, png_roundtrip_verified=True,
                  texture_packet_wire_verified=True, packet_generation_is_synthetic=True)
    report.update(shim_sha256=hashlib.sha256(shim.read_bytes()).hexdigest(),
                  runner_sha256=hashlib.sha256(runner.read_bytes()).hexdigest(),
                  analyzer_source_sha256=hashlib.sha256((ROOT / 'managed/tools/ContentReachability.cs').read_bytes()).hexdigest(),
                  api_source_sha256={s: hashlib.sha256((ROOT / s).read_bytes()).hexdigest() for s in API_SOURCES})
    (folder / 'original-defaults-result.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print('PASS ' + args.type + ': two original defaults instances match shipped-source oracle; original RGBA decoded; full lifecycle/rendering/Android not tested')


if __name__ == '__main__':
    main()
