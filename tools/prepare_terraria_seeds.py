"""Create deterministic Ghidra seeds from the validated offline IL2CPP address map."""
import argparse
import json
from pathlib import Path
import re
import struct

def main():
    p = argparse.ArgumentParser()
    p.add_argument('mapping', type=Path)
    p.add_argument('output', type=Path)
    args = p.parse_args()
    rows = json.loads(args.mapping.read_text(encoding='utf-8'))
    seen = set()
    result = []
    core = {'Terraria.Main', 'Terraria.Player', 'Terraria.NPC', 'Terraria.Item',
            'Terraria.Projectile', 'Terraria.WorldGen', 'Terraria.NetMessage',
            'Terraria.MessageBuffer', 'Terraria.IO.WorldFile', 'Terraria.IO.PlayerFileData'}
    priority_methods = {'Update', 'UpdateDead', 'Spawn', 'KillMe', 'Hurt', 'StrikeNPC',
                        'AI', 'SetDefaults', 'UpdateTime', 'SendData', 'GetData',
                        'SaveWorld', 'LoadWorld', 'SavePlayer', 'LoadPlayer', 'ItemCheck',
                        'GenerateWorld', 'NewProjectile', 'NewNPC'}
    for row in rows:
        address = row.get('address')
        if not address or address in seen:
            continue
        seen.add(address)
        full = row['type'] + '::' + row['name']
        clean = re.sub('[^A-Za-z0-9_]', '_', full)[:180]
        clean += '_m' + str(row['method_index'])
        priority = (0 if row['name'] in priority_methods else 1) if row['type'] in core else (2 if row['image'] == 'Assembly-CSharp.dll' else 3)
        result.append((address, clean, full, row['image'], str(priority)))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(''.join('\t'.join(r)+'\n' for r in result), encoding='utf-8')
    binary = (args.mapping.parent/'libil2cpp.so').read_bytes()
    segment_offset = struct.unpack_from('<Q', binary, 32)[0]
    segment_size, segment_count = struct.unpack_from('<HH', binary, 54)
    segments = [struct.unpack_from('<II6Q', binary, segment_offset+i*segment_size) for i in range(segment_count)]
    addresses = {int(r[0],16) for r in result}
    generic_seeds = args.mapping.parent/'generic-method-seeds.tsv'
    if generic_seeds.exists():
        addresses.update(int(line.split('\t')[0],16) for line in generic_seeds.read_text(encoding='utf-8').splitlines() if line)
    anchors = []
    for address in sorted(addresses):
        matches = [s for s in segments if s[0]==1 and s[3]<=address and address+16<=s[3]+s[5]]
        if len(matches)!=1:
            raise ValueError(f'Non-unique file mapping for {address:#x}')
        segment = matches[0]
        offset = segment[2]+address-segment[3]
        anchors.append(f'{address:#x}\t{binary[offset:offset+16].hex()}\n')
    args.output.with_name('method-byte-anchors.tsv').write_text(''.join(anchors), encoding='utf-8')
    print(json.dumps({'seeds':len(result), 'output':str(args.output)}))

if __name__ == '__main__':
    main()
