"""Compare saved mod references with the built shim, without executing mod code.

This is a type/member-name inventory; no signature or behavioral compatibility claim.
"""
import argparse
import json
from pathlib import Path
from inspect_mod_api import metadata

ROOT = Path(__file__).resolve().parents[1]


def area(name):
    if name.startswith(('Terraria.ModLoader.IO.', 'Terraria.IO.')): return 'persistence'
    if name.startswith(('Terraria.ModLoader.Config.',)): return 'configuration'
    if any(token in name for token in ('Projectile', 'NPC', 'DamageClass', 'HitInfo', 'StatModifier')): return 'combat-and-ai'
    if any(token in name for token in ('World', 'Tile', 'Biome', 'Wall', 'Water', 'Gen')): return 'world-content'
    if any(token in name for token in ('Texture', 'Draw', 'UI', 'Gore', 'Dust', 'Asset', 'Sound', 'Audio', 'Music')): return 'assets-rendering-audio'
    if any(token in name for token in ('Item', 'Recipe', 'Prefix')): return 'items-and-recipes'
    if 'Player' in name: return 'player'
    return 'loader-and-game-services'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--shim', type=Path, required=True)
    p.add_argument('--audit', type=Path, default=ROOT/'reports/calamity-api-audit.json')
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    audit = json.loads(args.audit.read_text(encoding='utf-8-sig'))
    shim = metadata(args.shim.read_bytes(), include_definitions=True)
    types, members = set(shim['defined_type_names']), set(shim['defined_member_names'])
    rows = [{'type': name, 'area': area(name), 'declared_in_shim': name in types,
             'direct_members': [{'name': member.split('::', 1)[1], 'declared_in_shim': member in members}
                                for member in audit['tml_direct_member_references'] if member.startswith(name+'::')]}
            for name in audit['tml_type_references']]
    result = {'audit_source': args.audit.name, 'required_types': len(rows),
              'declared_type_names': sum(r['declared_in_shim'] for r in rows),
              'required_direct_members': len(audit['tml_direct_member_references']),
              'declared_direct_member_names': len(set(audit['tml_direct_member_references']) & members),
              'compatibility_verified': False, 'assembly_executed': False,
              'limitations': 'Names only; signatures, generics, reflection, IL hooks, FNA/ReLogic behavior and mobile binding are not validated.',
              'references': rows}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in result.items() if k != 'references'}))


if __name__ == '__main__':
    main()
