"""Compare selected local mods without executing their DLLs or extracting code."""
import argparse
import hashlib
import json
from pathlib import Path

from inspect_mod_api import assembly_bytes, metadata

NAMES = ('ShorterRespawn', 'ChangeSleepTime', 'DisableCorruptionSpread',
         'NoFishingQuests', 'Roommates', 'Lights', 'BossCursor', 'TownNPCHome')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, default=Path('reports/workshop-inventory.json'))
    parser.add_argument('--output', type=Path, default=Path('reports/small-mod-candidates.json'))
    parser.add_argument('--shim', type=Path)
    args = parser.parse_args()
    inventory = json.loads(args.inventory.read_text(encoding='utf-8'))
    root = Path(inventory['root'])
    provided = set(metadata(args.shim.read_bytes(), True)['defined_type_names']) if args.shim else None
    reports = []
    for name in NAMES:
        selected = max((r for r in inventory['files'] if r['name'] == name),
                       key=lambda r: tuple(map(int, r['tmodloader_build_version'].split('.'))))
        path = root / selected['path']
        data, header = assembly_bytes(path, name + '.dll')
        report = {**header, 'path': selected['path'], 'bytes': path.stat().st_size,
                  'assembly_sha256': hashlib.sha256(data).hexdigest(), **metadata(data),
                  'executed': False, 'compatibility_verified': False}
        if provided is not None:
            report['own_shim_missing_type_names'] = sorted(set(report['tml_type_references']) - provided)
        reports.append(report)
    report = {
        'scope': 'Read-only static references; no mod executed or DLL written to disk; highest loader build in the supplied local inventory per selected name.',
        'limitations': 'Type names do not prove behavior/signatures; generic owners, reflection and dynamic dependencies are incomplete. AssemblyRefs are not a complete mandatory-mod dependency list.',
        'first_candidate': 'ChangeSleepTime',
        'selection': 'Initially selected for the smallest observed API surface and no direct FNA/TerrariaHooks AssemblyRef. The separate sleep bridge is now verified on-device; see reports/sleep-device-validation.json. This names-only inventory does not grant generic loader compatibility.',
        'candidates': reports
    }
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    for row in sorted(reports, key=lambda r: len(r['tml_type_references'])):
        print(json.dumps({'mod': row['mod'], 'version': row['version'],
                          'types': len(row['tml_type_references']),
                          'members': len(row['tml_direct_member_references']), 'executed': False}))


if __name__ == '__main__':
    main()
