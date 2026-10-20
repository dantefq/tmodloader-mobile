"""Audit one explicit local content mod before execution or enabling it."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from inspect_mod_api import assembly_bytes, metadata
from inspect_workshop import exact, integer, string
from plan_mod_load import build


def resource_table(path):
    # assembly_bytes independently validates the complete payload hash/coverage.
    with path.open('rb') as stream:
        if exact(stream, 4) != b'TMOD':
            raise ValueError('Not a TMOD')
        string(stream); exact(stream, 276); integer(stream)
        string(stream); string(stream)
        count = integer(stream)
        if not 0 <= count <= 100000:
            raise ValueError('Entry count outside bounds')
        groups = {}
        for _ in range(count):
            name, expanded, stored = string(stream), integer(stream), integer(stream)
            if min(expanded, stored) < 0:
                raise ValueError('Negative resource size')
            extension = Path(name).suffix.lower() or '<no-extension>'
            group = groups.setdefault(extension, dict(entries=0, expanded_bytes=0, stored_bytes=0))
            group['entries'] += 1
            group['expanded_bytes'] += expanded
            group['stored_bytes'] += stored
        return dict(entry_count=count, by_extension=dict(sorted(groups.items())), resources_decompressed=False)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('tmod', type=Path)
    p.add_argument('--assembly', required=True)
    p.add_argument('--lab', type=Path, required=True)
    p.add_argument('--dotnet', type=Path, default=Path('C:/Program Files/dotnet'))
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    initial_hash = hashlib.sha256(args.tmod.read_bytes()).hexdigest()
    dll, header = assembly_bytes(args.tmod, args.assembly)
    command = build(args.dotnet, args.lab)
    result = subprocess.run([*command, 'client', str(args.tmod)], capture_output=True, text=True, check=True, timeout=120)
    plan = json.loads(result.stdout)
    if len(plan['artifacts']) != 1 or plan['artifacts'][0]['sha256'] != initial_hash:
        raise ValueError('Dependency plan artifact differs')
    definitions = metadata(dll, include_definitions=True)
    # A short list for later method-by-method audit, not executable candidates.
    import dnfile
    pe = dnfile.dnPE(data=dll)
    try:
        items = []
        for row in pe.net.mdtables.TypeDef.rows:
            base = row.Extends.row
            if base is not None and str(getattr(base, 'TypeNamespace', '')) == 'Terraria.ModLoader' and str(base.TypeName) == 'ModItem':
                methods = [str(m.row.Name) for m in row.MethodList]
                items.append(dict(type=str(row.TypeNamespace) + '.' + str(row.TypeName), methods=methods))
        items.sort(key=lambda row: (len(row['methods']), row['type']))
    finally:
        pe.close()
    definitions.pop('defined_member_names')
    definitions.pop('defined_type_names')
    table = resource_table(args.tmod)
    if hashlib.sha256(args.tmod.read_bytes()).hexdigest() != initial_hash:
        raise ValueError('Source changed during audit')
    report = dict(format='terraria-mobile-content-mod-audit-v1', **header,
        source_path=str(args.tmod.resolve()), tmod_sha256=initial_hash,
        dll_sha256=hashlib.sha256(dll).hexdigest(), dependency_plan=plan,
        resources=table, metadata=definitions, smallest_direct_moditem_method_sets=items[:15],
        assembly_executed=False, third_party_files_extracted=False, enabled_on_phone=False,
        compatibility_verified=False,
        limitations=['Direct subclasses and method counts describe metadata, not registered content or compatibility.',
            'Small method sets can still call unsupported helpers; each candidate needs a full reachable-path audit.',
            'Assembly references are declarations, not proof of execution, platform use, or required mod dependencies.',
            'Resources are counted from the table, not decompressed, rendered, or validated by the Android runtime.'])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(mod=header['mod'], version=header['version'], tmod_sha256=initial_hash,
        resource_entries=table['entry_count'], direct_bases=definitions['direct_tml_base_counts'],
        required=plan['artifacts'][0]['required'], weak=plan['artifacts'][0]['weak'], executed=False), indent=2))


if __name__ == '__main__':
    main()
