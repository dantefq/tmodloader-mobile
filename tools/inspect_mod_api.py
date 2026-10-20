"""Read .tmod assembly metadata without loading/executing the assembly.

Requires dnfile (pip install dnfile). Reports references, not compatibility.
No DLL or game implementation is written to disk.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import zlib

from inspect_workshop import exact, integer, string

try:
    import dnfile
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'.tools/metadata-deps'))
    import dnfile


def assembly_bytes(path, entry_name):
    with path.open('rb') as stream:
        if exact(stream, 4) != b'TMOD':
            raise ValueError('Not a TMOD')
        loader = string(stream)
        if tuple(map(int, loader.split('.'))) < (0, 11):
            raise ValueError('Legacy format not supported')
        digest = exact(stream, 20)
        exact(stream, 256)  # Do not treat the signature as authenticated.
        payload_size = integer(stream)
        if payload_size != path.stat().st_size-stream.tell():
            raise ValueError('Payload length mismatch')
        start = stream.tell()
        sha = hashlib.sha1()
        while chunk := stream.read(1024*1024):
            sha.update(chunk)
        if sha.digest() != digest:
            raise ValueError('Payload SHA1 mismatch')
        stream.seek(start)
        name, version = string(stream), string(stream)
        count = integer(stream)
        if not 0 <= count <= 100000:
            raise ValueError('Invalid entry count')
        entries = []
        for _ in range(count):
            entry, expanded, stored = string(stream), integer(stream), integer(stream)
            if min(expanded, stored) < 0:
                raise ValueError('Negative size')
            entries.append((entry, expanded, stored))
        if sum(e[2] for e in entries) != path.stat().st_size-stream.tell():
            raise ValueError('Entry coverage mismatch')
        selected = None
        for entry, expanded, stored in entries:
            if entry != entry_name:
                stream.seek(stored, 1)
                continue
            if selected is not None or max(stored, expanded) > 128*1024*1024:
                raise ValueError('Duplicate or oversized assembly')
            data = exact(stream, stored)
            if stored != expanded:
                decoder = zlib.decompressobj(-15)
                data = decoder.decompress(data, expanded+1)
                if not decoder.eof or decoder.unconsumed_tail or decoder.unused_data:
                    raise ValueError('Incomplete or oversized deflate stream')
            if len(data) != expanded:
                raise ValueError('Expanded size mismatch')
            selected = data
        if selected is None:
            raise ValueError('Assembly entry missing')
        return selected, {'mod': name, 'version': version, 'loader': loader,
                          'payload_sha1_verified': True, 'signature_authenticated': False}


def metadata(data, include_definitions=False):
    pe = dnfile.dnPE(data=data)
    try:
        if pe.net is None:
            raise ValueError('Assembly is not managed')
        tables = pe.net.mdtables
        def rows(name):
            table = getattr(tables, name, None)
            return table.rows if table else []
        enclosing = {}
        for nested in rows('NestedClass'):
            child, parent = nested.NestedClass.row, nested.EnclosingClass.row
            if child is None or parent is None or id(child) in enclosing:
                raise ValueError('Invalid or duplicate nested class metadata')
            enclosing[id(child)] = parent
        def identity(row, seen=None):
            seen = set() if seen is None else seen
            if id(row) in seen:
                raise ValueError('Cyclic nested type metadata')
            seen.add(id(row))
            if id(row) in enclosing:
                return identity(enclosing[id(row)], seen)+'/'+str(row.TypeName)
            ref = getattr(row, 'ResolutionScope', None)
            if ref is not None and ref.row is not None and hasattr(ref.row, 'ResolutionScope'):
                return identity(ref.row, seen)+'/'+str(row.TypeName)
            namespace = str(row.TypeNamespace)
            return (namespace+'.' if namespace else '')+str(row.TypeName)
        def scope(row, seen=None):
            seen = set() if seen is None else seen
            if id(row) in seen:
                raise ValueError('Cyclic metadata scope')
            seen.add(id(row))
            ref = row.ResolutionScope
            if ref.row is None:
                return '<local>'
            if hasattr(ref.row, 'ResolutionScope'):
                return scope(ref.row, seen)
            return str(getattr(ref.row, 'Name', '<unknown>'))
        references = rows('TypeRef')
        types = sorted({identity(row) for row in references if scope(row) == 'tModLoader'})
        members = set()
        for row in rows('MemberRef'):
            owner = row.Class.row
            if owner is not None and hasattr(owner, 'ResolutionScope') and scope(owner) == 'tModLoader':
                members.add(identity(owner)+'::'+str(row.Name))
        bases = Counter()
        for row in rows('TypeDef'):
            if row.Extends.row is not None and hasattr(row.Extends.row, 'TypeNamespace'):
                base = identity(row.Extends.row)
                if base.startswith('Terraria.ModLoader.'):
                    bases[base] += 1
        result = {'assembly_references': [{'name':str(r.Name), 'version':'.'.join(str(getattr(r,x)) for x in ('MajorVersion','MinorVersion','BuildNumber','RevisionNumber'))} for r in rows('AssemblyRef')],
                'type_definition_count': len(rows('TypeDef')),
                'tml_type_references': types, 'tml_direct_member_references': sorted(members),
                'direct_tml_base_counts':dict(sorted(bases.items())),
                'reference_scope_counts':dict(Counter(scope(r) for r in references))}
        if include_definitions:
            result['defined_type_names'] = [identity(r) for r in rows('TypeDef')]
            result['defined_member_names'] = sorted({identity(r)+'::'+str(member.row.Name)
                for r in rows('TypeDef') for member in [*r.MethodList, *r.FieldList]})
        return result
    finally:
        pe.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tmod', type=Path)
    parser.add_argument('--assembly', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--shim', type=Path, help='Own API shim; compare type names only, not signatures/behavior')
    args = parser.parse_args()
    data, header = assembly_bytes(args.tmod, args.assembly)
    report = {**header, 'assembly_entry':args.assembly,
              'assembly_sha256':hashlib.sha256(data).hexdigest(), **metadata(data),
              'assembly_executed':False, 'assembly_extracted_to_disk':False,
              'compatibility_verified':False,
              'limitations':'Static references only. Generic TypeSpec member owners, reflection and dynamically accessed APIs are not fully enumerated. Base counts are direct inheritance only.'}
    if args.shim:
        shim = args.shim.read_bytes()
        provided = set(metadata(shim, include_definitions=True)['defined_type_names'])
        missing = sorted(set(report['tml_type_references'])-provided)
        report['own_shim_comparison'] = {'sha256':hashlib.sha256(shim).hexdigest(),
            'missing_referenced_types':missing, 'missing_type_count':len(missing),
            'type_name_comparison_only':True, 'matching_names_do_not_prove_compatibility':True}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({k:report[k] for k in ('mod','version','type_definition_count','direct_tml_base_counts')}))
    print(json.dumps({'tml_types':len(report['tml_type_references']), 'tml_direct_members':len(report['tml_direct_member_references']), 'executed':False}))


if __name__ == '__main__':
    main()
