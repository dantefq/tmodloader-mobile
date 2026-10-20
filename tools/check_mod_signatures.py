"""Conservative static MemberRef preflight; never load a third-party assembly.

Signature encoding: ECMA-335 II.23.2 (6th edition).
https://ecma-international.org/publications-and-standards/standards/ecma-335/
Unsupported encodings are diagnostics, never successful matches.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from inspect_mod_api import assembly_bytes, dnfile


class Unsupported(ValueError):
    pass


class Blob:
    def __init__(self, data):
        self.data = bytes(data)
        self.pos = 0

    def byte(self):
        if self.pos >= len(self.data):
            raise Unsupported('Truncated signature')
        value = self.data[self.pos]
        self.pos += 1
        return value

    def uint(self):
        first = self.byte()
        if first < 0x80:
            return first
        if first < 0xc0:
            return ((first & 0x3f) << 8) | self.byte()
        if first < 0xe0:
            return ((first & 0x1f) << 24) | (self.byte() << 16) | (self.byte() << 8) | self.byte()
        raise Unsupported('Invalid compressed integer')


PRIMITIVES = dict(zip((1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 22, 24, 25, 28),
    ('void', 'bool', 'char', 'i1', 'u1', 'i2', 'u2', 'i4', 'u4', 'i8', 'u8',
     'r4', 'r8', 'string', 'typedref', 'nativeint', 'nativeuint', 'object')))


class Assembly:
    def __init__(self, data):
        self.pe = dnfile.dnPE(data=data)
        if self.pe.net is None:
            self.pe.close()
            raise ValueError('Not a managed assembly')
        self.tables = self.pe.net.mdtables
        self.name = str(self.rows('Assembly')[0].Name)
        self.parents = {id(r.NestedClass.row): r.EnclosingClass.row for r in self.rows('NestedClass')}
        self.definitions = {self.identity(r): r for r in self.rows('TypeDef')}

    def close(self):
        self.pe.close()

    def rows(self, name):
        table = getattr(self.tables, name, None)
        return table.rows if table else []

    def identity(self, row, seen=None):
        seen = set() if seen is None else seen
        if row is None or id(row) in seen:
            raise Unsupported('Missing or cyclic type')
        seen.add(id(row))
        parent = self.parents.get(id(row))
        if parent is not None:
            return self.identity(parent, seen) + '/' + str(row.TypeName)
        scope = getattr(row, 'ResolutionScope', None)
        if scope is not None and scope.row is not None and hasattr(scope.row, 'TypeName'):
            return self.identity(scope.row, seen) + '/' + str(row.TypeName)
        if not hasattr(row, 'TypeName'):
            raise Unsupported('Generic TypeSpec owner requires substitution')
        namespace = str(row.TypeNamespace)
        return (namespace + '.' if namespace else '') + str(row.TypeName)

    def scope(self, row, seen=None):
        seen = set() if seen is None else seen
        if row is None or id(row) in seen:
            raise Unsupported('Missing or cyclic scope')
        seen.add(id(row))
        parent = self.parents.get(id(row))
        if parent is not None:
            return self.scope(parent, seen)
        scope = getattr(row, 'ResolutionScope', None)
        if scope is None or scope.row is None:
            return self.name
        if hasattr(scope.row, 'TypeName'):
            return self.scope(scope.row, seen)
        if hasattr(scope.row, 'Name'):
            return str(scope.row.Name)
        raise Unsupported('Unsupported resolution scope')

    def token_type(self, token, depth):
        tag, rid = token & 3, token >> 2
        if tag == 3 or rid < 1:
            raise Unsupported('Invalid TypeDefOrRefEncoded')
        rows = self.rows(('TypeDef', 'TypeRef', 'TypeSpec')[tag])
        if rid > len(rows):
            raise Unsupported('Out-of-range type token')
        row = rows[rid - 1]
        if tag == 2:
            blob = Blob(row.Signature.value)
            value = self.type(blob, depth + 1)
            if blob.pos != len(blob.data):
                raise Unsupported('Trailing TypeSpec bytes')
            return value
        return ('named', self.scope(row), self.identity(row))

    def type(self, blob, depth=0):
        if depth > 64:
            raise Unsupported('Signature nesting limit')
        code = blob.byte()
        if code in PRIMITIVES:
            return PRIMITIVES[code]
        if code in (0x11, 0x12):
            return ('value' if code == 0x11 else 'class', self.token_type(blob.uint(), depth))
        if code in (0x0f, 0x10, 0x1d):
            return ({0x0f: 'pointer', 0x10: 'byref', 0x1d: 'array'}[code], self.type(blob, depth + 1))
        if code in (0x13, 0x1e):
            return ('var' if code == 0x13 else 'mvar', blob.uint())
        if code == 0x15:
            base = self.type(blob, depth + 1)
            count = blob.uint()
            if count > 1024:
                raise Unsupported('Generic argument limit')
            return ('generic', base, tuple(self.type(blob, depth + 1) for _ in range(count)))
        if code in (0x1f, 0x20):
            return ('modreq' if code == 0x1f else 'modopt', self.token_type(blob.uint(), depth), self.type(blob, depth + 1))
        # Array lower bounds use compressed signed integers. Do not equate
        # an unimplemented multidimensional/function-pointer signature.
        raise Unsupported(f'Unsupported element type 0x{code:02x}')

    def signature(self, data):
        blob = Blob(data)
        convention = blob.byte()
        if convention == 6:
            result = ('field', self.type(blob))
        else:
            if convention & 0x0f != 0 or convention & ~0x70:
                raise Unsupported(f'Unsupported calling convention 0x{convention:02x}')
            generic = blob.uint() if convention & 0x10 else 0
            count = blob.uint()
            if count > 1024:
                raise Unsupported('Parameter count limit')
            result = ('method', convention, generic, self.type(blob), tuple(self.type(blob) for _ in range(count)))
        if blob.pos != len(blob.data):
            raise Unsupported('Trailing signature bytes')
        return result


def compare(mod_data, shim_data):
    mod, shim = Assembly(mod_data), Assembly(shim_data)
    try:
        results = []
        for ref in mod.rows('MemberRef'):
            owner = ref.Class.row
            if owner is None:
                results.append(dict(status='unsupported', member=str(ref.Name), reason='Missing owner'))
                continue
            if not hasattr(owner, 'TypeName'):
                results.append(dict(status='unsupported-owner', member=str(ref.Name),
                    reason='TypeSpec or MethodDef owner not resolved; may reference external assemblies'))
                continue
            if mod.scope(owner) != shim.name:
                continue
            name, member = mod.identity(owner), str(ref.Name)
            result = dict(type=name, member=member)
            target = shim.definitions.get(name)
            if target is None:
                results.append(dict(result, status='missing-type'))
                continue
            try:
                requested = mod.signature(ref.Signature.value)
                result['requested_signature'] = requested
                family = 'FieldList' if requested[0] == 'field' else 'MethodList'
                candidates = [r.row for r in getattr(target, family) if str(r.row.Name) == member]
                if not candidates:
                    # Inheritance is deliberately unresolved until validated.
                    results.append(dict(result, status='missing-declared-member',
                        reason='Inherited members are not resolved by this preflight'))
                    continue
                signatures = []
                errors = []
                for candidate in candidates:
                    try:
                        signatures.append(shim.signature(candidate.Signature.value))
                    except Unsupported as error:
                        errors.append(str(error))
                if requested[0] == 'field':
                    # FieldSig has no static/instance bit; opcode use is not examined.
                    result['field_staticness_checked'] = False
                results.append(dict(result, status=('exact-signature' if requested in signatures
                    else 'unsupported-definition' if errors else 'signature-mismatch'),
                    available_signatures=signatures, unsupported_definitions=errors))
            except Unsupported as error:
                results.append(dict(result, status='unsupported', reason=str(error)))
        missing_types = sorted({mod.identity(r) for r in mod.rows('TypeRef')
            if mod.scope(r) == shim.name and mod.identity(r) not in shim.definitions})
        overrides = []
        for type_row in mod.rows('TypeDef'):
            base = type_row.Extends.row
            methods = [r.row for r in type_row.MethodList if r.row.Flags.mdVirtual and not r.row.Flags.mdNewSlot]
            if not methods or base is None:
                continue
            if not hasattr(base, 'TypeName'):
                overrides.append(dict(type=mod.identity(type_row), status='unsupported-base',
                    reason='Generic base substitution is unresolved'))
                continue
            if mod.scope(base) != shim.name:
                continue
            target = shim.definitions.get(mod.identity(base))
            for method in methods:
                result = dict(type=mod.identity(type_row), base=mod.identity(base), member=str(method.Name))
                if target is None:
                    overrides.append(dict(result, status='missing-base'))
                    continue
                try:
                    requested = mod.signature(method.Signature.value)
                    candidates = [r.row for r in target.MethodList if str(r.row.Name)==str(method.Name)]
                    compatible = [r for r in candidates if shim.signature(r.Signature.value)==requested]
                    status = ('exact-override' if any(r.Flags.mdVirtual and not r.Flags.mdFinal for r in compatible)
                        else 'non-overridable' if compatible else 'missing-or-mismatched-override')
                    overrides.append(dict(result, status=status, requested_signature=requested))
                except Unsupported as error:
                    overrides.append(dict(result, status='unsupported', reason=str(error)))
        return dict(counts=dict(Counter(r['status'] for r in results)), missing_types=missing_types,
                    member_checks=results, override_checks=overrides,
                    override_counts=dict(Counter(r['status'] for r in overrides)),
                    assembly_references=[dict(name=str(r.Name), version='.'.join(str(getattr(r,k)) for k in
                        ('MajorVersion','MinorVersion','BuildNumber','RevisionNumber'))) for r in mod.rows('AssemblyRef')],
                    compatibility_verified=False, assembly_executed=False,
                    limitations=['Exact encoded member signatures only; no runtime binding or behavior proof.',
                        'Only direct non-generic base overrides are checked; inherited bases, MethodImpl and covariant returns remain unresolved.',
                        'Inherited member lookup, generic owner substitution and MethodSpec constraints are unresolved.',
                        'Assembly versions, visibility, field staticness, reflection, dynamic access and native hooks are not validated.',
                        'Unsupported owners include external generic calls and are never accepted as compatible.'])
    finally:
        mod.close()
        shim.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, default=Path('reports/workshop-inventory.json'))
    parser.add_argument('--shim', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=Path('reports/small-mod-signatures.json'))
    parser.add_argument('--mods', nargs='+', help='Explicit local mod names; default is the eight small candidates')
    args = parser.parse_args()
    from audit_small_mods import NAMES
    inventory = json.loads(args.inventory.read_text(encoding='utf-8'))
    shim = args.shim.read_bytes()
    candidates = []
    for name in args.mods or NAMES:
        selected = max((r for r in inventory['files'] if r['name'] == name),
            key=lambda r: tuple(map(int, r['tmodloader_build_version'].split('.'))))
        path = Path(inventory['root']) / selected['path']
        data, header = assembly_bytes(path, name + '.dll')
        row = dict(header, path=selected['path'], tmod_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                   assembly_sha256=hashlib.sha256(data).hexdigest(), **compare(data, shim))
        candidates.append(row)
        print(json.dumps(dict(mod=name, counts=row['counts'], overrides=row['override_counts'], missing_types=len(row['missing_types']))))
    report = dict(format='terraria-mobile-signature-preflight-v1', shim_sha256=hashlib.sha256(shim).hexdigest(),
        third_party_dll_written=False, candidates=candidates)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
