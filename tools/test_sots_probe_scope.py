"""Reject probe scope drift before executing the pinned original assembly."""
import copy
import unittest

from probe_sots_item_defaults import TYPE, require_hash, require_scope


class ProbeScopeTests(unittest.TestCase):
    def fixture(self):
        signatures = {
            'Terraria.ModLoader.ModItem::get_Item': ('call', '20001255', 5),
            'Terraria.ModLoader.ModItem::.ctor': ('call', '200001', 1),
            'Terraria.Item::sellPrice': ('call', '00040808080808', 1),
        }
        for name in ('Terraria.Entity::width', 'Terraria.Entity::height', 'Terraria.Item::value',
                     'Terraria.Item::rare', 'Terraria.Item::maxStack'):
            signatures[name] = ('stfld', '0608', 1)
        return dict(content_type=TYPE, root_methods=['.ctor', 'SetDefaults'],
            methods=[{'name': TYPE + '::.ctor'}, {'name': TYPE + '::SetDefaults'}],
            dependencies=[dict(target=name, opcode=op, signature=sig, generic_signature='')
                          for name, (op, sig, count) in signatures.items() for _ in range(count)],
            blockers=['External base lifecycle: Terraria.ModLoader.ModItem'] +
                     ['External or unresolved dependency: ' + name for name in signatures])

    def test_recorded_shape(self):
        require_scope(self.fixture())

    def test_scope_drift_rejected(self):
        changes = [
            lambda r: r['methods'].append({'name': 'Unexpected::.cctor'}),
            lambda r: r['dependencies'].pop(),
            lambda r: r['dependencies'][0].update(signature='changed'),
            lambda r: r['dependencies'][0].update(opcode='callvirt'),
            lambda r: r['dependencies'][0].update(generic_signature='0A0108'),
            lambda r: r['dependencies'][0].update(target='Unknown::Call'),
            lambda r: r['blockers'].append('Module initializer requires audit'),
            lambda r: r['blockers'].clear(),
            lambda r: r.update(root_methods=['SetStaticDefaults']),
            lambda r: r.update(content_type='Other.Item'),
        ]
        for change in changes:
            report = copy.deepcopy(self.fixture()); change(report)
            with self.subTest(change=changes.index(change)), self.assertRaises(ValueError):
                require_scope(report)

    def test_reference_drift_rejected(self):
        with self.assertRaises(ValueError):
            require_hash(b'changed reference', '0' * 64)
        with self.assertRaises(ValueError):
            require_scope(self.fixture(), 'Unsupported.Type')


if __name__ == '__main__':
    unittest.main()
