"""Bounded IL2CPP v31 symbol catalog; names and relations, never method bodies.

Generated catalogs contain game-derived metadata and belong in a private directory
outside this repository. Native Il2CppType indices stay unresolved unless a
separately reconstructed, bounds-checked registration map is supplied.
"""
import argparse
import collections
import csv
import hashlib
import json
import math
from pathlib import Path
import struct
import zipfile

METADATA_PATH = 'assets/bin/Data/Managed/Metadata/global-metadata.dat'
TABLES = [
    ('string_literals', '<2I', 'length data_index'),
    ('string_literal_data', None, ''), ('strings', None, ''),
    ('events', '<IiiiiI', 'name_index type_index add remove raise token'),
    ('properties', '<IiiII', 'name_index get set attributes token'),
    ('methods', '<IiiIiiI4H', 'name_index declaring_type return_type_index return_parameter_token parameter_start generic_container_index token flags implementation_flags slot parameter_count'),
    ('parameter_defaults', '<iii', 'parameter_index type_index data_index'),
    ('field_defaults', '<iii', 'field_index type_index data_index'),
    ('default_data', None, ''),
    ('field_marshaled_sizes', '<iii', 'field_index type_index size'),
    ('parameters', '<IIi', 'name_index token type_index'),
    ('fields', '<IiI', 'name_index type_index token'),
    ('generic_parameters', '<iIhhHH', 'owner_index name_index constraints_start constraints_count number flags'),
    ('generic_constraints', '<i', 'type_index'),
    ('generic_containers', '<iiii', 'owner_index argument_count is_method generic_parameter_start'),
    ('nested_types', '<i', 'type_index'),
    ('interfaces', '<i', 'type_index'),
    ('vtable_methods', '<I', 'encoded_method_index'),
    ('interface_offsets', '<ii', 'type_index offset'),
    ('types', '<IIiiiiIIiiiiiiii8HII', 'name_index namespace_index byval_type_index declaring_type_index parent_type_index element_type_index generic_container_index flags field_start method_start event_start property_start nested_type_start interfaces_start vtable_start interface_offsets_start method_count property_count field_count event_count nested_type_count vtable_count interfaces_count interface_offsets_count bitfield token'),
    ('images', '<IiiiiiiIii', 'name_index assembly_index type_start type_count exported_type_start exported_type_count entry_point_index token custom_attribute_start custom_attribute_count'),
    ('assemblies', '<iIiiIII7I8s', 'image_index token referenced_assembly_start referenced_assembly_count name_index culture_index public_key_index hash_algorithm hash_length flags major minor build revision public_key_token'),
    ('field_refs', '<ii', 'type_index field_index'),
    ('referenced_assemblies', '<i', 'assembly_index'),
    ('attribute_data', None, ''),
    ('attribute_ranges', '<II', 'token start_offset'),
    ('unresolved_virtual_call_parameter_types', '<i', 'type_index'),
    ('unresolved_virtual_call_parameter_ranges', '<ii', 'start length'),
    ('windows_runtime_type_names', '<Ii', 'name_index type_index'),
    ('windows_runtime_strings', None, ''),
    ('exported_types', '<i', 'type_index'),
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


class BlobReader:
    """Strict Unity metadata compressed integers, not ECMA CLI/ULEB128.

    Independent Python implementation of the format documented by upstream
    Perfare/Il2CppDumper BinaryReaderExtensions.cs and Il2CppExecutor.cs.
    """
    def __init__(self, data, offset):
        self.data = data
        self.position = offset

    def read(self, count):
        if count < 0 or self.position < 0 or self.position > len(self.data) or count > len(self.data) - self.position:
            raise ValueError('Constant read exceeds default data bounds')
        value = self.data[self.position:self.position + count]
        self.position += count
        return value

    def number(self, fmt):
        return struct.unpack(fmt, self.read(struct.calcsize(fmt)))[0]

    def compressed_uint32(self):
        first = self.number('<B')
        if first & 0x80 == 0:
            return first
        if first & 0xc0 == 0x80:
            return ((first & 0x7f) << 8) | self.number('<B')
        if first & 0xe0 == 0xc0:
            tail = self.read(3)
            return ((first & 0x3f) << 24) | int.from_bytes(tail, 'big')
        if first == 0xf0:
            return self.number('<I')
        if first == 0xfe:
            return 0xfffffffe
        if first == 0xff:
            return 0xffffffff
        raise ValueError(f'Invalid Unity compressed integer lead byte {first:#x}')

    def compressed_int32(self):
        encoded = self.compressed_uint32()
        if encoded == 0xffffffff:
            return -2147483648
        return -(encoded // 2 + 1) if encoded & 1 else encoded // 2


class Catalog:
    def __init__(self, data):
        self.data = data
        self.tables = {}
        self.layout = {}
        self.errors = []
        self.checks = collections.Counter()
        if len(data) < 256 or struct.unpack_from('<II', data) != (0xFAB11BAF, 31):
            raise ValueError('Expected IL2CPP metadata magic and version 31 with 256-byte header')
        occupied = []
        for i, (name, fmt, keys) in enumerate(TABLES):
            offset, length = struct.unpack_from('<II', data, 8 + 8 * i)
            if offset < 256 or offset > len(data) or length > len(data) - offset:
                raise ValueError(f'{name}: invalid file range {offset}:{length}')
            size = struct.calcsize(fmt) if fmt else None
            if size and length % size:
                raise ValueError(f'{name}: byte count {length} is not divisible by record size {size}')
            self.layout[name] = dict(offset=offset, byte_count=length, record_size=size,
                                     count=length // size if size else None,
                                     sha256=digest(data[offset:offset + length]))
            if length:
                occupied.append((offset, offset + length, name))
            if fmt:
                fields = keys.split()
                records = []
                for index, values in enumerate(struct.iter_unpack(fmt, data[offset:offset + length])):
                    if len(fields) != len(values):
                        raise ValueError(f'{name}: schema mismatch')
                    record = dict(zip(fields, values))
                    record['index'] = index
                    for key, value in list(record.items()):
                        if isinstance(value, bytes):
                            record[key] = value.hex()
                    records.append(record)
                self.tables[name] = records
        for a, b in zip(sorted(occupied), sorted(occupied)[1:]):
            if a[1] > b[0]:
                raise ValueError(f'Overlapping tables: {a[2]} and {b[2]}')
        self.checks['table_file_ranges'] = len(TABLES)
        self._resolve_names()
        self._validate()
        self._enrich()

    def string(self, index):
        table = self.layout['strings']
        if not 0 <= index < table['byte_count']:
            raise ValueError(f'String index outside pool: {index}')
        start = table['offset'] + index
        end = self.data.find(b'\0', start, table['offset'] + table['byte_count'])
        if end < 0:
            raise ValueError(f'Unterminated string at {index}')
        self.checks['string_references'] += 1
        return self.data[start:end].decode('utf-8', errors='strict')

    def _resolve_names(self):
        for table, rows in self.tables.items():
            for row in rows:
                for key in ('name_index', 'namespace_index', 'culture_index'):
                    if key in row:
                        row[key.removesuffix('_index')] = self.string(row[key])

    def ref(self, value, target, context, sentinel=True):
        self.checks['index_references'] += 1
        if sentinel and value == -1:
            return
        if not 0 <= value < len(self.tables[target]):
            self.errors.append(f'{context}: invalid {target} index {value}')

    def span(self, start, count, target, context):
        self.checks['table_spans'] += 1
        if count == 0 and start in (-1, 0):
            return
        if count < 0 or start < 0 or start > len(self.tables[target]) or count > len(self.tables[target]) - start:
            self.errors.append(f'{context}: invalid {target} span {start}+{count}')

    def byte_span(self, start, count, target, context):
        self.checks['byte_spans'] += 1
        if start < 0 or count < 0 or start > self.layout[target]['byte_count'] or count > self.layout[target]['byte_count'] - start:
            self.errors.append(f'{context}: invalid {target} byte span {start}+{count}')

    def _validate(self):
        for row in self.tables['types']:
            for stem, count, target in (
                ('field', 'field', 'fields'), ('method', 'method', 'methods'),
                ('event', 'event', 'events'), ('property', 'property', 'properties'),
                ('nested_type', 'nested_type', 'nested_types'),
                ('interfaces', 'interfaces', 'interfaces'),
                ('vtable', 'vtable', 'vtable_methods'),
                ('interface_offsets', 'interface_offsets', 'interface_offsets')):
                self.span(row[stem + '_start'], row[count + '_count'], target, f'type[{row["index"]}]')
            # Il2CppType references are not indices into typeDefinitions.
            g = row['generic_container_index']
            if g == 0xffffffff:
                row['generic_container_index'] = -1
            self.ref(row['generic_container_index'], 'generic_containers', f'type[{row["index"]}].generic')
        for row in self.tables['methods']:
            self.ref(row['declaring_type'], 'types', f'method[{row["index"]}].declaring', False)
            self.ref(row['generic_container_index'], 'generic_containers', f'method[{row["index"]}].generic')
            self.span(row['parameter_start'], row['parameter_count'], 'parameters', f'method[{row["index"]}]')
        for target, keys in [('properties', ('get', 'set')), ('events', ('add', 'remove', 'raise'))]:
            # Accessors are relative to the owning type's methodStart, not global.
            for typ in self.tables['types']:
                stem = 'property' if target == 'properties' else 'event'
                for row in self.tables[target][typ[stem + '_start']:typ[stem + '_start'] + typ[stem + '_count']]:
                    for key in keys:
                        value = row[key]
                        self.checks['relative_accessors'] += 1
                        if value != -1 and not 0 <= value < typ['method_count']:
                            self.errors.append(f'{target}[{row["index"]}].{key}: invalid relative method {value}')
        for row in self.tables['nested_types']:
            self.ref(row['type_index'], 'types', f'nested[{row["index"]}]', False)
        for row in self.tables['images']:
            self.ref(row['assembly_index'], 'assemblies', f'image[{row["index"]}].assembly', False)
            self.span(row['type_start'], row['type_count'], 'types', f'image[{row["index"]}]')
            self.span(row['exported_type_start'], row['exported_type_count'], 'exported_types', f'image[{row["index"]}].exported')
            self.ref(row['entry_point_index'], 'methods', f'image[{row["index"]}].entry')
            self.span(row['custom_attribute_start'], row['custom_attribute_count'], 'attribute_ranges', f'image[{row["index"]}].attributes')
        for row in self.tables['assemblies']:
            self.ref(row['image_index'], 'images', f'assembly[{row["index"]}].image', False)
            self.span(row['referenced_assembly_start'], row['referenced_assembly_count'], 'referenced_assemblies', f'assembly[{row["index"]}]')
        for row in self.tables['referenced_assemblies']:
            self.ref(row['assembly_index'], 'assemblies', f'assembly_ref[{row["index"]}]', False)
        for row in self.tables['exported_types']:
            self.ref(row['type_index'], 'types', f'exported[{row["index"]}]')
        for row in self.tables['generic_containers']:
            self.ref(row['owner_index'], 'methods' if row['is_method'] else 'types', f'generic_container[{row["index"]}].owner', False)
            self.span(row['generic_parameter_start'], row['argument_count'], 'generic_parameters', f'generic_container[{row["index"]}]')
            if row['is_method'] not in (0, 1):
                self.errors.append(f'generic_container[{row["index"]}]: invalid is_method')
        for row in self.tables['generic_parameters']:
            self.ref(row['owner_index'], 'generic_containers', f'generic_parameter[{row["index"]}].owner', False)
            self.span(row['constraints_start'], row['constraints_count'], 'generic_constraints', f'generic_parameter[{row["index"]}]')
        for table, key, target in [('field_defaults', 'field_index', 'fields'), ('parameter_defaults', 'parameter_index', 'parameters')]:
            for row in self.tables[table]:
                self.ref(row[key], target, f'{table}[{row["index"]}]', False)
                if row['data_index'] != -1:
                    self.byte_span(row['data_index'], 1, 'default_data', f'{table}[{row["index"]}]')
        for row in self.tables['field_marshaled_sizes']:
            self.ref(row['field_index'], 'fields', f'marshaled[{row["index"]}]', False)
        for row in self.tables['string_literals']:
            self.byte_span(row['data_index'], row['length'], 'string_literal_data', f'literal[{row["index"]}]')
        for row in self.tables['attribute_ranges']:
            self.byte_span(row['start_offset'], 0, 'attribute_data', f'attribute_range[{row["index"]}]')
        for row in self.tables['unresolved_virtual_call_parameter_ranges']:
            self.span(row['start'], row['length'], 'unresolved_virtual_call_parameter_types', f'unresolved_call[{row["index"]}]')
        if self.errors:
            raise ValueError('Metadata relation validation failed:\n' + '\n'.join(self.errors[:30]) + f'\nTotal errors: {len(self.errors)}')

    def _enrich(self):
        for typ in self.tables['types']:
            typ['full_name'] = (typ['namespace'] + '.' if typ['namespace'] else '') + typ['name']
        # Metadata nestedTypes provides reliable definition indices, unlike native declaringTypeIndex.
        parents = {}
        for typ in self.tables['types']:
            for link in self.tables['nested_types'][typ['nested_type_start']:typ['nested_type_start'] + typ['nested_type_count']]:
                parents[link['type_index']] = typ['index']
        def fullname(index, seen=None):
            seen = set() if seen is None else seen
            if index in seen:
                raise ValueError('Nested type cycle')
            typ = self.tables['types'][index]
            if index in parents:
                return fullname(parents[index], seen | {index}) + '+' + typ['name']
            return typ['full_name']
        for typ in self.tables['types']:
            typ['full_name'] = fullname(typ['index'])
            typ['declaring_definition_index'] = parents.get(typ['index'], -1)
            for stem, target in [('field', 'fields'), ('method', 'methods'), ('property', 'properties'), ('event', 'events')]:
                for row in self.tables[target][typ[stem + '_start']:typ[stem + '_start'] + typ[stem + '_count']]:
                    if 'owner_type_index' in row:
                        raise ValueError(f'Multiply owned {target}[{row["index"]}]')
                    row['owner_type_index'] = typ['index']
                    row['owner_type'] = typ['full_name']
        for image in self.tables['images']:
            for typ in self.tables['types'][image['type_start']:image['type_start'] + image['type_count']]:
                if 'image_index' in typ:
                    raise ValueError('Multiply owned type')
                typ['image_index'] = image['index']
                typ['assembly'] = image['name']
        for method in self.tables['methods']:
            if method['owner_type_index'] != method['declaring_type']:
                raise ValueError('Declaring method owner disagreement')
            params = self.tables['parameters'][method['parameter_start']:method['parameter_start'] + method['parameter_count']]
            method['parameter_indices'] = [p['index'] for p in params]
            method['parameter_names'] = [p['name'] for p in params]
            method['display_signature'] = method['owner_type'] + '::' + method['name'] + '(' + ', '.join(p['name'] + ':type#' + str(p['type_index']) for p in params) + ') -> type#' + str(method['return_type_index'])
            for p in params:
                if 'owner_method_index' in p:
                    raise ValueError('Multiply owned parameter')
                p['owner_method_index'] = method['index']
        for table, keys in [('properties', ('get', 'set')), ('events', ('add', 'remove', 'raise'))]:
            for row in self.tables[table]:
                typ = self.tables['types'][row['owner_type_index']]
                for key in keys:
                    row[key + '_method_index'] = typ['method_start'] + row[key] if row[key] != -1 else -1
        for target in ('methods', 'fields', 'properties', 'events'):
            for row in self.tables[target]:
                if 'owner_type_index' not in row:
                    raise ValueError(f'Unowned {target}[{row["index"]}]')
                row['assembly'] = self.tables['types'][row['owner_type_index']]['assembly']
        for row in self.tables['parameters']:
            if 'owner_method_index' not in row:
                raise ValueError(f'Unowned parameter[{row["index"]}]')
        for row in self.tables['types']:
            if 'image_index' not in row:
                raise ValueError(f'Unowned type[{row["index"]}]')

    def merge_native_methods(self, path):
        data = path.read_bytes()
        rows = json.loads(data)
        if not isinstance(rows, list) or len(rows) != len(self.tables['methods']):
            raise ValueError('Native method map must have exactly one row per metadata method')
        seen = set()
        for row in rows:
            index = row['method_index']
            if not isinstance(index, int) or index in seen or not 0 <= index < len(rows):
                raise ValueError('Invalid/duplicate native method index')
            seen.add(index)
            method = self.tables['methods'][index]
            if (row['name'] != method['name'] or row['type_index'] != method['owner_type_index']
                    or int(row['token'], 16) != method['token'] or row['image'] != method['assembly']
                    or row['parameter_count'] != method['parameter_count']):
                raise ValueError(f'Native/metadata method identity mismatch at {index}')
            method['native_address'] = row['address']
            method['native_file_offset'] = row['file_offset']
            method['native_mapping_status'] = row['status']
            method['native_address_alias_count'] = row['address_alias_count']
        self.native_method_map = {'path': str(path.resolve()), 'sha256': digest(data),
                                  'validated_identities': len(rows),
                                  'statuses': dict(collections.Counter(r['status'] for r in rows))}

    def merge_native_types(self, path):
        data = path.read_bytes()
        source = json.loads(data)
        rows = source['types']
        count = source['registration']['types_count']
        if len(rows) != count or sorted(r['type_index'] for r in rows) != list(range(count)):
            raise ValueError('Native type map has missing/duplicate/out-of-range indices')
        native = {r['type_index']: r for r in rows}
        checked = 0
        for typ in self.tables['types']:
            mapped = native.get(typ['byval_type_index'])
            # Core primitive definitions use their primitive tag, with the same definition union index.
            definition_tags = set(range(1, 15)) | {17, 18, 22, 24, 25, 28}
            if mapped is None or mapped['type_tag'] not in definition_tags or int(mapped['data'], 16) != typ['index']:
                raise ValueError(f'Native type-definition byval mismatch at {typ["index"]}')
            checked += 1
        references = 0
        schemas = {
            'types': ('byval_type_index', 'declaring_type_index', 'parent_type_index', 'element_type_index'),
            'fields': ('type_index',), 'parameters': ('type_index',), 'events': ('type_index',),
            'methods': ('return_type_index',), 'generic_constraints': ('type_index',),
            'interfaces': ('type_index',), 'interface_offsets': ('type_index',),
            'field_refs': ('type_index',), 'field_defaults': ('type_index',),
            'parameter_defaults': ('type_index',), 'field_marshaled_sizes': ('type_index',),
            'unresolved_virtual_call_parameter_types': ('type_index',),
            'windows_runtime_type_names': ('type_index',),
        }
        for table, keys in schemas.items():
            for row in self.tables[table]:
                for key in keys:
                    index = row[key]
                    if index == -1:
                        row[key.removesuffix('_index') + '_name'] = None
                        continue
                    if index not in native:
                        raise ValueError(f'{table}[{row["index"]}].{key}: invalid native type {index}')
                    references += 1
                    row[key.removesuffix('_index') + '_name'] = native[index]['name']
                    if table == 'fields':
                        row['native_field_attributes'] = native[index]['attributes']
        for method in self.tables['methods']:
            params = [self.tables['parameters'][i] for i in method['parameter_indices']]
            method['display_signature'] = method['return_type_name'] + ' ' + method['owner_type'] + '::' + method['name'] + '(' + ', '.join(p['type_name'] + ' ' + p['name'] for p in params) + ')'
        for prop in self.tables['properties']:
            getter = prop['get_method_index']
            if getter != -1:
                prop['type_name_from_getter'] = self.tables['methods'][getter]['return_type_name']
        self.native_type_map = {'path': str(path.resolve()), 'sha256': digest(data),
                                'native_type_count': count, 'typedef_byval_crosschecks': checked,
                                'validated_type_references': references,
                                'reported_unresolved_type_count': source['registration']['unresolved_type_count'],
                                'coverage': 'All native type indices referenced by exported metadata tables are bounds checked and named from this supplied registration mapping.'}

    def merge_native_layouts(self, path):
        data = path.read_bytes()
        rows = json.loads(data)
        if len(rows) != len(self.tables['types']) or sorted(r['type_definition_index'] for r in rows) != list(range(len(rows))):
            raise ValueError('Native layouts must cover every definition once')
        field_count = 0
        for row in rows:
            typ = self.tables['types'][row['type_definition_index']]
            if row['field_start'] & 0xffffffff != typ['field_start'] & 0xffffffff or row['field_count'] != typ['field_count'] or len(row['field_offsets']) != typ['field_count']:
                raise ValueError('Native layout field range mismatch')
            for key in ('instance_size', 'native_size', 'static_fields_size', 'thread_static_fields_size'):
                typ['native_' + key] = row[key]
            for local, offset in enumerate(row['field_offsets']):
                if not isinstance(offset, int):
                    raise ValueError('Noninteger field offset')
                field = self.tables['fields'][typ['field_start'] + local]
                field['native_field_offset_raw'] = offset
                field['native_field_offset_hex'] = f'{offset & 0xffffffff:#010x}'
                attrs = field.get('native_field_attributes')
                field['native_field_offset_scope'] = ('special_or_unassigned' if offset < 0 else
                                                      'unknown_without_native_type_attrs' if attrs is None else
                                                      'static_storage' if attrs & 0x10 else 'instance_storage')
                field_count += 1
        self.native_type_layouts = {'path': str(path.resolve()), 'sha256': digest(data),
                                   'validated_type_layouts': len(rows), 'validated_field_offsets': field_count,
                                   'limitation': 'Negative offsets are retained as special/unassigned sentinels. Static offsets are not object-instance offsets.'}

    def decode_constants(self):
        if not hasattr(self, 'native_type_map'):
            raise ValueError('Default constant decoding requires a validated native type map')
        table = self.layout['default_data']
        blob = self.data[table['offset']:table['offset'] + table['byte_count']]
        formats = {'System.Boolean': '<B', 'System.Byte': '<B', 'System.SByte': '<b',
                   'System.Char': '<H', 'System.UInt16': '<H', 'System.Int16': '<h',
                   'System.UInt64': '<Q', 'System.Int64': '<q', 'System.Single': '<f', 'System.Double': '<d'}
        result = {}
        for source, target, index_key in [('field_defaults', 'fields', 'field_index'), ('parameter_defaults', 'parameters', 'parameter_index')]:
            rows = []
            for default in self.tables[source]:
                owner = self.tables[target][default[index_key]]
                row = {'default_record_index': default['index'], index_key: owner['index'],
                       'name': owner['name'], 'default_type_index': default['type_index'],
                       'default_type_name': default['type_name'], 'data_index': default['data_index'],
                       'status': 'unknown', 'value': None, 'bytes_consumed': 0}
                if target == 'fields':
                    row.update(owner_type=owner['owner_type'], owner_type_index=owner['owner_type_index'],
                               assembly=owner['assembly'], token=hex(owner['token']),
                               declared_type_name=owner['type_name'])
                else:
                    method = self.tables['methods'][owner['owner_method_index']]
                    row.update(owner_type=method['owner_type'], owner_method_index=method['index'],
                               owner_method=method['name'], assembly=method['assembly'],
                               declared_type_name=owner['type_name'])
                index, name = default['data_index'], default['type_name']
                if index == -1:
                    row['reason'] = 'metadata dataIndex=-1 sentinel; no encoded blob; null/default semantics not guessed'
                    rows.append(row)
                    continue
                reader = BlobReader(blob, index)
                try:
                    if name in formats:
                        value = reader.number(formats[name])
                        if name == 'System.Boolean':
                            if value not in (0, 1):
                                raise ValueError('Boolean blob is not canonical 0/1')
                            value = bool(value)
                        elif name == 'System.Char':
                            row['code_unit'] = value
                            if 0xd800 <= value <= 0xdfff:
                                row['character_representation'] = 'escaped_utf16_surrogate_code_unit'
                                value = f'\\u{value:04x}'
                            else:
                                value = chr(value)
                        row['encoding'] = 'little_endian_' + formats[name]
                    elif name == 'System.Int32':
                        value = reader.compressed_int32()
                        row['encoding'] = 'unity_compressed_int32_v29plus'
                    elif name == 'System.UInt32':
                        value = reader.compressed_uint32()
                        row['encoding'] = 'unity_compressed_uint32_v29plus'
                    elif name == 'System.String':
                        length = reader.compressed_int32()
                        value = None if length == -1 else reader.read(length).decode('utf-8', errors='strict')
                        row['encoding'] = 'unity_compressed_int32_byte_length_then_utf8_v29plus'
                    else:
                        row['reason'] = 'Unsupported default value type; no guessed raw-object/enum/array decoding'
                        rows.append(row)
                        continue
                    if isinstance(value, float) and not math.isfinite(value):
                        row['nonfinite_float'] = repr(value)
                        value = None
                    row['value'] = value
                    row['status'] = 'decoded'
                    row['bytes_consumed'] = reader.position - index
                    row['encoded_hex'] = blob[index:reader.position].hex()
                except (ValueError, UnicodeDecodeError, struct.error) as error:
                    row['status'] = 'decode_error'
                    row['reason'] = str(error)
                rows.append(row)
            result[target] = rows
        literals = []
        table = self.layout['string_literal_data']
        literal_blob = self.data[table['offset']:table['offset'] + table['byte_count']]
        for row in self.tables['string_literals']:
            raw = literal_blob[row['data_index']:row['data_index'] + row['length']]
            item = dict(row)
            item['encoding'] = 'utf8_explicit_byte_length'
            try:
                item.update(value=raw.decode('utf-8', errors='strict'), status='decoded')
            except UnicodeDecodeError:
                item.update(value=None, status='invalid_utf8', encoded_hex=raw.hex())
            literals.append(item)
        result['string_literals'] = literals
        self.constants = result
        ids = [r for r in result['fields'] if r['owner_type'].startswith('Terraria.ID.')]
        anchors = []
        expected = [('Terraria.ID.ItemID', 'None', 0), ('Terraria.ID.ItemID', 'IronPickaxe', 1),
                    ('Terraria.ID.ItemID', 'Torch', 8), ('Terraria.ID.ItemID', 'WoodenSword', 24),
                    ('Terraria.ID.ItemID', 'CopperShortsword', 3507), ('Terraria.ID.TileID', 'Dirt', 0),
                    ('Terraria.ID.NPCID', 'BlueSlime', 1), ('Terraria.ID.NPCID', 'NegativeIDCount', -66),
                    ('Terraria.ID.MessageID', 'Hello', 1), ('Terraria.ID.MessageID', 'SyncEquipment', 5),
                    ('Terraria.ID.PrefixID', 'Legendary', 81), ('Terraria.ID.PrefixID', 'Mythical', 83)]
        for typ, name, value in expected:
            found = [r for r in ids if r['owner_type'] == typ and r['name'] == name]
            if len(found) != 1 or found[0]['status'] != 'decoded' or found[0]['value'] != value:
                raise ValueError(f'Known constant crosscheck failed for {typ}.{name}')
            anchors.append({'owner_type': typ, 'name': name, 'expected': value, 'decoded': found[0]['value'],
                            'encoded_hex': found[0]['encoded_hex'], 'pass': True})
        self.constants_summary = {
            'encoding_sources': [
                'https://github.com/Perfare/Il2CppDumper/blob/master/Il2CppDumper/Extensions/BinaryReaderExtensions.cs',
                'https://github.com/Perfare/Il2CppDumper/blob/master/Il2CppDumper/Utils/Il2CppExecutor.cs',
                'https://github.com/Perfare/Il2CppDumper/blob/master/Il2CppDumper/Il2Cpp/Metadata.cs'],
            'encoding_source_checked_date': '2026-10-12',
            'coverage': {name: dict(collections.Counter(r['status'] for r in rows)) for name, rows in result.items()},
            'known_id_crosschecks': anchors,
            'terraria_id_catalogs': [{'owner_type': name, 'total': len([r for r in ids if r['owner_type'] == name]),
                                      'decoded': len([r for r in ids if r['owner_type'] == name and r['status'] == 'decoded'])}
                                     for name in sorted(set(r['owner_type'] for r in ids))],
            'limitations': ['dataIndex=-1 is retained as an unknown/no-blob sentinel rather than inferred null/default.',
                            'Unsupported structured defaults and compiler-generated initializer blobs remain unknown.',
                            'String-literal membership alone does not identify the method using a literal.']}

    def summary(self):
        def counts(types):
            return {'types': len(types), **{plural: sum(t[stem + '_count'] for t in types) for stem, plural in [('method', 'methods'), ('field', 'fields'), ('property', 'properties'), ('event', 'events')]},
                    'parameters': sum(self.tables['methods'][i]['parameter_count'] for t in types for i in range(t['method_start'], t['method_start'] + t['method_count']))}
        assemblies = []
        for image in self.tables['images']:
            types = self.tables['types'][image['type_start']:image['type_start'] + image['type_count']]
            assembly = self.tables['assemblies'][image['assembly_index']]
            assemblies.append({'name': image['name'], 'image_index': image['index'],
                               'assembly_version': '.'.join(str(assembly[k]) for k in ('major', 'minor', 'build', 'revision')),
                               **counts(types)})
        terraria = [t for t in self.tables['types'] if t['namespace'] == 'Terraria' or t['namespace'].startswith('Terraria.')]
        namespaces = []
        for ns in sorted(set(t['namespace'] for t in terraria)):
            namespaces.append({'namespace': ns, **counts([t for t in terraria if t['namespace'] == ns])})
        subsystems = []
        seeds = ['Terraria.Main', 'Terraria.Player', 'Terraria.NPC', 'Terraria.Projectile', 'Terraria.Item', 'Terraria.WorldGen', 'Terraria.Wiring', 'Terraria.NetMessage', 'Terraria.MessageBuffer', 'Terraria.IO.WorldFile', 'Terraria.IO.PlayerFileData', 'Terraria.Recipe', 'Terraria.Lighting', 'Terraria.GameContent.ItemDropRules.ItemDropResolver']
        for name in seeds:
            found = [t for t in self.tables['types'] if t['full_name'] == name]
            for typ in found:
                methods = self.tables['methods'][typ['method_start']:typ['method_start'] + typ['method_count']]
                subsystems.append({'type': name, 'type_index': typ['index'], 'field_count': typ['field_count'], 'method_count': typ['method_count'], 'methods': [{'index': m['index'], 'name': m['name'], 'parameters': m['parameter_names'], 'token': hex(m['token'])} for m in methods]})
        ownership = {table: {'owned': sum('owner_type_index' in r for r in self.tables[table]), 'total': len(self.tables[table])} for table in ('methods', 'fields', 'properties', 'events')}
        ownership['parameters'] = {'owned': sum('owner_method_index' in r for r in self.tables['parameters']), 'total': len(self.tables['parameters'])}
        ownership['types'] = {'owned': sum('image_index' in r for r in self.tables['types']), 'total': len(self.tables['types'])}
        return {'metadata_sha256': digest(self.data), 'metadata_version': 31, 'metadata_bytes': len(self.data),
                'tables': self.layout, 'validation': {'errors': [], 'checks': dict(self.checks), 'ownership': ownership},
                'assemblies': assemblies, 'terraria_namespaces_total': counts(terraria),
                'terraria_namespaces': namespaces, 'subsystem_method_inventories': subsystems,
                'limitations': ['This is a symbol/metadata inventory, not original C# source and not a behavioral decompilation.',
                                'Native Il2CppType references, field types, return types, parameter types, parent types and interface types remain raw indices until code/metadata registrations are mapped.',
                                'No executable method bodies, field offsets or method addresses are present in these metadata tables.',
                                'Field references contain a native type index and a type-relative field index; the latter is not treated as a global field index.',
                                'Default data values, custom attribute blobs, string literal contents and vtable encodings are cataloged by range or raw index, not decoded into guessed semantics.',
                                'Comment-only C# skeleton files are nonexecutable symbol outlines, not buildable replacements.']}

    def export(self, output, summary_path, apk_path):
        output.mkdir(parents=True, exist_ok=True)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary = self.summary()
        if hasattr(self, 'native_method_map'):
            summary['native_method_map'] = self.native_method_map
        if hasattr(self, 'native_type_map'):
            summary['native_type_map'] = self.native_type_map
            summary['limitations'][1] = 'Native type names and signatures are reconstructed from the supplied registration map; this does not restore original source aliases, source syntax, comments, local variables or behavior.'
        if hasattr(self, 'native_type_layouts'):
            summary['native_type_layouts'] = self.native_type_layouts
        if hasattr(self, 'constants_summary'):
            summary['constants'] = self.constants_summary
            summary['limitations'][4] = 'Primitive numerical/string default values and UTF-8 string literals are decoded using documented v29+ encoding. Unsupported structured defaults, custom attributes and vtable encodings retain explicit limits.'
        negative_tests = output / 'parser-negative-tests.json'
        if negative_tests.exists():
            summary['parser_negative_tests'] = json.loads(negative_tests.read_text(encoding='utf-8'))
        summary['source_apk'] = str(apk_path.resolve())
        with apk_path.open('rb') as stream:
            summary['apk_sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
        summary['private_export_directory'] = str(output.resolve())
        summary['export_files'] = []
        for name, rows in self.tables.items():
            path = output / (name + '.jsonl')
            with path.open('w', encoding='utf-8') as stream:
                for row in rows:
                    stream.write(json.dumps(row, ensure_ascii=False, separators=(',', ':')) + '\n')
            summary['export_files'].append({'name': path.name, 'records': len(rows), 'bytes': path.stat().st_size})
            if rows:
                path = output / (name + '.csv')
                keys = list(dict.fromkeys(k for row in rows for k in row))
                with path.open('w', encoding='utf-8-sig', newline='') as stream:
                    writer = csv.DictWriter(stream, fieldnames=keys)
                    writer.writeheader()
                    writer.writerows({k: json.dumps(v, ensure_ascii=False) if isinstance(v, (list, dict)) else v for k, v in row.items()} for row in rows)
        if hasattr(self, 'constants'):
            exports = {name: rows for name, rows in self.constants.items() if name != 'string_literals'}
            exports['ids'] = [r for r in self.constants['fields'] if r['owner_type'].startswith('Terraria.ID.')]
            for typ in sorted(set(r['owner_type'] for r in exports['ids'])):
                exports[typ] = [r for r in exports['ids'] if r['owner_type'] == typ]
            for name, rows in exports.items():
                write_json(output / ('constants.' + name + '.json'), rows)
                path = output / ('constants.' + name + '.csv')
                keys = list(dict.fromkeys(k for row in rows for k in row))
                with path.open('w', encoding='utf-8-sig', newline='') as stream:
                    writer = csv.DictWriter(stream, fieldnames=keys)
                    writer.writeheader()
                    writer.writerows(rows)
            with (output / 'string-literals.values.jsonl').open('w', encoding='utf-8') as stream:
                for row in self.constants['string_literals']:
                    stream.write(json.dumps(row, ensure_ascii=False, separators=(',', ':')) + '\n')
            write_json(output / 'constants-summary.json', self.constants_summary)
            write_json(summary_path.parent / 'constants-summary.json', self.constants_summary)
        skeletons = output / 'nonexecutable-symbol-outlines'
        skeletons.mkdir(exist_ok=True)
        for image in self.tables['images']:
            lines = ['// NONEXECUTABLE METADATA SYMBOL OUTLINE. EVERY LINE IS A COMMENT.',
                     '// Not original C# source. No method bodies. Metadata v31.',
                     '// Assembly: ' + image['name'], '']
            for typ in self.tables['types'][image['type_start']:image['type_start'] + image['type_count']]:
                lines += [f'// type#{typ["index"]} token={typ["token"]:#010x} {typ["full_name"]}', '// {']
                for f in self.tables['fields'][typ['field_start']:typ['field_start'] + typ['field_count']]:
                    field_type = f.get('type_name', 'type#' + str(f['type_index']))
                    layout = f' // offset={f["native_field_offset_raw"]} scope={f["native_field_offset_scope"]}' if 'native_field_offset_raw' in f else ''
                    lines.append(f'//   field#{f["index"]} token={f["token"]:#010x} {field_type} {f["name"]};{layout}')
                for m in self.tables['methods'][typ['method_start']:typ['method_start'] + typ['method_count']]:
                    native = f' native_address={m["native_address"]} status={m["native_mapping_status"]}' if 'native_mapping_status' in m else ''
                    lines.append(f'//   method#{m["index"]} token={m["token"]:#010x} flags={m["flags"]:#x} {m["display_signature"]}; // BODY UNAVAILABLE{native}')
                for p in self.tables['properties'][typ['property_start']:typ['property_start'] + typ['property_count']]:
                    lines.append(f'//   property#{p["index"]} token={p["token"]:#010x} {p["name"]} get=method#{p["get_method_index"]} set=method#{p["set_method_index"]};')
                for e in self.tables['events'][typ['event_start']:typ['event_start'] + typ['event_count']]:
                    event_type = e.get('type_name', 'type#' + str(e['type_index']))
                    lines.append(f'//   event#{e["index"]} token={e["token"]:#010x} {event_type} {e["name"]};')
                lines += ['// }', '']
            (skeletons / (image['name'] + '.symbols.cs')).write_text('\n'.join(lines), encoding='utf-8')
        readme = [
            'PRIVATE GAME-DERIVED METADATA CATALOG — NOT ORIGINAL SOURCE CODE',
            '',
            'All structured metadata tables are exported to JSON Lines and CSV.',
            'Rows retain raw numeric metadata indices/tokens alongside derived names.',
            'nonexecutable-symbol-outlines contains 35 comment-only .cs files.',
            'No method bodies are invented or included in these outlines.',
            'When supplied, native method/type mappings are merged after identity and range checks.',
            'Mapped addresses belong to this exact APK/native file and are not absolute runtime addresses.',
            'Read catalog-summary.json for hashes, counts, validation and coverage limits.',
            'Keep these game-derived exports private; the reusable parser is in the workspace tools directory.',
            '',
        ]
        (output / 'README.txt').write_text('\n'.join(readme), encoding='utf-8')
        write_json(output / 'catalog-summary.json', summary)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        write_json(summary_path, summary)
        return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('apk', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--summary', type=Path, required=True)
    parser.add_argument('--native-method-map', type=Path, help='Optional identity-checked method-addresses.json')
    parser.add_argument('--native-type-map', type=Path, help='Optional registration-checked il2cpp-types.json')
    parser.add_argument('--native-type-layouts', type=Path, help='Optional definition-checked type-layouts.json')
    parser.add_argument('--decode-constants', action='store_true', help='Decode documented primitive defaults and UTF-8 literals privately')
    args = parser.parse_args()
    if args.output.resolve().is_relative_to(Path(__file__).resolve().parent.parent):
        parser.error('Game-derived metadata exports must be outside the repository')
    with zipfile.ZipFile(args.apk) as archive:
        if archive.namelist().count(METADATA_PATH) != 1:
            raise ValueError('Expected exactly one global-metadata.dat')
        catalog = Catalog(archive.read(METADATA_PATH))
    if args.native_method_map:
        catalog.merge_native_methods(args.native_method_map)
    if args.native_type_map:
        catalog.merge_native_types(args.native_type_map)
    if args.native_type_layouts:
        catalog.merge_native_layouts(args.native_type_layouts)
    if args.decode_constants:
        catalog.decode_constants()
    summary = catalog.export(args.output, args.summary, args.apk)
    print(json.dumps({'counts': {k: len(v) for k, v in catalog.tables.items()}, 'validation': summary['validation'], 'output': str(args.output), 'summary': str(args.summary)}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
