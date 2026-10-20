"""Source-bound, offline reconciliation of the existing 70 declaration gaps.

Uses existing ELF relocation and metadata parsers. Never assigns a body from an
invoker, name match, or an absent table row. Proprietary outputs stay outside repo.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import struct

from terraria_native_map import ELF
from terraria_metadata_catalog import TABLES

LIB_SHA = '9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
META_SHA = '4c904c49d168913d28ef547c4f461e539d926d2ed27c0253ed53a2954e9585f7'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def metadata_record(data, table, index):
    i = next(i for i, x in enumerate(TABLES) if x[0] == table)
    _, fmt, keys = TABLES[i]
    start, size = struct.unpack_from('<II', data, 8+8*i)
    width = struct.calcsize(fmt)
    require(0 <= index < size//width, 'Metadata record index outside table')
    off = start+index*width
    return dict(file_offset=hex(off), raw_bytes=data[off:off+width].hex(),
                fields=dict(zip(keys.split(), struct.unpack_from(fmt, data, off))))


def classify(specs, mappings, pointer):
    if pointer or any(x['implementation_address'] for x in mappings):
        return 'implementation_pointer_recovered'
    if mappings:
        return 'registered_codegen_rows_without_implementation_pointer'
    return 'method_specs_without_codegen_rows' if specs else 'no_registered_method_spec'


def selftest():
    tests = []
    for specs, maps, ptr, expected in [([], [], 0, 'no_registered_method_spec'),
            ([{}], [], 0, 'method_specs_without_codegen_rows'),
            ([{}], [{'implementation_address': None, 'invoker_address': '0x1234'}], 0,
             'registered_codegen_rows_without_implementation_pointer'),
            ([{}], [{'implementation_address': '0x1234'}], 0, 'implementation_pointer_recovered')]:
        require(classify(specs, maps, ptr) == expected, 'Classification negative control failed')
        tests.append(expected)
    # A malformed index must fail, never silently select the last Python element.
    try:
        metadata_record(bytes(256), 'methods', -1)
    except ValueError:
        tests.append('negative_metadata_index_rejected')
    else:
        raise ValueError('Negative metadata index accepted')
    return tests


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--delivery', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    require(not a.output.resolve().is_relative_to(Path(__file__).resolve().parents[1]), 'Private output required')
    n = a.delivery/'native'
    load = lambda p: json.loads(p.read_text(encoding='utf-8'))
    files = [n/x for x in ['libil2cpp.so', 'global-metadata.dat', 'concrete-implementation-gaps.json',
             'method-addresses.json', 'generic-method-addresses.json', 'il2cpp-types.json', 'generic-instances.json']]
    files.append(a.delivery/'evidence/native-summary.json')
    inputs = {str(p): sha(p) for p in files}
    require(inputs[str(files[0])] == LIB_SHA and inputs[str(files[1])] == META_SHA, 'Original identity mismatch')
    raw = files[1].read_bytes()
    elf = ELF(files[0].read_bytes())
    gaps, direct, generic = [load(x) for x in files[2:5]]
    type_catalog = load(files[5]); reg = type_catalog['registration']
    instances = load(files[6]); summary = load(files[7])
    type_by_pointer = {int(t['pointer'], 16): t for t in type_catalog['types']}
    instance_evidence = {}
    for i, inst in enumerate(instances):
        slot = int(reg['generic_insts_pointer'], 16)+8*i
        ptr = elf.pointer(slot)
        require(ptr == int(inst['pointer'], 16), 'Generic instance pointer mismatch')
        argc = struct.unpack_from('<I', elf.data, elf.file_offset(ptr))[0]
        require(argc == len(inst['arguments']), 'Generic instance arity mismatch')
        argv = elf.pointer(ptr+8)
        args = []
        for j in range(argc):
            tp = elf.pointer(argv+8*j)
            require(tp in type_by_pointer, 'Generic argument type pointer absent from types catalog')
            tr = type_by_pointer[tp]
            require(tr['name'] == inst['arguments'][j], 'Generic instance argument name mismatch')
            td, tb = struct.unpack_from('<QI', elf.data, elf.file_offset(tp))
            require(td == int(tr['data'], 16) and (tb >> 16) & 255 == tr['type_tag'], 'Generic argument bytes mismatch')
            args.append(dict(pointer_slot=hex(argv+8*j), type_pointer=hex(tp), type_data=hex(td),
                             type_bits=hex(tb), name=tr['name']))
        instance_evidence[i] = dict(index=i, pointer_slot=hex(slot), instance_address=hex(ptr),
                                   argument_count=argc, arguments= args)
    require(len(gaps) == 70, 'Expected fixed original 70-record scope')
    cb = int(summary['generic_registration']['code_registration_address'], 16)
    rb = int(reg['address'], 16)
    require(elf.pointer(rb+32) == reg['generic_method_table_count'] and
            elf.pointer(rb+64) == reg['method_specs_count'], 'Registration count mismatch')
    table = elf.pointer(rb+40); specs_base = elf.pointer(rb+72)
    require(table == int(reg['generic_method_table_pointer'], 16) and
            specs_base == int(reg['method_specs_pointer'], 16), 'Registration pointer mismatch')
    inv_count, inv_array = elf.pointer(cb+40), elf.pointer(cb+48)
    gp_count, gp_array = elf.pointer(cb+16), elf.pointer(cb+24)
    by_spec = defaultdict(list); specs = defaultdict(list)
    for i in range(reg['method_specs_count']):
        slot = specs_base+12*i
        mi, ci, gi = struct.unpack_from('<3i', elf.data, elf.file_offset(slot))
        require(0 <= mi < len(direct), 'MethodSpec method out of range')
        require(-1 <= ci < len(instances) and -1 <= gi < len(instances), 'Generic instantiation out of range')
        specs[mi].append(dict(method_spec_index=i, virtual_address=hex(slot), file_offset=hex(elf.file_offset(slot)),
                             raw_bytes=elf.data[elf.file_offset(slot):elf.file_offset(slot)+12].hex(), method_index=mi,
                             class_inst_index=ci, method_inst_index=gi,
                             class_arguments=instances[ci]['arguments'] if ci >= 0 else [],
                             method_arguments=instances[gi]['arguments'] if gi >= 0 else [],
                             class_instance_evidence=instance_evidence[ci] if ci >= 0 else None,
                             method_instance_evidence=instance_evidence[gi] if gi >= 0 else None))
    require(len(generic) == reg['generic_method_table_count'], 'Generic table coverage mismatch')
    for i, published in enumerate(generic):
        slot = table+16*i
        si, pi, ii, ai = struct.unpack_from('<4i', elf.data, elf.file_offset(slot))
        require((si, pi, ii, ai) == tuple(published[k] for k in ['method_spec_index', 'generic_method_pointer_index',
                    'invoker_index', 'adjustor_thunk_index']), 'Published generic row differs from ELF')
        require(0 <= si < reg['method_specs_count'] and -1 <= pi < gp_count and -1 <= ii < inv_count,
                'Codegen index out of bounds')
        mi = struct.unpack_from('<i', elf.data, elf.file_offset(specs_base+12*si))[0]
        require(mi == published['method_index'], 'Published MethodSpec binding mismatch')
        pointer = elf.pointer(gp_array+8*pi) if pi >= 0 else 0
        require(pointer == (int(published['address'], 16) if published['address'] else 0), 'Generic address mismatch')
        by_spec[si].append(dict(generic_table_index=i, virtual_address=hex(slot), file_offset=hex(elf.file_offset(slot)),
             method_spec_index=si, generic_method_pointer_index=pi, implementation_address=hex(pointer) if pointer else None,
             implementation_pointer_slot=hex(gp_array+8*pi) if pi >= 0 else None, invoker_index=ii,
             invoker_address=hex(elf.pointer(inv_array+8*ii)) if ii >= 0 else None, adjustor_thunk_index=ai))
    modules = {x['image']: x for x in summary['modules']}
    module_count, module_array = elf.pointer(cb+104), elf.pointer(cb+112)
    require(module_count == len(summary['images']) == 35, 'Codegen module count mismatch')
    module_addresses = {elf.pointer(module_array+8*i) for i in range(module_count)}
    for module in modules.values():
        ptr = int(module['module_address'], 16)
        require(ptr in module_addresses, 'Module absent from original registration')
        name_offset = elf.file_offset(elf.pointer(ptr))
        name = elf.data[name_offset:elf.data.index(b'\0', name_offset)].decode('utf-8')
        require(name == module['image'] and elf.pointer(ptr+8) == module['method_pointer_count'] and
                elf.pointer(ptr+16) == int(module['method_pointer_array'], 16), 'Module source fields mismatch')
    types = type_catalog['types']
    # Nested ownership is carried by nestedTypes, not by Il2CppType parent indexes.
    nested_owner = {}
    for ti in range(reg['type_sizes_count']):
        tr = metadata_record(raw, 'types', ti)['fields']
        for ni in range(tr['nested_type_start'], tr['nested_type_start']+tr['nested_type_count']):
            child = metadata_record(raw, 'nested_types', ni)['fields']['type_index']
            require(child not in nested_owner, 'Duplicate nested type owner')
            nested_owner[child] = ti
    ledger = []
    for old in gaps:
        mi = old['index']; method = metadata_record(raw, 'methods', mi)
        require(all(old[k] == v for k, v in method['fields'].items()), 'Gap metadata differs from original')
        dm = direct[mi]; require(dm['method_index'] == mi, 'Direct catalog order mismatch')
        module = modules[dm['image']]; mb = int(module['module_address'], 16)
        rid = method['fields']['token'] & 0xffffff
        direct_slot = elf.pointer(mb+16)+8*(rid-1)
        pointer = elf.pointer(direct_slot)
        require(pointer == 0 and dm['address'] is None, 'Original gap direct pointer changed')
        ip = elf.pointer(mb+40)+4*(rid-1)
        ii = struct.unpack_from('<i', elf.data, elf.file_offset(ip))[0]
        require(-1 <= ii < inv_count, 'Module invoker index out of bounds')
        mappings = [x for s in specs[mi] for x in by_spec[s['method_spec_index']]]
        chain = []; ti = method['fields']['declaring_type']; seen = set()
        while ti not in seen:
            seen.add(ti); tr = metadata_record(raw, 'types', ti)
            chain.append(dict(type_definition_index=ti, metadata_record=tr))
            parent = tr['fields']['parent_type_index']
            if parent < 0 or types[parent]['type_tag'] not in (17, 18):
                break
            ti = int(types[parent]['data'], 16)
        nested_chain = []; ti = method['fields']['declaring_type']; seen = set()
        while ti in nested_owner and ti not in seen:
            seen.add(ti); ti = nested_owner[ti]
            nested_chain.append(dict(type_definition_index=ti, metadata_record=metadata_record(raw, 'types', ti)))
        generic_owner_evidence = []
        for node in chain+nested_chain:
            gc = node['metadata_record']['fields']['generic_container_index']
            if gc != 0xffffffff:
                generic_owner_evidence.append(dict(type_definition_index=node['type_definition_index'],
                    generic_container=metadata_record(raw, 'generic_containers', gc)))
        gc = method['fields']['generic_container_index']
        owner_flags = chain[0]['metadata_record']['fields']['flags']
        owner_attributes = dict(raw=hex(owner_flags), interface=bool(owner_flags & 0x20),
                               abstract=bool(owner_flags & 0x80), windows_runtime=bool(owner_flags & 0x4000))
        ledger.append(dict(method_index=mi, signature=old['display_signature'], previous_gap_category=old['gap_category'],
             metadata_method_record=method, method_generic_container=metadata_record(raw, 'generic_containers', gc) if gc >= 0 else None,
             owner_type_attributes=owner_attributes,
             owner_and_base_chain=chain, enclosing_type_chain=nested_chain, generic_owner_evidence=generic_owner_evidence,
             module=module, direct_pointer_slot=hex(direct_slot), direct_pointer_file_offset=hex(elf.file_offset(direct_slot)),
             direct_pointer_raw=hex(elf.raw_pointer(direct_slot)), direct_pointer_relocated=hex(pointer),
             module_invoker_index_slot=hex(ip), module_invoker_index=ii,
             module_invoker_pointer_slot=hex(inv_array+8*ii) if ii >= 0 else None,
             module_invoker_address=hex(elf.pointer(inv_array+8*ii)) if ii >= 0 else None,
             registered_method_specs=specs[mi], matching_codegen_rows=mappings,
             status=classify(specs[mi], mappings, pointer), missing_cause='unknown', stripping_proven=False))
    result = dict(inputs=inputs, producer_sha256=sha(Path(__file__)), original_apk_sha256=summary['apk_sha256'],
         code_registration_address=hex(cb), metadata_registration_address=hex(rb),
         search_boundary=dict(metadata_method_records=len(direct), method_specs=reg['method_specs_count'],
             generic_codegen_rows=len(generic), generic_implementation_pointer_count=gp_count, invoker_count=inv_count),
         summary=dict(records=len(ledger), statuses=dict(Counter(x['status'] for x in ledger)),
             module_invoker_present=sum(x['module_invoker_index'] >= 0 for x in ledger),
             records_with_specs=sum(bool(x['registered_method_specs']) for x in ledger),
             records_with_codegen_rows=sum(bool(x['matching_codegen_rows']) for x in ledger),
             owner_is_interface=sum(x['owner_type_attributes']['interface'] for x in ledger)),
         negative_controls=selftest(), invoker_interpretation={
             'observed': 'All 70 per-module indices equal 0, whose global invoker slot is nonzero at 0x5f5090.',
             'limit': 'A shared index-zero value for null method pointers may be a default slot. No callable association or method body is established.',
             'existing_pseudocode': str(a.delivery/'native-ranges-pseudocode/ranges/table_invoker/FUN_005f5090_5f5090.c'),
             'source_bytes_start': '0x5f5090', 'source_bytes_end_exclusive': '0x5f516c',
             'source_bytes_sha256': hashlib.sha256(elf.data[elf.file_offset(0x5f5090):elf.file_offset(0x5f516c)]).hexdigest()},
         owner_attribute_reference='https://source.dot.net/System.Private.CoreLib/src/runtime/src/libraries/System.Private.CoreLib/src/System/Reflection/TypeAttributes.cs.html',
         non_generic_refinement='Index 65577 owner typeDefinition 9381 has flags 0x1040a0: abstract WindowsRuntime interface. The old concrete filter checked method Abstract bit only; this is not an ordinary concrete class body gap.',
         limitations=[
             'Absence from shipped MethodSpec/codegen tables establishes no registered instance in those tables, not no source instantiation or stripping.',
             'Invokers are ABI dispatch helpers; a nonzero invoker is not the method implementation.',
             'Intrinsic substitutions, runtime-generated implementations, and unregistered code cannot be resolved from these tables alone.',
             'No native call-site, RGCTX, or execution coverage claimed; no target code executed.'], records=ledger)
    a.output.mkdir(parents=True, exist_ok=False)
    (a.output/'ledger.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(result['summary'], indent=2))


if __name__ == '__main__':
    main()
