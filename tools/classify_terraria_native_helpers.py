"""Classify FDE entries absent from managed implementation maps, offline.

The ABI roles are reconstructed from registration slots and validated indexes;
pointer membership is exact, but this does not recover unnamed function bodies.
Only new unmapped-fde-classification* artifacts are written. No target execution.
"""
import argparse
import bisect
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path
import struct

from terraria_native_map import ELF

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--lab', type=Path, default=Path('C:/Temp/terraria-re-20261012'))
    ap.add_argument('--summary', type=Path, default=ROOT/'reports/terraria-re-20261012/native-summary.json')
    args = ap.parse_args()
    native = args.lab/'native'
    names = ['libil2cpp.so', 'global-metadata.dat', 'unwind-function-ranges.json',
             'method-addresses.json', 'generic-method-addresses.json', 'elf-symbols.json', 'il2cpp-types.json']
    inputs = {name: dict(path=str(native/name), sha256=sha(native/name)) for name in names}
    inputs['native-summary.json'] = dict(path=str(args.summary), sha256=sha(args.summary))
    inputs['classifier_source'] = dict(path=str(Path(__file__)),sha256=sha(Path(__file__)))
    summary = json.loads(args.summary.read_text(encoding='utf-8'))
    assert inputs['libil2cpp.so']['sha256'] == summary['libil2cpp_sha256']
    assert inputs['global-metadata.dat']['sha256'] == summary['metadata_sha256']
    elf = ELF((native/'libil2cpp.so').read_bytes())
    load = lambda name: json.loads((native/name).read_text(encoding='utf-8'))
    ranges = load('unwind-function-ranges.json')
    direct, generic = load('method-addresses.json'), load('generic-method-addresses.json')
    symbols, types = load('elf-symbols.json'), load('il2cpp-types.json')['types']
    assert symbols == elf.symbols, 'Symbol input differs from original ELF dynsym'
    starts = {int(r['address'], 16): r for r in ranges}
    assert len(starts) == len(ranges) == 123152
    ordered = sorted(starts)
    assert all(int(starts[a]['end_exclusive'], 16) <= b for a, b in zip(ordered, ordered[1:]))
    managed = {int(r['address'], 16) for r in direct + generic if r['address']}
    assert len(managed) == 93990 and managed <= starts.keys()
    extra = starts.keys() - managed
    assert len(extra) == 29162
    refs = defaultdict(list)
    bindings = []
    tables = []
    validation = Counter()
    base = int(summary['generic_registration']['code_registration_address'], 16)

    def span(address, size):
        assert address and size >= 0
        off = elf.file_offset(address)
        if size:
            assert elf.file_offset(address+size-1) == off+size-1, 'Table crosses file-backed LOAD boundary'
        return off

    def ref(role, address, slot, index, **extra_info):
        evidence = dict(role=role, pointer_slot=hex(slot), index=index,
                        relocation_backed=slot in elf.relocations, **extra_info)
        if address:
            assert elf.executable(address), (role, hex(address))
            assert address in starts, ('Callback is not an exact FDE start', role, hex(address))
            refs[address].append(evidence)
            validation['nonzero_code_pointers_exact_fde_start'] += 1
        else:
            validation['null_code_pointer_slots'] += 1
        return address

    def pointer_table(role, count, pointer, registration_count_offset=None, registration_pointer_offset=None):
        assert 0 <= count < 1000000
        span(pointer, count*8) if count else None
        values = [ref(role, elf.pointer(pointer+i*8), pointer+i*8, i) for i in range(count)]
        tables.append(dict(role=role, count=count, address=hex(pointer),end_exclusive=hex(pointer+8*count),stride=8,
                           count_registration_offset=registration_count_offset,
                           pointer_registration_offset=registration_pointer_offset,
                           unique_nonzero=len(set(values)-{0}),
                           unseeded_unique=len(set(values)&extra),
                           managed_unique=len(set(values)&managed)))
        return values

    reverse = pointer_table('reverse_pinvoke_wrapper', elf.pointer(base), elf.pointer(base+8), 0, 8)
    generic_pointers = pointer_table('generic_implementation', elf.pointer(base+16), elf.pointer(base+24), 16, 24)
    assert set(generic_pointers)-{0} == {int(g['address'],16) for g in generic if g['address']}
    invokers = pointer_table('invoker', elf.pointer(base+40), elf.pointer(base+48), 40, 48)
    # ABI slot +56/+64: historically called unresolved virtual/indirect calls.
    # Preserve the slot name without inferring each dispatch target or signature.
    pointer_table('unresolved_indirect_call_stub', elf.pointer(base+56), elf.pointer(base+64), 56, 64)
    adjustor_indexes = {g['adjustor_thunk_index'] for g in generic if g['adjustor_thunk_index'] >= 0}
    assert adjustor_indexes == set(range(max(adjustor_indexes)+1))
    generic_adjustors = pointer_table('generic_adjustor_thunk', len(adjustor_indexes), elf.pointer(base+32), None, 32)
    tables[-1]['count_derivation'] = 'max referenced genericMethodTable adjustor index + 1; every index referenced'
    tables[-1]['unreferenced_tail_claimed'] = False
    for g in generic:
        pi, ii, ai = (g[k] for k in ('generic_method_pointer_index','invoker_index','adjustor_thunk_index'))
        assert -1 <= pi < len(generic_pointers) and -1 <= ii < len(invokers) and -1 <= ai < len(generic_adjustors)
        assert (generic_pointers[pi] if pi >= 0 else 0) == (int(g['address'],16) if g['address'] else 0)
        for role, index, array in [('invoker',ii,invokers), ('generic_adjustor_thunk',ai,generic_adjustors)]:
            if index >= 0:
                bindings.append(dict(role=role,address=hex(array[index]),method_index=g['method_index'],
                                     generic_table_index=g['generic_table_index'],image=g['image'],table_index=index))
        validation['generic_mapping_index_crosschecks'] += 1
    direct_by_image = defaultdict(dict)
    for m in direct:
        direct_by_image[m['image']][m['rid']] = m
    module_reverse_indexes = []
    assert elf.pointer(base+104) == len(summary['images']) == 35
    module_array = elf.pointer(base+112)
    known_modules = {int(m['module_address'],16):m for m in summary['modules']}
    modules = []
    for i in range(35):
        address = elf.pointer(module_array+8*i)
        no = elf.file_offset(elf.pointer(address))
        name = elf.data[no:elf.data.index(b'\0',no)].decode('utf-8')
        if address in known_modules:
            module = known_modules[address]
            assert module['image'] == name
        else:
            assert elf.pointer(address+8) == 0, 'Uncataloged nonempty codegen module'
            module = dict(image=name,module_address=hex(address),method_pointer_count=0)
            validation['previously_empty_codegen_modules'] += 1
        modules.append(module)
    assert {m['image'] for m in modules} == {im['name'] for im in summary['images']}
    assert known_modules.keys() <= {int(m['module_address'],16) for m in modules}
    for module in modules:
        image = module['image']
        address = int(module['module_address'],16)
        assert elf.pointer(address+8) == module['method_pointer_count']
        count, pointer = elf.pointer(address+24), elf.pointer(address+32)
        span(pointer,count*16) if count else None
        values = set()
        for i in range(count):
            token, padding = struct.unpack_from('<II',elf.data,elf.file_offset(pointer+i*16))
            assert token >> 24 == 6 and padding == 0
            method = direct_by_image[image][token & 0xffffff]
            target = ref('module_adjustor_thunk',elf.pointer(pointer+i*16+8),pointer+i*16+8,i,
                         image=image,method_token=hex(token),method_index=method['method_index'])
            values.add(target)
            bindings.append(dict(role='module_adjustor_thunk',address=hex(target),method_index=method['method_index'],
                                 image=image,table_index=i))
            validation['module_adjustor_method_token_crosschecks'] += 1
        tables.append(dict(role='module_adjustor_thunk',image=image,count=count,address=hex(pointer),end_exclusive=hex(pointer+16*count),stride=16,
                           module_address=hex(address),count_module_offset=24,pointer_module_offset=32,
                           unique_nonzero=len(values-{0}),unseeded_unique=len(values&extra)))
        # Per-module invoker indices have one int32 for each MethodDef RID.
        ip = elf.pointer(address+40)
        io = span(ip,module['method_pointer_count']*4) if module['method_pointer_count'] else None
        indices = struct.unpack_from('<'+str(module['method_pointer_count'])+'i',elf.data,io) if io is not None else ()
        assert all(-1 <= x < len(invokers) for x in indices)
        for rid, method in direct_by_image[image].items():
            index = indices[rid-1]
            if index >= 0:
                bindings.append(dict(role='invoker',address=hex(invokers[index]),method_index=method['method_index'],
                                     image=image,table_index=index,invoker_index_slot=hex(ip+4*(rid-1))))
            validation['module_invoker_index_crosschecks'] += 1
        # Token/index/method-cache/generic-index tuple is 24 bytes on AArch64.
        rc, rp = elf.pointer(address+48), elf.pointer(address+56)
        ro = span(rp,rc*24) if rc else None
        for i in range(rc):
            token,index,cache,generic_index,pad = struct.unpack_from('<IiQii',elf.data,ro+i*24)
            assert token >> 24 == 6 and 0 <= index < len(reverse) and pad == 0
            method = direct_by_image[image][token&0xffffff]
            assert cache == 0 or not elf.executable(cache)
            module_reverse_indexes.append(index)
            bindings.append(dict(role='reverse_pinvoke_wrapper',address=hex(reverse[index]),method_index=method['method_index'],
                                 image=image,table_index=index,token_tuple_address=hex(rp+i*24),
                                 opaque_method_cache_pointer=hex(cache),opaque_generic_index=generic_index))
            validation['module_reverse_pinvoke_token_index_crosschecks'] += 1
    assert set(module_reverse_indexes) == set(range(len(reverse)))
    # Interop records: five code callbacks, GUID data pointer, Il2CppType pointer.
    type_by_pointer = {int(t['pointer'],16):t for t in types}
    ic, ip = elf.pointer(base+72),elf.pointer(base+80)
    span(ip,ic*56)
    roles = ['interop_delegate_pinvoke_wrapper','interop_marshal_to_native',
             'interop_marshal_from_native','interop_marshal_cleanup','interop_create_ccw']
    for i in range(ic):
        record = ip+i*56
        typ = type_by_pointer[elf.pointer(record+48)]
        guid = elf.pointer(record+40)
        if guid:
            # This ELF places .rodata inside an executable LOAD. Section flags,
            # not the broad segment permission, distinguish GUID data here.
            span(guid,16)
            assert any(s['vaddr'] <= guid and guid+16 <= s['vaddr']+s['size']
                       and not s['flags'] & 4 for s in elf.sections)
            validation['interop_guid_data_crosschecks'] += 1
        for column,role in enumerate(roles):
            ref(role,elf.pointer(record+8*column),record+8*column,i,
                interop_record=hex(record),interop_type_index=typ['type_index'],interop_type=typ['name'])
        validation['interop_type_pointer_crosschecks'] += 1
    tables.append(dict(role='interop_record',count=ic,address=hex(ip),end_exclusive=hex(ip+56*ic),stride=56,
                       count_registration_offset=72,pointer_registration_offset=80,
                       callback_offsets=dict(zip(roles,range(0,40,8))),guid_offset=40,type_offset=48))
    assert elf.pointer(base+88) == elf.pointer(base+96) == 0
    validation['codegen_module_array_crosschecks'] = 35
    # ELF loader constructor/destructor arrays are independently named tables.
    # Some callbacks have no FDE: retain them separately, not in this partition.
    external_table_targets = []
    for section in elf.sections:
        if section['type'] not in (14,15,16):
            continue
        role = {14:'elf_initializer',15:'elf_finalizer',16:'elf_preinitializer'}[section['type']]
        assert section['size'] % 8 == 0
        values=[]
        for i in range(section['size']//8):
            slot=section['vaddr']+8*i
            target=elf.pointer(slot)
            values.append(target)
            if target in starts:
                ref(role,target,slot,i,section=section['name'])
            elif target:
                assert elf.executable(target)
                external_table_targets.append(dict(role=role,address=hex(target),pointer_slot=hex(slot),
                                                   section=section['name'],index=i,status='no_fde_at_entry'))
        tables.append(dict(role=role,address=hex(section['vaddr']),end_exclusive=hex(section['vaddr']+section['size']),count=len(values),stride=8,
                           section=section['name'],unique_nonzero=len(set(values)-{0}),
                           unseeded_unique=len(set(values)&extra),outside_fde_count=len(set(values)-starts.keys()-{0})))
    # Symbol categories use literal ELF names; no demangler or semantic guessing.
    # A sized, named _ZTV object supplies a separate provenance for hidden virtual
    # entries. Scan its bounded words; only exact FDE targets become evidence.
    # Itanium offset/typeinfo/header words and unresolved pointers stay opaque.
    vtable_symbols = [s for s in symbols if s['defined'] and s['type']==1
                      and s['name'].startswith('_ZTV') and s['size']]
    for symbol in vtable_symbols:
        address=int(symbol['address'],16)
        assert symbol['size']%8==0
        span(address,symbol['size'])
        matched=[]
        for i in range(symbol['size']//8):
            slot=address+8*i
            target=elf.pointer(slot)
            if target in starts:
                ref('elf_named_vtable_slot',target,slot,i,vtable_symbol=symbol['name'],
                    vtable_object_address=hex(address),vtable_object_size=symbol['size'])
                matched.append(target)
        tables.append(dict(role='elf_named_vtable_slot',symbol=symbol['name'],address=hex(address),end_exclusive=hex(address+symbol['size']),
                           size=symbol['size'],bounded_words=symbol['size']//8,
                           matched_fde_slots=len(matched),unique_fde_entries=len(set(matched)),
                           unseeded_unique=len(set(matched)&extra)))
    validation['sized_named_vtable_objects_checked']=len(vtable_symbols)
    sym_by_address = defaultdict(list)
    non_entry_symbols = []
    for symbol in symbols:
        if not symbol['defined'] or symbol['type'] != 2:
            continue
        address = int(symbol['address'],16)
        if address in starts:
            sym_by_address[address].append(symbol)
        elif elf.executable(address):
            pos = bisect.bisect_right(ordered,address)-1
            containing = ordered[pos] if pos>=0 and address < int(starts[ordered[pos]]['end_exclusive'],16) else None
            non_entry_symbols.append(dict(**symbol,containing_fde=hex(containing) if containing else None,
                                          relation='interior' if containing else 'outside_fde'))
    binding_counts = Counter(int(b['address'],16) for b in bindings)
    rows=[]
    for address in sorted(extra):
        fde = starts[address]
        evidence = refs[address]
        role_set = sorted({r['role'] for r in evidence})
        syms = sym_by_address[address]
        snames = [s['name'] for s in syms]
        if len(role_set) > 1:
            category = 'table_multiple_roles'
        elif role_set:
            category = 'table_'+role_set[0]
        elif any(n.startswith('il2cpp_') for n in snames):
            category = 'symbol_il2cpp_api'
        elif any(n.startswith(('_ZNSt','_ZNKSt','_ZTVSt','_ZTISt')) for n in snames):
            category = 'symbol_cpp_standard_library'
        elif any(n.startswith(('__cxa_','__gxx_','_Unwind_','_ZSt')) for n in snames):
            category = 'symbol_cpp_abi_or_runtime'
        elif snames:
            category = 'symbol_other_named_native'
        else:
            category = 'unknown'
        rows.append(dict(address=hex(address),end_exclusive=fde['end_exclusive'],size=fde['size'],
                         category=category,roles=role_set,pointer_evidence=evidence,symbols=syms,
                         method_binding_count=binding_counts[address],fde_file_offset=fde['fde_file_offset'],
                         evidence_confidence='exact_pointer_membership' if role_set else 'exact_symbol_entry' if snames else 'unknown'))
    assert len(rows)==len({r['address'] for r in rows})==len(extra)
    categories=Counter(r['category'] for r in rows)
    role_counts=Counter(role for r in rows for role in r['roles'])
    overlap_patterns=Counter('|'.join(r['roles']) for r in rows if len(r['roles'])>1)
    prefix=native/'unmapped-fde-classification'
    write_json(prefix.with_suffix('.json'),rows)
    with prefix.with_suffix('.csv').open('w',encoding='utf-8-sig',newline='') as f:
        fields=['address','end_exclusive','size','category','roles','method_binding_count','symbols','fde_file_offset','evidence_confidence']
        writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader()
        for row in rows:
            writer.writerow({k:json.dumps(row[k],ensure_ascii=False) if isinstance(row[k],list) else row[k] for k in fields})
    for suffix, records in [('-method-bindings.jsonl',bindings),('-pointer-evidence.jsonl',
                            [dict(address=hex(a),**r) for a in sorted(refs) for r in refs[a] if a in extra])]:
        with Path(str(prefix)+suffix).open('w',encoding='utf-8',newline='\n') as f:
            for record in records:
                f.write(json.dumps(record,ensure_ascii=False,separators=(',',':'))+'\n')
    write_json(Path(str(prefix)+'-tables.json'),tables)
    write_json(Path(str(prefix)+'-non-entry-symbols.json'),non_entry_symbols)
    write_json(Path(str(prefix)+'-external-table-targets.json'),external_table_targets)
    result=dict(schema_version=1,inputs=inputs,code_registration_address=hex(base),fde_count=len(starts),
                managed_implementation_count=len(managed),unseeded_fde_count=len(extra),
                category_counts=dict(categories),category_byte_counts=dict(Counter({c:sum(r['size'] for r in rows if r['category']==c) for c in categories})),
                table_role_counts_nonexclusive=dict(role_counts),multiple_role_patterns=dict(overlap_patterns),
                unknown_count=categories['unknown'],classified_count=len(rows)-categories['unknown'],
                method_bindings_count=len(bindings),validation=dict(validation),
                defined_function_symbols=sum(s['defined'] and s['type']==2 for s in symbols),
                symbols_not_at_fde_start=len(non_entry_symbols),
                table_targets_without_fde=len(external_table_targets),
                tables=tables,partition_complete=sum(categories.values())==29162,
                limitations=[
                    'Categories form an exclusive partition of the 29,162 FDE entries absent from the managed implementation catalogs; table roles and symbols are retained as nonexclusive evidence.',
                    'Registration role names are reconstructed IL2CPP ABI interpretations, validated by original pointer slots and token/index/type relationships; stripped ELF has no struct debug declarations.',
                    'Unknown entries are not asserted to be helpers, runtime code, generic sharing, or recovered source.',
                    'Generic adjustor table bound is the fully referenced index range; no unreferenced tail is claimed.',
                    'Unresolved indirect-call slot identifies a table of stubs, not their individual signatures or runtime dispatch targets.',
                    'Native symbol names identify an ELF function entry; semantic behavior and original source are not reconstructed here.',
                    'Sized named ELF _ZTV objects are scanned only for exact FDE target membership; header, RTTI, and other words remain opaque. No claim that all virtual slots were resolved.',
                    'FDE coverage does not prove coverage of leaf code without unwind records or of other APK libraries.',
                    'No Ghidra process, canonical pseudocode, report, explorer, or permanent delivery directory was modified.'
                ])
    output_paths=[prefix.with_suffix('.json'),prefix.with_suffix('.csv')]+sorted(native.glob('unmapped-fde-classification-*.jsonl'))+[Path(str(prefix)+'-tables.json'),Path(str(prefix)+'-non-entry-symbols.json'),Path(str(prefix)+'-external-table-targets.json')]
    result['outputs']={p.name:dict(sha256=sha(p),bytes=p.stat().st_size) for p in output_paths}
    write_json(Path(str(prefix)+'-summary.json'),result)
    print(json.dumps({k:result[k] for k in ['category_counts','table_role_counts_nonexclusive','unknown_count','classified_count','partition_complete']},indent=2))


if __name__=='__main__':
    main()
