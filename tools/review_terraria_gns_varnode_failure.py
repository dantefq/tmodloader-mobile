"""Read-only source/ELF/journal bindings for the GNS varnode failure review."""
import hashlib
import json
from pathlib import Path
from prove_libmain_stackchk_import import ELF

sha = lambda b: hashlib.sha256(b).hexdigest()
lab = Path('C:/Temp/terraria-re-20261012')
prep = lab / 'portable-decompiler-baseline-prep-20261017'
manifest = json.loads((prep / 'preparation-manifest.json').read_text())
sources = {r['path']: r for r in manifest['snapshot_files']}
selected = ['funcdata_varnode.cc', 'dynamic.cc', 'coreaction.cc', 'ghidra_process.cc', 'options.cc']
for name in selected:
    assert sha((prep / 'source' / name).read_bytes()) == sources[name]['sha256']
elf_path = Path('C:/Private/Documents/ChatGPT/Terraria-Reverse-20261012/android-native/libGNS_Wrapper.so')
raw = elf_path.read_bytes()
assert sha(raw) == '7e850163b92735b7b7307fb2919fb8064d5740cc0597b5e7c6a35d8454159df8'
elf = ELF(raw)
range_manifest_path = lab / 'other-native-range-v3-manifests-20261019/libGNS_Wrapper.so.manifest.json'
range_manifest_raw = range_manifest_path.read_bytes()
assert sha(range_manifest_raw) == 'c1ba2b0a384ed1af5ca1ae7e6d5a3eefc7aa8af6d0643370d13ae476abf9b264'
ranges = {r['address']: r for r in json.loads(range_manifest_raw)['rows']}
export = lab / 'other-native-range-c-libGNS_Wrapper-sample-v3-20261019'
commits = [json.loads(s) for s in (export / 'journal.jsonl').read_text().splitlines()]
results = []
for address in ['0x431198', '0x431520']:
    matches = [r for r in commits if r['address'] == address]
    assert len(matches) == 1
    p = export / ('range_' + address + '.json')
    result_raw = p.read_bytes()
    assert sha(result_raw) == matches[0]['result_sha256']
    result = json.loads(result_raw)
    row = ranges[address]
    for field in ['address', 'end_exclusive', 'source_sha256', 'evidence_kind']:
        assert result[field] == row[field]
    start, end = int(address, 16), int(row['end_exclusive'], 16)
    assert elf.mapping(start, end - start, True) == int(row['file_offset'], 16)
    assert sha(elf.read(start, end - start, True)) == row['source_sha256']
    assert result['status'] == 'decompile_failed' and result['timed_out'] is False
    assert not result['actual_C_object_returned'] and not result['decompile_completed']
    assert result['message'].strip() == 'Recoverable Error: Unable to find unique hash for varnode'
    assert not (export / ('range_' + address + '.c')).exists()
    results.append(dict(address=address, result_sha256=sha(result_raw), source_sha256=row['source_sha256'],
                        elapsed_seconds=result['elapsed_seconds'], bytes=end-start))
print(json.dumps(dict(source_snapshot_hashes_verified={n:sources[n]['sha256'] for n in selected},
                      journal_and_original_ELF_bindings_verified=True, results=results,
                      engine_or_JVM_or_compiler_launched=False, target_execution=False), indent=2))
