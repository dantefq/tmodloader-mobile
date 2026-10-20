"""Independent final audit of the separate native-range pseudocode export.

Refuses unfinished exports before scanning their journal or artifacts. Uses an
independent ELF LOAD parser and ARM64 branch decoder, not the exporter or its
ELF helper. Writes only new audit artifacts after a completed audit.
"""
import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import struct
from itertools import islice
import tempfile

MODEL = 'bounded-fde-terminal-calls-signatures-v3'
PROFILE = 'native-ranges-readonly-v3-journal-1'
ELF_SHA = '9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
TITLE = 'NATIVE RANGE PSEUDOCODE; NOT ORIGINAL SOURCE'
ASM_HEADER = ['range_entry', 'instruction_address', 'bytes', 'instruction']
CALL_HEADER = ['caller', 'source', 'target', 'type']


class AuditError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise AuditError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def number(value):
    require(isinstance(value, str) and bool(re.fullmatch(r'(?:0x)?[0-9a-fA-F]+', value)), f'Invalid RAM address {value!r}')
    return int(value, 16)


def sign(value, bits):
    return value - (1 << bits) if value & (1 << (bits-1)) else value


def branch(word, address):
    """Decode only direct AArch64 B/BL. Never guess register-call targets."""
    opcode = word & 0xfc000000
    if opcode in (0x94000000, 0x14000000):
        return ('BL' if opcode == 0x94000000 else 'B'), address + sign(word & 0x3ffffff, 26)*4
    if word & 0xfffffc1f == 0xd63f0000:
        return 'BLR', None
    return 'other', None


class OriginalELF:
    def __init__(self, path):
        self.bytes = path.read_bytes()
        require(digest(self.bytes) == ELF_SHA, 'Original ELF SHA mismatch')
        require(self.bytes[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H',self.bytes,18)[0] == 183, 'Wrong ELF ABI')
        phoff = struct.unpack_from('<Q',self.bytes,32)[0]
        size,count = struct.unpack_from('<HH',self.bytes,54)
        self.loads=[]
        for i in range(count):
            kind,flags,offset,va,_,filesz,_,_ = struct.unpack_from('<II6Q',self.bytes,phoff+i*size)
            if kind == 1:
                require(offset+filesz <= len(self.bytes), 'Invalid ELF LOAD bound')
                self.loads.append((va,va+filesz,offset,flags))

    def read(self, address, size):
        matches = [(a,b,o,f) for a,b,o,f in self.loads if a <= address and address+size <= b]
        require(len(matches)==1, f'No unique file-backed LOAD for {address:#x}+{size}')
        a,b,o,f=matches[0]
        start=o+address-a
        return self.bytes[start:start+size]


def confined(out, relative):
    require(isinstance(relative,str) and relative and '\\' not in relative, 'Empty or nonportable artifact path')
    p=Path(relative)
    require(not p.is_absolute() and '..' not in p.parts, f'Unconfined artifact path {relative!r}')
    resolved=(out/p).resolve()
    require(resolved.is_relative_to(out.resolve()), f'Artifact escapes export: {relative}')
    require(resolved.is_file(), f'Missing artifact: {relative}')
    return resolved


def native_header(row):
    comment=lambda s: s.replace('*/','* /').replace('\r',' ').replace('\n',' ')
    roles=json.dumps(row['classification']['roles'],ensure_ascii=False,separators=(',',':'))
    return (f'/* {TITLE}\n * Native function label: {comment(row["function_name"])}'
            f'\n * ELF VA: {row["address"]}; image base: 0\n * Compiler FDE end-exclusive: {row["compiler_end_exclusive"]}'
            f'\n * Analysis model: {MODEL}\n * Export profile: {PROFILE}'
            f'\n * Classification: {comment(row["classification"]["category"])}; roles: {comment(roles)}'
            f'\n * Native bytes SHA256: {row["source_bytes_sha256"]}\n */\n').encode('utf-8')


def tsv(data, expected_header):
    reader=csv.reader(io.StringIO(data.decode('utf-8')),delimiter='\t',quoting=csv.QUOTE_NONE)
    require(next(reader,None)==expected_header, f'Wrong TSV header {expected_header}')
    for row in reader:
        require(len(row)==len(expected_header), f'Wrong TSV column count: {row!r}')
        yield row


def verify_instructions(rows, address, end, original):
    previous=address;covered=0;count=0;words={};direct_branches={}
    for owner,va,raw,mnemonic in rows:
        ins=number(va)
        require(number(owner)==address, f'Instruction owner mismatch at {va}')
        require(address <= ins < end and ins % 4 == 0 and ins >= previous, f'Instruction outside FDE, overlap, or unaligned at {va}')
        require(bool(re.fullmatch('[0-9a-fA-F]{8}',raw)), f'Non-4-byte ARM64 instruction at {va}')
        encoded=bytes.fromhex(raw)
        require(ins+4 <= end and encoded==original(ins,4), f'Instruction bytes differ from original ELF at {va}')
        words[ins]=int.from_bytes(encoded,'little')
        kind,target=branch(words[ins],ins)
        if target is not None:
            direct_branches[ins]=(kind,target)
        previous=ins+4;covered+=4;count+=1
    return dict(count=count,bytes=covered,complete=covered==end-address,words=words,direct_branches=direct_branches)


def read_jsonl(path):
    with path.open('rb') as f:
        for index,line in enumerate(f,1):
            require(line.endswith(b'\n') and line.strip(), f'Incomplete/blank JSONL row {path}:{index}')
            try:
                yield json.loads(line)
            except Exception as error:
                raise AuditError(f'Invalid JSONL {path}:{index}: {error}') from error


def prefetch_artifacts(out, row):
    """Read each artifact once; its verified bytes feed the unchanged validators."""
    cached={}
    kinds=['asm','calls']+(['c'] if row.get('status')=='decompiled' else [])
    for kind in kinds:
        path_key,hash_key=('file','file_sha256') if kind=='c' else (kind+'_file',kind+'_sha256')
        path=confined(out,row[path_key])
        data=path.read_bytes()
        require(digest(data)==row[hash_key], f'{kind} artifact SHA mismatch at {row["address"]}')
        cached[kind]=(path,data)
    return row,cached


def prefetched_rows(out, path):
    # executor.map on an entire journal would enqueue all 87k reads. A batch
    # bounds pending work and cached bytes while preserving original row order.
    rows=iter(read_jsonl(path))
    with ThreadPoolExecutor(max_workers=16) as pool:
        while batch:=list(islice(rows,512)):
            yield from pool.map(lambda row:prefetch_artifacts(out,row),batch)


def self_test():
    # Positive and negative branch immediates; register targets stay unresolved.
    require(branch(0x94000002,0x1000)==('BL',0x1008),'BL decode')
    require(branch(0x97ffffff,0x1000)==('BL',0xffc),'Negative BL decode')
    require(branch(0x14000004,0x1000)==('B',0x1010),'B decode')
    require(branch(0xd63f0200,0x1000)==('BLR',None),'BLR decode')
    raw=struct.pack('<II',0x94000002,0xd65f03c0)
    original=lambda a,n:raw[a-0x1000:a-0x1000+n]
    rows=[['0x1000','00001000',raw[:4].hex(),'bl'],['0x1000','00001004',raw[4:].hex(),'ret']]
    verified=verify_instructions(rows,0x1000,0x1008,original)
    require(verified['complete'] and verified['count']==2,'Valid listing rejected')
    mutations=[rows[::-1],rows+[rows[-1]], [['0x1000','00001000','00000000','bad']],
               [['0x1000','00001001',raw[:4].hex(),'unaligned']], [['0x1004','00001000',raw[:4].hex(),'wrong owner']]]
    for mutation in mutations:
        try:
            verify_instructions(mutation,0x1000,0x1008,original)
        except AuditError:
            continue
        raise AuditError('Adversarial instruction fixture unexpectedly accepted')
    require(not verify_instructions(rows[:1],0x1000,0x1008,original)['complete'],'Gap incorrectly called complete')
    with tempfile.TemporaryDirectory(prefix='native-audit-io-smoke-') as temporary:
        directory=Path(temporary).resolve()
        data=b'caller\tsource\ttarget\ttype\n'
        for name in ['a.tsv','b.tsv','a.c']:
            (directory/name).write_bytes(data)
        row=dict(address='0x1000',status='decompiled',asm_file='a.tsv',asm_sha256=digest(data),calls_file='b.tsv',calls_sha256=digest(data),file='a.c',file_sha256=digest(data))
        _,cached=prefetch_artifacts(directory,row)
        require(all(content==data for _,content in cached.values()),'Prefetch changed artifact bytes')
        negative=[dict(row,asm_sha256='0'*64),dict(row,file_sha256='0'*64),dict(row,calls_file='../escape.tsv'),dict(row,file='missing.c')]
        for changed in negative:
            try:
                prefetch_artifacts(directory,changed)
            except AuditError:
                continue
            raise AuditError('Adversarial prefetch fixture unexpectedly accepted')
        journal=directory/'rows.jsonl'
        journal.write_text(''.join(json.dumps(dict(row,address=hex(0x1000+i*4)))+'\n' for i in range(513)),encoding='utf-8')
        ordered=[item['address'] for item,_ in prefetched_rows(directory,journal)]
        require(ordered==[hex(0x1000+i*4) for i in range(513)],'Prefetch changed order across batch boundary')
    print(json.dumps(dict(self_test='passed',target_export_read=False,adversarial_listing_cases=len(mutations),adversarial_io_cases=len(negative),prefetch_order_rows=513)))


def audit(args):
    lab=args.lab.resolve();out=(args.export or lab/'native-ranges-pseudocode').resolve();native=lab/'native'
    progress=json.loads((out/'progress.json').read_text(encoding='utf-8'))
    require(progress.get('finished') is True and progress.get('phase')=='complete', 'Export unfinished: audit intentionally refused before reading journal/artifacts')
    manifest=json.loads((out/'manifest.json').read_text(encoding='utf-8'))
    summary=json.loads((out/'summary.json').read_text(encoding='utf-8'))
    for key,value in [('profile',PROFILE),('model',MODEL),('image_base',0),('total',29162),('workers',4),('batch_size',4096),
                      ('language','AARCH64:LE:64:v8A'),('max_instructions',100000),('max_payload_mb',64),('header_title',TITLE)]:
        require(manifest.get(key)==value, f'Manifest {key} mismatch')
    require(manifest['timeout_seconds'] in (15,30),'Unknown timeout profile')
    for key,value in manifest.items():
        require(summary.get(key)==value, f'Summary manifest identity mismatch: {key}')
    require(summary.get('finished') is True,'Summary unfinished')
    classification_path=native/'unmapped-fde-classification.json'
    require(file_sha(classification_path)==manifest['classification_sha256'],'Classification SHA mismatch')
    fde_path=native/'unwind-function-ranges.tsv'
    require(file_sha(fde_path)==manifest['fde_tsv_sha256'],'FDE TSV SHA mismatch')
    require(manifest['elf_sha256']==ELF_SHA,'Manifest ELF SHA mismatch')
    original=OriginalELF(native/'libil2cpp.so')
    fdes={}
    with fde_path.open(encoding='utf-8') as f:
        for line in f:
            columns=line.rstrip('\n').split('\t');require(len(columns)==2,'Bad FDE TSV')
            address,end=map(number,columns);require(address not in fdes and address<end,'Duplicate/invalid FDE');fdes[address]=end
    require(len(fdes)==123152,'Incomplete FDE catalog')
    ordered=sorted(fdes)
    require(all(fdes[a]<=b for a,b in zip(ordered,ordered[1:])), 'Overlapping FDE extents')
    managed=set()
    for name in ['method-addresses.json','generic-method-addresses.json']:
        for row in json.loads((native/name).read_text(encoding='utf-8')):
            if row['address']:
                managed.add(number(row['address']))
    require(len(managed)==93990 and managed <= fdes.keys(),'Wrong managed implementation partition')
    classification=json.loads(classification_path.read_text(encoding='utf-8'))
    classes={number(row['address']):row for row in classification}
    require(len(classes)==len(classification)==29162 and classes.keys()==fdes.keys()-managed,'Wrong extra-FDE partition')
    for address,row in classes.items():
        require(number(row['end_exclusive'])==fdes[address] and row['size']==fdes[address]-address,'Classification FDE join mismatch')
    # Baseline is optional to locate, but its exact manifest hash is mandatory.
    candidates=[args.baseline] if args.baseline else [lab/'pseudocode/coverage.jsonl']+sorted(lab.glob('coverage-v3*.jsonl'))
    matching=[p for p in candidates if p and p.is_file() and file_sha(p)==manifest['managed_baseline_sha256']]
    require(matching,'Cannot locate pinned complete managed baseline SHA; pass --baseline')
    baseline=matching[0];baseline_seen=set()
    for row in read_jsonl(baseline):
        address=number(row['address']);require(address not in baseline_seen,'Duplicate managed baseline row');baseline_seen.add(address)
        require(row['profile']==MODEL and row['image_base']==0 and number(row['compiler_end_exclusive'])==fdes[address],'Invalid model-v3 baseline')
    require(baseline_seen==managed,'Pinned baseline differs from metadata direct/generic address union')
    if args.engine:
        require(file_sha(args.engine)==manifest['decompiler_engine_sha256'],'Engine SHA mismatch')
    rows={};status_counts=Counter();checks=Counter();known_calls=[];artifact_paths=set();expected_c=set()
    # Recompute exact aggregate content in classification order, matching producer,
    # while validating every independent per-range artifact below.
    aggregate_asm=hashlib.sha256(('\t'.join(ASM_HEADER)+'\n').encode())
    aggregate_calls=hashlib.sha256(('\t'.join(CALL_HEADER)+'\n').encode())
    per_address_artifacts={};call_references=[]
    for row,cached in prefetched_rows(out,out/'coverage.jsonl'):
        address=number(row['address']);require(address not in rows and address in classes,'Duplicate or unexpected native journal address')
        rows[address]=row;end=fdes[address]
        require(row['classification']==classes[address],'Coverage classification evidence differs from input')
        require(number(row['compiler_end_exclusive'])==end and row['compiler_size']==end-address,'Coverage FDE mismatch')
        for key,value in [('profile',PROFILE),('model',MODEL),('image_base',0),('timeout_seconds',manifest['timeout_seconds']),('max_instructions',100000)]:
            require(row[key]==value,f'Coverage profile mismatch at {address:#x}: {key}')
        require(row['source_bytes_sha256']==digest(original.read(address,end-address)),'Full FDE bytes SHA mismatch')
        header=native_header(row);require(row['header_sha256']==digest(header),'Header SHA mismatch')
        status=row['status'];require(status in ('decompiled','decompile_failed','missing_function','export_error'),'Unknown terminal status');status_counts[status]+=1
        for kind in ['asm','calls']:
            path,_=cached[kind];require(path not in artifact_paths,'Artifact reused across native rows');artifact_paths.add(path)
        asm_data=cached['asm'][1];calls_data=cached['calls'][1]
        decoded=verify_instructions(tsv(asm_data,ASM_HEADER),address,end,original.read)
        require(decoded['count']==row['instructions'] and decoded['bytes']==row['instruction_bytes'] and decoded['complete']==row['instruction_coverage_complete'],'Instruction counters or coverage flag mismatch')
        checks['verified_instruction_rows']+=decoded['count'];checks['verified_instruction_bytes']+=decoded['bytes']
        checks['ranges_with_listing_gaps']+=not decoded['complete'];checks['verified_full_fde_source_bytes']+=end-address
        for owner,source,target,kind in tsv(calls_data,CALL_HEADER):
            source_va=number(source);require(number(owner)==address and source_va in decoded['words'],'Call source missing from verified range listing')
            decoded_kind,decoded_target=branch(decoded['words'][source_va],source_va)
            ram_target=number(target) if re.fullmatch(r'(?:0x)?[0-9a-fA-F]+',target) else None
            if decoded_target is not None and ram_target is not None:
                require(decoded_target==ram_target,f'Direct branch/call target mismatch at {source}')
                checks['decoded_direct_bl_calls' if decoded_kind=='BL' else 'decoded_direct_b_refs_marked_call_by_model']+=1
                call_references.append((address,source_va,ram_target,decoded_kind))
            else:
                checks['indirect_or_symbolic_call_targets_not_independently_resolved']+=1
            checks['verified_call_reference_sources']+=1
        if status=='decompiled':
            path,content=cached['c'];require(path not in artifact_paths,'C artifact reused');artifact_paths.add(path);expected_c.add(path)
            require(content.startswith(header) and content[len(header):].strip(),'Missing exact native header or empty C body')
            require(b'NOT ORIGINAL C#' not in header and b' * Method:' not in header,'Native header makes managed source claims')
            checks['verified_c_files']+=1;checks['c_files_with_warnings']+=b'WARNING:' in content
        else:
            require(row['file']=='' and row['file_sha256']=='','Failed row claims C artifact')
            checks['failed_rows_without_c_claims']+=1
        per_address_artifacts[address]=(asm_data,calls_data)
    require(rows.keys()==classes.keys() and len(rows)==29162 and not rows.keys()&managed,'Incomplete/disjointness failure')
    require({p.resolve() for p in out.rglob('*.c')}==expected_c,'Unreferenced or missing C artifact found; review orphan output')
    for address in classes:
        asm_data,calls_data=per_address_artifacts[address]
        # Java readLine/newLine normalizes aggregate data rows to platform CRLF.
        # The first header was written with literal LF.
        for data,hasher in [(asm_data,aggregate_asm),(calls_data,aggregate_calls)]:
            lines=data.decode('utf-8').splitlines()[1:]
            for line in lines:
                hasher.update((line+'\r\n').encode('utf-8'))
    require(file_sha(out/'coverage.jsonl')==summary['coverage_sha256'],'Final coverage SHA mismatch')
    require(file_sha(out/'instructions.tsv')==summary['instructions_sha256']==aggregate_asm.hexdigest(),'Aggregate instructions differ from per-range records')
    require(file_sha(out/'calls.tsv')==summary['calls_sha256']==aggregate_calls.hexdigest(),'Aggregate calls differ from per-range records')
    for label,status in [('decompiled','decompiled'),('failed','decompile_failed'),('missing','missing_function'),('export_error','export_error')]:
        require(progress[label]==summary[label]==status_counts[status],f'Final {label} counter differs from journal')
    for key,value in [('profile',PROFILE),('model',MODEL),('total',29162),('processed',29162),('completed',29162),('workers',4),('batch_size',4096),('max_instructions',100000),('timeout_seconds',manifest['timeout_seconds']),('error','')]:
        require(progress[key]==value,f'Final progress {key} mismatch')
    # Confirm only structural relationships, not inferred behavior or new roles.
    unknown={a for a,r in classes.items() if r['category']=='unknown'}
    relationships=[];unknown_with_known_target=set()
    for caller,source,target,opcode in call_references:
        if caller in unknown and target in classes and classes[target]['category']!='unknown':
            evidence=classes[target];unknown_with_known_target.add(caller)
            relationships.append(dict(unknown_address=hex(caller),source_instruction=hex(source),target=hex(target),
                raw_branch_opcode=opcode,target_category=evidence['category'],target_roles=evidence['roles'],
                target_symbols=[s['name'] for s in evidence['symbols']],
                confidence='confirmed_raw_direct_branch_relationship',semantic_role='unknown',
                caveat='B marked as call is a model interpretation; branch target itself decoded from original bytes'))
    # Detect changes during auditing instead of approving a moving corpus.
    require(json.loads((out/'progress.json').read_text())==progress,'Progress changed during audit')
    require(json.loads((out/'manifest.json').read_text())==manifest,'Manifest changed during audit')
    require(file_sha(out/'coverage.jsonl')==summary['coverage_sha256'],'Coverage changed during audit')
    result=dict(audit_schema=1,passed=True,export_directory=str(out),fde_count=123152,
        managed_implementation_count=93990,native_range_count=29162,partition_disjoint=True,
        status_counts=dict(status_counts),checks=dict(checks),unknown_ranges=len(unknown),
        unknown_ranges_with_confirmed_direct_branch_to_known_extra_function=len(unknown_with_known_target),
        structural_relationship_count=len(relationships),semantic_roles_reassigned=0,
        model_snapshot_fingerprint_independently_recomputed=False,
        engine_sha_independently_checked=bool(args.engine),
        inputs=dict(elf_sha256=ELF_SHA,classification_sha256=manifest['classification_sha256'],
                    managed_baseline_sha256=file_sha(baseline),coverage_sha256=summary['coverage_sha256'],
                    manifest_sha256=file_sha(out/'manifest.json'),summary_sha256=file_sha(out/'summary.json'),
                    auditor_sha256=file_sha(Path(__file__))),
        limitations=['Artifact provenance, partition, bytes, calls and counter checks do not prove semantic correctness of decompiler C.',
                     'Original machine branch targets are independently decoded for B/BL only; register and symbolic targets remain explicitly unresolved.',
                     'Program snapshot signatures/flow fingerprint is producer evidence; independently reopening or altering Ghidra is outside this audit.',
                     'Unknown function roles remain unknown even when an exact direct branch reaches a known function.'])
    output=args.output or native/'native-ranges-export-audit.json'
    relations=output.with_name(output.stem+'-unknown-direct-relationships.jsonl')
    require(output.resolve()!=out/'summary.json' and not output.resolve().is_relative_to(out),'Audit output must be outside exporter directory')
    output.parent.mkdir(parents=True,exist_ok=True)
    with relations.open('w',encoding='utf-8',newline='\n') as f:
        for relation in relationships:
            f.write(json.dumps(relation,ensure_ascii=False,separators=(',',':'))+'\n')
    result['relationships_output']=dict(path=str(relations),sha256=file_sha(relations))
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return result


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--lab',type=Path,default=Path('C:/Temp/terraria-re-20261012'))
    ap.add_argument('--export',type=Path)
    ap.add_argument('--baseline',type=Path)
    ap.add_argument('--engine',type=Path,help='Optional selected decompile.exe: independently compare pinned SHA')
    ap.add_argument('--output',type=Path)
    ap.add_argument('--self-test',action='store_true')
    args=ap.parse_args()
    if args.self_test:
        self_test();return
    try:
        result=audit(args)
    except (AuditError,KeyError,FileNotFoundError,json.JSONDecodeError) as error:
        raise SystemExit(f'AUDIT REFUSED/FAILED: {error}') from error
    print(json.dumps({k:result[k] for k in ['passed','native_range_count','status_counts','checks','semantic_roles_reassigned']},indent=2))


if __name__=='__main__':
    main()
