"""Check captured ABI-control bytes and explicit register-use examples against ELF."""
import argparse, hashlib, json
from pathlib import Path
from terraria_native_map import ELF

p=argparse.ArgumentParser();p.add_argument('attempt',type=Path);p.add_argument('--lab',type=Path,default=Path('C:/Temp/terraria-re-20261012'));a=p.parse_args()
raw=(a.lab/'native/libil2cpp.so').read_bytes();elf=ELF(raw)
controls=json.loads((a.lab/'native/abi-v4/control-methods.json').read_text())
assert len(controls)==10
ins={}; results={}; count=0
for control in controls:
    address=control['native_address'];folder=a.attempt/address
    r=json.loads((folder/'result.json').read_text());results[address]=r
    assert r['decompile_completed'] and r['candidate_c_written']
    assert r['metadata']==control and not r['canonical_ledger_changed'] and not r['runtime_verified']
    rows=[json.loads(line) for line in (folder/'instructions.jsonl').read_text().splitlines()]
    assert len(rows)==r['instructions']
    for row in rows:
        va=int(row['address'],16);offset=elf.file_offset(va);b=bytes.fromhex(row['raw_bytes'])
        assert len(b)==4 and raw[offset:offset+4]==b
        assert row['flow_override']=='NONE'
        count+=1
    ins[address]=[row['instruction'] for row in rows]
def registers(item):return [s['register'] for s in item['storage_pieces']]
add=results['0xe99208']
assert registers(add['return'])==['s1','s0']
assert registers(add['parameters'][0])==['s1','s0']
assert registers(add['parameters'][1])==['s3','s2']
assert ins['0xe99208']==['fadd s0,s0,s2','fadd s1,s1,s3','ret']
length=results['0xe99914']
assert registers(length['parameters'][0])==['x0'] and registers(length['return'])==['s0']
lerp=results['0xe99994']
assert registers(lerp['parameters'][2])==['s4'] and registers(lerp['return'])==['s1','s0']
rectangle=results['0xe9879c']
assert registers(rectangle['parameters'][0])==['x0']
assert registers(rectangle['parameters'][1])==['x2','x1']
assert 'cmp w8,w1' in ins['0xe9879c'] and 'add w10,w2,w1' in ins['0xe9879c']
report={'finished':True,'control_methods':10,'decompiled':10,'verified_instruction_bytes':count*4,
        'elf_sha256':hashlib.sha256(raw).hexdigest(), 'control_attempt':str(a.attempt.resolve()),
        'register_use_examples':['Vector2.Add: s0/s1+s2/s3 -> s0/s1',
                                 'Vector2.Length: receiver x0, scalar return s0',
                                 'Vector2.Lerp: amount s4, aggregate return s0/s1',
                                 'Rectangle.Contains: receiver x0, 16-byte value x1/x2'],
        'scope':'Representative controls, not proof of every aggregate or caller; no target execution',
        'all_55524_signatures_validated':False,'runtime_verified':False}
(a.attempt/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
