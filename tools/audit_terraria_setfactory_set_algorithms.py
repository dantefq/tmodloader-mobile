"""Independent opcode/flow and high-level output audit; no producer imports."""
import argparse,copy,hashlib,json,mmap,pathlib,struct

SOURCE='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
LITERAL='6fe84f649ecd9f9872106f4776b586a223a0593b6d19096dee9ca25264ca37fa'
BOOL_WORDS='f81e0ff4 a9017bf3 aa0203f3 2a0103f4 94000076 b4000400 f9400c0a d3607d48 f100051f 5400012b aa1f03e8 12000289 93407d4a 9100800b 38286969 91000508 eb0a011f 54ffffab b4000273 f9400e69 d3607d28 f100051f 5400018b 2a3403ea aa1f03e8 93407d29 1200014a 9100826b b8a8796c 91000508 eb09011f 8b0c000c 3900818a 54ffff6b a9417bf3 f84207f4 d65f03c0 97b0c065'
INT_WORDS='f81e0ff4 a9017bf3 b4000442 39406048 aa0203f3 37000408 2a0103f4 94002759 b4000380 f9400c09 d3607d28 f100051f 5400010b aa1f03e8 93407d29 9100800a b8287954 91000508 eb09011f 54ffffab b9401a68 7100051f 5400016b 2a1f03e9 9100826a b8a9d94b 1100052c b86cd94a 11000929 8b0b080b 6b08013f b900216a 54ffff0b a9417bf3 f84207f4 d65f03c0 97b0e6fb'
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);ap.add_argument('--check-source-only',action='store_true');a=ap.parse_args();lab=a.lab;binary=lab/'native/libil2cpp.so';assert sha(binary)==SOURCE;f=binary.open('rb');raw=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ);ph=struct.unpack_from('<Q',raw,32)[0];pw,pn=struct.unpack_from('<HH',raw,54);segments=[struct.unpack_from('<II6Q',raw,ph+i*pw) for i in range(pn)]
    def read(va,n):
        offsets=[s[2]+va-s[3] for s in segments if s[0]==1 and s[3]<=va and va+n<=s[3]+s[5]];assert len(offsets)==1;return raw[offsets[0]:offsets[0]+n]
    def word(pc):return int.from_bytes(read(pc,4),'little')
    # Entire two fixed instruction templates are checked, not only handpicked stores.
    for pc,text in [(0x1acf484,BOOL_WORDS),(0x1ac5a30,INT_WORDS)]:
        values=[int(w,16) for w in text.split()];assert read(pc,len(values)*4)==struct.pack('<'+'I'*len(values),*values)
    def signed(v,b):return v-(1<<b) if v&1<<(b-1) else v
    # Explicit signed-LT fill/apply loops and exits; no index bounds check inside.
    for pc,target in [(0x1acf4a8,0x1acf4cc),(0x1acf4c8,0x1acf4bc),(0x1acf4dc,0x1acf50c),(0x1acf508,0x1acf4f4),(0x1ac5a60,0x1ac5a80),(0x1ac5a7c,0x1ac5a70),(0x1ac5a88,0x1ac5ab4),(0x1ac5ab0,0x1ac5a90)]:
        w=word(pc);assert w&0xff00001f==0x5400000b and pc+signed((w>>5)&0x7ffff,19)*4==target
    parity=word(0x1ac5a44);assert parity&0x7f00001f==0x37000008 and (parity>>19)&31==0 and 0x1ac5a44+signed((parity>>5)&0x3fff,14)*4==0x1ac5ac4
    if a.check_source_only:print(json.dumps({'source_templates_verified':2,'native_bytes':300,'signed_LT_flow_edges':8,'odd_input_guard_verified':True}));raw.close();f.close();return
    out=lab/'setfactory-set-algorithms-20261015';p=out/'set-algorithms.json';d=json.loads(p.read_text());dep=lab/'itemsets-array-literals-20261015/array-literals.json';assert sha(dep)==LITERAL;literal=json.loads(dep.read_text());fixtures=[]
    for x in literal['arrays']:fixtures.append((x['conditional_result_static_field']['name'],'bool' if x['SetFactory_callee']=='0x1acf484' else 'int',x['serialized_little_endian_Int32_values'],x['SetFactory_default_argument']))
    fixtures.append(('ReceivesDiagonalCorrectionAsFakeFish','bool',[2342],1))
    def verify(doc):
        assert doc['elf_sha256']==SOURCE
        for path,h in doc['dependencies'].items():assert sha(lab/path)==h
        for fn,pc,end in zip(doc['functions'],[0x1acf484,0x1ac5a30],[0x1acf51c,0x1ac5ac4]):
            b=read(pc,end-pc);assert fn['start']==hex(pc) and fn['end_exclusive']==hex(end) and fn['bytes']==b.hex() and fn['sha256']==hashlib.sha256(b).hexdigest() and len(fn['instructions'])*4==len(b)
            for i,ins in enumerate(fn['instructions']):assert ins['address']==hex(pc+i*4) and ins['raw_bytes']==b[i*4:i*4+4].hex()
        for row,(name,kind,inputs,default) in zip(doc['results'],fixtures):
            assert row['conditional_static_field']==name and row['kind']==kind and row['input_values']==inputs and row['default']==default and row['assumed_output_length']==6196
            values=[default&1 if kind=='bool' else default for _ in range(6196)]
            if kind=='bool':
                for index in inputs:assert 0<=index<6196;values[index]=(default&1)^1
                payload=bytes(values);expected_steps=19+6196*4+len(inputs)*6;assert row['true_count']==sum(values) and row['false_count']==6196-sum(values) and row['instruction_visit_counts']['0x1acf4bc']==6196 and row['instruction_visit_counts']['0x1acf504']==len(inputs)
            else:
                assert len(inputs)%2==0
                for i in range(0,len(inputs),2):assert 0<=inputs[i]<6196;values[inputs[i]]=inputs[i+1]
                payload=b''.join(int(v).to_bytes(4,'little',signed=True) for v in values);expected_steps=12+6196*4+len(inputs)//2*9;assert row['instruction_visit_counts']['0x1ac5a70']==6196 and row['instruction_visit_counts']['0x1ac5aac']==len(inputs)//2
            edits=[{'index':i,'value':v} for i,v in enumerate(values) if v!=(default&1 if kind=='bool' else default)];assert row['output_byte_length']==len(payload) and row['modeled_output_sha256']==hashlib.sha256(payload).hexdigest() and row['sparse_edits_from_default']==edits and row['unique_edited_indices']==len(edits) and row['native_whitelist_steps']==expected_steps and row['all_input_indices_in_bounds'] is True and row['reference_agrees'] is True and row['actual_runtime_observed'] is False
        assert [x['unique_edited_indices'] for x in doc['results']]==[3,95,4,1]
    verify(d);rejected=[]
    for label,mut in [('wrong_bool_flip',lambda x:x['results'][0]['sparse_edits_from_default'][0].update(value=0)),('wrong_pair_value',lambda x:x['results'][2]['sparse_edits_from_default'][0].update(value=6169)),('wrong_output_length',lambda x:x['results'][1].update(assumed_output_length=6195)),('wrong_hash',lambda x:x['results'][3].update(modeled_output_sha256='0'*64)),('wrong_loop_count',lambda x:x['results'][0]['instruction_visit_counts'].update({'0x1acf4bc':6195})),('changed_opcode',lambda x:x['functions'][0].update(bytes='00'*152))]:
        bad=copy.deepcopy(d);mut(bad)
        try:verify(bad)
        except (AssertionError,KeyError,ValueError):rejected.append(label)
        else:raise AssertionError('Negative accepted '+label)
    result={'integrity_passed':True,'auditor_sha256':sha(pathlib.Path(__file__)),'evidence_sha256':sha(p),'producer_or_interpreter_imported':False,'native_instruction_bytes_verified':300,'signed_LT_flow_edges_verified':8,'odd_input_guard_verified':True,'modeled_arrays_verified':4,'unique_sparse_edits':[3,95,4,1],'negative_controls_rejected':rejected,'actual_runtime_execution_proven':False}
    (out/'independent-audit.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8');print(json.dumps(result));raw.close();f.close()

if __name__=='__main__':main()
