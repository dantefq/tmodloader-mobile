"""Fresh mmap/raw ISA and ELF/metadata audit of a conditional copy model."""
import copy,hashlib,json,mmap,struct
from pathlib import Path
LAB=Path('C:/Temp/terraria-re-20261012');OUT=LAB/'initialize-array-copy-model-20261015'
def sha(b):return hashlib.sha256(b).hexdigest()

def main():
    path=OUT/'copy-model.json';doc=json.loads(path.read_text())
    assert doc['elf_sha256']=='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
    assert doc['metadata_sha256']=='4c904c49d168913d28ef547c4f461e539d926d2ed27c0253ed53a2954e9585f7'
    for name,h in doc['dependencies'].items():assert sha((LAB/name).read_bytes())==h
    assert doc['dependencies']['itemsets-array-literals-20261015/array-literals.json']=='6fe84f649ecd9f9872106f4776b586a223a0593b6d19096dee9ca25264ca37fa'
    previous=json.loads((LAB/'itemsets-array-literals-20261015/array-literals.json').read_text(encoding='utf8'))
    assert sha(Path(__file__).with_name('terraria_initialize_array_copy_model.py').read_bytes())==doc['producer_sha256']
    with (LAB/'native/libil2cpp.so').open('rb') as f,(LAB/'native/global-metadata.dat').open('rb') as g:
      with mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as b,mmap.mmap(g.fileno(),0,access=mmap.ACCESS_READ) as m:
        assert sha(b)==doc['elf_sha256'] and sha(m)==doc['metadata_sha256']
        def uint(blob,off,size=4):return int.from_bytes(blob[off:off+size],'little')
        po=uint(b,32,8);ps=uint(b,54,2);pn=uint(b,56,2);loads=[]
        for i in range(pn):
            p=po+i*ps
            if uint(b,p)==1:loads.append((uint(b,p+16,8),uint(b,p+32,8),uint(b,p+8,8)))
        def at(va,n=4):
            found=[off+va-start for start,size,off in loads if start<=va and va+n<=start+size]
            assert len(found)==1;return found[0]
        def data(va,n):p=at(va,n);return b[p:p+n]
        def word(va):return uint(b,at(va))
        so=uint(b,40,8);ss=uint(b,58,2);sn=uint(b,60,2)
        sections=[(uint(b,so+i*ss+4),uint(b,so+i*ss+24,8),uint(b,so+i*ss+32,8),uint(b,so+i*ss+40),uint(b,so+i*ss+56,8)) for i in range(sn)]
        wanted={int(r['GOT_slot'],16) for r in doc['PLT_bindings']};rel={}
        for kind,off,length,link,stride in sections:
            if kind!=4:continue
            assert stride==24
            for p in range(off,off+length,24):
                target=uint(b,p,8)
                if target in wanted:
                    assert target not in rel;rel[target]=(p,link)
        def direct(pc):
            w=word(pc);op=w>>26;assert op in (5,37)
            imm=w%0x4000000;imm-=0x4000000 if imm>=0x2000000 else 0
            return ('B' if op==5 else 'BL',pc+imm*4)
        def load(pc,bits,rd,rn,offset):
            w=word(pc);opcode=0xf9400000 if bits==64 else 0xb9400000
            assert w&0xffc00000==opcode and w&31==rd and w>>5&31==rn
            assert ((w>>10)&4095)*(bits//8)==offset
        def globalpair(pc,loadpc,rn,expected):
            w=word(pc);assert w&0x9f000000==0x90000000 and w&31==rn
            imm=((w>>5)&0x7ffff)*4+((w>>29)&3);imm-=0x200000 if imm&0x100000 else 0
            base=pc//4096*4096+imm*4096
            l=word(loadpc);assert l&0xffc00000==0xf9400000 and l>>5&31==rn
            assert base+((l>>10)&4095)*8==expected
        # Independently assert raw ISA semantics for the model's arithmetic and source/dest registers.
        load(0x7143a4,32,0,0,256);assert word(0x7143a8)==0xd65f03c0
        load(0x751b1c,32,8,0,0);load(0x751b20,32,9,1,0)
        assert word(0x751b24)==0x4b090100 and word(0x751b28)==0xd65f03c0
        load(0x6ab748,64,22,0,0);load(0x6ab7b0,32,8,19,24)
        assert word(0x6ab7b8)==0x1b087eb5  # MADD W21,W21,W8,WZR.
        assert word(0x6ab7c0)==0x91008268  # ADD X8,X19,#32.
        assert word(0x6ab7c4)==0xaa1503e2 and word(0x6ab7d0)==0xaa0003e1 and word(0x6ab7d4)==0xaa0803e0
        load(0x74be54,64,20,0,16);load(0x74be5c,64,8,20,128)
        assert word(0x74be60)==0xcb080008 and word(0x74be68)==0xd345fd16
        load(0x74be80,64,8,20,104);load(0x74be90,32,8,8,32)
        assert word(0x74bea0)==0x0b160108 and word(0x74bea8)==0x69482528
        assert word(0x74bebc)==0x9bcb7d28 and word(0x74bec0)==0xd343fd02 and word(0x74bec4)==0x52800183
        globalpair(0x74be84,0x74be88,21,0x3214f18);globalpair(0x74be8c,0x74be94,20,0x3214f10)
        # Comparator address uses ADRP+ADD rather than LDR.
        a=word(0x74beac);add=word(0x74beb0)
        assert a&0x9f00001f==0x90000004 and add&0xffc003ff==0x91000084
        displacement=((a>>5)&0x7ffff)*4+((a>>29)&3);displacement-=0x200000 if displacement&0x100000 else 0
        assert 0x74beac//4096*4096+displacement*4096+((add>>10)&4095)==0x751b1c
        do,ds=uint(m,64),uint(m,68);bo,bs=uint(m,72),uint(m,76)
        original_records=[struct.unpack_from('<iii',m,p) for p in range(do,do+ds,12)]
        def sorted_defaults(records):
            assert records and all(0<=records[i][0]<records[i+1][0] for i in range(len(records)-1))
        sorted_defaults(original_records)
        assert ds%12==0 and ((ds*0xaaaaaaaaaaaaaaab)//(1<<64))//8==ds//12
        lookup={row[0]:(i,row) for i,row in enumerate(original_records)}
        def verify(d):
            for row in d['source_fragments']:
                start=int(row['start'],16);end=int(row['end_exclusive'],16);raw=data(start,end-start)
                assert raw.hex()==row['raw_bytes'] and sha(raw)==row['sha256']
            for row in d['exact_instruction_checks']:assert word(int(row['site'],16))==int(row['word'],16)
            for row in d['direct_edges']:assert direct(int(row['site'],16))==(row['kind'],int(row['target'],16))
            assert {r['symbol_name'] for r in d['PLT_bindings']}=={'bsearch','memcpy'}
            for row in d['PLT_bindings']:
                entry=int(row['entry'],16);raw=data(entry,16);assert raw.hex()==row['raw_bytes']
                a,l,add,br=struct.unpack('<4I',raw)
                assert a&0x9f00001f==0x90000010 and l&0xffc003ff==0xf9400211 and add&0xffc003ff==0x91000210 and br==0xd61f0220
                disp=((a>>5)&0x7ffff)*4+((a>>29)&3);disp-=1<<21 if disp&1<<20 else 0
                base=entry//4096*4096+disp*4096;slot=base+((l>>10)&4095)*8
                assert slot==int(row['GOT_slot'],16) and base+((add>>10)&4095)==slot
                off,section=rel[slot];info=uint(b,off+8,8);assert info&0xffffffff==row['relocation_type']==1026
                assert uint(b,off+16,8)==0
                assert row['relocation_file_offset']==hex(off) and row['relocation_bytes']==b[off:off+24].hex()
                _,syoff,sysize,sylink,systride=sections[section];ix=info>>32;sp=syoff+ix*systride
                assert sp+24<=syoff+sysize and systride==24
                name=uint(b,sp);defined=uint(b,sp+6,2);value=uint(b,sp+8,8)
                _,stro,strsize,_,_=sections[sylink];p=stro+name;end=b.find(b'\0',p,stro+strsize);assert end>=p
                label=b[p:end].decode('ascii')
                assert row['symbol_name']==label and row['dynsym_index']==ix and row['symbol_record_offset']==hex(sp)
                assert row['symbol_record_bytes']==b[sp:sp+24].hex() and row['symbol_defined']==bool(defined) and row['symbol_value']==hex(value)
                assert label==({0x59ecd0:'bsearch',0x59f490:'memcpy'}[entry])
            table=d['field_default_table'];assert table['offset']==do and table['byte_size']==ds and table['count']==len(original_records)
            assert table['table_sha256']==sha(m[do:do+ds]) and table['strictly_sorted_unique_field_indices'] is True
            assert table['first_field_index']==original_records[0][0] and table['last_field_index']==original_records[-1][0]
            assert d['owner_typedef']==3812
            to=uint(m,160);p=to+3812*88;fieldstart=uint(m,p+32)
            assert d['owner_metadata_record_offset']==hex(p) and d['owner_metadata_record_bytes']==m[p:p+88].hex() and d['owner_field_start']==fieldstart
            assert len(d['arrays'])==3
            total=0;bytes_count=0
            for row,old in zip(d['arrays'],previous['arrays']):
                field=old['source_field_index'];index,record=lookup[field]
                assert row['source_field_index']==field and row['local_FieldInfo_index']==field-fieldstart
                assert row['metadata_default_record_index']==index and row['metadata_default_record_offset']==hex(do+12*index)
                assert row['metadata_default_record_bytes']==m[do+12*index:do+12*index+12].hex()
                assert row['data_index']==record[2]>=0
                count=old['caller_allocation_count'];n=count*4
                assert row['array_length']==count and row['assumed_runtime_element_size']==4 and row['conditional_copy_bytes']==n
                assert row['source_metadata_file_offset']==hex(bo+record[2]) and record[2]+n<=bs and n<1<<32
                blob=m[bo+record[2]:bo+record[2]+n]
                assert row['blob_bytes']==blob.hex()==old['blob_bytes'] and row['blob_sha256']==sha(blob)
                assert row['copied_little_endian_Int32_values']==list(struct.unpack('<'+'i'*count,blob))==old['serialized_little_endian_Int32_values']
                # Different search strategy from producer: direct uniqueness plus comparator sign for every original table key.
                assert sum(r[0]==field for r in original_records)==1
                for r in original_records:
                    difference=field-r[0];assert -(1<<31)<=difference<1<<31
                    assert ((difference>0)-(difference<0))==((field>r[0])-(field<r[0]))
                total+=count;bytes_count+=n
            assert d['literal_Int32_count']==total==109 and d['conditional_copy_bytes']==bytes_count==436
            assert d['runtime_verified'] is False and d['full_set_membership_proven'] is False and d['baseline_modified'] is False
            assert len(d['semantic_contract_assumptions'])==2 and len(d['runtime_layout_and_path_assumptions'])==5 and len(d['missing_proofs'])==2
        verify(doc);negatives=[]
        for label,mutate in [
            ('wrong_memcpy_symbol',lambda d:d['PLT_bindings'][1].__setitem__('symbol_name','memmove')),
            ('wrong_GOT_slot',lambda d:d['PLT_bindings'][0].__setitem__('GOT_slot','0x1234')),
            ('wrong_comparator_word',lambda d:next(r for r in d['exact_instruction_checks'] if r['site']=='0x751b24').__setitem__('word','0x4b080120')),
            ('wrong_field_index',lambda d:d['arrays'][0].__setitem__('source_field_index',43867)),
            ('wrong_blob_index',lambda d:d['arrays'][0].__setitem__('data_index',0)),
            ('wrong_copy_length',lambda d:d['arrays'][1].__setitem__('conditional_copy_bytes',396)),
            ('changed_element_size_premise',lambda d:d['arrays'][0].__setitem__('assumed_runtime_element_size',8)),
            ('invented_full_membership',lambda d:d.__setitem__('full_set_membership_proven',True))]:
            bad=copy.deepcopy(doc);mutate(bad)
            try:verify(bad)
            except (AssertionError,KeyError,ValueError):negatives.append(label)
            else:raise AssertionError('Accepted negative '+label)
        unsorted=list(original_records);unsorted[0],unsorted[1]=unsorted[1],unsorted[0]
        duplicate=list(original_records);duplicate[1]=duplicate[0]
        for label,records in [('unsorted_defaults_rejected',unsorted),('duplicate_defaults_rejected',duplicate)]:
            try:sorted_defaults(records)
            except AssertionError:negatives.append(label)
            else:raise AssertionError('Accepted negative '+label)
    result=dict(integrity_passed=True,evidence_sha256=sha(path.read_bytes()),auditor_sha256=sha(Path(__file__).read_bytes()),
                producer_imported=False,fresh_mmap_ELF_RELA_dynsym_metadata_and_raw_ISA_checks=True,
                source_fragments_verified=len(doc['source_fragments']),source_bytes_verified=sum(len(bytes.fromhex(r['raw_bytes'])) for r in doc['source_fragments']),
                sorted_unique_default_records=29227,arrays_verified=3,literal_Int32_count=109,conditional_copy_bytes=436,
                negative_controls_rejected=negatives,runtime_verified=False,cache_construction_proven=False,actual_runtime_element_size_proven=False,
                limits=doc['missing_proofs'])
    (OUT/'independent-audit.json').write_text(json.dumps(result,indent=2)+'\n')
    report=['# Условная модель InitializeArray: литеральный blob → массив','',
            'По исходным ARM64, ELF relocations/dynsym и metadata31 проверены привязки PLT к bsearch/memcpy, comparator signed Int32 subtraction, getter размера элемента и вычисление адресов/count в copy path.',
            '', 'Все 29227 field-default records исходных метаданных строго упорядочены и уникальны по field index. Три проверенных FieldInfo-индекса соответствуют точным blob records:12,392,32 байта — всего109 сериализованных little-endian Int32.',
            '', 'При перечисленных предпосылках runtime layouts, успешного guard path, согласованного FieldInfo/class cache, размера элемента4 и обычных C-контрактов bsearch/memcpy путь копирует эти436байт в соответствующие array+0x20. Нативный MUL выполняется в32битах; для этих трёх длин переполнения нет.',
            '', 'Это условный вывод о копировании, не наблюдение runtime-массивов и не полный membership ItemID.Sets. Построение cache и фактический runtime element_size остаются непроверенными предпосылками. Исходный frozen array-literals proof не изменён.',
            '', '[Исходные байты, отдельные предпосылки и модель](copy-model.json) · [Свежий независимый аудит и10 отрицательных проверок](independent-audit.json)']
    (OUT/'REPORT.ru.md').write_text('\n'.join(report)+'\n',encoding='utf8')
    print(json.dumps({k:result[k] for k in ('integrity_passed','sorted_unique_default_records','literal_Int32_count','conditional_copy_bytes','negative_controls_rejected')}))

if __name__=='__main__':main()
