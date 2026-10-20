"""Independent mmap ELF64/metadata and raw instruction audit; no producer imports."""
import copy,hashlib,json,mmap,struct
from pathlib import Path
LAB=Path('C:/Temp/terraria-re-20261012');OUT=LAB/'class-usage-root-catalog-20261015'
def digest(x):return hashlib.sha256(x).hexdigest()

def main():
    doc=json.loads((OUT/'catalog.json').read_text())
    assert doc['elf_sha256']=='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
    assert doc['metadata_sha256']=='4c904c49d168913d28ef547c4f461e539d926d2ed27c0253ed53a2954e9585f7'
    proof=LAB/'static-field-roots-20261015/static-field-roots.json'
    assert digest(proof.read_bytes())==doc['parent_model_sha256']=='22f6f7fd1eba05ae5c284adcc4adb856296122133ff5050d8e9a553459ef02e3'
    assert doc['dependencies']=={'static-field-roots-20261015/static-field-roots.json':doc['parent_model_sha256']}
    assert digest(Path(__file__).with_name('terraria_class_usage_root_catalog_20261015.py').read_bytes())==doc['producer_sha256']
    with (LAB/'native/libil2cpp.so').open('rb') as f,(LAB/'native/global-metadata.dat').open('rb') as g:
        with mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as b,mmap.mmap(g.fileno(),0,access=mmap.ACCESS_READ) as m:
            assert digest(b)==doc['elf_sha256'] and digest(m)==doc['metadata_sha256']
            assert b[:7]==b'\x7fELF\x02\x01\x01' and int.from_bytes(b[18:20],'little')==183
            assert int.from_bytes(m[:4],'little')==0xfab11baf and int.from_bytes(m[4:8],'little')==31
            def u16(blob,p):return int.from_bytes(blob[p:p+2],'little')
            def u32(blob,p):return int.from_bytes(blob[p:p+4],'little')
            def u64(blob,p):return int.from_bytes(blob[p:p+8],'little')
            po=u64(b,32);ps=u16(b,54);pn=u16(b,56);segments=[]
            for i in range(pn):
                p=po+ps*i
                if u32(b,p)==1:segments.append((u64(b,p+16),u64(b,p+32),u64(b,p+8),u32(b,p+4)))
            def offset(va,n=8):
                found=[file+va-start for start,size,file,flags in segments if start<=va and va+n<=start+size]
                assert len(found)==1
                return found[0]
            so=u64(b,40);ss=u16(b,58);sn=u16(b,60);relative={}
            for i in range(sn):
                p=so+ss*i
                if u32(b,p+4)!=4:continue
                assert u64(b,p+56)==24
                begin=u64(b,p+24);end=begin+u64(b,p+32)
                for r in range(begin,end,24):
                    # R_AARCH64_RELATIVE with zero symbol index only.
                    if u64(b,r+8)!=1027:continue
                    slot=u64(b,r);assert slot not in relative
                    relative[slot]=(int.from_bytes(b[r+16:r+24],'little',signed=True),r)
            registration=relative[0x306f9c0][0];assert registration==0x2fdb588
            table=relative[registration+56][0];count=u64(b,offset(registration+48));assert table==0x2ff5128 and count==23420
            to,ts=u32(m,160),u32(m,164);st,sz=u32(m,24),u32(m,28)
            assert ts%88==0 and to+ts<=len(m) and st+sz<=len(m)
            def string(index):
                assert index<sz
                end=m.find(b'\0',st+index,st+sz);assert end>=st+index
                return m[st+index:end].decode('utf8')
            def typeinfo(index,requirebyval=True,bits_override=None):
                assert 0<=index<count
                ptr,record=relative[table+index*8]
                p=offset(ptr,12);definition=u64(b,p);bits=u32(b,p+8)
                if bits_override is not None:bits=bits_override
                assert bits>>16&255==18 and definition<ts//88 and bits>>30==0
                mp=to+definition*88
                if requirebyval:assert u32(m,mp+8)==index
                return ptr,definition,mp
            def name(definition,ancestors=()):
                assert definition not in ancestors and len(ancestors)<32
                mp=to+definition*88;n=string(u32(m,mp));ns=string(u32(m,mp+4))
                parent=int.from_bytes(m[mp+12:mp+16],'little',signed=True)
                if parent>=0:return name(typeinfo(parent,False)[1],ancestors+(definition,))+'+'+n
                return ns+'.'+n if ns else n
            def cell(slot):
                assert slot%8==0
                assert any(flags&2 and start<=slot and slot+8<=start+size for start,size,file,flags in segments)
                word=u64(b,offset(slot))
                assert word<0x100000000 and word%2==1 and word//0x20000000==1
                index=(word//2)%0x10000000
                ptr,definition,mp=typeinfo(index)
                label=name(definition)
                return word,index,ptr,definition,mp,label
            expected_cells=set();allcells=0;kind1valid=0;rejected=0
            targets={value for value,off in relative.values()}
            for start,size,file,flags in segments:
                if not flags&2:continue
                for va in range((start+7)//8*8,start+size-7,8):
                    allcells+=1;word=u64(b,offset(va))
                    if not(word<0x100000000 and word%2==1 and word//0x20000000==1):continue
                    try:cell(va)
                    except (AssertionError,KeyError,ValueError):rejected+=1;continue
                    kind1valid+=1
                    if va in targets:expected_cells.add(va)
            def checkroot(row):
                slot=int(row['slot'],16);word,index,ptr,definition,mp,label=cell(slot)
                assert row['encoded_word']==hex(word) and row['initial_bytes']==b[offset(slot):offset(slot)+8].hex()
                assert row['usage_kind']==1 and row['type_index']==index and row['typedef_index']==definition
                assert row['native_type_pointer']==hex(ptr) and row['native_type_bytes']==b[offset(ptr,12):offset(ptr,12)+12].hex()
                assert row['metadata_record_file_offset']==hex(mp) and row['metadata_record_bytes']==m[mp:mp+88].hex()
                assert row['declared_name']==label
                expected=[]
                for source,(value,off) in relative.items():
                    if value==slot:expected.append(dict(slot=hex(source),addend=hex(value),file_offset=hex(off),raw_bytes=b[off:off+24].hex()))
                assert row['incoming_RELATIVE_relocations']==expected and expected
                return slot
            # Index incoming relocations once; use exact row checks without O(roots*relocations).
            bytarget={}
            for source,pair in relative.items():
                if pair[0] in expected_cells:bytarget.setdefault(pair[0],{})[source]=pair
            roots={};firstroot=None
            with (OUT/'roots.jsonl').open(encoding='utf8') as stream:
                for line in stream:
                    row=json.loads(line);slot=int(row['slot'],16)
                    # Keep full map for type resolution, but avoid repeatedly scanning it in checkroot.
                    word,index,ptr,definition,mp,label=cell(slot)
                    assert row['encoded_word']==hex(word) and row['initial_bytes']==b[offset(slot):offset(slot)+8].hex()
                    assert row['usage_kind']==1 and row['type_index']==index and row['typedef_index']==definition
                    assert row['native_type_pointer']==hex(ptr) and row['native_type_bytes']==b[offset(ptr,12):offset(ptr,12)+12].hex()
                    assert row['metadata_record_file_offset']==hex(mp) and row['metadata_record_bytes']==m[mp:mp+88].hex() and row['declared_name']==label
                    incoming=[dict(slot=hex(source),addend=hex(value),file_offset=hex(off),raw_bytes=b[off:off+24].hex()) for source,(value,off) in bytarget[slot].items()]
                    assert row['incoming_RELATIVE_relocations']==incoming and incoming
                    assert slot not in roots;roots[slot]=row['exact_init_call_count']
                    if firstroot is None:firstroot=row
            assert set(roots)==expected_cells
            def exact(site,bytes_override=None):
                assert site%4==0 and any(flags&1 and start<=site and site+12<=start+size for start,size,file,flags in segments)
                raw=b[offset(site,12):offset(site,12)+12] if bytes_override is None else bytes_override
                a=int.from_bytes(raw[:4],'little');l=int.from_bytes(raw[4:8],'little');bl=int.from_bytes(raw[8:12],'little')
                assert (a&0x9f000000)==0x90000000 and a&31==0
                assert l>>22==0x3e5 and l&1023==0
                assert bl>>26==37
                imm=bl%(1<<26);imm-=1<<26 if imm>=1<<25 else 0
                assert site+8+imm*4==0x6ff5ac
                disp=((a>>5)&0x7ffff)*4+((a>>29)&3);disp-=1<<21 if disp>=1<<20 else 0
                got=site//4096*4096+disp*4096+((l>>10)&4095)*8
                value=relative[got][0];assert value in roots
                return got,value,raw
            seen=set();counts={};firstcall=None
            with (OUT/'exact-init-calls.jsonl').open(encoding='utf8') as stream:
                for line in stream:
                    row=json.loads(line);site=int(row['adrp_site'],16);got,slot,raw=exact(site)
                    assert row==dict(adrp_site=hex(site),BL_site=hex(site+8),helper_entry='0x6ff5ac',source_bytes=raw.hex(),RELATIVE_pointer_slot=hex(got),usage_cell=hex(slot))
                    assert site not in seen;seen.add(site);counts[slot]=counts.get(slot,0)+1
                    if firstcall is None:firstcall=row
            complete=set();starts=0
            # Alternate traversal starts at BL and examines preceding words, rather than ADRP.
            for start,size,file,flags in segments:
                if not flags&1:continue
                for call in range((start+3)//4*4+8,start+size-3,4):
                    starts+=1;word=u32(b,offset(call,4))
                    if word>>26!=37:continue
                    imm=word&0x3ffffff;imm-=0x4000000 if imm&0x2000000 else 0
                    if call+4*imm!=0x6ff5ac:continue
                    try:exact(call-8)
                    except (AssertionError,KeyError):continue
                    complete.add(call-8)
            assert seen==complete and all(roots[s]==counts.get(s,0) for s in roots)
            assert doc['structural_root_candidates']==len(roots) and doc['exact_init_call_sites']==len(seen)
            assert doc['candidates_with_exact_init_call']==len(counts)
            assert doc['writable_aligned_cells_scanned']==allcells and doc['registered_byval_CLASS18_encoded_cells_before_pointer_filter']==kind1valid
            assert doc['rejected_kind1_like_cells']==rejected and doc['executable_pattern_starts_scanned']==starts
            assert doc['unique_typedefs']==len({cell(s)[3] for s in roots})
            assert not doc['runtime_verified'] and not doc['baseline_modified']
            for old in json.loads(proof.read_text(encoding='utf8'))['roots']:
                s=int(old['slot'],16);assert s in roots and cell(s)[1]==old['type_index'] and cell(s)[3]==old['typedef_index']
            negatives=[]
            original_bits=int.from_bytes(bytes.fromhex(firstroot['native_type_bytes'])[8:12],'little')
            for label,flag in [('byref_flag_rejected',1<<30),('pinned_flag_rejected',1<<31)]:
                try:typeinfo(firstroot['type_index'],bits_override=original_bits|flag)
                except AssertionError:negatives.append(label)
                else:raise AssertionError('Flag mutation accepted '+label)
            for label,key,value in [('wrong_class_index','type_index',0),('wrong_typedef','typedef_index',999999),
                                     ('wrong_name','declared_name','Terraria.FalseMatch'),('wrong_encoded_word','encoded_word','0x40000001'),
                                     ('wrong_native_type_bytes','native_type_bytes','00'*12),('omitted_pointer_support','incoming_RELATIVE_relocations',[])]:
                bad=copy.deepcopy(firstroot);bad[key]=value
                try:checkroot(bad)
                except (AssertionError,ValueError,KeyError):negatives.append(label)
                else:raise AssertionError('Mutation accepted '+label)
            site=int(firstcall['adrp_site'],16);code=bytes.fromhex(firstcall['source_bytes'])
            for label,mutated in [('ADRP_wrong_register',(int.from_bytes(code[:4],'little')|1).to_bytes(4,'little')+code[4:]),
                                  ('LDR_wrong_base',code[:4]+(int.from_bytes(code[4:8],'little')|32).to_bytes(4,'little')+code[8:]),
                                  ('B_instead_of_BL',code[:8]+(int.from_bytes(code[8:12],'little')&0x7fffffff).to_bytes(4,'little'))]:
                try:exact(site,mutated)
                except (AssertionError,ValueError,KeyError):negatives.append(label)
                else:raise AssertionError('Opcode mutation accepted '+label)
    assert digest((OUT/'roots.jsonl').read_bytes())==doc['roots_jsonl_sha256']
    assert digest((OUT/'exact-init-calls.jsonl').read_bytes())==doc['exact_calls_jsonl_sha256']
    result=dict(integrity_passed=True,catalog_sha256=digest((OUT/'catalog.json').read_bytes()),
                evidence_sha256=digest((OUT/'catalog.json').read_bytes()),
                auditor_sha256=digest(Path(__file__).read_bytes()),producer_imported=False,
                independent_mmap_ELF_metadata_and_raw_A64_audit=True,complete_within_declared_scope=True,
                roots_verified=len(roots),exact_calls_verified=len(seen),roots_with_exact_calls=len(counts),
                structural_only_roots=len(roots)-len(counts),negative_controls_rejected=negatives,
                runtime_verified=False,limits=doc['limitations'])
    (OUT/'independent-audit.json').write_text(json.dumps(result,indent=2)+'\n')
    report=['# Ограниченный каталог class-usage roots','',
            f'Найдено {len(roots)} структурных кандидатов CLASS18 с совпадающим metadata byval index и входящей ELF RELATIVE relocation. У {len(counts)} есть точные последовательные ADRP x0 / LDR x0,[x0] / BL0x6ff5ac шаблоны: {len(seen)} encoded call-sites.',
            '',f'{len(roots)-len(counts)} записей имеют только структурную поддержку. Для них не доказано, что ячейка используется resolver. Входящий указатель и похожее encoded значение сами по себе не устанавливают назначение.',
            '', 'Каждый точный шаблон доказывает исходные инструкции и передаваемый через relocation адрес ячейки при обычной последовательности исполнения. Достижимость, runtime-выполнение и успешная публикация класса не доказаны. Подробные предпосылки унаследованы от исходно-байтовой модели static-field-roots и записаны в catalog.json.',
            '', f'Независимый аудитор повторно разобрал ELF64, RELA, нативную регистрацию и metadata31, проверил все строки и полноту в объявленных границах. Отклонено {len(negatives)} отрицательных проверок, включая явные byref/pinned flags. Ghidra и Capstone не использованы; исходные файлы читаются через mmap.',
            '', 'Каталог намеренно исключает другие type kinds, aliases/byref без совпадающего byval index, BSS-only/невыравненные ячейки и непоследовательные шаблоны. Структурные кандидаты не называются доказанными runtime class roots.',
            '', '[Охват, хеши и ограничения](catalog.json) · [Ячейки и metadata records](roots.jsonl) · [Точные исходные call-sites](exact-init-calls.jsonl) · [Независимый аудит](independent-audit.json)']
    (OUT/'REPORT.ru.md').write_text('\n'.join(report)+'\n',encoding='utf8')
    print(json.dumps({k:result[k] for k in ('integrity_passed','roots_verified','exact_calls_verified','structural_only_roots','negative_controls_rejected')}))

if __name__=='__main__':main()
