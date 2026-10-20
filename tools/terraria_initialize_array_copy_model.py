"""Conditional original-blob-to-array byte-copy model; cache construction remains a premise."""
import hashlib,json,mmap,struct
from pathlib import Path
LAB=Path('C:/Temp/terraria-re-20261012');OUT=LAB/'initialize-array-copy-model-20261015'
FROZEN='6fe84f649ecd9f9872106f4776b586a223a0593b6d19096dee9ca25264ca37fa'
def sha(x):return hashlib.sha256(x).hexdigest()
def sign(x,bits):return x-(1<<bits) if x&(1<<(bits-1)) else x

def main():
    sourcepath=LAB/'itemsets-array-literals-20261015/array-literals.json'
    assert sha(sourcepath.read_bytes())==FROZEN
    previous=json.loads(sourcepath.read_text(encoding='utf8'))
    auditpath=sourcepath.parent/'independent-audit.json';oldaudit=json.loads(auditpath.read_text())
    assert oldaudit['integrity_passed'] and oldaudit['evidence_sha256']==FROZEN
    with (LAB/'native/libil2cpp.so').open('rb') as f,(LAB/'native/global-metadata.dat').open('rb') as g:
      with mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as raw,mmap.mmap(g.fileno(),0,access=mmap.ACCESS_READ) as meta:
        assert sha(raw)==previous['elf_sha256'] and sha(meta)==previous['metadata_sha256']
        ph=struct.unpack_from('<Q',raw,32)[0];sz,n=struct.unpack_from('<HH',raw,54)
        loads=[struct.unpack_from('<II6Q',raw,ph+i*sz) for i in range(n)]
        def at(va,size=4):
            offsets=[p[2]+va-p[3] for p in loads if p[0]==1 and p[3]<=va and va+size<=p[3]+p[5]]
            assert len(offsets)==1;return offsets[0]
        def read(va,n):p=at(va,n);return raw[p:p+n]
        def word(va):return struct.unpack_from('<I',raw,at(va))[0]
        def branch(pc,kind,target):
            w=word(pc);assert w>>26==({'B':5,'BL':37}[kind])
            assert pc+sign(w&0x3ffffff,26)*4==target
        sh=struct.unpack_from('<Q',raw,40)[0];sz,n=struct.unpack_from('<HH',raw,58)
        sections=[struct.unpack_from('<IIQQQQIIQQ',raw,sh+i*sz) for i in range(n)]
        def plt(va,label):
            a,l,d,b=struct.unpack('<4I',read(va,16))
            assert a&0x9f00001f==0x90000010 and l&0xffc003ff==0xf9400211
            assert d&0xffc003ff==0x91000210 and b==0xd61f0220
            page=(va&~4095)+(sign(((a>>29)&3)|(((a>>5)&0x7ffff)<<2),21)<<12)
            slot=page+((l>>10)&4095)*8;assert page+((d>>10)&4095)==slot
            found=[]
            for s in sections:
                if s[1]!=4:continue
                for p in range(s[4],s[4]+s[5],s[9]):
                    address,info,add=struct.unpack_from('<QQq',raw,p)
                    if address!=slot:continue
                    assert info&0xffffffff==1026
                    syms=sections[s[6]];sp=syms[4]+(info>>32)*syms[9]
                    name,flags,other,defined,value,length=struct.unpack_from('<IBBHQQ',raw,sp)
                    strings=sections[syms[6]];start=strings[4]+name
                    text=raw[start:raw.find(b'\0',start,strings[4]+strings[5])].decode('ascii')
                    assert text==label and add==0
                    found.append(dict(entry=hex(va),raw_bytes=read(va,16).hex(),GOT_slot=hex(slot),
                                      relocation_file_offset=hex(p),relocation_bytes=raw[p:p+24].hex(),
                                      relocation_type=1026,dynsym_index=info>>32,symbol_record_offset=hex(sp),
                                      symbol_record_bytes=raw[sp:sp+24].hex(),symbol_name=text,
                                      symbol_defined=bool(defined),symbol_value=hex(value)))
            assert len(found)==1;return found[0]
        symbols=[plt(0x59ecd0,'bsearch'),plt(0x59f490,'memcpy')]
        checks={0x7143a4:0xb9410000,0x7143a8:0xd65f03c0,
                0x751b1c:0xb9400008,0x751b20:0xb9400029,0x751b24:0x4b090100,0x751b28:0xd65f03c0,
                0x6ab748:0xf9400016,0x6ab75c:0xf94022c8,0x6ab760:0x2a0003f5,
                0x6ab7b0:0xb9401a68,0x6ab7b8:0x1b087eb5,0x6ab7c0:0x91008268,0x6ab7c4:0xaa1503e2,
                0x6ab7d0:0xaa0003e1,0x6ab7d4:0xaa0803e0,
                0x74be54:0xf9400814,0x74be5c:0xf9404288,0x74be60:0xcb080008,0x74be68:0xd345fd16,
                0x74be80:0xf9403688,0x74be90:0xb9402108,0x74bea0:0x0b160108,
                0x74bea4:0xb90003e8,0x74bea8:0x69482528,0x74be98:0xb201f3eb,0x74be9c:0xf295556b,
                0x74bebc:0x9bcb7d28,0x74bec0:0xd343fd02,0x74bec4:0x52800183,
                0x74bef8:0xb9400808,0x74bf0c:0xb9804929,0x74bf10:0x8b090149,0x74bf14:0x8b080120}
        for pc,w in checks.items():assert word(pc)==w,hex(pc)
        edges=[(0x22bca9c,'B',0x6ab73c),(0x6ab758,'BL',0x7143a4),(0x6ab7bc,'BL',0x6e1fc8),
               (0x6e1fec,'BL',0x6ee4e4),(0x6ee4e4,'B',0x74be44),(0x74bec8,'BL',0x59ecd0),(0x6ab7dc,'B',0x59f490)]
        for edge in edges:branch(*edge)
        # Critical ADRP/LDR pairs address original metadata-header and metadata-base globals.
        globalpairs=[]
        for p,l,reg,expected in [(0x74be84,0x74be88,21,0x3214f18),(0x74be8c,0x74be94,20,0x3214f10)]:
            a=word(p);load=word(l);assert a&0x9f000000==0x90000000 and a&31==reg
            assert load&0xffc00000==0xf9400000 and load>>5&31==reg
            page=(p&~4095)+(sign(((a>>29)&3)|(((a>>5)&0x7ffff)<<2),21)<<12)
            assert page+((load>>10)&4095)*8==expected
            globalpairs.append(dict(ADRP_site=hex(p),LDR_site=hex(l),global_address=hex(expected)))
        do,ds=struct.unpack_from('<II',meta,64);bo,bs=struct.unpack_from('<II',meta,72)
        assert ds%12==0 and ds>0 and do+ds<=len(meta) and bo+bs<=len(meta)
        records=[struct.unpack_from('<iii',meta,p) for p in range(do,do+ds,12)]
        keys=[r[0] for r in records]
        assert all(0<=a<b for a,b in zip(keys,keys[1:])) and keys[-1]<1<<31
        # Exact native UMULH(magic)/LSR3 matches division by12 for the concrete original byte-size.
        count=((ds*0xaaaaaaaaaaaaaaab)>>64)>>3;assert count==ds//12==len(records)
        assert max(keys)-min(keys)<1<<31
        # Native bsearch comparator is signed subtraction; no overflow for these original keys/searches.
        bykey={r[0]:(i,r) for i,r in enumerate(records)};arrays=[]
        fieldso,fieldss=struct.unpack_from('<II',meta,96);typeo,types=struct.unpack_from('<II',meta,160)
        owneroff=typeo+3812*88;fieldstart=struct.unpack_from('<i',meta,owneroff+32)[0]
        for old in previous['arrays']:
            field=old['source_field_index'];index,record=bykey[field]
            p=do+index*12;assert hex(p)==old['field_default_record_offset']
            assert meta[p:p+12].hex()==old['field_default_record_bytes'] and record[2]==old['default_data_index']
            length=old['caller_allocation_count'];size=4*length
            assert size==old['literal_byte_length'] and size<1<<32 and 0<=record[2] and record[2]+size<=bs
            blob=meta[bo+record[2]:bo+record[2]+size]
            assert blob.hex()==old['blob_bytes'] and sha(blob)==old['blob_sha256']
            assert list(struct.unpack('<'+'i'*length,blob))==old['serialized_little_endian_Int32_values']
            # Model bsearch using the exact comparator and concrete source table.
            low,high=0,len(records);matched=None
            while low<high:
                middle=(low+high)//2;comparison=field-records[middle][0]
                assert -(1<<31)<=comparison<1<<31
                if comparison==0:matched=middle;break
                if comparison<0:high=middle
                else:low=middle+1
            assert matched==index
            local=field-fieldstart;assert local>=0
            arrays.append(dict(source_field_index=field,local_FieldInfo_index=local,
                               assumed_FieldInfo_relation='owner.fields + '+str(local)+' * 32',
                               metadata_default_record_index=index,metadata_default_record_offset=hex(p),
                               metadata_default_record_bytes=meta[p:p+12].hex(),data_index=record[2],
                               conditional_source_pointer='metadataBase + '+hex(bo)+' + '+hex(record[2]),
                               source_metadata_file_offset=hex(bo+record[2]),blob_bytes=blob.hex(),blob_sha256=sha(blob),
                               array_length=length,assumed_runtime_element_size=4,conditional_copy_bytes=size,
                               copied_little_endian_Int32_values=old['serialized_little_endian_Int32_values']))
        fragments=[]
        for label,start,end in [('managed_wrapper',0x22bca34,0x22bcaa0),('native_copy',0x6ab73c,0x6ab810),
                                ('field_data',0x6e1fc8,0x6e1ff8),('field_default_bridge',0x6ee4e4,0x6ee4e8),
                                ('field_default_lookup',0x74be44,0x74bf34),('default_comparator',0x751b1c,0x751b2c),
                                ('array_element_size_getter',0x7143a4,0x7143ac)]:
            data=read(start,end-start);fragments.append(dict(label=label,start=hex(start),end_exclusive=hex(end),raw_bytes=data.hex(),sha256=sha(data)))
        doc=dict(profile='conditional-InitializeArray-original-field-blob-copy-v1',elf_sha256=sha(raw),metadata_sha256=sha(meta),
                 producer_sha256=sha(Path(__file__).read_bytes()),dependencies={'itemsets-array-literals-20261015/array-literals.json':FROZEN,
                 'itemsets-array-literals-20261015/independent-audit.json':sha(auditpath.read_bytes())},
                 PLT_bindings=symbols,source_fragments=fragments,exact_instruction_checks=[dict(site=hex(p),word=hex(w)) for p,w in checks.items()],
                 direct_edges=[dict(site=hex(p),kind=k,target=hex(t)) for p,k,t in edges],metadata_global_address_pairs=globalpairs,
                 field_default_table=dict(offset=do,byte_size=ds,count=len(records),strictly_sorted_unique_field_indices=True,
                                          first_field_index=keys[0],last_field_index=keys[-1],comparator_signed_subtraction_no_overflow_for_original_keys=True,
                                          table_sha256=sha(meta[do:do+ds])),owner_typedef=3812,owner_metadata_record_offset=hex(owneroff),
                 owner_metadata_record_bytes=meta[owneroff:owneroff+88].hex(),owner_field_start=fieldstart,arrays=arrays,
                 literal_Int32_count=sum(r['array_length'] for r in arrays),conditional_copy_bytes=sum(r['conditional_copy_bytes'] for r in arrays),
                 checked_byte_facts=['PLT relocations bind symbols bsearch/memcpy; comparator loads and subtracts signed Int32 field indices.',
                                     'Original field-default table is sorted/unique, stride12; three field indices resolve to exact metadata blob records.',
                                     'Getter returns array-class field+0x100; copy path multiplies its low32 element size by low32 length at array+0x18, then passes array+0x20/blob/zero-extended product to memcpy.'],
                 semantic_contract_assumptions=['The bsearch and memcpy dynamic bindings honor the standard C semantic contracts; no interposition/GOT patch changes their behavior.',
                                                'bsearch uses the supplied comparator and sorted original table; memcpy copies exactly n bytes from valid nonoverlapping source/destination ranges.'],
                 runtime_layout_and_path_assumptions=['FieldHandle resolution yields a valid FieldInfo for each original field: owner pointer at+0x10, owner.fields at+0x80, FieldInfo stride32; the selected non-generic owner path keeps the original owner.',
                                                     'owner+0x68 points to the corresponding loaded metadata type record whose field_start is at+0x20; metadata globals+0x3214f18/+0x3214f10 retain original header/base.',
                                                     'The supplied array is valid, count equals the recorded caller count, runtime array-class element-size field+0x100 equals4; array length at+0x18 and data at+0x20 have the decoded layout.',
                                                     'Managed wrapper and native type/RVA guards take the shown successful copy path; helper calls return normally and preserve AAPCS64 callee-saved state. No conflicting concurrent writes, stack corruption, failed allocation or nonlocal reentry bypasses this path.',
                                                     'The source registration/fixup bootstrap has populated runtime class and FieldInfo caches consistently with the original metadata. This cache construction is assumed, not recovered here.'],
                 conclusions=['Under all listed assumptions, the exact three original blobs are copied into the corresponding supplied arrays:109 little-endian Int32 values,436bytes total.',
                              'This strengthens the blob-to-array association conditionally; it does not prove full SetFactory membership or observed runtime output.'],
                 missing_proofs=['Complete FieldInfo/class cache construction and actual class element_size value in runtime.',
                                 'Actual execution, global reachability, dynamic symbol binding, successful allocations and full wrapper error/exception behavior.'],
                 runtime_verified=False,full_set_membership_proven=False,baseline_modified=False,low_memory_mmap=True)
        OUT.mkdir(exist_ok=True);(OUT/'copy-model.json').write_text(json.dumps(doc,indent=2)+'\n')
        print(json.dumps(dict(default_records=len(records),arrays=len(arrays),literal_Int32_count=doc['literal_Int32_count'],conditional_copy_bytes=doc['conditional_copy_bytes'])))

if __name__=='__main__':main()
