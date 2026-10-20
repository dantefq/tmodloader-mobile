"""Bounded mmap catalogue of registered CLASS18 usage-cell candidates and exact call sites."""
import hashlib,json,mmap,struct
from pathlib import Path
LAB=Path('C:/Temp/terraria-re-20261012')
OUT=LAB/'class-usage-root-catalog-20261015'
ELFSHA='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
METASHA='4c904c49d168913d28ef547c4f461e539d926d2ed27c0253ed53a2954e9585f7'
ROOTSHA='22f6f7fd1eba05ae5c284adcc4adb856296122133ff5050d8e9a553459ef02e3'
def sha(b):return hashlib.sha256(b).hexdigest()
def signed(n,b):return n-(1<<b) if n&(1<<(b-1)) else n

def main():
    OUT.mkdir(exist_ok=True)
    proof=LAB/'static-field-roots-20261015/static-field-roots.json'
    assert sha(proof.read_bytes())==ROOTSHA
    previous=json.loads(proof.read_text(encoding='utf8'))
    oldaudit=json.loads((proof.parent/'independent-audit.json').read_text())
    assert oldaudit['integrity_passed'] and oldaudit['evidence_sha256']==ROOTSHA
    with (LAB/'native/libil2cpp.so').open('rb') as ef,(LAB/'native/global-metadata.dat').open('rb') as mf:
        with mmap.mmap(ef.fileno(),0,access=mmap.ACCESS_READ) as raw,mmap.mmap(mf.fileno(),0,access=mmap.ACCESS_READ) as meta:
            assert sha(raw)==ELFSHA and sha(meta)==METASHA
            assert struct.unpack_from('<II',meta)==(0xfab11baf,31)
            ph=struct.unpack_from('<Q',raw,32)[0];stride,count=struct.unpack_from('<HH',raw,54)
            segs=[struct.unpack_from('<IIQQQQQQ',raw,ph+i*stride) for i in range(count)]
            loads=[p for p in segs if p[0]==1]
            def at(va,n=8):
                places=[p[2]+va-p[3] for p in loads if p[3]<=va and va+n<=p[3]+p[5]]
                assert len(places)==1
                return places[0]
            def q(va):return struct.unpack_from('<Q',raw,at(va))[0]
            sh=struct.unpack_from('<Q',raw,40)[0];stride,count=struct.unpack_from('<HH',raw,58)
            sections=[struct.unpack_from('<IIQQQQIIQQ',raw,sh+i*stride) for i in range(count)]
            def relative_records():
                for s in sections:
                    if s[1]!=4:continue
                    assert s[9]==24
                    for p in range(s[4],s[4]+s[5],24):
                        slot,info,add=struct.unpack_from('<QQq',raw,p)
                        if info==1027:yield slot,add,p
            registration=0x2fdb588;table=0x2ff5128;typecount=23420
            assert q(registration+0x30)==typecount
            rel={slot:(value,off) for slot,value,off in relative_records()
                 if table<=slot<table+typecount*8 or slot in (0x306f9c0,registration+0x38)}
            assert rel[0x306f9c0][0]==registration and rel[registration+0x38][0]==table
            typeoff,typesize=struct.unpack_from('<II',meta,160)
            stroff,strsize=struct.unpack_from('<II',meta,24)
            assert typesize%88==0 and typeoff+typesize<=len(meta) and stroff+strsize<=len(meta)
            def text(i):
                assert 0<=i<strsize
                p=stroff+i;return meta[p:meta.find(b'\0',p,stroff+strsize)].decode('utf8')
            def native(index):
                assert 0<=index<typecount
                ptr=rel[table+index*8][0];p=at(ptr,12)
                definition,bits=struct.unpack_from('<QI',raw,p)
                assert bits>>16&255==18 and definition<typesize//88 and not bits&0xc0000000
                return ptr,definition,bits
            def typename(definition,seen=()):
                assert definition not in seen and len(seen)<32
                p=typeoff+88*definition
                name,namespace,byval,parent=struct.unpack_from('<IIii',meta,p)
                if parent>=0:
                    _,pd,_=native(parent)
                    return typename(pd,seen+(definition,))+'+'+text(name)
                ns=text(namespace);return (ns+'.' if ns else '')+text(name)
            roots={};scanned=0;rejected=0
            for s in loads:
                if not s[1]&2:continue
                start=(s[3]+7)&~7
                for slot in range(start,s[3]+s[5]-7,8):
                    scanned+=1;encoded=q(slot)
                    if not (encoded<1<<32 and encoded&1 and encoded>>29==1):continue
                    index=(encoded>>1)&0xfffffff
                    try:
                        ptr,definition,bits=native(index)
                        p=typeoff+definition*88
                        name,namespace,byval=struct.unpack_from('<IIi',meta,p)
                        # Deliberately excludes attribute aliases/byref entries not the declared byval index.
                        assert byval==index
                        label=typename(definition)
                    except (AssertionError,KeyError,ValueError):
                        rejected+=1;continue
                    roots[slot]=dict(slot=hex(slot),initial_bytes=raw[at(slot):at(slot)+8].hex(),
                                     encoded_word=hex(encoded),usage_kind=1,type_index=index,
                                     native_type_pointer=hex(ptr),native_type_bytes=raw[at(ptr,12):at(ptr,12)+12].hex(),
                                     typedef_index=definition,metadata_record_file_offset=hex(p),
                                     metadata_record_bytes=meta[p:p+88].hex(),declared_name=label,
                                     incoming_RELATIVE_relocations=[],exact_init_call_count=0)
            incoming={}
            for slot,value,off in relative_records():
                if value in roots:
                    row=dict(slot=hex(slot),addend=hex(value),file_offset=hex(off),raw_bytes=raw[off:off+24].hex())
                    roots[value]['incoming_RELATIVE_relocations'].append(row)
                    incoming[slot]=value
            calls=0;scannedinstructions=0
            with (OUT/'exact-init-calls.jsonl').open('w',encoding='utf8') as stream:
                for s in loads:
                    if not s[1]&1:continue
                    for pc in range((s[3]+3)&~3,s[3]+s[5]-11,4):
                        scannedinstructions+=1;p=at(pc,12)
                        a,l,b=struct.unpack_from('<III',raw,p)
                        if a&0x9f00001f!=0x90000000 or l&0xffc003ff!=0xf9400000 or b>>26!=37:continue
                        if pc+8+signed(b&0x3ffffff,26)*4!=0x6ff5ac:continue
                        page=(pc&~4095)+(signed(((a>>29)&3)|(((a>>5)&0x7ffff)<<2),21)<<12)
                        got=page+((l>>10)&4095)*8
                        if got not in incoming:continue
                        slot=incoming[got];roots[slot]['exact_init_call_count']+=1;calls+=1
                        stream.write(json.dumps(dict(adrp_site=hex(pc),BL_site=hex(pc+8),helper_entry='0x6ff5ac',
                                                     source_bytes=raw[p:p+12].hex(),RELATIVE_pointer_slot=hex(got),
                                                     usage_cell=hex(slot)))+'\n')
            # Keep structural roots only when supported by an incoming RELATIVE pointer or exact init call.
            selected=[r for r in roots.values() if r['incoming_RELATIVE_relocations'] or r['exact_init_call_count']]
            selected.sort(key=lambda r:int(r['slot'],16))
            with (OUT/'roots.jsonl').open('w',encoding='utf8') as stream:
                for r in selected:stream.write(json.dumps(r,ensure_ascii=False)+'\n')
            called=sum(bool(r['exact_init_call_count']) for r in selected)
            doc=dict(profile='bounded-registered-CLASS18-usage-roots-v1',elf_sha256=ELFSHA,metadata_sha256=METASHA,
                     parent_model_sha256=ROOTSHA,producer_sha256=sha(Path(__file__).read_bytes()),
                     dependencies={'static-field-roots-20261015/static-field-roots.json':ROOTSHA},
                     registered_types_count=typecount,metadata_typedef_count=typesize//88,
                     scan_scope='Eight-byte-aligned file-backed cells in writable PT_LOAD segments; executable PT_LOAD exact three-instruction patterns.',
                     writable_aligned_cells_scanned=scanned,executable_pattern_starts_scanned=scannedinstructions,
                     registered_byval_CLASS18_encoded_cells_before_pointer_filter=len(roots),rejected_kind1_like_cells=rejected,
                     structural_root_candidates=len(selected),candidates_with_exact_init_call=called,
                     exact_init_call_sites=calls,unique_typedefs=len({r['typedef_index'] for r in selected}),
                     roots_jsonl_sha256=sha((OUT/'roots.jsonl').read_bytes()),
                     exact_calls_jsonl_sha256=sha((OUT/'exact-init-calls.jsonl').read_bytes()),
                     conditions=previous['conditions'][:2]+[
                         'For each exact call, metadata usage kind1 resolution follows the source-decoded case, resolves the per-row registered type index and publishes the corresponding class in that row\'s usage cell; source execution of this publication is not observed.',
                         'At an exact call site the three consecutive instructions execute in order, the RELATIVE GOT pointer retains its initial relocated target, and the usage cell has not been replaced or resolved inconsistently.',
                         'The original source-bound kind1 resolver/fixup model is applicable; standard relocation and ordinary call semantics hold.'],
                     limitations=['RELATIVE pointers alone establish structural candidates, not proven metadata usage or runtime class roots; encoded-looking data may be incidental.',
                                  'Exact pattern records prove encoded call sites conditionally supplying the cell address; they do not prove execution, reachability, successful class publication or complete wrapper ABI.',
                                  'Only CLASS18 records with a matching metadata byval registration index and clear native byref/pinned flag bits30/31 are admitted. Other kinds, aliases, byref/pinned records, unaligned cells, BSS-only data and nonconsecutive instruction patterns are excluded.',
                                  'No unrestricted scan may turn a bit pattern or incoming relocation into a semantic proof. Original unknown categories and existing evidence remain unchanged.'],
                     runtime_verified=False,baseline_modified=False)
            (OUT/'catalog.json').write_text(json.dumps(doc,indent=2)+'\n')
            print(json.dumps({k:doc[k] for k in ('structural_root_candidates','candidates_with_exact_init_call','exact_init_call_sites','unique_typedefs','rejected_kind1_like_cells')}))

if __name__=='__main__':main()
