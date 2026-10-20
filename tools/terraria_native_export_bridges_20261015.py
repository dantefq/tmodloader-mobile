"""Named IL2CPP export entry -> unconditional direct-B chains, not semantic recovery."""
import hashlib,json,pathlib,struct,sys
from terraria_native_map import ELF
sys.path.insert(0,'C:/Temp/terraria-re-20261012/python-analysis')
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
LAB=pathlib.Path('C:/Temp/terraria-re-20261012')
def sha(data):return hashlib.sha256(data).hexdigest()
def target(word,address):
    if word&0xfc000000!=0x14000000:return None
    displacement=word&0x3ffffff
    if displacement&0x2000000:displacement-=0x4000000
    return address+4*displacement
def main():
    raw=(LAB/'native/libil2cpp.so').read_bytes();assert sha(raw)=='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
    elf=ELF(raw);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    classification=LAB/'native/unmapped-fde-classification.json';unknown={int(r['address'],16) for r in json.loads(classification.read_text()) if r['category']=='unknown'}
    exports=[s for s in elf.symbols if s['defined'] and s['type']==2 and s['binding'] in (1,2) and s['name'].startswith('il2cpp_')]
    records=[];covered=set();proof=set()
    for symbol in exports:
        address=int(symbol['address'],16);chain=[];visited=set()
        while address not in visited and len(chain)<8:
            visited.add(address);offset=elf.file_offset(address);word=struct.unpack_from('<I',raw,offset)[0];destination=target(word,address)
            if destination is None:break
            assert elf.executable(destination)
            ins=next(cs.disasm(raw[offset:offset+4],address));assert ins.mnemonic=='b' and ins.operands[0].imm==destination
            chain.append({'address':hex(address),'raw_bytes':raw[offset:offset+4].hex(),'target':hex(destination)});proof.add(address);address=destination
        if chain:
            members=sorted({int(step['target'],16) for step in chain}&unknown)
            covered.update(members)
            records.append({'symbol':symbol,'direct_B_chain':chain,'final_observed_target':hex(address),'original_unknown_FDE_entries_on_chain':[hex(a) for a in members],'stopped_before_non_B_or_after_bound':True})
    # Negative encodings: BL, B.cond and BR must never be treated as direct B.
    assert target(0x14000002,0x100)==0x108 and target(0x17ffffff,0x100)==0xfc
    assert all(target(w,0x100) is None for w in (0x94000000,0x54000000,0xd61f0100,0xd65f03c0))
    classinit=next(r for r in records if r['symbol']['name']=='il2cpp_runtime_class_init')
    assert classinit['final_observed_target']=='0x6e19f4'
    thunk_offset=elf.file_offset(0x6ff688);thunk=struct.unpack_from('<I',raw,thunk_offset)[0]
    assert target(thunk,0x6ff688)==0x6e19f4
    out=LAB/'native-export-bridges-20261015';out.mkdir(exist_ok=True)
    doc={'profile':'IL2CPP-export-direct-B-bridges-v1','elf_sha256':sha(raw),'producer_sha256':sha(pathlib.Path(__file__).read_bytes()),'ELF_parser_sha256':sha(pathlib.Path(__file__).with_name('terraria_native_map.py').read_bytes()),'classification_sha256':sha(classification.read_bytes()),'defined_IL2CPP_function_exports_scanned':len(exports),'exports_with_direct_B_chains':len(records),'unique_branch_bytes_checked':len(proof)*4,'original_unknown_FDE_entries_linked':[hex(a) for a in sorted(covered)],'records':records,'class_init_shared_target_observation':{'named_export_entry':classinit['symbol']['address'],'helper_entry':'0x6ff688','helper_raw_bytes':raw[thunk_offset:thunk_offset+4].hex(),'shared_target':'0x6e19f4'},'negative_controls_passed':4,'positive_displacement_controls_passed':2,'limits':['Source symbol labels and encoded direct transfers only; final target semantic implementation and ABI are not proven.','Stops at first non-B instruction or eight-hop bound; no analysis of full wrapper bodies, indirect dispatch or runtime execution.','Does not change original unknown categories or assert newly recovered full purposes.'],'runtime_verified':False}
    (out/'bridges.json').write_text(json.dumps(doc,indent=2)+'\n')
    lines=['# Связи нативных помощников с именованными IL2CPP exports','',f"Проверено {len(exports)} именованных экспортов; у {len(records)} найдены цепочки прямых безусловных B. На этих цепочках {len(covered)} исходных неизвестных FDE-entry имеют связь с именованным API. Это источник дополнительной маркировки, не число полностью установленных назначений.",'','Export `il2cpp_runtime_class_init` и часто вызываемый helper 0x6ff688 передают управление на общий адрес 0x6e19f4. Связь подтверждена исходными инструкциями. Реализация общего адреса, полный ABI и выполнение в игре этим не доказаны.','', '[Цепочки, исходные байты, имена символов и ограничения](bridges.json). Прежние категории неизвестных диапазонов сохранены.']
    (out/'REPORT.ru.md').write_text('\n'.join(lines)+'\n',encoding='utf8')
    print(json.dumps({'exports':len(exports),'bridges':len(records),'unknown_entries_linked':len(covered),'bytes_checked':len(proof)*4}))
if __name__=='__main__':main()
