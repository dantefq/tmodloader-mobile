"""Source-bound direct-call inventory; encoded sites are not execution counts."""
import collections,hashlib,json,pathlib,sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from terraria_flow_islands import Elf
sys.path.insert(0,'C:/Temp/terraria-re-20261012/python-analysis')
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
LAB=pathlib.Path('C:/Temp/terraria-re-20261012')
def sha(data):return hashlib.sha256(data).hexdigest()
def main():
    elf=Elf(LAB/'native/libil2cpp.so');assert sha(elf.raw)=='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
    metadata=LAB/'metadata/methods.jsonl';names=collections.defaultdict(list)
    for line in metadata.open(encoding='utf8'):
        r=json.loads(line)
        if r.get('native_address'):names[int(r['native_address'],16)].append({'index':r['index'],'signature':r['display_signature']})
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;results=[]
    for start,end in ((0x947404,0x960f98),(0x11242ec,0x1140194)):
        data=b''.join(elf.word(a).to_bytes(4,'little') for a in range(start,end,4));raw_calls=[]
        for address in range(start,end,4):
            word=elf.word(address)
            if word&0xfc000000!=0x94000000:continue
            delta=word&0x3ffffff
            if delta&0x2000000:delta-=0x4000000
            raw_calls.append((address,address+delta*4))
        instructions=list(cs.disasm(data,start));assert len(instructions)*4==len(data)
        decoded=[(i.address,i.operands[0].imm) for i in instructions if i.mnemonic=='bl'];assert decoded==raw_calls
        rows=[{'site':hex(a),'target':hex(t),'raw_bytes':elf.word(a).to_bytes(4,'little').hex(),'metadata_aliases':names.get(t,[])} for a,t in raw_calls]
        tally=collections.Counter(row['metadata_aliases'][0]['signature'] if row['metadata_aliases'] else row['target'] for row in rows)
        results.append({'address':hex(start),'end_exclusive':hex(end),'method_aliases':names[start],'FDE_bytes_sha256':sha(data),'FDE_bytes':len(data),'direct_BL_sites':len(rows),'named_BL_sites':sum(bool(r['metadata_aliases']) for r in rows),'target_site_counts':dict(tally.most_common()),'calls':rows})
    out=LAB/'selected-call-catalog-20261015';out.mkdir(exist_ok=True)
    doc={'elf_sha256':sha(elf.raw),'metadata_catalog_sha256':sha(metadata.read_bytes()),'producer_sha256':sha(pathlib.Path(__file__).read_bytes()),'ELF_helper_sha256':sha(pathlib.Path(__file__).with_name('terraria_flow_islands.py').read_bytes()),'raw_BL_vs_capstone_passed':True,'methods':results,'limits':['Exact FDE scopes only; no detached continuation or indirect-call inventory.','Metadata labels are catalog associations; signatures/ABI/argument meanings not independently reconstructed here.','Counts are encoded static BL sites, not observed frequency or feasible/reachable paths.'],'runtime_verified':False}
    word=elf.word(0x6ff688);assert word==0x17ff88db
    delta=word&0x3ffffff;delta=delta-0x4000000 if delta&0x2000000 else delta
    assert 0x6ff688+4*delta==0x6e19f4
    doc['direct_forwarder_observation']={'entry':'0x6ff688','raw_bytes':word.to_bytes(4,'little').hex(),'unconditional_B_target':'0x6e19f4','ProcessData_BL_sites_to_entry':sum(r['target']=='0x6ff688' for r in results[1]['calls']),'semantic_role_established':False}
    (out/'calls.json').write_text(json.dumps(doc,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    lines=['# Каталог прямых вызовов двух оставшихся методов','', 'Все BL декодированы из исходных ARM64-слов и сопоставлены с Capstone. Имена взяты из ранее восстановленного каталога metadata; это статические сайты, не частоты исполнения.','']
    for r in results:
        lines.extend(['## '+r['method_aliases'][0]['signature'],'',f"FDE {r['address']} — {r['end_exclusive']}; прямых BL {r['direct_BL_sites']}, именованных {r['named_BL_sites']}.",'','| Цель | Статических сайтов |','|---|---:|'])
        lines.extend(f'| `{name}` | {count} |' for name,count in list(r['target_site_counts'].items())[:25]);lines.append('')
    lines.extend(['В ProcessData 1 416 из 3 049 прямых BL направлены на общий entry 0x6ff688. Его единственная проверенная инструкция `db88ff17` — B на 0x6e19f4. Роль конечного помощника здесь не установлена; это не 1 416 отдельных игровых операций.','', '[Все адреса, байты и SHA](calls.json). Косвенные вызовы, внешние продолжения, достижимость и ABI этим каталогом не восстановлены.'])
    (out/'REPORT.ru.md').write_text('\n'.join(lines)+'\n',encoding='utf8')
    print(json.dumps([{'address':r['address'],'BL':r['direct_BL_sites'],'named':r['named_BL_sites']} for r in results]))
if __name__=='__main__':main()
