"""Source-bound conditional normal-flow model; no decompiler/database changes."""
import copy
import hashlib
import json
from pathlib import Path
import struct

LAB = Path('C:/Temp/terraria-re-20261012')
SHA = '9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
BOUNDS = {0x6ff6ac:0x6ff6b4, 0x741278:0x74128c, 0x74128c:0x74129c,
          0x74129c:0x7412c4, 0x7411e0:0x741208}
# Exact decoded ordinary instructions: no control-flow broad-mask assumptions.
ORDINARY = {
    0xf81f0ffe:'str x30,[sp,#-16]!', 0xd10083ff:'sub sp,sp,#32',
    0xa900fbff:'stp xzr,x30,[sp,#8]', 0x910003e0:'add x0,sp,#0',
    0xf90003ff:'str xzr,[sp]', 0xaa1f03e1:'orr x1,xzr,xzr',
    0xa9bf7bf3:'stp x19,x30,[sp,#-16]!', 0xaa0003f3:'orr x19,xzr,x0',
    0xd00117a1:'adrp x1,0x2a37000', 0x90011782:'adrp x2,0x2a31000',
    0x91207821:'add x1,x1,#0x81e', 0x91200042:'add x2,x2,#0x800',
    0xaa1303e3:'orr x3,xzr,x19', 0xa8c17bf3:'ldp x19,x30,[sp],#16',
    0x52800100:'movz w0,#8', 0xf00140c1:'adrp x1,0x2f5c000',
    0x910de021:'add x1,x1,#0x378', 0xaa1f03e2:'orr x2,xzr,xzr',
    0xf9000013:'str x19,[x0]',
}

def sha(data): return hashlib.sha256(data).hexdigest()
def sign(n,bits): return n-(1<<bits) if n & (1<<(bits-1)) else n

class ELF:
    def __init__(self, raw):
        self.raw = raw
        assert raw[:7] == b'\x7fELF\x02\x01\x01' and self.u('<H',18)[0] == 183
        ph = self.u('<Q',32)[0]; size,count = self.u('<HH',54)
        self.loads = [self.u('<IIQQQQQQ',ph+i*size) for i in range(count)]
        sh = self.u('<Q',40)[0]; size,count = self.u('<HH',58)
        self.sections = [self.u('<IIQQQQIIQQ',sh+i*size) for i in range(count)]
    def u(self,fmt,off): return struct.unpack_from(fmt,self.raw,off)
    def at(self,va,size=4,executable=False):
        candidates=[p[2]+va-p[3] for p in self.loads if p[0]==1 and p[3]<=va and va+size<=p[3]+p[5] and (not executable or p[1]&1)]
        assert len(candidates)==1
        return candidates[0]
    def word(self,va): return self.u('<I',self.at(va,4,True))[0]
    def bytes(self,va,size): return self.raw[self.at(va,size):self.at(va,size)+size]
    def relocation(self,slot):
        found=[]
        for sec in self.sections:
            if sec[1]!=4: continue
            assert sec[9]==24
            for off in range(sec[4],sec[4]+sec[5],24):
                address,info,addend=self.u('<QQq',off)
                if address != slot: continue
                symbol_sec=self.sections[sec[6]]; index=info>>32
                symoff=symbol_sec[4]+index*symbol_sec[9]
                name,flags,other,defined,value,length=self.u('<IBBHQQ',symoff)
                strings=self.sections[symbol_sec[6]]
                textoff=strings[4]+name
                label=self.raw[textoff:self.raw.index(b'\0',textoff,strings[4]+strings[5])].decode('ascii')
                found.append(dict(slot=hex(slot), relocation_file_offset=hex(off),
                                  relocation_bytes=self.raw[off:off+24].hex(), type=info&0xffffffff,
                                  dynsym_index=index, symbol_record_bytes=self.raw[symoff:symoff+24].hex(),
                                  symbol_name=label,symbol_defined=bool(defined), symbol_value=hex(value),
                                  addend=addend))
        assert len(found)==1
        return found[0]

def direct(word,pc):
    opcode=word>>26
    if opcode not in (5,37): return None
    return ('B' if opcode==5 else 'BL',pc+4*sign(word&0x3ffffff,26))

def analyze(words, assumed_noreturn):
    result={}; proven=set(assumed_noreturn)
    # Least fixed point. Unknown calls may return only to site+4 on normal completion.
    for iteration in range(len(BOUNDS)+1):
        changed=False
        for start,end in BOUNDS.items():
            pc=start; nodes=[]; terminal=None
            while pc<end:
                word=words[pc]; edge=direct(word,pc)
                if edge:
                    kind,target=edge
                    nodes.append(dict(site=hex(pc),kind=kind,target=hex(target),
                                      normal_continuation=None if target in proven or kind=='B' else hex(pc+4)))
                    if target in proven:
                        terminal=dict(kind='call_to_assumed_or_derived_noreturn',site=hex(pc),target=hex(target)); break
                    if kind=='B':
                        terminal=dict(kind='unknown_tail_transfer_may_return',site=hex(pc),target=hex(target)); break
                else:
                    assert word in ORDINARY, f'Unsupported instruction {pc:x}:{word:08x}'
                    nodes.append(dict(site=hex(pc),kind='ordinary',decoded=ORDINARY[word],normal_continuation=hex(pc+4)))
                pc+=4
            if terminal is None:
                terminal=dict(kind='unblocked_FDE_end_fallthrough',target=hex(end))
            no_return=terminal['kind']=='call_to_assumed_or_derived_noreturn'
            result[start]=dict(entry=hex(start),end_exclusive=hex(end),normal_flow_nodes=nodes,
                               terminal=terminal,conditional_no_normal_return=no_return)
            if no_return and start not in proven:
                proven.add(start);changed=True
        if not changed:break
    return result, proven-set(assumed_noreturn)

def plt(elf,entry):
    # Fixed AArch64 PLT form ADRP x16; LDR x17,[x16,#imm]; ADD x16,x16,#imm; BR x17.
    w0,w1,w2,w3=struct.unpack('<4I',elf.bytes(entry,16))
    assert w0&0x9f00001f==0x90000010 and w1&0xffc003ff==0xf9400211
    assert w2&0xffc003ff==0x91000210 and w3==0xd61f0220
    immediate=((w0>>5)&0x7ffff)<<2 | ((w0>>29)&3)
    page=(entry&~4095)+sign(immediate,21)*4096
    got=page+((w1>>10)&4095)*8
    assert page+((w2>>10)&4095)==got
    record=elf.relocation(got)
    assert record['type']==1026 and record['symbol_name']=='__cxa_throw'
    assert record['symbol_defined'] and record['symbol_value']=='0x7b276c' and record['addend']==0
    return dict(entry=hex(entry),raw_bytes=elf.bytes(entry,16).hex(),**record)

def main():
    raw=(LAB/'native/libil2cpp.so').read_bytes();assert sha(raw)==SHA
    elf=ELF(raw)
    ranges={int(x.split('\t')[0],16):int(x.split('\t')[1],16) for x in (LAB/'native/unwind-function-ranges.tsv').read_text().splitlines()}
    priorpath=LAB/'native-continuation-20261014/nullguard-exception-chain.json'
    prior=json.loads(priorpath.read_text());assert prior['elf_sha256']==SHA
    words={pc:elf.word(pc) for start,end in BOUNDS.items() for pc in range(start,end,4)}
    source=[]
    for start,end in BOUNDS.items():
        assert ranges[start]==end
        old=next(r for r in prior['functions'] if int(r['start'],16)==start)
        code=elf.bytes(start,end-start)
        assert old['source_sha256']==sha(code)
        for row in old['instructions']:
            assert elf.bytes(int(row['address'],16),4).hex()==row['bytes']
        source.append(dict(entry=hex(start),end_exclusive=hex(end),raw_bytes=code.hex(),sha256=sha(code)))
    relocation=plt(elf,0x59fe50)
    baseline,_=analyze(words,set())
    model,candidates=analyze(words,{0x59fe50})
    expected={0x6ff6ac,0x741278,0x74128c,0x7411e0}
    assert candidates==expected
    assert not any(r['conditional_no_normal_return'] for r in baseline.values())
    assert not model[0x74129c]['conditional_no_normal_return']
    controls=[]
    # Mutating each decisive call must destroy the upstream conclusion.
    for site,target,affected in [(0x741204,0x59ec50,0x7411e0),(0x741298,0x74129c,0x74128c),
                                 (0x741288,0x74129c,0x741278),(0x6ff6b0,0x74129c,0x6ff6ac)]:
        altered=copy.deepcopy(words); altered[site]=0x94000000|(((target-site)//4)&0x3ffffff)
        mutated,_=analyze(altered,{0x59fe50})
        assert not mutated[affected]['conditional_no_normal_return']
        controls.append(f'retarget_decisive_BL_{site:x}')
    altered=copy.deepcopy(words);altered[0x7411fc]=0xd65f03c0
    try: analyze(altered,{0x59fe50})
    except AssertionError: controls.append('injected_RET_rejected_by_ordinary_whitelist')
    else: raise AssertionError('Injected RET accepted')
    out=LAB/'nullguard-noreturn-model-20261015';out.mkdir(exist_ok=True)
    assumptions=[
        'The __cxa_throw relocation/PLT resolves to an implementation honoring the Itanium C++ ABI no-normal-return contract; symbol interposition, GOT rewriting, hooks or modified code do not violate it.',
        'BL uses ordinary AArch64 call semantics: normal completion resumes at site+4, with no corrupted return address, fabricated normal return, stack pivot or asynchronous control-flow rewriting.',
        'Non-control instructions either complete normally or leave normal flow; no trap/signal handler changes PC to bypass the decisive call.',
        'Exceptional unwinding, longjmp, cancellation and other nonlocal transfers do not reenter these wrapper bodies at a continuation/landing pad that later returns normally. LSDA/personality reentry is excluded by model assumption, not proved absent.',
        'Unknown ordinary callees, including factory0x74129c and its tail target0x741bcc, may return normally to their call continuation or transfer nonlocally; their values, prototypes and termination are not required or inferred.',
        'Analysis starts at the listed FDE entries and follows ordinary control flow. Alternate interior entries and runtime reachability are outside scope.'
    ]
    doc=dict(profile='conditional-nullguard-no-normal-return-v1',integrity_passed=True,elf_sha256=SHA,
             auditor_sha256=sha(Path(__file__).read_bytes()),prior_evidence_sha256=sha(priorpath.read_bytes()),
             FDE_ranges_sha256=sha((LAB/'native/unwind-function-ranges.tsv').read_bytes()),
             verified_source_bytes=sum(end-start for start,end in BOUNDS.items()),source_functions=source,
             independently_decoded_throw_PLT=relocation,assumed_contract_entry='0x59fe50',
             conditional_noreturn_candidate_entries=[hex(x) for x in sorted(candidates)],
             conditional_noreturn_entry_points=[hex(x) for x in sorted(candidates)],
             inputproof_sha256={'native/libil2cpp.so':SHA,
                                'native/unwind-function-ranges.tsv':sha((LAB/'native/unwind-function-ranges.tsv').read_bytes()),
                                'native-continuation-20261014/nullguard-exception-chain.json':sha(priorpath.read_bytes())},
             excluded_factory_entry='0x74129c',normal_flow_model=list(model.values()),
             without_noreturn_contract=list(baseline.values()),assumptions=assumptions,
             ABI_primary_source={'url':'https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html#cxx-throw',
                                 'section':'2.4.3','verified_date':'2026-10-15',
                                 'paraphrase':'__cxa_throw does not return; an unwind failure results in termination.'},
             negative_controls_passed=controls,annotations_applied=False,runtime_verified=False,
             limitations=['Only normal return is ruled out under assumptions, not exceptions, termination or nonlocal exits.',
                          'Factory74129c is deliberately not classified noreturn.',
                          'No Ghidra annotation, original report or original unknown category is modified.',
                          'FDE-end fallthrough is not silently discarded: it remains reachable without the contract and is blocked by a proved downstream no-normal-return call with the contract.'])
    (out/'evidence.json').write_text(json.dumps(doc,indent=2)+'\n')
    report=['# Условная модель отсутствия нормального возврата nullguard','',
            'По исходным ARM64 инструкциям установлена последовательность вызовов: `6ff6ac → 741278 → 74128c → 7411e0 → PLT(__cxa_throw)`.',
            'Для четырёх wrapper-entry нет нормального RET/fallthrough пути при перечисленных предпосылках. PLT и R_AARCH64_JUMP_SLOT независимо связаны с символом `__cxa_throw`.',
            '', 'Контракт взят из [Itanium C++ ABI §2.4.3](https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html#cxx-throw): вызов не возвращается нормально; ошибка раскрутки приводит к завершению.',
            '', '`0x74129c` — вызываемая фабрика; она не помечается noreturn, поскольку её tail-B на `0x741bcc` может вернуть управление в `0x741294`.',
            '', 'Это альтернативная условная модель для анализа. Динамическое связывание и выполнение не проверены. Исключительные/nonlocal переходы с повторным входом в wrapper исключены предпосылкой; отсутствие landing pads по LSDA отдельно не доказано. Аннотации Ghidra не применены.',
            '', '[Байты, CFG, предпосылки, базовая модель без контракта и отрицательные проверки](evidence.json).']
    (out/'REPORT.ru.md').write_text('\n'.join(report)+'\n',encoding='utf8')
    print(json.dumps(dict(candidates=doc['conditional_noreturn_candidate_entries'],bytes_checked=doc['verified_source_bytes'],negative_controls=len(controls))))

if __name__=='__main__': main()
