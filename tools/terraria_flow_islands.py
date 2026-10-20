"""Find bounded direct out-and-back ARM64 islands from original ELF bytes; no DB changes.

Only a conservative whitelist of non-control instructions is traversed. A successful
result proves the encoded branch path, not runtime reachability or complete CFG coverage.
"""
import argparse
import bisect
import collections
import hashlib
import json
import pathlib
import struct


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def branch(word, address):
    if word & 0xFC000000 == 0x14000000:
        return "b", address + signed(word & 0x3FFFFFF, 26) * 4
    if word & 0xFF000010 == 0x54000000:
        return "b.cond", address + signed((word >> 5) & 0x7FFFF, 19) * 4
    if word & 0x7E000000 == 0x34000000:
        return "cbnz" if word & 0x1000000 else "cbz", address + signed((word >> 5) & 0x7FFFF, 19) * 4
    if word & 0x7E000000 == 0x36000000:
        return "tbnz" if word & 0x1000000 else "tbz", address + signed((word >> 5) & 0x3FFF, 14) * 4
    return None


def safe_nonflow(word):
    # Integer/scalar FP/SIMD unsigned-immediate loads/stores. Reserved encodings
    # are not treated as arbitrary ordinary instructions by a broad opcode mask.
    forms = {
        0xF9400000: ("ldr", "x", 8), 0xF9000000: ("str", "x", 8),
        0xB9400000: ("ldr", "w", 4), 0xB9000000: ("str", "w", 4),
        0x39400000: ("ldrb", "w", 1), 0x39000000: ("strb", "w", 1),
        0x79400000: ("ldrh", "w", 2), 0x79000000: ("strh", "w", 2),
        0xBD400000: ("ldr", "s", 4), 0xBD000000: ("str", "s", 4),
        0xFD400000: ("ldr", "d", 8), 0xFD000000: ("str", "d", 8),
        0x3DC00000: ("ldr", "q", 16), 0x3D800000: ("str", "q", 16),
    }
    form = forms.get(word & 0xFFC00000)
    if form:
        mnemonic, register, scale = form
        base = (word >> 5) & 31
        return f"{mnemonic} {register}{word & 31},[{'sp' if base == 31 else 'x'+str(base)},#{((word >> 10) & 4095)*scale}]"
    if word == 0xD503201F:
        return "nop"
    return None


class Elf:
    def __init__(self, path):
        self.raw = path.read_bytes()
        if self.raw[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", self.raw, 18)[0] != 183:
            raise ValueError("Requires ELF64 little-endian ARM64")
        offset = struct.unpack_from("<Q", self.raw, 32)[0]
        size, count = struct.unpack_from("<HH", self.raw, 54)
        if size < 56 or offset + size * count > len(self.raw):
            raise ValueError("Malformed program headers")
        self.segments = []
        for i in range(count):
            kind, flags, off, va, _, file_size, _, _ = struct.unpack_from("<IIQQQQQQ", self.raw, offset+i*size)
            if kind == 1:
                if off+file_size > len(self.raw):
                    raise ValueError("Segment file bounds invalid")
                self.segments.append((va, va+file_size, off, flags))

    def at(self, address):
        for start, end, offset, flags in self.segments:
            if start <= address and address+4 <= end and flags & 1:
                return offset+address-start
        raise ValueError("Address outside executable file-backed PT_LOAD")

    def word(self, address):
        return struct.unpack_from("<I", self.raw, self.at(address))[0]


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--lab", type=pathlib.Path, required=True)
    ap.add_argument("--max-steps", type=int, default=64)
    ap.add_argument("--notes", type=pathlib.Path, default=pathlib.Path("notes/terraria-flow-islands-20261013.md"))
    args=ap.parse_args()
    if not 1 <= args.max_steps <= 64:
        ap.error("max-steps must be1..64")
    native=args.lab/"native"; elf=Elf(native/"libil2cpp.so")
    ranges=[tuple(int(x,16) for x in line.split("\t")) for line in (native/"unwind-function-ranges.tsv").read_text().splitlines() if line]
    if len(ranges)!=123152 or any(a%4 or b%4 or a>=b or (i and a<ranges[i-1][1]) for i,(a,b) in enumerate(ranges)):
        raise ValueError("Unexpected or malformed verified FDE catalogue")
    starts=[a for a,_ in ranges]
    def inside(address):
        index=bisect.bisect_right(starts,address)-1
        return index>=0 and address<ranges[index][1]
    references=collections.defaultdict(list)
    for name,kind in [("method-addresses.json","direct"),("generic-method-addresses.json","generic")]:
        for row in json.loads((native/name).read_text()):
            if row.get("address"):
                references[int(row["address"],16)].append({"kind":kind,"method_index":row["method_index"],"image":row["image"],"method":row["type"]+"::"+row["name"]})

    candidates=[]; proven=[]; failures=collections.Counter(); scanned=0; direct=0; computed=0
    for fde_start,fde_end in ranges:
        offset=elf.at(fde_start)
        # ARM64 instructions have fixed4byte size. Resolve each FDE VA using PT_LOAD,
        # rather than silently assuming the ELF virtual address equals file offset.
        if elf.at(fde_end-4)!=offset+fde_end-fde_start-4:
            raise ValueError("FDE crosses noncontiguous executable segments")
        for origin in range(fde_start,fde_end,4):
            scanned+=1;word=struct.unpack_from("<I",elf.raw,offset+origin-fde_start)[0]
            decoded=branch(word,origin)
            if not decoded:
                if word & 0xFFFFFC1F == 0xD61F0000:
                    computed+=1
                continue
            direct+=1;mnemonic,target=decoded
            if inside(target):
                continue
            row={"fde_start":hex(fde_start),"fde_end_exclusive":hex(fde_end),"origin":hex(origin),"origin_raw_bytes":struct.pack("<I",word).hex(),
                 "origin_branch":mnemonic,"target":hex(target),"runtime_reachability_proven":False,"steps":[]}
            visited=set();pc=target;reason="step_limit";success=False
            for step in range(args.max_steps):
                if pc%4:
                    reason="unaligned_target";break
                if pc in visited:
                    reason="cycle";break
                if inside(pc):
                    reason="unexpected_entry_into_fde";break
                visited.add(pc)
                try:
                    instruction=elf.word(pc)
                except ValueError:
                    reason="outside_executable_file_bytes";break
                raw=struct.pack("<I",instruction).hex();flow=branch(instruction,pc)
                item={"address":hex(pc),"raw_bytes":raw}
                if flow:
                    item["instruction"]=flow[0]+" "+hex(flow[1]);row["steps"].append(item)
                    if flow[0]!="b":
                        reason="conditional_path_not_expanded";break
                    if fde_start<=flow[1]<fde_end:
                        row["return_target"]=hex(flow[1]);row["returns_to_origin_plus_four"]=flow[1]==origin+4
                        success=True;reason="structurally_verified_out_and_back";break
                    if inside(flow[1]):
                        reason="branch_to_other_fde";break
                    pc=flow[1];continue
                if instruction & 0xFC000000 == 0x94000000 or instruction & 0xFFFFFC1F in (0xD61F0000,0xD63F0000,0xD65F0000):
                    item["instruction"]="call_or_indirect_branch_or_return";row["steps"].append(item);reason=item["instruction"];break
                plain=safe_nonflow(instruction)
                if plain is None:
                    item["instruction"]="unclassified_opcode";row["steps"].append(item);reason="unclassified_opcode";break
                item["instruction"]=plain;row["steps"].append(item);pc+=4
            row["classification"]=reason;row["proven_encoded_path"]=success;candidates.append(row)
            if success:
                row["associated_methods"]=references.get(fde_start,[]);proven.append(row)
            else:
                failures[reason]+=1
    unique_instruction_addresses={int(s["address"],16) for row in proven for s in row["steps"]}
    by_fde=collections.defaultdict(list)
    for row in proven:
        by_fde[row["fde_start"]].append(row)
    extensions=[]
    for start,associations in by_fde.items():
        extra=sorted({int(s["address"],16) for row in associations for s in row["steps"]})
        runs=[]
        for address in extra:
            if runs and address==runs[-1][1]:runs[-1][1]+=4
            else:runs.append([address,address+4])
        extensions.append({"fde_start":start,"fde_end_exclusive":associations[0]["fde_end_exclusive"],"associated_methods":references.get(int(start,16),[]),
            "additional_ranges":[{"start":hex(a),"end_exclusive":hex(b)} for a,b in runs],"additional_bytes":len(extra)*4,
            "body_candidate_only":True,"database_modified":False})
    summary={"schema_version":1,"elf_sha256":hashlib.sha256(elf.raw).hexdigest(),"fde_count":len(ranges),"fde_bytes":sum(b-a for a,b in ranges),
        "scanned_aligned_slots":scanned,"decoded_direct_branch_slots":direct,"computed_br_slots_not_resolved":computed,
        "branches_targeting_outside_fde_union":len(candidates),"structurally_verified_out_and_back_associations":len(proven),
        "associations_returning_to_origin_plus_four":sum(r["returns_to_origin_plus_four"] for r in proven),"unique_extra_instructions":len(unique_instruction_addresses),
        "unique_extra_bytes":len(unique_instruction_addresses)*4,"extended_fde_candidates":len(extensions),"unresolved_classifications":dict(failures),
        "max_follow_steps":args.max_steps,"runtime_reachability_proven":False,"complete_semantic_cfg_proven":False,"database_modified":False,
        "limitation":"Only direct branch destinations outside all FDEs are followed, using a conservative load/store/NOP whitelist; computed tables and calls are not expanded."}
    for name,value in [("flow-islands.json",candidates),("flow-islands-summary.json",summary),("flow-island-body-candidates.json",extensions)]:
        (native/name).write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding="utf8")
    evidence=[]
    for r in proven:
        if r["fde_start"]=="0x1423370":
            evidence.append("|"+r["origin"]+"|"+r["target"]+"|"+"; ".join(s["instruction"] for s in r["steps"])+"|"+r["return_target"]+"|")
    note=f'''# Внешние блоки ARM64 и границы покрытия FDE

Сканировались исходные байты ELF SHA-256 `{summary['elf_sha256']}`, все{len(ranges)} проверенные FDE. Нативные процессы и базы Ghidra не запускались и не изменялись. Наличие FDE подтверждает диапазон unwind-информации, но не утверждает, что весь выполняемый код функции находится исключительно внутри него.

Найдено{len(candidates)} прямых переходов с целями вне объединения FDE. Для{len(proven)} ассоциаций консервативный обход подтвердил закодированный путь из узнаваемых load/store/NOP и безусловных переходов обратно в исходный FDE; {summary['associations_returning_to_origin_plus_four']} возвращаются ровно к origin+4. Это добавляет{len(unique_instruction_addresses)*4} уникальных байт вне FDE и затрагивает{len(extensions)} диапазонов. Эти числа описывают структуру машинного кода, а не доказанную runtime-достижимость всех источников перехода.

Доказательства: [все пути/неразрешённые кандидаты](C:/Temp/terraria-re-20261012/native/flow-islands.json), [итоги](C:/Temp/terraria-re-20261012/native/flow-islands-summary.json), [дополнительные диапазоны кандидатов тел](C:/Temp/terraria-re-20261012/native/flow-island-body-candidates.json). Последний файл — предложение объединить исходный FDE с маленькими внешними диапазонами; автоматическое изменение Function.body не выполнялось. JSON каждого пути содержит оригинальные байты источника и каждой внешней инструкции.

## Projectile.AI: три внешних load-and-return блока

| Исходный B | Внешний блок | Декодированный путь | Возврат |
|---|---|---|---|
'''+"\n".join(evidence)+'''

Эти блоки продолжают исходную функцию после загрузки значения. Пометка исходного перехода CALL_RETURN уничтожила бы корректное продолжение, поэтому ограничивать их таким образом нельзя. Прежний v3-tailcall-pass помечал только переходы к точному началу другого FDE и эти островки не изменял.

Форма8-байтного блока load/store→B назад, а также ADRP на offset0xff8/0xffc исходной страницы, совпадает с механизмом исправления Cortex-A53 erratum843419, описанным в [официальном LLVM AArch64ErrataFix.cpp](https://llvm.googlesource.com/llvm-project/lld/+/refs/heads/main/ELF/AArch64ErrataFix.cpp). Это обоснованная гипотеза происхождения островков: конкретный linker build flag/версия по этим данным не доказаны.

## Ограничения

Обход ограничен64 инструкциями и узнаваемыми unsigned-immediate load/store и NOP; на условном ветвлении внутри островка, неизвестном opcode, вызове, косвенном переходе или RET он останавливается. Цель исходного условного перехода может быть проверена, но достижимость этой ветки не устанавливается. Косвенные таблицы переходов не разрешаются. Инструкции внутри FDE могут включать недостижимые байты; поэтому структурно распознанный переход не равен доказательству выполнения. Статистика остаётся нижней границей найденных внешних участков, а не полным CFG.

Практический вывод: отчёт о полном покрытии инструкций **внутри FDE** следует сохранять именно с таким ограничением. Для исследования крупных функций нужно учитывать связанные внешние островки; их наличие само по себе не объясняет таймаут и не позволяет удалить эти инструкции ради ускорения.
'''
    args.notes.parent.mkdir(parents=True,exist_ok=True);args.notes.write_text(note,encoding="utf8")
    print(json.dumps(summary))


if __name__=="__main__":
    main()
