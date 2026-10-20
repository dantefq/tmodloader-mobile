"""Audit every raw SLEIGH instruction/operation against the original ARM64 ELF.

Completeness means all selected FDE slots plus proven islands were represented;
it does not establish reachability, SSA, complete semantic CFG, or original source.
"""
import argparse
import gzip
import hashlib
import json
import pathlib
import struct

from audit_terraria_hard_ir import Elf, address, require, sha, validate_pcode_nodes


PROFILE = "hard20-raw-sleigh-fde-plus-proven-islands-v1"
BASE = "bounded-fde-terminal-calls-signatures-v3"
ELF_SHA = "9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5"


def encoded_control(word, va):
    def signed(value, bits):
        return value - (1 << bits) if value & (1 << (bits - 1)) else value
    if word & 0xFC000000 == 0x14000000:
        return 4, va + signed(word & 0x3FFFFFF, 26) * 4
    if word & 0xFC000000 == 0x94000000:
        return 7, va + signed(word & 0x3FFFFFF, 26) * 4
    if word & 0xFF000010 == 0x54000000 or word & 0x7E000000 == 0x34000000:
        return 5, va + signed((word >> 5) & 0x7FFFF, 19) * 4
    if word & 0x7E000000 == 0x36000000:
        return 5, va + signed((word >> 5) & 0x3FFF, 14) * 4
    for pattern, opcode in ((0xD61F0000, 6), (0xD63F0000, 8), (0xD65F0000, 10)):
        if word & 0xFFFFFC1F == pattern:
            return opcode, None
    return None


def audit_function(root, row, expected_addresses, start, end, elf):
    file = (root / row["file"]).resolve()
    require(file.is_relative_to(root.resolve()) and file.is_file(), "Unconfined/missing raw IR file")
    require(file.stat().st_size == row["bytes"] and sha(file) == row["sha256"], "Compressed artifact size/SHA mismatch")
    instructions = operations = outside = computed = pseudo = encoded_controls = direct_targets = 0
    source = hashlib.sha256()
    listing_parts = []
    with gzip.open(file, "rb") as stream:
        for line in stream:
            require(line.endswith(b"\n"), "Incomplete decompressed JSONL line")
            item = json.loads(line)
            require(instructions < len(expected_addresses), "Unexpected extra instruction")
            va = address(item["address"])
            require(item["ordinal"] == instructions and va == expected_addresses[instructions], "Missing/reordered/duplicate instruction address")
            require(item["decode_complete"], f"Instruction decode incomplete at{va:#x}")
            raw = bytes.fromhex(item["raw_bytes"])
            require(len(raw) == 4 and raw == elf.instruction(va), f"Original ELF byte mismatch at{va:#x}")
            source.update(struct.pack("<Q", va))
            source.update(raw)
            is_outside = not start <= va < end
            require(item["outside_fde"] == is_outside, "Outside-FDE classification mismatch")
            outside += is_outside
            require(item["decode_source"] in ("existing_listing", "public_PseudoDisassembler_no_DB_write"), "Unknown decoder provenance")
            is_pseudo = item["decode_source"] == "public_PseudoDisassembler_no_DB_write"
            pseudo += is_pseudo
            recorded_override = item["flow_override_recorded_not_applied"]
            require(recorded_override in ("NONE", "BRANCH", "CALL", "CALL_RETURN", "RETURN"), "Unknown recorded override")
            listing_parts.append(f"{hex(va)}:{raw.hex()}:{'PSEUDO' if is_pseudo else recorded_override}\n".encode())
            for ordinal, op in enumerate(item["raw_pcode"]):
                require(op["ordinal"] == ordinal and isinstance(op["opcode"], int) and isinstance(op["mnemonic"], str) and isinstance(op["text"], str), "Malformed raw operation")
                require(address(op["sequence_address"]) == va and isinstance(op["sequence_time"], int), "Raw operation sequence location mismatch")
                validate_pcode_nodes(op, raw=True)
                operations += 1
                computed += op["opcode"] in (6, 8, 10)  # BRANCHIND, CALLIND, RETURN.
            control = encoded_control(int.from_bytes(raw, "little"), va)
            if control is not None:
                expected_opcode, target = control
                candidates = [op for op in item["raw_pcode"] if op["opcode"] == expected_opcode]
                require(candidates, f"Encoded ARM64 control flow missing raw P-code opcode{expected_opcode} at{va:#x}")
                if target is not None:
                    require(any(op["inputs"] and op["inputs"][0]["space"] == "ram" and address(op["inputs"][0]["offset"]) == target for op in candidates), f"Encoded direct branch/call target differs from raw P-code at{va:#x}")
                    direct_targets += 1
                encoded_controls += 1
            instructions += 1
    require(instructions == len(expected_addresses) == row["instructions"], "Instruction coverage count mismatch")
    require(row["fde_instructions"] == (end - start) // 4 and row["island_instructions"] == outside, "FDE/island instruction totals mismatch")
    require(operations == row["raw_pcode_operations"] and computed == row["unresolved_computed_control_operations"], "Raw/control operation totals mismatch")
    require(pseudo == row["pseudo_disassembled_instructions"] and row["decode_or_export_gaps"] == 0, "Decode/gap totals mismatch")
    require(source.hexdigest() == row["instruction_sequence_source_sha256"], "Source sequence fingerprint mismatch")
    return {"address": row["address"], "method": row["method"], "instructions": instructions,
            "verified_original_instruction_bytes": instructions * 4, "raw_pcode_operations": operations,
            "outside_fde_instructions": outside, "unresolved_computed_control_operations": computed,
            "independently_checked_control_instructions": encoded_controls, "verified_direct_control_targets": direct_targets,
            "pseudo_disassembled_instructions": pseudo, "integrity_passed": True}, listing_parts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab", required=True, type=pathlib.Path)
    parser.add_argument("--baseline", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    lab = args.lab.resolve()
    root = lab / "hard-functions-raw-ir"
    progress = json.loads((root / "progress.json").read_text())
    if not progress.get("finished"):
        print(json.dumps({"audit_started": False, "reason": "Raw producer pass not finished; no large artifacts read"}))
        raise SystemExit(2)
    baseline = args.baseline or lab / "coverage-v3-before-stack32.jsonl"
    output = args.output or root / "audit.json"
    report = {"profile": PROFILE, "integrity_passed": False, "functions": [], "errors": [],
              "semantic_correctness_proven": False, "complete_semantic_CFG_proven": False,
              "runtime_reachability_proven": False, "valid_C_proven": False, "original_source_recovered": False}
    elf = None
    try:
        scope = json.loads((root / "scope.json").read_text())
        require(scope["profile"] == PROFILE and not scope["native_decompiler_used"] and not scope["database_modified"], "Invalid producer scope")
        require(scope["baseline_sha256"] == sha(baseline) and scope["elf_sha256"] == ELF_SHA == sha(lab / "native/libil2cpp.so"), "Baseline/source identity mismatch")
        require(scope["program_executable_sha256"] in (None, "", ELF_SHA), "Imported program hash differs from original ELF")
        require(scope["language"] == "AARCH64:LE:64:v8A", "Wrong language")
        provider = hashlib.sha256()
        provider_files = scope["language_provider_files"]
        require(provider_files, "Missing SLEIGH provider manifest")
        names = []
        for item in provider_files:
            file = pathlib.Path(item["file"])
            require(file.is_file() and file.stat().st_size == item["bytes"] and sha(file) == item["sha256"], "SLEIGH provider file mismatch")
            names.append(file.name)
            provider.update(f"{file.name}\t{item['sha256']}\n".encode())
        # Producer uses Java WindowsPath.sorted(): comparisons uppercase each
        # character, including punctuation ordering. Python casefold order is
        # different for AARCH64base.sinc versus AARCH64_AMXext.sinc.
        require(names == sorted(names, key=str.upper) and len(set(names)) == len(names) and provider.hexdigest() == scope["language_provider_sha256"], "SLEIGH provider fingerprint mismatch")
        manifest_paths = {pathlib.Path(item["file"]).resolve() for item in provider_files}
        require(all(pathlib.Path(scope[key]).resolve() in manifest_paths for key in ("actual_sla_file", "actual_processor_spec", "language_definitions")), "Actual SLEIGH files absent from manifest")
        fdes = [tuple(int(x, 16) for x in line.split("\t")) for line in (lab / "native/unwind-function-ranges.tsv").read_text().splitlines()]
        require(len(fdes) == 123152 and all(a < b and a % 4 == b % 4 == 0 and (i == 0 or fdes[i - 1][1] <= a) for i, (a, b) in enumerate(fdes)), "Malformed FDE catalogue")
        ends = dict(fdes)
        targets, seen, total = {}, set(), 0
        with baseline.open(encoding="utf8") as stream:
            for line in stream:
                row = json.loads(line)
                va = address(row["address"])
                require(va not in seen and row["profile"] == BASE and row["image_base"] == 0 and address(row["compiler_end_exclusive"]) == ends[va], "Baseline row identity mismatch")
                seen.add(va)
                total += 1
                if row["status"] != "decompiled":
                    targets[va] = row
        require(total == 93990 and len(targets) == 20, "Expected20 failed targets in93990 baseline")
        review_path = lab / "native/flow-islands-hard20-review.json"
        flow_path = lab / "native/flow-islands.json"
        require(sha(review_path) == scope["flow_review_sha256"] and sha(flow_path) == scope["flow_islands_sha256"], "Island evidence identity mismatch")
        review = json.loads(review_path.read_text())
        require(review["baseline_sha256"] == scope["baseline_sha256"] and review["flow_islands_sha256"] == scope["flow_islands_sha256"], "Review source identity mismatch")
        extras = {va: set() for va in targets}
        associations = 0
        elf = Elf(lab / "native/libil2cpp.so")
        for row in json.loads(flow_path.read_text()):
            start = address(row["fde_start"])
            if start not in targets or not row["proven_encoded_path"]:
                continue
            require(row["returns_to_origin_plus_four"], "Unexpected island continuation")
            associations += 1
            for instruction in row["steps"]:
                va = address(instruction["address"])
                require(not any(a <= va < b for a, b in fdes), "Claimed external island is within an FDE")
                require(elf.instruction(va).hex() == instruction["raw_bytes"], "Island source bytes mismatch")
                extras[start].add(va)
        require(associations == review["out_and_back_associations"] and sum(map(len, extras.values())) == review["unique_extra_instructions"], "Island coverage counts mismatch")
        selected, current_targets = {}, set()
        context = ("baseline_sha256", "language_provider_sha256", "flow_islands_sha256", "flow_review_sha256", "listing_bytes_overrides_sha256")
        with (root / "results.jsonl").open(encoding="utf8") as stream:
            for line in stream:
                row = json.loads(line)
                va = address(row["address"])
                require(va in targets, "Unknown journal target")
                require(all(row[key] == targets[va][key] for key in ("address", "method", "image", "compiler_end_exclusive")), "Journal target mismatch")
                require(row["profile"] == PROFILE and not row["native_decompiler_used"] and not row["raw_pcode_includes_overrides"] and not row["valid_C"] and not row["database_modified"] and not row["high_function_or_SSA"], "Journal scope mismatch")
                if any(row[key] != scope[key] for key in context):
                    continue
                current_targets.add(va)
                require(row["status"] in ("raw_ir_complete", "raw_ir_incomplete"), "Unknown journal status")
                if row["status"] == "raw_ir_complete":
                    selected[va] = row
        require(current_targets == set(targets), "Finished raw pass lacks terminal records for all20 targets")
        require(progress["targets"] == 20 and progress["complete"] == len(selected) and progress["not_complete"] == 20 - len(selected) and progress["all_targets_complete"] == (len(selected) == 20), "Journal/progress counts mismatch")
        listing = hashlib.sha256()
        for start, target in targets.items():
            if start not in selected:
                continue
            expected = sorted(set(range(start, ends[start], 4)) | extras[start])
            try:
                checked, parts = audit_function(root, selected[start], expected, start, ends[start], elf)
                for part in parts:
                    listing.update(part)
                report["functions"].append(checked)
                print(json.dumps({"address": hex(start), "integrity_passed": True, "instructions": checked["instructions"]}), flush=True)
            except Exception as error:
                report["errors"].append({"address": hex(start), "error": str(error)})
        if len(selected) == 20 and not report["errors"]:
            require(listing.hexdigest() == scope["listing_bytes_overrides_sha256"], "All-target listing/source/override fingerprint mismatch")
        report.update({"targets": 20, "complete_raw_ir": len(selected), "incomplete_raw_ir": 20 - len(selected),
                       "all_targets_complete": len(selected) == 20, "baseline_sha256": scope["baseline_sha256"],
                       "elf_sha256": ELF_SHA, "language_provider_sha256": scope["language_provider_sha256"],
                       "native_decompiler_used": False, "out_and_back_associations": associations})
        report["integrity_passed"] = not report["errors"] and len(report["functions"]) == len(selected)
        report["verified_original_instruction_bytes"] = sum(row["verified_original_instruction_bytes"] for row in report["functions"])
        report["raw_pcode_operations"] = sum(row["raw_pcode_operations"] for row in report["functions"])
        report["scope"] = "Instruction-level completeness within selected FDEs plus explicitly proven external islands; byte/representation integrity only. No native whole-function decompilation, SSA, complete semantic CFG, original C# or runtime reachability proof."
    except Exception as error:
        report["errors"].append({"error": str(error)})
    finally:
        if elf is not None:
            elf.close()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf8")
    temporary.replace(output)
    print(json.dumps({"integrity_passed": report["integrity_passed"], "errors": report["errors"]}, ensure_ascii=False))
    raise SystemExit(0 if report["integrity_passed"] else 1)


if __name__ == "__main__":
    main()
