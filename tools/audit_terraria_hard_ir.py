"""Independent structural/source-byte audit of complete firstpass IR exports.

Checks representation integrity, not semantics, source recovery, or runtime reachability.
Requires a finished producer pass before reading large artifacts.
"""
import argparse
import bisect
import collections
import hashlib
import json
import mmap
import pathlib
import sqlite3
import struct
import tempfile


PROFILE = "hard20-firstpass-complete-ir-v1-stack32"
BASE_PROFILE = "bounded-fde-terminal-calls-signatures-v3"
ELF_SHA = "9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5"
ARTIFACTS = {"pcode-operations.jsonl", "basic-blocks.jsonl", "control-flow-edges.jsonl", "instruction-addresses.jsonl"}
VALUE_PRODUCING_OPCODES = {1, 2} | set(range(11, 45)) | set(range(46, 75))


def validate_pcode_nodes(operation, raw=False):
    """Gson omits null outputs; only explicitly permitted opcode classes allow it.

    Raw CALL/CALLIND have no output. High-function versions may attach return
    storage. CALLOTHER user operations can have or omit output in either form.
    """
    opcode = operation["opcode"]
    nonproducing = {0, 3, 4, 5, 6, 10} | ({7, 8} if raw else set())
    optional = {9} | (set() if raw else {7, 8})
    require(opcode in VALUE_PRODUCING_OPCODES | nonproducing | optional, "Unknown/reserved P-code opcode")
    output = operation.get("output")
    if opcode in VALUE_PRODUCING_OPCODES:
        require(isinstance(output, dict), f"Missing required output for value-producing opcode{opcode}")
    elif opcode in nonproducing:
        require(output is None, f"Unexpected output for nonproducing opcode{opcode}")
    require(isinstance(operation["inputs"], list), "Malformed P-code inputs")
    require(all(isinstance(node, dict) for node in operation["inputs"]), "Missing/null input varnode")
    nodes = operation["inputs"] + ([output] if output is not None else [])
    for node in nodes:
        require(isinstance(node["space"], str) and isinstance(node["size"], int) and node["size"] >= 0, "Malformed varnode")
        address(node["offset"])


def require(condition, message):
    if not condition:
        raise ValueError(message)


def address(value):
    return int(str(value).split(":")[-1], 16)


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


class Elf:
    def __init__(self, path):
        self.file = path.open("rb")
        self.raw = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_READ)
        require(self.raw[:6] == b"\x7fELF\x02\x01", "ELF64 LE required")
        require(struct.unpack_from("<H", self.raw, 18)[0] == 183, "ARM64 required")
        offset = struct.unpack_from("<Q", self.raw, 32)[0]
        size, count = struct.unpack_from("<HH", self.raw, 54)
        require(size >= 56 and offset + size * count <= len(self.raw), "Invalid program header bounds")
        self.loads = []
        for index in range(count):
            kind, flags, off, va, _, filesz, memsz, align = struct.unpack_from("<IIQQQQQQ", self.raw, offset + index * size)
            if kind == 1:
                require(off + filesz <= len(self.raw) and filesz <= memsz, "Invalid LOAD bounds")
                self.loads.append((va, va + filesz, off, flags))

    def instruction(self, va):
        matches = [(start, off) for start, end, off, flags in self.loads if start <= va and va + 4 <= end and flags & 1]
        require(len(matches) == 1, f"VA{va:#x} is not uniquely file-backed executable LOAD")
        start, off = matches[0]
        return self.raw[off + va - start:off + va - start + 4]

    def close(self):
        self.raw.close()
        self.file.close()


def artifact_path(root, item):
    path = (root / item["file"]).resolve()
    require(path.is_relative_to(root.resolve()) and path.is_file(), f"Unconfined/missing artifact:{path}")
    return path


def rows(root, item):
    path = artifact_path(root, item)
    require(path.stat().st_size == item["bytes"], f"Size mismatch:{path}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for ordinal, line in enumerate(stream, 1):
            digest.update(line)
            require(line.endswith(b"\n"), f"Incomplete JSONL line:{path}:{ordinal}")
            yield json.loads(line)
    require(digest.hexdigest() == item["sha256"], f"SHA mismatch:{path}")


def audit_function(root, record, elf, ranges, starts):
    start, end = address(record["address"]), address(record["compiler_end_exclusive"])
    manifest = record["artifacts"]
    require(len(manifest) == 4, "Expected four full IR artifacts")
    artifacts = {pathlib.PurePosixPath(item["file"]).name: item for item in manifest}
    require(set(artifacts) == ARTIFACTS, "Unexpected/duplicate artifact names")
    blocks = {}
    for row in rows(root, artifacts["basic-blocks.jsonl"]):
        index = row["index"]
        require(isinstance(index, int) and index not in blocks, "Duplicate/invalid block index")
        require(address(row["start"]) <= address(row["stop_inclusive"]), f"Reversed block extent:{index}")
        require(row["incoming_count"] == len(row["incoming"]) and row["outgoing_count"] == len(row["outgoing"]), "Block degree mismatch")
        blocks[index] = row
    require(len(blocks) == record["basic_blocks"], "Block count mismatch")
    require(blocks, "Hard method returned no basic blocks")
    expected_edges = collections.Counter()
    incoming_edges = collections.Counter()
    for index, block in blocks.items():
        for slot, target in enumerate(block["outgoing"]):
            require(target in blocks, "Edge references unknown target block")
            expected_edges[index, target, slot] += 1
        for source in block["incoming"]:
            require(source in blocks, "Unknown incoming block")
            incoming_edges[source, index] += 1
    outgoing_pairs = collections.Counter()
    for (source, target, _), count in expected_edges.items():
        outgoing_pairs[source, target] += count
    require(outgoing_pairs == incoming_edges, "Incoming/outgoing block edges disagree")
    actual_edges = collections.Counter((r["source"], r["target"], r["outgoing_slot"]) for r in rows(root, artifacts["control-flow-edges.jsonl"]))
    require(actual_edges == expected_edges and sum(actual_edges.values()) == record["control_flow_edges"], "Explicit edge artifact mismatch")

    instructions = set()
    outside, other_fde, outside_union = [], [], []
    instruction_spaces = set()
    for row in rows(root, artifacts["instruction-addresses.jsonl"]):
        va = address(row["address"])
        key = row["space"], va
        require(key not in instructions and va % 4 == 0, "Duplicate/unaligned captured instruction")
        instructions.add(key)
        instruction_spaces.add(row["space"])
        is_outside = not start <= va < end
        require(row["outside_fde"] == is_outside, "Captured outside-FDE flag mismatch")
        require("byte_read_error" not in row and "program_memory_bytes" in row, "Unreadable captured source bytes")
        captured = bytes.fromhex(row["program_memory_bytes"])
        require(len(captured) == 4 and captured == elf.instruction(va), f"Original ELF byte mismatch at{va:#x}")
        if is_outside:
            outside.append(va)
            index = bisect.bisect_right(starts, va) - 1
            if index >= 0 and va < ranges[index][1]:
                other_fde.append({"address": hex(va), "containing_fde": hex(ranges[index][0])})
            else:
                outside_union.append(va)
    require(len(instructions) == record["unique_instruction_addresses"], "Unique source-address count mismatch")
    require(len(outside) == record["unique_instruction_addresses_outside_fde"], "Outside source-address count mismatch")
    require(record["unreadable_instruction_addresses"] == 0, "Producer reported unreadable bytes")
    operations = outside_ops = duplicates = orphan_operations = 0
    observed_addresses, nonmemory_spaces = set(), collections.Counter()
    with tempfile.TemporaryDirectory(prefix=".audit-sequences-", dir=root) as temporary:
        database = sqlite3.connect(str(pathlib.Path(temporary) / "sequences.sqlite"))
        database.execute("PRAGMA journal_mode=OFF")
        database.execute("PRAGMA synchronous=OFF")
        database.execute("PRAGMA cache_size=-8192")
        database.execute("CREATE TABLE sequences(space TEXT,address TEXT,time INTEGER,PRIMARY KEY(space,address,time)) WITHOUT ROWID")
        pending = []
        for row in rows(root, artifacts["pcode-operations.jsonl"]):
            require(row["ordinal"] == operations, "P-code ordinals not contiguous")
            require(isinstance(row["opcode"], int) and isinstance(row["mnemonic"], str) and isinstance(row["text"], str) and isinstance(row["inputs"], list), "Malformed P-code operation")
            validate_pcode_nodes(row, raw=False)
            operations += 1
            space, va = row["address_space"], address(row["instruction_address"])
            block_index = row["block_index"]
            if block_index == -1:
                orphan_operations += 1
            else:
                require(block_index in blocks, "P-code references unknown block")
                block = blocks[block_index]
                require(address(block["start"]) <= va <= address(block["stop_inclusive"]), f"P-code address outside declared block:{va:#x}/{block_index}")
            if space in instruction_spaces:
                observed_addresses.add((space, va))
                require((space, va) in instructions, "P-code instruction address absent from source-byte artifact")
                is_outside = not start <= va < end
            else:
                nonmemory_spaces[space] += 1
                is_outside = True
            require(row["outside_fde"] == is_outside, "P-code outside-FDE flag mismatch")
            outside_ops += is_outside
            require(isinstance(row["sequence_time"], int), "Invalid P-code sequence time")
            pending.append((space, hex(va), row["sequence_time"]))
            if len(pending) >= 4096:
                before = database.total_changes
                database.executemany("INSERT OR IGNORE INTO sequences VALUES(?,?,?)", pending)
                duplicates += len(pending) - (database.total_changes - before)
                pending.clear()
        if pending:
            before = database.total_changes
            database.executemany("INSERT OR IGNORE INTO sequences VALUES(?,?,?)", pending)
            duplicates += len(pending) - (database.total_changes - before)
        database.close()
    require(operations == record["pcode_operations"] and outside_ops == record["pcode_operations_outside_fde"], "P-code operation totals mismatch")
    require(operations > 0 and instructions, "Hard method returned empty IR")
    require(observed_addresses == instructions, "Captured instruction set differs from P-code targets")
    require(record["all_returned_pcode_operations_saved"] and record["all_returned_basic_blocks_saved"] and not record["pcode_sample_truncated"], "Producer did not claim full returned tree")
    return {"address": record["address"], "method": record["method"], "pcode_operations": operations,
            "basic_blocks": len(blocks), "control_flow_edges": sum(actual_edges.values()), "verified_instruction_bytes": len(instructions) * 4,
            "outside_fde_operations": outside_ops, "outside_fde_instruction_addresses": len(outside),
            "outside_entire_fde_union_instruction_addresses": len(outside_union), "addresses_inside_other_fdes": other_fde,
            "outside_fde_addresses": [hex(va) for va in outside], "duplicate_sequence_keys": duplicates,
            "operations_without_parent_block": orphan_operations, "nonmemory_sequence_spaces": dict(nonmemory_spaces),
            "duplicate_sequence_is_semantic_error_proven": False, "integrity_passed": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab", type=pathlib.Path, required=True)
    parser.add_argument("--baseline", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    lab = args.lab.resolve()
    root = lab / "hard-functions-ir"
    progress = json.loads((root / "progress.json").read_text())
    if not progress.get("finished"):
        print(json.dumps({"audit_started": False, "reason": "Producer pass not finished; no large artifacts read"}))
        raise SystemExit(2)
    baseline = args.baseline or lab / "coverage-v3-before-stack32.jsonl"
    destination = args.output or root / "audit.json"
    report = {"profile": PROFILE, "producer_pass_finished": True, "integrity_passed": False,
              "semantic_correctness_proven": False, "runtime_reachability_proven": False,
              "original_source_recovered": False, "valid_C_proven": False, "functions": [], "errors": []}
    elf = None
    try:
        scope = json.loads((root / "scope.json").read_text())
        require(scope["profile"] == PROFILE and scope["baseline_sha256"] == sha(baseline), "Scope/baseline SHA mismatch")
        require(scope["elf_sha256"] == ELF_SHA == sha(lab / "native/libil2cpp.so"), "ELF identity mismatch")
        require(scope["actual_engine_sha256"] == sha(pathlib.Path(scope["actual_engine_path"])), "Selected engine SHA mismatch")
        require(scope["model_fingerprint_sha256"] == sha(root / "model.json"), "Model fingerprint mismatch")
        fde_path = lab / "native/unwind-function-ranges.tsv"
        if "fde_catalogue_sha256" in scope:
            require(scope["fde_catalogue_sha256"] == sha(fde_path), "FDE catalogue SHA mismatch")
        ranges = [tuple(int(x, 16) for x in line.split("\t")) for line in fde_path.read_text().splitlines()]
        require(len(ranges) == 123152 and all(a < b and a % 4 == b % 4 == 0 and (i == 0 or ranges[i - 1][1] <= a) for i, (a, b) in enumerate(ranges)), "Invalid FDE catalogue")
        starts = [a for a, _ in ranges]
        ends = dict(ranges)
        targets, seen, count = {}, set(), 0
        with baseline.open(encoding="utf8") as stream:
            for line in stream:
                row = json.loads(line)
                va = address(row["address"])
                require(va not in seen and row["profile"] == BASE_PROFILE and row["image_base"] == 0 and ends[va] == address(row["compiler_end_exclusive"]), "Invalid baseline identity")
                seen.add(va)
                count += 1
                if row["status"] != "decompiled":
                    targets[va] = row
        require(count == 93990 and len(targets) == 20, "Expected baseline93990 with20 failures")
        selected, journal_rows, stale_rows, current_context_targets = {}, 0, 0, set()
        with (root / "results.jsonl").open(encoding="utf8") as stream:
            for line in stream:
                row = json.loads(line)
                journal_rows += 1
                va = address(row["address"])
                require(va in targets, "Journal target absent from20 failures")
                for key in ("address", "method", "image", "compiler_end_exclusive"):
                    require(row[key] == targets[va][key], "Journal target identity mismatch")
                require(row["profile"] == PROFILE and row["elf_sha256"] == ELF_SHA and not row["valid_C"] and not row["database_modified"], "Journal scope mismatch")
                if any(row[key] != scope[key] for key in ("baseline_sha256", "actual_engine_sha256", "model_fingerprint_sha256")):
                    stale_rows += 1
                    continue
                current_context_targets.add(va)
                if row["status"] == "ir_complete":
                    selected[va] = row
                else:
                    require(row["status"] == "ir_incomplete", "Unknown journal status")
        require(progress["targets"] == 20 and progress["complete_ir"] == len(selected) and progress["not_complete"] == 20 - len(selected), "Journal/progress totals mismatch")
        require(current_context_targets == set(targets), "Finished pass lacks terminal records for all20 targets")
        require(progress["failed_this_run"] == 20 - len(selected) and 0 <= progress["failed_this_run"] <= progress["attempted_this_run"] <= 20, "Finished-pass attempted/failed counters disagree")
        if "all_targets_complete" in progress:
            require(progress["all_targets_complete"] == (len(selected) == 20), "all_targets_complete mismatch")
        report.update({"journal_rows": journal_rows, "stale_context_rows": stale_rows, "targets": 20,
                       "complete_ir": len(selected), "incomplete_ir": 20 - len(selected), "all_targets_complete": len(selected) == 20,
                       "baseline_sha256": scope["baseline_sha256"], "elf_sha256": ELF_SHA,
                       "actual_engine_sha256": scope["actual_engine_sha256"], "model_fingerprint_sha256": scope["model_fingerprint_sha256"]})
        elf = Elf(lab / "native/libil2cpp.so")
        for va, record in selected.items():
            try:
                checked = audit_function(root, record, elf, ranges, starts)
                report["functions"].append(checked)
                print(json.dumps({"address": hex(va), "integrity_passed": True, "operations": checked["pcode_operations"]}), flush=True)
            except Exception as error:
                report["errors"].append({"address": hex(va), "error": str(error)})
        report["integrity_passed"] = not report["errors"] and len(report["functions"]) == len(selected)
        report["verified_instruction_bytes"] = sum(row["verified_instruction_bytes"] for row in report["functions"])
        report["pcode_operations"] = sum(row["pcode_operations"] for row in report["functions"])
        report["scope"] = "Integrity of complete returned firstpass IR; incomplete methods remain incomplete. Duplicate sequence keys are reported, not assumed errors. Cross-FDE source addresses are explicitly reported, not silently classified as islands."
    except Exception as error:
        report["errors"].append({"error": str(error)})
    finally:
        if elf is not None:
            elf.close()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf8")
    temporary.replace(destination)
    print(json.dumps({key: report[key] for key in ("integrity_passed", "errors")}, ensure_ascii=False))
    raise SystemExit(0 if report["integrity_passed"] else 1)


if __name__ == "__main__":
    main()
