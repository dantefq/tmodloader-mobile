// Deterministic, bounded ARM64 disassembly in compiler FDE ranges.
// Use with AnalyzeHeadless -noanalysis. Changes listing metadata only, never machine bytes.
import ghidra.app.script.GhidraScript;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.io.*;
import java.util.*;

public class TerrariaDisassembleBodies extends GhidraScript {
    private record Body(Address start, Address end) {}
    private static String hex(Address a) { return "0x"+Long.toHexString(a.getOffset()); }
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) throw new Exception("Arguments: unwind-function-ranges.tsv output-directory");
        if (currentProgram.getImageBase().getOffset() != 0 ||
            !currentProgram.getLanguageID().toString().equals("AARCH64:LE:64:v8A"))
            throw new Exception("Requires ARM64 LE v8A ELF imported at image base zero");
        Path output = Path.of(args[1]); Files.createDirectories(output);
        Files.writeString(output.resolve("disassembly-summary.json"),
            "{\"finished\":false,\"image_base\":0,\"automatic_analysis\":false}", StandardCharsets.UTF_8);
        List<Body> bodies = new ArrayList<>();
        AddressSet union = new AddressSet(), entries = new AddressSet();
        Address previousEnd = null;
        for (String line : Files.readAllLines(Path.of(args[0]), StandardCharsets.UTF_8)) {
            if (line.isBlank()) continue;
            String[] fields = line.split("\t");
            Address start = toAddr(fields[0]), exclusiveEnd = toAddr(fields[1]);
            if ((start.getOffset() & 3) != 0 || (exclusiveEnd.getOffset() & 3) != 0 ||
                start.compareTo(exclusiveEnd) >= 0 ||
                (previousEnd != null && start.compareTo(previousEnd) < 0))
                throw new Exception("Unaligned, overlapping, or unsorted compiler range: "+line);
            Address end = exclusiveEnd.subtract(1);
            if (!currentProgram.getMemory().contains(start, end))
                throw new Exception("Compiler range outside imported memory: "+line);
            bodies.add(new Body(start, end)); union.add(start, end); entries.add(start);
            previousEnd = exclusiveEnd;
        }
        if (bodies.size() != 123152) throw new Exception("Unexpected FDE count: "+bodies.size());
        long started = System.nanoTime();
        long[] notices = {0};
        // Direct Disassembler has no AutoAnalysisManager calls. DisassembleCommand's default
        // enableAnalysis=true is deliberately avoided. -noanalysis also prevents headless analysis.
        Disassembler decoder = Disassembler.getDisassembler(currentProgram, monitor, message -> notices[0]++);
        decoder.setRepeatPatternLimit(-1);
        println("TERRARIA_RESTRICTED_FLOW_DISASSEMBLY_START "+bodies.size());
        AddressSet flowNew = decoder.disassemble(entries, union, true);
        println("TERRARIA_RESTRICTED_FLOW_DISASSEMBLY_BYTES "+flowNew.getNumAddresses());
        Listing listing = currentProgram.getListing();
        long decoded=0, linear=0, missing=0, data=0, total=0, processed=0;
        try (BufferedWriter coverage = Files.newBufferedWriter(output.resolve("disassembly-coverage.jsonl"), StandardCharsets.UTF_8);
             BufferedWriter gaps = Files.newBufferedWriter(output.resolve("disassembly-gaps.tsv"), StandardCharsets.UTF_8)) {
            gaps.write("address\tcompiler_entry\treason\traw_bytes\n");
            monitor.initialize(bodies.size());
            for (Body body : bodies) {
                monitor.checkCancelled();
                AddressSet bound = new AddressSet(body.start(), body.end());
                long bodyDecoded=0, bodyLinear=0, bodyMissing=0, bodyData=0;
                for (Address at = body.start(); at.compareTo(body.end()) <= 0; at = at.add(4)) {
                    monitor.checkCancelled(); total++;
                    Instruction instruction = listing.getInstructionAt(at);
                    boolean attempted = false;
                    if (instruction == null && listing.getDefinedDataAt(at) == null &&
                        listing.getInstructionContaining(at) == null && listing.getDefinedDataContaining(at) == null) {
                        // Bounded linear completion is a decoding hypothesis, not reachability proof.
                        AddressSet added = decoder.disassemble(at, bound, false);
                        bodyLinear += added.getNumAddresses()/4;
                        attempted = true; instruction = listing.getInstructionAt(at);
                    }
                    if (instruction != null && instruction.getLength() == 4) bodyDecoded++;
                    else {
                        bodyMissing++;
                        Data defined = listing.getDefinedDataContaining(at);
                        String reason = defined != null ? "existing_defined_data" :
                            instruction != null ? "unexpected_instruction_width" :
                            attempted ? "undecodable_or_conflict" : "code_unit_conflict";
                        if (defined != null) bodyData++;
                        gaps.write(hex(at)+"\t"+hex(body.start())+"\t"+reason+"\t"+
                            HexFormat.of().formatHex(getBytes(at,4))+"\n");
                    }
                }
                decoded+=bodyDecoded; linear+=bodyLinear; missing+=bodyMissing; data+=bodyData;
                coverage.write("{\"address\":\""+hex(body.start())+"\",\"end_exclusive\":\""+hex(body.end().add(1))+
                    "\",\"decoded_slots\":"+bodyDecoded+",\"linear_added_slots\":"+bodyLinear+
                    ",\"missing_slots\":"+bodyMissing+",\"defined_data_slots\":"+bodyData+"}\n");
                processed++; monitor.incrementProgress(1);
                if (processed%1000==0) {
                    coverage.flush(); gaps.flush();
                    println("TERRARIA_DISASSEMBLY_PROGRESS "+processed+"/"+bodies.size()+" decoded="+decoded+" gaps="+missing);
                }
            }
        }
        double seconds = (System.nanoTime()-started)/1e9;
        Files.writeString(output.resolve("disassembly-summary.json"),
            "{\"finished\":true,\"image_base\":0,\"automatic_analysis\":false,\"fde_bodies\":"+bodies.size()+
            ",\"aligned_slots\":"+total+",\"decoded_slots\":"+decoded+",\"linear_added_slots\":"+linear+
            ",\"missing_slots\":"+missing+",\"defined_data_slots\":"+data+",\"decoder_notices\":"+notices[0]+
            ",\"elapsed_seconds\":"+seconds+",\"reachability_proven\":false}", StandardCharsets.UTF_8);
        println("TERRARIA_DISASSEMBLY_COMPLETE bodies="+processed+" decoded="+decoded+" gaps="+missing+" seconds="+seconds);
    }
}
