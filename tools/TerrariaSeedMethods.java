// Seeds recovered IL2CPP method entries in a private Ghidra analysis database.
// No original program bytes are changed.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class TerrariaSeedMethods extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (currentProgram.getImageBase().getOffset() != 0) {
            throw new Exception("ELF address map requires image base zero; import with -loader-imagebase 0x0");
        }
        Path anchors = Path.of(args[0]).resolveSibling("method-byte-anchors.tsv");
        int verified = 0;
        for (String line : Files.readAllLines(anchors, StandardCharsets.UTF_8)) {
            String[] anchor = line.split("\t");
            byte[] expected = java.util.HexFormat.of().parseHex(anchor[1]);
            byte[] actual = getBytes(toAddr(anchor[0]), expected.length);
            if (!Arrays.equals(expected, actual)) throw new Exception("Loaded bytes do not match original ELF at " + anchor[0]);
            verified++;
        }
        println("TERRARIA_IMAGE_BASE_ZERO_BYTE_ANCHORS_VERIFIED " + verified);
        Path unwind = Path.of(args[0]).resolveSibling("unwind-function-ranges.tsv");
        int bodies = 0;
        for (String line : Files.readAllLines(unwind, StandardCharsets.UTF_8)) {
            String[] row = line.split("\t");
            Address entry = toAddr(row[0]);
            Address end = toAddr(row[1]).subtract(1);
            AddressSet body = new AddressSet(entry, end);
            List<Function> conflicts = new ArrayList<>();
            Iterator<Function> overlapping = currentProgram.getFunctionManager().getFunctionsOverlapping(body);
            while (overlapping.hasNext()) {
                Function existing = overlapping.next();
                if (!existing.getEntryPoint().equals(entry)) conflicts.add(existing);
            }
            for (Function existing : conflicts) currentProgram.getFunctionManager().removeFunction(existing.getEntryPoint());
            Function function = getFunctionAt(entry);
            if (function == null) {
                var symbol = currentProgram.getSymbolTable().getPrimarySymbol(entry);
                String name = symbol == null ? "FUN_"+entry : symbol.getName();
                currentProgram.getFunctionManager().createFunction(name, entry, body, SourceType.ANALYSIS);
            } else function.setBody(body);
            bodies++;
            if (bodies % 10000 == 0) println("TERRARIA_UNWIND_BODIES " + bodies);
        }
        println("TERRARIA_UNWIND_BODIES_COMPLETE " + bodies);
        int count = 0;
        List<String> lines = new ArrayList<>(Files.readAllLines(Path.of(args[0]), StandardCharsets.UTF_8));
        Path generic = Path.of(args[0]).resolveSibling("generic-method-seeds.tsv");
        if (Files.exists(generic)) lines.addAll(Files.readAllLines(generic, StandardCharsets.UTF_8));
        for (String line : lines) {
            if (line.isBlank() || line.startsWith("#")) continue;
            String[] row = line.split("\t", -1);
            Address entry = toAddr(row[0]);
            if (!currentProgram.getMemory().contains(entry)) throw new Exception("Unmapped entry " + row[0]);
            createLabel(entry, row[1], true, SourceType.USER_DEFINED);
            Function function = getFunctionAt(entry);
            if (function == null) throw new Exception("Seed has no compiler unwind function at " + row[0]);
            function.setName(row[1], SourceType.USER_DEFINED);
            addEntryPoint(entry);
            count++;
            if (count % 5000 == 0) println("TERRARIA_SEEDS " + count);
        }
        // Parameter ID guesses are expensive and can obscure the true IL2CPP ABI.
        Map<String, String> options = getCurrentAnalysisOptionsAndValues(currentProgram);
        for (String option : options.keySet()) {
            if (option.equals("Decompiler Parameter ID") || option.equals("Non-Returning Functions - Discovered") ||
                    option.equals("GCC Exception Handlers") || option.equals("Decompiler Switch Analysis"))
                setAnalysisOption(currentProgram, option, "false");
        }
        println("TERRARIA_SEEDS_COMPLETE " + count);
    }
}
