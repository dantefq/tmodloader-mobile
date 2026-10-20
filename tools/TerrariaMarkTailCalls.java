// Bounded tail-call hypotheses for independently recovered compiler function ranges.
// No machine bytes change. Run after TerrariaDisassembleBodies and before decompilation.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.FlowType;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.io.*;
import java.util.*;

public class TerrariaMarkTailCalls extends GhidraScript {
    private record Body(Address start, Address end) {}
    private static String hex(Address a) { return "0x"+Long.toHexString(a.getOffset()); }
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) throw new Exception("Arguments: unwind-function-ranges.tsv output-directory");
        if (currentProgram.getImageBase().getOffset()!=0 ||
            !currentProgram.getLanguageID().toString().equals("AARCH64:LE:64:v8A"))
            throw new Exception("Requires ARM64 LE v8A ELF imported at image base zero");
        Path output=Path.of(args[1]); Files.createDirectories(output);
        Files.writeString(output.resolve("tail-call-summary.json"), "{\"finished\":false}", StandardCharsets.UTF_8);
        TreeMap<Address,Body> bodies=new TreeMap<>();
        AddressSet union=new AddressSet();
        Address previousEnd=null;
        for (String line:Files.readAllLines(Path.of(args[0]),StandardCharsets.UTF_8)) {
            if(line.isBlank()) continue;
            String[] row=line.split("\t"); Address start=toAddr(row[0]), end=toAddr(row[1]);
            if((start.getOffset()&3)!=0 || (end.getOffset()&3)!=0 || start.compareTo(end)>=0 ||
                (previousEnd!=null && start.compareTo(previousEnd)<0)) throw new Exception("Invalid FDE range "+line);
            bodies.put(start,new Body(start,end.subtract(1))); union.add(start,end.subtract(1)); previousEnd=end;
        }
        if(bodies.size()!=123152) throw new Exception("Unexpected FDE count: "+bodies.size());
        long started=System.nanoTime(), scanned=0, jumps=0, marked=0, already=0;
        try(BufferedWriter ledger=Files.newBufferedWriter(output.resolve("tail-call-overrides.tsv"),StandardCharsets.UTF_8)) {
            ledger.write("address\tsource_fde\ttarget_fde\told_flow\tnew_flow\traw_bytes\n");
            InstructionIterator iterator=currentProgram.getListing().getInstructions(union,true);
            while(iterator.hasNext()) {
                monitor.checkCancelled(); Instruction instruction=iterator.next(); scanned++;
                if(instruction.getFlowOverride()!=FlowOverride.NONE) { already++; continue; }
                FlowType flow=instruction.getFlowType();
                if(!flow.isJump() || flow.isConditional() || flow.isComputed() || flow.isCall()) continue;
                Address[] targets=instruction.getFlows();
                if(targets.length!=1 || !bodies.containsKey(targets[0])) continue;
                jumps++;
                Map.Entry<Address,Body> containing=bodies.floorEntry(instruction.getAddress());
                if(containing==null || instruction.getAddress().compareTo(containing.getValue().end())>0 ||
                    containing.getKey().equals(targets[0])) continue;
                Function target=currentProgram.getFunctionManager().getFunctionAt(targets[0]);
                if(target==null) throw new Exception("Known FDE target lacks function: "+targets[0]);
                instruction.setFlowOverride(FlowOverride.CALL_RETURN);
                ledger.write(hex(instruction.getAddress())+"\t"+hex(containing.getKey())+"\t"+hex(targets[0])+"\t"+
                    flow+"\tCALL_RETURN\t"+HexFormat.of().formatHex(instruction.getBytes())+"\n");
                marked++;
                if(marked%10000==0) { ledger.flush(); println("TERRARIA_TAIL_CALL_PROGRESS "+marked); }
            }
        }
        double seconds=(System.nanoTime()-started)/1e9;
        Files.writeString(output.resolve("tail-call-summary.json"),
            "{\"finished\":true,\"image_base\":0,\"automatic_analysis\":false,\"scanned_instructions\":"+scanned+
            ",\"direct_jumps_to_fde_entries\":"+jumps+",\"marked_call_return\":"+marked+
            ",\"existing_overrides_preserved\":"+already+",\"elapsed_seconds\":"+seconds+
            ",\"interpretation\":\"Unconditional direct transfers to another compiler FDE entry treated as tail calls; annotations, not original source\"}",StandardCharsets.UTF_8);
        println("TERRARIA_TAIL_CALL_COMPLETE marked="+marked+" scanned="+scanned+" seconds="+seconds);
    }
}
