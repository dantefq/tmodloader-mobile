// Suppress inferred fallthrough beyond verified compiler FDE bounds at terminal calls.
// This is a bounded-function-model annotation, not proof that the target never returns.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.io.*;
import java.util.*;

public class TerrariaMarkTerminalCalls extends GhidraScript {
    private static String hex(Address a) {return "0x"+Long.toHexString(a.getOffset());}
    public void run() throws Exception {
        String[] args=getScriptArgs();if(args.length<2)throw new Exception("Arguments: unwind-function-ranges.tsv output-directory");
        if(currentProgram.getImageBase().getOffset()!=0 || !currentProgram.getLanguageID().toString().equals("AARCH64:LE:64:v8A"))throw new Exception("Requires ARM64 LE v8A ELF base0");
        Path out=Path.of(args[1]);Files.createDirectories(out);
        Files.writeString(out.resolve("terminal-call-summary.json"),"{\"finished\":false}");
        long bodies=0,marked=0,existing=0;Address previousEnd=null;
        try(BufferedWriter ledger=Files.newBufferedWriter(out.resolve("terminal-call-overrides.tsv"),StandardCharsets.UTF_8)) {
            ledger.write("address\tsource_fde\tcompiler_end_exclusive\ttarget\traw_bytes\tannotation\n");
            for(String line:Files.readAllLines(Path.of(args[0]),StandardCharsets.UTF_8)) {
                monitor.checkCancelled();if(line.isBlank())continue;String[] row=line.split("\t");
                Address start=toAddr(row[0]),end=toAddr(row[1]);
                if((start.getOffset()&3)!=0 || (end.getOffset()&3)!=0 || start.compareTo(end)>=0 ||
                    (previousEnd!=null && start.compareTo(previousEnd)<0))throw new Exception("Invalid FDE "+line);
                previousEnd=end;bodies++;
                Instruction ins=currentProgram.getListing().getInstructionAt(end.subtract(4));
                if(ins==null || ins.getLength()!=4)continue;
                if(ins.getFlowOverride()!=FlowOverride.NONE) {existing++;continue;}
                var flow=ins.getFlowType();
                if(!flow.isCall() || flow.isComputed() || flow.isConditional() || !end.equals(ins.getFallThrough()))continue;
                Address[] targets=ins.getFlows();
                if(targets.length!=1 || (targets[0].compareTo(start)>=0 && targets[0].compareTo(end)<0))continue;
                ins.setFlowOverride(FlowOverride.CALL_RETURN);marked++;
                ledger.write(hex(ins.getAddress())+"\t"+hex(start)+"\t"+hex(end)+"\t"+hex(targets[0])+"\t"+
                    HexFormat.of().formatHex(ins.getBytes())+"\tbounded_fde_terminal_call\n");
            }
        }
        if(bodies!=123152)throw new Exception("Expected123152 FDE ranges; got "+bodies);
        Files.writeString(out.resolve("terminal-call-summary.json"),"{\"finished\":true,\"fde_bodies\":"+bodies+
            ",\"marked_call_return\":"+marked+",\"existing_overrides_preserved\":"+existing+
            ",\"target_noreturn_proven\":false,\"machine_bytes_changed\":false,\"automatic_analysis\":false}");
        println("TERRARIA_TERMINAL_CALL_COMPLETE marked="+marked+" fdes="+bodies);
    }
}
