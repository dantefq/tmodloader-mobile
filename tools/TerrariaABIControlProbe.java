// Read-only ABI evidence: function storage, original bytes, raw P-code, and candidate C.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.io.*;
import java.util.*;

public class TerrariaABIControlProbe extends GhidraScript {
    private final Gson gson=new Gson();
    private JsonObject variable(Variable v) {
        JsonObject r=new JsonObject();r.addProperty("name",v.getName());r.addProperty("type",v.getDataType().getPathName());
        r.addProperty("type_size",v.getDataType().getLength());r.addProperty("storage",v.getVariableStorage().toString());
        JsonArray pieces=new JsonArray();for(Varnode node:v.getVariableStorage().getVarnodes()) {
            JsonObject piece=new JsonObject();piece.addProperty("address",node.getAddress().toString());piece.addProperty("size",node.getSize());
            var reg=currentProgram.getRegister(node.getAddress(),node.getSize());if(reg!=null)piece.addProperty("register",reg.getName());pieces.add(piece);
        }
        r.add("storage_pieces",pieces);return r;
    }
    public void run()throws Exception {
        String[] args=getScriptArgs();if(args.length<2)throw new Exception("Args: control-methods.json isolated-output-directory");
        Path output=Path.of(args[1]).toAbsolutePath().normalize();
        if(Files.exists(output.resolve("coverage.jsonl"))||output.getFileName().toString().equals("pseudocode"))throw new Exception("Use isolated control output");
        if(currentProgram.getImageBase().getOffset()!=0||!currentProgram.getLanguageID().toString().equals("AARCH64:LE:64:v8A"))throw new Exception("Requires ARM64 base0");
        Files.createDirectories(output);Path attempt=output.resolve("attempt-"+System.currentTimeMillis());Files.createDirectories(attempt);
        JsonArray controls=JsonParser.parseString(Files.readString(Path.of(args[0]),StandardCharsets.UTF_8)).getAsJsonArray();
        if(controls.size()!=10)throw new Exception("Expected exactly10 control methods");
        try(BufferedWriter ledger=Files.newBufferedWriter(attempt.resolve("controls.jsonl"),StandardCharsets.UTF_8)) {
            for(JsonElement element:controls) {
                monitor.checkCancelled();JsonObject metadata=element.getAsJsonObject();String address=metadata.get("native_address").getAsString();
                Function function=getFunctionAt(toAddr(address));if(function==null)throw new Exception("Missing control function "+address);
                Path dir=attempt.resolve(address);Files.createDirectories(dir);JsonObject result=new JsonObject();result.add("metadata",metadata.deepCopy());
                result.addProperty("probe_profile","abi-control-v4-evidence-only");result.addProperty("function",function.getName());result.addProperty("image_base",0);
                result.addProperty("formal_prototype",function.getPrototypeString(true,true));result.addProperty("storage_prototype",function.getPrototypeString(false,true));
                result.addProperty("calling_convention",function.getCallingConventionName());result.addProperty("custom_storage",function.hasCustomVariableStorage());
                result.addProperty("body",function.getBody().toString());result.add("return",variable(function.getReturn()));
                JsonArray parameters=new JsonArray();for(Parameter p:function.getParameters()) {
                    JsonObject param=variable(p);param.addProperty("ordinal",p.getOrdinal());parameters.add(param);
                }result.add("parameters",parameters);
                long instructionCount=0;
                try(BufferedWriter instructions=Files.newBufferedWriter(dir.resolve("instructions.jsonl"),StandardCharsets.UTF_8)) {
                    InstructionIterator it=currentProgram.getListing().getInstructions(function.getBody(),true);
                    while(it.hasNext()) {
                        Instruction ins=it.next();JsonObject row=new JsonObject();row.addProperty("address",ins.getAddress().toString());
                        row.addProperty("raw_bytes",HexFormat.of().formatHex(ins.getBytes()));row.addProperty("mnemonic",ins.getMnemonicString());
                        row.addProperty("instruction",ins.toString());row.addProperty("flow_override",ins.getFlowOverride().toString());
                        JsonArray operands=new JsonArray();for(int i=0;i<ins.getNumOperands();i++)operands.add(ins.getDefaultOperandRepresentation(i));row.add("operands",operands);
                        JsonArray pcode=new JsonArray();for(PcodeOp op:ins.getPcode(false))pcode.add(op.toString());row.add("raw_pcode_without_overrides",pcode);
                        instructions.write(gson.toJson(row));instructions.newLine();instructionCount++;
                    }
                }
                result.addProperty("instructions",instructionCount);result.addProperty("canonical_ledger_changed",false);result.addProperty("runtime_verified",false);
                DecompInterface decompiler=new DecompInterface();
                try {
                    // Default decompiler analysis options, with a10second per-control limit.
                    decompiler.setSimplificationStyle("decompile");decompiler.toggleCCode(true);decompiler.toggleSyntaxTree(false);
                    if(!decompiler.openProgram(currentProgram))throw new Exception("Open program failed: "+decompiler.getLastMessage());
                    long start=System.nanoTime();DecompileResults d=decompiler.decompileFunction(function,10,monitor);
                    result.addProperty("elapsed_ms",(System.nanoTime()-start)/1000000);result.addProperty("decompile_completed",d.decompileCompleted());result.addProperty("error",d.getErrorMessage());
                    if(d.decompileCompleted()&&d.getDecompiledFunction()!=null) {
                        String header="/* ABI CONTROL CANDIDATE; NOT ORIGINAL SOURCE; NOT RECOMPILED.\n * ELF VA: "+address+"; image base:0\n */\n";
                        Files.writeString(dir.resolve("candidate.c"),header+d.getDecompiledFunction().getC(),StandardCharsets.UTF_8);result.addProperty("candidate_c_written",true);
                    }
                }catch(Exception e){result.addProperty("exception",e.toString());}finally{decompiler.dispose();}
                Files.writeString(dir.resolve("result.json"),gson.toJson(result),StandardCharsets.UTF_8);ledger.write(gson.toJson(result));ledger.newLine();ledger.flush();
                println("TERRARIA_ABI_CONTROL "+address+" "+result.get("decompile_completed"));
            }
        }
        println("TERRARIA_ABI_CONTROL_COMPLETE "+attempt);
    }
}
