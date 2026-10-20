// Separate one-attempt-per-method batch; frozen conditional overrides, two read-only decompilers.
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.util.DecompilerConcurrentQ;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.JumpTable;
import ghidra.util.task.TaskMonitor;
import generic.concurrent.GThreadPool;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;
import java.io.*;
public class TerrariaSwitchHintBatch extends TerrariaSwitchHintProbe {
    Path output;Map<Long,JsonObject> records=new LinkedHashMap<>();BufferedWriter journal;int complete=0,success=0;
    synchronized void accept(JsonObject record){try{
        journal.write(gson.toJson(record).replace("\n",""));journal.newLine();journal.flush();complete++;if(record.get("status").getAsString().equals("decompiled_conditional_candidate"))success++;
        JsonObject p=new JsonObject();p.addProperty("attempted",complete);p.addProperty("total",records.size());p.addProperty("conditional_c",success);p.addProperty("finished",false);Files.writeString(output.resolve("progress.json"),gson.toJson(p));println("TERRARIA_HINT_BATCH_RESULT "+record.get("address")+" "+record.get("status")+" "+complete+"/"+records.size());
    }catch(IOException error){throw new UncheckedIOException(error);}}
    class Worker extends DecompilerCallback<JsonObject>{
        Worker(){super(currentProgram,d->{DecompileOptions o=new DecompileOptions();o.grabFromProgram(currentProgram);o.setMaxInstructions(250000);o.setMaxPayloadMBytes(256);d.setOptions(o);d.toggleCCode(true);d.toggleSyntaxTree(false);d.setSimplificationStyle("decompile");});setTimeout(180);}
        public JsonObject process(DecompileResults d,TaskMonitor m)throws Exception{
            JsonObject r=records.get(d.getFunction().getEntryPoint().getOffset()).deepCopy();r.addProperty("message",d.getErrorMessage());r.addProperty("timed_out",d.isTimedOut());
            if(d.decompileCompleted()&&d.getDecompiledFunction()!=null){Path c=output.resolve(r.get("address").getAsString()+"_conditional_candidate.c");String body="/* CONDITIONAL GHIDRA C CANDIDATE; NOT ORIGINAL SOURCE; switch assumptions unproved globally; no runtime verification. */\n"+d.getDecompiledFunction().getC();Files.writeString(c,body);r.addProperty("status","decompiled_conditional_candidate");r.addProperty("file",c.getFileName().toString());r.addProperty("c_sha256",hash(Files.readAllBytes(c)));r.addProperty("c_bytes",Files.size(c));r.addProperty("warning_count",body.split("WARNING:",-1).length-1);}else r.addProperty("status","decompile_failed");return r;
        }
        public JsonObject process(Function f,TaskMonitor m)throws Exception{long start=System.nanoTime();try{JsonObject r=super.process(f,m);r.addProperty("elapsed_seconds",(System.nanoTime()-start)/1e9);return r;}catch(Exception e){JsonObject r=records.get(f.getEntryPoint().getOffset()).deepCopy();r.addProperty("status","decompile_error");r.addProperty("message",e.toString());r.addProperty("elapsed_seconds",(System.nanoTime()-start)/1e9);return r;}}
    }
    public void run()throws Exception{
        String[] args=getScriptArgs();Path lab=Path.of(args[0]),producer=Path.of(args[1]);output=lab.resolve("pseudocode-switch-hint-batch");Files.createDirectories(output);if(Files.exists(output.resolve("results.jsonl")))throw new Exception("Existing batch journal; refusing repeats");
        byte[] elf=Files.readAllBytes(lab.resolve("native/libil2cpp.so"));if(!hash(elf).equals(ELF)||!ELF.equalsIgnoreCase(currentProgram.getExecutableSHA256()))throw new Exception("ELF identity mismatch");Path engine=ghidra.framework.Application.getOSFile("decompile.exe").toPath().toRealPath();if(!hash(Files.readAllBytes(engine)).equals(ENGINE))throw new Exception("Wrong actual engine");
        Path maps=lab.resolve("hard-switches-v2/switches.json");JsonObject all=JsonParser.parseString(Files.readString(maps)).getAsJsonObject();if(!ELF.equals(all.get("elf_sha256").getAsString()))throw new Exception("Wrong switch source");
        List<Function> functions=new ArrayList<>();int tx=currentProgram.startTransaction("Frozen ephemeral conditional switch hints batch");GThreadPool pool=null;Worker worker=null;DecompilerConcurrentQ<Function,JsonObject> queue=null;
        JsonObject scope=new JsonObject();scope.addProperty("profile","conditional-switch-hint-batch-v1-typed-v4-stack32");scope.addProperty("parent_helper_sha256",hash(Files.readAllBytes(producer.resolveSibling("TerrariaSwitchHintProbe.java"))));scope.addProperty("parallel_readonly_decompilers",2);scope.addProperty("excluded_successful_player_update",true);scope.addProperty("excluded_empty_switch_methods",true);
        try{
            for(JsonElement item:all.getAsJsonArray("methods")){JsonObject method=item.getAsJsonObject();long start=num(method.get("address")),end=num(method.get("end_exclusive"));if(start==0x12f63e8L||method.getAsJsonArray("switch_candidates").isEmpty())continue;Function f=getFunctionAt(addr(start));if(f==null||!f.getBody().equals(new AddressSet(addr(start),addr(end-1))))throw new Exception("Wrong saved body");verify(elf,start,Math.toIntExact(end-start));
                JsonObject r=new JsonObject();r.addProperty("profile",scope.get("profile").getAsString());r.add("method",method.get("method"));r.add("address",method.get("address"));r.add("end_exclusive",method.get("end_exclusive"));r.addProperty("elf_sha256",ELF);r.addProperty("actual_engine_sha256",ENGINE);r.addProperty("actual_engine_path",engine.toString());r.addProperty("switch_maps_sha256",hash(Files.readAllBytes(maps)));r.addProperty("script_sha256",hash(Files.readAllBytes(producer)));r.addProperty("parent_helper_sha256",scope.get("parent_helper_sha256").getAsString());r.addProperty("function_source_sha256",hash(source(elf,start,Math.toIntExact(end-start))));r.addProperty("function_source_bytes_verified",end-start);r.addProperty("timeout_seconds",180);r.addProperty("max_instructions",250000);r.addProperty("max_payload_mb",256);r.addProperty("runtime_verified",false);r.addProperty("canonical_journals_modified",false);r.addProperty("saved_project_modified",false);r.addProperty("conditional_assumptions","Recorded sequences execute without alternate entry, stable table bytes, high index bits zero; global dominance and semantic equivalence unproved.");JsonArray hints=new JsonArray();int entries=0;
                for(JsonElement element:method.getAsJsonArray("switch_candidates")){JsonObject map=element.getAsJsonObject();long branch=num(map.get("branch"));Instruction ins=currentProgram.getListing().getInstructionAt(addr(branch));if(ins==null||!ins.getMnemonicString().equalsIgnoreCase("br"))throw new Exception("Wrong BR");verify(elf,branch,4);verify(elf,num(map.get("table")),map.get("count").getAsInt()*map.get("width").getAsInt());ArrayList<Address> targets=new ArrayList<>();JsonArray addresses=new JsonArray();for(JsonElement entry:map.getAsJsonArray("entries")){long target=num(entry.getAsJsonObject().get("target"));if(target<start||target>=end)throw new Exception("Nonlocal switch target");verify(elf,target,4);targets.add(addr(target));addresses.add("0x"+Long.toHexString(target));entries++;}new JumpTable(addr(branch),targets,true,0).writeOverride(f);JsonObject hint=new JsonObject();hint.add("branch",map.get("branch"));hint.add("targets",addresses);hints.add(hint);}
                r.add("applied_hints",hints);r.addProperty("applied_hint_count",hints.size());r.addProperty("applied_entry_count",entries);records.put(start,r);functions.add(f);
            }
            if(records.size()!=12)throw new Exception("Expected exactly12 remaining mapped methods, found "+records.size());JsonArray identities=new JsonArray();records.values().forEach(identities::add);scope.add("methods",identities);Files.writeString(output.resolve("scope.json"),gson.toJson(scope));
            pool=GThreadPool.getPrivateThreadPool("Terraria switch hint batch "+UUID.randomUUID());pool.setMaxThreadCount(2);worker=new Worker();queue=new DecompilerConcurrentQ<>(worker,pool,false,monitor);
            try(BufferedWriter writer=Files.newBufferedWriter(output.resolve("results.jsonl"),StandardOpenOption.CREATE_NEW)){journal=writer;queue.process(functions.iterator(),this::accept);queue.waitUntilDone();if(complete!=records.size())throw new Exception("Incomplete batch");}
        }finally{if(queue!=null)queue.dispose(60);if(worker!=null)worker.dispose();if(pool!=null)pool.shutdownNow();currentProgram.endTransaction(tx,false);scope.addProperty("ephemeral_transaction_rolled_back",true);scope.addProperty("finished",complete==12);scope.addProperty("attempted",complete);scope.addProperty("conditional_c",success);Files.writeString(output.resolve("progress.json"),gson.toJson(scope));println("TERRARIA_HINT_BATCH_END attempted="+complete+" conditionalC="+success);}
    }
}
