// Complete firstpass P-code diagnostics for20 baseline failures; no C or DB mutation.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.io.*;
import java.time.Instant;
import java.util.*;

public class TerrariaExportHardIR extends GhidraScript {
    private static final String PROFILE="hard20-firstpass-complete-ir-v1-stack32";
    private static final String BASE_PROFILE="bounded-fde-terminal-calls-signatures-v3";
    private static final String ELF_SHA="9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5";
    private final Gson gson=new Gson();
    private Path output;private int timeout=90,maxInstructions=250000;
    private String baselineHash,engineHash,enginePath,modelFingerprint;
    private String fdeHash;
    private final Map<Long,JsonObject> targets=new LinkedHashMap<>(),completed=new LinkedHashMap<>();
    private static String hex(long n){return "0x"+Long.toHexString(n);}
    private static long number(String s){return Long.parseUnsignedLong(s.replace("0x",""),16);}
    private static String sha(Path p)throws Exception {
        var digest=java.security.MessageDigest.getInstance("SHA-256");
        try(InputStream input=Files.newInputStream(p)){byte[] block=new byte[1048576];int n;while((n=input.read(block))>0)digest.update(block,0,n);}
        return HexFormat.of().formatHex(digest.digest());
    }
    private void write(Path p,JsonObject r)throws IOException {Files.writeString(p,gson.toJson(r),StandardCharsets.UTF_8);}
    private JsonObject node(Varnode n) {
        if(n==null)return null;JsonObject r=new JsonObject();r.addProperty("space",n.getAddress().getAddressSpace().getName());
        r.addProperty("offset",hex(n.getOffset()));r.addProperty("size",n.getSize());
        r.addProperty("constant",n.isConstant());r.addProperty("register",n.isRegister());r.addProperty("unique",n.isUnique());
        if(n.isRegister()){var register=currentProgram.getRegister(n.getAddress(),n.getSize());if(register!=null)r.addProperty("register_name",register.getName());}
        return r;
    }
    private JsonObject base(JsonObject source,Function function) {
        JsonObject r=new JsonObject();for(String key:List.of("address","method","image","compiler_end_exclusive"))r.add(key,source.get(key));
        r.addProperty("profile",PROFILE);r.addProperty("baseline_profile",BASE_PROFILE);r.addProperty("baseline_sha256",baselineHash);
        r.addProperty("elf_sha256",ELF_SHA);r.addProperty("actual_engine_path",enginePath);r.addProperty("actual_engine_sha256",engineHash);
        r.addProperty("fde_catalogue_sha256",fdeHash);
        r.addProperty("model_fingerprint_sha256",modelFingerprint);r.addProperty("program_name",currentProgram.getName());
        r.addProperty("program_path",currentProgram.getDomainFile().getPathname());r.addProperty("program_executable_path",currentProgram.getExecutablePath());
        r.addProperty("procedure_va",source.get("address").getAsString());r.addProperty("image_base",0);
        r.addProperty("timeout_seconds",timeout);r.addProperty("max_instructions",maxInstructions);r.addProperty("max_payload_mbytes",256);
        r.addProperty("simplification_style","firstpass");r.addProperty("c_output_enabled",false);r.addProperty("syntax_tree_enabled",true);
        r.addProperty("valid_C",false);r.addProperty("original_CSharp",false);r.addProperty("runtime_verified",false);
        r.addProperty("database_modified",false);r.addProperty("canonical_ledger_modified",false);
        r.addProperty("listing_body_is_FDE_only",true);r.addProperty("decompiler_can_follow_outside_listing_body",true);
        r.addProperty("native_timeout_includes_java_decode",false);r.addProperty("wall_elapsed_includes_java_decode",true);
        if(function!=null){r.addProperty("ghidra_function",function.getName());r.addProperty("formal_prototype",function.getPrototypeString(true,true));}
        r.addProperty("started_utc",Instant.now().toString());return r;
    }
    private void artifacts(HighFunction high,Path dir,JsonObject record,long start,long end)throws Exception {
        long operations=0,outsideOperations=0,edges=0;TreeSet<Address> addresses=new TreeSet<>();
        try(BufferedWriter writer=Files.newBufferedWriter(dir.resolve("pcode-operations.jsonl"),StandardCharsets.UTF_8)) {
            Iterator<PcodeOpAST> iterator=high.getPcodeOps();
            while(iterator.hasNext()) {
                monitor.checkCancelled();PcodeOpAST op=iterator.next();Address address=op.getSeqnum().getTarget();
                boolean outside=!address.isMemoryAddress()||address.getOffset()<start||address.getOffset()>=end;
                if(address.isMemoryAddress())addresses.add(address);if(outside)outsideOperations++;
                JsonObject r=new JsonObject();r.addProperty("ordinal",operations++);r.addProperty("instruction_address",address.toString());
                r.addProperty("address_space",address.getAddressSpace().getName());r.addProperty("sequence_time",op.getSeqnum().getTime());
                r.addProperty("block_index",op.getParent()==null?-1:op.getParent().getIndex());r.addProperty("opcode",op.getOpcode());
                r.addProperty("mnemonic",op.getMnemonic());r.addProperty("text",op.toString());r.addProperty("outside_fde",outside);
                r.add("output",node(op.getOutput()));JsonArray inputs=new JsonArray();for(int i=0;i<op.getNumInputs();i++)inputs.add(node(op.getInput(i)));r.add("inputs",inputs);
                writer.write(gson.toJson(r));writer.newLine();
            }
        }
        var blocks=high.getBasicBlocks();
        try(BufferedWriter writer=Files.newBufferedWriter(dir.resolve("basic-blocks.jsonl"),StandardCharsets.UTF_8);
            BufferedWriter edgeWriter=Files.newBufferedWriter(dir.resolve("control-flow-edges.jsonl"),StandardCharsets.UTF_8)) {
            for(PcodeBlockBasic block:blocks) {
                monitor.checkCancelled();JsonObject r=new JsonObject();r.addProperty("index",block.getIndex());r.addProperty("start",block.getStart().toString());r.addProperty("stop_inclusive",block.getStop().toString());
                r.addProperty("incoming_count",block.getInSize());r.addProperty("outgoing_count",block.getOutSize());
                JsonArray incoming=new JsonArray(),outgoing=new JsonArray();for(int i=0;i<block.getInSize();i++)incoming.add(block.getIn(i).getIndex());
                for(int i=0;i<block.getOutSize();i++){int target=block.getOut(i).getIndex();outgoing.add(target);JsonObject edge=new JsonObject();edge.addProperty("source",block.getIndex());edge.addProperty("target",target);edge.addProperty("outgoing_slot",i);edgeWriter.write(gson.toJson(edge));edgeWriter.newLine();edges++;}
                r.add("incoming",incoming);r.add("outgoing",outgoing);writer.write(gson.toJson(r));writer.newLine();
            }
        }
        long outsideAddresses=0,unreadable=0;
        try(BufferedWriter writer=Files.newBufferedWriter(dir.resolve("instruction-addresses.jsonl"),StandardCharsets.UTF_8)) {
            for(Address address:addresses) {
                monitor.checkCancelled();JsonObject r=new JsonObject();r.addProperty("address",address.toString());r.addProperty("space",address.getAddressSpace().getName());
                boolean outside=address.getOffset()<start||address.getOffset()>=end;if(outside)outsideAddresses++;r.addProperty("outside_fde",outside);
                try{byte[] bytes=new byte[4];if(currentProgram.getMemory().getBytes(address,bytes)!=4)throw new IOException("Less than4bytes");r.addProperty("program_memory_bytes",HexFormat.of().formatHex(bytes));}
                catch(Exception e){unreadable++;r.addProperty("byte_read_error",e.toString());}
                Instruction instruction=currentProgram.getListing().getInstructionAt(address);if(instruction!=null){r.addProperty("listing_instruction",instruction.toString());r.addProperty("flow_override",instruction.getFlowOverride().toString());}
                r.addProperty("original_ELF_byte_comparison_performed",false);writer.write(gson.toJson(r));writer.newLine();
            }
        }
        record.addProperty("pcode_operations",operations);record.addProperty("pcode_operations_outside_fde",outsideOperations);
        record.addProperty("basic_blocks",blocks.size());record.addProperty("control_flow_edges",edges);record.addProperty("unique_instruction_addresses",addresses.size());
        record.addProperty("unique_instruction_addresses_outside_fde",outsideAddresses);record.addProperty("unreadable_instruction_addresses",unreadable);
        record.addProperty("all_returned_pcode_operations_saved",true);record.addProperty("all_returned_basic_blocks_saved",true);
        record.addProperty("complete_semantic_CFG_proven",false);record.addProperty("pcode_sample_truncated",false);
        JsonArray manifest=new JsonArray();for(String name:List.of("pcode-operations.jsonl","basic-blocks.jsonl","control-flow-edges.jsonl","instruction-addresses.jsonl")) {
            Path file=dir.resolve(name);JsonObject artifact=new JsonObject();artifact.addProperty("file",output.relativize(file).toString().replace('\\','/'));
            artifact.addProperty("bytes",Files.size(file));artifact.addProperty("sha256",sha(file));manifest.add(artifact);
        }record.add("artifacts",manifest);
    }
    private boolean reusable(JsonObject r)throws Exception {
        if(!"ir_complete".equals(r.get("status").getAsString())||!PROFILE.equals(r.get("profile").getAsString())||!baselineHash.equals(r.get("baseline_sha256").getAsString())||!engineHash.equals(r.get("actual_engine_sha256").getAsString())||!modelFingerprint.equals(r.get("model_fingerprint_sha256").getAsString()))return false;
        JsonObject target=targets.get(number(r.get("address").getAsString()));if(target==null)return false;
        for(String key:List.of("address","method","image","compiler_end_exclusive"))if(!target.get(key).equals(r.get(key)))return false;
        JsonArray artifacts=r.getAsJsonArray("artifacts");if(artifacts==null||artifacts.size()!=4)return false;
        for(JsonElement item:artifacts) {
            JsonObject a=item.getAsJsonObject();Path file=output.resolve(a.get("file").getAsString()).normalize();
            if(!file.startsWith(output)||!Files.isRegularFile(file)||!file.toRealPath().startsWith(output.toRealPath())||Files.size(file)!=a.get("bytes").getAsLong()||!sha(file).equals(a.get("sha256").getAsString()))return false;
        }return true;
    }
    private void progress(boolean finished,int attempted,int failures)throws Exception {
        JsonObject r=new JsonObject();r.addProperty("profile",PROFILE);r.addProperty("finished",finished);r.addProperty("targets",targets.size());
        r.addProperty("complete_ir",completed.size());r.addProperty("attempted_this_run",attempted);r.addProperty("failed_this_run",failures);
        r.addProperty("all_targets_complete",completed.size()==targets.size());
        r.addProperty("not_complete",targets.size()-completed.size());r.addProperty("updated_utc",Instant.now().toString());
        Path temp=output.resolve("progress.json.tmp");write(temp,r);Files.move(temp,output.resolve("progress.json"),StandardCopyOption.REPLACE_EXISTING);
    }
    public void run()throws Exception {
        String[] args=getScriptArgs();if(args.length<2)throw new Exception("Args: full-v3-baseline.jsonl lab/hard-functions-ir [90] [250000]");
        Path baseline=Path.of(args[0]);output=Path.of(args[1]).toAbsolutePath().normalize();
        if(!output.getFileName().toString().equals("hard-functions-ir"))throw new Exception("Use separate hard-functions-ir directory");
        Files.createDirectories(output);Path lab=output.getParent();timeout=args.length>2?Integer.parseInt(args[2]):90;maxInstructions=args.length>3?Integer.parseInt(args[3]):250000;
        if(timeout<1||timeout>3600||maxInstructions<1||maxInstructions>1000000)throw new Exception("Invalid resource limits");
        if(currentProgram.getImageBase().getOffset()!=0||!currentProgram.getLanguageID().toString().equals("AARCH64:LE:64:v8A"))throw new Exception("Requires ARM64 ELF base0");
        baselineHash=sha(baseline);if(!ELF_SHA.equals(sha(lab.resolve("native/libil2cpp.so"))))throw new Exception("Original ELF hash mismatch");
        Path selected=ghidra.framework.Application.getOSFile("decompile.exe").toPath().toRealPath();enginePath=selected.toString();engineHash=sha(selected);
        JsonObject provenance=JsonParser.parseString(Files.readString(lab.resolve("ghidra-stack32-provenance.json"))).getAsJsonObject();
        if(!engineHash.equals(provenance.get("modified_sha256").getAsString()))throw new Exception("Selected engine is not verified stack32 engine");
        Path fdePath=lab.resolve("native/unwind-function-ranges.tsv");fdeHash=sha(fdePath);
        Map<Long,Long> ends=new HashMap<>();for(String line:Files.readAllLines(fdePath)) {String[] row=line.split("\t");ends.put(number(row[0]),number(row[1]));}
        int count=0;Set<Long> seen=new HashSet<>();try(BufferedReader reader=Files.newBufferedReader(baseline,StandardCharsets.UTF_8)) {
            String line;while((line=reader.readLine())!=null){JsonObject r=JsonParser.parseString(line).getAsJsonObject();long address=number(r.get("address").getAsString());count++;
                if(!seen.add(address)||!BASE_PROFILE.equals(r.get("profile").getAsString())||r.get("image_base").getAsInt()!=0||!Objects.equals(ends.get(address),number(r.get("compiler_end_exclusive").getAsString())))throw new Exception("Invalid baseline row");
                if(!"decompiled".equals(r.get("status").getAsString()))targets.put(address,r);
            }
        }if(count!=93990||targets.size()!=20||ends.size()!=123152)throw new Exception("Incomplete baseline or FDE catalogue");
        JsonObject model=new JsonObject();model.addProperty("program_path",currentProgram.getDomainFile().getPathname());
        model.addProperty("aggregate_v4_types_present",currentProgram.getDataTypeManager().getCategory(new ghidra.program.model.data.CategoryPath("/TerrariaRecoveredV4"))!=null);
        var prototypes=java.security.MessageDigest.getInstance("SHA-256");long prototypeCount=0;
        FunctionIterator allFunctions=currentProgram.getFunctionManager().getFunctions(true);
        while(allFunctions.hasNext()) {
            monitor.checkCancelled();Function function=allFunctions.next();StringBuilder signature=new StringBuilder(function.getEntryPoint().toString()).append('\t').append(function.getPrototypeString(true,true));
            signature.append('\t').append(function.getReturn().getVariableStorage());for(Parameter parameter:function.getParameters())signature.append('\t').append(parameter.getDataType().getPathName()).append(':').append(parameter.getLength()).append(':').append(parameter.getVariableStorage());
            prototypes.update((signature+"\n").getBytes(StandardCharsets.UTF_8));prototypeCount++;
        }
        model.addProperty("all_function_signatures_sha256",HexFormat.of().formatHex(prototypes.digest()));model.addProperty("signature_functions",prototypeCount);
        JsonArray functions=new JsonArray();for(var entry:targets.entrySet()) {
            Function function=getFunctionAt(toAddr(hex(entry.getKey())));if(function==null)throw new Exception("Missing hard function");
            if(!function.getBody().equals(new AddressSet(function.getEntryPoint(),toAddr(hex(ends.get(entry.getKey())-1)))))throw new Exception("Function body differs from FDE");
            JsonObject item=new JsonObject();item.addProperty("address",hex(entry.getKey()));item.addProperty("prototype",function.getPrototypeString(true,true));functions.add(item);
            var flow=java.security.MessageDigest.getInstance("SHA-256");InstructionIterator instructions=currentProgram.getListing().getInstructions(function.getBody(),true);
            while(instructions.hasNext()){monitor.checkCancelled();Instruction instruction=instructions.next();flow.update((instruction.getAddress()+":"+instruction.getFlowOverride()+":"+HexFormat.of().formatHex(instruction.getBytes())+"\n").getBytes(StandardCharsets.UTF_8));}
            item.addProperty("FDE_listing_bytes_and_overrides_sha256",HexFormat.of().formatHex(flow.digest()));
        }model.add("functions",functions);write(output.resolve("model.json"),model);modelFingerprint=sha(output.resolve("model.json"));
        JsonObject scope=new JsonObject();scope.addProperty("profile",PROFILE);scope.addProperty("baseline_sha256",baselineHash);scope.addProperty("elf_sha256",ELF_SHA);
        scope.addProperty("actual_engine_path",enginePath);scope.addProperty("actual_engine_sha256",engineHash);scope.addProperty("model_fingerprint_sha256",modelFingerprint);
        scope.addProperty("fde_catalogue_sha256",fdeHash);
        scope.addProperty("scope","All returned firstpass P-code operations/blocks/edges, not optimized C or original C#. Returned tree completeness does not prove complete semantic CFG; unresolved computed flow remains possible. Source bytes captured from program memory, original ELF byte audit pending.");
        scope.addProperty("database_modified",false);scope.addProperty("runtime_verified",false);write(output.resolve("scope.json"),scope);
        Path journal=output.resolve("results.jsonl");
        if(Files.isRegularFile(journal)) {
            byte[] bytes=Files.readAllBytes(journal);if(bytes.length>0&&bytes[bytes.length-1]!=10){int begin=bytes.length-1;while(begin>=0&&bytes[begin]!=10)begin--;begin++;
                try{JsonParser.parseString(new String(bytes,begin,bytes.length-begin,StandardCharsets.UTF_8)).getAsJsonObject();}
                catch(RuntimeException e){Files.write(output.resolve("truncated-tail-"+System.currentTimeMillis()+".txt"),Arrays.copyOfRange(bytes,begin,bytes.length));Files.write(journal,Arrays.copyOf(bytes,begin));}
            }
            try(BufferedReader reader=Files.newBufferedReader(journal,StandardCharsets.UTF_8)){String line;while((line=reader.readLine())!=null)try{JsonObject r=JsonParser.parseString(line).getAsJsonObject();if(reusable(r))completed.put(number(r.get("address").getAsString()),r);}catch(Exception e){/* Invalid/incomplete records are retried, never treated as complete. */}}
        }
        int attempted=0,failures=0;progress(false,attempted,failures);
        boolean newline=false;if(Files.isRegularFile(journal)&&Files.size(journal)>0)try(RandomAccessFile previous=new RandomAccessFile(journal.toFile(),"r")){previous.seek(previous.length()-1);newline=previous.read()!=10;}
        try(BufferedWriter ledger=Files.newBufferedWriter(journal,StandardCharsets.UTF_8,StandardOpenOption.CREATE,StandardOpenOption.APPEND)) {
            if(newline){ledger.newLine();ledger.flush();}
            for(var entry:targets.entrySet()) {
                if(completed.containsKey(entry.getKey()))continue;monitor.checkCancelled();Function function=getFunctionAt(toAddr(hex(entry.getKey())));
                JsonObject record=base(entry.getValue(),function);Path dir=output.resolve(hex(entry.getKey())).resolve("attempt-"+System.currentTimeMillis());Files.createDirectories(dir);
                record.addProperty("artifact_directory",output.relativize(dir).toString().replace('\\','/'));record.addProperty("status","ir_incomplete");
                record.addProperty("all_returned_pcode_operations_saved",false);record.addProperty("all_returned_basic_blocks_saved",false);
                println("TERRARIA_HARD_IR_START "+hex(entry.getKey()));DecompInterface decompiler=new DecompInterface();long wall=System.nanoTime();
                try {
                    DecompileOptions options=new DecompileOptions();options.grabFromProgram(currentProgram);options.setMaxInstructions(maxInstructions);options.setMaxPayloadMBytes(256);
                    decompiler.setSimplificationStyle("firstpass");decompiler.toggleCCode(false);decompiler.toggleSyntaxTree(true);
                    if(!decompiler.setOptions(options)||!decompiler.openProgram(currentProgram))throw new Exception("Initialization failed: "+decompiler.getLastMessage());
                    long nativeStart=System.nanoTime();DecompileResults result=decompiler.decompileFunction(function,timeout,monitor);
                    record.addProperty("decompile_and_java_decode_ms",(System.nanoTime()-nativeStart)/1000000);record.addProperty("decompile_completed",result.decompileCompleted());record.addProperty("error",result.getErrorMessage());
                    if(result.decompileCompleted()&&result.getHighFunction()!=null){artifacts(result.getHighFunction(),dir,record,entry.getKey(),ends.get(entry.getKey()));record.addProperty("status","ir_complete");}
                    else record.addProperty("partial_tree_exported",false);
                }catch(Exception e){record.addProperty("error",e.toString());record.addProperty("status","ir_incomplete");record.addProperty("all_returned_pcode_operations_saved",false);record.addProperty("all_returned_basic_blocks_saved",false);record.addProperty("partial_artifacts_valid_as_complete",false);}
                finally{decompiler.dispose();}
                record.addProperty("elapsed_ms",(System.nanoTime()-wall)/1000000);record.addProperty("finished_utc",Instant.now().toString());
                write(dir.resolve("result.json"),record);ledger.write(gson.toJson(record));ledger.newLine();ledger.flush();attempted++;
                if("ir_complete".equals(record.get("status").getAsString()))completed.put(entry.getKey(),record);else failures++;
                progress(false,attempted,failures);println("TERRARIA_HARD_IR_RESULT "+hex(entry.getKey())+" "+record.get("status"));monitor.checkCancelled();
            }
        }progress(true,attempted,failures);println("TERRARIA_HARD_IR_DONE complete="+completed.size()+"/"+targets.size());
    }
}
