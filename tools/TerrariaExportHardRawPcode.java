// Complete instruction-level raw SLEIGH P-code; no native decompiler, DB mutation, C or SSA.
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.lang.SleighLanguageDescription;
import com.google.gson.*;
import java.nio.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.io.*;
import java.time.Instant;
import java.util.*;
import java.util.zip.GZIPOutputStream;

public class TerrariaExportHardRawPcode extends GhidraScript {
    private static final String PROFILE="hard20-raw-sleigh-fde-plus-proven-islands-v1";
    private static final String BASE="bounded-fde-terminal-calls-signatures-v3";
    private static final String ELF_SHA="9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5";
    private final Gson gson=new Gson();private Path output;private byte[] elf;
    private String baselineHash,providerHash,flowHash,reviewHash,listingFingerprint,programExeHash;
    private final List<long[]> loads=new ArrayList<>();
    private final Map<Long,JsonObject> targets=new LinkedHashMap<>(),successes=new LinkedHashMap<>();
    private final Map<Long,TreeSet<Long>> islands=new HashMap<>();
    private static long num(String s){return Long.parseUnsignedLong(s.replace("0x",""),16);}
    private static String hex(long n){return "0x"+Long.toHexString(n);}
    private static java.security.MessageDigest digest()throws Exception{return java.security.MessageDigest.getInstance("SHA-256");}
    private static String hash(Path p)throws Exception{var h=digest();try(InputStream in=Files.newInputStream(p)){byte[] b=new byte[1048576];int n;while((n=in.read(b))>0)h.update(b,0,n);}return HexFormat.of().formatHex(h.digest());}
    private void json(Path p,JsonObject r)throws Exception{Files.writeString(p,gson.toJson(r),StandardCharsets.UTF_8);}
    private byte[] original(long address)throws Exception {
        long found=-1;for(long[] s:loads)if(s[0]<=address&&address+4<=s[1]&&(s[3]&1)!=0){if(found!=-1)throw new Exception("Ambiguous executable PT_LOAD");found=s[2]+address-s[0];}
        if(found<0||found+4>elf.length)throw new Exception("VA outside original executable bytes: "+hex(address));return Arrays.copyOfRange(elf,(int)found,(int)found+4);
    }
    private TreeSet<Long> addresses(long start,long end) {
        TreeSet<Long> all=new TreeSet<>();for(long va=start;va<end;va+=4)all.add(va);all.addAll(islands.getOrDefault(start,new TreeSet<>()));return all;
    }
    private JsonObject node(Varnode n) {
        if(n==null)return null;JsonObject r=new JsonObject();r.addProperty("space",n.getAddress().getAddressSpace().getName());r.addProperty("offset",hex(n.getOffset()));
        r.addProperty("size",n.getSize());r.addProperty("constant",n.isConstant());r.addProperty("register",n.isRegister());r.addProperty("unique",n.isUnique());
        if(n.isRegister()){var reg=currentProgram.getRegister(n.getAddress(),n.getSize());if(reg!=null)r.addProperty("register_name",reg.getName());}return r;
    }
    private boolean cached(JsonObject r)throws Exception {
        if(!"raw_ir_complete".equals(r.get("status").getAsString()))return false;
        for(var e:Map.of("profile",PROFILE,"baseline_sha256",baselineHash,"language_provider_sha256",providerHash,"flow_islands_sha256",flowHash,"flow_review_sha256",reviewHash,"listing_bytes_overrides_sha256",listingFingerprint).entrySet())if(!r.has(e.getKey())||!e.getValue().equals(r.get(e.getKey()).getAsString()))return false;
        JsonObject target=targets.get(num(r.get("address").getAsString()));if(target==null)return false;for(String key:List.of("address","method","image","compiler_end_exclusive"))if(!target.get(key).equals(r.get(key)))return false;
        Path file=output.resolve(r.get("file").getAsString()).normalize();return file.startsWith(output)&&Files.isRegularFile(file)&&file.toRealPath().startsWith(output.toRealPath())&&Files.size(file)==r.get("bytes").getAsLong()&&hash(file).equals(r.get("sha256").getAsString());
    }
    private void progress(boolean finished,int attempted)throws Exception {
        JsonObject r=new JsonObject();r.addProperty("profile",PROFILE);r.addProperty("finished",finished);r.addProperty("targets",20);r.addProperty("complete",successes.size());r.addProperty("not_complete",20-successes.size());r.addProperty("attempted_this_run",attempted);r.addProperty("all_targets_complete",successes.size()==20);r.addProperty("updated_utc",Instant.now().toString());
        Path tmp=output.resolve("progress.json.tmp");json(tmp,r);Files.move(tmp,output.resolve("progress.json"),StandardCopyOption.REPLACE_EXISTING);
    }
    public void run()throws Exception {
        String[] args=getScriptArgs();if(args.length!=2)throw new Exception("Args: full-v3-baseline.jsonl lab/hard-functions-raw-ir");
        Path baseline=Path.of(args[0]);output=Path.of(args[1]).toAbsolutePath().normalize();if(!output.getFileName().toString().equals("hard-functions-raw-ir"))throw new Exception("Use separate hard-functions-raw-ir directory");Files.createDirectories(output);Path lab=output.getParent();
        if(currentProgram.getImageBase().getOffset()!=0||!currentProgram.getLanguageID().toString().equals("AARCH64:LE:64:v8A"))throw new Exception("Requires ARM64 LE v8A base0");
        baselineHash=hash(baseline);Path source=lab.resolve("native/libil2cpp.so");if(!ELF_SHA.equals(hash(source)))throw new Exception("Original ELF SHA mismatch");elf=Files.readAllBytes(source);
        ByteBuffer b=ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);if(elf[0]!=0x7f||elf[1]!='E'||elf[2]!='L'||elf[3]!='F'||elf[4]!=2||elf[5]!=1||b.getShort(18)!=183)throw new Exception("Invalid ELF64 ARM64 LE");
        long ph=b.getLong(32);int size=Short.toUnsignedInt(b.getShort(54)),count=Short.toUnsignedInt(b.getShort(56));if(size<56||ph<0||ph+(long)size*count>elf.length)throw new Exception("Invalid ELF headers");
        for(int i=0;i<count;i++){int at=Math.toIntExact(ph+(long)i*size);if(b.getInt(at)==1){long off=b.getLong(at+8),va=b.getLong(at+16),len=b.getLong(at+32);if(off<0||len<0||off+len>elf.length)throw new Exception("Invalid LOAD bounds");loads.add(new long[]{va,va+len,off,Integer.toUnsignedLong(b.getInt(at+4))});}}
        Map<Long,Long> ends=new HashMap<>();for(String line:Files.readAllLines(lab.resolve("native/unwind-function-ranges.tsv"))){String[] row=line.split("\t");ends.put(num(row[0]),num(row[1]));}if(ends.size()!=123152)throw new Exception("Incomplete FDE catalogue");
        Set<Long> seen=new HashSet<>();int total=0;try(BufferedReader reader=Files.newBufferedReader(baseline,StandardCharsets.UTF_8)){String line;while((line=reader.readLine())!=null){JsonObject r=JsonParser.parseString(line).getAsJsonObject();long va=num(r.get("address").getAsString());total++;if(!seen.add(va)||!BASE.equals(r.get("profile").getAsString())||r.get("image_base").getAsInt()!=0||!Objects.equals(ends.get(va),num(r.get("compiler_end_exclusive").getAsString())))throw new Exception("Invalid baseline identity");if(!"decompiled".equals(r.get("status").getAsString()))targets.put(va,r);}}
        if(total!=93990||targets.size()!=20)throw new Exception("Expected93990 baseline with20 failures");
        Path flowPath=lab.resolve("native/flow-islands.json"),reviewPath=lab.resolve("native/flow-islands-hard20-review.json");flowHash=hash(flowPath);reviewHash=hash(reviewPath);
        JsonObject review=JsonParser.parseString(Files.readString(reviewPath)).getAsJsonObject();if(!baselineHash.equals(review.get("baseline_sha256").getAsString())||!flowHash.equals(review.get("flow_islands_sha256").getAsString()))throw new Exception("Flow review source mismatch");
        int associations=0;for(JsonElement element:JsonParser.parseString(Files.readString(flowPath)).getAsJsonArray()){JsonObject r=element.getAsJsonObject();long start=num(r.get("fde_start").getAsString());if(!targets.containsKey(start)||!r.get("proven_encoded_path").getAsBoolean())continue;if(!r.get("returns_to_origin_plus_four").getAsBoolean())throw new Exception("Unexpected island shape");associations++;for(JsonElement step:r.getAsJsonArray("steps")){JsonObject instruction=step.getAsJsonObject();long va=num(instruction.get("address").getAsString());if(va%4!=0||!HexFormat.of().formatHex(original(va)).equals(instruction.get("raw_bytes").getAsString()))throw new Exception("Island bytes mismatch");islands.computeIfAbsent(start,k->new TreeSet<>()).add(va);}}
        if(associations!=review.get("out_and_back_associations").getAsInt())throw new Exception("Island associations mismatch");
        SleighLanguageDescription description=(SleighLanguageDescription)currentProgram.getLanguage().getLanguageDescription();
        Path definitions=description.getDefsFile().getFile(false).toPath().toRealPath(),providerDir=definitions.getParent();JsonArray providerFiles=new JsonArray();var providerDigest=digest();
        try(var files=Files.list(providerDir)){for(Path p:files.filter(Files::isRegularFile).sorted().toList()){String name=p.getFileName().toString();if(!(name.endsWith(".sla")||name.endsWith(".slaspec")||name.endsWith(".sinc")||name.endsWith(".pspec")||name.endsWith(".cspec")||name.endsWith(".ldefs")))continue;String h=hash(p);JsonObject entry=new JsonObject();entry.addProperty("file",p.toString());entry.addProperty("sha256",h);entry.addProperty("bytes",Files.size(p));providerFiles.add(entry);providerDigest.update((name+"\t"+h+"\n").getBytes(StandardCharsets.UTF_8));}}
        providerHash=HexFormat.of().formatHex(providerDigest.digest());programExeHash=currentProgram.getExecutableSHA256();if(programExeHash!=null&&!programExeHash.isBlank()&&!programExeHash.equalsIgnoreCase(ELF_SHA))throw new Exception("Program imported ELF SHA mismatch");
        var fingerprint=digest();for(long start:targets.keySet())for(long va:addresses(start,ends.get(start))){monitor.checkCancelled();Address address=toAddr(hex(va));byte[] memory=new byte[4];if(currentProgram.getMemory().getBytes(address,memory)!=4||!Arrays.equals(memory,original(va)))throw new Exception("Program/source bytes differ at "+hex(va));Instruction instruction=getInstructionAt(address);fingerprint.update((hex(va)+":"+HexFormat.of().formatHex(memory)+":"+(instruction==null?"PSEUDO":instruction.getFlowOverride())+"\n").getBytes(StandardCharsets.UTF_8));}listingFingerprint=HexFormat.of().formatHex(fingerprint.digest());
        JsonObject scope=new JsonObject();scope.addProperty("profile",PROFILE);scope.addProperty("baseline_sha256",baselineHash);scope.addProperty("elf_sha256",ELF_SHA);scope.addProperty("program_executable_sha256",programExeHash);scope.addProperty("flow_islands_sha256",flowHash);scope.addProperty("flow_review_sha256",reviewHash);scope.addProperty("listing_bytes_overrides_sha256",listingFingerprint);scope.addProperty("language_provider_sha256",providerHash);scope.add("language_provider_files",providerFiles);
        scope.addProperty("language",currentProgram.getLanguageID().toString());scope.addProperty("compiler_spec",currentProgram.getCompilerSpec().getCompilerSpecID().toString());scope.addProperty("actual_sla_file",description.getSlaFile().getAbsolutePath());scope.addProperty("actual_processor_spec",description.getSpecFile().getAbsolutePath());scope.addProperty("language_definitions",definitions.toString());scope.addProperty("native_decompiler_used",false);scope.addProperty("database_modified",false);scope.addProperty("runtime_verified",false);scope.addProperty("scope","Every aligned4byte slot within20 FDEs plus34 proven out-and-back associations; raw Instruction.getPcode(false) without applying flow overrides. Not C, HighFunction, SSA, reachability or complete semantic CFG. Provider file manifest includes all definitions in the selected language directory, not a minimal include dependency graph.");json(output.resolve("scope.json"),scope);
        Path journal=output.resolve("results.jsonl");if(Files.isRegularFile(journal)){byte[] old=Files.readAllBytes(journal);if(old.length>0&&old[old.length-1]!=10){int from=old.length-1;while(from>=0&&old[from]!=10)from--;from++;try{JsonParser.parseString(new String(old,from,old.length-from,StandardCharsets.UTF_8)).getAsJsonObject();}catch(RuntimeException e){Files.write(output.resolve("truncated-tail-"+System.currentTimeMillis()+".txt"),Arrays.copyOfRange(old,from,old.length));Files.write(journal,Arrays.copyOf(old,from));}}try(BufferedReader reader=Files.newBufferedReader(journal)){String line;while((line=reader.readLine())!=null)try{JsonObject r=JsonParser.parseString(line).getAsJsonObject();if(cached(r))successes.put(num(r.get("address").getAsString()),r);}catch(Exception e){/* incomplete/stale attempts are retried */}}}
        boolean newline=false;if(Files.isRegularFile(journal)&&Files.size(journal)>0)try(RandomAccessFile prior=new RandomAccessFile(journal.toFile(),"r")){prior.seek(prior.length()-1);newline=prior.read()!=10;}
        int attempted=0;progress(false,attempted);PseudoDisassembler pseudo=new PseudoDisassembler(currentProgram);
        try(BufferedWriter ledger=Files.newBufferedWriter(journal,StandardCharsets.UTF_8,StandardOpenOption.CREATE,StandardOpenOption.APPEND)) {
            if(newline){ledger.newLine();ledger.flush();}
            for(var target:targets.entrySet()) {
                if(successes.containsKey(target.getKey()))continue;monitor.checkCancelled();long start=target.getKey(),end=ends.get(start);JsonObject result=new JsonObject();for(String key:List.of("address","method","image","compiler_end_exclusive"))result.add(key,target.getValue().get(key));
                for(String key:List.of("profile","baseline_sha256","elf_sha256","program_executable_sha256","flow_islands_sha256","flow_review_sha256","listing_bytes_overrides_sha256","language_provider_sha256","language","compiler_spec"))result.add(key,scope.get(key));
                result.addProperty("started_utc",Instant.now().toString());result.addProperty("native_decompiler_used",false);result.addProperty("database_modified",false);result.addProperty("canonical_ledger_modified",false);result.addProperty("raw_pcode_includes_overrides",false);result.addProperty("valid_C",false);result.addProperty("high_function_or_SSA",false);result.addProperty("complete_semantic_CFG_proven",false);result.addProperty("runtime_verified",false);
                Path dir=output.resolve(hex(start)).resolve("attempt-"+System.currentTimeMillis());Files.createDirectories(dir);Path file=dir.resolve("raw-pcode.jsonl.gz");long instructions=0,operations=0,gaps=0,pseudoCount=0,computedControls=0;var sourceDigest=digest();long began=System.nanoTime();
                println("TERRARIA_RAW_IR_START "+hex(start));
                try(BufferedWriter writer=new BufferedWriter(new OutputStreamWriter(new GZIPOutputStream(Files.newOutputStream(file),65536),StandardCharsets.UTF_8),65536)) {
                    for(long va:addresses(start,end)) {
                        monitor.checkCancelled();Address address=toAddr(hex(va));byte[] bytes=original(va),memory=new byte[4];if(currentProgram.getMemory().getBytes(address,memory)!=4||!Arrays.equals(bytes,memory))throw new Exception("Source bytes changed at "+hex(va));
                        sourceDigest.update(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(va).array());sourceDigest.update(bytes);
                        JsonObject row=new JsonObject();row.addProperty("ordinal",instructions++);row.addProperty("address",hex(va));row.addProperty("raw_bytes",HexFormat.of().formatHex(bytes));row.addProperty("outside_fde",va<start||va>=end);
                        try {
                            Instruction instruction=getInstructionAt(address);boolean synthetic=instruction==null;if(synthetic){instruction=pseudo.disassemble(address,bytes);pseudoCount++;}if(instruction==null||instruction.getLength()!=4)throw new Exception("Missing/non4byte ARM64 instruction");
                            row.addProperty("decode_source",synthetic?"public_PseudoDisassembler_no_DB_write":"existing_listing");row.addProperty("instruction",instruction.toString());row.addProperty("flow_override_recorded_not_applied",instruction.getFlowOverride().toString());row.addProperty("listing_flow_type_may_include_override",instruction.getFlowType().toString());
                            PcodeOp[] pcode=instruction.getPcode(false);JsonArray ops=new JsonArray();for(int i=0;i<pcode.length;i++){PcodeOp op=pcode[i];JsonObject item=new JsonObject();item.addProperty("ordinal",i);item.addProperty("opcode",op.getOpcode());item.addProperty("mnemonic",op.getMnemonic());item.addProperty("text",op.toString());item.addProperty("sequence_address",op.getSeqnum().getTarget().toString());item.addProperty("sequence_time",op.getSeqnum().getTime());item.add("output",node(op.getOutput()));JsonArray inputs=new JsonArray();for(int j=0;j<op.getNumInputs();j++)inputs.add(node(op.getInput(j)));item.add("inputs",inputs);ops.add(item);if(op.getOpcode()==PcodeOp.BRANCHIND||op.getOpcode()==PcodeOp.CALLIND||op.getOpcode()==PcodeOp.RETURN)computedControls++;}row.add("raw_pcode",ops);operations+=pcode.length;row.addProperty("decode_complete",true);
                        }catch(Exception e){gaps++;row.addProperty("decode_complete",false);row.addProperty("error",e.toString());}
                        writer.write(gson.toJson(row));writer.newLine();
                    }
                }catch(Exception e){result.addProperty("export_error",e.toString());gaps++;}
                result.addProperty("instructions",instructions);result.addProperty("fde_instructions",(end-start)/4);result.addProperty("island_instructions",islands.getOrDefault(start,new TreeSet<>()).size());result.addProperty("raw_pcode_operations",operations);result.addProperty("decode_or_export_gaps",gaps);result.addProperty("pseudo_disassembled_instructions",pseudoCount);result.addProperty("unresolved_computed_control_operations",computedControls);result.addProperty("computed_control_targets_resolved",false);
                result.addProperty("instruction_sequence_source_sha256",HexFormat.of().formatHex(sourceDigest.digest()));result.addProperty("file",output.relativize(file).toString().replace('\\','/'));result.addProperty("bytes",Files.size(file));result.addProperty("sha256",hash(file));result.addProperty("elapsed_ms",(System.nanoTime()-began)/1000000);result.addProperty("finished_utc",Instant.now().toString());
                result.addProperty("status",gaps==0&&instructions==(end-start)/4+islands.getOrDefault(start,new TreeSet<>()).size()?"raw_ir_complete":"raw_ir_incomplete");json(dir.resolve("result.json"),result);ledger.write(gson.toJson(result));ledger.newLine();ledger.flush();attempted++;if("raw_ir_complete".equals(result.get("status").getAsString()))successes.put(start,result);progress(false,attempted);println("TERRARIA_RAW_IR_RESULT "+hex(start)+" "+result.get("status"));monitor.checkCancelled();
            }
        }progress(true,attempted);println("TERRARIA_RAW_IR_DONE complete="+successes.size()+"/20");
    }
}
