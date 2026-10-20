// Serial bounded ELF range export; generated C is pseudocode, not original source.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import com.google.gson.*;
import java.io.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ApkNativeRangeExport extends GhidraScript {
    static final String PROFILE="apk-native-bounded-range-C-v1";
    static final String ENGINE="d64bd049b88d8d2f9452b92079705d4e95b71abb0aad018f596f143246f9f67a";
    static final int TIMEOUT=20,MAX_INS=100000,MAX_PAYLOAD=64;
    final Gson gson=new Gson();
    Path out;String manifestSha,sourceSha,elfSha;JsonObject identity;
    final Map<String,JsonObject> rows=new LinkedHashMap<>(),done=new LinkedHashMap<>();
    static void require(boolean v,String message)throws IOException{if(!v)throw new IOException(message);}
    static long num(JsonElement e){String s=e.getAsString();return s.startsWith("0x")?Long.parseUnsignedLong(s.substring(2),16):Long.parseLong(s);}
    static String hex(long n){return "0x"+Long.toHexString(n);}
    static String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    static String hash(Path p)throws Exception{
        MessageDigest d=MessageDigest.getInstance("SHA-256");
        try(InputStream in=Files.newInputStream(p)){byte[] b=new byte[65536];int n;while((n=in.read(b))!=-1)d.update(b,0,n);}
        return HexFormat.of().formatHex(d.digest());
    }
    Path artifact(String name)throws Exception{
        require(name.matches("[A-Za-z0-9_.-]+")&&!name.equals(".")&&!name.equals(".."),"Unsafe artifact name");
        Path p=out.resolve(name);require(!Files.isSymbolicLink(p),"Symlink artifact rejected");
        if(Files.exists(p))require(p.toRealPath().getParent().equals(out),"Artifact escaped output");
        return p;
    }
    void durable(Path p,byte[] data)throws Exception{
        try(FileChannel f=FileChannel.open(p,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE)){
            ByteBuffer b=ByteBuffer.wrap(data);while(b.hasRemaining())f.write(b);f.force(true);
        }
    }
    void durableJson(Path p,JsonObject data)throws Exception{durable(p,(gson.toJson(data)+"\n").getBytes(StandardCharsets.UTF_8));}
    void progress(String phase)throws Exception{
        JsonObject p=new JsonObject();p.addProperty("profile",PROFILE);p.addProperty("phase",phase);
        p.addProperty("total_manifest_rows",rows.size());p.addProperty("attempted_rows",done.size());
        p.addProperty("not_attempted_rows",rows.size()-done.size());p.addProperty("all_rows_attempted",done.size()==rows.size());
        p.addProperty("successful_C_rows",done.values().stream().filter(r->r.get("status").getAsString().equals("decompiled")).count());
        p.addProperty("semantic_equivalence_verified",false);p.addProperty("original_source_recovered",false);
        Path tmp=artifact("progress.tmp");Files.deleteIfExists(tmp);durableJson(tmp,p);
        try{Files.move(tmp,artifact("progress.json"),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}
        catch(AtomicMoveNotSupportedException e){Files.move(tmp,artifact("progress.json"),StandardCopyOption.REPLACE_EXISTING);}
    }
    void verifyArtifact(JsonObject result,JsonObject row)throws Exception{
        require(result.get("profile").getAsString().equals(PROFILE)&&result.get("manifest_sha256").getAsString().equals(manifestSha)
            &&result.get("script_sha256").getAsString().equals(sourceSha)&&result.get("engine_sha256").getAsString().equals(ENGINE)
            &&result.get("elf_sha256").getAsString().equals(elfSha),"Prior result identity mismatch");
        for(String k:List.of("address","end_exclusive","source_sha256","evidence_kind"))require(result.get(k).equals(row.get(k)),"Prior result range mismatch");
        String status=result.get("status").getAsString();require(Set.of("decompiled","decompile_failed","range_error").contains(status),"Unknown prior status");
        Path c=artifact("range_"+row.get("address").getAsString()+".c");
        if(status.equals("decompiled"))require(Files.isRegularFile(c)&&hash(c).equals(result.get("c_sha256").getAsString())
            &&Files.size(c)==result.get("c_bytes").getAsLong()&&result.get("actual_C_object_returned").getAsBoolean()
            &&result.get("decompile_completed").getAsBoolean()&&!result.get("timed_out").getAsBoolean(),"Prior C artifact invalid");
        else require(!Files.exists(c),"Non-success row has C artifact");
    }
    void loadJournal(Path journal)throws Exception{
        byte[] raw=Files.readAllBytes(journal);require(raw.length==0||raw[raw.length-1]=='\n',"Incomplete journal tail: preserve output; no automatic truncation");
        for(String line:new String(raw,StandardCharsets.UTF_8).split("\n")){
            if(line.isEmpty())continue;JsonObject commit=JsonParser.parseString(line).getAsJsonObject();String address=commit.get("address").getAsString();
            JsonObject row=rows.get(address);require(row!=null&&!done.containsKey(address),"Unknown or duplicate journal row");
            require(commit.get("result_file").getAsString().equals("range_"+address+".json"),"Unexpected result filename");
            Path file=artifact(commit.get("result_file").getAsString());require(hash(file).equals(commit.get("result_sha256").getAsString()),"Prior result hash mismatch");
            JsonObject result=JsonParser.parseString(Files.readString(file)).getAsJsonObject();verifyArtifact(result,row);done.put(address,result);
        }
    }
    JsonObject export(JsonObject row,DecompInterface dc)throws Exception{
        long start=num(row.get("address")),end=num(row.get("end_exclusive"));Address a=toAddr(start);AddressSet exact=new AddressSet(a,toAddr(end-1));
        JsonObject r=new JsonObject();r.addProperty("profile",PROFILE);r.addProperty("manifest_sha256",manifestSha);r.addProperty("script_sha256",sourceSha);
        r.addProperty("engine_sha256",ENGINE);r.addProperty("elf_sha256",elfSha);
        for(String key:List.of("address","end_exclusive","source_sha256","evidence_kind"))r.add(key,row.get(key));
        r.addProperty("timeout_seconds",TIMEOUT);r.addProperty("new_flow_overrides_applied",false);r.addProperty("new_NoReturn_annotations_applied",false);
        r.addProperty("normal_decompile_action",true);r.addProperty("semantic_equivalence_verified",false);r.addProperty("decompiler_invoked",false);
        int tx=currentProgram.startTransaction("Disposable bounded range export");
        try{
            Function function=getFunctionAt(a);
            Iterator<Function> overlapping=currentProgram.getFunctionManager().getFunctionsOverlapping(exact);
            while(overlapping.hasNext()){Function f=overlapping.next();
                require(f.getEntryPoint().equals(a)&&f.getBody().equals(exact),"Existing overlapping function/body conflict");}
            if(function!=null)require(function.getBody().equals(exact)&&!function.hasNoReturn()&&!function.isThunk(),"Existing function model conflict");
            require(end-start<=4L*MAX_INS,"Range exceeds configured instruction budget; not disassembled");
            for(long pc=start;pc<end;pc+=4){
                monitor.checkCancelled();Instruction ins=currentProgram.getListing().getInstructionAt(toAddr(pc));
                if(ins==null){DisassembleCommand cmd=new DisassembleCommand(toAddr(pc),new AddressSet(toAddr(pc),toAddr(pc+3)),false);
                    require(cmd.applyTo(currentProgram,monitor),"Bounded disassembly failed");ins=currentProgram.getListing().getInstructionAt(toAddr(pc));}
                require(ins!=null&&ins.getLength()==4&&ins.getFlowOverride()==FlowOverride.NONE,"Invalid instruction or existing flow override");
            }
            if(function==null)function=currentProgram.getFunctionManager().createFunction("apk_range_"+Long.toHexString(start),a,exact,SourceType.ANALYSIS);
            require(function!=null&&function.getBody().equals(exact),"Exact function creation failed");
            r.addProperty("original_instruction_bytes_verified",end-start);r.addProperty("bounded_instruction_count",(end-start)/4);
            dc.flushCache();r.addProperty("decompiler_invoked",true);long before=System.nanoTime();
            DecompileResults result=dc.decompileFunction(function,TIMEOUT,monitor);
            r.addProperty("elapsed_seconds",(System.nanoTime()-before)/1e9);r.addProperty("timed_out",result.isTimedOut());
            r.addProperty("decompile_completed",result.decompileCompleted());r.addProperty("actual_C_object_returned",result.getDecompiledFunction()!=null);
            r.addProperty("message",result.getErrorMessage());
            if(result.decompileCompleted()&&!result.isTimedOut()&&result.getDecompiledFunction()!=null){
                String body=result.getDecompiledFunction().getC();require(body!=null&&!body.isBlank(),"Empty C body");
                byte[] c=("/* GHIDRA PSEUDOCODE; NOT ORIGINAL SOURCE. Profile: "+PROFILE+"; ELF VA "+hex(start)+".."+hex(end)+
                    "; exact input bytes checked; default imported types; native recovery may follow control flow beyond listing body; no semantic completeness proof. */\n"+body).getBytes(StandardCharsets.UTF_8);
                String filename="range_"+row.get("address").getAsString()+".c";durable(artifact(filename),c);
                r.addProperty("status","decompiled");r.addProperty("c_file",filename);r.addProperty("c_sha256",hash(c));r.addProperty("c_bytes",c.length);
            }else r.addProperty("status","decompile_failed");
        }catch(ghidra.util.exception.CancelledException e){throw e;}
        catch(Exception e){r.addProperty("status","range_error");r.addProperty("message",e.toString());}
        finally{currentProgram.endTransaction(tx,false);r.addProperty("transaction_rollback_requested",true);dc.flushCache();}
        return r;
    }
    public void run()throws Exception{
        String[] args=getScriptArgs();require(args.length>=5&&args.length<=7,"elf manifest manifest-sha own-source private-output [max_rows] [resume]");
        Path elf=Path.of(args[0]).toRealPath(),manifest=Path.of(args[1]).toRealPath(),source=Path.of(args[3]).toRealPath();
        require(source.getFileName().toString().equals("ApkNativeRangeExport.java"),"Wrong own source filename");
        manifestSha=hash(manifest);require(manifestSha.equals(args[2])&&manifestSha.matches("[0-9a-f]{64}"),"Manifest SHA mismatch");sourceSha=hash(source);
        JsonObject m=JsonParser.parseString(Files.readString(manifest)).getAsJsonObject();
        require(m.get("schema_version").getAsInt()==1&&m.get("profile").getAsString().equals(PROFILE),"Wrong manifest schema/profile");
        elfSha=hash(elf);require(m.get("elf_sha256").getAsString().equals(elfSha)&&m.get("engine_sha256").getAsString().equals(ENGINE),"Manifest binary/engine mismatch");
        require(elfSha.equalsIgnoreCase(currentProgram.getExecutableSHA256())&&currentProgram.getImageBase().getOffset()==0
            &&currentProgram.getLanguageID().toString().equals("AARCH64:LE:64:v8A"),"Program SHA/base/language mismatch");
        Path engine=Application.getOSFile("decompile.exe").toPath().toRealPath();require(hash(engine).equals(ENGINE),"Actual engine mismatch");
        JsonObject limits=m.getAsJsonObject("limits");require(limits.get("timeout_seconds").getAsInt()==TIMEOUT
            &&limits.get("max_instructions").getAsInt()==MAX_INS&&limits.get("max_payload_mb").getAsInt()==MAX_PAYLOAD,"Manifest limits mismatch");
        byte[] bytes=Files.readAllBytes(elf);ByteBuffer b=ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        require(bytes.length>=64&&b.getInt(0)==0x464c457f&&bytes[4]==2&&bytes[5]==1&&b.getShort(18)==183,"Not LE ELF64 AArch64");
        long ph=b.getLong(32);int stride=Short.toUnsignedInt(b.getShort(54)),count=Short.toUnsignedInt(b.getShort(56));
        require(ph>=0&&ph<=bytes.length&&stride>=56&&(long)stride*count<=bytes.length-ph,"ELF program-header bounds");
        List<long[]> segments=new ArrayList<>();
        for(int i=0;i<count;i++){int p=Math.toIntExact(ph+(long)i*stride);if(b.getInt(p)==1&&(b.getInt(p+4)&1)!=0)
            segments.add(new long[]{b.getLong(p+8),b.getLong(p+16),b.getLong(p+32)});}
        long previousEnd=-1;
        for(JsonElement e:m.getAsJsonArray("rows")){
            JsonObject row=e.getAsJsonObject();long a=num(row.get("address")),z=num(row.get("end_exclusive")),off=num(row.get("file_offset"));
            require(a>=0&&a%4==0&&z>a&&z%4==0&&a>=previousEnd,"Bad/overlapping work range");
            require(row.get("address").getAsString().equals(hex(a))&&row.get("end_exclusive").getAsString().equals(hex(z)),"Noncanonical address");
            require(Set.of("fde","defined_function_symbol").contains(row.get("evidence_kind").getAsString()),"Unsupported range evidence");
            require(off>=0&&off<=bytes.length&&z-a<=bytes.length-off,"File range bounds");int mapped=0;
            for(long[] s:segments)if(a>=s[1]&&a-s[1]<=s[2]&&z-a<=s[2]-(a-s[1])&&off==s[0]+a-s[1])mapped++;
            require(mapped==1,"Range not uniquely mapped to executable PT_LOAD");
            byte[] expected=Arrays.copyOfRange(bytes,Math.toIntExact(off),Math.toIntExact(off+z-a)),actual=new byte[expected.length];
            require(hash(expected).equals(row.get("source_sha256").getAsString())&&currentProgram.getMemory().getBytes(toAddr(a),actual)==actual.length
                &&Arrays.equals(actual,expected),"Original/source/program byte mismatch");
            require(rows.put(hex(a),row)==null,"Duplicate work address");previousEnd=z;
        }
        require(!rows.isEmpty(),"Empty manifest");int max=rows.size();boolean resume=false;
        for(int i=5;i<args.length;i++)if(args[i].equals("resume")){require(!resume,"Duplicate resume");resume=true;}else{max=Integer.parseInt(args[i]);require(max>0,"Positive max_rows required");}
        Path requested=Path.of(args[4]).toAbsolutePath().normalize();require(requested.getParent()!=null&&Files.isDirectory(requested.getParent()),"Existing private output parent required");
        require(!requested.startsWith(source.getParent())&&!elf.startsWith(requested)&&!manifest.startsWith(requested),"Output must be separate from tools/inputs");
        if(source.getParent().getFileName().toString().equals("tools"))require(!requested.startsWith(source.getParent().getParent()),"Output must stay outside source workspace");
        if(!resume)Files.createDirectory(requested);else require(Files.isDirectory(requested)&&!Files.isSymbolicLink(requested),"Resume output missing/symlink");
        out=requested.toRealPath();require(out.equals(requested),"Output path redirects through symlink/junction");
        identity=new JsonObject();identity.addProperty("profile",PROFILE);identity.addProperty("manifest_sha256",manifestSha);identity.addProperty("script_sha256",sourceSha);
        identity.addProperty("engine_sha256",ENGINE);identity.addProperty("elf_sha256",elfSha);identity.addProperty("image_base",0);
        identity.addProperty("language",currentProgram.getLanguageID().toString());identity.addProperty("compiler_spec",currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        identity.addProperty("ghidra_version",Application.getApplicationVersion());
        identity.addProperty("timeout_seconds",TIMEOUT);identity.addProperty("max_instructions",MAX_INS);identity.addProperty("max_payload_mb",MAX_PAYLOAD);
        identity.addProperty("normal_decompile_action",true);identity.addProperty("default_imported_types",true);identity.addProperty("workers",1);
        try(FileChannel lockChannel=FileChannel.open(artifact("run.lock"),StandardOpenOption.CREATE,StandardOpenOption.WRITE);FileLock lock=lockChannel.tryLock()){
            require(lock!=null,"Exporter already owns output");Path journalPath=artifact("journal.jsonl");
            if(resume){require(JsonParser.parseString(Files.readString(artifact("run.json"))).equals(identity),"Resume run identity mismatch");loadJournal(journalPath);}
            else{durableJson(artifact("run.json"),identity);durable(artifact("manifest.input.json"),Files.readAllBytes(manifest));durable(artifact("ApkNativeRangeExport.java"),Files.readAllBytes(source));durable(journalPath,new byte[0]);}
            require(hash(artifact("manifest.input.json")).equals(manifestSha)&&hash(artifact("ApkNativeRangeExport.java")).equals(sourceSha),"Stored run inputs changed");
            try(FileChannel journal=FileChannel.open(journalPath,StandardOpenOption.WRITE,StandardOpenOption.APPEND)){
                DecompInterface dc=new DecompInterface();try{
                    DecompileOptions options=new DecompileOptions();options.setMaxInstructions(MAX_INS);options.setMaxPayloadMBytes(MAX_PAYLOAD);
                    require(dc.setSimplificationStyle("decompile")&&dc.toggleCCode(true)&&dc.toggleSyntaxTree(false)&&dc.setOptions(options),"Decompiler setup rejected");
                    require(dc.openProgram(currentProgram)&&dc.setOptions(options),"Program/options rejected");int attempted=0;progress("running");
                    for(Map.Entry<String,JsonObject> item:rows.entrySet()){
                        if(done.containsKey(item.getKey()))continue;if(attempted>=max)break;monitor.checkCancelled();
                        String base="range_"+item.getKey();require(!Files.exists(artifact(base+".json"))&&!Files.exists(artifact(base+".c")),"Unjournaled artifact preserved; use new output or investigate explicitly");
                        JsonObject result=export(item.getValue(),dc);verifyArtifact(result,item.getValue());Path resultPath=artifact(base+".json");durableJson(resultPath,result);
                        JsonObject commit=new JsonObject();commit.addProperty("address",item.getKey());commit.addProperty("result_file",resultPath.getFileName().toString());commit.addProperty("result_sha256",hash(resultPath));
                        ByteBuffer line=ByteBuffer.wrap((gson.toJson(commit)+"\n").getBytes(StandardCharsets.UTF_8));while(line.hasRemaining())journal.write(line);journal.force(true);
                        done.put(item.getKey(),result);attempted++;progress("running");
                    }
                    progress(done.size()==rows.size()?"all_rows_attempted":"bounded_subset_returned");
                }finally{dc.dispose();}
            }
        }
    }
}
