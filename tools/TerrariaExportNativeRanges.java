// Separate, resumable native-range export. Does not modify the Program.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.util.DecompilerConcurrentQ;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.CancelledException;
import generic.concurrent.GThreadPool;
import com.google.gson.*;
import java.nio.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.io.*;
import java.security.MessageDigest;
import java.util.*;

public class TerrariaExportNativeRanges extends GhidraScript {
    static final String MODEL="bounded-fde-terminal-calls-signatures-v3";
    static final String PROFILE="native-ranges-readonly-v3-journal-1";
    static final String ELF_SHA="9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5";
    static final String TITLE="NATIVE RANGE PSEUDOCODE; NOT ORIGINAL SOURCE";
    static final int TOTAL=29162, BATCH=4096, MAX_INSTRUCTIONS=100000;
    final Gson gson=new Gson();
    final Map<Long,Work> targets=new LinkedHashMap<>();
    final Map<Long,JsonObject> completed=new LinkedHashMap<>();
    Path out,lab;int timeout=15,resumed=0;
    JsonObject manifest;
    FileOutputStream journalFile;BufferedWriter journal;
    volatile Throwable commitFailure;
    Counter counters=new Counter();
    class Work {
        long address,end;Function function;JsonObject evidence;String name,sourceSha,header,baseFile;
        long size(){return end-address;}
    }
    static long number(String hex){return Long.parseUnsignedLong(hex.replace("0x",""),16);}
    static String hex(long n){return "0x"+Long.toHexString(n);}
    static String safe(String s){s=s.replaceAll("[^A-Za-z0-9_.-]","_");return s.isBlank()||s.equals(".")||s.equals("..")?"_":s;}
    static String comment(String s){return s.replace("*/","* /").replace("\r"," ").replace("\n"," ");}
    static String hash(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    static String hash(Path file)throws Exception {
        MessageDigest d=MessageDigest.getInstance("SHA-256");
        try(InputStream in=Files.newInputStream(file)){byte[] b=new byte[65536];int n;while((n=in.read(b))!=-1)d.update(b,0,n);}
        return HexFormat.of().formatHex(d.digest());
    }
    void atomic(Path destination,String text)throws IOException {
        Files.createDirectories(destination.getParent());
        Path temp=Files.createTempFile(destination.getParent(),destination.getFileName()+".",".tmp");
        Files.writeString(temp,text,StandardCharsets.UTF_8);
        FileSystemException first=null;
        for(int attempt=0;attempt<10;attempt++) {
            try {
                try{Files.move(temp,destination,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}
                catch(AtomicMoveNotSupportedException e){Files.move(temp,destination,StandardCopyOption.REPLACE_EXISTING);}
                return;
            } catch(FileSystemException e) {
                if(first==null)first=e;else first.addSuppressed(e);
                if(attempt==9)throw first; // Original error retained; old destination and durable journal survive.
                try{Thread.sleep(attempt==0?50:100);}
                catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new IOException("Interrupted retrying atomic artifact move",interrupted);}
            }
        }
        throw new IOException("Unreachable atomic move retry state");
    }
    Path confined(String relative)throws IOException {
        if(relative.isBlank())throw new IOException("Empty artifact path");
        Path p=out.resolve(relative).normalize();
        if(!p.startsWith(out)||p.equals(out))throw new IOException("Unconfined native export path");
        Path parent=p.getParent();Files.createDirectories(parent);
        if(!parent.toRealPath().startsWith(out.toRealPath()))throw new IOException("Artifact parent escapes via symlink");
        if(Files.exists(p)&&!p.toRealPath().startsWith(out.toRealPath()))throw new IOException("Artifact escapes via symlink");
        return p;
    }
    synchronized void progress(boolean finished,String phase,String error)throws IOException {
        Counter count=counters;JsonObject p=new JsonObject();p.addProperty("finished",finished);p.addProperty("phase",phase);
        p.addProperty("profile",PROFILE);p.addProperty("model",MODEL);p.addProperty("workers",4);p.addProperty("batch_size",BATCH);
        p.addProperty("total",TOTAL);p.addProperty("processed",completed.size());p.addProperty("completed",completed.size());
        p.addProperty("decompiled",count.good);p.addProperty("failed",count.failed);p.addProperty("missing",count.missing);
        p.addProperty("export_error",count.errors);p.addProperty("resumed",resumed);p.addProperty("timeout_seconds",timeout);
        p.addProperty("max_instructions",MAX_INSTRUCTIONS);p.addProperty("error",error);
        atomic(out.resolve("progress.json"),gson.toJson(p)+"\n");
    }
    class Counter {int good,failed,missing,errors;}
    void increment(JsonObject r){switch(r.get("status").getAsString()) {
        case "decompiled":counters.good++;break;case "decompile_failed":counters.failed++;break;
        case "missing_function":counters.missing++;break;case "export_error":counters.errors++;break;
        default:throw new IllegalStateException("Unknown journal status");
    }}
    Counter count(){Counter c=new Counter();for(JsonObject r:completed.values())switch(r.get("status").getAsString()){
        case "decompiled":c.good++;break;case "decompile_failed":c.failed++;break;
        case "missing_function":c.missing++;break;case "export_error":c.errors++;break;default:throw new IllegalStateException("Unknown status");
    }return c;}
    String header(Work w){return "/* "+TITLE+"\n * Native function label: "+comment(w.name)+
        "\n * ELF VA: "+hex(w.address)+"; image base: 0\n * Compiler FDE end-exclusive: "+hex(w.end)+
        "\n * Analysis model: "+MODEL+"\n * Export profile: "+PROFILE+
        "\n * Classification: "+comment(w.evidence.get("category").getAsString())+
        "; roles: "+comment(gson.toJson(w.evidence.get("roles")))+
        "\n * Native bytes SHA256: "+w.sourceSha+"\n */\n";}
    void preflight(Path classification,Path baseline)throws Exception {
        if(currentProgram.getImageBase().getOffset()!=0||!currentProgram.getLanguageID().toString().equals("AARCH64:LE:64:v8A"))
            throw new Exception("Requires saved ARM64 v3 program at image base zero");
        Path nativeDir=classification.getParent();Path original=nativeDir.resolve("libil2cpp.so");
        if(!ELF_SHA.equals(hash(original)))throw new Exception("Original ELF SHA mismatch");
        String programSha=currentProgram.getExecutableSHA256();
        if(programSha!=null&&!programSha.isBlank()&&!ELF_SHA.equalsIgnoreCase(programSha))throw new Exception("Program executable SHA mismatch");
        Map<Long,Long> ends=new HashMap<>();
        for(String line:Files.readAllLines(nativeDir.resolve("unwind-function-ranges.tsv"),StandardCharsets.UTF_8)) {
            String[] columns=line.split("\t",-1);if(columns.length!=2)throw new Exception("Invalid FDE TSV");
            if(ends.put(number(columns[0]),number(columns[1]))!=null)throw new Exception("Duplicate FDE");
        }
        if(ends.size()!=123152)throw new Exception("Incomplete FDE catalog");
        String baselineSha=hash(baseline);Set<Long> managed=new HashSet<>();
        try(BufferedReader r=Files.newBufferedReader(baseline,StandardCharsets.UTF_8)) {
            String line;while((line=r.readLine())!=null){JsonObject o=JsonParser.parseString(line).getAsJsonObject();
                long a=number(o.get("address").getAsString()),end=number(o.get("compiler_end_exclusive").getAsString());
                if(!MODEL.equals(o.get("profile").getAsString())||o.get("image_base").getAsInt()!=0||
                   !Objects.equals(ends.get(a),end)||!managed.add(a))throw new Exception("Invalid complete model-v3 managed ledger");
            }
        }
        if(managed.size()!=93990)throw new Exception("Expected complete 93990-entry model-v3 managed ledger");
        if(!baselineSha.equals(hash(baseline)))throw new Exception("Managed ledger changed while reading; pass a stable baseline snapshot");
        byte[] elf=Files.readAllBytes(original);ByteBuffer buffer=ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);
        if(buffer.getInt(0)!=0x464c457f||buffer.getShort(18)!=183)throw new Exception("Invalid ELF64 AArch64");
        long phoff=buffer.getLong(32);int phsize=Short.toUnsignedInt(buffer.getShort(54)),phcount=Short.toUnsignedInt(buffer.getShort(56));
        List<long[]> loads=new ArrayList<>();
        for(int i=0;i<phcount;i++){int p=Math.toIntExact(phoff+(long)i*phsize);if(buffer.getInt(p)==1)
            loads.add(new long[]{buffer.getLong(p+8),buffer.getLong(p+16),buffer.getLong(p+32)});}
        JsonArray rows=JsonParser.parseString(Files.readString(classification,StandardCharsets.UTF_8)).getAsJsonArray();
        MessageDigest fingerprint=MessageDigest.getInstance("SHA-256");
        for(JsonElement element:rows) {
            monitor.checkCancelled();JsonObject row=element.getAsJsonObject();Work w=new Work();w.evidence=row;
            w.address=number(row.get("address").getAsString());w.end=number(row.get("end_exclusive").getAsString());
            if(!Objects.equals(ends.get(w.address),w.end)||managed.contains(w.address)||w.end<=w.address||w.size()!=row.get("size").getAsLong())
                throw new Exception("Wrong native FDE identity at "+hex(w.address));
            w.function=getFunctionAt(toAddr(w.address));
            if(w.function!=null&&!w.function.getBody().equals(new AddressSet(toAddr(w.address),toAddr(w.end-1))))
                throw new Exception("Saved function differs from exact FDE; no repair permitted: "+hex(w.address));
            String fallback="FUN_"+Long.toHexString(w.address);
            JsonArray syms=row.getAsJsonArray("symbols");
            if(syms.size()>0)fallback=syms.get(0).getAsJsonObject().get("name").getAsString();
            w.name=w.function!=null?w.function.getName(true):fallback;
            long fileOffset=-1;for(long[] segment:loads)if(w.address>=segment[1]&&w.end<=segment[1]+segment[2])
                {fileOffset=segment[0]+w.address-segment[1];break;}
            if(fileOffset<0)throw new Exception("FDE outside original file-backed LOAD");
            byte[] expected=Arrays.copyOfRange(elf,Math.toIntExact(fileOffset),Math.toIntExact(fileOffset+w.size()));
            byte[] actual=new byte[expected.length];
            if(currentProgram.getMemory().getBytes(toAddr(w.address),actual)!=actual.length||!Arrays.equals(expected,actual))
                throw new Exception("Saved program bytes differ from ELF: "+hex(w.address));
            w.sourceSha=hash(expected);w.header=header(w);
            String name=safe(w.name);if(name.length()>100)name=name.substring(0,100);
            w.baseFile="ranges/"+safe(row.get("category").getAsString())+"/"+name+"_"+Long.toHexString(w.address);
            if(targets.put(w.address,w)!=null)throw new Exception("Duplicate extra FDE");
            String signature=w.function==null?"MISSING":w.function.getSignature().toString();
            fingerprint.update((hex(w.address)+"\t"+hex(w.end)+"\t"+w.name+"\t"+signature+"\t"+w.sourceSha+"\n").getBytes(StandardCharsets.UTF_8));
            for(Instruction ins:currentProgram.getListing().getInstructions(new AddressSet(toAddr(w.address),toAddr(w.end-1)),true)) {
                fingerprint.update((ins.getAddress()+"\t"+ins+"\t"+ins.getFlowType()+"\n").getBytes(StandardCharsets.UTF_8));
                for(var ref:ins.getReferencesFrom())fingerprint.update((ref.getToAddress()+"\t"+ref.getReferenceType()+"\n").getBytes(StandardCharsets.UTF_8));
            }
            if(targets.size()%1000==0){progress(false,"validating_original_bytes_and_model","");println("TERRARIA_NATIVE_PREFLIGHT "+targets.size()+"/"+TOTAL);}
        }
        if(targets.size()!=TOTAL||!targets.keySet().equals(difference(ends.keySet(),managed)))throw new Exception("Incomplete extra FDE partition");
        manifest=new JsonObject();manifest.addProperty("schema",1);manifest.addProperty("profile",PROFILE);manifest.addProperty("model",MODEL);
        manifest.addProperty("elf_sha256",ELF_SHA);manifest.addProperty("classification_sha256",hash(classification));
        manifest.addProperty("fde_tsv_sha256",hash(nativeDir.resolve("unwind-function-ranges.tsv")));
        manifest.addProperty("managed_baseline_sha256",baselineSha);manifest.addProperty("program_snapshot_sha256",HexFormat.of().formatHex(fingerprint.digest()));
        File engine=Application.getOSFile("decompile.exe");
        manifest.addProperty("decompiler_engine_sha256",hash(engine.toPath()));manifest.addProperty("ghidra_version",Application.getApplicationVersion());
        manifest.addProperty("language",currentProgram.getLanguageID().toString());manifest.addProperty("compiler_spec",currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        manifest.addProperty("image_base",0);manifest.addProperty("total",TOTAL);manifest.addProperty("timeout_seconds",timeout);
        manifest.addProperty("max_instructions",MAX_INSTRUCTIONS);manifest.addProperty("max_payload_mb",64);manifest.addProperty("workers",4);
        manifest.addProperty("batch_size",BATCH);manifest.addProperty("header_title",TITLE);
        manifest.addProperty("program_model_evidence","Complete v3 managed ledger + ELF bytes + exact extra FDE bodies; no embedded database model marker exists");
        Path p=out.resolve("manifest.json");
        if(Files.exists(p)) {if(!JsonParser.parseString(Files.readString(p)).equals(manifest))throw new Exception("Resume profile/model/input SHA manifest mismatch; use separate output directory");}
        else {if(Files.exists(out.resolve("coverage.jsonl")))throw new Exception("Journal without manifest");atomic(p,gson.toJson(manifest)+"\n");}
    }
    static Set<Long> difference(Set<Long> all,Set<Long> exclude){Set<Long> result=new HashSet<>(all);result.removeAll(exclude);return result;}
    void checkArtifact(JsonObject row,String pathKey,String hashKey)throws Exception {
        Path file=confined(row.get(pathKey).getAsString());
        if(!Files.isRegularFile(file)||!hash(file).equals(row.get(hashKey).getAsString()))throw new Exception("Resume artifact missing/SHA mismatch: "+file);
    }
    void loadJournal()throws Exception {
        Path path=out.resolve("coverage.jsonl");if(!Files.exists(path))return;
        byte[] raw=Files.readAllBytes(path);
        if(raw.length>0&&raw[raw.length-1]!=10) {
            int cut=raw.length-1;while(cut>=0&&raw[cut]!=10)cut--;cut++;
            Path tail=out.resolve("incomplete-journal-tail-"+System.currentTimeMillis()+".txt");Files.write(tail,Arrays.copyOfRange(raw,cut,raw.length));
            try(RandomAccessFile f=new RandomAccessFile(path.toFile(),"rw")){f.setLength(cut);f.getFD().sync();}
        }
        try(BufferedReader reader=Files.newBufferedReader(path,StandardCharsets.UTF_8)) {
            String line;while((line=reader.readLine())!=null) {
                JsonObject r=JsonParser.parseString(line).getAsJsonObject();long a=number(r.get("address").getAsString());Work w=targets.get(a);
                if(w==null||!hex(w.end).equals(r.get("compiler_end_exclusive").getAsString())||!PROFILE.equals(r.get("profile").getAsString())||
                   !MODEL.equals(r.get("model").getAsString())||r.get("image_base").getAsInt()!=0||r.get("timeout_seconds").getAsInt()!=timeout||
                   r.get("max_instructions").getAsInt()!=MAX_INSTRUCTIONS||!w.name.equals(r.get("function_name").getAsString())||
                   !w.sourceSha.equals(r.get("source_bytes_sha256").getAsString())||!hash(w.header.getBytes(StandardCharsets.UTF_8)).equals(r.get("header_sha256").getAsString())||
                   !w.evidence.equals(r.get("classification")))throw new Exception("Resume row identity/profile/header mismatch at "+hex(a));
                for(String kind:List.of("asm","calls"))checkArtifact(r,kind+"_file",kind+"_sha256");
                if("decompiled".equals(r.get("status").getAsString())) {
                    checkArtifact(r,"file","file_sha256");
                    if(!Files.readString(confined(r.get("file").getAsString()),StandardCharsets.UTF_8).startsWith(w.header))throw new Exception("Resume C header mismatch");
                } else if(!r.get("file").getAsString().isEmpty())throw new Exception("Non-success has C file");
                if(completed.put(a,r)!=null)throw new Exception("Duplicate journal address");
            }
        }
        counters=count();resumed=completed.size();
    }
    JsonObject export(Work w,DecompileResults result,Exception error)throws Exception {
        JsonObject r=new JsonObject();r.addProperty("address",hex(w.address));r.addProperty("compiler_end_exclusive",hex(w.end));
        r.addProperty("function_name",w.name);r.addProperty("image_base",0);r.addProperty("profile",PROFILE);r.addProperty("model",MODEL);
        r.addProperty("timeout_seconds",timeout);r.addProperty("max_instructions",MAX_INSTRUCTIONS);r.addProperty("compiler_size",w.size());
        r.addProperty("source_bytes_sha256",w.sourceSha);r.addProperty("header_sha256",hash(w.header.getBytes(StandardCharsets.UTF_8)));
        r.add("classification",w.evidence.deepCopy());
        StringBuilder assembly=new StringBuilder("range_entry\tinstruction_address\tbytes\tinstruction\n"),calls=new StringBuilder("caller\tsource\ttarget\ttype\n");
        long count=0,bytes=0;
        for(Instruction ins:currentProgram.getListing().getInstructions(new AddressSet(toAddr(w.address),toAddr(w.end-1)),true)) {
            byte[] b=ins.getBytes();assembly.append(hex(w.address)).append('\t').append(ins.getAddress()).append('\t').append(HexFormat.of().formatHex(b)).append('\t')
                .append(ins.toString().replace('\t',' ').replace('\n',' ')).append('\n');count++;bytes+=b.length;
            for(var ref:ins.getReferencesFrom())if(ref.getReferenceType().isCall())calls.append(hex(w.address)).append('\t').append(ins.getAddress()).append('\t')
                .append(ref.getToAddress()).append('\t').append(ref.getReferenceType()).append('\n');
        }
        r.addProperty("instructions",count);r.addProperty("instruction_bytes",bytes);r.addProperty("instruction_coverage_complete",bytes==w.size());
        for(String kind:List.of("asm","calls")) {
            String rel=w.baseFile+"."+kind+".tsv";Path p=confined(rel);atomic(p,kind.equals("asm")?assembly.toString():calls.toString());
            r.addProperty(kind+"_file",rel);r.addProperty(kind+"_sha256",hash(p));
        }
        String status="missing_function",message="",file="",fileSha="";
        if(error!=null){status="export_error";message=error.toString();}
        else if(w.function!=null) {
            if(result==null){status="decompile_failed";message="Decompiler returned no result";}
            else {
                message=result.getErrorMessage()==null?"":result.getErrorMessage();
                if(result.decompileCompleted()&&result.getDecompiledFunction()!=null) {
                    file=w.baseFile+".c";Path p=confined(file);atomic(p,w.header+result.getDecompiledFunction().getC());fileSha=hash(p);status="decompiled";
                } else status="decompile_failed";
            }
        }
        if(bytes!=w.size())message+=(message.isBlank()?"":"; ")+"Listing does not cover complete compiler FDE; missing instructions remain explicit";
        r.addProperty("status",status);r.addProperty("message",message);r.addProperty("file",file);r.addProperty("file_sha256",fileSha);
        return r;
    }
    synchronized void accept(JsonObject r) {
        try {
            if(commitFailure!=null)throw new IOException("Previous journal commit failed",commitFailure);
            long address=number(r.get("address").getAsString());if(completed.containsKey(address))throw new IOException("Duplicate completion");
            journal.write(gson.toJson(r));journal.newLine();journal.flush();journalFile.getFD().sync(); // Commit completed work immediately.
            completed.put(address,r);increment(r);progress(false,"exporting","");
            if(completed.size()%100==0)println("TERRARIA_NATIVE_EXPORT "+completed.size()+"/"+TOTAL);
        }catch(Exception e){commitFailure=e;throw new RuntimeException(e);}
    }
    class Worker extends DecompilerCallback<JsonObject> {
        Worker(){super(currentProgram,decompiler->{DecompileOptions o=new DecompileOptions();o.grabFromProgram(currentProgram);
            o.setMaxInstructions(MAX_INSTRUCTIONS);o.setMaxPayloadMBytes(64);decompiler.setOptions(o);decompiler.toggleCCode(true);
            decompiler.toggleSyntaxTree(false);decompiler.setSimplificationStyle("decompile");});setTimeout(timeout);}
        @Override public JsonObject process(DecompileResults r,TaskMonitor m)throws Exception{return export(targets.get(r.getFunction().getEntryPoint().getOffset()),r,null);}
        @Override public JsonObject process(Function f,TaskMonitor m)throws Exception {
            m.checkCancelled();try{return super.process(f,m);}catch(CancelledException e){throw e;}
            catch(Exception e){return export(targets.get(f.getEntryPoint().getOffset()),null,e);}
        }
    }
    void aggregates()throws Exception {
        for(String kind:List.of("asm","calls")) {
            String name=kind.equals("asm")?"instructions.tsv":"calls.tsv";Path temp=out.resolve(name+".tmp");int n=0;
            try(BufferedWriter writer=Files.newBufferedWriter(temp,StandardCharsets.UTF_8)) {
                writer.write(kind.equals("asm")?"range_entry\tinstruction_address\tbytes\tinstruction\n":"caller\tsource\ttarget\ttype\n");
                for(Work w:targets.values()) {
                    monitor.checkCancelled();JsonObject r=completed.get(w.address);
                    try(BufferedReader reader=Files.newBufferedReader(confined(r.get(kind+"_file").getAsString()),StandardCharsets.UTF_8)) {
                        reader.readLine();String line;while((line=reader.readLine())!=null){writer.write(line);writer.newLine();}
                    }
                    if(++n%1000==0)progress(false,"building_"+name,"");
                }
            }
            Files.move(temp,out.resolve(name),StandardCopyOption.REPLACE_EXISTING);
        }
    }
    @Override public void run()throws Exception {
        String[] args=getScriptArgs();if(args.length<2)throw new Exception("Args: classification.json output-directory [15|30] [complete-v3-managed-coverage.jsonl]");
        Path classification=Path.of(args[0]).toAbsolutePath().normalize();lab=classification.getParent().getParent();
        out=Path.of(args[1]).toAbsolutePath().normalize();
        if(!out.equals(lab.resolve("native-ranges-pseudocode"))&&!out.getFileName().toString().startsWith("native-ranges-pseudocode-"))
            throw new Exception("Requires separate native-ranges-pseudocode output directory");
        if(!out.getParent().equals(lab))throw new Exception("Native export must remain in the same lab");
        timeout=args.length>2?Integer.parseInt(args[2]):15;if(timeout!=15&&timeout!=30)throw new Exception("Timeout must be 15 or 30 seconds");
        Files.createDirectories(out);progress(false,"preflight","");
        Path baseline=args.length>3?Path.of(args[3]):lab.resolve("pseudocode/coverage.jsonl");
        GThreadPool threads=null;Worker callback=null;DecompilerConcurrentQ<Function,JsonObject> queue=null;boolean finished=false;String failure="";
        try {
            preflight(classification,baseline);loadJournal();progress(false,"exporting","");
            journalFile=new FileOutputStream(out.resolve("coverage.jsonl").toFile(),true);
            journal=new BufferedWriter(new OutputStreamWriter(journalFile,StandardCharsets.UTF_8));
            threads=GThreadPool.getPrivateThreadPool("Terraria native ranges "+UUID.randomUUID());threads.setMaxThreadCount(4);
            // Pinned Ghidra 12.1.4 registers even this private factory's pool as shared;
            // batch queue disposal therefore leaves it reusable. Never change global pool limits.
            if(threads.isPrivate())throw new Exception("Pinned Ghidra pool behavior changed; bounded-batch reuse requires review");
            callback=new Worker();List<Work> todo=new ArrayList<>();for(Work w:targets.values())if(!completed.containsKey(w.address))todo.add(w);
            for(int offset=0;offset<todo.size();offset+=BATCH) {
                monitor.checkCancelled();List<Function> functions=new ArrayList<>();int end=Math.min(offset+BATCH,todo.size());
                for(Work w:todo.subList(offset,end))if(w.function==null)accept(export(w,null,null));else functions.add(w.function);
                queue=new DecompilerConcurrentQ<>(callback,threads,false,monitor);queue.process(functions.iterator(),this::accept);queue.waitUntilDone();queue=null;
                if(commitFailure!=null)throw new Exception("Journal completion failed",commitFailure);
                for(Work w:todo.subList(offset,end))if(!completed.containsKey(w.address))throw new Exception("Batch lost result at "+hex(w.address));
            }
            if(completed.size()!=TOTAL||!completed.keySet().equals(targets.keySet()))throw new Exception("Incomplete native range coverage");
            journal.flush();journalFile.getFD().sync();aggregates();Counter c=count();
            if(c.good+c.failed+c.missing+c.errors!=TOTAL)throw new Exception("Final counters differ from journal");
            JsonObject finalSummary=manifest.deepCopy();finalSummary.addProperty("decompiled",c.good);finalSummary.addProperty("failed",c.failed);
            finalSummary.addProperty("missing",c.missing);finalSummary.addProperty("export_error",c.errors);finalSummary.addProperty("coverage_sha256",hash(out.resolve("coverage.jsonl")));
            finalSummary.addProperty("instructions_sha256",hash(out.resolve("instructions.tsv")));finalSummary.addProperty("calls_sha256",hash(out.resolve("calls.tsv")));
            finalSummary.addProperty("finished",true);atomic(out.resolve("summary.json"),gson.toJson(finalSummary)+"\n");finished=true;
        }catch(Exception e){failure=e.toString();throw e;}
        finally {
            if(queue!=null)queue.dispose(timeout+5);if(callback!=null)callback.dispose();if(threads!=null)threads.shutdownNow();
            if(journal!=null)journal.close();progress(finished,finished?"complete":"aborted",failure);
        }
    }
}
