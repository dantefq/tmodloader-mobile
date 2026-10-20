// Durable retry journal for failed rows only. Baseline/coverage/assembly are never rewritten.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.util.DecompilerConcurrentQ;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.CancelledException;
import generic.concurrent.GThreadPool;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.io.*;
import java.util.*;

public class TerrariaRetryFailed extends GhidraScript {
    private static final String PROFILE="bounded-fde-terminal-calls-signatures-v3";
    private final Gson gson=new Gson();
    private Path out;private int timeout=120,maxInstructions=250000,workers=4;
    private Map<Long,JsonObject> targets=new LinkedHashMap<>(),results=new LinkedHashMap<>();
    private BufferedWriter journal;
    private static String safe(String s) {s=s.replaceAll("[^A-Za-z0-9_.-]","_");return s.isBlank()||s.equals(".")||s.equals("..")?"_":s;}
    private static long address(JsonObject r) {return Long.parseUnsignedLong(r.get("address").getAsString().replace("0x",""),16);}
    private String header(JsonObject r) {
        return "/* RECOVERED GHIDRA PSEUDOCODE; NOT ORIGINAL C#; static analysis only.\n"+
            " * Method: "+r.get("method").getAsString().replace("*/","* /")+"\n * ELF VA: "+r.get("address").getAsString()+"; image base: 0\n"+
            " * Compiler unwind extent end-exclusive: "+r.get("compiler_end_exclusive").getAsString()+"\n * Analysis profile: "+PROFILE+"\n */\n";
    }
    private boolean identity(JsonObject r,JsonObject original) {
        for(String key:List.of("address","compiler_end_exclusive","method","image","profile","image_base"))
            if(!r.has(key)||!r.get(key).equals(original.get(key)))return false;
        return true;
    }
    private boolean validSuccess(JsonObject r) throws IOException {
        if(!r.has("file"))return false;String relative=r.get("file").getAsString();Path p=out.resolve(relative).normalize();
        if(relative.isBlank()||!p.startsWith(out)||!Files.isRegularFile(p)||!p.toRealPath().startsWith(out.toRealPath()))return false;
        StringBuilder first=new StringBuilder();try(BufferedReader f=Files.newBufferedReader(p,StandardCharsets.UTF_8)) {
            for(int i=0;i<6;i++){String line=f.readLine();if(line==null)break;first.append(line).append('\n');}
        }
        return first.toString().equals(header(r));
    }
    private synchronized void progress(boolean finished) throws IOException {
        int success=0;for(JsonObject r:results.values())if("decompiled".equals(r.get("status").getAsString()))success++;
        JsonObject p=new JsonObject();p.addProperty("finished",finished);p.addProperty("profile",PROFILE);
        p.addProperty("retry_total",targets.size());p.addProperty("attempted",results.size());p.addProperty("decompiled",success);
        p.addProperty("failed",results.size()-success);p.addProperty("timeout_seconds",timeout);p.addProperty("max_instructions",maxInstructions);p.addProperty("workers",workers);
        Path temp=out.resolve("retry-progress.json.tmp");Files.writeString(temp,gson.toJson(p),StandardCharsets.UTF_8);
        Files.move(temp,out.resolve("retry-progress.json"),StandardCopyOption.REPLACE_EXISTING);
    }
    private synchronized void accept(JsonObject r) {
        try {journal.write(gson.toJson(r));journal.newLine();journal.flush();results.put(address(r),r);progress(false);
            println("TERRARIA_RETRY_RESULT "+r.get("address")+" "+r.get("status")+" "+results.size()+"/"+targets.size());
        } catch(IOException e){throw new UncheckedIOException(e);}
    }
    private JsonObject result(Function f,DecompileResults d,Exception error) {
        JsonObject r=targets.get(f.getEntryPoint().getOffset()).deepCopy();r.addProperty("file","");r.addProperty("cached",false);
        r.addProperty("timeout_seconds",timeout);r.addProperty("max_instructions",maxInstructions);
        try {
            if(error!=null)throw error;
            r.addProperty("message",d.getErrorMessage()==null?"":d.getErrorMessage());
            if(!d.decompileCompleted()||d.getDecompiledFunction()==null){r.addProperty("status","decompile_failed");return r;}
            String basename=safe(f.getName());if(basename.length()>150)basename=basename.substring(0,150);
            String relative=safe(r.get("image").getAsString())+"/"+basename+"_"+r.get("address").getAsString().replace("0x","")+".c";
            Path destination=out.resolve(relative).normalize();if(!destination.startsWith(out))throw new IOException("Unconfined output");
            Files.createDirectories(destination.getParent());Path temp=destination.resolveSibling(destination.getFileName()+".tmp");
            Files.writeString(temp,header(r)+d.getDecompiledFunction().getC(),StandardCharsets.UTF_8);
            Files.move(temp,destination,StandardCopyOption.REPLACE_EXISTING);r.addProperty("file",relative);r.addProperty("status","decompiled");
        }catch(Exception e){r.addProperty("status","export_error");r.addProperty("message",e.toString());r.addProperty("file","");}
        return r;
    }
    private class Worker extends DecompilerCallback<JsonObject> {
        Worker(){super(currentProgram,decompiler->{DecompileOptions o=new DecompileOptions();o.grabFromProgram(currentProgram);
            o.setMaxPayloadMBytes(64);o.setMaxInstructions(maxInstructions);decompiler.setOptions(o);decompiler.toggleCCode(true);
            decompiler.toggleSyntaxTree(false);decompiler.setSimplificationStyle("decompile");});setTimeout(timeout);}
        public JsonObject process(DecompileResults r,TaskMonitor m){return result(r.getFunction(),r,null);}
        public JsonObject process(Function f,TaskMonitor m)throws Exception {
            try{m.checkCancelled();return super.process(f,m);}catch(CancelledException e){throw e;}catch(Exception e){return result(f,null,e);}
        }
    }
    public void run() throws Exception {
        String[] args=getScriptArgs();if(args.length<2)throw new Exception("Args: full-baseline.jsonl output-directory [120] [250000]");
        out=Path.of(args[1]).toAbsolutePath().normalize();Files.createDirectories(out);
        timeout=args.length>2?Integer.parseInt(args[2]):120;maxInstructions=args.length>3?Integer.parseInt(args[3]):250000;workers=args.length>4?Integer.parseInt(args[4]):4;
        if(workers<1||workers>4)throw new Exception("Workers must be 1..4");
        if(timeout<1||timeout>3600||maxInstructions<1||maxInstructions>1000000)throw new Exception("Invalid resource limits");
        if(currentProgram.getImageBase().getOffset()!=0 || !currentProgram.getLanguageID().toString().equals("AARCH64:LE:64:v8A"))throw new Exception("Requires ARM64 v8A ELF base zero");
        Map<Long,Long> ends=new HashMap<>();
        for(String line:Files.readAllLines(out.getParent().resolve("native/unwind-function-ranges.tsv"),StandardCharsets.UTF_8)) {
            String[] row=line.split("\t");ends.put(Long.parseUnsignedLong(row[0].replace("0x",""),16),Long.parseUnsignedLong(row[1].replace("0x",""),16));
        }
        Set<Long> seen=new HashSet<>();int baselineCount=0;
        try(BufferedReader input=Files.newBufferedReader(Path.of(args[0]),StandardCharsets.UTF_8)) {
            String line;while((line=input.readLine())!=null) {
                JsonObject r=JsonParser.parseString(line).getAsJsonObject();long a=address(r);baselineCount++;
                long end=Long.parseUnsignedLong(r.get("compiler_end_exclusive").getAsString().replace("0x",""),16);
                if(!seen.add(a)||!PROFILE.equals(r.get("profile").getAsString())||r.get("image_base").getAsInt()!=0||!Objects.equals(ends.get(a),end))
                    throw new Exception("Invalid baseline identity/FDE at "+r.get("address"));
                if(!"decompiled".equals(r.get("status").getAsString()))targets.put(a,r);
            }
        }
        if(baselineCount!=93990||ends.size()!=123152)throw new Exception("Incomplete baseline/FDE catalogue");
        Path journalPath=out.resolve("retry-results.jsonl");
        if(Files.isRegularFile(journalPath)) {
            byte[] old=Files.readAllBytes(journalPath);
            if(old.length>0 && old[old.length-1]!=10) {
                int start=old.length-1;while(start>=0 && old[start]!=10)start--;start++;
                try {JsonParser.parseString(new String(old,start,old.length-start,StandardCharsets.UTF_8)).getAsJsonObject();}
                catch(RuntimeException damaged) {
                    Files.write(out.resolve("retry-journal-truncated-tail-"+System.currentTimeMillis()+".txt"),Arrays.copyOfRange(old,start,old.length));
                    Files.write(journalPath,Arrays.copyOf(old,start));
                }
            }
        }
        if(Files.isRegularFile(journalPath))try(BufferedReader input=Files.newBufferedReader(journalPath,StandardCharsets.UTF_8)) {
            String line;while((line=input.readLine())!=null)try {
                JsonObject r=JsonParser.parseString(line).getAsJsonObject();JsonObject original=targets.get(address(r));
                if(original==null||!identity(r,original))continue;
                boolean success="decompiled".equals(r.get("status").getAsString());
                boolean terminalFailure=Set.of("decompile_failed","export_error","missing_function").contains(r.get("status").getAsString());
                if(success?validSuccess(r):(terminalFailure&&r.has("timeout_seconds")&&r.get("timeout_seconds").getAsInt()==timeout&&r.has("max_instructions")&&r.get("max_instructions").getAsInt()==maxInstructions))results.put(address(r),r);
            }catch(RuntimeException|IOException e){/* damaged final row is ignored */}
        }
        List<Function> functions=new ArrayList<>();List<JsonObject> missing=new ArrayList<>();
        for(var pair:targets.entrySet())if(!results.containsKey(pair.getKey())) {
            Function f=getFunctionAt(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(pair.getKey()));
            if(f==null){JsonObject r=pair.getValue().deepCopy();r.addProperty("status","missing_function");r.addProperty("file","");r.addProperty("message","No function in saved database");r.addProperty("timeout_seconds",timeout);r.addProperty("max_instructions",maxInstructions);r.addProperty("cached",false);missing.add(r);continue;}
            if(!f.getBody().equals(new AddressSet(f.getEntryPoint(),f.getEntryPoint().getNewAddress(ends.get(pair.getKey())-1))))throw new Exception("Saved function differs from FDE: "+f.getEntryPoint());
            functions.add(f);
        }
        if(args.length>5) {
            Set<Long> priority=new HashSet<>();for(String text:args[5].split(","))priority.add(Long.parseUnsignedLong(text.replace("0x",""),16));
            functions.sort(Comparator.comparingInt(f->priority.contains(f.getEntryPoint().getOffset())?0:1));
        }
        progress(false);println("TERRARIA_RETRY_START targets="+targets.size()+" journal_resumed="+results.size()+" queued="+functions.size());
        GThreadPool pool=GThreadPool.getPrivateThreadPool("Terraria retry "+UUID.randomUUID());pool.setMaxThreadCount(workers);Worker worker=new Worker();
        DecompilerConcurrentQ<Function,JsonObject> queue=new DecompilerConcurrentQ<>(worker,pool,false,monitor);
        boolean needsNewline=false;
        if(Files.isRegularFile(journalPath)&&Files.size(journalPath)>0)try(RandomAccessFile previous=new RandomAccessFile(journalPath.toFile(),"r")) {
            previous.seek(previous.length()-1);needsNewline=previous.read()!=10;
        }
        try(BufferedWriter writer=Files.newBufferedWriter(journalPath,StandardCharsets.UTF_8,StandardOpenOption.CREATE,StandardOpenOption.APPEND)) {
            if(needsNewline){writer.newLine();writer.flush();} // Quarantine a truncated last row without deleting journal evidence.
            journal=writer;for(JsonObject r:missing)accept(r);queue.process(functions.iterator(),this::accept);queue.waitUntilDone();monitor.checkCancelled();
            if(results.size()!=targets.size())throw new Exception("Retry lacks terminal records");progress(true);
        }finally{queue.dispose(Math.min(timeout+5,60));worker.dispose();pool.shutdownNow();}
    }
}
