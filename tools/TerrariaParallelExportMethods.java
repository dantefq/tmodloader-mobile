// Read-only four-worker export after exact ELF/FDE setup. Not original C#.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.util.DecompilerConcurrentQ;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.CancelledException;
import generic.concurrent.GThreadPool;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.io.*;
import java.util.*;

public class TerrariaParallelExportMethods extends GhidraScript {
    private static final String PROFILE="bounded-fde-terminal-calls-signatures-v3";
    static String safe(String value) {
        String s=value.replaceAll("[^A-Za-z0-9_.-]", "_");
        return s.equals(".") || s.equals("..") || s.isEmpty() ? "_" : s;
    }
    static String esc(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t");
    }
    static class Work {
        int index; String[] row; String end; Function function; long size;
        Work(int i,String[] r,String e,Function f,long z) {index=i;row=r;end=e;function=f;size=z;}
    }
    static class ExportRecord {
        Work work; String status="missing_function", error="", file="";
        long instructions=0,instructionBytes=0; String asm="", calls="";
        int timeout=30,maxInstructions=100000; boolean cached=false;
        ExportRecord(Work w) {work=w;}
        String json() {
            return "{\"address\":\""+work.row[0]+"\",\"compiler_end_exclusive\":\""+work.end+
                "\",\"image_base\":0,\"method\":\""+esc(work.row[2])+"\",\"image\":\""+esc(work.row[3])+
                "\",\"status\":\""+status+"\",\"instructions\":"+instructions+
                ",\"instruction_bytes\":"+instructionBytes+",\"compiler_size\":"+work.size+
                ",\"instruction_coverage_complete\":"+(instructionBytes==work.size)+
                ",\"profile\":\""+PROFILE+"\",\"timeout_seconds\":"+timeout+",\"max_instructions\":"+maxInstructions+",\"cached\":"+cached+
                ",\"file\":\""+esc(file)+"\",\"message\":\""+esc(error)+"\"}\n";
        }
    }
    private Path out;
    private Map<Long,Work> byAddress;
    private List<Work> work;
    private int timeoutSeconds=30,maxInstructions=100000,cachedCount=0;
    private Map<Long,JsonObject> successCache=new HashMap<>();
    private BufferedWriter ledger,asm,calls;
    private final Object outputLock=new Object();
    private final TreeMap<Integer,ExportRecord> pending=new TreeMap<>();
    private int committed=0,completed=0,done=0,failed=0,missing=0,exceptions=0;

    private void restoreCompilerExtents(Map<String,String> ends) throws Exception {
        progress(false,",\"phase\":\"repairing_compiler_extents\"");
        TreeMap<Long,Address> expected=new TreeMap<>();AddressSet coverage=new AddressSet();
        for(var pair:ends.entrySet()) {
            Address start=toAddr(pair.getKey()),last=toAddr(pair.getValue()).subtract(1);
            expected.put(start.getOffset(),last);coverage.add(start,last);
        }
        List<Function> existing=new ArrayList<>();
        for(Function f:currentProgram.getFunctionManager().getFunctions(true))existing.add(f);
        int shrunk=0,removed=0,restored=0;
        // Release conflicting old flow-derived extents before expanding any FDE.
        // Entry names/labels survive; only private analysis-database bodies change.
        for(Function f:existing) {
            monitor.checkCancelled();Address entry=f.getEntryPoint();Address last=expected.get(entry.getOffset());
            if(last!=null) {
                if(!f.getBody().equals(new AddressSet(entry,last))) {f.setBody(new AddressSet(entry));shrunk++;}
            } else if(f.getBody().intersects(coverage)) {
                if(coverage.contains(entry)) {
                    String name=f.getName();var ns=f.getParentNamespace();SourceType source=f.getSymbol().getSource();
                    if(source==SourceType.DEFAULT)source=SourceType.ANALYSIS;
                    currentProgram.getFunctionManager().removeFunction(entry);
                    currentProgram.getSymbolTable().createLabel(entry,name,ns,source);removed++;
                } else {
                    AddressSet rest=new AddressSet(f.getBody()).subtract(coverage);
                    f.setBody(rest);shrunk++;
                }
            }
        }
        for(var pair:expected.entrySet()) {
            monitor.checkCancelled();Address entry=currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(pair.getKey());
            AddressSet body=new AddressSet(entry,pair.getValue());Function f=getFunctionAt(entry);
            if(f==null) {
                var symbol=currentProgram.getSymbolTable().getPrimarySymbol(entry);
                String name=symbol==null?"FUN_"+entry:symbol.getName();
                SourceType source=symbol==null?SourceType.ANALYSIS:symbol.getSource();if(source==SourceType.DEFAULT)source=SourceType.ANALYSIS;
                f=currentProgram.getFunctionManager().createFunction(name,entry,body,source);
            } else if(!f.getBody().equals(body))f.setBody(body);
            if(f==null||!f.getBody().equals(body))throw new Exception("Failed compiler extent restore at "+entry);
            restored++;if(restored%10000==0)println("TERRARIA_EXPORT_FDE_PREFLIGHT "+restored+"/"+expected.size());
        }
        println("TERRARIA_EXPORT_FDE_PREFLIGHT_COMPLETE restored="+restored+" shrunk="+shrunk+" interior_flow_functions_relabelled="+removed);
    }

    private void progress(boolean finished,String extra) throws IOException {
        String text="{\"finished\":"+finished+",\"workers\":4,\"total\":"+(work==null?93990:work.size())+
            ",\"processed\":"+committed+",\"completed\":"+completed+",\"decompiled\":"+done+
            ",\"failed\":"+failed+",\"missing\":"+missing+",\"export_error\":"+exceptions+
            ",\"cached\":"+cachedCount+",\"timeout_seconds\":"+timeoutSeconds+",\"max_instructions\":"+maxInstructions+",\"profile\":\""+PROFILE+"\""+extra+"}";
        Path temp=out.resolve("progress.json.tmp");
        Files.writeString(temp,text,StandardCharsets.UTF_8);
        Files.move(temp,out.resolve("progress.json"),StandardCopyOption.REPLACE_EXISTING);
    }
    private ExportRecord export(Work w,DecompileResults result,Exception exception) {
        ExportRecord r=new ExportRecord(w);r.timeout=timeoutSeconds;r.maxInstructions=maxInstructions; StringBuilder a=new StringBuilder(),c=new StringBuilder();
        try {
            if(w.function==null) return r;
            InstructionIterator it=currentProgram.getListing().getInstructions(w.function.getBody(),true);
            while(it.hasNext()) {
                Instruction ins=it.next(); byte[] raw=ins.getBytes(); StringBuilder bytes=new StringBuilder();
                for(byte b:raw) {bytes.append(Character.forDigit((b>>>4)&15,16));bytes.append(Character.forDigit(b&15,16));}
                a.append(w.row[0]).append('\t').append(ins.getAddress()).append('\t').append(bytes).append('\t').append(ins).append('\n');
                for(var ref:ins.getReferencesFrom()) if(ref.getReferenceType().isCall()) {
                    c.append(w.row[0]).append('\t').append(ins.getAddress()).append('\t').append(ref.getToAddress()).append('\t').append(ref.getReferenceType()).append('\n');
                }
                r.instructions++;r.instructionBytes+=raw.length;
            }
            if(exception!=null) {
                r.status="export_error";r.error=exception.getClass().getSimpleName()+": "+exception.getMessage();
            } else if(result==null && successCache.containsKey(w.function.getEntryPoint().getOffset())) {
                JsonObject cached=successCache.get(w.function.getEntryPoint().getOffset());
                r.status="decompiled";r.file=cached.get("file").getAsString();r.cached=true;
                r.timeout=cached.has("timeout_seconds")?cached.get("timeout_seconds").getAsInt():30;
                r.maxInstructions=cached.has("max_instructions")?cached.get("max_instructions").getAsInt():100000;
                r.error=cached.has("message")?cached.get("message").getAsString():"";
            } else if(result!=null) {
                r.error=result.getErrorMessage()==null?"":result.getErrorMessage();
                if(result.decompileCompleted() && result.getDecompiledFunction()!=null) {
                    String basename=safe(w.row[1]);if(basename.length()>150)basename=basename.substring(0,150);
                    r.file=safe(w.row[3])+"/"+basename+"_"+w.row[0].replace("0x","")+".c";
                    Path destination=out.resolve(r.file).normalize();
                    if(!destination.startsWith(out))throw new IOException("Output path outside export directory");
                    Files.createDirectories(destination.getParent());
                    String header="/* RECOVERED GHIDRA PSEUDOCODE; NOT ORIGINAL C#; static analysis only.\n"+
                        " * Method: "+w.row[2].replace("*/","* /")+"\n * ELF VA: "+w.row[0]+"; image base: 0\n"+
                        " * Compiler unwind extent end-exclusive: "+w.end+"\n * Analysis profile: "+PROFILE+"\n */\n";
                    Path temporary=destination.resolveSibling(destination.getFileName()+".tmp");
                    Files.writeString(temporary,header+result.getDecompiledFunction().getC(),StandardCharsets.UTF_8);
                    Files.move(temporary,destination,StandardCopyOption.REPLACE_EXISTING);
                    r.status="decompiled";
                } else r.status="decompile_failed";
            } else {r.status="decompile_failed";r.error="Decompiler returned no result";}
            if(r.instructionBytes!=w.size && !r.error.contains("Listing does not cover the complete compiler unwind extent"))
                r.error+=(r.error.isEmpty()?"":"; ")+"Listing does not cover the complete compiler unwind extent";
        } catch(Exception e) {
            r.status="export_error";r.error=e.getClass().getSimpleName()+": "+e.getMessage();r.file="";
        } finally {r.asm=a.toString();r.calls=c.toString();}
        return r;
    }
    private void accept(ExportRecord record) {
        synchronized(outputLock) {
            try {
                if(pending.put(record.work.index,record)!=null)throw new IOException("Duplicate export result");
                completed++;
                while(pending.containsKey(committed)) {
                    ExportRecord r=pending.remove(committed);
                    ledger.write(r.json());asm.write(r.asm);calls.write(r.calls);
                    switch(r.status) {
                        case "decompiled":done++;break;
                        case "missing_function":missing++;break;
                        case "export_error":exceptions++;break;
                        default:failed++;
                    }
                    if(r.cached)cachedCount++;
                    committed++;
                }
                // Deterministic seed-order rows in ALL three shared output files.
                ledger.flush();
                if(completed%100==0) {
                    asm.flush();calls.flush();progress(false,"");
                    println("TERRARIA_PARALLEL_EXPORT "+committed+"/"+work.size()+" completed="+completed+" ok="+done+" failed="+failed+" missing="+missing);
                }
            } catch(IOException e) {throw new UncheckedIOException(e);}
        }
    }
    private class Worker extends DecompilerCallback<ExportRecord> {
        Worker() {super(currentProgram,decompiler->{
            DecompileOptions options=new DecompileOptions();options.grabFromProgram(currentProgram);
            options.setMaxInstructions(maxInstructions);
            options.setMaxPayloadMBytes(64);decompiler.setOptions(options);
            decompiler.toggleCCode(true);decompiler.toggleSyntaxTree(false);decompiler.setSimplificationStyle("decompile");
        });setTimeout(timeoutSeconds);}
        @Override public ExportRecord process(DecompileResults result,TaskMonitor taskMonitor) {
            Work w=byAddress.get(result.getFunction().getEntryPoint().getOffset());
            return export(w,result,null);
        }
        @Override public ExportRecord process(Function f,TaskMonitor taskMonitor) throws Exception {
            Work w=byAddress.get(f.getEntryPoint().getOffset());
            if(successCache.containsKey(f.getEntryPoint().getOffset()))return export(w,null,null);
            try {taskMonitor.checkCancelled();return super.process(f,taskMonitor);}
            catch(CancelledException e) {throw e;}
            catch(Exception e) {return export(w,null,e);}
        }
    }
    @Override public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length<2)throw new IllegalArgumentException("Expected seeds TSV, export directory, optional timeout seconds, optional resume true/false, optional max instructions");
        timeoutSeconds=args.length>2?Integer.parseInt(args[2]):30;
        if(timeoutSeconds<1 || timeoutSeconds>3600)throw new IllegalArgumentException("Timeout must be 1..3600 seconds");
        boolean resume=args.length<4 || Boolean.parseBoolean(args[3]);
        maxInstructions=args.length>4?Integer.parseInt(args[4]):100000;
        if(maxInstructions<1 || maxInstructions>1000000)throw new IllegalArgumentException("Maximum instructions must be 1..1000000");
        out=Path.of(args[1]).toAbsolutePath().normalize();Files.createDirectories(out);progress(false,"");
        if(currentProgram.getImageBase().getOffset()!=0)throw new Exception("Wrong ELF image base; expected zero");
        Map<String,String> ends=new HashMap<>();
        for(String line:Files.readAllLines(Path.of(args[0]).resolveSibling("unwind-function-ranges.tsv"))) {
            String[] r=line.split("\t");if(r.length!=2)throw new Exception("Expected verified two-column unwind TSV");ends.put(r[0],r[1]);
        }
        if(ends.size()!=123152)throw new Exception("Expected all 123152 independently verified FDE extents");
        restoreCompilerExtents(ends); // Serial preflight only; workers below are read-only.
        List<String[]> rows=new ArrayList<>();
        for(Path source:List.of(Path.of(args[0]),Path.of(args[0]).resolveSibling("generic-method-seeds.tsv"))) {
            for(String line:Files.readAllLines(source,StandardCharsets.UTF_8))if(!line.isBlank()&&!line.startsWith("#")) {
                String[] r=line.split("\t",-1);if(r.length<4)throw new Exception("Invalid seed row");rows.add(r);
            }
        }
        rows.sort(Comparator.comparingInt((String[] r)->r.length>4?Integer.parseInt(r[4]):10)
            .thenComparingLong(r->Long.parseUnsignedLong(r[0].substring(2),16)));
        if(rows.size()!=93990)throw new Exception("Expected all 93990 managed implementation seeds, got "+rows.size());
        work=new ArrayList<>();byAddress=new HashMap<>();
        for(String[] row:rows) {
            Address entry=toAddr(row[0]);String end=ends.get(row[0]);if(end==null)throw new Exception("Missing compiler extent: "+row[0]);
            Address last=toAddr(end).subtract(1);Function f=getFunctionAt(entry);
            if(f!=null&&!f.getBody().equals(new AddressSet(entry,last)))throw new Exception("Function extent differs from independently decoded FDE: "+row[0]);
            Work w=new Work(work.size(),row,end,f,last.subtract(entry)+1);work.add(w);
            if(byAddress.put(entry.getOffset(),w)!=null)throw new Exception("Duplicate seed address");
        }
        if(resume)loadSuccessCache(); // MUST precede truncating the existing ledger.
        GThreadPool threads=GThreadPool.getPrivateThreadPool("Terraria export "+UUID.randomUUID());threads.setMaxThreadCount(4);
        Worker callback=new Worker();
        DecompilerConcurrentQ<Function,ExportRecord> queue=null;
        try(BufferedWriter l=Files.newBufferedWriter(out.resolve("coverage.jsonl"),StandardCharsets.UTF_8);
            BufferedWriter a=Files.newBufferedWriter(out.resolve("instructions.tsv"),StandardCharsets.UTF_8);
            BufferedWriter c=Files.newBufferedWriter(out.resolve("calls.tsv"),StandardCharsets.UTF_8)) {
            ledger=l;asm=a;calls=c;asm.write("function_entry\tinstruction_address\tbytes\tinstruction\n");calls.write("caller\tsource\ttarget\ttype\n");
            progress(false,"");monitor.initialize(work.size());
            // Bounded batches prevent a slow early method retaining an unbounded number
            // of later assembly strings in the deterministic pending-result map.
            // In pinned Ghidra12.1.4 the GThreadPool constructor registers this pool in
            // sharedPoolMap; isPrivate()==false, so queue disposal does not shut it down.
            if(threads.isPrivate())throw new Exception("Batch queues require a reusable Ghidra thread pool");
            for(int offset=0;offset<work.size();offset+=4096) {
                monitor.checkCancelled();int limit=Math.min(offset+4096,work.size());
                List<Function> functions=new ArrayList<>();
                for(Work w:work.subList(offset,limit)) {
                    if(w.function==null) {
                        ExportRecord r=new ExportRecord(w);r.timeout=timeoutSeconds;r.maxInstructions=maxInstructions;accept(r);
                    } else functions.add(w.function);
                }
                queue=new DecompilerConcurrentQ<>(callback,threads,false,monitor);
                queue.process(functions.iterator(),this::accept);queue.waitUntilDone();queue=null;
                monitor.checkCancelled();
                if(committed!=limit || !pending.isEmpty())throw new Exception("Incomplete bounded export batch ending "+limit);
                asm.flush();calls.flush();progress(false,"");
            }
            if(committed!=work.size()||completed!=work.size()||!pending.isEmpty())throw new Exception("Export did not produce exactly one result per seed");
            ledger.flush();asm.flush();calls.flush();progress(true,"");
        } catch(Exception e) {
            synchronized(outputLock) {progress(false,",\"aborted\":true,\"error\":\""+esc(e.toString())+"\"");}
            throw e;
        } finally {if(queue!=null)queue.dispose(Math.min(timeoutSeconds+5,60));callback.dispose();threads.shutdownNow();}
        println("TERRARIA_PARALLEL_EXPORT_COMPLETE total="+committed+" ok="+done+" failed="+failed+" missing="+missing);
    }

    private void loadSuccessCache() throws IOException {
        Path oldLedger=out.resolve("coverage.jsonl");if(!Files.isRegularFile(oldLedger))return;
        Set<Long> seen=new HashSet<>();long rejected=0;
        try(BufferedReader input=Files.newBufferedReader(oldLedger,StandardCharsets.UTF_8)) {
            String line;
            while((line=input.readLine())!=null) {
                try {
                    JsonObject row=JsonParser.parseString(line).getAsJsonObject();
                    long address=Long.parseUnsignedLong(row.get("address").getAsString().replace("0x",""),16);
                    if(!seen.add(address)) {successCache.remove(address);rejected++;continue;}
                    Work w=byAddress.get(address);
                    if(w==null || w.function==null || !"decompiled".equals(row.get("status").getAsString()) ||
                        !PROFILE.equals(row.get("profile").getAsString()) || row.get("image_base").getAsLong()!=0 ||
                        !w.end.equals(row.get("compiler_end_exclusive").getAsString()) ||
                        !w.row[2].equals(row.get("method").getAsString()) || !w.row[3].equals(row.get("image").getAsString())) {
                        rejected++;continue;
                    }
                    String relative=row.get("file").getAsString();Path file=out.resolve(relative).normalize();
                    if(relative.isBlank() || !file.startsWith(out) || !Files.isRegularFile(file) ||
                        !file.toRealPath().startsWith(out.toRealPath())) {rejected++;continue;}
                    StringBuilder header=new StringBuilder();
                    try(BufferedReader reader=Files.newBufferedReader(file,StandardCharsets.UTF_8)) {
                        for(int i=0;i<6;i++) {String s=reader.readLine();if(s==null)break;header.append(s).append('\n');}
                    }
                    String text=header.toString();
                    if(!text.startsWith("/* RECOVERED GHIDRA PSEUDOCODE; NOT ORIGINAL C#;") ||
                        !text.contains(" * Method: "+w.row[2].replace("*/","* /")+"\n") ||
                        !text.contains(" * ELF VA: "+w.row[0]+"; image base: 0\n") ||
                        !text.contains(" * Compiler unwind extent end-exclusive: "+w.end+"\n") ||
                        !text.contains(" * Analysis profile: "+PROFILE+"\n")) {rejected++;continue;}
                    successCache.put(address,row);
                } catch(RuntimeException | IOException e) {rejected++;} // Unreadable files/truncated final rows are never cached.
            }
        }
        println("TERRARIA_RESUME_CACHE valid="+successCache.size()+" rejected="+rejected+" profile="+PROFILE);
    }
}
