// Isolated experiments only. Never updates canonical coverage or program metadata.
// normalize/register/firstpass outputs are P-code diagnostics, NOT valid C or original source.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.*;
import static ghidra.program.model.pcode.ElementId.*;
import static ghidra.program.model.pcode.AttributeId.*;
import com.google.gson.*;
import java.lang.reflect.*;
import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class TerrariaHardFunctionProbe extends GhidraScript {
    private static final String CANONICAL="bounded-fde-terminal-calls-signatures-v3";
    private static final long[] ADDRESSES={0x12f63e8L,0x1423370L,0x1635538L};
    private final Gson gson=new Gson();
    private record Profile(String name,String style,boolean candidateC,boolean unreachable,boolean light,String disabledGroup) {}
    private static final Map<String,Profile> PROFILES=new LinkedHashMap<>();
    static {
        PROFILES.put("firstpass",new Profile("firstpass","firstpass",false,true,false,""));
        PROFILES.put("register",new Profile("register","register",false,true,false,""));
        PROFILES.put("normalize",new Profile("normalize","normalize",false,true,false,""));
        PROFILES.put("decompile_light",new Profile("decompile_light","decompile",true,true,true,""));
        PROFILES.put("decompile_no_merge",new Profile("decompile_no_merge","decompile",false,true,true,"merge"));
        PROFILES.put("decompile_no_deadcode",new Profile("decompile_no_deadcode","decompile",false,true,true,"deadcode"));
        PROFILES.put("decompile_no_unreachable",new Profile("decompile_no_unreachable","decompile",true,false,true,""));
    }
    private static String safe(String s){return s.replaceAll("[^A-Za-z0-9_.-]","_");}
    private static String hex(long v){return "0x"+Long.toHexString(v);}

    // Preserve ALL normal options and append the official OptionCurrentAction inside the
    // existing optionslist. No private DecompInterface fields or native reflection are used.
    private class ActionOptions extends DecompileOptions {
        private final String group;
        ActionOptions(String group){this.group=group;}
        @Override public void encode(Encoder actual,DecompInterface iface)throws IOException {
            if(group.isEmpty()){super.encode(actual,iface);return;}
            Encoder wrapped=(Encoder)Proxy.newProxyInstance(Encoder.class.getClassLoader(),new Class<?>[]{Encoder.class},(proxy,method,args)->{
                if(method.getName().equals("closeElement")&&args!=null&&args.length==1&&ELEM_OPTIONSLIST.equals(args[0])) {
                    actual.openElement(ELEM_CURRENTACTION);
                    actual.openElement(ELEM_PARAM1);actual.writeString(ATTRIB_CONTENT,iface.getSimplificationStyle());actual.closeElement(ELEM_PARAM1);
                    actual.openElement(ELEM_PARAM2);actual.writeString(ATTRIB_CONTENT,group);actual.closeElement(ELEM_PARAM2);
                    actual.openElement(ELEM_PARAM3);actual.writeString(ATTRIB_CONTENT,"off");actual.closeElement(ELEM_PARAM3);
                    actual.closeElement(ELEM_CURRENTACTION);
                }
                try{return method.invoke(actual,args);}catch(InvocationTargetException e){throw e.getCause();}
            });
            super.encode(wrapped,iface);
        }
    }
    private void treeArtifacts(HighFunction high,Path destination,JsonObject record)throws Exception {
        long operations=0,sampled=0;final long SAMPLE_LIMIT=10000;
        try(BufferedWriter writer=Files.newBufferedWriter(destination.resolve("pcode-sample.jsonl"),StandardCharsets.UTF_8)) {
            Iterator<PcodeOpAST> it=high.getPcodeOps();
            while(it.hasNext()) {
                monitor.checkCancelled();PcodeOpAST op=it.next();operations++;
                if(sampled<SAMPLE_LIMIT) {
                    JsonObject row=new JsonObject();row.addProperty("address",op.getSeqnum().getTarget().toString());
                    row.addProperty("sequence",op.getSeqnum().getTime());row.addProperty("pcode",op.toString());writer.write(gson.toJson(row));writer.newLine();sampled++;
                }
            }
        }
        record.addProperty("pcode_operations",operations);record.addProperty("pcode_sample_operations",sampled);
        record.addProperty("pcode_sample_truncated",operations>sampled);
        var blocks=high.getBasicBlocks();record.addProperty("basic_blocks",blocks.size());
        try(BufferedWriter writer=Files.newBufferedWriter(destination.resolve("basic-blocks.tsv"),StandardCharsets.UTF_8)) {
            writer.write("block\tstart\tstop\toutgoing_blocks\n");
            for(PcodeBlockBasic block:blocks) {
                StringJoiner edges=new StringJoiner(",");for(int i=0;i<block.getOutSize();i++)edges.add(Integer.toString(block.getOut(i).getIndex()));
                writer.write(block.getIndex()+"\t"+block.getStart()+"\t"+block.getStop()+"\t"+edges+"\n");
            }
        }
    }
    public void run()throws Exception {
        String[] args=getScriptArgs();if(args.length<1)throw new Exception("Args: isolated-output-directory [timeout=30] [maxInstructions=250000] [commaProfiles] [verifiedFdeTsv]");
        Path output=Path.of(args[0]).toAbsolutePath().normalize();
        if(Files.exists(output.resolve("coverage.jsonl"))||output.getFileName().toString().equals("pseudocode"))throw new Exception("Use a dedicated probe directory, not canonical pseudocode directory");
        Files.createDirectories(output);int timeout=args.length>1?Integer.parseInt(args[1]):30;
        int maxInstructions=args.length>2?Integer.parseInt(args[2]):250000;
        if(timeout<1||timeout>120||maxInstructions<1||maxInstructions>1000000)throw new Exception("Probe bounds: timeout1..120, maxInstructions1..1000000");
        String chosen=args.length>3?args[3]:"firstpass,register,normalize,decompile_light,decompile_no_merge";
        List<Profile> profiles=new ArrayList<>();for(String name:chosen.split(",")){Profile p=PROFILES.get(name);if(p==null)throw new Exception("Unknown probe profile "+name);profiles.add(p);}
        Path fde=args.length>4?Path.of(args[4]):Path.of("C:/Temp/terraria-re-20261012/native/unwind-function-ranges.tsv");
        Map<Long,Long> ends=new HashMap<>();for(String line:Files.readAllLines(fde,StandardCharsets.UTF_8)) {
            String[] r=line.split("\t");ends.put(Long.parseUnsignedLong(r[0].replace("0x",""),16),Long.parseUnsignedLong(r[1].replace("0x",""),16));
        }
        if(currentProgram.getImageBase().getOffset()!=0||!currentProgram.getLanguageID().toString().equals("AARCH64:LE:64:v8A")||ends.size()!=123152)throw new Exception("Requires verified ARM64 base0 saved program/FDE catalogue");
        // Create a unique attempt directory so repeated probes retain their prior evidence.
        Path attempt=output.resolve("attempt-"+System.currentTimeMillis());Files.createDirectories(attempt);
        try(BufferedWriter ledger=Files.newBufferedWriter(attempt.resolve("probe-results.jsonl"),StandardCharsets.UTF_8)) {
            for(long address:ADDRESSES) {
                Function function=getFunctionAt(toAddr(hex(address)));Long end=ends.get(address);
                if(function==null||end==null||!function.getBody().equals(new AddressSet(function.getEntryPoint(),toAddr(hex(end-1)))))throw new Exception("Function body differs from compiler FDE at "+hex(address));
                long instructionCount=0;InstructionIterator listing=currentProgram.getListing().getInstructions(function.getBody(),true);while(listing.hasNext()){listing.next();instructionCount++;}
                for(Profile profile:profiles) {
                    monitor.checkCancelled();Path destination=attempt.resolve(hex(address)+"-"+profile.name());Files.createDirectories(destination);
                    JsonObject record=new JsonObject();record.addProperty("address",hex(address));record.addProperty("method",function.getName());
                    record.addProperty("compiler_end_exclusive",hex(end));record.addProperty("image_base",0);record.addProperty("listing_instructions",instructionCount);
                    record.addProperty("canonical_model",CANONICAL);record.addProperty("probe_profile","hard-function-probe-v1/"+profile.name());
                    record.addProperty("simplification_style",profile.style());record.addProperty("disabled_action_group",profile.disabledGroup());
                    record.addProperty("light_options",profile.light());record.addProperty("eliminate_unreachable",profile.unreachable());
                    record.addProperty("timeout_seconds",timeout);record.addProperty("max_instructions",maxInstructions);record.addProperty("max_payload_mbytes",256);
                    record.addProperty("timing_includes_output_decode",true);record.addProperty("c_output_enabled",profile.candidateC());record.addProperty("syntax_tree_enabled",!profile.candidateC());
                    record.addProperty("c_validity",profile.candidateC()?"candidate_requires_manual_review_not_recompiled":"not_C_Pcode_diagnostic_only");
                    record.addProperty("canonical_ledger_changed",false);record.addProperty("runtime_verified",false);
                    println("TERRARIA_HARD_PROBE_START "+hex(address)+" "+profile.name());
                    DecompInterface decompiler=new DecompInterface();long start=System.nanoTime();
                    try {
                        decompiler.setSimplificationStyle(profile.style());decompiler.toggleCCode(profile.candidateC());decompiler.toggleSyntaxTree(!profile.candidateC());
                        ActionOptions options=new ActionOptions(profile.disabledGroup());options.grabFromProgram(currentProgram);
                        options.setMaxInstructions(maxInstructions);options.setMaxPayloadMBytes(256);options.setEliminateUnreachable(profile.unreachable());
                        if(profile.light()) {
                            options.setPredicate(false);options.setSimplifyDoublePrecision(false);options.setAnalyzeForLoops(false);
                            options.setSplitStructures(false);options.setSplitArrays(false);options.setSplitPointers(false);
                        }
                        if(!decompiler.setOptions(options)||!decompiler.openProgram(currentProgram))throw new Exception("Decompiler initialization failed: "+decompiler.getLastMessage());
                        start=System.nanoTime();DecompileResults result=decompiler.decompileFunction(function,timeout,monitor);
                        record.addProperty("decompile_elapsed_ms",(System.nanoTime()-start)/1000000);
                        record.addProperty("decompile_completed",result.decompileCompleted());record.addProperty("error",result.getErrorMessage());
                        if(result.decompileCompleted()) {
                            if(profile.candidateC()&&result.getDecompiledFunction()!=null) {
                                String header="/* EXPERIMENTAL GHIDRA PSEUDOCODE; NOT ORIGINAL SOURCE; NOT RECOMPILED.\n * Probe: "+profile.name()+"; VA: "+hex(address)+"; FDE end-exclusive: "+hex(end)+"\n */\n";
                                Files.writeString(destination.resolve("candidate.c"),header+result.getDecompiledFunction().getC(),StandardCharsets.UTF_8);
                                record.addProperty("candidate_c_written",true);
                            } else if(result.getHighFunction()!=null)treeArtifacts(result.getHighFunction(),destination,record);
                        }
                    }catch(Exception e) {record.addProperty("exception",e.toString());record.addProperty("elapsed_until_exception_ms",(System.nanoTime()-start)/1000000);}
                    finally{decompiler.dispose();}
                    record.addProperty("artifact_directory",destination.toString());
                    Files.writeString(destination.resolve("result.json"),gson.toJson(record),StandardCharsets.UTF_8);
                    ledger.write(gson.toJson(record));ledger.newLine();ledger.flush();
                    println("TERRARIA_HARD_PROBE_RESULT "+gson.toJson(record));
                }
            }
        }
        println("TERRARIA_HARD_PROBE_COMPLETE "+attempt);
    }
}
