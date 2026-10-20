// Separate readonly-project experiment; helpers derived from frozen Coarse parent.
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.JumpTable;
import com.google.gson.*;
import java.nio.*;
import java.nio.file.*;
import java.util.*;
import java.io.IOException;
import java.lang.reflect.*;
import ghidra.program.model.pcode.Encoder;
import static ghidra.program.model.pcode.ElementId.*;
import static ghidra.program.model.pcode.AttributeId.*;

public class TerrariaLongBudgetCProbe extends TerrariaCoarseCopiesProbe {
    static final String SMOKE_FOLDER="pseudocode-long-budget-c-smoke-20261017";
    static final String EXTENDED_BASE="2855837418f2d00493efa3b5a03347dd636bd8a6a05cad0ad137f457e67973e6";
    static final String PROFILE="verified-known-islands-conditional-noreturn-long-budget-C-v4-stack32-v1";
    static final String PARENT="65f3e4f2fbc3c2965c9b2a49dced2c6e5042a2b156eaccc2badc42a4a60ceecb";
    static final String PROOF="04d8474fa751442c6fc2f01e1d11c40bba282e6e1ea04222e62a9a38e7f78245";
    static final String FDES="8b238f458b7a0505138fc56ea70ffe59c21d46a6b83ea2e4106f6f896a3f7756";
    static final long[] HELPERS={0x6ff6acL,0x741278L,0x74128cL,0x7411e0L};
    long word(byte[] elf,long a)throws Exception{return Integer.toUnsignedLong(ByteBuffer.wrap(source(elf,a,4)).order(ByteOrder.LITTLE_ENDIAN).getInt());}
    long branch(long w,long a)throws Exception{if((w>>>26)!=5)throw new Exception("Not unconditional B");long i=w&0x3ffffffL;return a+((i&0x2000000L)!=0?i-0x4000000L:i)*4;}
    JsonArray ranges(AddressSetView body){JsonArray a=new JsonArray();for(AddressRange r:body){JsonObject o=new JsonObject();o.addProperty("start","0x"+Long.toHexString(r.getMinAddress().getOffset()));o.addProperty("end_exclusive","0x"+Long.toHexString(r.getMaxAddress().getOffset()+1));a.add(o);}return a;}
    // Official options protocol, preserving all base options and the actual decompile action.
    static class UntypedOptions extends DecompileOptions {
        int injections=0;
        static void content(Encoder e,ghidra.program.model.pcode.ElementId id,String value)throws IOException{
            e.openElement(id);e.writeString(ATTRIB_CONTENT,value);e.closeElement(id);
        }
        @Override public void encode(Encoder encoder,DecompInterface iface)throws IOException{
            if(!"decompile".equals(iface.getSimplificationStyle()))throw new IOException("Actual C action required");
            Encoder wrapper=(Encoder)Proxy.newProxyInstance(Encoder.class.getClassLoader(),new Class<?>[]{Encoder.class},(proxy,method,args)->{
                if(method.getName().equals("closeElement")&&args!=null&&args.length==1&&args[0]==ELEM_OPTIONSLIST){
                    encoder.openElement(ELEM_CURRENTACTION);
                    content(encoder,ELEM_PARAM1,"decompile");content(encoder,ELEM_PARAM2,"typerecovery");content(encoder,ELEM_PARAM3,"off");
                    encoder.closeElement(ELEM_CURRENTACTION);injections++;
                }
                try{return method.invoke(encoder,args);}catch(InvocationTargetException error){throw error.getCause();}
            });
            super.encode(wrapper,iface);
        }
    }
    static final String UNTYPED_BASE="4caba66f21b937c30a2f8af10692d22af3acca8e7a25b8b98989ee56f1749ad2";
    public void run()throws Exception{
        String[] args=getScriptArgs();if(args.length<4||args.length>5)throw new Exception("lab own-source fresh-folder address [c-smoke]");
        boolean smoke=args.length==5&&args[4].equals("c-smoke");if(args.length==5&&!smoke)throw new Exception("Unknown fifth argument");
        Path lab=Path.of(args[0]).toAbsolutePath().normalize(),script=Path.of(args[1]).toAbsolutePath().normalize();String folder=args[2];
        if(!folder.startsWith("pseudocode-long-budget-c-")||folder.contains("/")||folder.contains("\\")||!script.getFileName().toString().equals("TerrariaLongBudgetCProbe.java"))throw new Exception("Separate model paths required");
        if(!hash(Files.readAllBytes(script.resolveSibling("TerrariaUntypedCProbe.java"))).equals(UNTYPED_BASE))throw new Exception("Frozen Untyped source differs");
        Path out=lab.resolve(folder);if(Files.exists(out))throw new Exception("Fresh output directory required");
        if(!hash(Files.readAllBytes(script.resolveSibling("TerrariaCoarseCopiesProbe.java"))).equals(PARENT))throw new Exception("Frozen helper parent differs");
        if(!hash(Files.readAllBytes(script.resolveSibling("TerrariaExtendedNoreturnProbe.java"))).equals(EXTENDED_BASE))throw new Exception("Frozen Extended source differs");
        JsonObject smokeGate=null;String smokeResultHash=null,smokeAuditHash=null;
        if(smoke){if(!folder.equals(SMOKE_FOLDER))throw new Exception("Use dedicated fixed C smoke folder");}
        else{
            Path smokeDir=lab.resolve(SMOKE_FOLDER),smokeResult=smokeDir.resolve("result.json"),smokeAudit=smokeDir.resolve("audit.json");
            smokeGate=JsonParser.parseString(Files.readString(smokeResult)).getAsJsonObject();JsonObject audited=JsonParser.parseString(Files.readString(smokeAudit)).getAsJsonObject();
            smokeResultHash=hash(Files.readAllBytes(smokeResult));smokeAuditHash=hash(Files.readAllBytes(smokeAudit));
            if(!smokeGate.get("c_smoke").getAsBoolean()||!smokeGate.get("status").getAsString().equals("decompiled_conditional_candidate")||!smokeGate.get("script_sha256").getAsString().equals(hash(Files.readAllBytes(script)))||!audited.get("integrity_passed").getAsBoolean()||!audited.get("result_sha256").getAsString().equals(smokeResultHash)||!audited.get("auditor_sha256").getAsString().equals(hash(Files.readAllBytes(script.resolveSibling("audit_terraria_long_budget_c.py")))))throw new Exception("Successful audited same-source C smoke required");
        }
        Path maps=lab.resolve("hard-switches-v2/switches.json"),flowPath=lab.resolve("native/flow-islands.json"),fdePath=lab.resolve("native/unwind-function-ranges.tsv"),proofPath=lab.resolve("nullguard-noreturn-model-20261015/evidence.json");
        byte[] elf=Files.readAllBytes(lab.resolve("native/libil2cpp.so"));if(!hash(elf).equals(ELF)||!ELF.equalsIgnoreCase(currentProgram.getExecutableSHA256()))throw new Exception("Original ELF mismatch");
        if(!hash(Files.readAllBytes(fdePath)).equals(FDES)||!hash(Files.readAllBytes(proofPath)).equals(PROOF))throw new Exception("Frozen evidence mismatch");
        JsonObject proof=JsonParser.parseString(Files.readString(proofPath)).getAsJsonObject();if(!proof.get("integrity_passed").getAsBoolean()||!proof.get("elf_sha256").getAsString().equals(ELF))throw new Exception("Proof identity");
        Set<Long> helperSet=new TreeSet<>();for(long h:HELPERS)helperSet.add(h);Set<Long> proven=new TreeSet<>();for(JsonElement e:proof.getAsJsonArray("conditional_noreturn_entry_points"))proven.add(num(e));if(!helperSet.equals(proven))throw new Exception("Proof helper set");
        Path proofAuditor=script.resolveSibling("audit_terraria_nullguard_noreturn_model.py");if(!hash(Files.readAllBytes(proofAuditor)).equals(proof.get("auditor_sha256").getAsString()))throw new Exception("Proof auditor differs");
        for(JsonElement e:proof.getAsJsonArray("source_functions")){JsonObject v=e.getAsJsonObject();long lo=num(v.get("entry"));int size=Math.toIntExact(num(v.get("end_exclusive"))-lo);verify(elf,lo,size);if(!HexFormat.of().formatHex(source(elf,lo,size)).equals(v.get("raw_bytes").getAsString()))throw new Exception("Proof native bytes");}
        Path engine=ghidra.framework.Application.getOSFile("decompile.exe").toPath().toRealPath();if(!hash(Files.readAllBytes(engine)).equals(ENGINE))throw new Exception("Wrong engine");
        JsonObject method=null,all=JsonParser.parseString(Files.readString(maps)).getAsJsonObject();long start=Long.decode(args[3]);for(JsonElement e:all.getAsJsonArray("methods"))if(num(e.getAsJsonObject().get("address"))==start)method=e.getAsJsonObject();if(smoke){if(start!=0x74129cL)throw new Exception("C smoke restricted to small known factory helper");
            for(String line:Files.readAllLines(fdePath)){String[] parts=line.split("\\t");if(Long.decode(parts[0])==start){method=new JsonObject();method.addProperty("address","0x"+Long.toHexString(start));method.addProperty("end_exclusive",parts[1]);method.addProperty("method","small-native-factory-0x74129c-C-smoke");method.add("switch_candidates",new JsonArray());break;}}
        }if(method==null)throw new Exception("No chosen method");
        if(!smoke&&!Set.of(0xf6954cL,0xf9a914L,0xfcbda0L,0x11242ecL,0x1484e54L,0x911f1cL,0xb1ab78L,0x1635538L).contains(start))throw new Exception("Outside reviewed island scope");
        long end=num(method.get("end_exclusive"));Function f=getFunctionAt(addr(start));AddressSet original=new AddressSet(addr(start),addr(end-1));if(f==null||!f.getBody().equals(original))throw new Exception("Original body is not exact FDE");verify(elf,start,Math.toIntExact(end-start));
        ArrayList<long[]> fdes=new ArrayList<>();for(String line:Files.readAllLines(fdePath)){String[] p=line.split("\\t");fdes.add(new long[]{Long.decode(p[0]),Long.decode(p[1])});}if(fdes.size()!=123152)throw new Exception("FDE count");
        JsonArray flows=JsonParser.parseString(Files.readString(flowPath)).getAsJsonArray(),islands=new JsonArray();AddressSet extended=new AddressSet(original),extra=new AddressSet();
        for(JsonElement e:flows){JsonObject r=e.getAsJsonObject();if(num(r.get("fde_start"))!=start||!r.get("proven_encoded_path").getAsBoolean())continue;if(num(r.get("fde_end_exclusive"))!=end)throw new Exception("FDE bounds mismatch");
            long origin=num(r.get("origin")),target=num(r.get("target"));JsonArray steps=r.getAsJsonArray("steps");if(steps.size()!=2||origin<start||origin>=end||branch(word(elf,origin),origin)!=target)throw new Exception("Island origin");
            if(!HexFormat.of().formatHex(source(elf,origin,4)).equals(r.get("origin_raw_bytes").getAsString()))throw new Exception("Origin bytes");
            for(int i=0;i<2;i++){JsonObject s=steps.get(i).getAsJsonObject();long pc=num(s.get("address"));if(pc!=target+4*i||!HexFormat.of().formatHex(source(elf,pc,4)).equals(s.get("raw_bytes").getAsString()))throw new Exception("Island bytes/order");for(long[] range:fdes)if(pc>=range[0]&&pc<range[1])throw new Exception("Island overlaps FDE");verify(elf,pc,4);Function owner=getFunctionContaining(addr(pc));if(owner!=null)throw new Exception("Island already owned by a saved function");}
            if((word(elf,target)&0xffc00000L)!=0xf9400000L||branch(word(elf,target+4),target+4)!=origin+4||num(r.get("return_target"))!=origin+4||origin+4>=end)throw new Exception("Not LDR-X then original continuation");
            for(JsonElement other:flows){JsonObject r2=other.getAsJsonObject();if(!r2.get("proven_encoded_path").getAsBoolean()||num(r2.get("fde_start"))==start)continue;for(JsonElement s:r2.getAsJsonArray("steps")){long pc=num(s.getAsJsonObject().get("address"));if(pc==target||pc==target+4)throw new Exception("Known shared island ownership");}}
            extra.add(addr(target),addr(target+7));extended.add(addr(target),addr(target+7));islands.add(r.deepCopy());
        }
        boolean exactFde=false;for(long[] r:fdes)if(r[0]==start&&r[1]==end)exactFde=true;if(!exactFde)throw new Exception("Chosen method not exact catalogue FDE");
        Function factory=getFunctionAt(addr(0x74129cL));if(factory==null||factory.hasNoReturn())throw new Exception("Factory must remain may-return");
        JsonObject rec=new JsonObject();rec.addProperty("derived_from_untyped_sha256",UNTYPED_BASE);rec.addProperty("only_budget_changed",true);rec.addProperty("baseline_hard_timeout_seconds",600);rec.addProperty("budget_change_is_analysis_improvement",false);rec.addProperty("profile",PROFILE);rec.addProperty("method",method.get("method").getAsString());rec.addProperty("address","0x"+Long.toHexString(start));rec.addProperty("end_exclusive","0x"+Long.toHexString(end));rec.addProperty("elf_sha256",ELF);rec.addProperty("script_sha256",hash(Files.readAllBytes(script)));rec.addProperty("derived_from_parent_sha256",PARENT);rec.addProperty("fde_catalogue_sha256",FDES);rec.addProperty("flow_islands_sha256",hash(Files.readAllBytes(flowPath)));rec.addProperty("switch_maps_sha256",hash(Files.readAllBytes(maps)));rec.addProperty("noreturn_model_evidence_sha256",PROOF);rec.addProperty("noreturn_model_auditor_sha256",hash(Files.readAllBytes(proofAuditor)));rec.addProperty("actual_engine_sha256",ENGINE);rec.addProperty("function_source_sha256",hash(source(elf,start,Math.toIntExact(end-start))));rec.addProperty("function_source_bytes_verified",end-start);rec.add("known_islands",islands);rec.add("original_body_ranges",ranges(original));rec.add("extended_body_ranges",ranges(extended));rec.add("additional_ABI_assumptions",proof.get("assumptions"));rec.addProperty("conditional_assumptions","Known direct B-LDR-B paths only; all incoming edges, global CFG, switch guard dominance and runtime reachability unproved. Standard C++ throw normal-noreturn ABI and no exceptional/nonlocal helper reentry are assumed.");rec.addProperty("runtime_verified",false);rec.addProperty("semantic_equivalence_verified",false);rec.addProperty("saved_project_modified",false);rec.addProperty("read_only_disposable_project_lifecycle_required",true);rec.addProperty("split_structures",false);rec.addProperty("split_arrays",false);rec.addProperty("split_pointers",false);rec.addProperty("timeout_seconds",smoke?60:1800);rec.addProperty("max_instructions",250000);rec.addProperty("max_payload_mb",256);rec.addProperty("factory_0x74129c_before_no_return",false);
        if(!smoke){rec.addProperty("prerequisite_C_smoke_folder",SMOKE_FOLDER);rec.addProperty("prerequisite_C_smoke_result_sha256",smokeResultHash);rec.addProperty("prerequisite_C_smoke_audit_sha256",smokeAuditHash);}rec.addProperty("derived_from_extended_sha256",EXTENDED_BASE);rec.addProperty("c_smoke",smoke);rec.addProperty("simplification_style","decompile");rec.addProperty("typerecovery_enabled",false);rec.addProperty("retained_final_groups","merge,casts,cleanup,blockrecovery");rec.addProperty("actual_engine_path",engine.toString());rec.addProperty("original_body_exact_fde_verified",true);rec.addProperty("islands_previously_unowned_in_saved_program_verified",true);rec.addProperty("islands_single_known_catalogue_owner_verified",true);rec.addProperty("islands_outside_all_catalogue_fdes_verified",true);rec.addProperty("canonical_journals_modified",false);
        JsonArray annotations=new JsonArray(),hints=new JsonArray();rec.add("conditional_noreturn_annotations",annotations);rec.add("applied_hints",hints);Files.createDirectories(out);int tx=currentProgram.startTransaction("Known external islands and conditional throw annotations");DecompInterface dc=new DecompInterface();Exception restoreError=null;
        try{
            for(long h:HELPERS){Function helper=getFunctionAt(addr(h));if(helper==null||helper.hasNoReturn())throw new Exception("Expected unannotated helper");JsonObject a=new JsonObject();a.addProperty("address","0x"+Long.toHexString(h));a.addProperty("before_no_return",false);annotations.add(a);helper.setNoReturn(true);a.addProperty("during_no_return",helper.hasNoReturn());if(!helper.hasNoReturn())throw new Exception("Annotation failed");}
            int disassembled=0;for(AddressRange range:extra){for(long pc=range.getMinAddress().getOffset();pc<=range.getMaxAddress().getOffset();pc+=4){Instruction ins=currentProgram.getListing().getInstructionAt(addr(pc));if(ins==null){AddressSet restricted=new AddressSet(addr(pc),addr(pc+3));DisassembleCommand cmd=new DisassembleCommand(addr(pc),restricted,false);if(!cmd.applyTo(currentProgram,monitor))throw new Exception("Bounded island disassembly failed");disassembled++;}ins=currentProgram.getListing().getInstructionAt(addr(pc));if(ins==null||ins.getLength()!=4)throw new Exception("Missing island instruction");}}
            rec.addProperty("bounded_island_disassembly_count",disassembled);rec.addProperty("island_instruction_count_verified",extra.getNumAddresses()/4);f.setBody(extended);rec.addProperty("extended_body_applied_verified",f.getBody().equals(extended));if(!f.getBody().equals(extended))throw new Exception("Extended body not applied");
            int entries=0;for(JsonElement e:method.getAsJsonArray("switch_candidates")){JsonObject map=e.getAsJsonObject();long br=num(map.get("branch"));Instruction ins=currentProgram.getListing().getInstructionAt(addr(br));if(ins==null||!ins.getMnemonicString().equalsIgnoreCase("br"))throw new Exception("Not BR");verify(elf,br,4);verify(elf,num(map.get("table")),map.get("count").getAsInt()*map.get("width").getAsInt());ArrayList<Address> targets=new ArrayList<>();JsonArray dest=new JsonArray();for(JsonElement item:map.getAsJsonArray("entries")){long target=num(item.getAsJsonObject().get("target"));if(target<start||target>=end)throw new Exception("Nonlocal switch target");verify(elf,target,4);targets.add(addr(target));dest.add("0x"+Long.toHexString(target));entries++;}new JumpTable(addr(br),targets,true,0).writeOverride(f);JsonObject hint=new JsonObject();hint.addProperty("branch",map.get("branch").getAsString());hint.add("targets",dest);hints.add(hint);}
            rec.addProperty("applied_hint_count",hints.size());rec.addProperty("applied_entry_count",entries);rec.addProperty("factory_0x74129c_during_no_return",factory.hasNoReturn());if(factory.hasNoReturn())throw new Exception("Factory changed");rec.addProperty("status","attempting");Files.writeString(out.resolve("scope.json"),gson.toJson(rec));
            UntypedOptions options=new UntypedOptions();options.grabFromProgram(currentProgram);options.setSplitStructures(false);options.setSplitArrays(false);options.setSplitPointers(false);options.setMaxInstructions(250000);options.setMaxPayloadMBytes(256);
            if(!dc.setSimplificationStyle("decompile")||!dc.toggleCCode(true)||!dc.toggleSyntaxTree(false)||!dc.setOptions(options))throw new Exception("Pre-open options rejected");
            if(!dc.openProgram(currentProgram))throw new Exception(dc.getLastMessage());
            rec.addProperty("open_program_accepted",true);rec.addProperty("options_accepted_after_open",dc.setOptions(options));
            rec.addProperty("option_injection_count_before_decompile",options.injections);
            if(!rec.get("options_accepted_after_open").getAsBoolean()||options.injections<2)throw new Exception("Untyped C option protocol not accepted");
            rec.addProperty("decompiler_invoked",true);long begin=System.nanoTime();DecompileResults result=dc.decompileFunction(f,smoke?60:1800,monitor);
            rec.addProperty("elapsed_seconds",(System.nanoTime()-begin)/1e9);rec.addProperty("message",result.getErrorMessage());rec.addProperty("timed_out",result.isTimedOut());rec.addProperty("decompile_completed",result.decompileCompleted());
            rec.addProperty("option_injection_count_after_decompile",options.injections);rec.addProperty("actual_C_object_returned",result.getDecompiledFunction()!=null);
            if(result.decompileCompleted()&&result.getDecompiledFunction()!=null){String body=result.getDecompiledFunction().getC();if(body==null||body.isBlank())throw new Exception("Empty C body");Path c=out.resolve("conditional_candidate.c");Files.writeString(c,"/* CONDITIONAL UNTYPED GHIDRA C: decompile action retained; typerecovery subgroup off; verified known islands and conditional NoReturn/switch premises; weaker recovered types; not original C# or semantic-equivalence proof. */\n"+body);rec.addProperty("status","decompiled_conditional_candidate");rec.addProperty("file",c.getFileName().toString());rec.addProperty("c_bytes",Files.size(c));rec.addProperty("c_sha256",hash(Files.readAllBytes(c)));}else rec.addProperty("status","decompile_failed");

        }catch(Exception error){rec.addProperty("status","probe_error");rec.addProperty("message",error.toString());throw error;}
        finally{
            boolean bodyRestored=false,closed=false;
            try{f.setBody(original);bodyRestored=f.getBody().equals(original);rec.addProperty("original_body_explicitly_restored_before_close",bodyRestored);}catch(Exception e){restoreError=e;}
            for(JsonElement e:annotations){JsonObject a=e.getAsJsonObject();try{Function h=getFunctionAt(addr(num(a.get("address"))));h.setNoReturn(false);a.addProperty("explicitly_restored_before_close",!h.hasNoReturn());}catch(Exception err){if(restoreError==null)restoreError=err;else restoreError.addSuppressed(err);}}
            try{dc.dispose();}catch(Exception e){if(restoreError==null)restoreError=e;else restoreError.addSuppressed(e);}
            rec.addProperty("outer_transaction_rollback_requested",true);try{currentProgram.endTransaction(tx,false);closed=true;}catch(Exception e){if(restoreError==null)restoreError=e;else restoreError.addSuppressed(e);}
            boolean ok=bodyRestored&&f.getBody().equals(original)&&closed&&annotations.size()==4&&!factory.hasNoReturn();for(JsonElement e:annotations){JsonObject a=e.getAsJsonObject();boolean restored=!getFunctionAt(addr(num(a.get("address")))).hasNoReturn();a.addProperty("original_no_return_restored",restored);ok&=restored&&a.has("explicitly_restored_before_close")&&a.get("explicitly_restored_before_close").getAsBoolean();}
            rec.addProperty("original_body_restored_after_close_check",f.getBody().equals(original));rec.addProperty("factory_0x74129c_after_no_return",factory.hasNoReturn());rec.addProperty("transaction_close_returned",closed);rec.addProperty("explicit_model_restoration_verified",ok&&restoreError==null);if(!ok||restoreError!=null){rec.addProperty("status","probe_error");rec.addProperty("restoration_error",restoreError==null?"Incomplete lifecycle":restoreError.toString());}Files.writeString(out.resolve("result.json"),gson.toJson(rec));if(restoreError!=null)throw restoreError;if(!ok)throw new Exception("Incomplete restoration");
        }
    }
}
