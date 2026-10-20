// Separate conditional model. Use only on a read-only disposable project copy.
import ghidra.program.model.listing.*;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;

public class TerrariaNoreturnCoarseProbe extends TerrariaCoarseCopiesProbe {
    static final String MODEL="conditional-standard-cxx-throw-noreturn-aggregate-unsplit-typed-v4-stack32-v1";
    static final String PARENT="65f3e4f2fbc3c2965c9b2a49dced2c6e5042a2b156eaccc2badc42a4a60ceecb";
    static final String PROOF="04d8474fa751442c6fc2f01e1d11c40bba282e6e1ea04222e62a9a38e7f78245";
    static final String C_HEADER="/* ADDITIONAL CONDITIONAL MODEL: standard __cxa_throw has no normal return; no exceptional/nonlocal wrapper reentry; four helper NoReturn annotations plus aggregate-copy splitting disabled. ABI contract is assumed. Not original source, global-guard-dominance, runtime or semantic-equivalence proof. */\n";
    static final long FACTORY=0x74129cL;
    public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=4)throw new Exception("Expected lab, own source, fresh folder, address or transaction-smoke");
        Path lab=Path.of(args[0]).toAbsolutePath().normalize(),script=Path.of(args[1]).toAbsolutePath().normalize();
        String folder=args[2];
        if(!folder.startsWith("pseudocode-noreturn-coarse-")||!Path.of(folder).getFileName().toString().equals(folder)||folder.contains("/")||folder.contains("\\"))throw new Exception("Separate direct-child model output required");
        Path out=lab.resolve(folder);
        if(Files.exists(out.resolve("result.json"))||Files.exists(out.resolve("model-scope.json")))throw new Exception("Refusing repeated model trial");
        if(!script.getFileName().toString().equals("TerrariaNoreturnCoarseProbe.java"))throw new Exception("Own source path required");
        Path parentPath=script.resolveSibling("TerrariaCoarseCopiesProbe.java"),proofPath=lab.resolve("nullguard-noreturn-model-20261015/evidence.json"),proofAuditor=script.resolveSibling("audit_terraria_nullguard_noreturn_model.py");
        String parentSHA=hash(Files.readAllBytes(parentPath)),proofSHA=hash(Files.readAllBytes(proofPath));
        if(!parentSHA.equals(PARENT)||!proofSHA.equals(PROOF))throw new Exception("Frozen parent/proof changed");
        JsonObject proof=JsonParser.parseString(Files.readString(proofPath)).getAsJsonObject();
        if(!proof.get("integrity_passed").getAsBoolean()||!proof.get("elf_sha256").getAsString().equals(ELF)||!hash(Files.readAllBytes(proofAuditor)).equals(proof.get("auditor_sha256").getAsString()))throw new Exception("Conditional proof identity mismatch");
        Set<Long> wanted=new TreeSet<>(List.of(0x6ff6acL,0x741278L,0x74128cL,0x7411e0L)),actual=new TreeSet<>();
        for(JsonElement v:proof.getAsJsonArray("conditional_noreturn_entry_points"))actual.add(num(v));
        if(!actual.equals(wanted))throw new Exception("Unexpected annotation scope");
        byte[] elf=Files.readAllBytes(lab.resolve("native/libil2cpp.so"));
        if(!hash(elf).equals(ELF)||!ELF.equalsIgnoreCase(currentProgram.getExecutableSHA256()))throw new Exception("Original ELF/program mismatch");
        for(JsonElement item:proof.getAsJsonArray("source_functions")){
            JsonObject f=item.getAsJsonObject();long lo=num(f.get("entry")),hi=num(f.get("end_exclusive"));int size=Math.toIntExact(hi-lo);verify(elf,lo,size);
            if(!HexFormat.of().formatHex(source(elf,lo,size)).equals(f.get("raw_bytes").getAsString()))throw new Exception("Conditional proof source bytes differ");
        }
        Path engine=ghidra.framework.Application.getOSFile("decompile.exe").toPath().toRealPath();
        if(!hash(Files.readAllBytes(engine)).equals(ENGINE))throw new Exception("Actual engine differs");
        Function factory=getFunctionAt(addr(FACTORY));
        if(factory==null||factory.hasNoReturn())throw new Exception("Factory must retain ordinary may-return annotation");
        JsonObject model=new JsonObject();
        model.addProperty("profile",MODEL);model.addProperty("elf_sha256",ELF);model.addProperty("script_sha256",hash(Files.readAllBytes(script)));
        model.addProperty("parent_helper_sha256",parentSHA);model.addProperty("noreturn_model_evidence_sha256",proofSHA);model.addProperty("noreturn_model_auditor_sha256",hash(Files.readAllBytes(proofAuditor)));
        model.addProperty("actual_engine_path",engine.toString());model.addProperty("actual_engine_sha256",ENGINE);
        model.add("additional_ABI_assumptions",proof.get("assumptions"));model.addProperty("noreturn_contract_is_assumption",true);
        model.addProperty("nullguard_has_noreturn_annotation_expected_during_parent",true);model.addProperty("outer_annotation_rollback_requested",false);
        model.addProperty("factory_0x74129c_before_no_return",false);model.addProperty("factory_0x74129c_marked_noreturn",false);
        model.addProperty("read_only_disposable_project_lifecycle_required",true);model.addProperty("runtime_verified",false);model.addProperty("semantic_equivalence_verified",false);model.addProperty("global_guard_dominance_verified",false);
        JsonArray annotations=new JsonArray();model.add("conditional_noreturn_annotations",annotations);
        Files.createDirectories(out);int tx=currentProgram.startTransaction("Conditional throw ABI with unsplit aggregate copies");boolean factoryDuring=false,closed=false;
        Exception restorationError=null;
        try {
            for(long address:wanted){
                Function f=getFunctionAt(addr(address));if(f==null||f.hasNoReturn())throw new Exception("Expected unannotated helper at "+Long.toHexString(address));
                JsonObject a=new JsonObject();a.addProperty("address","0x"+Long.toHexString(address));a.addProperty("before_no_return",false);annotations.add(a);
                f.setNoReturn(true);if(!f.hasNoReturn())throw new Exception("NoReturn annotation not applied");a.addProperty("during_no_return",true);
            }
            factoryDuring=!factory.hasNoReturn();if(!factoryDuring)throw new Exception("Factory unexpectedly changed");
            model.addProperty("factory_0x74129c_during_no_return",false);Files.writeString(out.resolve("model-scope.json"),gson.toJson(model));
            if(args[3].equals("transaction-smoke")){
                int nested=currentProgram.startTransaction("Nested rollback lifecycle smoke");currentProgram.endTransaction(nested,false);
                JsonObject smoke=new JsonObject();smoke.addProperty("status","annotation_transaction_smoke");smoke.addProperty("decompiler_invoked",false);Files.writeString(out.resolve("result.json"),gson.toJson(smoke));
            } else super.run();
        } finally {
            // Explicit restore happens before closing our transaction. GhidraScript may
            // retain an enclosing transaction, so endTransaction(false) alone is not
            // evidence that annotations or hints have already reverted here.
            try {
                for(JsonElement item:annotations){
                    JsonObject a=item.getAsJsonObject();
                    try{Function f=getFunctionAt(addr(num(a.get("address"))));if(f==null)throw new Exception("Helper vanished during restoration");f.setNoReturn(a.get("before_no_return").getAsBoolean());boolean restored=f.hasNoReturn()==a.get("before_no_return").getAsBoolean();a.addProperty("explicitly_restored_before_close",restored);if(!restored)throw new Exception("Explicit helper restoration failed");}
                    catch(Exception error){if(restorationError==null)restorationError=error;else restorationError.addSuppressed(error);a.addProperty("restoration_error",error.toString());}
                }
            } finally {
                model.addProperty("outer_annotation_rollback_requested",true);
                try{currentProgram.endTransaction(tx,false);closed=true;}catch(Exception error){if(restorationError==null)restorationError=error;else restorationError.addSuppressed(error);}
            }
            boolean complete=closed&&annotations.size()==4&&factoryDuring;
            for(JsonElement item:annotations){JsonObject a=item.getAsJsonObject();Function f=getFunctionAt(addr(num(a.get("address"))));boolean ok=f!=null&&f.hasNoReturn()==a.get("before_no_return").getAsBoolean();a.addProperty("original_no_return_restored",ok);complete&=ok&&a.has("explicitly_restored_before_close")&&a.get("explicitly_restored_before_close").getAsBoolean()&&a.has("during_no_return");}
            boolean factoryAfter=factory.hasNoReturn();model.addProperty("factory_0x74129c_after_no_return",factoryAfter);complete&=!factoryAfter;
            model.addProperty("annotation_transaction_close_returned",closed);model.addProperty("explicit_annotation_restoration_verified",complete);
            JsonObject result=Files.exists(out.resolve("result.json"))?JsonParser.parseString(Files.readString(out.resolve("result.json"))).getAsJsonObject():new JsonObject();
            if(!result.has("status")){result.addProperty("status","probe_error");result.addProperty("message","Parent attempt did not write a result");}
            if(result.has("profile"))result.addProperty("parent_recorded_profile",result.get("profile").getAsString());
            if(result.has("ephemeral_transaction_rolled_back")){result.addProperty("parent_ephemeral_transaction_rollback_requested",result.get("ephemeral_transaction_rolled_back").getAsBoolean());result.remove("ephemeral_transaction_rolled_back");}
            for(Map.Entry<String,JsonElement> entry:model.entrySet())result.add(entry.getKey(),entry.getValue());
            if(restorationError!=null||!complete){result.addProperty("status","probe_error");result.addProperty("restoration_error",restorationError==null?"Incomplete annotation lifecycle":restorationError.toString());}
            if(result.get("status").getAsString().equals("decompiled_conditional_candidate")){
                Path c=out.resolve(result.get("file").getAsString());if(!c.toAbsolutePath().normalize().getParent().equals(out.toAbsolutePath().normalize()))throw new Exception("Invalid C output path");
                Files.writeString(c,C_HEADER+Files.readString(c));result.addProperty("c_sha256",hash(Files.readAllBytes(c)));result.addProperty("c_bytes",Files.size(c));
            }
            Files.writeString(out.resolve("result.json"),gson.toJson(result));
            if(restorationError!=null)throw restorationError;
            if(!complete)throw new Exception("Incomplete explicit annotation restoration; inspect result.json");
        }
    }
}
