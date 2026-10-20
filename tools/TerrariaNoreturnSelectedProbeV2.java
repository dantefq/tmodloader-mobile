// Separate conditional ABI model; all function annotations and hints roll back.
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;
public class TerrariaNoreturnSelectedProbeV2 extends TerrariaHardSelectedProbe {
    public void run() throws Exception {
        String[] args=getScriptArgs();Path lab=Path.of(args[0]),script=Path.of(args[1]),out=lab.resolve(args[2]);
        if(!args[2].startsWith("pseudocode-noreturn-"))throw new Exception("Separate model output required");
        Path proofPath=lab.resolve("nullguard-noreturn-model-20261015/evidence.json");JsonObject proof=JsonParser.parseString(Files.readString(proofPath)).getAsJsonObject();
        if(!proof.get("integrity_passed").getAsBoolean()||!proof.get("elf_sha256").getAsString().equals(ELF))throw new Exception("Unverified conditional model");
        if(!hash(Files.readAllBytes(script.resolveSibling("audit_terraria_nullguard_noreturn_model.py"))).equals(proof.get("auditor_sha256").getAsString()))throw new Exception("Model auditor changed");
        Set<Long> wanted=new TreeSet<>(List.of(0x6ff6acL,0x741278L,0x74128cL,0x7411e0L)),actual=new TreeSet<>();
        for(JsonElement value:proof.getAsJsonArray("conditional_noreturn_entry_points"))actual.add(num(value));
        if(!actual.equals(wanted))throw new Exception("Wrong conditional annotation scope");
        byte[] elf=Files.readAllBytes(lab.resolve("native/libil2cpp.so"));if(!hash(elf).equals(ELF))throw new Exception("ELF changed");
        for(JsonElement item:proof.getAsJsonArray("source_functions")){JsonObject f=item.getAsJsonObject();long lo=num(f.get("entry")),hi=num(f.get("end_exclusive"));verify(elf,lo,Math.toIntExact(hi-lo));if(!HexFormat.of().formatHex(source(elf,lo,Math.toIntExact(hi-lo))).equals(f.get("raw_bytes").getAsString()))throw new Exception("Conditional proof bytes differ");}
        JsonArray annotations=new JsonArray();int tx=currentProgram.startTransaction("Conditional standard C++ throw ABI model");
        try {
            for(long address:wanted){Function f=getFunctionAt(addr(address));if(f==null)throw new Exception("Missing helper function");JsonObject item=new JsonObject();item.addProperty("address","0x"+Long.toHexString(address));item.addProperty("before_no_return",f.hasNoReturn());f.setNoReturn(true);if(!f.hasNoReturn())throw new Exception("Annotation not applied");item.addProperty("during_no_return",true);annotations.add(item);}
            if(args[3].equals("transaction-smoke")){Files.createDirectories(out);int nested=currentProgram.startTransaction("Nested rollback smoke");currentProgram.endTransaction(nested,false);JsonObject smoke=new JsonObject();smoke.addProperty("status","annotation_transaction_smoke");smoke.addProperty("elf_sha256",ELF);smoke.addProperty("script_sha256",hash(Files.readAllBytes(script)));Files.writeString(out.resolve("result.json"),gson.toJson(smoke));}else super.run();
        } finally {
            try{for(JsonElement item:annotations){JsonObject a=item.getAsJsonObject();Function f=getFunctionAt(addr(num(a.get("address"))));f.setNoReturn(a.get("before_no_return").getAsBoolean());if(f.hasNoReturn()!=a.get("before_no_return").getAsBoolean())throw new Exception("Explicit annotation restoration failed");a.addProperty("explicitly_restored_before_close",true);}}
            finally{currentProgram.endTransaction(tx,false);}
            if(Files.exists(out.resolve("result.json"))){JsonObject r=JsonParser.parseString(Files.readString(out.resolve("result.json"))).getAsJsonObject();
                r.addProperty("profile","conditional-standard-cxx-throw-noreturn-typed-v4-stack32-v2");r.addProperty("noreturn_model_evidence_sha256",hash(Files.readAllBytes(proofPath)));r.addProperty("parent_helper_sha256",hash(Files.readAllBytes(script.resolveSibling("TerrariaHardSelectedProbe.java"))));r.add("conditional_noreturn_annotations",annotations);r.add("additional_ABI_assumptions",proof.get("assumptions"));r.addProperty("outer_annotation_rollback_requested",true);r.addProperty("noreturn_contract_is_assumption",true);r.addProperty("factory_0x74129c_marked_noreturn",false);
                for(JsonElement item:annotations){JsonObject a=item.getAsJsonObject();boolean restored=getFunctionAt(addr(num(a.get("address")))).hasNoReturn()==a.get("before_no_return").getAsBoolean();a.addProperty("original_no_return_restored",restored);if(!restored)throw new Exception("Conditional annotation not restored");}
                if(r.get("status").getAsString().equals("decompiled_conditional_candidate")){Path c=out.resolve(r.get("file").getAsString());String header="/* ADDITIONAL CONDITIONAL MODEL: standard __cxa_throw has no normal return; no exceptional/nonlocal wrapper reentry; four helper annotations only. Not runtime or semantic-equivalence proof. */\n";Files.writeString(c,header+Files.readString(c));r.addProperty("c_sha256",hash(Files.readAllBytes(c)));}
                Files.writeString(out.resolve("result.json"),gson.toJson(r));
            }
        }
    }
}
