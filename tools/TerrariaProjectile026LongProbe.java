// One conditional switch-hint experiment; no saved program or canonical journal changes.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.JumpTable;
import com.google.gson.*;
import java.nio.*;
import java.nio.file.*;
import java.util.*;
public class TerrariaProjectile026LongProbe extends GhidraScript {
    static final String ELF="9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5";
    static final String ENGINE="1fd85827247f1ff1417fa412db26a53066d050c59017db98dd23ff196751521e";
    final Gson gson=new GsonBuilder().setPrettyPrinting().create();
    static String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(b));}
    static long num(JsonElement e){return Long.parseUnsignedLong(e.getAsString().replace("0x",""),16);}
    Address addr(long n){return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(n);}
    byte[] source(byte[] elf,long va,int count)throws Exception{
        ByteBuffer b=ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);long ph=b.getLong(32);int size=b.getShort(54)&65535,n=b.getShort(56)&65535;
        for(int i=0;i<n;i++){int p=Math.toIntExact(ph+(long)i*size);if(b.getInt(p)!=1)continue;long off=b.getLong(p+8),start=b.getLong(p+16),length=b.getLong(p+32);if(va>=start&&va+count<=start+length)return Arrays.copyOfRange(elf,Math.toIntExact(off+va-start),Math.toIntExact(off+va-start+count));}
        throw new Exception("Unmapped source VA "+Long.toHexString(va));
    }
    void verify(byte[] elf,long va,int count)throws Exception{byte[] expected=source(elf,va,count),actual=new byte[count];currentProgram.getMemory().getBytes(addr(va),actual);if(!Arrays.equals(expected,actual))throw new Exception("Memory/source mismatch "+Long.toHexString(va));}
    public void run()throws Exception{
        String[] args=getScriptArgs();Path lab=Path.of(args[0]),out=lab.resolve("pseudocode-projectile026-long-probe");Files.createDirectories(out);
        if(Files.exists(out.resolve("result.json")))throw new Exception("One attempt already recorded; refusing repeated trial");
        Path maps=lab.resolve("hard-switches-v2/switches.json"),script=Path.of(args[1]);byte[] elf=Files.readAllBytes(lab.resolve("native/libil2cpp.so"));
        if(!hash(elf).equals(ELF)||!ELF.equalsIgnoreCase(currentProgram.getExecutableSHA256()))throw new Exception("ELF identity mismatch");
        Path engine=ghidra.framework.Application.getOSFile("decompile.exe").toPath().toRealPath();if(!hash(Files.readAllBytes(engine)).equals(ENGINE))throw new Exception("Wrong actual engine");
        JsonObject all=JsonParser.parseString(Files.readString(maps)).getAsJsonObject();if(!ELF.equals(all.get("elf_sha256").getAsString()))throw new Exception("Switch map source mismatch");
        JsonObject method=null;for(JsonElement e:all.getAsJsonArray("methods"))if(num(e.getAsJsonObject().get("address"))==0x14702c0L)method=e.getAsJsonObject();
        if(method==null)throw new Exception("No chosen method");long start=num(method.get("address")),end=num(method.get("end_exclusive"));Function f=getFunctionAt(addr(start));
        if(f==null||!f.getBody().equals(new AddressSet(addr(start),addr(end-1))))throw new Exception("Wrong saved function body");verify(elf,start,Math.toIntExact(end-start));
        JsonObject record=new JsonObject();record.addProperty("profile","conditional-switch-hint-long-v1-typed-v4-stack32");record.addProperty("method",method.get("method").getAsString());record.addProperty("address",method.get("address").getAsString());record.addProperty("end_exclusive",method.get("end_exclusive").getAsString());
        record.addProperty("elf_sha256",ELF);record.addProperty("actual_engine_sha256",ENGINE);record.addProperty("actual_engine_path",engine.toString());record.addProperty("switch_maps_sha256",hash(Files.readAllBytes(maps)));record.addProperty("script_sha256",hash(Files.readAllBytes(script)));record.addProperty("function_source_sha256",hash(source(elf,start,Math.toIntExact(end-start))));record.addProperty("function_source_bytes_verified",end-start);
        record.addProperty("conditional_assumptions","Each recorded guard/load/branch sequence executes without alternate entry, table bytes unchanged, high 32 index bits zero; global dominance and runtime reachability unproved. Hints are experimental candidate model constraints.");record.addProperty("saved_project_modified",false);record.addProperty("canonical_journals_modified",false);record.addProperty("runtime_verified",false);record.addProperty("timeout_seconds",600);record.addProperty("max_instructions",250000);record.addProperty("max_payload_mb",256);
        JsonArray hints=new JsonArray();int tx=currentProgram.startTransaction("Ephemeral conditional switch hints");DecompInterface decompiler=new DecompInterface();
        try{
            int entries=0;for(JsonElement e:method.getAsJsonArray("switch_candidates")){JsonObject map=e.getAsJsonObject();long br=num(map.get("branch"));Instruction instruction=currentProgram.getListing().getInstructionAt(addr(br));if(instruction==null||!instruction.getMnemonicString().equalsIgnoreCase("br"))throw new Exception("Not BR");verify(elf,br,4);verify(elf,num(map.get("table")),map.get("count").getAsInt()*map.get("width").getAsInt());
                ArrayList<Address> targets=new ArrayList<>();JsonObject hint=new JsonObject();hint.addProperty("branch",map.get("branch").getAsString());JsonArray destinations=new JsonArray();
                for(JsonElement item:map.getAsJsonArray("entries")){long target=num(item.getAsJsonObject().get("target"));if(target<start||target>=end)throw new Exception("Nonlocal target");verify(elf,target,4);targets.add(addr(target));destinations.add("0x"+Long.toHexString(target));entries++;}
                new JumpTable(addr(br),targets,true,0).writeOverride(f);hint.add("targets",destinations);hints.add(hint);
            }
            record.add("applied_hints",hints);record.addProperty("applied_hint_count",hints.size());record.addProperty("applied_entry_count",entries);record.addProperty("status","attempting");Files.writeString(out.resolve("scope.json"),gson.toJson(record));
            DecompileOptions options=new DecompileOptions();options.grabFromProgram(currentProgram);options.setMaxInstructions(250000);options.setMaxPayloadMBytes(256);decompiler.setOptions(options);decompiler.toggleCCode(true);decompiler.toggleSyntaxTree(false);decompiler.setSimplificationStyle("decompile");if(!decompiler.openProgram(currentProgram))throw new Exception(decompiler.getLastMessage());
            long begin=System.nanoTime();println("TERRARIA_SWITCH_HINT_START hints="+hints.size()+" entries="+entries);DecompileResults result=decompiler.decompileFunction(f,600,monitor);record.addProperty("elapsed_seconds",(System.nanoTime()-begin)/1e9);record.addProperty("message",result.getErrorMessage());record.addProperty("timed_out",result.isTimedOut());
            if(result.decompileCompleted()&&result.getDecompiledFunction()!=null){Path c=out.resolve("Projectile_AI026_conditional_candidate.c");Files.writeString(c,"/* CONDITIONAL GHIDRA C CANDIDATE; NOT ORIGINAL SOURCE; switch assumptions unproved globally; no runtime verification. */\n"+result.getDecompiledFunction().getC());record.addProperty("status","decompiled_conditional_candidate");record.addProperty("file",c.getFileName().toString());record.addProperty("c_sha256",hash(Files.readAllBytes(c)));}else record.addProperty("status","decompile_failed");
        }catch(Exception error){record.addProperty("status","probe_error");record.addProperty("message",error.toString());throw error;}finally{decompiler.dispose();currentProgram.endTransaction(tx,false);record.addProperty("ephemeral_transaction_rolled_back",true);Files.writeString(out.resolve("result.json"),gson.toJson(record));println("TERRARIA_SWITCH_HINT_END "+record.get("status"));}
    }
}
