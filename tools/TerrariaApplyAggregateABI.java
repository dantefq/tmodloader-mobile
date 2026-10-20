// Candidate flat aggregate ABI model; use only a copied private program.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import com.google.gson.*;
import java.nio.file.*;
import java.io.*;
import java.util.*;

public class TerrariaApplyAggregateABI extends GhidraScript {
    private Map<String,DataType> aggregates=new HashMap<>();
    private DataType type(String c) throws Exception {
        if(aggregates.containsKey(c))return aggregates.get(c);
        return switch(c) {
            case "void" -> VoidDataType.dataType;case "bool" -> BooleanDataType.dataType;
            case "i8" -> SignedByteDataType.dataType;case "u8" -> ByteDataType.dataType;
            case "i16" -> ShortDataType.dataType;case "u16" -> UnsignedShortDataType.dataType;
            case "i32" -> IntegerDataType.dataType;case "u32" -> UnsignedIntegerDataType.dataType;
            case "i64" -> LongLongDataType.dataType;case "u64" -> UnsignedLongLongDataType.dataType;
            case "f32" -> FloatDataType.dataType;case "f64" -> DoubleDataType.dataType;
            case "ptr" -> new PointerDataType(VoidDataType.dataType,8,currentProgram.getDataTypeManager());
            default -> throw new Exception("Unknown candidate type "+c);
        };
    }
    public void run() throws Exception {
        String[] a=getScriptArgs();if(a.length<2)throw new Exception("Args: abi-v4-directory output-directory");
        if(currentProgram.getImageBase().getOffset()!=0 || !currentProgram.getLanguageID().toString().equals("AARCH64:LE:64:v8A"))throw new Exception("ARM64 base-zero required");
        Path in=Path.of(a[0]),out=Path.of(a[1]);Files.createDirectories(out);int applied=0,failed=0;
        JsonArray structs=JsonParser.parseString(Files.readString(in.resolve("aggregates.json"))).getAsJsonArray();
        for(JsonElement item:structs) {
            JsonObject r=item.getAsJsonObject();int size=r.get("size").getAsInt();
            StructureDataType s=new StructureDataType(new CategoryPath("/TerrariaRecoveredV4"),r.get("name").getAsString().replaceAll("[^A-Za-z0-9_]","_"),size,currentProgram.getDataTypeManager());
            s.setExplicitMinimumAlignment(r.get("alignment").getAsInt());
            for(JsonElement field:r.getAsJsonArray("fields")) {
                JsonObject f=field.getAsJsonObject();DataType dt=type(f.get("code").getAsString());int at=f.get("offset").getAsInt();
                if(dt.getLength()!=f.get("size").getAsInt() || at<0 || at+dt.getLength()>size)throw new Exception("Invalid aggregate field bounds");
                s.replaceAtOffset(at,dt,dt.getLength(),f.get("name").getAsString(),"IL2CPP boxed field offset minus 16; v4 candidate");
            }
            DataType resolved=currentProgram.getDataTypeManager().resolve(s,DataTypeConflictHandler.REPLACE_HANDLER);
            if(resolved.getLength()!=size)throw new Exception("Aggregate size changed");aggregates.put(r.get("code").getAsString(),resolved);
        }
        try(BufferedWriter log=Files.newBufferedWriter(out.resolve("aggregate-abi-storage.tsv"))) {
            log.write("address\tmethod_index\treturn_type\treturn_storage\tparameters\n");
            for(String line:Files.readAllLines(in.resolve("signatures.tsv"))) {
                monitor.checkCancelled();String[] r=line.split("\t",-1);Function f=getFunctionAt(toAddr(r[0]));if(f==null)throw new Exception("Missing function "+r[0]);
                try {
                    String[] codes=r[2].split(","),names=r[3].split(",");List<Parameter> ps=new ArrayList<>();
                    for(int i=0;i<codes.length;i++)ps.add(new ParameterImpl(names[i],type(codes[i]),currentProgram));
                    f.updateFunction(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName(),new ReturnParameterImpl(type(r[1]),currentProgram),ps,Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED);
                    f.setVarArgs(false);applied++;
                    StringJoiner storage=new StringJoiner(";");for(Parameter p:f.getParameters())storage.add(p.getName()+":"+p.getDataType().getName()+":"+p.getVariableStorage());
                    log.write(r[0]+"\t"+r[4]+"\t"+f.getReturnType().getName()+"\t"+f.getReturn().getVariableStorage()+"\t"+storage+"\n");
                } catch(Exception e) {failed++;throw new Exception("ABI apply failed at "+r[0],e);}
            }
        }
        Files.writeString(out.resolve("aggregate-abi-applied.json"),"{\"finished\":true,\"applied\":"+applied+",\"failed\":"+failed+",\"aggregates\":"+aggregates.size()+",\"machine_abi_verified\":false}");
        println("TERRARIA_AGGREGATE_ABI_APPLIED "+applied+" structs="+aggregates.size());
    }
}
