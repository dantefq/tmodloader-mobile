// Conservative signatures only; aggregate/unknown ABIs were excluded by catalogue generator.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.io.*;
import java.util.*;

public class TerrariaApplySignatures extends GhidraScript {
    private DataType type(String code) throws Exception {
        return switch(code) {
            case "void" -> VoidDataType.dataType;
            case "bool" -> BooleanDataType.dataType;
            case "i8" -> SignedByteDataType.dataType;
            case "u8" -> ByteDataType.dataType;
            case "i16" -> ShortDataType.dataType;
            case "u16" -> UnsignedShortDataType.dataType;
            case "i32" -> IntegerDataType.dataType;
            case "u32" -> UnsignedIntegerDataType.dataType;
            case "i64" -> LongLongDataType.dataType;
            case "u64" -> UnsignedLongLongDataType.dataType;
            case "f32" -> FloatDataType.dataType;
            case "f64" -> DoubleDataType.dataType;
            case "ptr" -> new PointerDataType(VoidDataType.dataType,8,currentProgram.getDataTypeManager());
            default -> throw new Exception("Unsupported ABI code "+code);
        };
    }
    public void run() throws Exception {
        String[] args=getScriptArgs();if(args.length<2)throw new Exception("Arguments: signatures.tsv output-directory");
        if(currentProgram.getImageBase().getOffset()!=0 || !currentProgram.getLanguageID().toString().equals("AARCH64:LE:64:v8A"))throw new Exception("Requires ARM64 LE v8A ELF base0");
        Path out=Path.of(args[1]);Files.createDirectories(out);int applied=0,missing=0,failed=0;
        Files.writeString(out.resolve("signatures-applied-summary.json"),"{\"finished\":false}");
        try(BufferedWriter ledger=Files.newBufferedWriter(out.resolve("signatures-applied.tsv"),StandardCharsets.UTF_8)) {
            ledger.write("address\tstatus\tmessage\n");
            for(String line:Files.readAllLines(Path.of(args[0]),StandardCharsets.UTF_8)) {
                monitor.checkCancelled();if(line.isBlank())continue;String[] row=line.split("\t",-1);
                Function function=getFunctionAt(toAddr(row[0]));
                if(function==null) {missing++;ledger.write(row[0]+"\tmissing_function\t\n");continue;}
                try {
                    String[] codes=row[2].split(","),names=row[3].split(",");
                    if(codes.length!=names.length)throw new Exception("Parameter columns mismatch");
                    List<Parameter> parameters=new ArrayList<>();
                    for(int i=0;i<codes.length;i++)parameters.add(new ParameterImpl(names[i],type(codes[i]),currentProgram));
                    String convention=currentProgram.getCompilerSpec().getDefaultCallingConvention().getName();
                    function.updateFunction(convention,new ReturnParameterImpl(type(row[1]),currentProgram),parameters,
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED);
                    function.setVarArgs(false);applied++;ledger.write(row[0]+"\tapplied\t\n");
                } catch(Exception e) {failed++;ledger.write(row[0]+"\tfailed\t"+e.toString().replace('\t',' ').replace('\n',' ')+"\n");}
            }
        }
        Files.writeString(out.resolve("signatures-applied-summary.json"),"{\"finished\":true,\"applied\":"+applied+",\"missing\":"+missing+",\"failed\":"+failed+",\"aggregate_abi_inferred\":false}");
        println("TERRARIA_SIGNATURES_COMPLETE applied="+applied+" missing="+missing+" failed="+failed);
    }
}
