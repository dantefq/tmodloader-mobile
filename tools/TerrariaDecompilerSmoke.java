import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import java.nio.file.*;
public class TerrariaDecompilerSmoke extends GhidraScript {
    public void run() throws Exception {
        Path out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);
        DecompInterface d=new DecompInterface();
        try {
            DecompileOptions o=new DecompileOptions();o.grabFromProgram(currentProgram);o.setMaxPayloadMBytes(64);
            d.setOptions(o);d.toggleCCode(true);d.toggleSyntaxTree(false);d.openProgram(currentProgram);
            for(String a:new String[]{"1007664","100760c","125efe4","134aaa8"}) {
                long start=System.nanoTime();var r=d.decompileFunction(getFunctionAt(toAddr(a)),30,monitor);
                println("SMOKE "+a+" completed="+r.decompileCompleted()+" ms="+((System.nanoTime()-start)/1000000)+" error="+r.getErrorMessage());
                if(r.decompileCompleted()&&r.getDecompiledFunction()!=null)Files.writeString(out.resolve(a+".c"),r.getDecompiledFunction().getC());
            }
        } finally {d.dispose();}
    }
}
