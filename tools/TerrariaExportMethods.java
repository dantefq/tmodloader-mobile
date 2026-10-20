// Post-analysis dispatch; all database setup finishes before four read-only workers.
import ghidra.app.script.GhidraScript;
public class TerrariaExportMethods extends GhidraScript {
    public void run() throws Exception {
        runScript("TerrariaParallelExportMethods.java", getScriptArgs());
    }
}
