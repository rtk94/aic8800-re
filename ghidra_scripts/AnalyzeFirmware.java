// Ghidra analysis script for AIC8800 firmware - Java version
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.Data;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.app.script.GhidraScript;

public class AnalyzeFirmware extends GhidraScript {

    @Override
    public void run() throws Exception {
        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
        
        // Get function manager
        FunctionManager fm = currentProgram.getFunctionManager();
        int funcCount = fm.getFunctionCount();
        println("=== Functions found: " + funcCount + " ===");
        
        // Collect non-thunk functions
        java.util.List<Function> funcList = new java.util.ArrayList<>();
        for (Function f : fm.getFunctions(true)) {
            if (!f.isThunk()) {
                funcList.add(f);
            }
        }
        
        // Sort by address
        funcList.sort((a, b) -> Long.compare(a.getEntryPoint().getOffset(), b.getEntryPoint().getOffset()));
        
        for (Function f : funcList) {
            println("  " + f.getName() + " @ 0x" + Long.toHexString(f.getEntryPoint().getOffset()));
        }
        
        // Decompile first 20 functions
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        
        int count = 0;
        for (Function f : funcList) {
            if (count >= 20) break;
            var results = decomp.decompileFunction(f, 60, monitor);
            if (results != null && results.decompileCompleted()) {
                println("\n--- " + f.getName() + " @ 0x" + Long.toHexString(f.getEntryPoint().getOffset()) + " ---");
                println(results.getDecompiledFunction().getC());
            }
            count++;
        }
        
        decomp.dispose();
        
        // String references
        println("\n=== String references ===");
        Listing listing = currentProgram.getListing();
        java.util.Iterator<?> it = listing.getDefinedData(true);
        while (it.hasNext()) {
            Object obj = it.next();
            if (obj instanceof Data) {
                Data dd = (Data) obj;
                if (dd.getDataType() instanceof StringDataType) {
                    Object val = dd.getValue();
                    if (val != null) {
                        String sval = val.toString();
                        if (!sval.isEmpty()) {
                            println("  0x" + Long.toHexString(dd.getAddress().getOffset()) + ": " + sval);
                        }
                    }
                }
            }
        }
        
        println("\nDone");
    }
}