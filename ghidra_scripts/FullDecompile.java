// Ghidra full decompile script - exports decompilations to file
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Function;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.app.script.GhidraScript;
import java.io.*;

public class FullDecompile extends GhidraScript {

    @Override
    public void run() throws Exception {
        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
        String outPath = System.getenv("GHIDRA_DECOMPILE_OUT");
        if (outPath == null) outPath = "/tmp/decompile_out.txt";
        
        FunctionManager fm = currentProgram.getFunctionManager();
        java.util.List<Function> funcList = new java.util.ArrayList<>();
        for (Function f : fm.getFunctions(true)) {
            if (!f.isThunk() && f.getName().startsWith("FUN_") == false) {
                funcList.add(f);
            }
        }
        
        // Also include FUN_ functions for breadth
        for (Function f : fm.getFunctions(true)) {
            if (!f.isThunk() && f.getName().startsWith("FUN_")) {
                funcList.add(f);
            }
        }
        
        // Sort by address
        funcList.sort((a, b) -> Long.compare(a.getEntryPoint().getOffset(), b.getEntryPoint().getOffset()));
        
        PrintWriter out = new PrintWriter(new FileWriter(outPath));
        out.println("=== " + currentProgram.getName() + " ===");
        out.println("Total functions: " + funcList.size());
        out.println();
        
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        
        int decompiled = 0;
        for (Function f : funcList) {
            try {
                var results = decomp.decompileFunction(f, 120, monitor);
                if (results != null && results.decompileCompleted()) {
                    out.println("--- " + f.getName() + " @ 0x" + Long.toHexString(f.getEntryPoint().getOffset()) + " ---");
                    out.println(results.getDecompiledFunction().getC());
                    out.println();
                    decompiled++;
                }
            } catch (Exception e) {
                // skip failures
            }
        }
        
        decomp.dispose();
        out.close();
        println("Decompiled " + decompiled + " functions to " + outPath);
        println("\nDone");
    }
}