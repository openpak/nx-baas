// @category OpenPakAudit
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.nio.file.*;
import java.util.*;

public class DecompAround extends GhidraScript {
  public void run() throws Exception {
    String[] args = getScriptArgs();
    Path out = Paths.get(args[0]);
    Files.createDirectories(out);
    DecompInterface dec = new DecompInterface();
    dec.openProgram(currentProgram);
    StringBuilder idx = new StringBuilder();
    for (int i = 1; i < args.length; i++) {
      Address a = toAddr(args[i]);
      Function f = getFunctionContaining(a);
      if (f == null) { idx.append("NOFUNC " + a + "\n"); continue; }
      idx.append("ADDR " + a + " in " + f.getName() + " @" + f.getEntryPoint() + "\n");
      for (Reference r : getReferencesTo(f.getEntryPoint()))
        idx.append("  CALLER " + r.getFromAddress() + " " + r.getReferenceType() + "\n");
      DecompileResults res = dec.decompileFunction(f, 60, monitor);
      if (res.decompileCompleted())
        Files.writeString(out.resolve(f.getEntryPoint() + ".c"), res.getDecompiledFunction().getC());
    }
    Files.writeString(out.resolve("index.txt"), idx.toString());
    dec.dispose();
  }
}
