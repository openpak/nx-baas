// @category OpenPakAudit
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
public class RefsTo extends GhidraScript {
  public void run() throws Exception {
    for (String s : getScriptArgs()) {
      Address a = toAddr(s);
      println("== refs to " + a);
      for (Reference r : getReferencesTo(a)) {
        Function f = getFunctionContaining(r.getFromAddress());
        println("   " + r.getFromAddress() + " " + r.getReferenceType() +
                (f != null ? "  in " + f.getEntryPoint() : ""));
      }
    }
  }
}
