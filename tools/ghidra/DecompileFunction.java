// Decompile one function at an operator-supplied address in headless Ghidra.
// @category Ward

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class DecompileFunction extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length < 1 || arguments.length > 2) {
            throw new IllegalArgumentException("usage: DecompileFunction.java <address> [summary]");
        }
        boolean summaryOnly = arguments.length == 2 && "summary".equals(arguments[1]);
        if (arguments.length == 2 && !summaryOnly) {
            throw new IllegalArgumentException("unknown output mode: " + arguments[1]);
        }

        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(currentProgram);
            for (String addressText : arguments[0].split(",")) {
                Address address = currentProgram.getAddressFactory().getAddress(addressText);
                if (address == null) {
                    throw new IllegalArgumentException("invalid address: " + addressText);
                }

                Function function = getFunctionContaining(address);
                if (function == null) {
                    disassemble(address);
                    function = createFunction(address, null);
                }
                if (function == null) {
                    throw new IllegalStateException("no function at or containing " + address);
                }

                DecompileResults result = decompiler.decompileFunction(function, 120, monitor);
                if (!result.decompileCompleted()) {
                    throw new IllegalStateException("decompilation failed: " + result.getErrorMessage());
                }
                println("WARD_DECOMPILE_BEGIN " + function.getName() + " " + function.getEntryPoint());
                String source = result.getDecompiledFunction().getC();
                if (summaryOnly) {
                    for (String line : source.split("\\R")) {
                        if (line.matches(".*(_exref|VirtualAlloc|VirtualProtect|FUN_[0-9A-Fa-f]+\\(|\\(\\*.*\\)\\(|DAT_[0-9A-Fa-f]+).*$")) {
                            println(line);
                        }
                    }
                }
                else {
                    println(source);
                }
                println("WARD_DECOMPILE_END");
            }
        }
        finally {
            decompiler.dispose();
        }
    }
}
