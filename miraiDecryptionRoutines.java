//Ghidra Script to detect mirai decryption routines and decrypt the strings found.
//Currently the encryption types Shift XOR, RC4 and Bruetforce XOR are supported.
//@category Analysis/Mirai

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GenericAddress;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import static ghidra.program.model.pcode.PcodeOp.*;
import java.util.*;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;

public class miraiDecryptionRoutines extends GhidraScript {


    private final int DEFAULT_MAX_STRING_LENGTH = 2048;
    private boolean LOG_DEBUG_MESSAGES = true;
    private List<ScriptLogger> SCRITP_LOGGERS = new ArrayList<>(
            Arrays.asList(new StringLogger(), new JsonLogger(), new GhidraUpdate()));
    private ScriptLogger logger;

    enum EncryptionType {
        BRUTEFORCE_XOR,
        SHIFTXOR,
        RC4,
        //CHACHA20 TODO
    }

    static class StringPtr {
        StringPtr(long address, int length) {
            this.address = address;
            this.length = length;
        }

        long address;
        int length;

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof StringPtr other)) {
                return false;
            }
            return this.address == other.address && this.length == other.length;
        }

        public int hashCode() {
            return (int) this.address + this.length;
        }
    }

    static class EncryptedCredentialEntry {
        EncryptedCredentialEntry(Address username, Address password) {
            this.username = username;
            this.password = password;
        }

        Address username;
        Address password;
    }

    @Override
    public void run() throws Exception {
        if (!parseArguments()) {
            return;
        }
        logger.logSampleInformation(currentProgram.getDomainFile().getName(),
                currentProgram.getExecutableSHA256(),
                String.valueOf(currentProgram.getLanguage().getProcessor()));

        DecompInterface decompiler = new DecompInterface();
        Map<EncryptionType, List<Address>> encryptionRoutineMap = findMiraiStringEncryptionRoutine(decompiler);
        if (!encryptionRoutineMap.isEmpty()) {
            analyzeEncryptionRoutineMap(encryptionRoutineMap, decompiler);
        } else {
            logger.logError("No encryption Routine was detected!");
        }
        // Added at the end since both String and Credential decryption routines can be
        // present in parallel.
        Address bruteForceRoutineAddress = findMiraiCredentialEncryptionRoutine(decompiler);
        if (bruteForceRoutineAddress != null) {
            analyzeBruteforceRoutine(bruteForceRoutineAddress, decompiler);
        } else {
            logger.logError("No Brute Force Routine was detected!");
        }
        logger.logDebug("Analysis Finished");
    }

    private boolean parseArguments() { // Returns if program shoud continue
        logger = new MulitLogger(SCRITP_LOGGERS.stream()
                .filter(logger -> (logger.getName().equals("STRING") || logger.getName().equals("GHIDRA_UPDATE")))
                .collect(Collectors.toList()));
        String[] arguments = getScriptArgs();
        for (int pos = 0; pos < arguments.length; pos++) {
            switch (arguments[pos]) {
                case "help" -> {
                    List<String> logModes = new ArrayList<>();
                    for (ScriptLogger scriptLogger : SCRITP_LOGGERS) {
                        logModes.add(scriptLogger.getName());
                    }

                    println("The following command lines switches are available:");
                    println(" help # Adds additional debug output");
                    println(" verbose # Adds additional debug output");
                    println(" logMode [MODE] # Changes the log output to follow another syntax, avaiable MODE's are '"
                            + String.join("','", logModes) + "'");
                    return false;
                }
                case "verbose" -> {
                    LOG_DEBUG_MESSAGES = true;
                    logger.logDebug("Enabled verbose mode");
                }
                case "logMode" -> {
                    int modePos = ++pos;
                    if (modePos < arguments.length) {
                        String txtMode = arguments[modePos];
                        boolean foundLogger = false;
                        for (ScriptLogger scriptLogger : SCRITP_LOGGERS) {
                            if (scriptLogger.getName().toUpperCase().equals(txtMode.toUpperCase())) {
                                logger = scriptLogger;
                                foundLogger = true;
                            }
                        }
                        if (!foundLogger) {
                            logger.logError("Logger " + txtMode + " not found!");
                        } else {
                            logger.logDebug("Logger changed to " + logger.getName());
                        }
                    } else {
                        logger.logError("LogMode not supplied");
                    }
                }
                default -> {
                    logger.logError("Could not interpret argument " + arguments[pos] + "");
                }
            }
        }
        return true;
    }

    private Map<EncryptionType, List<Address>> findMiraiStringEncryptionRoutine(DecompInterface decompiler) {
        Listing listing = currentProgram.getListing();
        Map<EncryptionType, List<Address>> encryptionFunction = new HashMap<>();
        for (Function function : listing.getFunctions(true)) {
            decompiler.openProgram(function.getProgram());
            DecompileResults decompiledFunction = decompiler.decompileFunction(function, 60, null);
            if (hasShiftXorPattern(decompiledFunction)) {
                logger.logEncryptionFunction(function, EncryptionType.SHIFTXOR);
                List<Address> encryptionRoutineAddressList = encryptionFunction.getOrDefault(EncryptionType.SHIFTXOR,
                        new ArrayList<Address>());
                encryptionRoutineAddressList.add(function.getEntryPoint());
                encryptionFunction.put(EncryptionType.SHIFTXOR, encryptionRoutineAddressList);
            } else if (hasRc4Pattern(decompiledFunction)) {
                logger.logEncryptionFunction(function, EncryptionType.RC4);
                List<Address> encryptionRoutineAddressList = encryptionFunction.getOrDefault(EncryptionType.RC4,
                        new ArrayList<Address>());
                encryptionRoutineAddressList.add(function.getEntryPoint());
                encryptionFunction.put(EncryptionType.RC4, encryptionRoutineAddressList);
            }
        }
        return encryptionFunction;
    }

    private Address findMiraiCredentialEncryptionRoutine(DecompInterface decompiler) {
        Listing listing = currentProgram.getListing();
        for (Function function : listing.getFunctions(true)) {
            decompiler.openProgram(function.getProgram());
            DecompileResults decompiledFunction = decompiler.decompileFunction(function, 60, null);
            if (hasBruteForceXORPattern(decompiledFunction)) {
                logger.logEncryptionFunction(function, EncryptionType.BRUTEFORCE_XOR);
                return function.getEntryPoint();
            }
        }
        return null;
    }

    private boolean hasShiftXorPattern(DecompileResults decompiledFunction) {
        HighFunction highFunction = decompiledFunction.getHighFunction();
        if (highFunction == null) {
            return false;
        }
        List<Varnode> shrOpList = new ArrayList<>();
        boolean hasSHR1 = false, hasSHR2 = false, hasSHR3 = false;
        Iterator<PcodeOpAST> pcodeOpASTIterator = highFunction.getPcodeOps();
        while (pcodeOpASTIterator.hasNext()) {
            PcodeOpAST pcodeOp = pcodeOpASTIterator.next();
            if (pcodeOp.getOpcode() == INT_RIGHT) {
                Varnode shiftXorValue0 = pcodeOp.getInput(0);
                Varnode shiftXorValue1 = pcodeOp.getInput(1);
                if (shiftXorValue0.isUnique() && shiftXorValue1.isConstant()
                        && shiftXorValue1.getOffset() == 0x8) {
                    shrOpList.add(shiftXorValue1);
                    hasSHR1 = true;
                }
                if (shiftXorValue0.isUnique() && shiftXorValue1.isConstant()
                        && shiftXorValue1.getOffset() == 0x10) {
                    shrOpList.add(shiftXorValue1);
                    hasSHR2 = true;
                }
                if (shiftXorValue0.isUnique() && shiftXorValue1.isConstant()
                        && shiftXorValue1.getOffset() == 0x18) {
                    shrOpList.add(shiftXorValue1);
                    hasSHR3 = true;
                }
            }
        }
        return hasSHR1 && hasSHR2 && hasSHR3 && shrOpList.size() == 3;
    }

    private boolean hasRc4Pattern(DecompileResults decompiledFunction) {
        HighFunction highFunction = decompiledFunction.getHighFunction();
        if (highFunction == null) {
            return false;
        }
        List<Varnode> loopCondList = new ArrayList<>();
        Varnode varConstHex100 = null;
        Iterator<PcodeOpAST> pcodeOpASTIterator = highFunction.getPcodeOps();
        while (pcodeOpASTIterator.hasNext()) {
            PcodeOpAST pcodeOp = pcodeOpASTIterator.next();
            if (pcodeOp.getOpcode() == INT_NOTEQUAL) {
                Varnode counterSourceNode = pcodeOp.getInput(0);
                Varnode conditionSourceNode = pcodeOp.getInput(1);
                if (counterSourceNode.isRegister() && conditionSourceNode.isConstant()) {
                    if (conditionSourceNode.getOffset() == 0x100) {
                        loopCondList.add(counterSourceNode);
                    } else if (varConstHex100 != null &&
                            counterSourceNode.getSpace() == varConstHex100.getSpace() &&
                            counterSourceNode.getOffset() == varConstHex100.getOffset()) {
                        loopCondList.add(counterSourceNode);
                        varConstHex100 = null;
                    }
                }
                // If the constant is assigned to a variable (PowerPC Sample)
            } else if (pcodeOp.getOpcode() == COPY) {
                Varnode constSourceNode = pcodeOp.getInput(0);
                if (constSourceNode.isConstant() && constSourceNode.getOffset() == 0x100) {
                    varConstHex100 = pcodeOp.getOutput();
                }
            }
        }
        return loopCondList.size() == 2;
    }

    private boolean hasBruteForceXORPattern(DecompileResults decompiledFunction) {
        HighFunction highFunction = decompiledFunction.getHighFunction();
        if (highFunction == null) {
            return false;
        }
        List<String> xorKeyList = new ArrayList<>();
        List<String> addEntryCall = new ArrayList<>();
        Iterator<PcodeOpAST> pcodeOpASTIterator = highFunction.getPcodeOps();
        while (pcodeOpASTIterator.hasNext()) {
            PcodeOpAST pcodeOp = pcodeOpASTIterator.next();
            Varnode buffValue = pcodeOp.getInput(0);
            Varnode xorKey = pcodeOp.getInput(1);
            if (pcodeOp.getOpcode() == INT_XOR && xorKey.isConstant()) {
                xorKeyList.add(xorKey.toString());
            } else if ((pcodeOp.getOpcode() == CALL || pcodeOp.getOpcode() == CALLIND)
                    && pcodeOp.getOutput() == null) {
                addEntryCall.add(buffValue.toString());
            }
        }
        return xorKeyList.size() == 2 && addEntryCall.size() == 2 &&
                xorKeyList.get(0).equals(xorKeyList.get(1)); // Compare using the toString of Varnode
    }

    private void analyzeEncryptionRoutineMap(Map<EncryptionType, List<Address>> encryptionRoutineMap,
            DecompInterface decompiler) {
        for (Map.Entry<EncryptionType, List<Address>> encryptionRoutine : encryptionRoutineMap.entrySet()) {
            EncryptionType encryptionRoutineType = encryptionRoutine.getKey();
            List<Address> encryptionRoutineAddressList = encryptionRoutine.getValue();
            logger.logDebug("Encryption Type: " + encryptionRoutineType);
            switch (encryptionRoutineType) {
                case SHIFTXOR -> {
                    Map<String, byte[]> encryptionKeys = new HashMap<>();
                    for (Address encRoutineAddress : encryptionRoutineAddressList) {
                        Function shiftxorFunction = getFunctionAt(encRoutineAddress);
                        DecompileResults decompiledShiftxorFunction = decompiler.decompileFunction(shiftxorFunction, 60,
                                null);
                        byte[] stringEncryptionKey = fetchShiftXorEncKey(decompiledShiftxorFunction);
                        if (stringEncryptionKey == null || stringEncryptionKey.length == 0) {
                            logger.logError("Key not found for Address: 0x" + encRoutineAddress);
                            continue;
                        }
                        logger.logDebug("Enc Key: " + byteArrayToHexString(stringEncryptionKey));
                        encryptionKeys.put(byteArrayToHexString(stringEncryptionKey), stringEncryptionKey); // To allow
                                                                                                            // de-duplication
                        Address bufferAddress = fetchShiftXorBufferAddress(decompiledShiftxorFunction);
                        if (bufferAddress != null) {
                            logger.logDebug("Buffer Address: " + bufferAddress);
                        }
                    }
                    for (byte[] encryptionKey : encryptionKeys.values()) {
                        Listing listing = currentProgram.getListing();
                        logger.logDebug("Enc Key: " + byteArrayToHexString(encryptionKey));
                        for (Function function : listing.getFunctions(true)) {
                            decompiler.openProgram(function.getProgram()); // TODO when is this needed and when not
                            DecompileResults decompiledFunction = decompiler.decompileFunction(function, 60, null);
                            Set<StringPtr> addresses = getShiftXorDataSectionAddresses(decompiledFunction);

                            for (StringPtr address : addresses) {
                                byte[] bytes;
                                if (address.length == 0) {
                                    bytes = fetchDataFromAddress(toAddr(address.address));
                                } else {
                                    bytes = fetchDataFromAddress(toAddr(address.address), address.length);
                                }
                                if (bytes.length != 0) {
                                    logger.logDecryption(toAddr(address.address), xorDecryptor(bytes, encryptionKey),
                                            encryptionKey, encryptionRoutineType);
                                }
                            }
                        }
                    }
                }
                case RC4 -> {
                    List<Address> encryptedStringAddresses = new ArrayList<>();
                    for (Address encRoutineAddress : encryptionRoutineAddressList) {
                        Function rc4Function = getFunctionAt(encRoutineAddress);
                        DecompileResults decompiledRC4Function = decompiler.decompileFunction(rc4Function, 60, null);
                        byte[] encryptionKey = fetchRc4EncKey(decompiledRC4Function);
                        if (encryptionKey == null || encryptionKey.length == 0) {
                            logger.logError("Key not found for Address: " + encRoutineAddress);
                            continue;
                        }
                        logger.logDebug("Enc Key: " + byteArrayToHexString(encryptionKey));
                        List<Address> returnedList = fetchRc4EncStrings(encRoutineAddress, decompiler);
                        encryptedStringAddresses.addAll(returnedList);
                        for (Address encryptedStringAddresse : encryptedStringAddresses) {
                            if (encryptedStringAddresse != null) {
                                byte[] encryptedHexString = fetchDataFromAddress(encryptedStringAddresse);
                                logger.logDecryption(encryptedStringAddresse,
                                        rc4Algorithm(encryptionKey, encryptedHexString), encryptionKey,
                                        encryptionRoutineType);
                            }
                        }
                    }
                }
                default -> {
                    logger.logError("Found currently unsupported type: " + encryptionRoutineType);
                }
            }
        }
    }

    private void analyzeBruteforceRoutine(Address bruteForceRoutineAddress, DecompInterface decompiler) {
        logger.logDebug("Brute Force Routine: " + bruteForceRoutineAddress);
        Function bruteforceFunction = getFunctionAt(bruteForceRoutineAddress);
        DecompileResults decompiledBruteforceFunction = decompiler.decompileFunction(bruteforceFunction, 60, null);
        byte[] bruteforceEncryptionKey = fetchBruteforceEncKey(decompiledBruteforceFunction);
        if (bruteforceEncryptionKey != null && bruteforceEncryptionKey.length > 0) {
            logger.logDebug("Brute Force Enc Key: " + byteArrayToHexString(bruteforceEncryptionKey));
            List<EncryptedCredentialEntry> encryptedHexCredentialsList = fetchBruteforceEncCredentials(
                    bruteForceRoutineAddress, decompiler);
            for (EncryptedCredentialEntry encCredential : encryptedHexCredentialsList) {
                byte[] username = xorDecryptor(fetchDataFromAddress(encCredential.username), bruteforceEncryptionKey);
                byte[] password = xorDecryptor(fetchDataFromAddress(encCredential.password), bruteforceEncryptionKey);
                logger.logCredential(encCredential.username, encCredential.password, username, password,
                        bruteforceEncryptionKey);
            }
        } else {
            logger.logError("Error: Unable to read Bruteforce Encryption Key!");
        }
    }

    private Set<StringPtr> getShiftXorDataSectionAddresses(DecompileResults decompiledFunction) {
        Set<StringPtr> addresses = new HashSet<>();
        Map<Long, Long> reg = new HashMap<>();
        HighFunction highFunction = decompiledFunction.getHighFunction();
        if (highFunction == null) {
            return addresses;
        }
        Iterator<PcodeOpAST> pcodeOpASTIterator = highFunction.getPcodeOps();
        while (pcodeOpASTIterator.hasNext()) {
            PcodeOpAST pcodeOp = pcodeOpASTIterator.next();
            if (pcodeOp.getOpcode() == BRANCH || pcodeOp.getOpcode() == CBRANCH || pcodeOp.getOpcode() == BRANCHIND) {
                // Return empty array because string init functions do not branch
                addresses.clear();
                return addresses;
            } else if (pcodeOp.getOpcode() == PTRADD && pcodeOp.getNumInputs() == 3) { // Save register value for later
                Varnode destNode = pcodeOp.getOutput();
                Varnode sourceNode0 = pcodeOp.getInput(0);
                Varnode sourceNode1 = pcodeOp.getInput(1);
                Varnode sourceNode2 = pcodeOp.getInput(2);

                if (destNode.isRegister() && sourceNode0.isAddress() && sourceNode1.isConstant()
                        && sourceNode2.isConstant()) {
                    Address addressPtr = resolveIndirectAddress(sourceNode0.getAddress());
                    if (addressPtr != null) {
                        Long value = addressPtr.add((int) sourceNode1.getOffset()).getOffset();
                         // Cast to work with negative signed int
                        reg.put(destNode.getOffset(), value);
                    }
                }
            } else if (pcodeOp.getOpcode() == CALLIND && pcodeOp.getNumInputs() == 4) { // Works for MIPS, but requires
                                                                                        // reading register value
                Varnode callDestNode = pcodeOp.getInput(0);
                Varnode bufferNode = pcodeOp.getInput(1);
                Varnode encDataNode = pcodeOp.getInput(2);
                Varnode sizeNode = pcodeOp.getInput(3);

                if (callDestNode.isUnique() && bufferNode.isRegister() && encDataNode.isRegister()
                        && sizeNode.isConstant()) {
                    if (reg.containsKey(encDataNode.getOffset())) {
                        addresses.add(new StringPtr(reg.get(encDataNode.getOffset()), (int) sizeNode.getOffset()));
                    }
                }
            } else if (pcodeOp.getOpcode() == INDIRECT && pcodeOp.getNumInputs() == 2) { // Works for AMD
                Varnode sourceNode0 = pcodeOp.getInput(0);
                Varnode sourceNode1 = pcodeOp.getInput(1);

                if (sourceNode0.isAddress() && sourceNode1.isConstant()) {
                    Address addressPtr = resolveIndirectAddress(sourceNode0.getAddress());
                    if (addressPtr == null) {
                        continue;
                    }
                    Data data = currentProgram.getListing().getDataAt(addressPtr);
                    if (data == null) {
                        continue;
                    }
                    Object value = data.getValue();
                    if (value != null) {
                        // Maybe string address
                        addresses.add(new StringPtr(addressPtr.getOffset(), 0)); // TODO fix by finding actual length
                    }
                }
            } else if (pcodeOp.getOpcode() == CALL && pcodeOp.getNumInputs() == 4) { // Works with Intel
                Varnode callDestNode = pcodeOp.getInput(0);
                Varnode bufferNode = pcodeOp.getInput(1);
                Varnode encDataNode = pcodeOp.getInput(2);
                Varnode sizeNode = pcodeOp.getInput(3);

                if (callDestNode.isAddress() && bufferNode.isRegister() && sizeNode.isConstant()) {
                    if (encDataNode.isUnique()) {
                        PcodeOp instructionDef = encDataNode.getDef();
                        if (instructionDef.getOpcode() == PTRSUB) {
                            Varnode constBase = instructionDef.getInput(0);
                            Varnode constOffset = instructionDef.getInput(1);
                            if (constBase.isConstant() && constOffset.isConstant()) {
                                addresses.add(new StringPtr(constBase.getOffset() + constOffset.getOffset(),
                                        (int) sizeNode.getOffset()));
                            }
                        } else if (instructionDef.getOpcode() == COPY) {
                            Varnode constAddr = instructionDef.getInput(0);
                            if (constAddr.isConstant()) {
                                addresses.add(new StringPtr(constAddr.getOffset(), (int) sizeNode.getOffset()));
                            }
                        }
                    } else if (encDataNode.isAddress()) { // needed for some ARM Samples
                        Address addressPtr = resolveIndirectAddress(encDataNode.getAddress());
                        if (addressPtr != null) {
                            addresses.add(new StringPtr(addressPtr.getOffset(), 0));
                        }
                    }
                }
            }
        }
        return addresses;
    }

    // ToDo: Improve code
    private byte[] fetchShiftXorEncKey(DecompileResults decompiledFunction) {
        HighFunction highFunction = decompiledFunction.getHighFunction();
        Iterator<PcodeOpAST> pcodeOpASTIterator = highFunction.getPcodeOps();
        while (pcodeOpASTIterator.hasNext()) {
            PcodeOpAST pcodeOp = pcodeOpASTIterator.next();
            /*
            * The LOAD Mnemonic is used in ARM, MIPS and some of the x86_64 Samples to load the Encryption Key from memory.
            * */
            if (pcodeOp.getOpcode() == LOAD) {
                Varnode destination = pcodeOp.getOutput();
                /*
                * Required for ARM and MIPS samples
                * There are two different cases we can have of how the key is loaded from memory with the PcodeOps.
                * The first one loads the Key directly into a Register (Variable) thats covered with the first If Statement. if(sourceNode.isUnique()) {
                *   LOAD INSTR: (register, 0x10, 4) LOAD (const, 0x1a1, 4) , (unique, 0x10000025, 4)
                *   RAM CAST INSTR: (unique, 0x10000025, 4) CAST (ram, 0x471324, 4)
                * The second one loads a pointer to the Encryption Key into a Register (Variable) thats covered with the second If Statement. } else if (sourceNode.isRegister()) {
                *   LOAD INSTR: (register, 0x10, 4) LOAD (const, 0x1a1, 4) , (register, 0x2c, 4)
                *   MULTIEQUAL INSTR: (register, 0x2c, 4) MULTIEQUAL (unique, 0x10000021, 4) , (register, 0x2c, 4)
                *   COPY INSTR: (unique, 0x10000021, 4) COPY (unique, 0x10000031, 4)
                *   RAM CAST INSTR: (unique, 0x10000031, 4) CAST (ram, 0x4555d4, 4)
                * With the RAM Element we can load Encryption Key from Memory, after Resolving it twice.
                * */
                if (destination.isRegister()) {
                    Varnode source = pcodeOp.getInput(1);
                    if (source.isUnique()) {
                        PcodeOp instructionDef = source.getDef();
                        source = instructionDef.getInput(0);
                        if (source.isAddress()) {
                            Address keyDataAddress = resolveIndirectAddress(source.getAddress());
                            if (keyDataAddress != null) {
                                Data data = currentProgram.getListing().getDataAt(keyDataAddress);
                                if (data != null) {
                                    Object keyData = data.getValue();
                                    if (keyData instanceof Scalar keyDataScalar) {
                                        return keyDataScalar.byteArrayValue();
                                    } else {
                                        logger.logDebug("Unknown keyData type: " + keyData.getClass());
                                    }
                                }
                            }
                        }
                    } else if (source.isRegister()) {
                        PcodeOp instructionDef = source.getDef();
                        source = instructionDef.getInput(0);
                        if (source.isUnique()) {
                            instructionDef = source.getDef();
                            source = instructionDef.getInput(0);
                            instructionDef = source.getDef();
                            source = instructionDef.getInput(0);
                            if (source.isAddress()) {
                                Address keyDataAddress = resolveIndirectAddress(source.getAddress());
                                if (keyDataAddress != null) {
                                    Data data = currentProgram.getListing().getDataAt(keyDataAddress);
                                    if (data != null) {
                                        Object keyData = data.getValue();
                                        if (keyData instanceof Scalar keyDataScalar) {
                                            return keyDataScalar.byteArrayValue();
                                        } else {
                                            logger.logDebug("Unknown keyData type: " + keyData.getClass());
                                        }
                                    }
                                }
                            }
                        }
                    } else if (source.isAddress()) {
                        Address keyDataAddress = resolveIndirectAddress(source.getAddress());
                        if (keyDataAddress != null) {
                            Data data = currentProgram.getListing().getDataAt(keyDataAddress);
                            if (data != null) {
                                Object keyData = data.getValue();
                                if (keyData instanceof Scalar keyDataScalar) {
                                    return keyDataScalar.byteArrayValue();
                                } else {
                                    logger.logDebug("Unknown keyData type: " + keyData.getClass());
                                }
                            }
                        }
                    }
                    /*
                    * Required for x86_64 Samples that use a pointer to load the Key
                    * Those have a unique element as Destination instead of a register.
                    * When following the Unique Element of the Input we get to a PTRADD instruction that contains a PTRSUB instruction.
                    * In this PTRSUB Instruction we get the Memory Address of the Key in the Constant Element.
                    * LOAD INSTR: (unique, 0xc200, 4) LOAD (const, 0x1b1, 4) , (unique, 0x10000069, 8)
                    * PTRADD INSTR: (unique, 0x3580, 8) PTRADD (unique, 0x1000002d, 8) , (register, 0x98, 8) , (const, 0x4, 8));
                    * PTRSUB INSTR: (unique, 0x1000002d, 8) PTRSUB (const, 0x0, 8) , (const, 0x50e140, 8)
                    * Memory Address: 0x50e140
                    * */
                } else if (destination.isUnique()) {
                    Varnode sourceNode = pcodeOp.getInput(1);
                    if (sourceNode.isUnique()) {
                        PcodeOp instructionDef = sourceNode.getDef();
                        if (instructionDef.getOpcode() == PTRADD) {
                            sourceNode = instructionDef.getInput(0);
                            instructionDef = sourceNode.getDef();
                            sourceNode = instructionDef.getInput(1);
                            Data data = currentProgram.getListing().getDataAt(sourceNode.getAddress());
                            if (data == null) {
                                continue;
                            }
                            Object keyData = data.getValue();
                            if (keyData == null) {
                                continue;
                            }
                            if (keyData instanceof Scalar keyDataScalar) {
                                return keyDataScalar.byteArrayValue();
                            } else {
                                logger.logDebug("Unknown keyData type: " + keyData.getClass());
                            }
                        }
                    }
                }
            /*
             * The COPY Mnemonic is used in intel and some of the x86_64 Samples to load the Encryption Key from ram.
             * RAM COPY INSTR: (unique, 0x10000063, 4) COPY (ram, 0x512cf0, 4)
             * Where we can directly read the Key from the Address used in the ram element.
             * */
            } else if (pcodeOp.getOpcode() == COPY) { // for x86_64 and intel
                Varnode source = pcodeOp.getInput(0);
                if (source.isAddress()) {
                    Data data = currentProgram.getListing().getDataAt(source.getAddress());
                    if (data != null) {
                        Object keyData = data.getValue();
                        if (keyData instanceof Scalar keyDataScalar) {
                            return keyDataScalar.byteArrayValue();
                        } else {
                            logger.logDebug("Unknown keyData type: " + keyData.getClass());
                        }
                    }
                }
            }
        }
        return new byte[0];
    }

    private Address fetchShiftXorBufferAddress(DecompileResults decompiledFunction) {
        HighFunction highFunction = decompiledFunction.getHighFunction();
        Iterator<PcodeOpAST> pcodeOpASTIterator = highFunction.getPcodeOps();
        while (pcodeOpASTIterator.hasNext()) {
            PcodeOpAST pcodeOp = pcodeOpASTIterator.next();
            if (pcodeOp.getOpcode() == PTRADD) { // ARM
                Varnode sourceNode = pcodeOp.getInput(0);
                if (sourceNode.isAddress()) {
                    Data data = currentProgram.getListing().getDataAt(sourceNode.getAddress());
                    if (data != null) {
                        Object addressPtr = data.getValue();
                        if (addressPtr instanceof GenericAddress genericAddress) {
                            return genericAddress.getPhysicalAddress();
                        } else {
                            logger.logDebug("Unknown value type: " + addressPtr.getClass());
                        }
                    }
                }
            } else if (pcodeOp.getOpcode() == PTRSUB) { // Intel
                Varnode sourceNode = pcodeOp.getInput(1);
                if (sourceNode.isConstant()) {
                    return sourceNode.getAddress();
                }
            }
        }

        return null;
    }

    private byte[] fetchRc4EncKey(DecompileResults decompiledFunction) {
        HighFunction highFunction = decompiledFunction.getHighFunction();
        Iterator<PcodeOpAST> pcodeOpASTIterator = highFunction.getPcodeOps();

        boolean foundIntNotEqual = false;
        while (pcodeOpASTIterator.hasNext()) {
            PcodeOpAST pcodeOp = pcodeOpASTIterator.next();
            if (pcodeOp.getOpcode() == INT_NOTEQUAL && !foundIntNotEqual) {
                foundIntNotEqual = true;
            } else if (foundIntNotEqual && pcodeOp.getOpcode() == LOAD) {
                Varnode destination = pcodeOp.getOutput();
                if (destination.isUnique()) {
                    Varnode sourceNode = pcodeOp.getInput(1);
                    if (sourceNode.isUnique()) {
                        PcodeOp instructionDef = sourceNode.getDef();
                        if (instructionDef.getOpcode() == PTRADD) {
                            sourceNode = instructionDef.getInput(0);
                            instructionDef = sourceNode.getDef();
                            if (instructionDef.getOpcode() == PTRSUB) {// Works for PowerPC
                                sourceNode = instructionDef.getInput(1);
                                if (sourceNode.isConstant()) {
                                    Address address = sourceNode.getAddress();
                                    if (((int) address.getOffset()) > 0) {
                                        // Const to normal address space
                                        address = toAddr(address.getOffset());
                                        return fetchDataFromAddress(address, DEFAULT_MAX_STRING_LENGTH, true);
                                    }
                                }
                            } else if (instructionDef.getOpcode() == INDIRECT) {
                                Instruction loadInstr = getInstructionAt(destination.getPCAddress());
                                return fetchDataFromAddress(loadInstr.getOperandReferences(1)[0].getToAddress(),
                                        DEFAULT_MAX_STRING_LENGTH, true);
                            }
                        }
                    } else if (sourceNode.isRegister()) { // Works for MIPS
                        Instruction loadInstr = getInstructionAt(destination.getPCAddress());
                        return fetchDataFromAddress(loadInstr.getOperandReferences(1)[0].getToAddress(),
                                DEFAULT_MAX_STRING_LENGTH, true);
                    }
                }
            }
        }
        return new byte[0];
    }

    private byte[] fetchBruteforceEncKey(DecompileResults decompiledFunction) {
        HighFunction highFunction = decompiledFunction.getHighFunction();
        Iterator<PcodeOpAST> pcodeOpASTIterator = highFunction.getPcodeOps();
        while (pcodeOpASTIterator.hasNext()) {
            PcodeOpAST pcodeOp = pcodeOpASTIterator.next();
            if (pcodeOp.getOpcode() == INT_XOR) {
                Varnode xorConstantNode = pcodeOp.getInput(1);
                if (xorConstantNode.isConstant()) {
                    byte[] keyByte = new byte[1];
                    keyByte[0] = (byte) xorConstantNode.getOffset();
                    return keyByte;
                }
            }
        }
        return new byte[0];
    }

    private List<Address> fetchRc4EncStrings(Address encryptionRoutineAddress, DecompInterface decompiler) {
        HashSet<Function> callerFunctionSet = new HashSet<>();
        List<Address> encStringList = new ArrayList<>();
        Reference[] references = getReferencesTo(encryptionRoutineAddress);
        for (Reference ref : references) {
            callerFunctionSet.add(getFunctionContaining(ref.getFromAddress()));
        }
        // Loop over all caller Functions, could be more than one.
        for (Function callerFunction : callerFunctionSet) {
            if (callerFunction == null) {
                continue;
            }
            DecompileResults decompiledFunction = decompiler.decompileFunction(callerFunction, 60, null);
            List<Address> returnedList = rc4ResolveCallParameters(decompiledFunction, encryptionRoutineAddress);
            encStringList.addAll(returnedList);
        }
        return encStringList;
    }

    private List<EncryptedCredentialEntry> fetchBruteforceEncCredentials(Address encryptionRoutineAddress,
            DecompInterface decompiler) {
        List<EncryptedCredentialEntry> encCredMap = new ArrayList<>();
        HashSet<Function> callerFunctionSet = new HashSet<>();
        Reference[] references = getReferencesTo(encryptionRoutineAddress);
        for (Reference ref : references) {
            callerFunctionSet.add(getFunctionContaining(ref.getFromAddress()));
        }
        for (Function callerFunction : callerFunctionSet) {
            if (callerFunction == null) {
                continue;
            }
            DecompileResults decompiledFunction = decompiler.decompileFunction(callerFunction, 60, null);
            List<EncryptedCredentialEntry> returnedList = bruteforceResolveCallParameters(decompiledFunction,
                    encryptionRoutineAddress);
            encCredMap.addAll(returnedList);
        }
        return encCredMap;
    }

    private List<Address> rc4ResolveCallParameters(DecompileResults decompiledFunction,
            Address encryptionRoutineAddress) {
        HighFunction highFunction = decompiledFunction.getHighFunction();
        Iterator<PcodeOpAST> pcodeOpASTIterator = highFunction.getPcodeOps();
        List<Address> encStringList = new ArrayList<>();
        while (pcodeOpASTIterator.hasNext()) {
            PcodeOpAST pcodeOp = pcodeOpASTIterator.next();
            if (pcodeOp.getOpcode() == CALL) { // ARM
                Varnode callToAddress = pcodeOp.getInput(0);
                if (callToAddress.getAddress().equals(encryptionRoutineAddress)) { // only get strings for calls that
                                                                                   // are made to the rc4
                    Varnode strSourceNode = pcodeOp.getInput(2);
                    if (strSourceNode != null) { // check that there is actually a string present.
                        if (strSourceNode.isAddress()) {
                            encStringList.add(resolveIndirectAddress(strSourceNode.getAddress()));
                        } else if (strSourceNode.isUnique()) { // PowerPC
                            PcodeOp parameterDef = strSourceNode.getDef();
                            Varnode sourceNode = parameterDef.getInput(1);
                            Address address = toAddr(sourceNode.getAddress().getOffset());
                            if (((int) address.getOffset()) > 0) {
                                encStringList.add(address);
                            }
                        }
                    }
                }
            } else if (pcodeOp.getOpcode() == CALLIND) { // MIPS
                encStringList.add(fetchAddressFromVorNodeInstruction(pcodeOp.getInput(2)));
            }
        }
        return encStringList;
    }

    // ToDo: Add arm
    private List<EncryptedCredentialEntry> bruteforceResolveCallParameters(DecompileResults decompiledFunction,
            Address encryptionRoutineAddress) {
        HighFunction highFunction = decompiledFunction.getHighFunction();
        Iterator<PcodeOpAST> pcodeOpASTIterator = highFunction.getPcodeOps();
        List<EncryptedCredentialEntry> encCredMap = new ArrayList<>();
        Address username, password;
        while (pcodeOpASTIterator.hasNext()) {
            PcodeOpAST pcodeOp = pcodeOpASTIterator.next();
            username = null;
            password = null;
            if (pcodeOp.getOpcode() == CALL) {
                Varnode calltoAddress = pcodeOp.getInput(0);
                if (calltoAddress.getAddress().equals(encryptionRoutineAddress)) {
                    Varnode usernameNode = pcodeOp.getInput(1);
                    Varnode passwordNode = pcodeOp.getInput(2);
                    if (usernameNode != null && usernameNode.isUnique() && passwordNode != null
                            && passwordNode.isUnique()) {
                        if (usernameNode.getDef() != null) {
                            PcodeOp usernamePcodeOp = usernameNode.getDef();
                            if (usernamePcodeOp.getOpcode() == COPY) {
                                usernameNode = usernamePcodeOp.getInput(0);
                                Address address = toAddr(usernameNode.getAddress().getOffset());
                                if (((int) address.getOffset()) > 0) {
                                    username = address;
                                }
                            } else if (usernamePcodeOp.getOpcode() == PTRSUB) {
                                usernameNode = usernamePcodeOp.getInput(1);
                                Address address = toAddr(usernameNode.getAddress().getOffset());
                                if (((int) address.getOffset()) > 0) {
                                    username = address;
                                }
                            }
                        }
                        if (passwordNode.getDef() != null) {
                            PcodeOp passwordPcodeOp = passwordNode.getDef();
                            if (passwordPcodeOp.getOpcode() == COPY) {
                                passwordNode = passwordPcodeOp.getInput(0);
                                Address address = toAddr(passwordNode.getAddress().getOffset());
                                if (((int) address.getOffset()) > 0) {
                                    password = address;
                                }
                            } else if (passwordPcodeOp.getOpcode() == PTRSUB) {
                                passwordNode = passwordPcodeOp.getInput(1);
                                Address address = toAddr(passwordNode.getAddress().getOffset());
                                if (((int) address.getOffset()) > 0) {
                                    password = address;
                                }
                            }
                        }
                    } else if (usernameNode != null && usernameNode.isAddress() && passwordNode.isAddress()) {
                        username = resolveIndirectAddress(usernameNode.getAddress());
                        password = resolveIndirectAddress(passwordNode.getAddress());
                    }
                }
            } else if (pcodeOp.getOpcode() == CALLIND) {
                if (pcodeOp.getInputs().length > 2) {
                    Varnode callDestNode = pcodeOp.getInput(0);
                    Varnode usernameNode = pcodeOp.getInput(1);
                    Varnode passwordNode = pcodeOp.getInput(2);
                    if (callDestNode.isRegister() && usernameNode != null && usernameNode.isRegister()
                            && passwordNode != null && passwordNode.isRegister()) {
                        username = fetchAddressFromVorNodeInstruction(usernameNode);
                        password = fetchAddressFromVorNodeInstruction(passwordNode);
                    } else if (usernameNode != null && usernameNode.isAddress() && passwordNode != null
                            && passwordNode.isAddress()) { // Renesas Samples
                        username = resolveIndirectAddress(usernameNode.getAddress());
                        password = resolveIndirectAddress(passwordNode.getAddress());
                    }
                }
            }
            if (username != null || password != null) {
                encCredMap.add(new EncryptedCredentialEntry(username, password));
            }
        }
        return encCredMap;
    }

    private Address fetchAddressFromVorNodeInstruction(Varnode inputNode) {
        Instruction instr = getInstructionAt(inputNode.getPCAddress());
        if (instr != null) {
            Reference[] references = instr.getReferencesFrom();
            if (references.length > 0) {
                return references[0].getToAddress();
            }
        }
        return null;
    }

    private Address resolveIndirectAddress(Address addressPointer) {
        Data dataNode = currentProgram.getListing().getDataAt(addressPointer);
        if (dataNode == null) {
            return null;
        }
        Object data = dataNode.getValue();
        if (data instanceof Address dataAddress) {
            return toAddr(dataAddress.getOffset());
        }
        if (data != null) { // Special case for ARM ghidra.program.database.code.DataDB
            String dataStr = data.toString().substring(data.toString().lastIndexOf(' ') + 1);
            dataStr = dataStr.endsWith("h") ? dataStr.substring(0, dataStr.length() - 1) : dataStr;
            return toAddr(dataStr);
        }
        return null;
    }

    private byte[] fetchDataFromAddress(Address dataAddress) {
        return fetchDataFromAddress(dataAddress, DEFAULT_MAX_STRING_LENGTH, false);
    }

    private byte[] fetchDataFromAddress(Address dataAddress, int maxLength) {
        return fetchDataFromAddress(dataAddress, maxLength, false);
    }

    private byte[] fetchDataFromAddress(Address dataAddress, int maxLength, boolean requireDoubleNull) {
        if (dataAddress == null) {
            logger.logDebug("provided Address is null!");
            return new byte[0];
        }
        List<Byte> byteList = new ArrayList<>();
        try {
            while (byteList.size() < maxLength) {
                byte b = currentProgram.getMemory().getByte(dataAddress);
                // Check if the current byte is 0x00
                if (b == 0x00) {
                    if (!requireDoubleNull) {
                        break;
                    }
                    byte nextByte = currentProgram.getMemory().getByte(dataAddress.add(1));
                    if (nextByte == 0x00) {
                        // Two consecutive bytes are 0x00, terminate the loop
                        break;
                    }
                }
                byteList.add(b);
                dataAddress = dataAddress.add(1);
            }
        } catch (MemoryAccessException e) {
            logger.logError("MemoryAccessException while reading address: " + dataAddress.toString());
        }
        return listToByteArray(byteList);
    }

    private byte[] listToByteArray(List<Byte> byteList) {
        byte[] byteArrays = new byte[byteList.size()];
        for (int i = 0; i < byteList.size(); i++) {
            byteArrays[i] = byteList.get(i);
        }
        return byteArrays;
    }

    private String byteArrayToHexString(byte[] bytes) {
        final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    private byte[] xorDecryptor(byte[] ciphertext, byte[] tableKey) {
        byte key = 0;
        for (byte keyByte : tableKey) {
            key ^= keyByte;
        }

        byte[] plaintext = new byte[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i++) {
            byte b = ciphertext[i];
            b ^= key;
            plaintext[i] = b;
        }
        return plaintext;
    }

    // Not using the Java implementation, since the key length is limited to 128
    // Characters. But the used keys here are longer then that.
    private byte[] rc4Algorithm(byte[] key, byte[] ciphertext) {
        byte[] S = new byte[256];
        byte[] T = new byte[256];
        int keyLength = key.length;
        for (int i = 0; i < 256; i++) {
            S[i] = (byte) i;
            T[i] = key[i % keyLength];
        }
        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + S[i] + T[i]) & 0xFF;
            swap(S, i, j);
        }

        byte[] plaintext = new byte[ciphertext.length];
        int i = 0;
        j = 0;
        for (int k = 0; k < ciphertext.length; k++) {
            i = (i + 1) & 0xFF;
            j = (j + S[i]) & 0xFF;
            swap(S, i, j);
            int t = (S[i] + S[j]) & 0xFF;
            plaintext[k] = (byte) (ciphertext[k] ^ S[t]);
        }
        return plaintext;
    }

    private static void swap(byte[] array, int i, int j) {
        byte temp = array[i];
        array[i] = array[j];
        array[j] = temp;
    }

    interface ScriptLogger {
        public String getName();

        public void logSampleInformation(String filename, String hash, String arch);

        public void logDebug(String message);

        public void logError(String message);

        public void logEncryptionFunction(Function function, EncryptionType type);

        public void logDecryption(Address encryptedBufferAddress, byte[] decryptedBuffer,
                byte[] encryptionKey, EncryptionType type);

        public void logCredential(Address encryptedUsernameAddress, Address encryptedPasswordAddress,
                byte[] decryptedUsername, byte[] decryptedPassword, byte[] encryptionKey);
    }

    class StringLogger implements ScriptLogger {
        public String getName() {
            return "STRING";
        }

        public void logSampleInformation(String filename, String hash, String arch) {
            println("Sample Name: " + filename);
            println("SHA256 Hash: " + hash);
            println("Processor Arch: " + arch);
        }

        public void logDebug(String message) {
            if (LOG_DEBUG_MESSAGES) {
                println(message);
            }
        }

        public void logError(String message) {
            println("Error: " + message);
        }

        public void logEncryptionFunction(Function function, EncryptionType type) {
            logDebug("Found Encryption Function: " + function.getEntryPoint());
        }

        public void logDecryption(Address encryptedBufferAddress, byte[] decryptedBuffer,
                byte[] encryptionKey, EncryptionType type) {
            println("Decrypted: " + new String(decryptedBuffer, UTF_8));
        }

        public void logCredential(Address encryptedUsernameAddress, Address encryptedPasswordAddress,
                byte[] decryptedUsername, byte[] decryptedPassword, byte[] encryptionKey) {
            println("Creds: " + new String(decryptedUsername, UTF_8) + ": " + new String(decryptedPassword, UTF_8));
        }
    }

    class GhidraUpdate implements ScriptLogger {
        private Map<EncryptionType, Integer> fnameIncrements = new HashMap<>();

        public String getName() {
            return "GHIDRA_UPDATE";
        }

        public void logSampleInformation(String filename, String hash, String arch) {
            // Nothing to be done
        }

        public void logDebug(String message) {
            // Nothing to be done
        }

        public void logError(String message) {
            // Nothing to be done
        }

        public void logEncryptionFunction(Function function, EncryptionType type) {
            try {
                Integer functionIncrement = fnameIncrements.getOrDefault(type, 1);
                function.setName("fun_encryption_routine_" + type.toString().toLowerCase() + "_" + functionIncrement,
                        SourceType.USER_DEFINED);
                fnameIncrements.put(type, functionIncrement + 1);
            } catch (DuplicateNameException | InvalidInputException ex) {
                logger.logError("Failed to rename function: " + function.getEntryPoint());
            }
        }

        private String toLabelString(byte[] decryptedBuffer) {
            String str = new String();
            for (byte character : decryptedBuffer) {
                // Number || Uppercase || Lowercase
                if ((character >= 48 && character <= 57) || (character >= 65 && character <= 90)
                        || (character >= 97 && character <= 122)) {
                    byte[] singleChar = new byte[1];
                    singleChar[0] = character;
                    str += new String(singleChar, UTF_8);
                } else {
                    str += '_';
                }
            }
            return str;
        }

        public void logDecryption(Address encryptedBufferAddress, byte[] decryptedBuffer, byte[] encryptionKey,
                EncryptionType type) {
            String name = "DEC_" + type.toString().toLowerCase() + "_" + encryptedBufferAddress.getOffset() + "_STR_" + toLabelString(decryptedBuffer);
            try {
                createLabel(encryptedBufferAddress, name, true, SourceType.USER_DEFINED);
            } catch (Exception e) {
                logger.logError("Failed to create Label: " + name);
            }
        }

        public void logCredential(Address encryptedUsernameAddress, Address encryptedPasswordAddress,
                byte[] decryptedUsername, byte[] decryptedPassword, byte[] encryptionKey) {
            logDecryption(encryptedUsernameAddress, decryptedUsername, encryptionKey, EncryptionType.BRUTEFORCE_XOR);
            logDecryption(encryptedPasswordAddress, decryptedPassword, encryptionKey, EncryptionType.BRUTEFORCE_XOR);
        }
    }

    class MulitLogger implements ScriptLogger {
        private final List<ScriptLogger> loggers;

        public MulitLogger(List<ScriptLogger> loggers) {
            this.loggers = loggers;
        }

        public String getName() {
            List<String> combinedNames = new ArrayList<>();
            for (ScriptLogger scriptLogger : loggers) {
                combinedNames.add(scriptLogger.getName());
            }
            return "(" + String.join(",", combinedNames) + ")";
        }

        public void logSampleInformation(String filename, String hash, String arch) {
            for (ScriptLogger logger : loggers) {
                logger.logSampleInformation(filename, hash, arch);
            }
        }

        public void logDebug(String message) {
            for (ScriptLogger logger : loggers) {
                logger.logDebug(message);
            }
        }

        public void logError(String message) {
            for (ScriptLogger logger : loggers) {
                logger.logError(message);
            }
        }

        public void logEncryptionFunction(Function function, EncryptionType type) {
            for (ScriptLogger logger : loggers) {
                logger.logEncryptionFunction(function, type);
            }
        }

        public void logDecryption(Address encryptedBufferAddress, byte[] decryptedBuffer, byte[] encryptionKey,
                EncryptionType type) {
            for (ScriptLogger logger : loggers) {
                logger.logDecryption(encryptedBufferAddress, decryptedBuffer, encryptionKey, type);
            }
        }

        public void logCredential(Address encryptedUsernameAddress, Address encryptedPasswordAddress,
                byte[] decryptedUsername, byte[] decryptedPassword, byte[] encryptionKey) {
            for (ScriptLogger logger : loggers) {
                logger.logCredential(encryptedUsernameAddress, encryptedPasswordAddress, decryptedUsername,
                        decryptedPassword, encryptionKey);
            }
        }
    }

    class JsonLogger implements ScriptLogger {
        public String getName() {
            return "JSON";
        }

        public void logSampleInformation(String filename, String hash, String arch) {
            println("{'type': 'sample', 'name': '" + filename + "', 'hash': '" + hash + "', 'arch': '" + arch + "'}");
        }

        public void logDebug(String message) {
            if (LOG_DEBUG_MESSAGES) {
                println("{'type': 'debug', 'message': '" + message + "'}");
            }
        }

        public void logError(String message) {
            println("{'type': 'error', 'message': '" + message + "'}");
        }

        public void logEncryptionFunction(Function function, EncryptionType type) {
            println("{'type': 'encryptionFunction', 'entryPoint': '" + function.getEntryPoint() + "'}");
        }

        public void logDecryption(Address encryptedBufferAddress, byte[] decryptedBuffer, byte[] encryptionKey,
                EncryptionType type) {
            println("{'type': 'decryption', 'key': '" + byteArrayToHexString(encryptionKey) + "', 'address': "
                    + String.valueOf(encryptedBufferAddress.getOffset()) + ", 'decrypted': '"
                    + byteArrayToHexString(decryptedBuffer) + "'}");
        }

        public void logCredential(Address encryptedUsernameAddress, Address encryptedPasswordAddress,
                byte[] decryptedUsername, byte[] decryptedPassword, byte[] encryptionKey) {
            println("{'type': 'credential', 'key': '" + byteArrayToHexString(encryptionKey) + "', 'usernameAddress': "
                    + String.valueOf(encryptedUsernameAddress.getOffset()) + "', 'passwordAddress': "
                    + String.valueOf(encryptedPasswordAddress.getOffset()) + ", 'username': '"
                    + byteArrayToHexString(decryptedUsername) + ", 'password': '"
                    + byteArrayToHexString(decryptedPassword) + "'}");
        }
    }
}
