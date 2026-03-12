import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

// Binary Analysis Tools
import { registerAnalyzeBinary } from './tools/analyze-binary.js';
import { registerListFunctions } from './tools/list-functions.js';
import { registerDisassemble } from './tools/disassemble.js';
import { registerDecompileFunction } from './tools/decompile.js';
import { registerListStrings } from './tools/list-strings.js';
import { registerGetXrefs } from './tools/get-xrefs.js';
import { registerListImports } from './tools/list-imports.js';
import { registerListExports } from './tools/list-exports.js';
import { registerListSections } from './tools/list-sections.js';
import { registerReadBytes } from './tools/read-bytes.js';
import { registerRenameFunction } from './tools/rename-function.js';
import { registerAddComment } from './tools/add-comment.js';
import { registerGetFunctionInfo } from './tools/get-function-info.js';
import { registerListVariables } from './tools/list-variables.js';
import { registerWriteBytes } from './tools/write-bytes.js';
import { registerFindCryptoConstants } from './tools/find-crypto.js';
import { registerListResources } from './tools/list-resources.js';
import { registerTriageBinary } from './tools/triage-binary.js';
import { registerAnalyzeFunctionDeep } from './tools/analyze-function-deep.js';
import { registerFindConstraints } from './tools/find-constraints.js';
import { registerTraceExecution } from './tools/trace-execution.js';
import { registerFindVulnerabilities } from './tools/find-vulnerabilities.js';
import { registerSolveCrackme } from './tools/solve-crackme.js';
import { registerExtractIocs } from './tools/extract-iocs.js';
import { registerExploitHunter } from './tools/exploit-hunter.js';
import { registerDiffBinaries } from './tools/diff-binaries.js';
import { registerFileFormatAnalyzer } from './tools/file-format-analyzer.js';

// ESIL Emulation Tools
import { registerEsilInit } from './tools/esil-init.js';
import { registerEsilStep } from './tools/esil-step.js';
import { registerEsilRun } from './tools/esil-run.js';
import { registerEsilGetRegisters } from './tools/esil-get-registers.js';
import { registerEsilSetRegister } from './tools/esil-set-register.js';
import { registerEsilGetMemory } from './tools/esil-get-memory.js';
import { registerEsilSetMemory } from './tools/esil-set-memory.js';
import { registerEsilExpression } from './tools/esil-expression.js';
import { registerEsilDestroy } from './tools/esil-destroy.js';
import { registerEsilListSessions } from './tools/esil-list-sessions.js';

// RzIL Emulation Tools (Rizin backend)
import { registerRzilInit } from './tools/rzil-init.js';
import { registerRzilDestroy } from './tools/rzil-destroy.js';
import { registerRzilListSessions } from './tools/rzil-list-sessions.js';
import { registerRzilStep } from './tools/rzil-step.js';
import { registerRzilRun } from './tools/rzil-run.js';
import { registerRzilGetRegisters } from './tools/rzil-get-registers.js';
import { registerRzilSetRegister } from './tools/rzil-set-register.js';
import { registerRzilGetMemory } from './tools/rzil-get-memory.js';
import { registerRzilSetMemory } from './tools/rzil-set-memory.js';
import { registerRzilTraceStep } from './tools/rzil-trace-step.js';
import { registerRzilIlAst } from './tools/rzil-il-ast.js';

// Rizin Static Analysis Tools (where Rizin is superior)
import { registerRzTypes } from './tools/rz-types.js';
import { registerRzSymbols } from './tools/rz-symbols.js';
import { registerRzLibs } from './tools/rz-libs.js';
import { registerRzEntrypoints } from './tools/rz-entrypoints.js';
import { registerRzCallingConventions } from './tools/rz-calling-conventions.js';

// Shellcode & Advanced Tools
import { registerShellcodeAnalyze } from './tools/shellcode-analyze.js';
import { registerDisassembleBytes } from './tools/disassemble-bytes.js';
import { registerSearchBytes } from './tools/search-bytes.js';
import { registerSearchString } from './tools/search-string.js';
import { registerSearchRopGadgets } from './tools/search-rop-gadgets.js';
import { registerGetCallgraph } from './tools/get-callgraph.js';
import { registerGetControlFlowGraph } from './tools/get-cfg.js';
import { registerR2Command } from './tools/r2-command.js';
import { registerGetEntropy } from './tools/get-entropy.js';

// Debug Tools
import { registerDebugLaunch } from './tools/debug-launch.js';
import { registerDebugAttach } from './tools/debug-attach.js';
import { registerDebugDetach } from './tools/debug-detach.js';
import { registerDebugSetBreakpoint } from './tools/debug-set-breakpoint.js';
import { registerDebugRemoveBreakpoint } from './tools/debug-remove-breakpoint.js';
import { registerDebugListBreakpoints } from './tools/debug-list-breakpoints.js';
import { registerDebugContinue } from './tools/debug-continue.js';
import { registerDebugStep } from './tools/debug-step.js';
import { registerDebugGetRegisters } from './tools/debug-get-registers.js';
import { registerDebugSetRegister } from './tools/debug-set-register.js';
import { registerDebugGetMaps } from './tools/debug-get-maps.js';
import { registerDebugGetBacktrace } from './tools/debug-get-backtrace.js';
import { registerDebugGetThreads } from './tools/debug-get-threads.js';
import { registerDebugGetInfo } from './tools/debug-get-info.js';
import { registerDebugReadMemory } from './tools/debug-read-memory.js';
import { registerDebugWriteMemory } from './tools/debug-write-memory.js';
import { registerDebugKill } from './tools/debug-kill.js';
import { registerDebugListSessions } from './tools/debug-list-sessions.js';
import { registerListRelocations } from './tools/list-relocations.js';
import { registerListClasses } from './tools/list-classes.js';
import { registerAnalyzeTypes } from './tools/analyze-types.js';
import { registerBinaryHeaders } from './tools/binary-headers.js';
import { registerHashBinary } from './tools/hash-binary.js';

export function createServer(): McpServer {
  const server = new McpServer({
    name: 'radare2-mcp',
    version: '1.0.0',
  });

  // Binary Analysis (17 tools)
  registerAnalyzeBinary(server);
  registerListFunctions(server);
  registerDisassemble(server);
  registerDecompileFunction(server);
  registerListStrings(server);
  registerGetXrefs(server);
  registerListImports(server);
  registerListExports(server);
  registerListSections(server);
  registerReadBytes(server);
  registerRenameFunction(server);
  registerAddComment(server);
  registerGetFunctionInfo(server);
  registerListVariables(server);
  registerWriteBytes(server);
  registerFindCryptoConstants(server);
  registerListResources(server);
  registerListRelocations(server);
  registerListClasses(server);

  // Advanced Analysis (10 tools)
  registerTriageBinary(server);
  registerAnalyzeFunctionDeep(server);
  registerFindConstraints(server);
  registerTraceExecution(server);
  registerFindVulnerabilities(server);
  registerSolveCrackme(server);
  registerExtractIocs(server);
  registerExploitHunter(server);
  registerDiffBinaries(server);
  registerFileFormatAnalyzer(server);

  // ESIL Emulation (10 tools)
  registerEsilInit(server);
  registerEsilDestroy(server);
  registerEsilListSessions(server);
  registerEsilStep(server);
  registerEsilRun(server);
  registerEsilGetRegisters(server);
  registerEsilSetRegister(server);
  registerEsilGetMemory(server);
  registerEsilSetMemory(server);
  registerEsilExpression(server);

  // RzIL Emulation — Rizin backend (9 tools)
  registerRzilInit(server);
  registerRzilDestroy(server);
  registerRzilListSessions(server);
  registerRzilStep(server);
  registerRzilRun(server);
  registerRzilGetRegisters(server);
  registerRzilSetRegister(server);
  registerRzilGetMemory(server);
  registerRzilSetMemory(server);
  registerRzilTraceStep(server);
  registerRzilIlAst(server);

  // Rizin Static Analysis (5 tools — where Rizin excels over r2)
  registerRzTypes(server);
  registerRzSymbols(server);
  registerRzLibs(server);
  registerRzEntrypoints(server);
  registerRzCallingConventions(server);

  // Shellcode & Advanced (9 tools)
  registerShellcodeAnalyze(server);
  registerDisassembleBytes(server);
  registerSearchBytes(server);
  registerSearchString(server);
  registerSearchRopGadgets(server);
  registerGetCallgraph(server);
  registerGetControlFlowGraph(server);
  registerR2Command(server);
  registerGetEntropy(server);

  // Debug Tools (16 tools)
  registerDebugLaunch(server);
  registerDebugAttach(server);
  registerDebugDetach(server);
  registerDebugSetBreakpoint(server);
  registerDebugRemoveBreakpoint(server);
  registerDebugListBreakpoints(server);
  registerDebugContinue(server);
  registerDebugStep(server);
  registerDebugGetRegisters(server);
  registerDebugSetRegister(server);
  registerDebugGetMaps(server);
  registerDebugGetBacktrace(server);
  registerDebugGetThreads(server);
  registerDebugGetInfo(server);
  registerDebugReadMemory(server);
  registerDebugWriteMemory(server);
  registerDebugKill(server);
  registerDebugListSessions(server);

  // Type, Header & Hash Tools (3 tools)
  registerAnalyzeTypes(server);
  registerBinaryHeaders(server);
  registerHashBinary(server);

  return server;
}
