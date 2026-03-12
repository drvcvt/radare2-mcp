# Radare2 MCP Server

## Project Overview

MCP (Model Context Protocol) server that exposes radare2 and Rizin binary analysis capabilities to Claude. Provides 85 structured tools: 69 r2-based tools (via r2pipe) for disassembly, decompilation, function analysis, string extraction, cross-references, ESIL emulation, live debugging, shellcode analysis, vulnerability scanning, and exploit development; plus 16 Rizin-based tools (via child_process -q0 protocol) for RzIL typed emulation, IL AST lifting, and enhanced type/symbol analysis. All output is parsed into typed JSON responses -- no raw text passthrough.

## Tech Stack

| Component | Version | Purpose |
|---|---|---|
| TypeScript | 5.x, strict mode | Primary language |
| @modelcontextprotocol/sdk | ^1.12.1 | MCP server framework |
| r2pipe | ^2.8.6 | radare2 scripting bridge (spawns/connects to r2) |
| zod | ^3.24.0 | Runtime schema validation for tool parameters |
| radare2 | >= 5.8 | Must be installed system-wide, `r2` in PATH |
| rizin | >= 0.8.x | Optional second backend for RzIL emulation, spawned via child_process |
| tsx | ^4.19.0 | Dev runner |
| vitest | ^2.1.0 | Test framework |
| eslint + prettier | latest | Linting and formatting |

## Project Structure

```
radare2/
  CLAUDE.md                 # This file -- project rules for Claude Code
  package.json
  tsconfig.json
  eslint.config.mjs
  .prettierrc
  src/
    index.ts                # Entry point: stdio transport, shutdown handlers
    server.ts               # McpServer setup, imports & registers all 69 tools
    types.ts                # Shared TypeScript interfaces and Zod schemas
    r2/
      session.ts            # R2Session class: wraps r2pipe lifecycle, cmd/cmdj/close
      session-cache.ts      # SessionCache: reuses sessions across tool calls (avoids re-running aaa)
      commands.ts           # Typed wrappers around r2 commands (aflj, ij, iij, etc.)
      sanitize.ts           # Input sanitization: paths, addresses, commands, search queries, comments, PIDs, UUIDs, registers
      debug-session-manager.ts  # DebugSessionManager: persistent debug sessions across tool calls
      esil-session-manager.ts   # EsilSessionManager: persistent ESIL VM sessions across tool calls
    rizin/
      rizin-session.ts        # RizinSession: spawns rizin -q0 via child_process (newline cmd, null-byte response)
      rzil-session-manager.ts # RzilSessionManager: persistent RzIL sessions (UUID, 10min idle, max 5)
      formatters.ts           # Markdown formatters for RzIL tool output
    tools/                  # 85 tool files, one per tool (kebab-case filenames)
      analyze-binary.ts     # analyze_binary: open binary, get info (ij, iIj)
      list-functions.ts     # list_functions: list functions (aflj)
      disassemble.ts        # disassemble: disassemble at address (pdfj, pdj)
      decompile.ts          # decompile_function: pseudo-C decompilation (pdc, pdg)
      list-strings.ts       # list_strings: extract strings (izj, izzj)
      get-xrefs.ts          # get_xrefs: cross-references (axtj, axfj)
      list-imports.ts       # list_imports: imported symbols (iij)
      list-exports.ts       # list_exports: exported symbols (iEj)
      list-sections.ts      # list_sections: sections/segments (iSj)
      read-bytes.ts         # read_bytes: read raw bytes (pxj, px)
      rename-function.ts    # rename_function: rename function (afn)
      add-comment.ts        # add_comment: add comment (CCu base64:)
      get-function-info.ts  # get_function_info: function metadata (afij)
      list-variables.ts     # list_variables: function variables (afvj)
      write-bytes.ts        # write_bytes: patch bytes (wx, wa)
      find-crypto.ts        # find_crypto_constants: detect crypto (rahash2)
      list-resources.ts     # list_resources: PE resources (iRj)
      list-relocations.ts   # list_relocations: relocation entries (irj)
      list-classes.ts       # list_classes: classes and methods (icj)
      triage-binary.ts      # triage_binary: comprehensive one-shot triage
      analyze-function-deep.ts  # analyze_function_deep: deep single-function analysis
      find-constraints.ts   # find_constraints: crackme constraint extraction
      trace-execution.ts    # trace_execution: ESIL execution tracing
      find-vulnerabilities.ts   # find_vulnerabilities: vulnerability pattern scanning
      solve-crackme.ts      # solve_crackme: automated crackme solver
      extract-iocs.ts       # extract_iocs: IOC extraction (IPs, URLs, etc.)
      exploit-hunter.ts     # exploit_hunter: exploit development assistant
      diff-binaries.ts      # diff_binaries: binary diffing
      file-format-analyzer.ts   # file_format_analyzer: file format parsing
      esil-init.ts          # esil_init: create ESIL session
      esil-destroy.ts       # esil_destroy: destroy ESIL session
      esil-list-sessions.ts # esil_list_sessions: list ESIL sessions
      esil-step.ts          # esil_step: single-step ESIL
      esil-run.ts           # esil_run: run ESIL until address
      esil-get-registers.ts # esil_get_registers: read ESIL registers
      esil-set-register.ts  # esil_set_register: write ESIL register
      esil-get-memory.ts    # esil_get_memory: read ESIL memory
      esil-set-memory.ts    # esil_set_memory: write ESIL memory
      esil-expression.ts    # esil_expression: evaluate ESIL expression
      shellcode-analyze.ts  # shellcode_analyze: analyze raw shellcode bytes
      disassemble-bytes.ts  # disassemble_bytes: disassemble raw hex bytes
      search-bytes.ts       # search_bytes: byte pattern search (/xj)
      search-string.ts      # search_string: string pattern search (/ query)
      search-rop-gadgets.ts # search_rop_gadgets: ROP gadget search (/Rj)
      get-callgraph.ts      # get_callgraph: function call graph (agCj, agCd, agCm)
      get-cfg.ts            # get_control_flow_graph: CFG (agfj)
      r2-command.ts         # r2_command: execute allowlisted r2 command
      get-entropy.ts        # get_entropy: entropy analysis (p=ej)
      debug-launch.ts       # debug_launch: launch binary under debugger
      debug-attach.ts       # debug_attach: attach to process by PID
      debug-detach.ts       # debug_detach: detach from debugged process
      debug-set-breakpoint.ts   # debug_set_breakpoint: set breakpoint (db)
      debug-remove-breakpoint.ts # debug_remove_breakpoint: remove breakpoint (db-)
      debug-list-breakpoints.ts  # debug_list_breakpoints: list breakpoints (dbj)
      debug-continue.ts     # debug_continue: continue execution (dc)
      debug-step.ts         # debug_step: single-step debugger (ds, dso)
      debug-get-registers.ts    # debug_get_registers: read registers (drj)
      debug-set-register.ts     # debug_set_register: write register (dr)
      debug-get-maps.ts     # debug_get_maps: memory maps (dmj)
      debug-get-backtrace.ts    # debug_get_backtrace: call stack (dbtj)
      debug-get-threads.ts  # debug_get_threads: thread list (dptj)
      debug-get-info.ts     # debug_get_info: debug process info (dij)
      debug-read-memory.ts  # debug_read_memory: read debugged memory (px, pxj)
      debug-write-memory.ts # debug_write_memory: write debugged memory (wx, w)
      debug-kill.ts         # debug_kill: kill debugged process (dk)
      debug-list-sessions.ts    # debug_list_sessions: list debug sessions
      analyze-types.ts      # analyze_types: type analysis (tj, tsj, tej)
      binary-headers.ts     # binary_headers: PE/ELF header fields (ihj)
      hash-binary.ts        # hash_binary: compute file hashes (rahash2)
    utils/
      errors.ts             # mcpSuccess, mcpFormatted, mcpError response builders
      formatters.ts         # Markdown formatters for every tool's output
      pagination.ts         # paginate() and PaginatedResult<T> type
      shared-helpers.ts     # isConditionalJump(), stripImportPrefix()
      mitigations.ts        # detectMitigations() — shared canary/NX/PIC/RELRO detection
      temp-files.ts         # writeTempBinary(), cleanupTempFile() for shellcode blobs
  tests/
    fixtures/               # Small test binaries (ELF, PE, shellcode blobs)
    unit/                   # Unit tests (mocked r2, no radare2 required)
    integration/            # Integration tests (require r2 in PATH)
  docs/
    architecture.md
    binja-mcp-reference.md
    research.md
    tool-calls.md
```

## Development Guidelines

### Code Style

- `tsconfig.json`: `strict: true`, `noUncheckedIndexedAccess: true`, `exactOptionalPropertyTypes: true`
- ESLint flat config with `@typescript-eslint/recommended-type-checked`
- Prettier: single quotes, trailing commas, 100 char line width, 2-space indent
- Naming conventions:
  - Tool names (MCP): `snake_case` -- e.g. `list_functions`, `esil_init`
  - TypeScript identifiers: `camelCase` for variables/functions, `PascalCase` for types/classes
  - File names: `kebab-case.ts` -- e.g. `analyze-binary.ts`, `esil-get-registers.ts`
  - Constants: `UPPER_SNAKE_CASE`
- No `any`. Use `unknown` and narrow with Zod or type guards.
- No default exports. Always named exports.

### Architecture Rules

1. **One tool per file.** Each file in `src/tools/` exports a single `register*` function that takes the MCP server instance and calls `server.tool()`.
2. **Three-layer separation:**
   - **Transport layer** (`src/index.ts`, `src/server.ts`): stdio transport, MCP protocol handling, shutdown. No r2 logic.
   - **Tool handlers** (`src/tools/*.ts`): validate input (Zod), call session manager or r2 session, format response. No direct r2pipe calls.
   - **r2 layer** (`src/r2/`): owns r2pipe connections, runs commands, parses JSON output. No MCP awareness.
3. **Three session management patterns** (choose the right one per tool type):
   - **Cached sessions** (`withCachedSession`): For static analysis tools. Sessions are cached by `binaryPath::analysisLevel` key and reused across tool calls. The session cache (max 5 sessions, 5-minute TTL) avoids re-running `aaa` on repeated queries. On error, the session is evicted from the cache.
   - **Debug sessions** (`debugManager`): For debug tools. Persistent sessions identified by UUID. Sessions survive across tool calls so breakpoints, registers, and the debugged process are preserved. Auto-cleaned after 10 minutes idle. Max 5 concurrent sessions.
   - **ESIL sessions** (`esilManager`): For ESIL emulation tools. Persistent sessions identified by UUID. ESIL VM state (registers, memory, PC) is preserved between tool invocations for multi-step emulation workflows. Auto-cleaned after 10 minutes idle. Max 5 concurrent sessions.
   - **RzIL sessions** (`rzilManager`): For Rizin RzIL emulation tools. Persistent sessions spawning `rizin -q0` via `child_process`. RzIL VM state (typed bitvectors, individual CPU flags) is preserved between tool invocations. Uses newline-terminated commands, null-byte-terminated responses. Auto-cleaned after 10 minutes idle. Max 5 concurrent sessions.
   - **Rizin one-shot sessions** (`RizinSession.open/close`): For Rizin static analysis tools (`rz_types`, `rz_symbols`, etc.). Opens a fresh Rizin process per call with no caching.
4. **Error propagation.** r2pipe/Rizin errors become MCP `isError: true` responses with structured messages. Never let errors crash the server process.
5. **Graceful shutdown.** `index.ts` registers SIGINT/SIGTERM handlers that close all four session managers (`sessionCache.closeAll()`, `esilManager.closeAll()`, `rzilManager.closeAll()`, `debugManager.closeAll()`) before exiting.

### r2pipe Best Practices

- **Always prefer JSON output.** Append `j` to commands: `aflj` not `afl`, `ij` not `i`, `pdfj` not `pdf`. Parse the JSON in the r2 layer, return typed objects.
- **Close connections.** Every `r2pipe.open()` must have a corresponding `close()`. Leaked r2 processes consume system resources and file locks.
- **Set timeouts.** r2 commands can hang on malformed binaries. Default: 30s per command (`R2_COMMAND_TIMEOUT` env var).
- **Sanitize inputs.** The `sanitize.ts` module validates all user-provided strings before embedding them in r2 commands. Functions:
  - `sanitizePath()`: absolute path, exists, no shell metacharacters, symlink resolution, ALLOWED_DIRS check (uses `dir + path.sep` to prevent prefix attacks)
  - `sanitizeAddress()`: must match `/^(0x)?[0-9a-fA-F]+$/`
  - `sanitizeCommand()`: rejects `;|><`!~#!` sequences
  - `sanitizeFunctionName()`: alphanumeric + `._:-`
  - `sanitizeNumber()`: finite, within bounds
  - `sanitizeSearchQuery()`: strips shell metacharacters from search strings
  - `sanitizeComment()`: base64-encodes comment text (preserves all characters safely)
  - `sanitizePid()`: positive integer
  - `sanitizeSessionId()`: valid UUID v4
  - `sanitizeRegisterName()`: lowercase alphanumeric + underscore
- **Run analysis up front.** The session cache runs the configured analysis level (default `aaa`) on first open. Debug sessions skip analysis since the binary is loaded for debugging.

### MCP Best Practices

- **Tool descriptions** must be a single sentence that says what the tool does and returns. No filler. Example: `"Disassemble the function at the given address and return the instruction listing as JSON."`
- **Input schemas** use Zod, converted to JSON Schema via `zodToJsonSchema`. Every parameter has a `description`.
- **Shared Zod schemas** in `types.ts`: `pathSchema`, `addressSchema`, `offsetSchema`, `limitSchema`, `paginationSchema`, `functionIdentifierSchema`, `stepsSchema`, `minLengthSchema`, `byteLengthSchema`, `hexPatternSchema`.
- **Pagination.** Any tool that can return more than 100 items must accept `offset` and `limit` parameters (defaults: 0, 100). Return `PaginatedResult<T>` from `utils/pagination.ts`.
- **Consistent error format** via `utils/errors.ts`: `mcpSuccess(data)`, `mcpFormatted(text)`, `mcpError(message)`.
- **Markdown-formatted responses** via `utils/formatters.ts`: every tool type has a dedicated formatter that produces readable markdown with tables.

### Security

- **No arbitrary command execution.** The `r2_command` tool restricts commands to an allowlist of safe r2 commands. Commands containing `;`, `|`, `>`, `<`, `` ` ``, `!`, `~`, `#!` are rejected.
- **Binary path validation.** Paths must be absolute, must point to an existing file. Symlinks are resolved via `realpathSync` and both the link and target are validated against `ALLOWED_DIRS`. Directory prefix matching uses `dir + path.sep` to prevent attacks (e.g. `/binaries-evil` cannot match `/binaries`).
- **Comment safety.** Comments are base64-encoded before passing to r2's `CCu base64:` command, preventing injection of special characters (`$`, `#`, `;`, etc.).
- **Search query sanitization.** `sanitizeSearchQuery()` strips shell metacharacters from user-provided search strings before embedding in r2 commands.
- **Temp file cleanup.** Shellcode analysis writes blobs to a temp directory. Use `try/finally` to delete temp files via `cleanupTempFile()`. Never leave analysis artifacts on disk.
- **Local only.** r2pipe spawns local r2 processes. No TCP r2 connections. The MCP server runs over stdio, not HTTP.
- **No secrets in output.** If a binary contains environment variables or credential-like strings, the tools do not filter them -- but the MCP tool descriptions should warn that output may contain sensitive content from analyzed binaries.

## Commands

```bash
# Install dependencies
npm install

# Build
npm run build              # tsc -> dist/

# Dev (watch mode)
npm run dev                # tsx watch src/index.ts

# Run the server (stdio transport)
node dist/index.js
# or during dev:
npx tsx src/index.ts

# Lint
npm run lint               # eslint .
npm run lint:fix           # eslint . --fix

# Format
npm run format             # prettier --write .
npm run format:check       # prettier --check .

# Test
npm run test               # vitest run
npm run test:watch         # vitest
npm run test:unit          # vitest run tests/unit
npm run test:integration   # vitest run tests/integration (requires r2 in PATH)

# Type check
npm run typecheck          # tsc --noEmit
```

## Testing

### Strategy

- **Unit tests** (`tests/unit/`): test sanitization, pagination, JSON parsing, error formatting. Mock r2pipe. These run without radare2 installed.
- **Integration tests** (`tests/integration/`): open real test binaries with r2pipe, verify tool outputs. Require radare2 in PATH. Run in CI with r2 installed via GitHub Actions.
- **Test fixtures** (`tests/fixtures/`): minimal binaries compiled from small C programs. Commit the source and a Makefile. Binaries are gitignored and rebuilt in CI.
- **No snapshot tests** for r2 output -- r2 output format changes between versions.

### Writing Tests

```typescript
// Unit test example (mocked r2)
import { describe, it, expect } from 'vitest';
import { sanitizeAddress } from '../../src/r2/sanitize';

describe('sanitizeAddress', () => {
  it('accepts hex address with 0x prefix', () => {
    expect(sanitizeAddress('0x08048000')).toBe('0x08048000');
  });

  it('rejects addresses with shell metacharacters', () => {
    expect(() => sanitizeAddress('0x0;id')).toThrow();
  });
});
```

```typescript
// Integration test example (real r2)
import { describe, it, expect, afterEach } from 'vitest';
import { R2Session } from '../../src/r2/session';

describe('R2Session', () => {
  let session: R2Session;

  afterEach(async () => {
    await session?.close();
  });

  it('opens a binary and returns file info', async () => {
    session = await R2Session.open('tests/fixtures/hello-elf');
    const info = await session.cmdj<{ core: { file: string } }>('ij');
    expect(info.core.file).toContain('hello-elf');
  });
});
```

## Environment Setup

### Prerequisites

1. **Node.js** >= 20.x (LTS). Install via nvm or official installer.
2. **radare2** >= 5.8. Must be in PATH.
   - **Linux:** `git clone https://github.com/radareorg/radare2 && cd radare2 && sys/install.sh`
   - **macOS:** `brew install radare2`
   - **Windows:** Download from https://github.com/radareorg/radare2/releases or use `choco install radare2`
3. Verify: `r2 -v` should print the version.

### Project Setup

```bash
cd /path/to/radare2-mcp
npm install
npm run build
```

### Claude Desktop Configuration

Add to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "radare2": {
      "command": "node",
      "args": ["/path/to/radare2-mcp/dist/index.js"],
      "env": {
        "ALLOWED_DIRS": "/path/to/binaries"
      }
    }
  }
}
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `ALLOWED_DIRS` | (none) | Comma-separated list of directories from which binaries can be opened. If unset, any path is allowed. |
| `R2_ANALYSIS_LEVEL` | `aaa` | Default analysis command run after opening a binary (`aa`, `aaa`, `aaaa`). |
| `R2_COMMAND_TIMEOUT` | `30000` | Timeout in ms for individual r2 commands. |
| `RIZIN_PATH` | `C:/Program Files/rizin/bin/rizin.exe` (Win) or `rizin` | Path to rizin executable. |
| `RIZIN_COMMAND_TIMEOUT` | `30000` | Timeout in ms for individual Rizin commands. |

## Common Patterns

### Cached Session Pattern (static analysis tools)

```typescript
import { withCachedSession } from '../r2/session-cache.js';
import { sanitizePath } from '../r2/sanitize.js';
import { mcpError } from '../utils/errors.js';

export function registerMyTool(server: McpServer): void {
  server.tool('my_tool', 'Description here.', { /* Zod schema */ },
    async ({ binary_path }) => {
      const safePath = sanitizePath(binary_path);
      return withCachedSession(safePath, async (r2) => {
        // r2 session is cached -- no re-running aaa on repeated calls
        const data = await r2.cmdj<MyType[]>('somecmd');
        return mcpSuccess(data);
      });
    },
  );
}
```

### Debug Session Pattern

```typescript
import { debugManager } from '../r2/debug-session-manager.js';
import { sanitizeSessionId } from '../r2/sanitize.js';

// Launch: debugManager.launch(binaryPath) -> returns { sessionId, session, ... }
// Get:    debugManager.get(sessionId) -> returns { session, ... }
// Detach: debugManager.detach(sessionId)
// List:   debugManager.list()
```

### ESIL Session Pattern

```typescript
import { esilManager } from '../r2/esil-session-manager.js';

// Create: esilManager.create(binaryPath, { address, stackAddress, stackSize }) -> { sessionId, session }
// Get:    esilManager.get(sessionId) -> { session, ... }
// Destroy: esilManager.destroy(sessionId)
// List:   esilManager.list()
```

### Paginating Results

```typescript
import { paginate } from '../utils/pagination.js';

const page = paginate(allItems, offset, limit);
// Returns { results: T[], total: number, offset: number, limit: number }
```

### Formatting MCP Responses

```typescript
import { mcpSuccess, mcpFormatted, mcpError } from '../utils/errors.js';

return mcpSuccess(data);           // JSON-serialized response
return mcpFormatted(markdownText); // Pre-formatted markdown
return mcpError('Something failed'); // { isError: true, content: [{ text: "Error: ..." }] }
```

### Shared Utilities

```typescript
import { isConditionalJump, stripImportPrefix } from '../utils/shared-helpers.js';
import { detectMitigations } from '../utils/mitigations.js';
import { writeTempBinary, cleanupTempFile } from '../utils/temp-files.js';

// formatXxx() functions in utils/formatters.ts for every tool type
import { formatFunctions, formatStrings, formatBreakpoints, ... } from '../utils/formatters.js';
```

### Tool Registration Boilerplate

```typescript
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { withCachedSession } from '../r2/session-cache.js';
import { sanitizePath } from '../r2/sanitize.js';
import { paginate } from '../utils/pagination.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatStrings } from '../utils/formatters.js';
import { listStrings as r2ListStrings } from '../r2/commands.js';

export function registerListStrings(server: McpServer): void {
  server.tool(
    'list_strings',
    'Extract printable strings from the binary with their addresses and sections.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      min_length: z.number().int().min(1).default(5).describe('Minimum string length'),
      offset: z.number().int().min(0).default(0),
      limit: z.number().int().min(1).max(2000).default(100),
    },
    async ({ binary_path, min_length, offset, limit }) => {
      const safePath = sanitizePath(binary_path);
      return withCachedSession(safePath, async (r2) => {
        const strings = await r2ListStrings(r2);
        const filtered = strings.filter((s) => s.length >= min_length);
        const page = paginate(filtered, offset, limit);
        return mcpFormatted(formatStrings(page));
      });
    },
  );
}
```

---

## Complete Tool List (69 tools)

### Binary Analysis (19 tools)

| # | Tool Name | Description | r2 Commands |
|---|---|---|---|
| 1 | `analyze_binary` | Open and analyze a binary file, returning architecture, platform, entry point, and binary metadata as JSON. | `ij`, `iIj`, `aaa` |
| 2 | `list_functions` | List all functions identified by radare2 analysis with their names, addresses, sizes, and call conventions. | `aflj` |
| 3 | `disassemble` | Disassemble instructions at the given address or function, returning assembly with opcodes and metadata. | `pdfj`, `pdj` |
| 4 | `decompile_function` | Decompile a function to pseudo-C representation using the available decompiler backend. | `pdc`, `pdg` |
| 5 | `list_strings` | Extract printable strings from the binary with their addresses, sections, and lengths. | `izj`, `izzj` |
| 6 | `get_xrefs` | Get all cross-references to or from a specific address, identifying callers, callees, and data references. | `axtj`, `axfj` |
| 7 | `list_imports` | List all imported functions and symbols with their addresses and library origins. | `iij` |
| 8 | `list_exports` | List all exported functions and symbols with their addresses and types. | `iEj` |
| 9 | `list_sections` | List all sections and segments in the binary with addresses, sizes, and permissions. | `iSj` |
| 10 | `read_bytes` | Read raw bytes from a specific address in the binary, returned as hex string or formatted hexdump. | `pxj`, `px` |
| 11 | `rename_function` | Rename a function at the given address to a new user-defined name. | `afn` |
| 12 | `add_comment` | Add or update a comment at a specific address in the binary. | `CCu base64:` |
| 13 | `get_function_info` | Get detailed metadata for a single function including cyclomatic complexity, stack frame, args, locals, and basic block count. | `afij` |
| 14 | `list_variables` | List all local variables, stack variables, and arguments of a function. | `afvj` |
| 15 | `write_bytes` | Patch bytes at a specific address in the binary using hex bytes or assembly instructions. | `wx`, `wa` |
| 16 | `find_crypto_constants` | Detect cryptographic constants (AES S-boxes, CRC tables, RSA constants, SHA magic numbers) in the binary. | `/ca`, `/caj` |
| 17 | `list_resources` | List PE resources (icons, manifests, version info, embedded data) from the binary. | `iRj` |
| 18 | `list_relocations` | List all relocation entries in the binary with their addresses, types, and symbol names. | `irj` |
| 19 | `list_classes` | List all classes and their methods found in the binary (C++, ObjC, Java, etc.). | `icj` |

### Advanced Analysis (10 tools)

| # | Tool Name | Description | r2 Commands |
|---|---|---|---|
| 20 | `triage_binary` | Perform comprehensive one-shot binary triage: file info, sections, imports, exports, strings, functions, entry points, and security features in a single call. | `ij`, `iIj`, `iSj`, `iij`, `iEj`, `izj`, `aflj` |
| 21 | `analyze_function_deep` | Deep single-function analysis: disassembly, decompilation, variables, xrefs, callers, callees, strings, and complexity metrics in one call. | `afij`, `pdfj`, `pdc`, `afvj`, `axtj`, `axfj` |
| 22 | `find_constraints` | Extract comparisons, conditional branches, string references, and success/fail paths from a function -- ideal for crackme and CTF challenge analysis. | `pdfj`, `izj`, `axtj` |
| 23 | `trace_execution` | Trace execution using ESIL emulation, logging comparisons, branches, memory access, and register changes at each step. | `aei`, `aeim`, `aepc`, `aes`, `aerj` |
| 24 | `find_vulnerabilities` | Scan a binary for common vulnerability patterns: dangerous API usage, buffer overflows, format strings, integer overflows, and missing bounds checks. | `iij`, `axtj`, `pdc` |
| 25 | `solve_crackme` | Automatically attempt to solve a crackme by extracting constraints, identifying success/fail paths, and brute-forcing input character by character using ESIL emulation. | `aei`, `aeim`, `aepc`, `aes`, `aerj`, `ae` |
| 26 | `extract_iocs` | Extract Indicators of Compromise from a binary: IP addresses, URLs, domains, file paths, registry keys, email addresses, crypto wallets, and embedded payloads. | `izj`, `izzj`, `axtj` |
| 27 | `exploit_hunter` | Exploit development assistant: analyze security mitigations, find dangerous functions, collect ROP gadgets, map input sources, and suggest exploitation strategies. | `iIj`, `iij`, `axtj`, `/Rj` |
| 28 | `diff_binaries` | Compare two binary versions: find added, removed, and changed functions, imports, strings, and show instruction-level diffs for modified functions. | `aflj`, `iij`, `izj`, `pdfj` |
| 29 | `file_format_analyzer` | Analyze binary file format structures: identify format via magic bytes, parse containers (RIFF/WebP, PNG, ZIP, JPEG, PDF), and show chunk hierarchy with offsets, sizes, and metadata. | `px`, magic bytes parsing |

### ESIL Emulation (10 tools)

| # | Tool Name | Description | r2 Commands |
|---|---|---|---|
| 30 | `esil_init` | Initialize the ESIL virtual machine with stack memory, preparing it for emulation from a specified address. | `aei`, `aeim`, `aepc`, `aeip` |
| 31 | `esil_destroy` | Destroy an ESIL session and close the underlying r2 process. | session close |
| 32 | `esil_list_sessions` | List all active ESIL emulation sessions with their IDs, targets, and creation times. | manager query |
| 33 | `esil_step` | Execute a single instruction step in the ESIL emulator and return the updated register state. | `aes`, `aeso`, `aerj` |
| 34 | `esil_run` | Run ESIL emulation until a target address is reached, a breakpoint is hit, or maximum steps are exceeded. | `aes`, `aerj` |
| 35 | `esil_get_registers` | Read all register values or a specific register from the ESIL virtual machine state. | `aerj`, `aer` |
| 36 | `esil_set_register` | Set a register value in the ESIL virtual machine to a specified value. | `aer` |
| 37 | `esil_get_memory` | Read memory contents from the ESIL emulated memory space at a given address. | `pxj`, `ps`, `px` |
| 38 | `esil_set_memory` | Write data to the ESIL emulated memory space at a given address. | `wx`, `w` |
| 39 | `esil_expression` | Evaluate a raw ESIL expression string and return the result, useful for manual stack manipulation and computation. | `ae` |

### Shellcode & Search (9 tools)

| # | Tool Name | Description | r2 Commands |
|---|---|---|---|
| 40 | `shellcode_analyze` | Analyze raw shellcode bytes by loading them as a memory blob, disassembling, and identifying syscalls and patterns. | temp file + `aaa`, `pdfj` |
| 41 | `disassemble_bytes` | Disassemble raw bytes into assembly instructions without loading a full binary. | `rasm2` / `pad` |
| 42 | `search_bytes` | Search for a hex byte pattern across the binary and return all matching addresses. | `/xj` |
| 43 | `search_string` | Search for a string pattern in the binary and return all matching locations. | `/ query` |
| 44 | `search_rop_gadgets` | Search for ROP gadgets in the binary matching optional instruction constraints. | `/Rj`, `/R query` |
| 45 | `get_callgraph` | Get the call graph for a function showing all callers and callees as a structured graph. | `agCj`, `agCd`, `agCm` |
| 46 | `get_control_flow_graph` | Get the control flow graph of a function as a JSON structure with basic blocks and edges. | `agfj` |
| 47 | `r2_command` | Execute a radare2 command directly and return the raw output. Only safe commands from an allowlist are permitted. | allowlisted commands |
| 48 | `get_entropy` | Calculate entropy for the binary or specific sections to detect packed or encrypted regions. | `p=ej` |

### Debug Tools (18 tools)

| # | Tool Name | Description | r2 Commands |
|---|---|---|---|
| 49 | `debug_launch` | Launch a binary under the radare2 debugger and return a persistent session ID for subsequent debug commands. | `r2 -d`, `dij` |
| 50 | `debug_attach` | Attach the radare2 debugger to a running process by PID and return a persistent session ID. | `dbg://PID` |
| 51 | `debug_detach` | Detach from the debugged process, leaving it running, and close the debug session. | `dd` |
| 52 | `debug_set_breakpoint` | Set a software breakpoint at the specified address in the debugged process. | `db`, `dbH` |
| 53 | `debug_remove_breakpoint` | Remove a breakpoint at the specified address or remove all breakpoints. | `db-`, `db-*` |
| 54 | `debug_list_breakpoints` | List all active breakpoints in the debug session with their addresses and status. | `dbj` |
| 55 | `debug_continue` | Continue execution of the debugged process until a breakpoint is hit, an address is reached, or the process exits. | `dc`, `dcu` |
| 56 | `debug_step` | Single-step the debugged process (step into or step over) and return the updated register state. | `ds`, `dso`, `drj` |
| 57 | `debug_get_registers` | Read all register values or a specific register from the debugged process. | `drj`, `dr` |
| 58 | `debug_set_register` | Set a register value in the debugged process. | `dr` |
| 59 | `debug_get_maps` | List memory maps of the debugged process with addresses, sizes, and permissions. | `dmj` |
| 60 | `debug_get_backtrace` | Get the call stack backtrace of the debugged process. | `dbtj` |
| 61 | `debug_get_threads` | List all threads in the debugged process with their status. | `dptj` |
| 62 | `debug_get_info` | Get debug session information including PID, status, executable path, and command line. | `dij` |
| 63 | `debug_read_memory` | Read memory from the debugged process at a specific address, returned as hex string or formatted hexdump. | `pxj`, `px` |
| 64 | `debug_write_memory` | Write data to memory in the debugged process at a specific address. | `wx`, `w` |
| 65 | `debug_kill` | Kill the debugged process and clean up the debug session. | `dk 9` |
| 66 | `debug_list_sessions` | List all active debug sessions with their session IDs, targets, and PIDs. | manager query |

### Type, Header & Hash Tools (3 tools)

| # | Tool Name | Description | r2 Commands |
|---|---|---|---|
| 67 | `analyze_types` | List type definitions (structs, unions, enums, typedefs) discovered or loaded in the binary. | `tj`, `tsj`, `tej` |
| 68 | `binary_headers` | List PE/ELF/Mach-O header fields and their values. | `ihj` |
| 69 | `hash_binary` | Compute hash digests (MD5, SHA1, SHA256, CRC32) for the binary or a specific address range. | `rahash2` / `ph` |

---

## Reference: Binary Ninja MCP

> Full analysis: `docs/binja-mcp-reference.md`
> Repository: https://github.com/fosdickio/binary_ninja_mcp

The Binary Ninja MCP server (Python, FastMCP SDK) is our gold-standard reference. Key takeaways that shaped this project's design:

### What we adopted from BinaryNinja MCP

1. **Tool naming:** `snake_case` with verb prefixes (`list_`, `get_`, `analyze_`, `decompile_`, `disassemble_`, `rename_`, `add_`, `read_`, `search_`)
2. **Description style:** Single sentence, starts with a verb, states what is returned. No filler words.
3. **Address parameters as strings:** Hex strings (`"0x08048000"`), never numbers. JSON cannot represent 64-bit hex literals.
4. **Flexible function lookup:** Accept both `function_name` and `address` to identify a function.
5. **JSON returns:** All tools return structured JSON, never raw text.

### Where we improve over BinaryNinja MCP

| Area | BinaryNinja MCP | Our r2 MCP |
|---|---|---|
| **Tool count** | ~13 tools | 69 tools across 6 categories |
| **Pagination** | None -- returns all results | `offset`/`limit` on every list tool |
| **Error handling** | `{"error": "..."}` in body | MCP-standard `isError: true` flag |
| **Input validation** | Python type hints only | Zod schemas with regex validation |
| **Session lifecycle** | Re-opens binary every call | Cached sessions (5-min TTL), persistent debug/ESIL sessions |
| **Timeouts** | None | 30s default per r2 command |
| **Security** | No path validation | `ALLOWED_DIRS`, symlink resolution, shell-metachar rejection, base64 comments, search query sanitization |
| **Architecture** | Monolithic (all tools in one file) | 3-layer (transport / tools / r2) |
| **Output format** | Raw JSON | Markdown-formatted tables via formatters |
| **Debugging** | None | Full debugger integration (18 tools) |
| **Emulation** | None | ESIL VM with persistent sessions (10 tools) |

### r2-exclusive tools (no BinaryNinja equivalent)

| Tool | Why it matters |
|---|---|
| `esil_*` (10 tools) | r2's ESIL is a unique lightweight emulator -- no equivalent in BinaryNinja MCP |
| `debug_*` (18 tools) | Full debugger integration with persistent sessions |
| `shellcode_analyze` | Open raw bytes as blob, analyze without binary headers |
| `r2_command` | Sanitized escape hatch for power users; BinaryNinja has no CLI equivalent |
| `search_rop_gadgets` | Built-in ROP gadget finder (`/R`) -- security research essential |
| `search_bytes` | Byte pattern search (`/x`) across the binary |
| `search_string` | String pattern search across the binary |
| `get_entropy` | Entropy analysis for packer detection (`p=ej`) |
| `get_control_flow_graph` | JSON CFG output (`agfj`) |
| `triage_binary` | One-shot comprehensive triage |
| `find_vulnerabilities` | Automated vulnerability scanning |
| `solve_crackme` | Automated crackme solver via ESIL |
| `extract_iocs` | IOC extraction for malware analysis |
| `exploit_hunter` | Exploit development assistant |
| `diff_binaries` | Binary version diffing |
| `file_format_analyzer` | File format structure parsing |
| `analyze_types` | Type definition analysis |
| `binary_headers` | Header field extraction |
| `hash_binary` | File hash computation |

### Tool mapping (BinaryNinja -> r2)

| BinaryNinja Tool | r2 MCP Tool | r2 Commands |
|---|---|---|
| `analyze_binary` | `analyze_binary` | `ij`, `iIj`, `aaa` |
| `list_functions` | `list_functions` | `aflj` |
| `decompile_function` | `decompile_function` | `pdc`, `pdg` |
| `disassemble_function` | `disassemble` | `pdfj`, `pdj` |
| `list_strings` | `list_strings` | `izj`, `izzj` |
| `get_cross_references` | `get_xrefs` | `axtj`, `axfj` |
| `get_imports` | `list_imports` | `iij` |
| `get_exports` | `list_exports` | `iEj` |
| `get_sections` | `list_sections` | `iSj` |
| `read_bytes` | `read_bytes` | `pxj`, `px` |
| `rename_function` | `rename_function` | `afn` |
| `add_comment` | `add_comment` | `CCu base64:` |
| `get_callgraph` | `get_callgraph` | `agCj`, `agCd`, `agCm` |
