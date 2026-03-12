# radare2-mcp

MCP server exposing radare2 and Rizin binary analysis capabilities. Provides 85 tools covering static analysis, disassembly, decompilation, ESIL emulation, live debugging, vulnerability scanning, and exploit development -- all through structured JSON responses over the Model Context Protocol.

## What it does

### Static Analysis (19 tools)
Open binaries, list functions/imports/exports/strings/sections/classes, disassemble and decompile functions, read/write bytes, rename functions, add comments, find crypto constants, list PE resources and relocations.

### Advanced Analysis (10 tools)
One-shot binary triage, deep single-function analysis, constraint extraction for crackmes, ESIL execution tracing, automated vulnerability pattern scanning, crackme solver, IOC extraction, exploit development assistant, binary diffing, file format parsing.

### ESIL Emulation (10 tools)
Persistent ESIL VM sessions with register/memory read-write, single-step and run-to-address, raw ESIL expression evaluation. State is preserved across tool calls for multi-step emulation workflows.

### RzIL Emulation (16 Rizin-based tools)
Typed bitvector emulation via Rizin's RzIL backend. IL AST lifting, individual CPU flag access, calling convention analysis, enhanced type and symbol queries.

### Live Debugging (18 tools)
Launch or attach to processes, set/remove breakpoints, continue/step execution, read/write registers and memory, inspect memory maps, threads, and backtraces. Persistent debug sessions survive across tool calls.

### Search & Navigation (9 tools)
Byte pattern search, string search, ROP gadget search, call graph and control flow graph extraction, entropy analysis, raw r2 command execution (allowlisted).

## Requirements

- Node.js 20+
- [radare2](https://github.com/radareorg/radare2) >= 5.8 installed and in PATH
- [Rizin](https://rizin.re/) >= 0.8 (optional, for RzIL tools)

## Setup

```bash
npm install
npm run build
node dist/index.js
```

Or during development:

```bash
npm run dev
```

### MCP client configuration

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

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `ALLOWED_DIRS` | (none) | Comma-separated directories from which binaries can be opened. Unrestricted if unset. |
| `R2_ANALYSIS_LEVEL` | `aaa` | Analysis command run after opening a binary. |
| `R2_COMMAND_TIMEOUT` | `30000` | Timeout in ms for individual r2 commands. |
| `RIZIN_PATH` | `rizin` | Path to the Rizin executable. |
| `RIZIN_COMMAND_TIMEOUT` | `30000` | Timeout in ms for individual Rizin commands. |

## Architecture

```
radare2/
  src/
    index.ts             # Entry point, stdio transport, shutdown handlers
    server.ts            # MCP server setup, registers all tools
    types.ts             # Shared TypeScript interfaces and Zod schemas
    r2/
      session.ts         # r2pipe wrapper
      session-cache.ts   # Session reuse across tool calls (avoids re-running aaa)
      commands.ts        # Typed wrappers around r2 commands
      sanitize.ts        # Input validation for paths, addresses, commands
      debug-session-manager.ts
      esil-session-manager.ts
    rizin/
      rizin-session.ts   # Rizin process management (newline cmd, null-byte response)
      rzil-session-manager.ts
    tools/               # 85 tool files, one per tool
    utils/               # Error helpers, formatters, pagination
  tests/
    unit/                # Mocked tests, no radare2 needed
    integration/         # Requires r2 in PATH
```

Three session patterns: cached sessions for static analysis (reused across calls, 5-min TTL), persistent debug sessions (UUID-identified, survive across calls), persistent ESIL/RzIL sessions (same pattern, for emulation state).

All user input is validated through `sanitize.ts` before being passed to r2. Binary paths are checked against `ALLOWED_DIRS` with symlink resolution. The `r2_command` tool restricts commands to a safe allowlist.

## Security

- No arbitrary command execution -- `r2_command` uses an allowlist
- Path validation with symlink resolution and `ALLOWED_DIRS` enforcement
- Comments are base64-encoded to prevent r2 command injection
- Search queries are sanitized against shell metacharacters
- Local only -- r2pipe spawns local processes, MCP runs over stdio

## License

CC BY-NC-SA 4.0 -- see [LICENSE](LICENSE).
