# Radare2 MCP Server -- Architektur

## 1. Uebersicht

### 1.1 Zweck

Der Radare2 MCP Server stellt die Reverse-Engineering-Faehigkeiten von radare2 als
Model Context Protocol (MCP) Server bereit. Damit koennen LLMs direkt Binaeranalysen
durchfuehren, Shellcode untersuchen, ESIL-basierte Code-Emulation ausfuehren und
radare2-Befehle ueber r2pipe absetzen.

### 1.2 High-Level Architektur

```
+------------------------------------------------------------------+
|                        MCP Host                                  |
|  (Claude Desktop / Claude Code / VS Code / Custom Client)        |
+-------------------------------+----------------------------------+
                                |
                          JSON-RPC 2.0
                          (stdio / SSE)
                                |
+-------------------------------v----------------------------------+
|                     Radare2 MCP Server                           |
|  +------------------------------------------------------------+ |
|  |                   Transport Layer                           | |
|  |              (StdioServerTransport / SSE)                   | |
|  +-----------------------------+------------------------------+ |
|                                |                                 |
|  +-----------------------------v------------------------------+ |
|  |                  MCP Protocol Handler                       | |
|  |         (McpServer - Tool Registration & Dispatch)          | |
|  +----+----------+----------+----------+---------------------+ |
|       |          |          |          |                        |
|  +----v---+ +----v---+ +---v----+ +---v------------------+    |
|  | Binary | | ESIL   | | Shell- | | R2 Command           |    |
|  | Analy- | | Engine | | code   | | Executor             |    |
|  | sis    | | Wrap-  | | Analy- | | (Raw r2pipe)         |    |
|  | Module | | per    | | zer    | |                      |    |
|  +----+---+ +---+----+ +---+----+ +---+------------------+    |
|       |         |           |          |                        |
|  +----v---------v-----------v----------v---------------------+ |
|  |              R2 Session Manager                            | |
|  |         (r2pipe Lifecycle & Pool Management)               | |
|  +-----------------------------+------------------------------+ |
|                                |                                 |
+--------------------------------+---------------------------------+
                                 |
                           r2pipe (spawn)
                                 |
                    +------------v-----------+
                    |      radare2 (r2)      |
                    |   Binary Analysis      |
                    |   Disassembler          |
                    |   ESIL VM              |
                    |   Debugger             |
                    +------------------------+
```

### 1.3 Technologie-Stack

| Komponente          | Technologie                              |
|---------------------|------------------------------------------|
| Sprache             | TypeScript (ES2022, Node16 Module)       |
| MCP SDK             | @modelcontextprotocol/sdk                |
| r2 Kommunikation    | r2pipe (npm: r2pipe)                     |
| Schema-Validierung  | zod@3                                    |
| Build-System        | tsc (TypeScript Compiler)                |
| Runtime             | Node.js >= 18                            |
| Linter              | ESLint + Prettier                        |
| Test-Framework      | Vitest                                   |

### 1.4 Kommunikationsfluss

```
LLM (Claude)                MCP Client              MCP Server            radare2
    |                           |                        |                    |
    |-- "Analysiere binary" --->|                        |                    |
    |                           |-- tools/list --------->|                    |
    |                           |<-- Tool-Definitionen --|                    |
    |                           |                        |                    |
    |                           |-- tools/call ---------->|                   |
    |                           |   "analyze_binary"     |                    |
    |                           |   {path: "/bin/ls"}    |                    |
    |                           |                        |-- r2pipe.open() -->|
    |                           |                        |-- "aaa" ---------->|
    |                           |                        |<-- Analysis OK ----|
    |                           |                        |-- "aflj" --------->|
    |                           |                        |<-- JSON Functions -|
    |                           |                        |-- "quit" --------->|
    |                           |<-- Tool Result --------|                    |
    |<-- Analyseergebnis -------|                        |                    |
```

---

## 2. Projekt-Struktur

```
radare2-mcp/
|
|-- package.json                    # Projekt-Metadaten, Dependencies, Scripts
|-- tsconfig.json                   # TypeScript-Konfiguration
|-- .eslintrc.json                  # Linter-Konfiguration
|-- .prettierrc                     # Code-Formatierung
|-- .env.example                    # Beispiel-Umgebungsvariablen
|
|-- src/
|   |-- index.ts                    # Entry Point - Server-Bootstrap
|   |
|   |-- server/
|   |   |-- mcp-server.ts           # MCP Server Setup & Tool-Registrierung
|   |   +-- transport.ts            # Transport-Layer Konfiguration
|   |
|   |-- core/
|   |   |-- session-manager.ts      # R2 Session Pool & Lifecycle
|   |   |-- r2-command.ts           # Typisierte r2-Befehlsausfuehrung
|   |   +-- types.ts                # Gemeinsame TypeScript-Typen
|   |
|   |-- tools/
|   |   |-- binary-analysis.ts      # Binary-Analyse Tools
|   |   |-- esil-emulation.ts       # ESIL Emulation Tools
|   |   |-- shellcode-analysis.ts   # Shellcode-Analyse Tools
|   |   |-- r2-command-tools.ts     # Generische r2-Befehlsausfuehrung
|   |   +-- index.ts                # Tool-Registry (Re-Exports)
|   |
|   |-- analyzers/
|   |   |-- shellcode-detector.ts   # Shellcode-Pattern-Erkennung
|   |   |-- syscall-analyzer.ts     # Syscall-Analyse
|   |   |-- crypto-detector.ts      # Kryptographische Pattern-Erkennung
|   |   +-- rop-analyzer.ts         # ROP-Gadget-Analyse
|   |
|   |-- utils/
|   |   |-- logger.ts               # Logging (stderr fuer stdio-Transport)
|   |   |-- error-handler.ts        # Zentrales Error Handling
|   |   |-- sanitizer.ts            # Input-Sanitization fuer r2-Befehle
|   |   +-- config.ts               # Konfigurationsmanagement
|   |
|   +-- resources/
|       |-- binary-resource.ts      # MCP Resources fuer geoeffnete Binaerdateien
|       +-- session-resource.ts     # MCP Resources fuer aktive Sessions
|
|-- tests/
|   |-- unit/
|   |   |-- session-manager.test.ts
|   |   |-- shellcode-detector.test.ts
|   |   +-- sanitizer.test.ts
|   |-- integration/
|   |   |-- binary-analysis.test.ts
|   |   +-- esil-emulation.test.ts
|   +-- fixtures/
|       |-- test-binary               # Test-Binaerdateien
|       +-- shellcode-samples/        # Shellcode-Samples fuer Tests
|
|-- docs/
|   |-- architecture.md              # Dieses Dokument
|   +-- tool-reference.md            # API-Referenz aller Tools
|
+-- build/                           # Kompilierter JavaScript-Output
    +-- ...
```

### 2.1 Wichtige Dateien und deren Zweck

| Datei                          | Zweck                                                        |
|-------------------------------|--------------------------------------------------------------|
| `src/index.ts`                | Bootstrapping: Transport erstellen, Server starten           |
| `src/server/mcp-server.ts`    | Zentrale Tool-Registrierung, Capability-Deklaration          |
| `src/core/session-manager.ts` | r2pipe-Instanzen verwalten, Pools, Timeouts, Cleanup         |
| `src/tools/binary-analysis.ts`| Disassembly, Funktionsliste, Strings, Cross-References       |
| `src/tools/esil-emulation.ts` | ESIL-VM initialisieren, Stepping, Register lesen/schreiben   |
| `src/tools/shellcode-analysis.ts` | Shellcode-Erkennung, Emulation, Syscall-Extraktion       |
| `src/utils/sanitizer.ts`     | Schutz vor Command Injection in r2-Befehlen                  |

---

## 3. Kern-Komponenten

### 3.1 MCP Server (Entry Point)

Der Entry Point initialisiert den MCP Server, registriert alle Tools und startet
den Transport Layer.

**Datei: `src/index.ts`**

```typescript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { registerAllTools } from "./tools/index.js";
import { SessionManager } from "./core/session-manager.js";
import { Config } from "./utils/config.js";
import { logger } from "./utils/logger.js";

async function main(): Promise<void> {
  const config = Config.load();
  const sessionManager = new SessionManager(config);

  const server = new McpServer({
    name: "radare2-mcp",
    version: "1.0.0",
  });

  // Alle Tool-Module registrieren
  registerAllTools(server, sessionManager);

  // Transport starten
  const transport = new StdioServerTransport();
  await server.connect(transport);

  logger.info("Radare2 MCP Server laeuft auf stdio");

  // Graceful Shutdown
  process.on("SIGINT", async () => {
    logger.info("Shutting down...");
    await sessionManager.closeAll();
    process.exit(0);
  });
}

main().catch((error) => {
  logger.error("Fatal error:", error);
  process.exit(1);
});
```

**Datei: `src/server/mcp-server.ts`**

```typescript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SessionManager } from "../core/session-manager.js";
import { registerBinaryAnalysisTools } from "../tools/binary-analysis.js";
import { registerEsilTools } from "../tools/esil-emulation.js";
import { registerShellcodeTools } from "../tools/shellcode-analysis.js";
import { registerR2CommandTools } from "../tools/r2-command-tools.js";

export function registerAllTools(
  server: McpServer,
  sessionManager: SessionManager,
): void {
  registerBinaryAnalysisTools(server, sessionManager);
  registerEsilTools(server, sessionManager);
  registerShellcodeTools(server, sessionManager);
  registerR2CommandTools(server, sessionManager);
}
```

### 3.2 R2 Session Manager (r2pipe Lifecycle)

Der Session Manager ist die kritischste Komponente. Er verwaltet den Lebenszyklus
von r2pipe-Verbindungen und stellt sicher, dass Ressourcen korrekt freigegeben werden.

**Design-Entscheidungen:**
- **Ein r2pipe-Prozess pro geoeffneter Binaerdatei** -- radare2 ist nicht thread-safe,
  daher eine strikte 1:1-Zuordnung
- **Session-Pool mit Timeouts** -- Inaktive Sessions werden nach konfigurierbarer Zeit
  automatisch geschlossen
- **Mutex-artige Befehlsserialisierung** -- Verhindert Race Conditions bei parallelen
  Tool-Aufrufen auf derselben Session
- **Health Checks** -- Erkennt abgestuerzte r2-Prozesse und rauemt auf

**Datei: `src/core/session-manager.ts`**

```typescript
import r2pipe from "r2pipe";
import { logger } from "../utils/logger.js";
import { Config } from "../utils/config.js";

export interface R2Session {
  id: string;
  pipe: r2pipe.R2Pipe;
  filePath: string;
  createdAt: Date;
  lastUsedAt: Date;
  isAnalyzed: boolean;
  lock: Promise<void>;
  resolveLock: (() => void) | null;
}

export class SessionManager {
  private sessions: Map<string, R2Session> = new Map();
  private cleanupInterval: NodeJS.Timeout | null = null;
  private config: Config;

  constructor(config: Config) {
    this.config = config;
    this.startCleanupTimer();
  }

  /**
   * Oeffnet eine neue r2-Session oder gibt eine bestehende zurueck.
   * Wenn fuer den gleichen Pfad bereits eine Session existiert, wird
   * diese wiederverwendet.
   */
  async open(filePath: string, options?: R2OpenOptions): Promise<R2Session> {
    // Pruefen ob bereits eine Session existiert
    const existingSession = this.findByPath(filePath);
    if (existingSession) {
      existingSession.lastUsedAt = new Date();
      return existingSession;
    }

    // Neue Session erstellen
    const id = this.generateSessionId();

    try {
      const pipe = await this.openR2Pipe(filePath, options);
      const session: R2Session = {
        id,
        pipe,
        filePath,
        createdAt: new Date(),
        lastUsedAt: new Date(),
        isAnalyzed: false,
        lock: Promise.resolve(),
        resolveLock: null,
      };

      this.sessions.set(id, session);
      logger.info(`Session ${id} geoeffnet fuer: ${filePath}`);

      // Maximale Sessions pruefen
      if (this.sessions.size > this.config.maxSessions) {
        await this.evictOldestSession();
      }

      return session;
    } catch (error) {
      throw new Error(
        `Konnte r2 nicht oeffnen fuer ${filePath}: ${error}`,
      );
    }
  }

  /**
   * Fuehrt einen r2-Befehl auf einer Session aus.
   * Verwendet einen Lock, um sicherzustellen, dass immer nur
   * ein Befehl gleichzeitig auf einer Session ausgefuehrt wird.
   */
  async execute(sessionId: string, command: string): Promise<string> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Session ${sessionId} nicht gefunden`);
    }

    // Auf vorherigen Befehl warten (Mutex)
    await session.lock;

    // Neuen Lock setzen
    let resolveLock: () => void;
    session.lock = new Promise<void>((resolve) => {
      resolveLock = resolve;
    });

    try {
      session.lastUsedAt = new Date();
      const result = await this.executeWithTimeout(
        session.pipe,
        command,
        this.config.commandTimeout,
      );
      return result;
    } catch (error) {
      // Pruefen ob r2 abgestuerzt ist
      if (this.isProcessDead(error)) {
        logger.error(`r2-Prozess fuer Session ${sessionId} abgestuerzt`);
        this.sessions.delete(sessionId);
        throw new Error(
          "radare2-Prozess ist abgestuerzt. Bitte Session neu oeffnen.",
        );
      }
      throw error;
    } finally {
      resolveLock!();
    }
  }

  /**
   * Fuehrt einen r2-Befehl aus und parst das Ergebnis als JSON.
   */
  async executeJson<T>(sessionId: string, command: string): Promise<T> {
    const result = await this.execute(sessionId, command);
    try {
      return JSON.parse(result) as T;
    } catch {
      throw new Error(
        `r2-Befehl "${command}" lieferte kein gueltiges JSON: ${result.substring(0, 200)}`,
      );
    }
  }

  /**
   * Schliesst eine Session und den zugehoerigen r2-Prozess.
   */
  async close(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) return;

    try {
      await session.pipe.quit();
    } catch {
      logger.warn(`Fehler beim Schliessen von Session ${sessionId}`);
    }

    this.sessions.delete(sessionId);
    logger.info(`Session ${sessionId} geschlossen`);
  }

  /**
   * Schliesst alle Sessions (fuer Graceful Shutdown).
   */
  async closeAll(): Promise<void> {
    const closePromises = Array.from(this.sessions.keys()).map((id) =>
      this.close(id),
    );
    await Promise.allSettled(closePromises);
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
  }

  // --- Private Methoden ---

  private async openR2Pipe(
    filePath: string,
    options?: R2OpenOptions,
  ): Promise<r2pipe.R2Pipe> {
    return new Promise((resolve, reject) => {
      const flags = options?.flags ?? ["-2"]; // -2 = ohne stdin
      r2pipe.open(filePath, flags, (err: Error | null, pipe: r2pipe.R2Pipe) => {
        if (err) return reject(err);
        resolve(pipe);
      });
    });
  }

  private executeWithTimeout(
    pipe: r2pipe.R2Pipe,
    command: string,
    timeoutMs: number,
  ): Promise<string> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`Timeout nach ${timeoutMs}ms fuer: ${command}`));
      }, timeoutMs);

      pipe.cmd(command, (err: Error | null, result: string) => {
        clearTimeout(timer);
        if (err) return reject(err);
        resolve(result);
      });
    });
  }

  private startCleanupTimer(): void {
    this.cleanupInterval = setInterval(
      () => this.cleanupInactiveSessions(),
      60_000, // Jede Minute pruefen
    );
  }

  private async cleanupInactiveSessions(): Promise<void> {
    const now = Date.now();
    for (const [id, session] of this.sessions) {
      const inactiveMs = now - session.lastUsedAt.getTime();
      if (inactiveMs > this.config.sessionTimeout) {
        logger.info(
          `Session ${id} inaktiv seit ${Math.floor(inactiveMs / 1000)}s, schliesse...`,
        );
        await this.close(id);
      }
    }
  }

  private async evictOldestSession(): Promise<void> {
    let oldest: R2Session | null = null;
    for (const session of this.sessions.values()) {
      if (!oldest || session.lastUsedAt < oldest.lastUsedAt) {
        oldest = session;
      }
    }
    if (oldest) {
      await this.close(oldest.id);
    }
  }

  private findByPath(filePath: string): R2Session | undefined {
    for (const session of this.sessions.values()) {
      if (session.filePath === filePath) return session;
    }
    return undefined;
  }

  private isProcessDead(error: unknown): boolean {
    if (error instanceof Error) {
      return (
        error.message.includes("EPIPE") ||
        error.message.includes("EOF") ||
        error.message.includes("killed") ||
        error.message.includes("ECONNRESET")
      );
    }
    return false;
  }

  private generateSessionId(): string {
    return `r2_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
  }
}

export interface R2OpenOptions {
  flags?: string[];
}
```

**Session-Lebenszyklus:**

```
                open()
                  |
                  v
    +----------------------------+
    |     SESSION CREATED        |
    |  - r2pipe.open(file)       |
    |  - id zugewiesen           |
    |  - in Pool registriert     |
    +-------------+--------------+
                  |
                  v
    +----------------------------+
    |     SESSION ACTIVE         |<---+
    |  - execute() moeglich      |    |
    |  - lastUsedAt aktualisiert |    |  execute()
    |  - Lock-basierte Mutex     |----+
    +------+----------+----------+
           |          |
     Timeout      close()
           |          |
           v          v
    +----------------------------+
    |     SESSION CLOSING        |
    |  - pipe.quit()             |
    |  - aus Pool entfernt       |
    |  - Ressourcen freigegeben  |
    +----------------------------+
```

### 3.3 ESIL Engine Wrapper

ESIL (Evaluable Strings Intermediate Language) ist die IL (Intermediate Language) von
radare2 fuer Code-Emulation. Der Wrapper stellt eine High-Level-API ueber die
rohen ESIL-Befehle bereit.

**Wichtige radare2 ESIL-Befehle:**

| Befehl  | Beschreibung                                          |
|---------|-------------------------------------------------------|
| `aei`   | ESIL VM initialisieren                                |
| `aeim`  | ESIL-Stack-Memory allokieren                          |
| `aeip`  | Program Counter auf Entry Point setzen                |
| `aes`   | Einzelnen ESIL-Schritt ausfuehren (Step Into)         |
| `aeso`  | Step Over (ueberspringt Calls)                        |
| `aesu`  | Step Until (Adresse)                                  |
| `aecu`  | Continue Until (Adresse)                              |
| `aer`   | ESIL-Register lesen                                   |
| `aer=`  | Register-Werte als Tabelle anzeigen                   |
| `aerR`  | Register-Referenzen anzeigen                          |
| `ae`    | ESIL-Expression direkt auswerten                      |
| `aets+` | ESIL-Trace beginnen                                   |
| `aets-` | ESIL-Trace beenden                                    |
| `aep`   | ESIL-Breakpoint setzen                                |
| `aef`   | Ganze Funktion emulieren                              |
| `aei-`  | ESIL VM zuruecksetzen/beenden                         |

**Datei: `src/tools/esil-emulation.ts`**

```typescript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { SessionManager } from "../core/session-manager.js";
import { logger } from "../utils/logger.js";

export function registerEsilTools(
  server: McpServer,
  sessionManager: SessionManager,
): void {

  // --- ESIL VM initialisieren ---
  server.registerTool(
    "esil_init",
    {
      title: "ESIL VM Initialisieren",
      description:
        "Initialisiert die ESIL Virtual Machine fuer eine geoeffnete " +
        "Binary. Allokiert Stack-Memory und setzt den Program Counter " +
        "auf den Entry Point. Muss vor allen anderen ESIL-Operationen " +
        "aufgerufen werden.",
      inputSchema: {
        sessionId: z.string().describe("ID der r2-Session"),
        stackSize: z
          .number()
          .optional()
          .default(0x00100000)
          .describe("Stack-Groesse in Bytes (Standard: 1MB)"),
        stackAddr: z
          .number()
          .optional()
          .default(0x00100000)
          .describe("Stack-Basisadresse (Standard: 0x100000)"),
      },
    },
    async ({ sessionId, stackSize, stackAddr }) => {
      try {
        // ESIL VM initialisieren
        await sessionManager.execute(sessionId, "aei");
        // Stack-Memory allokieren
        await sessionManager.execute(
          sessionId,
          `aeim ${stackAddr} ${stackSize}`,
        );
        // Program Counter auf Entry Point setzen
        await sessionManager.execute(sessionId, "aeip");
        // Initiale Register lesen
        const registers = await sessionManager.execute(sessionId, "aerj");

        return {
          content: [
            {
              type: "text" as const,
              text: `ESIL VM initialisiert.\n\nRegister:\n${registers}`,
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Fehler bei ESIL-Initialisierung: ${error}`,
            },
          ],
          isError: true,
        };
      }
    },
  );

  // --- Einzelschritt-Emulation ---
  server.registerTool(
    "esil_step",
    {
      title: "ESIL Step",
      description:
        "Fuehrt einen oder mehrere ESIL-Schritte aus (Step Into). " +
        "Zeigt nach dem Stepping die aktuellen Registerwerte an.",
      inputSchema: {
        sessionId: z.string().describe("ID der r2-Session"),
        count: z
          .number()
          .optional()
          .default(1)
          .describe("Anzahl der Schritte (Standard: 1)"),
        stepOver: z
          .boolean()
          .optional()
          .default(false)
          .describe("Step Over statt Step Into (ueberspringt Calls)"),
      },
    },
    async ({ sessionId, count, stepOver }) => {
      const stepCmd = stepOver ? "aeso" : "aes";
      const results: string[] = [];

      for (let i = 0; i < count; i++) {
        await sessionManager.execute(sessionId, stepCmd);
        // Aktuelle Instruktion holen
        const currentInstr = await sessionManager.execute(sessionId, "pdj 1");
        results.push(currentInstr);
      }

      const registers = await sessionManager.execute(sessionId, "aerj");

      return {
        content: [
          {
            type: "text" as const,
            text:
              `${count}x ${stepOver ? "Step Over" : "Step Into"} ausgefuehrt.\n\n` +
              `Letzte Instruktion:\n${results[results.length - 1]}\n\n` +
              `Register:\n${registers}`,
          },
        ],
      };
    },
  );

  // --- Continue Until ---
  server.registerTool(
    "esil_continue_until",
    {
      title: "ESIL Continue Until",
      description:
        "Emuliert Code bis eine bestimmte Adresse erreicht wird. " +
        "Nuetzlich um schnell zu einem bestimmten Punkt im Code zu gelangen.",
      inputSchema: {
        sessionId: z.string().describe("ID der r2-Session"),
        address: z
          .string()
          .describe("Zieladresse in Hex (z.B. '0x00401000')"),
      },
    },
    async ({ sessionId, address }) => {
      try {
        await sessionManager.execute(sessionId, `aecu ${address}`);
        const registers = await sessionManager.execute(sessionId, "aerj");
        const currentInstr = await sessionManager.execute(sessionId, "pdj 1");

        return {
          content: [
            {
              type: "text" as const,
              text:
                `Emulation bis ${address} ausgefuehrt.\n\n` +
                `Aktuelle Instruktion:\n${currentInstr}\n\n` +
                `Register:\n${registers}`,
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Fehler bei Continue Until: ${error}`,
            },
          ],
          isError: true,
        };
      }
    },
  );

  // --- Register lesen/schreiben ---
  server.registerTool(
    "esil_registers",
    {
      title: "ESIL Register",
      description:
        "Liest oder schreibt ESIL-Register. Ohne Wert werden alle " +
        "Register gelesen. Mit Wert wird ein spezifisches Register gesetzt.",
      inputSchema: {
        sessionId: z.string().describe("ID der r2-Session"),
        register: z
          .string()
          .optional()
          .describe("Name des Registers (z.B. 'rax', 'eip', 'rsp')"),
        value: z
          .string()
          .optional()
          .describe("Neuer Wert fuer das Register (Hex)"),
      },
    },
    async ({ sessionId, register, value }) => {
      if (register && value) {
        await sessionManager.execute(sessionId, `aer ${register}=${value}`);
        return {
          content: [
            {
              type: "text" as const,
              text: `Register ${register} auf ${value} gesetzt.`,
            },
          ],
        };
      }

      const result = await sessionManager.execute(sessionId, "aerj");
      return {
        content: [
          {
            type: "text" as const,
            text: `Register:\n${result}`,
          },
        ],
      };
    },
  );

  // --- ESIL Expression auswerten ---
  server.registerTool(
    "esil_eval",
    {
      title: "ESIL Expression Evaluieren",
      description:
        "Wertet eine ESIL-Expression direkt aus. ESIL ist eine " +
        "Reverse-Polish-Notation-basierte IL. Beispiel: '1,2,+' ergibt 3. " +
        "Nuetzlich fuer manuelle Berechnungen im ESIL-Kontext.",
      inputSchema: {
        sessionId: z.string().describe("ID der r2-Session"),
        expression: z
          .string()
          .describe("ESIL-Expression (z.B. '1,2,+' oder 'rax,rbx,+,rcx,=')"),
      },
    },
    async ({ sessionId, expression }) => {
      const result = await sessionManager.execute(
        sessionId,
        `ae ${expression}`,
      );
      const registers = await sessionManager.execute(sessionId, "aerj");

      return {
        content: [
          {
            type: "text" as const,
            text:
              `ESIL Expression ausgewertet: ${expression}\n\n` +
              `Ergebnis: ${result}\n\n` +
              `Register nach Auswertung:\n${registers}`,
          },
        ],
      };
    },
  );

  // --- Funktion emulieren ---
  server.registerTool(
    "esil_emulate_function",
    {
      title: "ESIL Funktion Emulieren",
      description:
        "Emuliert eine gesamte Funktion mittels ESIL. Zeichnet dabei " +
        "den Trace auf und gibt Register-Aenderungen zurueck.",
      inputSchema: {
        sessionId: z.string().describe("ID der r2-Session"),
        functionName: z
          .string()
          .optional()
          .describe("Name der Funktion (z.B. 'main', 'sym.check_password')"),
        address: z
          .string()
          .optional()
          .describe("Adresse der Funktion als Alternative zum Namen"),
      },
    },
    async ({ sessionId, functionName, address }) => {
      try {
        // Zur Funktion springen
        if (functionName) {
          await sessionManager.execute(sessionId, `s ${functionName}`);
        } else if (address) {
          await sessionManager.execute(sessionId, `s ${address}`);
        }

        // Funktion emulieren mit Trace
        await sessionManager.execute(sessionId, "aets+");
        const result = await sessionManager.execute(sessionId, "aef");
        await sessionManager.execute(sessionId, "aets-");

        const registers = await sessionManager.execute(sessionId, "aerj");

        return {
          content: [
            {
              type: "text" as const,
              text:
                `Funktion emuliert: ${functionName || address}\n\n` +
                `Ergebnis:\n${result}\n\n` +
                `Register nach Emulation:\n${registers}`,
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Fehler bei Funktions-Emulation: ${error}`,
            },
          ],
          isError: true,
        };
      }
    },
  );

  // --- ESIL Memory lesen ---
  server.registerTool(
    "esil_read_memory",
    {
      title: "ESIL Memory Lesen",
      description:
        "Liest Memory aus dem ESIL-VM-Kontext. Zeigt die Bytes " +
        "an einer bestimmten Adresse als Hexdump an.",
      inputSchema: {
        sessionId: z.string().describe("ID der r2-Session"),
        address: z.string().describe("Adresse zum Lesen (Hex)"),
        size: z
          .number()
          .optional()
          .default(64)
          .describe("Anzahl der zu lesenden Bytes (Standard: 64)"),
      },
    },
    async ({ sessionId, address, size }) => {
      await sessionManager.execute(sessionId, `s ${address}`);
      const hexdump = await sessionManager.execute(sessionId, `px ${size}`);

      return {
        content: [
          {
            type: "text" as const,
            text: `Memory bei ${address} (${size} Bytes):\n\n${hexdump}`,
          },
        ],
      };
    },
  );
}
```

**ESIL-Expression Syntax (Referenz fuer das LLM):**

```
ESIL benutzt Reverse Polish Notation (RPN):

Arithmetik:     1,2,+          => 3
                rax,rbx,-      => rax - rbx

Zuweisung:      42,rax,=       => rax = 42
                rax,rbx,=      => rbx = rax

Memory:         rax,[4]        => 4 Bytes lesen ab Adresse in rax
                42,rax,=[4]    => 4 Bytes (42) schreiben an Adresse in rax

Vergleich:      rax,rbx,==,$z,zf,= => zf = (rax == rbx)

Control Flow:   addr,rip,=     => Jump zu addr
                rsp,[8],rip,=  => ret (Pop von Stack nach rip)

Spezial:        $$             => Aktuelle Adresse
                $z             => Zero Flag Result
                $c             => Carry Flag Result
                $b             => Borrow Flag Result
                $p             => Parity Flag Result
                $s             => Sign Flag Result
                $o             => Overflow Flag Result
```

### 3.4 Shellcode Analyzer

Der Shellcode Analyzer kombiniert statische Analyse mit ESIL-Emulation, um
Shellcode zu erkennen, zu klassifizieren und seine Funktionalitaet zu extrahieren.

**Datei: `src/tools/shellcode-analysis.ts`**

```typescript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { SessionManager } from "../core/session-manager.js";

export function registerShellcodeTools(
  server: McpServer,
  sessionManager: SessionManager,
): void {

  // --- Shellcode aus Datei oder Hex-String laden und analysieren ---
  server.registerTool(
    "shellcode_analyze",
    {
      title: "Shellcode Analysieren",
      description:
        "Laedt Shellcode aus einer Datei oder einem Hex-String und " +
        "fuehrt eine umfassende Analyse durch: Disassembly, Syscall-Erkennung, " +
        "Decoder-Stub-Erkennung, String-Extraktion und optionale Emulation.",
      inputSchema: {
        input: z
          .string()
          .describe(
            "Pfad zu einer Shellcode-Datei ODER Hex-String " +
            "(z.B. '\\x31\\xc0\\x50\\x68...' oder '31c050682f2f...')",
          ),
        inputType: z
          .enum(["file", "hex"])
          .describe("Art des Inputs: 'file' oder 'hex'"),
        arch: z
          .string()
          .optional()
          .default("x86")
          .describe("Architektur (x86, x86_64, arm, arm64, mips)"),
        bits: z
          .number()
          .optional()
          .default(32)
          .describe("Bitbreite (32 oder 64)"),
        emulate: z
          .boolean()
          .optional()
          .default(true)
          .describe("Shellcode mittels ESIL emulieren"),
      },
    },
    async ({ input, inputType, arch, bits, emulate }) => {
      let session;

      try {
        if (inputType === "hex") {
          // Hex-Input: r2 mit malloc:// oeffnen und Bytes schreiben
          const cleanHex = input
            .replace(/\\x/g, "")
            .replace(/\s/g, "")
            .replace(/0x/g, "");
          const byteCount = cleanHex.length / 2;

          session = await sessionManager.open(`malloc://${byteCount}`);
          await sessionManager.execute(session.id, `wx ${cleanHex}`);
        } else {
          session = await sessionManager.open(input);
        }

        // Architektur setzen
        await sessionManager.execute(session.id, `e asm.arch=${arch}`);
        await sessionManager.execute(session.id, `e asm.bits=${bits}`);
        await sessionManager.execute(session.id, `e anal.arch=${arch}`);

        const results: string[] = [];

        // 1. Disassembly
        const disasm = await sessionManager.execute(session.id, "pd 100");
        results.push("=== DISASSEMBLY ===\n" + disasm);

        // 2. Analyse ausfuehren
        await sessionManager.execute(session.id, "aaa");

        // 3. Erkannte Funktionen
        const functions = await sessionManager.execute(session.id, "aflj");
        results.push("\n=== FUNKTIONEN ===\n" + functions);

        // 4. Syscalls erkennen
        const syscalls = await sessionManager.execute(session.id, "as");
        results.push("\n=== SYSCALLS ===\n" + syscalls);

        // 5. Strings
        const strings = await sessionManager.execute(session.id, "izj");
        results.push("\n=== STRINGS ===\n" + strings);

        // 6. Shellcode-spezifische Patterns
        const patterns = await this.detectShellcodePatterns(session.id, sessionManager);
        results.push("\n=== PATTERN-ERKENNUNG ===\n" + patterns);

        // 7. Optionale ESIL-Emulation
        if (emulate) {
          const emulationResult = await this.emulateShellcode(
            session.id,
            sessionManager,
          );
          results.push("\n=== ESIL EMULATION ===\n" + emulationResult);
        }

        return {
          content: [
            {
              type: "text" as const,
              text: results.join("\n"),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Fehler bei Shellcode-Analyse: ${error}`,
            },
          ],
          isError: true,
        };
      }
    },
  );

  // --- Shellcode-Decoder erkennen ---
  server.registerTool(
    "shellcode_detect_encoder",
    {
      title: "Shellcode Encoder Erkennen",
      description:
        "Erkennt gaengige Shellcode-Encoder und -Decoder-Stubs " +
        "(XOR, Shikata Ga Nai, Alpha-Numeric etc.) und extrahiert " +
        "den Decode-Key wenn moeglich.",
      inputSchema: {
        sessionId: z.string().describe("ID der r2-Session mit geladenem Shellcode"),
      },
    },
    async ({ sessionId }) => {
      const results: string[] = [];

      // XOR-Encoder erkennen
      // Suche nach typischen Patterns: xor + loop
      const xorSearch = await sessionManager.execute(
        sessionId,
        '/x 8030??80??00??75' // Typisches XOR-Loop Pattern
      );
      if (xorSearch.trim()) {
        results.push("XOR-Encoder-Stub erkannt:\n" + xorSearch);
      }

      // Entropy-Analyse (codierte Shellcodes haben hoehere Entropie)
      const entropy = await sessionManager.execute(sessionId, "p=e 256");
      results.push("Entropie-Verteilung:\n" + entropy);

      // Byte-Haeufigkeitsverteilung
      const byteStats = await sessionManager.execute(sessionId, "p=b 256");
      results.push("Byte-Verteilung:\n" + byteStats);

      // Null-Byte Pruefung (Shellcodes vermeiden oft \x00)
      const nullBytes = await sessionManager.execute(sessionId, "/x 00");
      const nullCount = nullBytes.trim().split("\n").length;
      results.push(`Null-Bytes gefunden: ${nullCount}`);

      return {
        content: [
          {
            type: "text" as const,
            text: results.join("\n\n"),
          },
        ],
      };
    },
  );

  // --- ROP-Gadget-Suche ---
  server.registerTool(
    "shellcode_find_rop_gadgets",
    {
      title: "ROP-Gadgets Suchen",
      description:
        "Sucht nach ROP-Gadgets (Return Oriented Programming) in der " +
        "geoeffneten Binary. Findet Gadgets wie pop/ret, xchg, mov etc.",
      inputSchema: {
        sessionId: z.string().describe("ID der r2-Session"),
        search: z
          .string()
          .optional()
          .describe("Filter fuer bestimmte Gadget-Typen (z.B. 'pop rdi')"),
        maxResults: z
          .number()
          .optional()
          .default(50)
          .describe("Maximale Anzahl der Ergebnisse"),
      },
    },
    async ({ sessionId, search, maxResults }) => {
      let cmd = `/Rj ${maxResults}`;
      if (search) {
        cmd = `/R ${search}`;
      }

      const gadgets = await sessionManager.execute(sessionId, cmd);
      return {
        content: [
          {
            type: "text" as const,
            text: `ROP-Gadgets:\n\n${gadgets}`,
          },
        ],
      };
    },
  );
}
```

**Datei: `src/analyzers/shellcode-detector.ts`** (Helferfunktionen)

```typescript
/**
 * Bekannte Shellcode-Signaturen fuer gaengige Payloads.
 * Verwendet fuer heuristische Erkennung.
 */
export const SHELLCODE_SIGNATURES = {
  linux_x86_execve: {
    pattern: "31c050682f2f7368682f62696e89e3505389e1b00bcd80",
    description: "Linux x86 execve('/bin/sh')",
  },
  linux_x64_execve: {
    pattern: "4831f6480f05",
    description: "Linux x86_64 syscall stub",
  },
  windows_x86_messagebox: {
    pattern: "31d2526833320000",
    description: "Windows x86 LoadLibraryA('user32')",
  },
  egg_hunter_seh: {
    pattern: "6681caff0f42526a0258cd2e3c055a74",
    description: "SEH-based Egg Hunter",
  },
  xor_decoder_stub: {
    pattern: "eb??5e31c9????8036??46e2fa",
    description: "Generic XOR decoder stub (JMP-CALL-POP)",
  },
} as const;
```

### 3.5 Binary Analysis Module

Das Binary Analysis Module stellt die Kernfunktionalitaet fuer allgemeine
Binaeranalyse bereit.

**Datei: `src/tools/binary-analysis.ts`**

```typescript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { SessionManager } from "../core/session-manager.js";

export function registerBinaryAnalysisTools(
  server: McpServer,
  sessionManager: SessionManager,
): void {

  // --- Binary oeffnen und analysieren ---
  server.registerTool(
    "open_binary",
    {
      title: "Binary Oeffnen",
      description:
        "Oeffnet eine Binaerdatei in radare2 und fuehrt eine optionale " +
        "automatische Analyse durch. Gibt die Session-ID zurueck, die " +
        "fuer alle weiteren Operationen benoetigt wird.",
      inputSchema: {
        filePath: z.string().describe("Absoluter Pfad zur Binaerdatei"),
        analyze: z
          .boolean()
          .optional()
          .default(true)
          .describe("Automatische Analyse ausfuehren (aaa)"),
        analysisLevel: z
          .enum(["none", "basic", "deep", "experimental"])
          .optional()
          .default("deep")
          .describe(
            "Analyse-Tiefe: none (keine), basic (aa), " +
            "deep (aaa), experimental (aaaa)",
          ),
      },
    },
    async ({ filePath, analyze, analysisLevel }) => {
      const session = await sessionManager.open(filePath);

      if (analyze) {
        const analysisCmd =
          analysisLevel === "none" ? "" :
          analysisLevel === "basic" ? "aa" :
          analysisLevel === "experimental" ? "aaaa" :
          "aaa"; // deep (Standard)

        if (analysisCmd) {
          await sessionManager.execute(session.id, analysisCmd);
          session.isAnalyzed = true;
        }
      }

      // Binary-Informationen sammeln
      const info = await sessionManager.execute(session.id, "ij");

      return {
        content: [
          {
            type: "text" as const,
            text:
              `Binary geoeffnet. Session-ID: ${session.id}\n\n` +
              `Binary-Info:\n${info}`,
          },
        ],
      };
    },
  );

  // --- Session schliessen ---
  server.registerTool(
    "close_session",
    {
      title: "Session Schliessen",
      description: "Schliesst eine r2-Session und gibt alle Ressourcen frei.",
      inputSchema: {
        sessionId: z.string().describe("ID der zu schliessenden Session"),
      },
    },
    async ({ sessionId }) => {
      await sessionManager.close(sessionId);
      return {
        content: [
          {
            type: "text" as const,
            text: `Session ${sessionId} geschlossen.`,
          },
        ],
      };
    },
  );

  // --- Funktionsliste ---
  server.registerTool(
    "list_functions",
    {
      title: "Funktionen Auflisten",
      description:
        "Listet alle erkannten Funktionen in der Binary auf mit " +
        "Adressen, Groessen und Namen.",
      inputSchema: {
        sessionId: z.string().describe("ID der r2-Session"),
        filter: z
          .string()
          .optional()
          .describe("Filter fuer Funktionsnamen (z.B. 'main', 'sym.')"),
      },
    },
    async ({ sessionId, filter }) => {
      const functions = await sessionManager.executeJson(
        sessionId,
        "aflj",
      );

      let filtered = functions as Array<{
        name: string;
        offset: number;
        size: number;
      }>;

      if (filter) {
        filtered = filtered.filter((f) =>
          f.name.toLowerCase().includes(filter.toLowerCase()),
        );
      }

      const formatted = filtered.map(
        (f) =>
          `0x${f.offset.toString(16).padStart(8, "0")}  ${String(f.size).padStart(6)} bytes  ${f.name}`,
      );

      return {
        content: [
          {
            type: "text" as const,
            text:
              `${filtered.length} Funktionen gefunden:\n\n` +
              formatted.join("\n"),
          },
        ],
      };
    },
  );

  // --- Funktion disassemblieren ---
  server.registerTool(
    "disassemble_function",
    {
      title: "Funktion Disassemblieren",
      description:
        "Disassembliert eine Funktion oder einen Adressbereich. " +
        "Zeigt Assembly-Instruktionen mit Adressen und Kommentaren.",
      inputSchema: {
        sessionId: z.string().describe("ID der r2-Session"),
        target: z
          .string()
          .describe(
            "Funktionsname (z.B. 'main') oder Adresse (z.B. '0x00401000')",
          ),
        format: z
          .enum(["text", "json", "graph"])
          .optional()
          .default("text")
          .describe("Ausgabeformat: text, json oder graph (ASCII-Graph)"),
      },
    },
    async ({ sessionId, target, format }) => {
      // Zur Zieladresse/Funktion springen
      await sessionManager.execute(sessionId, `s ${target}`);

      let cmd: string;
      switch (format) {
        case "json":
          cmd = "pdfj";
          break;
        case "graph":
          cmd = "agf";
          break;
        default:
          cmd = "pdf";
      }

      const result = await sessionManager.execute(sessionId, cmd);

      return {
        content: [
          {
            type: "text" as const,
            text: result,
          },
        ],
      };
    },
  );

  // --- Cross-References ---
  server.registerTool(
    "get_xrefs",
    {
      title: "Cross-References Anzeigen",
      description:
        "Zeigt Cross-References (Xrefs) fuer eine Adresse oder Funktion. " +
        "Kann sowohl eingehende (wer ruft mich?) als auch ausgehende " +
        "(wen rufe ich?) Referenzen anzeigen.",
      inputSchema: {
        sessionId: z.string().describe("ID der r2-Session"),
        target: z
          .string()
          .describe("Adresse oder Funktionsname fuer Xref-Suche"),
        direction: z
          .enum(["to", "from", "both"])
          .optional()
          .default("both")
          .describe(
            "'to' = wer referenziert das Ziel, " +
            "'from' = was referenziert das Ziel, " +
            "'both' = beides",
          ),
      },
    },
    async ({ sessionId, target, direction }) => {
      await sessionManager.execute(sessionId, `s ${target}`);
      const results: string[] = [];

      if (direction === "to" || direction === "both") {
        const xrefsTo = await sessionManager.execute(sessionId, "axtj");
        results.push("=== Referenzen ZU diesem Ziel ===\n" + xrefsTo);
      }

      if (direction === "from" || direction === "both") {
        const xrefsFrom = await sessionManager.execute(sessionId, "axfj");
        results.push("=== Referenzen VON diesem Ziel ===\n" + xrefsFrom);
      }

      return {
        content: [
          {
            type: "text" as const,
            text: results.join("\n\n"),
          },
        ],
      };
    },
  );

  // --- String-Extraktion ---
  server.registerTool(
    "extract_strings",
    {
      title: "Strings Extrahieren",
      description:
        "Extrahiert Strings aus der Binary. Findet ASCII- und " +
        "Unicode-Strings in allen Sektionen.",
      inputSchema: {
        sessionId: z.string().describe("ID der r2-Session"),
        minLength: z
          .number()
          .optional()
          .default(4)
          .describe("Minimale String-Laenge (Standard: 4)"),
        section: z
          .string()
          .optional()
          .describe("Nur Strings aus dieser Sektion (z.B. '.rodata')"),
        filter: z
          .string()
          .optional()
          .describe("Regex-Filter fuer String-Inhalt"),
      },
    },
    async ({ sessionId, minLength, section, filter }) => {
      // Minimale String-Laenge setzen
      await sessionManager.execute(
        sessionId,
        `e bin.str.min=${minLength}`,
      );

      let cmd = "izj"; // Strings als JSON
      if (section) {
        cmd = `izj~${section}`;
      }

      const strings = await sessionManager.execute(sessionId, cmd);

      let result = strings;
      if (filter) {
        try {
          const parsed = JSON.parse(strings) as Array<{
            string: string;
            vaddr: number;
            section: string;
          }>;
          const regex = new RegExp(filter, "i");
          const filtered = parsed.filter((s) => regex.test(s.string));
          result = JSON.stringify(filtered, null, 2);
        } catch {
          // Fallback: Text-basierte Filterung
        }
      }

      return {
        content: [
          {
            type: "text" as const,
            text: `Strings:\n\n${result}`,
          },
        ],
      };
    },
  );

  // --- Hexdump ---
  server.registerTool(
    "hexdump",
    {
      title: "Hexdump",
      description:
        "Zeigt einen Hexdump an einer bestimmten Adresse an. " +
        "Nuetzlich fuer die Untersuchung von Rohdaten.",
      inputSchema: {
        sessionId: z.string().describe("ID der r2-Session"),
        address: z.string().describe("Startadresse (Hex)"),
        size: z
          .number()
          .optional()
          .default(256)
          .describe("Anzahl der Bytes (Standard: 256)"),
      },
    },
    async ({ sessionId, address, size }) => {
      await sessionManager.execute(sessionId, `s ${address}`);
      const dump = await sessionManager.execute(sessionId, `px ${size}`);

      return {
        content: [
          {
            type: "text" as const,
            text: dump,
          },
        ],
      };
    },
  );

  // --- Binary-Header und Sektionen ---
  server.registerTool(
    "binary_info",
    {
      title: "Binary Informationen",
      description:
        "Zeigt detaillierte Informationen ueber die Binary: " +
        "Header, Sektionen, Imports, Exports, Symbole.",
      inputSchema: {
        sessionId: z.string().describe("ID der r2-Session"),
        category: z
          .enum([
            "info",
            "sections",
            "imports",
            "exports",
            "symbols",
            "headers",
            "entrypoints",
            "libs",
            "relocs",
          ])
          .describe("Kategorie der gewuenschten Information"),
      },
    },
    async ({ sessionId, category }) => {
      const cmdMap: Record<string, string> = {
        info: "ij",
        sections: "iSj",
        imports: "iij",
        exports: "iEj",
        symbols: "isj",
        headers: "ihj",
        entrypoints: "iej",
        libs: "ilj",
        relocs: "irj",
      };

      const result = await sessionManager.execute(
        sessionId,
        cmdMap[category],
      );

      return {
        content: [
          {
            type: "text" as const,
            text: `${category}:\n\n${result}`,
          },
        ],
      };
    },
  );

  // --- Decompiler (r2ghidra / r2dec / pdc) ---
  server.registerTool(
    "decompile_function",
    {
      title: "Funktion Dekompilieren",
      description:
        "Dekompiliert eine Funktion zu Pseudocode. Verwendet den " +
        "in radare2 verfuegbaren Decompiler (pdc, pdg fuer r2ghidra, " +
        "pdd fuer r2dec).",
      inputSchema: {
        sessionId: z.string().describe("ID der r2-Session"),
        target: z
          .string()
          .describe("Funktionsname oder Adresse"),
        decompiler: z
          .enum(["pdc", "pdg", "pdd"])
          .optional()
          .default("pdc")
          .describe(
            "Decompiler: pdc (built-in), pdg (r2ghidra), pdd (r2dec)",
          ),
      },
    },
    async ({ sessionId, target, decompiler }) => {
      await sessionManager.execute(sessionId, `s ${target}`);
      const result = await sessionManager.execute(sessionId, decompiler);

      return {
        content: [
          {
            type: "text" as const,
            text: result,
          },
        ],
      };
    },
  );

  // --- Control Flow Graph ---
  server.registerTool(
    "function_graph",
    {
      title: "Funktions-Graph",
      description:
        "Erstellt einen ASCII-Control-Flow-Graph fuer eine Funktion. " +
        "Zeigt die Basic Blocks und deren Verbindungen.",
      inputSchema: {
        sessionId: z.string().describe("ID der r2-Session"),
        target: z.string().describe("Funktionsname oder Adresse"),
        format: z
          .enum(["ascii", "dot", "json"])
          .optional()
          .default("ascii")
          .describe("Graph-Format: ascii, dot (Graphviz) oder json"),
      },
    },
    async ({ sessionId, target, format }) => {
      await sessionManager.execute(sessionId, `s ${target}`);

      const cmdMap: Record<string, string> = {
        ascii: "agf",
        dot: "agfd",
        json: "agfj",
      };

      const result = await sessionManager.execute(sessionId, cmdMap[format]);

      return {
        content: [
          {
            type: "text" as const,
            text: result,
          },
        ],
      };
    },
  );

  // --- Rename ---
  server.registerTool(
    "rename_function",
    {
      title: "Funktion Umbenennen",
      description:
        "Benennt eine Funktion oder ein Flag um. Nuetzlich fuer die " +
        "Annotation waehrend der Analyse.",
      inputSchema: {
        sessionId: z.string().describe("ID der r2-Session"),
        oldName: z.string().describe("Aktueller Name oder Adresse"),
        newName: z.string().describe("Neuer Name"),
      },
    },
    async ({ sessionId, oldName, newName }) => {
      // Zur Adresse/Funktion springen
      await sessionManager.execute(sessionId, `s ${oldName}`);
      // Funktion umbenennen
      await sessionManager.execute(sessionId, `afn ${newName}`);

      return {
        content: [
          {
            type: "text" as const,
            text: `Funktion umbenannt: ${oldName} -> ${newName}`,
          },
        ],
      };
    },
  );

  // --- Kommentar setzen ---
  server.registerTool(
    "set_comment",
    {
      title: "Kommentar Setzen",
      description:
        "Setzt einen Kommentar an einer bestimmten Adresse in der Binary.",
      inputSchema: {
        sessionId: z.string().describe("ID der r2-Session"),
        address: z.string().describe("Adresse fuer den Kommentar"),
        comment: z.string().describe("Kommentartext"),
      },
    },
    async ({ sessionId, address, comment }) => {
      await sessionManager.execute(sessionId, `s ${address}`);
      // Kommentar mit Escaping setzen
      const escapedComment = comment.replace(/"/g, '\\"');
      await sessionManager.execute(sessionId, `CC "${escapedComment}"`);

      return {
        content: [
          {
            type: "text" as const,
            text: `Kommentar gesetzt bei ${address}: ${comment}`,
          },
        ],
      };
    },
  );
}
```

### 3.6 R2 Command Executor (Generischer Zugang)

Fuer fortgeschrittene Nutzer, die direkte r2-Befehle absetzen wollen.

**Datei: `src/tools/r2-command-tools.ts`**

```typescript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { SessionManager } from "../core/session-manager.js";
import { sanitizeR2Command } from "../utils/sanitizer.js";

export function registerR2CommandTools(
  server: McpServer,
  sessionManager: SessionManager,
): void {

  server.registerTool(
    "r2_command",
    {
      title: "Radare2 Befehl Ausfuehren",
      description:
        "Fuehrt einen beliebigen radare2-Befehl auf einer geoeffneten " +
        "Session aus. Fuer fortgeschrittene Nutzer, die direkte Kontrolle " +
        "ueber r2 benoetigen. WICHTIG: Befehle werden sanitized, " +
        "Shell-Escapes sind nicht moeglich.",
      inputSchema: {
        sessionId: z.string().describe("ID der r2-Session"),
        command: z
          .string()
          .describe(
            "r2-Befehl (z.B. 'pdf @ main', 'afl', 'px 64 @ 0x401000')",
          ),
      },
    },
    async ({ sessionId, command }) => {
      const sanitized = sanitizeR2Command(command);
      const result = await sessionManager.execute(sessionId, sanitized);

      return {
        content: [
          {
            type: "text" as const,
            text: result || "(Leere Ausgabe)",
          },
        ],
      };
    },
  );

  server.registerTool(
    "r2_script",
    {
      title: "Radare2 Script Ausfuehren",
      description:
        "Fuehrt mehrere r2-Befehle sequentiell aus und gibt alle " +
        "Ergebnisse gesammelt zurueck. Nuetzlich fuer komplexe " +
        "Analyse-Workflows.",
      inputSchema: {
        sessionId: z.string().describe("ID der r2-Session"),
        commands: z
          .array(z.string())
          .describe("Liste von r2-Befehlen, die sequentiell ausgefuehrt werden"),
      },
    },
    async ({ sessionId, commands }) => {
      const results: Array<{ command: string; output: string }> = [];

      for (const cmd of commands) {
        const sanitized = sanitizeR2Command(cmd);
        try {
          const output = await sessionManager.execute(sessionId, sanitized);
          results.push({ command: cmd, output: output || "(Leere Ausgabe)" });
        } catch (error) {
          results.push({ command: cmd, output: `FEHLER: ${error}` });
        }
      }

      const formatted = results
        .map((r) => `> ${r.command}\n${r.output}`)
        .join("\n\n");

      return {
        content: [
          {
            type: "text" as const,
            text: formatted,
          },
        ],
      };
    },
  );
}
```

---

## 4. Transport Layer

### 4.1 stdio (Primaerer Transport)

Der primaere Transport ist stdio, da der Server typischerweise als Child-Prozess
von Claude Desktop, Claude Code oder VS Code gestartet wird.

```
claude_desktop_config.json:
{
  "mcpServers": {
    "radare2": {
      "command": "node",
      "args": ["C:\\path\\to\\radare2-mcp\\build\\index.js"],
      "env": {
        "R2_PATH": "C:\\radare2\\bin\\radare2.exe",
        "R2_MAX_SESSIONS": "5",
        "R2_SESSION_TIMEOUT": "300000"
      }
    }
  }
}
```

**Wichtige Einschraenkungen bei stdio:**
- `console.log()` DARF NICHT verwendet werden (schreibt auf stdout, kollidiert
  mit JSON-RPC)
- Stattdessen `console.error()` oder einen Logger, der auf stderr schreibt
- Alle Ausgaben des Servers muessen korrekt als JSON-RPC 2.0 Nachrichten
  serialisiert werden

**Datei: `src/server/transport.ts`**

```typescript
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { Config } from "../utils/config.js";

export type TransportType = "stdio" | "sse";

export function createTransport(config: Config) {
  switch (config.transport) {
    case "sse":
      // SSE Transport fuer Remote-/Web-Szenarien
      // Erfordert HTTP-Server-Setup
      throw new Error("SSE Transport noch nicht implementiert");
    case "stdio":
    default:
      return new StdioServerTransport();
  }
}
```

### 4.2 SSE (Zukuenftiger Transport)

Fuer Remote-Szenarien (z.B. Cloud-basierte Analyse-Umgebung) kann spaeter ein
SSE-Transport (Server-Sent Events) / Streamable HTTP Transport implementiert werden.
Das wuerde einen HTTP-Server erfordern, der eingehende JSON-RPC-Nachrichten per
POST empfaengt und Antworten als SSE-Events streamt.

```
+---------------------------+     HTTPS      +---------------------------+
|   MCP Client              |<-------------->|  Radare2 MCP Server       |
|   (Claude, VS Code)       |   POST/SSE     |  (Express/Fastify + MCP)  |
+---------------------------+                +---------------------------+
```

### 4.3 Session-Management bei Mehrfach-Clients

Bei stdio ist nur ein Client gleichzeitig verbunden. Fuer den SSE-Transport
muessen Sessions Client-uebergreifend isoliert werden:

```typescript
// Pseudocode fuer Multi-Client Session Management
interface ClientSession {
  clientId: string;
  r2Sessions: Map<string, R2Session>;
  createdAt: Date;
}

class MultiClientSessionManager {
  private clients: Map<string, ClientSession> = new Map();

  getOrCreateClient(clientId: string): ClientSession {
    if (!this.clients.has(clientId)) {
      this.clients.set(clientId, {
        clientId,
        r2Sessions: new Map(),
        createdAt: new Date(),
      });
    }
    return this.clients.get(clientId)!;
  }
}
```

---

## 5. Error Handling & Logging

### 5.1 Error-Kategorien

```
+------------------------------------------+
|           Error Hierarchie               |
+------------------------------------------+
|                                          |
|  R2McpError (Basis)                      |
|  |-- R2SessionError                      |
|  |   |-- SessionNotFoundError            |
|  |   |-- SessionTimeoutError             |
|  |   +-- SessionCrashedError             |
|  |-- R2CommandError                      |
|  |   |-- CommandTimeoutError             |
|  |   |-- InvalidCommandError             |
|  |   +-- CommandExecutionError           |
|  |-- R2AnalysisError                     |
|  |   |-- FileNotFoundError               |
|  |   |-- UnsupportedFormatError          |
|  |   +-- AnalysisTimeoutError            |
|  +-- R2InputValidationError              |
|      |-- UnsafeCommandError              |
|      +-- InvalidAddressError             |
+------------------------------------------+
```

**Datei: `src/utils/error-handler.ts`**

```typescript
export class R2McpError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly isRetryable: boolean = false,
  ) {
    super(message);
    this.name = "R2McpError";
  }
}

export class SessionCrashedError extends R2McpError {
  constructor(sessionId: string) {
    super(
      `radare2-Prozess fuer Session ${sessionId} ist abgestuerzt. ` +
        `Bitte oeffne die Binary erneut mit open_binary.`,
      "SESSION_CRASHED",
      true,
    );
  }
}

export class CommandTimeoutError extends R2McpError {
  constructor(command: string, timeoutMs: number) {
    super(
      `r2-Befehl "${command}" hat nach ${timeoutMs}ms nicht geantwortet. ` +
        `Der Befehl koennte zu aufwaendig sein oder r2 haengt.`,
      "COMMAND_TIMEOUT",
      true,
    );
  }
}

/**
 * Konvertiert interne Errors in MCP-kompatible Tool-Ergebnisse.
 */
export function handleToolError(error: unknown): {
  content: Array<{ type: "text"; text: string }>;
  isError: true;
} {
  if (error instanceof R2McpError) {
    return {
      content: [
        {
          type: "text",
          text: `[${error.code}] ${error.message}`,
        },
      ],
      isError: true,
    };
  }

  const message =
    error instanceof Error ? error.message : String(error);
  return {
    content: [
      {
        type: "text",
        text: `Unerwarteter Fehler: ${message}`,
      },
    ],
    isError: true,
  };
}
```

### 5.2 Logging

**Datei: `src/utils/logger.ts`**

```typescript
/**
 * Logger, der auf stderr schreibt (WICHTIG fuer stdio-Transport).
 * Niemals console.log() verwenden!
 */
export const logger = {
  info: (message: string, ...args: unknown[]) => {
    console.error(`[INFO] ${new Date().toISOString()} ${message}`, ...args);
  },
  warn: (message: string, ...args: unknown[]) => {
    console.error(`[WARN] ${new Date().toISOString()} ${message}`, ...args);
  },
  error: (message: string, ...args: unknown[]) => {
    console.error(`[ERROR] ${new Date().toISOString()} ${message}`, ...args);
  },
  debug: (message: string, ...args: unknown[]) => {
    if (process.env.DEBUG === "true") {
      console.error(`[DEBUG] ${new Date().toISOString()} ${message}`, ...args);
    }
  },
};
```

### 5.3 radare2-Crash-Recovery

radare2 kann bei bestimmten Binaerdateien oder Befehlen abstuerzen. Die
Recovery-Strategie:

```
Befehlsausfuehrung
       |
       v
  +----+----+
  | Timeout? |--Ja--> CommandTimeoutError
  +----+----+       (Session bleibt offen,
       |             naechster Befehl
       | Nein        koennte funktionieren)
       v
  +----+------+
  | EPIPE/EOF? |--Ja--> SessionCrashedError
  +----+------+       (Session wird entfernt,
       |               Client muss neu oeffnen)
       | Nein
       v
  Ergebnis zurueck
```

---

## 6. Konfiguration

**Datei: `src/utils/config.ts`**

```typescript
export interface ConfigValues {
  transport: "stdio" | "sse";
  r2Path: string;
  maxSessions: number;
  sessionTimeout: number; // ms
  commandTimeout: number; // ms
  analysisTimeout: number; // ms
  debug: boolean;
  defaultAnalysisLevel: "none" | "basic" | "deep" | "experimental";
  allowedCommands?: string[]; // Whitelist (optional)
  blockedCommands: string[];  // Blacklist
}

export class Config implements ConfigValues {
  transport: "stdio" | "sse";
  r2Path: string;
  maxSessions: number;
  sessionTimeout: number;
  commandTimeout: number;
  analysisTimeout: number;
  debug: boolean;
  defaultAnalysisLevel: "none" | "basic" | "deep" | "experimental";
  blockedCommands: string[];

  private constructor(values: ConfigValues) {
    Object.assign(this, values);
  }

  static load(): Config {
    return new Config({
      transport: (process.env.R2_TRANSPORT as "stdio" | "sse") || "stdio",
      r2Path: process.env.R2_PATH || "radare2",
      maxSessions: parseInt(process.env.R2_MAX_SESSIONS || "5", 10),
      sessionTimeout: parseInt(
        process.env.R2_SESSION_TIMEOUT || "300000",
        10,
      ), // 5 Minuten
      commandTimeout: parseInt(
        process.env.R2_COMMAND_TIMEOUT || "30000",
        10,
      ), // 30 Sekunden
      analysisTimeout: parseInt(
        process.env.R2_ANALYSIS_TIMEOUT || "120000",
        10,
      ), // 2 Minuten
      debug: process.env.DEBUG === "true",
      defaultAnalysisLevel:
        (process.env.R2_ANALYSIS_LEVEL as ConfigValues["defaultAnalysisLevel"]) ||
        "deep",
      blockedCommands: [
        "!",     // Shell-Escape
        "=!",    // Remote-Shell
        "#!",    // Scripting-Engine Shell
        "o-*",   // Alle Dateien schliessen
      ],
    });
  }
}
```

**Umgebungsvariablen:**

| Variable               | Beschreibung                           | Standard       |
|------------------------|----------------------------------------|----------------|
| `R2_TRANSPORT`         | Transport-Typ (stdio, sse)             | `stdio`        |
| `R2_PATH`              | Pfad zur radare2-Executable            | `radare2`      |
| `R2_MAX_SESSIONS`      | Maximale Anzahl paralleler Sessions    | `5`            |
| `R2_SESSION_TIMEOUT`   | Session-Timeout in Millisekunden       | `300000` (5m)  |
| `R2_COMMAND_TIMEOUT`   | Timeout pro Befehl in Millisekunden    | `30000` (30s)  |
| `R2_ANALYSIS_TIMEOUT`  | Timeout fuer Analyse in Millisekunden  | `120000` (2m)  |
| `R2_ANALYSIS_LEVEL`    | Standard-Analysetiefe                  | `deep`         |
| `DEBUG`                | Debug-Logging aktivieren               | `false`        |

---

## 7. Dependencies

### 7.1 Laufzeit-Dependencies

```json
{
  "dependencies": {
    "@modelcontextprotocol/sdk": "^1.12.0",
    "r2pipe": "^0.2.1",
    "zod": "^3.24.0"
  }
}
```

| Paket                          | Zweck                                  | Version |
|-------------------------------|----------------------------------------|---------|
| `@modelcontextprotocol/sdk`   | MCP Server SDK (McpServer, Transport)  | ^1.12   |
| `r2pipe`                      | Kommunikation mit radare2 via Pipes    | ^0.2    |
| `zod`                         | Schema-Validierung fuer Tool-Inputs    | ^3.24   |

### 7.2 Entwicklungs-Dependencies

```json
{
  "devDependencies": {
    "@types/node": "^22.0.0",
    "typescript": "^5.7.0",
    "vitest": "^3.0.0",
    "eslint": "^9.0.0",
    "@typescript-eslint/eslint-plugin": "^8.0.0",
    "@typescript-eslint/parser": "^8.0.0",
    "prettier": "^3.4.0"
  }
}
```

### 7.3 System-Voraussetzungen

| Software    | Version    | Anmerkung                                        |
|------------|------------|--------------------------------------------------|
| Node.js    | >= 18.0    | ES2022 Modul-Support erforderlich                |
| radare2    | >= 5.9.0   | Muss im PATH oder via R2_PATH erreichbar sein    |
| npm / pnpm | >= 9.0     | Paketmanager                                     |

### 7.4 Optionale radare2-Plugins

| Plugin         | Zweck                              | r2-Befehl |
|---------------|-------------------------------------|-----------|
| r2ghidra      | Ghidra-basierter Decompiler         | `pdg`     |
| r2dec         | Alternativer Decompiler             | `pdd`     |
| r2yara        | YARA-Rule-Matching in r2            | `yara`    |

---

## 8. Sequenzdiagramme fuer wichtige Flows

### 8.1 Binary oeffnen und analysieren

```
Client (LLM)           MCP Server              SessionManager           radare2
    |                       |                        |                      |
    |-- tools/call -------->|                        |                      |
    |   "open_binary"       |                        |                      |
    |   {path, analyze}     |                        |                      |
    |                       |-- open(path) --------->|                      |
    |                       |                        |-- r2pipe.open() ---->|
    |                       |                        |<--- pipe ------------|
    |                       |                        |-- sessions.set() --->|
    |                       |<-- session ------------|                      |
    |                       |                        |                      |
    |                       |-- execute("aaa") ----->|                      |
    |                       |                        |-- pipe.cmd("aaa") -->|
    |                       |                        |<--- OK --------------|
    |                       |                        |                      |
    |                       |-- execute("ij") ------>|                      |
    |                       |                        |-- pipe.cmd("ij") --->|
    |                       |                        |<--- JSON Info -------|
    |                       |                        |                      |
    |<-- Tool Result -------|                        |                      |
    |   {sessionId, info}   |                        |                      |
```

### 8.2 ESIL-Emulationsworkflow

```
Client (LLM)           MCP Server              SessionManager           radare2
    |                       |                        |                      |
    |== Phase 1: Initialisierung ==========================================|
    |                       |                        |                      |
    |-- "esil_init" ------->|                        |                      |
    |   {sessionId}         |-- execute("aei") ----->|-- "aei" ----------->|
    |                       |-- execute("aeim") ---->|-- "aeim 0x.. 0x.."->|
    |                       |-- execute("aeip") ---->|-- "aeip" ---------->|
    |                       |-- execute("aerj") ---->|-- "aerj" ---------->|
    |                       |                        |<-- Register JSON ----|
    |<-- {registers} -------|                        |                      |
    |                       |                        |                      |
    |== Phase 2: Stepping ================================================|
    |                       |                        |                      |
    |-- "esil_step" ------->|                        |                      |
    |   {sessionId, n=5}    |-- execute("aes") x5 -->|-- "aes" x5 -------->|
    |                       |-- execute("aerj") ---->|-- "aerj" ---------->|
    |                       |                        |<-- Register JSON ----|
    |<-- {registers, pc} ---|                        |                      |
    |                       |                        |                      |
    |== Phase 3: Auswertung ===============================================|
    |                       |                        |                      |
    |-- "esil_read_memory"->|                        |                      |
    |   {addr, size}        |-- execute("px 64") --->|-- "px 64" --------->|
    |                       |                        |<-- Hexdump ----------|
    |<-- {hexdump} ---------|                        |                      |
```

### 8.3 Shellcode-Analyse-Pipeline

```
Client (LLM)           MCP Server              SessionManager           radare2
    |                       |                        |                      |
    |-- "shellcode_analyze"->|                       |                      |
    |   {hex, x86, 32bit}   |                       |                      |
    |                        |                       |                      |
    |   [1. Session erstellen]                       |                      |
    |                        |-- open("malloc://N")->|-- r2pipe.open() --->|
    |                        |-- execute("wx ..") -->|-- "wx 31c0..." ---->|
    |                        |-- execute("e arch")-->|-- "e asm.arch=x86"->|
    |                        |                       |                      |
    |   [2. Statische Analyse]                       |                      |
    |                        |-- execute("pd 100") ->|-- "pd 100" -------->|
    |                        |                       |<-- Disassembly ------|
    |                        |-- execute("aaa") ---->|-- "aaa" ----------->|
    |                        |-- execute("aflj") --->|-- "aflj" ---------->|
    |                        |                       |<-- Functions --------|
    |                        |-- execute("as") ----->|-- "as" ------------>|
    |                        |                       |<-- Syscalls ---------|
    |                        |                       |                      |
    |   [3. Pattern-Matching]                        |                      |
    |                        |-- execute("/x ...") ->|-- "/x 31c050..." -->|
    |                        |                       |<-- Matches ----------|
    |                        |                       |                      |
    |   [4. ESIL-Emulation]                          |                      |
    |                        |-- execute("aei") ---->|-- "aei" ----------->|
    |                        |-- execute("aeim") --->|-- "aeim" ---------->|
    |                        |-- execute("N x aes")->|-- "aes" x N ------->|
    |                        |                       |<-- Trace ------------|
    |                        |                       |                      |
    |<-- Tool Result --------|                       |                      |
    |   {disasm, syscalls,   |                       |                      |
    |    patterns, trace}    |                       |                      |
```

### 8.4 Crash-Recovery-Flow

```
Client (LLM)           MCP Server              SessionManager           radare2
    |                       |                        |                      |
    |-- "r2_command" ------>|                        |                      |
    |   {sessionId, cmd}    |-- execute(cmd) ------->|                      |
    |                       |                        |-- pipe.cmd(cmd) ---->|
    |                       |                        |                   CRASH!
    |                       |                        |<-- EPIPE/EOF --------|
    |                       |                        |                      |
    |                       |                        |-- isProcessDead() -->|
    |                       |                        |<-- true              |
    |                       |                        |                      |
    |                       |                        |-- sessions.delete()  |
    |                       |<-- SessionCrashedError |                      |
    |                       |                        |                      |
    |<-- Tool Result -------|                        |                      |
    |   {isError: true,     |                        |                      |
    |    "r2 abgestuerzt"}  |                        |                      |
    |                       |                        |                      |
    |   [Client oeffnet Binary erneut]               |                      |
    |-- "open_binary" ----->|                        |                      |
    |   {path}              |-- open(path) --------->|                      |
    |                       |                        |-- r2pipe.open() ---->|
    |                       |                        |<-- neue Pipe --------|
    |<-- {neueSessionId} ---|                        |                      |
```

---

## 9. Sicherheitsueberlegungen

### 9.1 Input-Sanitization

**Datei: `src/utils/sanitizer.ts`**

```typescript
/**
 * Sanitized r2-Befehle, um Shell-Injection und gefaehrliche
 * Operationen zu verhindern.
 */

const BLOCKED_COMMANDS = [
  /^!/,           // Shell-Escape (!ls, !cat etc.)
  /^=!/,          // Remote Shell
  /^#!/,          // Scripting Shell
  /^o\s+-/,       // Dateien loeschen
  /^\.\s/,        // Skript-Ausfuehrung von Dateien
];

const BLOCKED_PATTERNS = [
  /[;|&`$()]/,    // Shell-Metazeichen
  /\.\.\//,       // Path Traversal
];

export function sanitizeR2Command(command: string): string {
  const trimmed = command.trim();

  // Leere Befehle ablehnen
  if (!trimmed) {
    throw new Error("Leerer Befehl");
  }

  // Gegen Blockliste pruefen
  for (const pattern of BLOCKED_COMMANDS) {
    if (pattern.test(trimmed)) {
      throw new Error(
        `Befehl blockiert (Sicherheit): "${trimmed}" ` +
        `matcht blockiertes Pattern ${pattern}`,
      );
    }
  }

  // Shell-Metazeichen pruefen
  for (const pattern of BLOCKED_PATTERNS) {
    if (pattern.test(trimmed)) {
      throw new Error(
        `Befehl enthaelt unsichere Zeichen: "${trimmed}"`,
      );
    }
  }

  return trimmed;
}
```

### 9.2 Sicherheits-Schichten

```
+--------------------------------------------------+
|  1. Input Validation (zod Schema)                |
|     - Typ-Pruefung aller Parameter               |
|     - Wertebereich-Validierung                   |
+--------------------------------------------------+
                      |
+--------------------------------------------------+
|  2. Command Sanitization                         |
|     - Shell-Escape Blockierung                   |
|     - Metazeichen-Filterung                      |
|     - Path-Traversal-Schutz                      |
+--------------------------------------------------+
                      |
+--------------------------------------------------+
|  3. Session Isolation                            |
|     - Jede Binary in eigenem r2-Prozess          |
|     - Keine Cross-Session-Zugriffe               |
|     - Timeout-basierte Bereinigung               |
+--------------------------------------------------+
                      |
+--------------------------------------------------+
|  4. Ressourcen-Limits                            |
|     - Max. parallele Sessions                    |
|     - Befehls-Timeouts                           |
|     - Automatische Session-Bereinigung           |
+--------------------------------------------------+
```

---

## 10. Tool-Uebersicht (Komplett)

| Tool-Name                   | Kategorie        | Beschreibung                                    |
|-----------------------------|------------------|-------------------------------------------------|
| `open_binary`               | Binary           | Binary oeffnen und analysieren                  |
| `close_session`             | Binary           | Session schliessen                              |
| `list_functions`            | Binary           | Funktionsliste abrufen                          |
| `disassemble_function`      | Binary           | Funktion disassemblieren                        |
| `decompile_function`        | Binary           | Funktion dekompilieren (pdc/pdg/pdd)            |
| `get_xrefs`                 | Binary           | Cross-References anzeigen                       |
| `extract_strings`           | Binary           | Strings extrahieren                             |
| `hexdump`                   | Binary           | Hexdump an Adresse                              |
| `binary_info`               | Binary           | Header, Sektionen, Imports etc.                 |
| `function_graph`            | Binary           | Control-Flow-Graph erzeugen                     |
| `rename_function`           | Binary           | Funktion umbenennen                             |
| `set_comment`               | Binary           | Kommentar setzen                                |
| `esil_init`                 | ESIL             | ESIL VM initialisieren                          |
| `esil_step`                 | ESIL             | Step Into/Over                                  |
| `esil_continue_until`       | ESIL             | Bis Adresse emulieren                           |
| `esil_registers`            | ESIL             | Register lesen/schreiben                        |
| `esil_eval`                 | ESIL             | ESIL-Expression auswerten                       |
| `esil_emulate_function`     | ESIL             | Ganze Funktion emulieren                        |
| `esil_read_memory`          | ESIL             | Memory im ESIL-Kontext lesen                    |
| `shellcode_analyze`         | Shellcode        | Vollstaendige Shellcode-Analyse                 |
| `shellcode_detect_encoder`  | Shellcode        | Encoder/Decoder erkennen                        |
| `shellcode_find_rop_gadgets`| Shellcode        | ROP-Gadgets suchen                              |
| `r2_command`                | r2pipe           | Einzelnen r2-Befehl ausfuehren                  |
| `r2_script`                 | r2pipe           | Mehrere r2-Befehle sequentiell ausfuehren       |

---

## 11. Build & Deployment

### 11.1 package.json

```json
{
  "name": "radare2-mcp",
  "version": "1.0.0",
  "description": "MCP Server fuer radare2 Binary-Analyse, ESIL Emulation und Shellcode-Analyse",
  "type": "module",
  "bin": {
    "radare2-mcp": "./build/index.js"
  },
  "scripts": {
    "build": "tsc",
    "start": "node build/index.js",
    "dev": "tsc --watch",
    "test": "vitest run",
    "test:watch": "vitest",
    "lint": "eslint src/",
    "format": "prettier --write src/"
  },
  "files": ["build"],
  "engines": {
    "node": ">=18.0.0"
  }
}
```

### 11.2 tsconfig.json

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "Node16",
    "moduleResolution": "Node16",
    "outDir": "./build",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "build", "tests"]
}
```

### 11.3 Konfiguration in MCP-Clients

**Claude Desktop (claude_desktop_config.json):**

```json
{
  "mcpServers": {
    "radare2": {
      "command": "node",
      "args": ["C:\\Users\\matti\\code\\mcp\\radare2\\build\\index.js"],
      "env": {
        "R2_MAX_SESSIONS": "5",
        "R2_COMMAND_TIMEOUT": "30000",
        "R2_SESSION_TIMEOUT": "600000"
      }
    }
  }
}
```

**Claude Code (settings.json oder .claude.json):**

```json
{
  "mcpServers": {
    "radare2": {
      "command": "node",
      "args": ["C:\\Users\\matti\\code\\mcp\\radare2\\build\\index.js"]
    }
  }
}
```

---

## 12. Vergleich mit Ghidra MCP (Referenz-Implementierung)

Der Ghidra MCP Server dient als Referenz. Die folgende Tabelle zeigt die
Gegenuberstellung:

| Feature                     | Ghidra MCP            | Radare2 MCP (dieses Projekt)   |
|-----------------------------|-----------------------|--------------------------------|
| Sprache                     | Python/Java           | TypeScript                     |
| Backend-Kommunikation       | Ghidra Bridge/Script  | r2pipe                         |
| Decompilation               | Ghidra Decompiler     | pdc / r2ghidra / r2dec         |
| Emulation                   | Ghidra Emulator       | ESIL VM                        |
| Shellcode-Analyse           | Manuell               | Automatisiert                  |
| Transport                   | stdio                 | stdio (+ SSE geplant)          |
| Session-Management          | Single Session        | Multi-Session Pool             |
| Funktionen auflisten        | list_functions        | list_functions                 |
| Disassembly                 | disassemble_function  | disassemble_function           |
| Decompilation               | decompile_function    | decompile_function             |
| Cross-References            | get_xrefs_to/from     | get_xrefs (bidirektional)      |
| Strings                     | list_strings          | extract_strings                |
| Umbenennung                 | rename_function       | rename_function                |
| Kommentare                  | set_decompiler_comment| set_comment                    |
| Raw-Befehle                 | -                     | r2_command, r2_script          |
| ROP-Gadgets                 | -                     | shellcode_find_rop_gadgets     |
| ESIL Step/Continue          | -                     | esil_step, esil_continue_until |
| Hexdump                     | -                     | hexdump                        |
| Encoder-Erkennung           | -                     | shellcode_detect_encoder       |

---

## 13. Zukuenftige Erweiterungen

### Phase 2 (geplant)
- **MCP Resources**: Binaerdateien und Session-Zustaende als MCP Resources bereitstellen
- **MCP Prompts**: Vorgefertigte Analyse-Prompts (z.B. "Vulnerability Assessment",
  "Malware Triage")
- **SSE Transport**: Remote-Zugang ueber HTTP
- **Diff-Analyse**: Zwei Binaerdateien vergleichen (radiff2)

### Phase 3 (Vision)
- **YARA-Integration**: YARA-Rules in der Analyse verwenden
- **Automatisierte Malware-Klassifikation**: Heuristische Malware-Erkennung
- **Collaborative Analysis**: Mehrere Analysten arbeiten an derselben Binary
- **r2frida-Integration**: Dynamic Instrumentation fuer laufende Prozesse
