import { randomUUID } from 'node:crypto';
import { R2Session } from './session.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maximum idle time before an ESIL session is auto-closed (10 minutes). */
const MAX_IDLE_MS = 10 * 60 * 1000;

/** Maximum number of concurrent ESIL sessions. */
const MAX_SESSIONS = 5;

/** Interval for checking idle sessions (60 seconds). */
const CLEANUP_INTERVAL_MS = 60 * 1000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface EsilSessionEntry {
  readonly sessionId: string;
  readonly session: R2Session;
  readonly binaryPath: string;
  readonly startAddress: string | undefined;
  readonly createdAt: number;
  lastUsed: number;
}

// ---------------------------------------------------------------------------
// EsilSessionManager
// ---------------------------------------------------------------------------

/**
 * Manages persistent ESIL R2Sessions across multiple MCP tool calls.
 *
 * Unlike the default ESIL workflow (open, init, run, close per tool call),
 * persistent sessions preserve ESIL VM state (registers, memory, program
 * counter) between tool invocations, enabling multi-step emulation workflows.
 *
 * Sessions are identified by a UUID returned to the caller on creation.
 */
class EsilSessionManager {
  private sessions: Map<string, EsilSessionEntry> = new Map();
  private cleanupTimer: ReturnType<typeof setInterval> | undefined;

  constructor() {
    this.startCleanup();
  }

  /**
   * Create a new persistent ESIL session.
   *
   * Opens the binary, runs analysis, and initializes the ESIL VM with stack
   * memory and program counter.
   */
  async create(
    binaryPath: string,
    options?: {
      address?: string;
      stackAddress?: string;
      stackSize?: number;
      analysisLevel?: string;
    },
  ): Promise<EsilSessionEntry> {
    this.enforceSessionLimit();

    const sessionId = randomUUID();
    const session = await R2Session.open(binaryPath);

    // Run analysis
    const analysisLevel = options?.analysisLevel ?? 'aaa';
    await session.cmd(analysisLevel);

    // Initialize ESIL VM
    await session.cmd('aei');

    const stackAddr = options?.stackAddress ?? '0x00100000';
    const stackSize = options?.stackSize ?? 0x00100000;
    await session.cmd(`aeim ${stackAddr} ${stackSize}`);

    // Set program counter
    if (options?.address) {
      await session.cmd(`aepc ${options.address}`);
    } else {
      await session.cmd('aeip');
    }

    const entry: EsilSessionEntry = {
      sessionId,
      session,
      binaryPath,
      startAddress: options?.address,
      createdAt: Date.now(),
      lastUsed: Date.now(),
    };

    this.sessions.set(sessionId, entry);
    return entry;
  }

  /**
   * Retrieve an active ESIL session by its ID. Throws if not found.
   */
  get(sessionId: string): EsilSessionEntry {
    const entry = this.sessions.get(sessionId);
    if (!entry) {
      throw new Error(
        `ESIL session "${sessionId}" not found. Active sessions: ${this.sessions.size}`,
      );
    }
    entry.lastUsed = Date.now();
    return entry;
  }

  /**
   * Destroy an ESIL session and close the underlying r2 process.
   */
  async destroy(sessionId: string): Promise<void> {
    const entry = this.sessions.get(sessionId);
    if (!entry) return;

    await entry.session.close();
    this.sessions.delete(sessionId);
  }

  /**
   * List all active ESIL sessions.
   */
  list(): readonly EsilSessionEntry[] {
    return [...this.sessions.values()];
  }

  /**
   * Close all ESIL sessions (used during server shutdown).
   */
  async closeAll(): Promise<void> {
    const ids = [...this.sessions.keys()];
    for (const id of ids) {
      await this.destroy(id);
    }
    this.stopCleanup();
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  private enforceSessionLimit(): void {
    if (this.sessions.size >= MAX_SESSIONS) {
      throw new Error(
        `Maximum ESIL sessions (${MAX_SESSIONS}) reached. Destroy an existing session first.`,
      );
    }
  }

  private startCleanup(): void {
    this.cleanupTimer = setInterval(() => {
      void this.cleanupIdleSessions();
    }, CLEANUP_INTERVAL_MS);

    // Allow the Node process to exit even if the timer is active
    if (this.cleanupTimer.unref) {
      this.cleanupTimer.unref();
    }
  }

  private stopCleanup(): void {
    if (this.cleanupTimer !== undefined) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = undefined;
    }
  }

  private async cleanupIdleSessions(): Promise<void> {
    const now = Date.now();
    for (const [id, entry] of this.sessions) {
      if (now - entry.lastUsed > MAX_IDLE_MS) {
        await this.destroy(id);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Singleton export
// ---------------------------------------------------------------------------

/** Global ESIL session manager instance, shared across all ESIL tools. */
export const esilManager = new EsilSessionManager();
