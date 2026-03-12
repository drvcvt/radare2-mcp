import { randomUUID } from 'node:crypto';
import { RizinSession } from './rizin-session.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maximum idle time before an RzIL session is auto-closed (10 minutes). */
const MAX_IDLE_MS = 10 * 60 * 1000;

/** Maximum number of concurrent RzIL sessions. */
const MAX_SESSIONS = 5;

/** Interval for checking idle sessions (60 seconds). */
const CLEANUP_INTERVAL_MS = 60 * 1000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RzilSessionEntry {
  readonly sessionId: string;
  readonly session: RizinSession;
  readonly binaryPath: string;
  readonly startAddress: string | undefined;
  readonly createdAt: number;
  lastUsed: number;
}

// ---------------------------------------------------------------------------
// RzilSessionManager
// ---------------------------------------------------------------------------

/**
 * Manages persistent RzIL Rizin sessions across multiple MCP tool calls.
 *
 * Sessions preserve RzIL VM state (registers, memory, program counter)
 * between tool invocations, enabling multi-step emulation workflows.
 *
 * Sessions are identified by a UUID returned to the caller on creation.
 */
class RzilSessionManager {
  private sessions: Map<string, RzilSessionEntry> = new Map();
  private cleanupTimer: ReturnType<typeof setInterval> | undefined;

  constructor() {
    this.startCleanup();
  }

  /**
   * Create a new persistent RzIL session.
   *
   * Opens the binary in Rizin, runs analysis, and initializes the RzIL VM.
   */
  async create(
    binaryPath: string,
    options?: {
      address?: string;
      analysisLevel?: string;
    },
  ): Promise<RzilSessionEntry> {
    this.enforceSessionLimit();

    const sessionId = randomUUID();
    const session = await RizinSession.open(binaryPath);

    // Run analysis
    const analysisLevel = options?.analysisLevel ?? 'aaa';
    await session.cmd(analysisLevel);

    // Seek to start address before initializing RzIL
    if (options?.address) {
      await session.cmd(`s ${options.address}`);
    }

    // Initialize RzIL VM at current seek position
    await session.cmd('aezi');

    const entry: RzilSessionEntry = {
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
   * Retrieve an active RzIL session by its ID. Throws if not found.
   */
  get(sessionId: string): RzilSessionEntry {
    const entry = this.sessions.get(sessionId);
    if (!entry) {
      throw new Error(
        `RzIL session "${sessionId}" not found. Active sessions: ${this.sessions.size}`,
      );
    }
    entry.lastUsed = Date.now();
    return entry;
  }

  /**
   * Destroy an RzIL session and close the underlying Rizin process.
   */
  async destroy(sessionId: string): Promise<void> {
    const entry = this.sessions.get(sessionId);
    if (!entry) return;

    await entry.session.close();
    this.sessions.delete(sessionId);
  }

  /**
   * List all active RzIL sessions.
   */
  list(): readonly RzilSessionEntry[] {
    return [...this.sessions.values()];
  }

  /**
   * Close all RzIL sessions (used during server shutdown).
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
        `Maximum RzIL sessions (${MAX_SESSIONS}) reached. Destroy an existing session first.`,
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

/** Global RzIL session manager instance, shared across all RzIL tools. */
export const rzilManager = new RzilSessionManager();
