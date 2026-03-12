import { randomUUID } from 'node:crypto';
import { R2Session } from './session.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maximum idle time before a debug session is auto-closed (10 minutes). */
const MAX_IDLE_MS = 10 * 60 * 1000;

/** Maximum number of concurrent debug sessions. */
const MAX_SESSIONS = 5;

/** Interval for checking idle sessions (60 seconds). */
const CLEANUP_INTERVAL_MS = 60 * 1000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface DebugSessionEntry {
  readonly sessionId: string;
  readonly session: R2Session;
  readonly target: string;
  readonly pid: number | undefined;
  readonly attachedAt: number;
  lastUsed: number;
}

// ---------------------------------------------------------------------------
// DebugSessionManager
// ---------------------------------------------------------------------------

/**
 * Manages persistent debug R2Sessions across multiple MCP tool calls.
 *
 * Unlike static analysis sessions (opened and closed per tool call), debug
 * sessions must persist so that breakpoints, register state, and the debugged
 * process survive between tool invocations.
 *
 * Sessions are identified by a UUID returned to the caller on attach/launch.
 */
class DebugSessionManager {
  private sessions: Map<string, DebugSessionEntry> = new Map();
  private cleanupTimer: ReturnType<typeof setInterval> | undefined;

  constructor() {
    this.startCleanup();
  }

  /**
   * Launch a binary under the debugger and return a persistent session.
   */
  async launch(binaryPath: string): Promise<DebugSessionEntry> {
    this.enforceSessionLimit();

    const sessionId = randomUUID();
    const session = await R2Session.open(binaryPath, ['-d', '-2']);

    // Prevent r2 from killing the process when the session closes unexpectedly
    await session.cmd('e dbg.exitkills=false');

    const entry: DebugSessionEntry = {
      sessionId,
      session,
      target: binaryPath,
      pid: await this.queryPid(session),
      attachedAt: Date.now(),
      lastUsed: Date.now(),
    };

    this.sessions.set(sessionId, entry);
    return entry;
  }

  /**
   * Attach to a running process by PID and return a persistent session.
   */
  async attach(pid: number): Promise<DebugSessionEntry> {
    this.enforceSessionLimit();

    const sessionId = randomUUID();
    const session = await R2Session.open(`dbg://${pid}`, ['-2']);

    await session.cmd('e dbg.exitkills=false');

    const entry: DebugSessionEntry = {
      sessionId,
      session,
      target: `dbg://${pid}`,
      pid,
      attachedAt: Date.now(),
      lastUsed: Date.now(),
    };

    this.sessions.set(sessionId, entry);
    return entry;
  }

  /**
   * Retrieve an active debug session by its ID. Throws if not found.
   */
  get(sessionId: string): DebugSessionEntry {
    const entry = this.sessions.get(sessionId);
    if (!entry) {
      throw new Error(
        `Debug session "${sessionId}" not found. Active sessions: ${this.sessions.size}`,
      );
    }
    entry.lastUsed = Date.now();
    return entry;
  }

  /**
   * Detach from the debugged process and close the session.
   * The process continues running after detach.
   */
  async detach(sessionId: string): Promise<void> {
    const entry = this.sessions.get(sessionId);
    if (!entry) return;

    try {
      await entry.session.cmd('dd');
    } catch {
      // Process may already be gone
    }

    await entry.session.close();
    this.sessions.delete(sessionId);
  }

  /**
   * List all active debug sessions.
   */
  list(): readonly DebugSessionEntry[] {
    return [...this.sessions.values()];
  }

  /**
   * Close all debug sessions (used during server shutdown).
   * Detaches cleanly from all processes.
   */
  async closeAll(): Promise<void> {
    const ids = [...this.sessions.keys()];
    for (const id of ids) {
      await this.detach(id);
    }
    this.stopCleanup();
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  private enforceSessionLimit(): void {
    if (this.sessions.size >= MAX_SESSIONS) {
      throw new Error(
        `Maximum debug sessions (${MAX_SESSIONS}) reached. Detach an existing session first.`,
      );
    }
  }

  private async queryPid(session: R2Session): Promise<number | undefined> {
    try {
      const info = await session.cmdj<{ pid?: number }>('dij');
      return info?.pid;
    } catch {
      return undefined;
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
        await this.detach(id);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Singleton export
// ---------------------------------------------------------------------------

/** Global debug session manager instance, shared across all debug tools. */
export const debugManager = new DebugSessionManager();
