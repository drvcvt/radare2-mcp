import r2pipe from 'r2pipe';

// ---------------------------------------------------------------------------
// r2pipe callback-style type declarations
// r2pipe does not ship @types, so we declare the shapes we rely on.
// ---------------------------------------------------------------------------

type R2CmdCallback = (err: Error | null, output: string) => void;

interface R2PipeInstance {
  cmd(command: string, callback: R2CmdCallback): void;
  quit(): void;
}

type R2OpenCallback = (err: Error | null, r2: R2PipeInstance) => void;

interface R2PipeModule {
  open(path: string, callback: R2OpenCallback): void;
  open(path: string, flags: readonly string[], callback: R2OpenCallback): void;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_TIMEOUT = Number(process.env['R2_COMMAND_TIMEOUT']) || 30_000;

// ---------------------------------------------------------------------------
// R2Session
// ---------------------------------------------------------------------------

/**
 * Wraps an r2pipe instance with a Promise-based API, per-command timeouts, and
 * explicit lifecycle management. Always call {@link close} when finished —
 * prefer {@link withR2Session} for automatic cleanup.
 */
export class R2Session {
  private r2: R2PipeInstance;
  private closed = false;

  private constructor(r2: R2PipeInstance) {
    this.r2 = r2;
  }

  /**
   * Open a binary in a new r2 process and return a session handle.
   *
   * @param binaryPath - Absolute path to the binary file.
   * @param flags      - Flags passed to the r2 process (default: `['-2']` to suppress stderr).
   */
  static async open(
    binaryPath: string,
    flags: readonly string[] = ['-2'],
  ): Promise<R2Session> {
    return new Promise<R2Session>((resolve, reject) => {
      const r2mod = r2pipe as unknown as R2PipeModule;
      r2mod.open(binaryPath, flags, (err: Error | null, r2: R2PipeInstance) => {
        if (err) {
          reject(new Error(`Failed to open r2 session for "${binaryPath}": ${err.message}`));
          return;
        }
        resolve(new R2Session(r2));
      });
    });
  }

  /**
   * Execute an r2 command and return the raw string output.
   *
   * @param command   - The r2 command to execute (e.g. `"aaa"`, `"aflj"`).
   * @param timeoutMs - Maximum time in milliseconds to wait (default from env or 30 000).
   * @throws If the session is closed, the command errors, or the timeout elapses.
   */
  async cmd(command: string, timeoutMs: number = DEFAULT_TIMEOUT): Promise<string> {
    if (this.closed) {
      throw new Error('R2Session is closed');
    }

    let timer: ReturnType<typeof setTimeout>;
    const timeoutPromise = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => reject(new Error(`r2 command timed out after ${timeoutMs}ms: ${command}`)),
        timeoutMs,
      );
    });

    try {
      return await Promise.race([
        new Promise<string>((resolve, reject) => {
          this.r2.cmd(command, (err: Error | null, output: string) => {
            if (err) {
              reject(new Error(`r2 command failed (${command}): ${err.message}`));
              return;
            }
            resolve(output ?? '');
          });
        }),
        timeoutPromise,
      ]);
    } finally {
      clearTimeout(timer!);
    }
  }

  /**
   * Execute an r2 command and parse the JSON output.
   *
   * @param command   - The r2 command to execute (should produce JSON, e.g. `"aflj"`).
   * @param timeoutMs - Maximum time in milliseconds to wait.
   * @returns Parsed JSON value narrowed to `T` by the caller.
   * @throws If the output is empty, not valid JSON, or the command fails.
   */
  async cmdj<T = unknown>(command: string, timeoutMs: number = DEFAULT_TIMEOUT): Promise<T> {
    const raw = await this.cmd(command, timeoutMs);
    const trimmed = raw.trim();

    if (trimmed === '') {
      // Many r2 JSON commands return empty string when there are no results.
      // Return an empty array as a safe default for list-style commands.
      return [] as unknown as T;
    }

    try {
      return JSON.parse(trimmed) as T;
    } catch {
      throw new Error(
        `Failed to parse JSON from r2 command "${command}": ${trimmed.slice(0, 200)}`,
      );
    }
  }

  /**
   * Close the underlying r2 process. Idempotent — safe to call multiple times.
   */
  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;

    try {
      this.r2.quit();
    } catch {
      // Swallow errors during cleanup — the process may already be gone.
    }
  }

  /** Whether this session has been closed. */
  get isClosed(): boolean {
    return this.closed;
  }
}

// ---------------------------------------------------------------------------
// withR2Session helper
// ---------------------------------------------------------------------------

/**
 * Open a binary, run a callback, and guarantee the session is closed afterward.
 *
 * @param binaryPath - Absolute path to the binary file (must already be sanitized).
 * @param fn         - Async function that receives the open session.
 * @param flags      - Flags passed to the r2 process.
 * @returns The value returned by `fn`.
 */
export async function withR2Session<T>(
  binaryPath: string,
  fn: (session: R2Session) => Promise<T>,
  flags: readonly string[] = ['-2'],
): Promise<T> {
  const session = await R2Session.open(binaryPath, flags);
  try {
    return await fn(session);
  } finally {
    await session.close();
  }
}
