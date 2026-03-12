import { spawn, ChildProcess } from 'node:child_process';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_TIMEOUT = Number(process.env['RIZIN_COMMAND_TIMEOUT']) || 30_000;

/** Null byte used as response delimiter in rizin's -q0 protocol. */
const NULL_BYTE = 0x00;

/**
 * Resolve the rizin executable path.
 * Checks RIZIN_PATH env var, then common install locations, then falls back
 * to bare `rizin` (relies on PATH).
 */
function resolveRizinPath(): string {
  if (process.env['RIZIN_PATH']) {
    return process.env['RIZIN_PATH'];
  }
  // On Windows, winget installs to Program Files
  if (process.platform === 'win32') {
    return 'C:/Program Files/rizin/bin/rizin.exe';
  }
  return 'rizin';
}

const RIZIN_BIN = resolveRizinPath();

// ---------------------------------------------------------------------------
// RizinSession
// ---------------------------------------------------------------------------

/**
 * Wraps a Rizin process using the `-q0` protocol:
 *   - Commands are sent as newline-terminated strings (`cmd\n`)
 *   - Responses are null-byte-terminated (`output\0`)
 *
 * This differs from r2pipe where both directions use null bytes.
 * Always call {@link close} when finished.
 */
export class RizinSession {
  private proc: ChildProcess;
  private closed = false;

  /** Pending command resolve/reject callbacks. */
  private pending: {
    resolve: (output: string) => void;
    reject: (err: Error) => void;
  } | null = null;

  /** Buffer for accumulating stdout data between null-byte delimiters. */
  private buffer: Buffer = Buffer.alloc(0);

  private constructor(proc: ChildProcess) {
    this.proc = proc;

    proc.stdout!.on('data', (chunk: Buffer) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      this.drainBuffer();
    });

    proc.stderr!.on('data', () => {
      // Swallow stderr — Rizin prints warnings here
    });

    proc.on('error', (err) => {
      if (this.pending) {
        this.pending.reject(new Error(`Rizin process error: ${err.message}`));
        this.pending = null;
      }
    });

    proc.on('exit', (code) => {
      this.closed = true;
      if (this.pending) {
        this.pending.reject(new Error(`Rizin process exited unexpectedly (code ${code})`));
        this.pending = null;
      }
    });
  }

  /**
   * Open a binary in a new Rizin process and return a session handle.
   *
   * @param binaryPath - Absolute path to the binary file.
   * @param flags      - Extra flags passed to the Rizin process.
   */
  static async open(binaryPath: string, flags: readonly string[] = []): Promise<RizinSession> {
    const args = ['-q0', ...flags, binaryPath];
    const proc = spawn(RIZIN_BIN, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });

    return new Promise<RizinSession>((resolve, reject) => {
      const session = new RizinSession(proc);

      const onError = (err: Error): void => {
        reject(new Error(`Failed to start Rizin for "${binaryPath}": ${err.message}`));
      };

      const onExit = (code: number | null): void => {
        reject(
          new Error(`Rizin exited before ready (code ${code}). Is rizin installed? Set RIZIN_PATH if not in default location.`),
        );
      };

      // Wait for the initial null byte prompt
      const initHandler = (chunk: Buffer): void => {
        session.buffer = Buffer.concat([session.buffer, chunk]);
        const idx = session.buffer.indexOf(NULL_BYTE);
        if (idx !== -1) {
          // Consume the initial prompt
          session.buffer = session.buffer.subarray(idx + 1);
          proc.stdout!.removeListener('data', initHandler);
          proc.removeListener('error', onError);
          proc.removeListener('exit', onExit);
          // Re-attach the main data handler
          proc.stdout!.on('data', (c: Buffer) => {
            session.buffer = Buffer.concat([session.buffer, c]);
            session.drainBuffer();
          });
          resolve(session);
        }
      };

      // Replace the default data handler temporarily
      proc.stdout!.removeAllListeners('data');
      proc.stdout!.on('data', initHandler);
      proc.once('error', onError);
      proc.once('exit', onExit);
    });
  }

  /**
   * Execute a Rizin command and return the raw string output.
   *
   * Rizin -q0 protocol: send command with newline terminator,
   * receive response with null-byte terminator.
   *
   * @param command   - The Rizin command to execute (e.g. `"aaa"`, `"aflj"`).
   * @param timeoutMs - Maximum time in milliseconds to wait.
   */
  async cmd(command: string, timeoutMs: number = DEFAULT_TIMEOUT): Promise<string> {
    if (this.closed) {
      throw new Error('RizinSession is closed');
    }

    if (this.pending) {
      throw new Error('RizinSession: another command is already in progress');
    }

    let timer: ReturnType<typeof setTimeout>;
    const timeoutPromise = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => reject(new Error(`Rizin command timed out after ${timeoutMs}ms: ${command}`)),
        timeoutMs,
      );
    });

    const cmdPromise = new Promise<string>((resolve, reject) => {
      this.pending = { resolve, reject };
      // Rizin -q0 expects newline-terminated commands (not null-byte)
      this.proc.stdin!.write(command + '\n');
    });

    try {
      return await Promise.race([cmdPromise, timeoutPromise]);
    } finally {
      clearTimeout(timer!);
    }
  }

  /**
   * Execute a Rizin command and parse the JSON output.
   */
  async cmdj<T = unknown>(command: string, timeoutMs: number = DEFAULT_TIMEOUT): Promise<T> {
    const raw = await this.cmd(command, timeoutMs);
    const trimmed = raw.trim();

    if (trimmed === '') {
      return [] as unknown as T;
    }

    try {
      return JSON.parse(trimmed) as T;
    } catch {
      throw new Error(
        `Failed to parse JSON from Rizin command "${command}": ${trimmed.slice(0, 200)}`,
      );
    }
  }

  /**
   * Close the underlying Rizin process. Idempotent.
   */
  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;

    try {
      // Send quit command (newline-terminated)
      this.proc.stdin!.write('q\n');
      this.proc.stdin!.end();
    } catch {
      // Swallow errors during cleanup
    }

    // Force kill if still alive after 2 seconds
    setTimeout(() => {
      try {
        this.proc.kill('SIGKILL');
      } catch {
        // Already dead
      }
    }, 2000).unref();
  }

  /** Whether this session has been closed. */
  get isClosed(): boolean {
    return this.closed;
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /**
   * Drain accumulated buffer, resolving the pending command if a null byte
   * delimiter is found.
   */
  private drainBuffer(): void {
    if (!this.pending) return;

    const idx = this.buffer.indexOf(NULL_BYTE);
    if (idx === -1) return;

    const output = this.buffer.subarray(0, idx).toString('utf-8');
    this.buffer = this.buffer.subarray(idx + 1);

    const { resolve } = this.pending;
    this.pending = null;
    resolve(output);
  }
}
