import { R2Session } from './session.js';

// ---------------------------------------------------------------------------
// Session Cache — avoids re-running `aaa` on the same binary across tool calls
// ---------------------------------------------------------------------------

interface CachedSession {
  session: R2Session;
  lastUsed: number;
  analysisLevel: string;
}

const DEFAULT_MAX_AGE_MS = 5 * 60 * 1000; // 5 minutes
const CLEANUP_INTERVAL_MS = 60 * 1000; // Check for stale sessions every minute
const MAX_CACHED_SESSIONS = 5;

class SessionCache {
  private readonly cache = new Map<string, CachedSession>();
  private readonly pendingCreations = new Map<string, Promise<R2Session>>();
  private readonly maxAgeMs: number;
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor(maxAgeMs: number = DEFAULT_MAX_AGE_MS) {
    this.maxAgeMs = maxAgeMs;
    this.startCleanup();
  }

  /**
   * Get or create a cached R2 session for a binary.
   * If a cached session exists and is still fresh, reuses it.
   * Otherwise opens a new session and runs analysis.
   */
  async getSession(
    binaryPath: string,
    analysisLevel = 'aaa',
  ): Promise<R2Session> {
    const key = `${binaryPath}::${analysisLevel}`;
    const cached = this.cache.get(key);

    if (cached && !cached.session.isClosed && Date.now() - cached.lastUsed < this.maxAgeMs) {
      cached.lastUsed = Date.now();
      return cached.session;
    }

    // If another call is already creating a session for this key, await it
    const pending = this.pendingCreations.get(key);
    if (pending) {
      return pending;
    }

    const creationPromise = (async (): Promise<R2Session> => {
      // Close stale cached session if it exists
      if (cached) {
        await this.closeEntry(key, cached);
      }

      // Evict oldest if at capacity
      if (this.cache.size >= MAX_CACHED_SESSIONS) {
        await this.evictOldest();
      }

      const session = await R2Session.open(binaryPath);
      await session.cmd(analysisLevel);

      this.cache.set(key, {
        session,
        lastUsed: Date.now(),
        analysisLevel,
      });

      return session;
    })();

    this.pendingCreations.set(key, creationPromise);
    try {
      return await creationPromise;
    } finally {
      this.pendingCreations.delete(key);
    }
  }

  /**
   * Explicitly release a session back (marks it as recently used).
   * Does NOT close the session — it stays cached.
   */
  touch(binaryPath: string, analysisLevel = 'aaa'): void {
    const key = `${binaryPath}::${analysisLevel}`;
    const cached = this.cache.get(key);
    if (cached) {
      cached.lastUsed = Date.now();
    }
  }

  /** Close and remove all cached sessions. */
  async closeAll(): Promise<void> {
    const entries = [...this.cache.entries()];
    this.cache.clear();
    for (const [, entry] of entries) {
      try {
        if (!entry.session.isClosed) {
          await entry.session.close();
        }
      } catch {
        // Swallow errors during cleanup
      }
    }
    this.stopCleanup();
  }

  /** Remove and close a cached session by its cache key. */
  async remove(key: string): Promise<void> {
    const entry = this.cache.get(key);
    if (entry) {
      await this.closeEntry(key, entry);
    }
  }

  /** Remove and close a cached session by binary path and analysis level. */
  async removeByPath(binaryPath: string, analysisLevel = 'aaa'): Promise<void> {
    const key = `${binaryPath}::${analysisLevel}`;
    await this.remove(key);
  }

  /** Number of currently cached sessions. */
  get size(): number {
    return this.cache.size;
  }

  // -------------------------------------------------------------------------
  // Internal
  // -------------------------------------------------------------------------

  private async evictOldest(): Promise<void> {
    let oldestKey: string | null = null;
    let oldestTime = Infinity;

    for (const [key, entry] of this.cache) {
      if (entry.lastUsed < oldestTime) {
        oldestTime = entry.lastUsed;
        oldestKey = key;
      }
    }

    if (oldestKey) {
      const entry = this.cache.get(oldestKey);
      if (entry) {
        await this.closeEntry(oldestKey, entry);
      }
    }
  }

  private async closeEntry(key: string, entry: CachedSession): Promise<void> {
    this.cache.delete(key);
    try {
      if (!entry.session.isClosed) {
        await entry.session.close();
      }
    } catch {
      // Swallow errors during cleanup
    }
  }

  private startCleanup(): void {
    this.cleanupTimer = setInterval(() => {
      void this.cleanupStale();
    }, CLEANUP_INTERVAL_MS);
    // Don't keep the process alive just for cleanup
    if (this.cleanupTimer && typeof this.cleanupTimer === 'object' && 'unref' in this.cleanupTimer) {
      this.cleanupTimer.unref();
    }
  }

  private stopCleanup(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }

  private async cleanupStale(): Promise<void> {
    const now = Date.now();
    const staleKeys: string[] = [];

    for (const [key, entry] of this.cache) {
      if (entry.session.isClosed || now - entry.lastUsed > this.maxAgeMs) {
        staleKeys.push(key);
      }
    }

    for (const key of staleKeys) {
      const entry = this.cache.get(key);
      if (entry) {
        await this.closeEntry(key, entry);
      }
    }
  }
}

/** Global session cache singleton. */
export const sessionCache = new SessionCache();

/**
 * Run a function with a cached R2 session. The session is NOT closed after
 * the callback — it stays in the cache for reuse. If the session errors,
 * it is evicted from the cache.
 */
export async function withCachedSession<T>(
  binaryPath: string,
  fn: (session: R2Session) => Promise<T>,
  analysisLevel = 'aaa',
): Promise<T> {
  const session = await sessionCache.getSession(binaryPath, analysisLevel);
  try {
    const result = await fn(session);
    sessionCache.touch(binaryPath, analysisLevel);
    return result;
  } catch (error) {
    // On error, the session might be in a bad state — evict it from the cache
    try {
      await sessionCache.removeByPath(binaryPath, analysisLevel);
    } catch {
      // Swallow cleanup errors
    }
    throw error;
  }
}
