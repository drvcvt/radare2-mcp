import { existsSync, lstatSync, realpathSync } from 'node:fs';
import path from 'node:path';

// ---------------------------------------------------------------------------
// Regex patterns
// ---------------------------------------------------------------------------

/** Characters that could be used for shell injection or r2 command chaining. */
const SHELL_METACHAR_RE = /[;|><`$&!#(){}[\]'"\\]/;

/** Valid hex address with optional 0x prefix. */
const ADDRESS_RE = /^(0x)?[0-9a-fA-F]+$/;

/** Valid function name: starts with letter or underscore, may contain ., :, -. */
const FUNCTION_NAME_RE = /^[a-zA-Z_][a-zA-Z0-9_.:-]*$/;

/**
 * Characters that are dangerous in r2 commands.
 * Semicolon chains commands, pipe redirects, backtick executes, bang shells out, tilde filters.
 */
const DANGEROUS_CMD_RE = /[;|><`!~]/;

/** The `#!` sequence invokes r2 lang plugins – always reject. */
const HASHBANG_RE = /#!/;

// ---------------------------------------------------------------------------
// Sanitization functions
// ---------------------------------------------------------------------------

/**
 * Validate and normalize a hex address string.
 *
 * @param address - User-provided address (e.g. `"0x08048000"` or `"08048000"`).
 * @returns The trimmed, validated address.
 * @throws If the address contains non-hex characters or shell metacharacters.
 */
export function sanitizeAddress(address: string): string {
  if (!address || typeof address !== 'string') {
    throw new Error('Address is required');
  }

  const trimmed = address.trim();

  if (!ADDRESS_RE.test(trimmed)) {
    throw new Error(
      `Invalid address format: ${trimmed}. Expected hex address (e.g. "0x08048000")`,
    );
  }

  return trimmed;
}

/**
 * Validate and resolve a file system path for opening with r2.
 *
 * - Rejects shell metacharacters.
 * - Resolves to an absolute path.
 * - Checks the `ALLOWED_DIRS` environment variable if set.
 * - Verifies the file exists on disk.
 *
 * @param inputPath - User-provided binary path.
 * @returns The resolved, validated absolute path.
 * @throws If the path is invalid, contains forbidden characters, is outside
 *         allowed directories, or does not exist.
 */
export function sanitizePath(inputPath: string): string {
  if (!inputPath || typeof inputPath !== 'string') {
    throw new Error('Binary path is required');
  }

  // Normalize backslashes to forward slashes before the metachar check so that
  // Windows-style paths (C:\Users\...) are accepted.  path.resolve() handles
  // both separator styles on Windows, so the normalized copy is only used for
  // the regex test; the original string is still passed to path.resolve().
  const normalizedForCheck = inputPath.replace(/\\/g, '/');
  if (SHELL_METACHAR_RE.test(normalizedForCheck)) {
    throw new Error(`Path contains forbidden characters: ${inputPath}`);
  }

  const resolved = path.resolve(inputPath);

  if (!existsSync(resolved)) {
    throw new Error(`File does not exist: ${resolved}`);
  }

  // Check if the file is a symlink; if so, resolve the real path
  let realPath = resolved;
  try {
    const stat = lstatSync(resolved);
    if (stat.isSymbolicLink()) {
      realPath = realpathSync(resolved);
    }
  } catch {
    throw new Error(`Cannot stat file: ${resolved}`);
  }

  const allowedDirs = process.env['ALLOWED_DIRS'];
  if (allowedDirs) {
    const dirs = allowedDirs.split(',').map((d) => path.resolve(d.trim()));
    // Check both the resolved path and the real path (symlink target) are within allowed dirs.
    // Use dir + path.sep to prevent prefix matching (e.g. /binaries-evil matching /binaries).
    const isWithinDir = (filePath: string, dir: string): boolean =>
      filePath === dir || filePath.startsWith(dir + path.sep);
    const isAllowed = dirs.some(
      (dir) => isWithinDir(resolved, dir) && isWithinDir(realPath, dir),
    );
    if (!isAllowed) {
      throw new Error(`Path is outside allowed directories: ${resolved}`);
    }
  }

  return resolved;
}

/**
 * Validate an r2 command string, rejecting anything that could chain commands,
 * redirect output, or escape to a shell.
 *
 * @param cmd - The r2 command to validate (e.g. `"aflj"`, `"pdfj @ main"`).
 * @returns The trimmed, validated command.
 * @throws If the command contains dangerous characters or sequences.
 */
export function sanitizeCommand(cmd: string): string {
  if (!cmd || typeof cmd !== 'string') {
    throw new Error('Command is required');
  }

  const trimmed = cmd.trim();

  if (trimmed.length === 0) {
    throw new Error('Command must not be empty');
  }

  if (DANGEROUS_CMD_RE.test(trimmed)) {
    throw new Error(
      `Command contains forbidden characters (;|><\`!~): ${trimmed}`,
    );
  }

  if (HASHBANG_RE.test(trimmed)) {
    throw new Error(`Command contains forbidden sequence (#!): ${trimmed}`);
  }

  return trimmed;
}

/**
 * Validate a function name, allowing alphanumeric characters, underscores,
 * dots, colons, and hyphens.
 *
 * @param name - User-provided function name.
 * @returns The trimmed, validated function name.
 * @throws If the name contains invalid characters.
 */
export function sanitizeFunctionName(name: string): string {
  if (!name || typeof name !== 'string') {
    throw new Error('Function name is required');
  }

  const trimmed = name.trim();

  if (!FUNCTION_NAME_RE.test(trimmed)) {
    throw new Error(
      `Invalid function name: ${trimmed}. ` +
        'Must start with a letter or underscore and contain only ' +
        'alphanumeric characters, dots, colons, or hyphens.',
    );
  }

  return trimmed;
}

/**
 * Validate a numeric value is within the given bounds (inclusive).
 *
 * @param value - The number to validate.
 * @param min   - Minimum allowed value (inclusive).
 * @param max   - Maximum allowed value (inclusive).
 * @returns The validated number.
 * @throws If the value is outside the bounds or not a finite number.
 */
export function sanitizeNumber(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) {
    throw new Error(`Value must be a finite number, got: ${String(value)}`);
  }

  if (value < min || value > max) {
    throw new Error(`Value ${value} is out of range [${min}, ${max}]`);
  }

  return value;
}

/**
 * Sanitize a search query string by stripping characters that could break r2
 * command parsing or enable command injection.
 *
 * @param query - User-provided search query.
 * @returns The sanitized query.
 * @throws If the query is empty or empty after sanitization.
 */
export function sanitizeSearchQuery(query: string): string {
  if (!query || typeof query !== 'string') {
    throw new Error('Search query is required');
  }

  // Strip null bytes that could cause truncation
  const sanitized = query.replace(/\0/g, '').replace(/[;|><`$&!#\\]/g, '');
  if (sanitized.length === 0) {
    throw new Error('Search query is empty after sanitization');
  }

  return sanitized;
}

/**
 * Encode a comment string as base64 for safe use with r2's `CCa` command.
 * This preserves all characters (including `$`, `#`, `;`, etc.) without
 * silent stripping.
 *
 * @param comment - User-provided comment text.
 * @returns The base64-encoded comment string.
 * @throws If the comment is empty.
 */
export function sanitizeComment(comment: string): string {
  if (!comment || typeof comment !== 'string') {
    throw new Error('Comment is required');
  }

  const trimmed = comment.trim();
  if (trimmed.length === 0) {
    throw new Error('Comment must not be empty');
  }

  return Buffer.from(trimmed, 'utf-8').toString('base64');
}

// ---------------------------------------------------------------------------
// Debug-specific sanitization
// ---------------------------------------------------------------------------

/** Valid UUID v4 pattern for debug session IDs. */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Validate a process ID (PID).
 *
 * @param pid - User-provided PID value.
 * @returns The validated PID as a number.
 * @throws If the PID is not a positive integer.
 */
export function sanitizePid(pid: number): number {
  if (!Number.isFinite(pid) || !Number.isInteger(pid) || pid <= 0) {
    throw new Error(`Invalid PID: ${pid}. Must be a positive integer.`);
  }
  return pid;
}

/**
 * Validate a debug session UUID.
 *
 * @param sessionId - User-provided session ID.
 * @returns The validated session ID string.
 * @throws If the session ID is not a valid UUID v4.
 */
export function sanitizeSessionId(sessionId: string): string {
  if (!sessionId || typeof sessionId !== 'string') {
    throw new Error('Session ID is required');
  }

  const trimmed = sessionId.trim();

  if (!UUID_RE.test(trimmed)) {
    throw new Error(`Invalid session ID format: ${trimmed}. Expected UUID v4.`);
  }

  return trimmed;
}

/**
 * Validate a register name for debug commands.
 *
 * @param name - User-provided register name (e.g. "rax", "eip", "rflags").
 * @returns The validated register name.
 * @throws If the name contains invalid characters.
 */
export function sanitizeRegisterName(name: string): string {
  if (!name || typeof name !== 'string') {
    throw new Error('Register name is required');
  }

  const trimmed = name.trim().toLowerCase();

  if (!/^[a-z][a-z0-9_]*$/.test(trimmed)) {
    throw new Error(
      `Invalid register name: ${trimmed}. Must start with a letter and contain only alphanumeric characters or underscores.`,
    );
  }

  return trimmed;
}
