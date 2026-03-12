import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';

// ---------------------------------------------------------------------------
// Temp file management for shellcode blobs
// ---------------------------------------------------------------------------

/** Prefix used for temp directories created by this module. */
const TEMP_DIR_PREFIX = 'r2mcp-';

/**
 * Write a hex-encoded byte string to a temporary binary file.
 *
 * Creates a unique temp directory under the OS temp folder and writes the
 * decoded bytes to a file named `shellcode.bin` inside it.
 *
 * The caller **must** call {@link cleanupTempFile} in a `finally` block.
 *
 * @param hexBytes - Even-length string of hex characters (e.g. `"90cccc3c"`).
 * @returns The absolute path to the written temp file.
 * @throws If `hexBytes` is not a valid even-length hex string.
 */
export async function writeTempBinary(hexBytes: string): Promise<string> {
  if (!/^[0-9a-fA-F]*$/.test(hexBytes)) {
    throw new Error('hexBytes must contain only hex characters (0-9, a-f, A-F)');
  }

  if (hexBytes.length === 0) {
    throw new Error('hexBytes must not be empty');
  }

  if (hexBytes.length % 2 !== 0) {
    throw new Error('hexBytes must have an even number of characters');
  }

  const buffer = Buffer.from(hexBytes, 'hex');
  const dir = await mkdtemp(join(tmpdir(), TEMP_DIR_PREFIX));
  const filePath = join(dir, 'shellcode.bin');

  await writeFile(filePath, buffer);

  return filePath;
}

/**
 * Delete a temp file and its parent directory.
 *
 * Errors are silently ignored — this is a best-effort cleanup function
 * intended for use in `finally` blocks.
 *
 * @param filePath - The absolute path previously returned by {@link writeTempBinary}.
 */
export async function cleanupTempFile(filePath: string): Promise<void> {
  try {
    // The file lives inside a dedicated temp directory (e.g. /tmp/r2mcp-XXXX/shellcode.bin).
    // Remove the entire directory tree.
    const dir = dirname(filePath);
    if (dir.includes(TEMP_DIR_PREFIX)) {
      await rm(dir, { recursive: true, force: true });
    }
  } catch {
    // Best-effort cleanup — the OS will reclaim temp files eventually.
  }
}
