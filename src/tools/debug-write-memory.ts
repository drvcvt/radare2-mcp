import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizeSessionId, sanitizeAddress } from '../r2/sanitize.js';
import { debugManager } from '../r2/debug-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';

/** Validate hex byte string: even length, only hex chars. */
function validateHexBytes(hex: string): string {
  const trimmed = hex.trim();
  if (!/^[0-9a-fA-F]+$/.test(trimmed)) {
    throw new Error(`Invalid hex bytes: must contain only hex characters (0-9, a-f, A-F)`);
  }
  if (trimmed.length % 2 !== 0) {
    throw new Error(`Invalid hex bytes: length must be even (got ${trimmed.length})`);
  }
  return trimmed;
}

export function registerDebugWriteMemory(server: McpServer): void {
  server.tool(
    'debug_write_memory',
    'Write memory in the debugged process at a specific address using hex bytes or a string.',
    {
      session_id: z.string().describe('Debug session ID'),
      address: z.string().describe('Hex address to write to (e.g. "0x08048000")'),
      hex_bytes: z
        .string()
        .optional()
        .describe('Hex bytes to write (e.g. "90909090" for NOPs)'),
      data: z.string().optional().describe('String data to write (used when as_string is true)'),
      as_string: z
        .boolean()
        .default(false)
        .describe('If true, write data as an ASCII string; otherwise write hex_bytes'),
    },
    async ({ session_id, address, hex_bytes, data, as_string }) => {
      try {
        const safeId = sanitizeSessionId(session_id);
        const safeAddr = sanitizeAddress(address);
        const entry = debugManager.get(safeId);

        if (as_string) {
          if (!data) {
            return mcpError('Parameter "data" is required when as_string is true');
          }
          // Reject r2 metacharacters that could chain commands or shell out
          if (/[;|><`$&!#]/.test(data)) {
            return mcpError(
              'String data contains forbidden characters (;|><`$&!#) that could break r2 command parsing.',
            );
          }
          // Use the `w` command to write a string
          await entry.session.cmd(`w ${data} @ ${safeAddr}`);
          const byteCount = Buffer.byteLength(data, 'utf-8');
          return mcpFormatted(
            `## Memory Write\n\nWrote **${byteCount} bytes** (string) to \`${safeAddr}\`\n\n` +
              `Content: \`${data}\``,
          );
        } else {
          if (!hex_bytes) {
            return mcpError(
              'Either "hex_bytes" must be provided, or set "as_string" to true and provide "data"',
            );
          }
          const safeHex = validateHexBytes(hex_bytes);
          // Use the `wx` command to write hex bytes
          await entry.session.cmd(`wx ${safeHex} @ ${safeAddr}`);
          const byteCount = safeHex.length / 2;
          return mcpFormatted(
            `## Memory Write\n\nWrote **${byteCount} bytes** (hex) to \`${safeAddr}\`\n\n` +
              `Hex: \`${safeHex}\``,
          );
        }
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
