import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { withCachedSession } from '../r2/session-cache.js';
import { sanitizePath, sanitizeAddress } from '../r2/sanitize.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatHashResult } from '../utils/formatters.js';

export function registerHashBinary(server: McpServer): void {
  server.tool(
    'hash_binary',
    'Compute cryptographic hashes of the binary or a specific address range.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      algorithm: z
        .enum(['md5', 'sha1', 'sha256', 'crc32'])
        .default('sha256')
        .describe('Hash algorithm to use'),
      address: z
        .string()
        .regex(/^(0x)?[0-9a-fA-F]+$/, 'Must be a hex address (e.g. "0x08048000")')
        .optional()
        .describe('Start address for range hash (requires size)'),
      size: z
        .number()
        .int()
        .min(1)
        .max(104857600)
        .optional()
        .describe('Number of bytes to hash from address'),
    },
    async ({ binary_path, algorithm, address, size }) => {
      try {
        const safePath = sanitizePath(binary_path);
        return await withCachedSession(safePath, async (session) => {
          let hash: string;
          let mode: string;

          if (address !== undefined && size !== undefined) {
            // Hash a specific range
            const safeAddr = sanitizeAddress(address);
            const result = await session.cmd(`ph ${algorithm} ${size} @ ${safeAddr}`);
            hash = result.trim();
            mode = `range ${safeAddr} (${size} bytes)`;
          } else if (address !== undefined && size === undefined) {
            return mcpError('Both address and size are required for range hashing');
          } else {
            // Hash entire file using r2 command
            // Get file size from binary info
            const info = await session.cmdj<{ core?: { size?: number } }>('ij');
            const fileSize = info?.core?.size;
            if (fileSize === undefined || fileSize <= 0) {
              return mcpError('Could not determine file size');
            }
            const result = await session.cmd(`ph ${algorithm} ${fileSize} @ 0`);
            hash = result.trim();
            mode = 'entire file';
          }

          return mcpFormatted(
            formatHashResult({
              algorithm,
              hash,
              mode,
              binary_path: safePath,
            }),
          );
        });
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
