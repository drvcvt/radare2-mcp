import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { withR2Session } from '../r2/session.js';
import { sanitizePath, sanitizeAddress } from '../r2/sanitize.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatReadBytes } from '../utils/formatters.js';

export function registerReadBytes(server: McpServer): void {
  server.tool(
    'read_bytes',
    'Read raw bytes from a specific address in the binary, returned as hex string or formatted hexdump.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      address: z.string().describe('Hex address (e.g. "0x08048000")'),
      count: z
        .number()
        .int()
        .min(1)
        .max(65536)
        .default(64)
        .describe('Number of bytes to read'),
      format: z
        .enum(['hex', 'hexdump'])
        .default('hex')
        .describe('Output format: "hex" for raw hex string, "hexdump" for formatted hexdump'),
    },
    async ({ binary_path, address, count, format }) => {
      try {
        const safePath = sanitizePath(binary_path);
        const safeAddr = sanitizeAddress(address);
        return await withR2Session(
          safePath,
          async (session) => {
            // No analysis needed for raw byte reads
            await session.cmd(`s ${safeAddr}`);
            const command = format === 'hex' ? `p8 ${count}` : `px ${count}`;
            const data = await session.cmd(command);
            return mcpFormatted(formatReadBytes({
              address: safeAddr,
              count,
              format,
              data: data.trim(),
            }));
          },
          ['-2', '-n'],
        );
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
