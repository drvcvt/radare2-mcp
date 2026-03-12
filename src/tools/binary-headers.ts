import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { withCachedSession } from '../r2/session-cache.js';
import { sanitizePath } from '../r2/sanitize.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatBinaryHeaders } from '../utils/formatters.js';
import type { R2Header } from '../types.js';

export function registerBinaryHeaders(server: McpServer): void {
  server.tool(
    'binary_headers',
    'Show PE/ELF/Mach-O headers with detailed field information.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
    },
    async ({ binary_path }) => {
      try {
        const safePath = sanitizePath(binary_path);
        return await withCachedSession(safePath, async (session) => {
          const headers = await session.cmdj<R2Header[]>('ihj');
          const headerList = Array.isArray(headers) ? headers : [];
          return mcpFormatted(formatBinaryHeaders(headerList));
        });
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
