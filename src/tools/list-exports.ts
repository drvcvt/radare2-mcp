import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { withCachedSession } from '../r2/session-cache.js';
import { sanitizePath } from '../r2/sanitize.js';
import { paginate } from '../utils/pagination.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatExportList } from '../utils/formatters.js';
import type { R2Export } from '../types.js';

export function registerListExports(server: McpServer): void {
  server.tool(
    'list_exports',
    'List all exported functions and symbols with their addresses and types.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      offset: z.number().int().min(0).default(0).describe('Pagination offset (0-based)'),
      limit: z
        .number()
        .int()
        .min(1)
        .max(1000)
        .default(100)
        .describe('Max results to return'),
    },
    async ({ binary_path, offset, limit }) => {
      try {
        const safePath = sanitizePath(binary_path);
        return await withCachedSession(safePath, async (session) => {
          let exports = await session.cmdj<R2Export[]>('iEj');
          if (!Array.isArray(exports)) {
            exports = [];
          }
          const page = paginate(exports, offset, limit);
          return mcpFormatted(formatExportList(page));
        });
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
