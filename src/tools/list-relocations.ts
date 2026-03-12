import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizePath } from '../r2/sanitize.js';
import { withCachedSession } from '../r2/session-cache.js';
import { paginate } from '../utils/pagination.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatRelocationList } from '../utils/formatters.js';
import type { R2Relocation } from '../types.js';

export function registerListRelocations(server: McpServer): void {
  server.tool(
    'list_relocations',
    'List all relocations in the binary with their addresses, types, and target symbols.',
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
          let relocations = await session.cmdj<R2Relocation[]>('irj');
          if (!Array.isArray(relocations)) {
            relocations = [];
          }
          const page = paginate(relocations, offset, limit);
          return mcpFormatted(formatRelocationList(page));
        });
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
