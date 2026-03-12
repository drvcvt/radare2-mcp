import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { withCachedSession } from '../r2/session-cache.js';
import { sanitizePath } from '../r2/sanitize.js';
import { paginate } from '../utils/pagination.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatFunctionList } from '../utils/formatters.js';
import type { R2Function } from '../types.js';

export function registerListFunctions(server: McpServer): void {
  server.tool(
    'list_functions',
    'List all functions identified by radare2 analysis with their names, addresses, sizes, and call conventions.',
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
      filter: z
        .string()
        .optional()
        .describe('Optional substring to filter function names'),
      sort_by: z
        .enum(['address', 'size', 'name'])
        .default('address')
        .describe('Sort functions by address, size, or name'),
    },
    async ({ binary_path, offset, limit, filter, sort_by }) => {
      try {
        const safePath = sanitizePath(binary_path);
        return await withCachedSession(safePath, async (session) => {
          let functions = await session.cmdj<R2Function[]>('aflj');
          if (!Array.isArray(functions)) {
            functions = [];
          }
          if (filter) {
            const lowerFilter = filter.toLowerCase();
            functions = functions.filter(
              (fn) => fn.name && fn.name.toLowerCase().includes(lowerFilter),
            );
          }
          if (sort_by === 'size') {
            functions = [...functions].sort((a, b) => (b.size ?? 0) - (a.size ?? 0));
          } else if (sort_by === 'name') {
            functions = [...functions].sort((a, b) =>
              (a.name ?? '').localeCompare(b.name ?? ''),
            );
          }
          // sort_by === 'address' is the default order from aflj
          const page = paginate(functions, offset, limit);
          return mcpFormatted(formatFunctionList(page));
        });
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
