import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { withCachedSession } from '../r2/session-cache.js';
import { sanitizePath } from '../r2/sanitize.js';
import { paginate } from '../utils/pagination.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatStringList } from '../utils/formatters.js';
import type { R2String } from '../types.js';

export function registerListStrings(server: McpServer): void {
  server.tool(
    'list_strings',
    'Extract printable strings from the binary with their addresses, sections, and lengths.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      min_length: z
        .number()
        .int()
        .min(1)
        .default(5)
        .describe('Minimum string length to include'),
      search_all: z
        .boolean()
        .default(false)
        .describe('Search all bytes (izzj) instead of only data sections (izj)'),
      offset: z.number().int().min(0).default(0).describe('Pagination offset (0-based)'),
      limit: z
        .number()
        .int()
        .min(1)
        .max(1000)
        .default(100)
        .describe('Max results to return'),
    },
    async ({ binary_path, min_length, search_all, offset, limit }) => {
      try {
        const safePath = sanitizePath(binary_path);
        return await withCachedSession(safePath, async (session) => {
          const command = search_all ? 'izzj' : 'izj';
          let strings = await session.cmdj<R2String[]>(command);
          if (!Array.isArray(strings)) {
            strings = [];
          }
          strings = strings.filter((s) => s.length >= min_length);
          const page = paginate(strings, offset, limit);
          return mcpFormatted(formatStringList(page));
        });
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
