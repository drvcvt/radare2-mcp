import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { withCachedSession } from '../r2/session-cache.js';
import { sanitizePath } from '../r2/sanitize.js';
import { paginate } from '../utils/pagination.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatSectionList } from '../utils/formatters.js';
import type { R2Section } from '../types.js';

export function registerListSections(server: McpServer): void {
  server.tool(
    'list_sections',
    'List all sections and segments in the binary with addresses, sizes, and permissions.',
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
          let sections = await session.cmdj<R2Section[]>('iSj');
          if (!Array.isArray(sections)) {
            sections = [];
          }
          const page = paginate(sections, offset, limit);
          return mcpFormatted(formatSectionList(page));
        });
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
