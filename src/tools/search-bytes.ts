import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { withCachedSession } from '../r2/session-cache.js';
import { sanitizePath } from '../r2/sanitize.js';
import { paginate } from '../utils/pagination.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatSearchResults } from '../utils/formatters.js';

interface R2SearchHit {
  readonly offset: number;
  readonly type: string;
  readonly data: string;
}

export function registerSearchBytes(server: McpServer): void {
  server.tool(
    'search_bytes',
    'Search for a hex byte pattern across the binary and return all matching addresses.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      pattern: z
        .string()
        .regex(/^[0-9a-fA-F.]+$/, 'Must be a hex byte pattern (e.g. "90909090" or "90..90")')
        .describe('Hex byte pattern to search for, dots (..) as wildcards'),
      offset: z.number().int().min(0).default(0).describe('Pagination offset (0-based)'),
      limit: z
        .number()
        .int()
        .min(1)
        .max(2000)
        .default(100)
        .describe('Max results to return'),
    },
    async ({ binary_path, pattern, offset, limit }) => {
      try {
        const safePath = sanitizePath(binary_path);
        return await withCachedSession(safePath, async (session) => {
          const hits = await session.cmdj<R2SearchHit[]>(`/xj ${pattern}`);
          const results = Array.isArray(hits) ? hits : [];

          const mapped = results.map((hit) => ({
            address: `0x${hit.offset.toString(16)}`,
            offset_in_file: hit.offset,
            data: hit.data,
          }));

          const page = paginate(mapped, offset, limit);
          return mcpFormatted(formatSearchResults(page, 'byte pattern'));
        });
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
