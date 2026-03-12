import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { withCachedSession } from '../r2/session-cache.js';
import { sanitizePath, sanitizeAddress } from '../r2/sanitize.js';
import { paginate } from '../utils/pagination.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatXrefs } from '../utils/formatters.js';
import type { R2Xref } from '../types.js';

export function registerGetXrefs(server: McpServer): void {
  server.tool(
    'get_xrefs',
    'Get all cross-references to or from a specific address, identifying callers, callees, and data references.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      address: z.string().describe('Hex address (e.g. "0x08048000")'),
      direction: z
        .enum(['to', 'from'])
        .default('to')
        .describe('Direction of cross-references: "to" (who references this) or "from" (what this references)'),
      offset: z.number().int().min(0).default(0).describe('Pagination offset (0-based)'),
      limit: z
        .number()
        .int()
        .min(1)
        .max(1000)
        .default(100)
        .describe('Max results to return'),
    },
    async ({ binary_path, address, direction, offset, limit }) => {
      try {
        const safePath = sanitizePath(binary_path);
        const safeAddr = sanitizeAddress(address);
        return await withCachedSession(safePath, async (session) => {
          const command = direction === 'to' ? `axtj ${safeAddr}` : `axfj ${safeAddr}`;
          let xrefs = await session.cmdj<R2Xref[]>(command);
          if (!Array.isArray(xrefs)) {
            xrefs = [];
          }
          const page = paginate(xrefs, offset, limit);
          return mcpFormatted(formatXrefs(page.results, direction, safeAddr));
        });
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
