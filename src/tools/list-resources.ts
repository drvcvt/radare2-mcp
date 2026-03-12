import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { withCachedSession } from '../r2/session-cache.js';
import { sanitizePath } from '../r2/sanitize.js';
import { paginate } from '../utils/pagination.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatResources } from '../utils/formatters.js';

interface R2Resource {
  readonly name: string;
  readonly index: number;
  readonly type: string;
  readonly vaddr: number;
  readonly size: number;
  readonly lang: string;
}

export function registerListResources(server: McpServer): void {
  server.tool(
    'list_resources',
    'List PE resources (icons, manifests, version info, embedded data) from the binary.',
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
          let resources = await session.cmdj<R2Resource[]>('iRj');
          if (!Array.isArray(resources)) {
            resources = [];
          }
          const mapped = resources.map((r) => ({
            index: r.index,
            type: r.type,
            name: r.name,
            language: r.lang,
            vaddr: r.vaddr,
            size: r.size,
          }));
          const page = paginate(mapped, offset, limit);
          return mcpFormatted(formatResources(page));
        });
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
