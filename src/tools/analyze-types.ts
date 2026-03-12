import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { withCachedSession } from '../r2/session-cache.js';
import { sanitizePath } from '../r2/sanitize.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatTypeList } from '../utils/formatters.js';
import { paginate } from '../utils/pagination.js';
import type { R2Type } from '../types.js';

export function registerAnalyzeTypes(server: McpServer): void {
  server.tool(
    'analyze_types',
    'List type definitions from binary analysis including structs, enums, and typedefs.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      filter: z.string().optional().describe('Optional substring to filter type names'),
      offset: z.number().int().min(0).default(0).describe('Pagination offset (0-based)'),
      limit: z
        .number()
        .int()
        .min(1)
        .max(1000)
        .default(100)
        .describe('Max results to return'),
    },
    async ({ binary_path, filter, offset, limit }) => {
      try {
        const safePath = sanitizePath(binary_path);
        return await withCachedSession(safePath, async (session) => {
          // Collect types from multiple r2 commands
          const allTypes: R2Type[] = [];

          // Try `tj` for all types as JSON
          try {
            const types = await session.cmdj<R2Type[]>('tj');
            if (Array.isArray(types)) {
              allTypes.push(...types);
            }
          } catch {
            // tj may not be available or may return nothing
          }

          // Try `tsj` for struct definitions
          try {
            const structs = await session.cmdj<R2Type[]>('tsj');
            if (Array.isArray(structs)) {
              // Avoid duplicates by checking name
              const existingNames = new Set(allTypes.map((t) => t.name));
              for (const s of structs) {
                if (!existingNames.has(s.name)) {
                  allTypes.push({ ...s, kind: s.kind ?? 'struct' });
                }
              }
            }
          } catch {
            // tsj may not be available
          }

          // Try `tej` for enum definitions
          try {
            const enums = await session.cmdj<R2Type[]>('tej');
            if (Array.isArray(enums)) {
              const existingNames = new Set(allTypes.map((t) => t.name));
              for (const e of enums) {
                if (!existingNames.has(e.name)) {
                  allTypes.push({ ...e, kind: e.kind ?? 'enum' });
                }
              }
            }
          } catch {
            // tej may not be available
          }

          // Apply optional filter
          let filtered = allTypes;
          if (filter) {
            const lowerFilter = filter.toLowerCase();
            filtered = allTypes.filter((t) =>
              (t.name ?? '').toLowerCase().includes(lowerFilter),
            );
          }

          const page = paginate(filtered, offset, limit);
          return mcpFormatted(formatTypeList(page));
        });
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
