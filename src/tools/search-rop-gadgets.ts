import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { withCachedSession } from '../r2/session-cache.js';
import { sanitizePath, sanitizeSearchQuery } from '../r2/sanitize.js';
import { paginate } from '../utils/pagination.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatRopGadgets } from '../utils/formatters.js';

interface RopGadget {
  readonly address: string;
  readonly instructions: string;
}

export function registerSearchRopGadgets(server: McpServer): void {
  server.tool(
    'search_rop_gadgets',
    'Search for ROP gadgets in the binary matching optional instruction constraints.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      query: z
        .string()
        .optional()
        .describe('Instruction filter (e.g. "pop rdi") to match specific gadgets'),
      max_length: z
        .number()
        .int()
        .min(1)
        .max(20)
        .default(5)
        .describe('Maximum number of instructions per gadget'),
      offset: z.number().int().min(0).default(0).describe('Pagination offset (0-based)'),
      limit: z
        .number()
        .int()
        .min(1)
        .max(2000)
        .default(100)
        .describe('Max results to return'),
    },
    async ({ binary_path, query, max_length, offset, limit }) => {
      try {
        const safePath = sanitizePath(binary_path);
        return await withCachedSession(safePath, async (session) => {
          // Set max gadget length
          await session.cmd(`e search.roplen=${max_length}`);

          // Build the search command
          let command: string;
          if (query) {
            const safeQuery = sanitizeSearchQuery(query);
            command = `/R ${safeQuery}`;
          } else {
            command = '/R';
          }

          const raw = await session.cmd(command);
          const gadgets: RopGadget[] = [];

          // Parse ROP gadget output. Format varies but typically:
          //   0x<addr>  instr1; instr2; ret
          const lines = raw.split('\n');
          for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed.length === 0) continue;

            // Match lines starting with a hex address
            const match = /^(0x[0-9a-fA-F]+)\s+(.+)$/.exec(trimmed);
            if (match) {
              const addr = match[1];
              const instrs = match[2];
              if (addr && instrs) {
                gadgets.push({
                  address: addr,
                  instructions: instrs.trim(),
                });
              }
            }
          }

          const page = paginate(gadgets, offset, limit);
          return mcpFormatted(formatRopGadgets(page));
        });
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
