import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizePath } from '../r2/sanitize.js';
import { RizinSession } from '../rizin/rizin-session.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { paginate } from '../utils/pagination.js';

interface RzSymbol {
  name: string;
  flagname?: string;
  realname?: string;
  ordinal?: number;
  bind?: string;
  size?: number;
  type?: string;
  vaddr?: number;
  paddr?: number;
  is_imported?: boolean;
  lib?: string;
}

export function registerRzSymbols(server: McpServer): void {
  server.tool(
    'rz_symbols',
    'List all symbols from the binary using Rizin. Returns enriched data including is_imported flag, library origin, flagname, and realname — more detail than r2 isj.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      filter: z
        .string()
        .optional()
        .describe('Filter symbols by name substring (case-insensitive)'),
      imported_only: z
        .boolean()
        .default(false)
        .describe('If true, only show imported symbols'),
      offset: z.number().int().min(0).default(0),
      limit: z.number().int().min(1).max(2000).default(100),
    },
    async ({ binary_path, filter, imported_only, offset, limit }) => {
      let session: RizinSession | undefined;
      try {
        const safePath = sanitizePath(binary_path);
        session = await RizinSession.open(safePath);

        const symbols = await session.cmdj<RzSymbol[]>('isj');

        let filtered = symbols;
        if (imported_only) {
          filtered = filtered.filter((s) => s.is_imported);
        }
        if (filter) {
          const lowerFilter = filter.toLowerCase();
          filtered = filtered.filter(
            (s) =>
              s.name.toLowerCase().includes(lowerFilter) ||
              (s.realname ?? '').toLowerCase().includes(lowerFilter),
          );
        }

        const page = paginate(filtered, offset, limit);

        if (page.results.length === 0) {
          return mcpFormatted('No symbols found matching the given criteria.');
        }

        const lines: string[] = [];
        lines.push(
          `## Symbols (${page.offset + 1}–${page.offset + page.results.length} of ${page.total})\n`,
        );
        lines.push('| Address | Name | Type | Lib | Imported |');
        lines.push('|---------|------|------|-----|----------|');

        for (const s of page.results) {
          const addr = s.vaddr !== undefined ? `0x${s.vaddr.toString(16)}` : '?';
          const name = s.realname ?? s.name;
          lines.push(
            `| \`${addr}\` | \`${name}\` | ${s.type ?? '?'} | ${s.lib ?? '-'} | ${s.is_imported ? 'yes' : 'no'} |`,
          );
        }

        return mcpFormatted(lines.join('\n'));
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      } finally {
        if (session) {
          await session.close();
        }
      }
    },
  );
}
