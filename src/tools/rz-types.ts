import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizePath } from '../r2/sanitize.js';
import { RizinSession } from '../rizin/rizin-session.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { paginate } from '../utils/pagination.js';

interface RzStruct {
  name: string;
  members: Record<string, string>;
}

interface RzEnum {
  name: string;
  values: Record<string, number>;
}

interface RzTypedef {
  name: string;
  type: string;
}

interface RzUnion {
  name: string;
  members: Record<string, string>;
}

export function registerRzTypes(server: McpServer): void {
  server.tool(
    'rz_types',
    'List type definitions from the binary using Rizin separate typed JSON endpoints (tsj/tej/ttj/tuj). Returns structs, enums, typedefs, and unions with full member details. Superior to r2 which returns all types in a single flat list.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      category: z
        .enum(['all', 'structs', 'enums', 'typedefs', 'unions'])
        .default('all')
        .describe('Type category to list (default: all)'),
      filter: z
        .string()
        .optional()
        .describe('Filter types by name substring (case-insensitive)'),
      offset: z.number().int().min(0).default(0),
      limit: z.number().int().min(1).max(500).default(50),
    },
    async ({ binary_path, category, filter, offset, limit }) => {
      let session: RizinSession | undefined;
      try {
        const safePath = sanitizePath(binary_path);
        session = await RizinSession.open(safePath);
        await session.cmd('aa');

        const lines: string[] = [];

        const filterFn = (name: string): boolean => {
          if (!filter) return true;
          return name.toLowerCase().includes(filter.toLowerCase());
        };

        if (category === 'all' || category === 'structs') {
          const structs = await session.cmdj<RzStruct[]>('tsj');
          const filtered = structs.filter((s) => filterFn(s.name));
          const page = paginate(filtered, offset, limit);

          if (page.results.length > 0) {
            lines.push(`## Structs (${page.total} total)\n`);
            for (const s of page.results) {
              const members = Object.entries(s.members)
                .map(([name, type]) => `\`${type} ${name}\``)
                .join(', ');
              lines.push(`- **${s.name}**: ${members}`);
            }
            lines.push('');
          }
        }

        if (category === 'all' || category === 'enums') {
          const enums = await session.cmdj<RzEnum[]>('tej');
          const filtered = enums.filter((e) => filterFn(e.name));
          const page = paginate(filtered, offset, limit);

          if (page.results.length > 0) {
            lines.push(`## Enums (${page.total} total)\n`);
            for (const e of page.results) {
              const values = Object.entries(e.values)
                .map(([name, val]) => `${name}=${val}`)
                .join(', ');
              lines.push(`- **${e.name}**: ${values}`);
            }
            lines.push('');
          }
        }

        if (category === 'all' || category === 'typedefs') {
          const typedefs = await session.cmdj<RzTypedef[]>('ttj');
          const filtered = typedefs.filter((t) => filterFn(t.name));
          const page = paginate(filtered, offset, limit);

          if (page.results.length > 0) {
            lines.push(`## Typedefs (${page.total} total)\n`);
            lines.push('| Name | Underlying Type |');
            lines.push('|------|-----------------|');
            for (const t of page.results) {
              lines.push(`| \`${t.name}\` | \`${t.type}\` |`);
            }
            lines.push('');
          }
        }

        if (category === 'all' || category === 'unions') {
          const unions = await session.cmdj<RzUnion[]>('tuj');
          const filtered = unions.filter((u) => filterFn(u.name));
          const page = paginate(filtered, offset, limit);

          if (page.results.length > 0) {
            lines.push(`## Unions (${page.total} total)\n`);
            for (const u of page.results) {
              const members = Object.entries(u.members)
                .map(([name, type]) => `\`${type} ${name}\``)
                .join(', ');
              lines.push(`- **${u.name}**: ${members}`);
            }
            lines.push('');
          }
        }

        if (lines.length === 0) {
          return mcpFormatted('No types found matching the given criteria.');
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
