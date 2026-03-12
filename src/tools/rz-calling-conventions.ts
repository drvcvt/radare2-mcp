import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizePath } from '../r2/sanitize.js';
import { RizinSession } from '../rizin/rizin-session.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';

export function registerRzCallingConventions(server: McpServer): void {
  server.tool(
    'rz_calling_conventions',
    'List all calling conventions available for the binary architecture using Rizin afcl. Useful for understanding function signatures and ABI details.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
    },
    async ({ binary_path }) => {
      let session: RizinSession | undefined;
      try {
        const safePath = sanitizePath(binary_path);
        session = await RizinSession.open(safePath);
        await session.cmd('aa');

        const output = (await session.cmd('afcl')).trim();

        if (!output) {
          return mcpFormatted('No calling conventions found.');
        }

        const conventions = output.split('\n').filter((l) => l.trim());

        const lines: string[] = [];
        lines.push(`## Calling Conventions (${conventions.length})\n`);
        for (const cc of conventions) {
          lines.push(`- \`${cc.trim()}\``);
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
