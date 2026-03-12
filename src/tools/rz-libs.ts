import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizePath } from '../r2/sanitize.js';
import { RizinSession } from '../rizin/rizin-session.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';

export function registerRzLibs(server: McpServer): void {
  server.tool(
    'rz_libs',
    'List all linked libraries (DLLs/shared objects) from the binary using Rizin ilj. Returns a clean JSON array of library names.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
    },
    async ({ binary_path }) => {
      let session: RizinSession | undefined;
      try {
        const safePath = sanitizePath(binary_path);
        session = await RizinSession.open(safePath);

        const libs = await session.cmdj<string[]>('ilj');

        if (libs.length === 0) {
          return mcpFormatted('No linked libraries found (statically linked?).');
        }

        const lines: string[] = [];
        lines.push(`## Linked Libraries (${libs.length})\n`);
        for (const lib of libs) {
          lines.push(`- \`${lib}\``);
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
