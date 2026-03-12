import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizePath } from '../r2/sanitize.js';
import { RizinSession } from '../rizin/rizin-session.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';

interface RzEntrypoint {
  vaddr: number;
  paddr: number;
  baddr: number;
  laddr: number;
  haddr: number;
  type: string;
}

export function registerRzEntrypoints(server: McpServer): void {
  server.tool(
    'rz_entrypoints',
    'List all entry points of the binary (program entry, TLS callbacks, etc.) using Rizin iej. Returns virtual address, physical address, and entry type.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
    },
    async ({ binary_path }) => {
      let session: RizinSession | undefined;
      try {
        const safePath = sanitizePath(binary_path);
        session = await RizinSession.open(safePath);

        const entries = await session.cmdj<RzEntrypoint[]>('iej');

        if (entries.length === 0) {
          return mcpFormatted('No entry points found.');
        }

        const lines: string[] = [];
        lines.push(`## Entry Points (${entries.length})\n`);
        lines.push('| Type | Virtual Address | Physical Address | Base Address |');
        lines.push('|------|----------------|-----------------|--------------|');

        for (const e of entries) {
          lines.push(
            `| ${e.type} | \`0x${e.vaddr.toString(16)}\` | \`0x${e.paddr.toString(16)}\` | \`0x${e.baddr.toString(16)}\` |`,
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
