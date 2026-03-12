import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizeAddress } from '../r2/sanitize.js';
import { rzilManager } from '../rizin/rzil-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatRzilMemory } from '../rizin/formatters.js';

export function registerRzilGetMemory(server: McpServer): void {
  server.tool(
    'rzil_get_memory',
    'Read memory contents from the Rizin RzIL emulated memory space at a given address. Requires a persistent session from rzil_init.',
    {
      session_id: z.string().describe('RzIL session ID returned by rzil_init'),
      address: z.string().describe('Address (hex) to read memory from'),
      size: z
        .number()
        .int()
        .min(1)
        .max(65536)
        .default(64)
        .describe('Number of bytes to read (default 64)'),
      format: z
        .enum(['hex', 'string', 'hexdump'])
        .default('hex')
        .describe(
          'Output format: "hex" (raw hex bytes), "string" (ASCII), or "hexdump" (classic hex dump)',
        ),
    },
    async ({ session_id, address, size, format }) => {
      try {
        const safeAddr = sanitizeAddress(address);
        const entry = rzilManager.get(session_id);
        const session = entry.session;

        // Seek to the requested address
        await session.cmd(`s ${safeAddr}`);

        let data: string;
        switch (format) {
          case 'hex':
            data = (await session.cmd(`p8 ${size}`)).trim();
            break;
          case 'string':
            data = (await session.cmd(`ps ${size}`)).trim();
            break;
          case 'hexdump':
            data = (await session.cmd(`px ${size}`)).trim();
            break;
        }

        return mcpFormatted(
          formatRzilMemory({
            address: safeAddr,
            size,
            format,
            data,
          }),
        );
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
