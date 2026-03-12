import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizePath, sanitizeAddress } from '../r2/sanitize.js';
import { rzilManager } from '../rizin/rzil-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatRzilInit } from '../rizin/formatters.js';

export function registerRzilInit(server: McpServer): void {
  server.tool(
    'rzil_init',
    'Initialize the Rizin RzIL virtual machine and return a persistent session_id for subsequent RzIL tool calls. RzIL uses typed bitvectors (BAP Core Theory) for superior emulation fidelity compared to ESIL.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      address: z
        .string()
        .optional()
        .describe('Start address (hex). If omitted, entry point is used.'),
    },
    async ({ binary_path, address }) => {
      try {
        const safePath = sanitizePath(binary_path);
        const safeAddr = address ? sanitizeAddress(address) : undefined;

        const createOptions: { address?: string } = {};
        if (safeAddr) {
          createOptions.address = safeAddr;
        }

        const entry = await rzilManager.create(safePath, createOptions);

        // Read VM state from the persistent session
        const vmState = await entry.session.cmdj<Record<string, unknown>>('aezvj');
        const pc = typeof vmState?.['PC'] === 'string' ? vmState['PC'] as string : 'unknown';

        // Extract register values (convert string hex to numbers for formatter)
        const registers: Record<string, number> = {};
        for (const [key, value] of Object.entries(vmState)) {
          if (typeof value === 'string' && value.startsWith('0x')) {
            registers[key] = parseInt(value, 16);
          }
        }

        const lines: string[] = [];
        lines.push(
          formatRzilInit({
            initialized: true,
            entry_point: pc,
            registers,
          }),
        );
        lines.push(`\n**Session ID:** \`${entry.sessionId}\``);
        lines.push(
          '\nUse this `session_id` with other RzIL tools (`rzil_step`, `rzil_run`, `rzil_get_registers`, etc.) to preserve state across calls.',
        );

        return mcpFormatted(lines.join('\n'));
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
