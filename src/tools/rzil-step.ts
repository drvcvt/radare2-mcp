import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { rzilManager } from '../rizin/rzil-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatRzilSteps } from '../rizin/formatters.js';

export function registerRzilStep(server: McpServer): void {
  server.tool(
    'rzil_step',
    'Execute one or more instruction steps in the Rizin RzIL emulator and return VM change events and updated register state. Requires a persistent session from rzil_init.',
    {
      session_id: z.string().describe('RzIL session ID returned by rzil_init'),
      count: z
        .number()
        .int()
        .min(1)
        .max(10000)
        .default(1)
        .describe('Number of steps to execute (default 1)'),
      show_events: z
        .boolean()
        .default(true)
        .describe('If true, use aezse to show VM change events (pc_write, var_write). If false, use silent aezs.'),
    },
    async ({ session_id, count, show_events }) => {
      try {
        const entry = rzilManager.get(session_id);
        const session = entry.session;

        if (!show_events && count > 1) {
          // Bulk silent step
          await session.cmd(`aezs ${count}`);
          const vmState = await session.cmdj<Record<string, unknown>>('aezvj');
          const pc = typeof vmState?.['PC'] === 'string' ? vmState['PC'] as string : 'unknown';

          const registers: Record<string, number> = {};
          for (const [key, value] of Object.entries(vmState)) {
            if (typeof value === 'string' && value.startsWith('0x')) {
              registers[key] = parseInt(value, 16);
            }
          }

          return mcpFormatted(
            formatRzilSteps([
              { address: pc, instruction: `(${count} steps, silent)`, registers },
            ]),
          );
        }

        // Step one at a time with event capture
        const steps: Array<{
          address: string;
          instruction: string;
          registers: Record<string, number>;
        }> = [];

        for (let i = 0; i < count; i++) {
          // Get current PC from VM state
          const preState = await session.cmdj<Record<string, unknown>>('aezvj');
          const currentAddr =
            typeof preState?.['PC'] === 'string' ? preState['PC'] as string : '0x0';

          // Get current instruction at PC
          await session.cmd(`s ${currentAddr}`);
          const instruction = (await session.cmd('ao 1~opcode[1]')).trim();

          // Step with events
          const events = show_events
            ? (await session.cmd('aezse 1')).trim()
            : (await session.cmd('aezs 1'), '');

          // Get post-step VM state
          const postState = await session.cmdj<Record<string, unknown>>('aezvj');
          const registers: Record<string, number> = {};
          for (const [key, value] of Object.entries(postState)) {
            if (typeof value === 'string' && value.startsWith('0x')) {
              registers[key] = parseInt(value, 16);
            }
          }

          const desc = events ? `${instruction} | ${events}` : instruction;
          steps.push({ address: currentAddr, instruction: desc, registers });
        }

        return mcpFormatted(formatRzilSteps(steps));
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
