import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizeAddress } from '../r2/sanitize.js';
import { rzilManager } from '../rizin/rzil-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatRzilRunResult } from '../rizin/formatters.js';

export function registerRzilRun(server: McpServer): void {
  server.tool(
    'rzil_run',
    'Run RzIL emulation until a target address is reached or maximum steps are exceeded. Uses aezsu for address targets. Requires a persistent session from rzil_init.',
    {
      session_id: z.string().describe('RzIL session ID returned by rzil_init'),
      until_address: z
        .string()
        .optional()
        .describe('Stop emulation when PC equals this address (hex). Uses aezsu internally.'),
      max_steps: z
        .number()
        .int()
        .min(1)
        .max(100000)
        .default(1000)
        .describe('Maximum number of steps before stopping (default 1000)'),
    },
    async ({ session_id, until_address, max_steps }) => {
      try {
        const entry = rzilManager.get(session_id);
        const session = entry.session;

        let stoppedAt: string;
        let reason: 'address_reached' | 'max_steps' | 'breakpoint' | 'error';
        let stepsTaken: number;

        if (until_address) {
          const safeUntil = sanitizeAddress(until_address);

          // Use Rizin's native aezsu (step until address)
          await session.cmd(`aezsu ${safeUntil}`);

          const vmState = await session.cmdj<Record<string, unknown>>('aezvj');
          stoppedAt =
            typeof vmState?.['PC'] === 'string' ? vmState['PC'] as string : '0x0';

          const normalizeAddr = (a: string): string =>
            a.replace(/^0x/i, '').replace(/^0+/, '').toLowerCase();

          if (normalizeAddr(stoppedAt) === normalizeAddr(safeUntil)) {
            reason = 'address_reached';
          } else {
            reason = 'max_steps';
          }

          stepsTaken = -1; // aezsu doesn't report step count
        } else {
          // Manual step loop
          stepsTaken = 0;
          let prevPc = '';
          let hitStuck = false;

          for (let i = 0; i < max_steps; i++) {
            const vmState = await session.cmdj<Record<string, unknown>>('aezvj');
            const currentPc =
              typeof vmState?.['PC'] === 'string' ? vmState['PC'] as string : '0x0';

            if (currentPc === prevPc) {
              reason = 'error';
              stoppedAt = currentPc;
              hitStuck = true;
              break;
            }
            prevPc = currentPc;

            await session.cmd('aezs');
            stepsTaken++;
          }

          if (!hitStuck) {
            reason = 'max_steps';
            const finalState = await session.cmdj<Record<string, unknown>>('aezvj');
            stoppedAt =
              typeof finalState?.['PC'] === 'string' ? finalState['PC'] as string : '0x0';
          }
        }

        // Get final register state
        const finalVm = await session.cmdj<Record<string, unknown>>('aezvj');
        const finalRegisters: Record<string, number> = {};
        for (const [key, value] of Object.entries(finalVm)) {
          if (typeof value === 'string' && value.startsWith('0x')) {
            finalRegisters[key] = parseInt(value, 16);
          }
        }

        return mcpFormatted(
          formatRzilRunResult({
            stopped_at: stoppedAt!,
            reason: reason!,
            steps_taken: stepsTaken,
            final_registers: finalRegisters,
          }),
        );
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
