import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizeSessionId } from '../r2/sanitize.js';
import { debugManager } from '../r2/debug-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatDebugSteps } from '../utils/formatters.js';

export function registerDebugStep(server: McpServer): void {
  server.tool(
    'debug_step',
    'Single-step the debugged process (step into or step over) and return the updated register state.',
    {
      session_id: z.string().describe('Debug session ID'),
      count: z
        .number()
        .int()
        .min(1)
        .max(1000)
        .default(1)
        .describe('Number of instructions to step (default 1)'),
      step_over: z
        .boolean()
        .default(false)
        .describe('Step over calls instead of stepping into them'),
    },
    async ({ session_id, count, step_over }) => {
      try {
        const safeId = sanitizeSessionId(session_id);
        const entry = debugManager.get(safeId);

        const stepCmd = step_over ? 'dso' : 'ds';

        const steps: Array<{
          address: string;
          instruction: string;
          registers: Record<string, number>;
        }> = [];

        for (let i = 0; i < count; i++) {
          await entry.session.cmd(stepCmd);

          const registers = await entry.session.cmdj<Record<string, number>>('drj');

          let address = 'unknown';
          let instruction = '';
          try {
            address = (await entry.session.cmd('s')).trim();
            instruction = (await entry.session.cmd('pd 1')).trim();
          } catch {
            // May fail if process exited
          }

          steps.push({ address, instruction, registers });
        }

        return mcpFormatted(formatDebugSteps({
          steps_executed: steps.length,
          step_type: step_over ? 'over' : 'into',
          steps,
          final_registers: steps.length > 0 ? steps[steps.length - 1]!.registers : {},
        }));
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
