import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { R2Session } from '../r2/session.js';
import { sanitizePath, sanitizeAddress } from '../r2/sanitize.js';
import { esilManager } from '../r2/esil-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatSteps } from '../utils/formatters.js';

export function registerEsilStep(server: McpServer): void {
  server.tool(
    'esil_step',
    'Execute one or more instruction steps in the ESIL emulator and return the updated register state. If session_id is provided, uses a persistent session; otherwise creates a fresh session.',
    {
      binary_path: z
        .string()
        .optional()
        .describe(
          'Absolute path to the binary file. Required when session_id is not provided.',
        ),
      session_id: z
        .string()
        .optional()
        .describe(
          'Persistent ESIL session ID from esil_init. If provided, binary_path and address are ignored.',
        ),
      address: z
        .string()
        .optional()
        .describe('Start address (hex) for emulation. If omitted, entry point is used.'),
      count: z
        .number()
        .int()
        .min(1)
        .max(10000)
        .default(1)
        .describe('Number of steps to execute (default 1)'),
      step_over: z
        .boolean()
        .default(false)
        .describe('If true, use step-over (aeso) instead of step-into (aes)'),
    },
    async ({ binary_path, session_id, address, count, step_over }) => {
      let freshSession: R2Session | undefined;
      try {
        let session: R2Session;

        if (session_id) {
          // Use persistent session
          const entry = esilManager.get(session_id);
          session = entry.session;
        } else {
          // Fall back to fresh session
          if (!binary_path) {
            return mcpError('binary_path is required when session_id is not provided.');
          }
          const safePath = sanitizePath(binary_path);
          freshSession = await R2Session.open(safePath);
          session = freshSession;
          await session.cmd('aaa');

          // Initialize ESIL VM
          await session.cmd('aei');
          await session.cmd('aeim');

          if (address) {
            const safeAddr = sanitizeAddress(address);
            await session.cmd(`aepc ${safeAddr}`);
          } else {
            await session.cmd('aeip');
          }
        }

        const stepCmd = step_over ? 'aeso' : 'aes';
        const steps: Array<{
          address: string;
          instruction: string;
          registers: Record<string, number>;
        }> = [];

        for (let i = 0; i < count; i++) {
          const currentAddr = (await session.cmd('s')).trim();
          const instruction = (await session.cmd('ao 1~opcode[1]')).trim();

          await session.cmd(stepCmd);

          const registers = await session.cmdj<Record<string, number>>('aerj');

          steps.push({
            address: currentAddr,
            instruction,
            registers,
          });
        }

        return mcpFormatted(formatSteps(steps, { title: 'ESIL Step' }));
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      } finally {
        if (freshSession) {
          await freshSession.close();
        }
      }
    },
  );
}
