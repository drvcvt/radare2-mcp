import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { R2Session } from '../r2/session.js';
import { sanitizePath, sanitizeAddress } from '../r2/sanitize.js';
import { esilManager } from '../r2/esil-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatEsilRunResult } from '../utils/formatters.js';

export function registerEsilRun(server: McpServer): void {
  server.tool(
    'esil_run',
    'Run ESIL emulation until a target address is reached, a breakpoint is hit, or maximum steps are exceeded. If session_id is provided, uses a persistent session; otherwise creates a fresh session.',
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
      until_address: z
        .string()
        .optional()
        .describe('Stop emulation when this address is reached (hex)'),
      max_steps: z
        .number()
        .int()
        .min(1)
        .max(100000)
        .default(1000)
        .describe('Maximum number of steps before stopping (default 1000)'),
      timeout: z
        .number()
        .int()
        .min(1)
        .max(300)
        .default(30)
        .describe('Maximum time in seconds before stopping emulation (default 30)'),
    },
    async ({ binary_path, session_id, address, until_address, max_steps, timeout }) => {
      let freshSession: R2Session | undefined;
      try {
        let session: R2Session;

        if (session_id) {
          const entry = esilManager.get(session_id);
          session = entry.session;
        } else {
          if (!binary_path) {
            return mcpError('binary_path is required when session_id is not provided.');
          }
          const safePath = sanitizePath(binary_path);
          freshSession = await R2Session.open(safePath);
          session = freshSession;
          await session.cmd('aaa');

          await session.cmd('aei');
          await session.cmd('aeim');

          if (address) {
            const safeAddr = sanitizeAddress(address);
            await session.cmd(`aepc ${safeAddr}`);
          } else {
            await session.cmd('aeip');
          }
        }

        let stoppedAt: string;
        let reason: 'address_reached' | 'max_steps' | 'timeout' | 'breakpoint' | 'error';
        let stepsTaken: number;

        const normalizeAddr = (a: string): string =>
          a.replace(/^0x/i, '').toLowerCase();
        const deadline = Date.now() + timeout * 1000;

        if (until_address) {
          const safeUntil = sanitizeAddress(until_address);
          const normalizedUntil = normalizeAddr(safeUntil);

          stepsTaken = 0;
          let prevAddr = '';
          let hitTarget = false;
          let hitStuck = false;
          let hitTimeout = false;

          for (let i = 0; i < max_steps; i++) {
            const currentAddr = (await session.cmd('s')).trim();

            if (normalizeAddr(currentAddr) === normalizedUntil) {
              reason = 'address_reached';
              stoppedAt = currentAddr;
              hitTarget = true;
              break;
            }

            // Null pointer execution detection
            if (normalizeAddr(currentAddr) === '0' || normalizeAddr(currentAddr) === '00000000') {
              reason = 'error';
              stoppedAt = currentAddr;
              hitStuck = true;
              break;
            }

            if (currentAddr === prevAddr) {
              reason = 'error';
              stoppedAt = currentAddr;
              hitStuck = true;
              break;
            }
            prevAddr = currentAddr;

            if (Date.now() >= deadline) {
              reason = 'timeout';
              stoppedAt = currentAddr;
              hitTimeout = true;
              break;
            }

            await session.cmd('aes');
            stepsTaken++;
          }

          if (!hitTarget && !hitStuck && !hitTimeout) {
            reason = 'max_steps';
            stoppedAt = (await session.cmd('s')).trim();
          }
        } else {
          stepsTaken = 0;
          let prevAddr = '';
          let hitStuck = false;
          let hitTimeout = false;

          for (let i = 0; i < max_steps; i++) {
            const currentAddr = (await session.cmd('s')).trim();

            // Null pointer execution detection
            if (normalizeAddr(currentAddr) === '0' || normalizeAddr(currentAddr) === '00000000') {
              reason = 'error';
              stoppedAt = currentAddr;
              hitStuck = true;
              break;
            }

            if (currentAddr === prevAddr) {
              reason = 'error';
              stoppedAt = currentAddr;
              hitStuck = true;
              break;
            }
            prevAddr = currentAddr;

            if (Date.now() >= deadline) {
              reason = 'timeout';
              stoppedAt = currentAddr;
              hitTimeout = true;
              break;
            }

            await session.cmd('aes');
            stepsTaken++;
          }

          if (!hitStuck && !hitTimeout) {
            reason = 'max_steps';
            stoppedAt = (await session.cmd('s')).trim();
          }
        }

        const finalRegisters = await session.cmdj<Record<string, number>>('aerj');

        return mcpFormatted(
          formatEsilRunResult({
            stopped_at: stoppedAt!,
            reason: reason!,
            steps_taken: stepsTaken,
            final_registers: finalRegisters,
          }),
        );
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
