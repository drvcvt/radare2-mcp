import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { R2Session } from '../r2/session.js';
import { sanitizePath, sanitizeAddress, sanitizeRegisterName } from '../r2/sanitize.js';
import { esilManager } from '../r2/esil-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatRegisters } from '../utils/formatters.js';

export function registerEsilGetRegisters(server: McpServer): void {
  server.tool(
    'esil_get_registers',
    'Read all register values or a specific register from the ESIL virtual machine state. If session_id is provided, uses a persistent session; otherwise creates a fresh session.',
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
        .describe('Address (hex) to set as program counter before reading registers'),
      register_name: z
        .string()
        .optional()
        .describe(
          'Specific register name to read (e.g. "eax", "rip"). If omitted, all registers are returned.',
        ),
    },
    async ({ binary_path, session_id, address, register_name }) => {
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

        if (register_name) {
          const safeName = sanitizeRegisterName(register_name);
          const value = (await session.cmd(`aer ${safeName}`)).trim();
          return mcpFormatted(`Register \`${safeName}\` = \`${value}\``);
        } else {
          const registers = await session.cmdj<Record<string, number>>('aerj');
          return mcpFormatted(formatRegisters(registers, 'ESIL Registers'));
        }
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
