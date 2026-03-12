import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { R2Session } from '../r2/session.js';
import { sanitizePath, sanitizeAddress, sanitizeRegisterName } from '../r2/sanitize.js';
import { esilManager } from '../r2/esil-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';

function sanitizeValue(value: string): string {
  const trimmed = value.trim();
  if (!/^(0x)?[0-9a-fA-F]+$/.test(trimmed) && !/^[0-9]+$/.test(trimmed)) {
    throw new Error(
      `Invalid register value: ${trimmed}. Expected hex (e.g. "0x1234") or decimal number.`,
    );
  }
  return trimmed;
}

export function registerEsilSetRegister(server: McpServer): void {
  server.tool(
    'esil_set_register',
    'Set a register value in the ESIL virtual machine. If session_id is provided, uses a persistent session; otherwise creates a fresh session.',
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
        .describe('Address (hex) to set as program counter before modifying registers'),
      register_name: z.string().describe('Register name to set (e.g. "eax", "rip", "rsp")'),
      value: z
        .string()
        .describe('Value to set the register to (hex string, e.g. "0x41414141")'),
    },
    async ({ binary_path, session_id, address, register_name, value }) => {
      let freshSession: R2Session | undefined;
      try {
        const safeName = sanitizeRegisterName(register_name);
        const safeValue = sanitizeValue(value);

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

        await session.cmd(`aer ${safeName}=${safeValue}`);

        const readBack = (await session.cmd(`aer ${safeName}`)).trim();

        return mcpFormatted(`Register \`${safeName}\` set to \`${readBack}\``);
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
