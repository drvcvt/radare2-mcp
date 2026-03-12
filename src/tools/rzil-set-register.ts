import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizeRegisterName } from '../r2/sanitize.js';
import { rzilManager } from '../rizin/rzil-session-manager.js';
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

export function registerRzilSetRegister(server: McpServer): void {
  server.tool(
    'rzil_set_register',
    'Set a register value in the Rizin RzIL virtual machine. Requires a persistent session from rzil_init.',
    {
      session_id: z.string().describe('RzIL session ID returned by rzil_init'),
      register_name: z.string().describe('Register name to set (e.g. "rax", "rip", "rsp")'),
      value: z
        .string()
        .describe('Value to set the register to (hex string, e.g. "0x41414141")'),
    },
    async ({ session_id, register_name, value }) => {
      try {
        const safeName = sanitizeRegisterName(register_name);
        const safeValue = sanitizeValue(value);

        const entry = rzilManager.get(session_id);
        const session = entry.session;

        // aezv <name> <value> sets a register in the RzIL VM
        await session.cmd(`aezv ${safeName} ${safeValue}`);

        // Read back to confirm
        const readBack = (await session.cmd(`aezv ${safeName}`)).trim();

        return mcpFormatted(`Register \`${safeName}\` set to \`${readBack}\``);
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
