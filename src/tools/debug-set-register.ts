import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizeSessionId, sanitizeRegisterName, sanitizeAddress } from '../r2/sanitize.js';
import { debugManager } from '../r2/debug-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatRegisters } from '../utils/formatters.js';

export function registerDebugSetRegister(server: McpServer): void {
  server.tool(
    'debug_set_register',
    'Set a register value in the debugged process.',
    {
      session_id: z.string().describe('Debug session ID'),
      register_name: z.string().describe('Register name (e.g. "rax", "eip", "rflags")'),
      value: z.string().describe('Value to set (hex string, e.g. "0x41414141")'),
    },
    async ({ session_id, register_name, value }) => {
      try {
        const safeId = sanitizeSessionId(session_id);
        const safeName = sanitizeRegisterName(register_name);
        const safeValue = sanitizeAddress(value); // hex validation
        const entry = debugManager.get(safeId);

        await entry.session.cmd(`dr ${safeName}=${safeValue}`);

        // Read back to confirm
        const registers = await entry.session.cmdj<Record<string, number>>('drj');

        const lines: string[] = [];
        lines.push(`Register \`${safeName}\` set to \`${safeValue}\`\n`);
        if (registers) lines.push(formatRegisters(registers));
        return mcpFormatted(lines.join('\n'));
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
