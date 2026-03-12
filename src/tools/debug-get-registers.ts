import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizeSessionId, sanitizeRegisterName } from '../r2/sanitize.js';
import { debugManager } from '../r2/debug-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatRegisters } from '../utils/formatters.js';

export function registerDebugGetRegisters(server: McpServer): void {
  server.tool(
    'debug_get_registers',
    'Read all register values or a specific register from the debugged process.',
    {
      session_id: z.string().describe('Debug session ID'),
      register_name: z
        .string()
        .optional()
        .describe('Specific register to read (e.g. "rax", "eip"). If omitted, returns all registers.'),
    },
    async ({ session_id, register_name }) => {
      try {
        const safeId = sanitizeSessionId(session_id);
        const entry = debugManager.get(safeId);

        if (register_name !== undefined) {
          const safeName = sanitizeRegisterName(register_name);
          const value = (await entry.session.cmd(`dr ${safeName}`)).trim();
          return mcpFormatted(`Register \`${safeName}\` = \`${value}\``);
        }

        const registers = await entry.session.cmdj<Record<string, number>>('drj');
        return mcpFormatted(formatRegisters(registers, 'Debug Registers'));
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
