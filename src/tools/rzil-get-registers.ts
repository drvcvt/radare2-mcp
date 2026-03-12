import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizeRegisterName } from '../r2/sanitize.js';
import { rzilManager } from '../rizin/rzil-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatRzilRegisters } from '../rizin/formatters.js';

export function registerRzilGetRegisters(server: McpServer): void {
  server.tool(
    'rzil_get_registers',
    'Read all register values or a specific register from the Rizin RzIL VM. Returns typed values including individual CPU flags (zf, cf, sf, etc.) as booleans — superior to ESIL which packs flags into a single register.',
    {
      session_id: z.string().describe('RzIL session ID returned by rzil_init'),
      register_name: z
        .string()
        .optional()
        .describe(
          'Specific register or flag name (e.g. "rax", "rip", "zf", "cf"). If omitted, full VM state is returned.',
        ),
    },
    async ({ session_id, register_name }) => {
      try {
        const entry = rzilManager.get(session_id);
        const session = entry.session;

        if (register_name) {
          const safeName = sanitizeRegisterName(register_name);
          const value = (await session.cmd(`aezv ${safeName}`)).trim();
          if (value === '') {
            return mcpError(`Register "${safeName}" not found in RzIL VM state.`);
          }
          return mcpFormatted(`Register \`${safeName}\` = \`${value}\``);
        } else {
          const vmState = await session.cmdj<Record<string, unknown>>('aezvj');

          // Separate registers (hex strings) from flags (booleans)
          const registers: Record<string, number> = {};
          const flags: Record<string, boolean> = {};

          for (const [key, value] of Object.entries(vmState)) {
            if (typeof value === 'string' && value.startsWith('0x')) {
              registers[key] = parseInt(value, 16);
            } else if (typeof value === 'boolean') {
              flags[key] = value;
            }
          }

          const lines: string[] = [];
          lines.push(formatRzilRegisters(registers));

          // Append flags section
          if (Object.keys(flags).length > 0) {
            lines.push('\n### CPU Flags\n');
            lines.push('| Flag | Value |');
            lines.push('|------|-------|');
            for (const [name, value] of Object.entries(flags)) {
              lines.push(`| \`${name}\` | ${value} |`);
            }
          }

          return mcpFormatted(lines.join('\n'));
        }
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
