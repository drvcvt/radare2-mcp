import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizeSessionId, sanitizeAddress } from '../r2/sanitize.js';
import { debugManager } from '../r2/debug-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatDebugBreakpoints } from '../utils/formatters.js';
import type { R2Breakpoint } from '../types.js';

export function registerDebugSetBreakpoint(server: McpServer): void {
  server.tool(
    'debug_set_breakpoint',
    'Set a software breakpoint at the specified address in the debugged process.',
    {
      session_id: z.string().describe('Debug session ID'),
      address: z.string().describe('Hex address for the breakpoint (e.g. "0x08048000")'),
      hardware: z
        .boolean()
        .default(false)
        .describe('Use hardware breakpoint instead of software'),
    },
    async ({ session_id, address, hardware }) => {
      try {
        const safeId = sanitizeSessionId(session_id);
        const safeAddr = sanitizeAddress(address);
        const entry = debugManager.get(safeId);

        const cmd = hardware ? `dbh ${safeAddr}` : `db ${safeAddr}`;
        await entry.session.cmd(cmd);

        // Return updated breakpoint list
        let breakpoints: R2Breakpoint[] = [];
        try {
          breakpoints = await entry.session.cmdj<R2Breakpoint[]>('dbj');
          if (!Array.isArray(breakpoints)) breakpoints = [];
        } catch {
          // dbj may fail
        }

        const lines: string[] = [];
        lines.push(`Breakpoint set at \`${safeAddr}\`${hardware ? ' (hardware)' : ''}\n`);
        lines.push(formatDebugBreakpoints(breakpoints));
        return mcpFormatted(lines.join('\n'));
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
