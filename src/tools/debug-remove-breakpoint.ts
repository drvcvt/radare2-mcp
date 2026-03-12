import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizeSessionId, sanitizeAddress } from '../r2/sanitize.js';
import { debugManager } from '../r2/debug-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatDebugBreakpoints } from '../utils/formatters.js';
import type { R2Breakpoint } from '../types.js';

export function registerDebugRemoveBreakpoint(server: McpServer): void {
  server.tool(
    'debug_remove_breakpoint',
    'Remove a breakpoint at the specified address or remove all breakpoints.',
    {
      session_id: z.string().describe('Debug session ID'),
      address: z
        .string()
        .optional()
        .describe('Hex address of the breakpoint to remove. Omit to remove all breakpoints.'),
    },
    async ({ session_id, address }) => {
      try {
        const safeId = sanitizeSessionId(session_id);
        const entry = debugManager.get(safeId);
        const safeAddr = address !== undefined ? sanitizeAddress(address) : undefined;

        if (safeAddr !== undefined) {
          await entry.session.cmd(`db- ${safeAddr}`);
        } else {
          await entry.session.cmd('db-*');
        }

        // Return updated breakpoint list
        let breakpoints: R2Breakpoint[] = [];
        try {
          breakpoints = await entry.session.cmdj<R2Breakpoint[]>('dbj');
          if (!Array.isArray(breakpoints)) breakpoints = [];
        } catch {
          // dbj may fail
        }

        const target = safeAddr !== undefined ? `\`${safeAddr}\`` : 'all';
        const lines: string[] = [];
        lines.push(`Removed breakpoint(s): ${target}\n`);
        lines.push(formatDebugBreakpoints(breakpoints));
        return mcpFormatted(lines.join('\n'));
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
