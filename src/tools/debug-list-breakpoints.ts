import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizeSessionId } from '../r2/sanitize.js';
import { debugManager } from '../r2/debug-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatDebugBreakpoints } from '../utils/formatters.js';
import type { R2Breakpoint } from '../types.js';

export function registerDebugListBreakpoints(server: McpServer): void {
  server.tool(
    'debug_list_breakpoints',
    'List all active breakpoints in the debug session with their addresses and status.',
    {
      session_id: z.string().describe('Debug session ID'),
    },
    async ({ session_id }) => {
      try {
        const safeId = sanitizeSessionId(session_id);
        const entry = debugManager.get(safeId);

        let breakpoints: R2Breakpoint[] = [];
        try {
          breakpoints = await entry.session.cmdj<R2Breakpoint[]>('dbj');
          if (!Array.isArray(breakpoints)) breakpoints = [];
        } catch {
          // dbj may return empty
        }

        return mcpFormatted(formatDebugBreakpoints(breakpoints));
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
