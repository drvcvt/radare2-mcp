import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizeSessionId } from '../r2/sanitize.js';
import { debugManager } from '../r2/debug-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatDebugBacktrace } from '../utils/formatters.js';
import type { R2BacktraceFrame } from '../types.js';

export function registerDebugGetBacktrace(server: McpServer): void {
  server.tool(
    'debug_get_backtrace',
    'Get the call stack backtrace of the debugged process.',
    {
      session_id: z.string().describe('Debug session ID'),
    },
    async ({ session_id }) => {
      try {
        const safeId = sanitizeSessionId(session_id);
        const entry = debugManager.get(safeId);

        let frames: R2BacktraceFrame[] = [];
        try {
          frames = await entry.session.cmdj<R2BacktraceFrame[]>('dbtj');
          if (!Array.isArray(frames)) frames = [];
        } catch {
          // dbtj may fail
        }

        return mcpFormatted(formatDebugBacktrace(frames));
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
