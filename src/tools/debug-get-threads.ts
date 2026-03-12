import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizeSessionId } from '../r2/sanitize.js';
import { debugManager } from '../r2/debug-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatDebugThreadList } from '../utils/formatters.js';
import type { R2Thread } from '../types.js';

export function registerDebugGetThreads(server: McpServer): void {
  server.tool(
    'debug_get_threads',
    'List all threads in the debugged process with their status.',
    {
      session_id: z.string().describe('Debug session ID'),
    },
    async ({ session_id }) => {
      try {
        const safeId = sanitizeSessionId(session_id);
        const entry = debugManager.get(safeId);

        let threads: R2Thread[] = [];
        try {
          threads = await entry.session.cmdj<R2Thread[]>('dptj');
          if (!Array.isArray(threads)) threads = [];
        } catch {
          // dptj may not be available
        }

        return mcpFormatted(formatDebugThreadList(threads));
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
