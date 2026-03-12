import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizeSessionId } from '../r2/sanitize.js';
import { debugManager } from '../r2/debug-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatDebugProcessInfo } from '../utils/formatters.js';
import type { R2DebugInfo } from '../types.js';

export function registerDebugGetInfo(server: McpServer): void {
  server.tool(
    'debug_get_info',
    'Get debug session information including PID, status, executable path, and command line.',
    {
      session_id: z.string().describe('Debug session ID'),
    },
    async ({ session_id }) => {
      try {
        const safeId = sanitizeSessionId(session_id);
        const entry = debugManager.get(safeId);

        let debugInfo: R2DebugInfo | undefined;
        try {
          debugInfo = await entry.session.cmdj<R2DebugInfo>('dij');
        } catch {
          // dij may not be available
        }

        return mcpFormatted(formatDebugProcessInfo({
          sessionId: safeId,
          target: entry.target,
          pid: entry.pid,
          attachedAt: entry.attachedAt,
          debugInfo,
        }));
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
