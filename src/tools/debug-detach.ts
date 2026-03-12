import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizeSessionId } from '../r2/sanitize.js';
import { debugManager } from '../r2/debug-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatDebugDetach } from '../utils/formatters.js';

export function registerDebugDetach(server: McpServer): void {
  server.tool(
    'debug_detach',
    'Detach from the debugged process, leaving it running, and close the debug session.',
    {
      session_id: z.string().describe('Debug session ID returned by debug_launch or debug_attach'),
    },
    async ({ session_id }) => {
      try {
        const safeId = sanitizeSessionId(session_id);
        await debugManager.detach(safeId);

        return mcpFormatted(formatDebugDetach(safeId));
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
