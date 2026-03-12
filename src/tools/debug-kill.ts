import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizeSessionId } from '../r2/sanitize.js';
import { debugManager } from '../r2/debug-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';

export function registerDebugKill(server: McpServer): void {
  server.tool(
    'debug_kill',
    'Kill the debugged process and close the debug session.',
    {
      session_id: z
        .string()
        .describe('Debug session ID returned by debug_launch or debug_attach'),
    },
    async ({ session_id }) => {
      try {
        const safeId = sanitizeSessionId(session_id);
        const entry = debugManager.get(safeId);

        // Send SIGKILL (signal 9) to the debugged process
        try {
          await entry.session.cmd('dk 9');
        } catch {
          // Process may already be gone
        }

        // Clean up the session via detach (which closes the r2 session and removes from manager)
        await debugManager.detach(safeId);

        return mcpFormatted(
          `Killed process and closed debug session \`${safeId}\`.`,
        );
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
