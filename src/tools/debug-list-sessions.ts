import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { debugManager } from '../r2/debug-session-manager.js';
import { mcpFormatted } from '../utils/errors.js';
import { formatDebugSessionList } from '../utils/formatters.js';

export function registerDebugListSessions(server: McpServer): void {
  server.tool(
    'debug_list_sessions',
    'List all active debug sessions with their session IDs, targets, and PIDs.',
    {},
    async () => { // eslint-disable-line @typescript-eslint/require-await
      const entries = debugManager.list();
      return mcpFormatted(formatDebugSessionList(entries));
    },
  );
}
