import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizeSessionId } from '../r2/sanitize.js';
import { debugManager } from '../r2/debug-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatDebugMaps } from '../utils/formatters.js';
import type { R2MemoryMap } from '../types.js';

export function registerDebugGetMaps(server: McpServer): void {
  server.tool(
    'debug_get_maps',
    'List memory maps of the debugged process with addresses, sizes, and permissions.',
    {
      session_id: z.string().describe('Debug session ID'),
    },
    async ({ session_id }) => {
      try {
        const safeId = sanitizeSessionId(session_id);
        const entry = debugManager.get(safeId);

        let maps: R2MemoryMap[] = [];
        try {
          maps = await entry.session.cmdj<R2MemoryMap[]>('dmj');
          if (!Array.isArray(maps)) maps = [];
        } catch {
          // dmj may not work on all platforms
        }

        return mcpFormatted(formatDebugMaps(maps));
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
