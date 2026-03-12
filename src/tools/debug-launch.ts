import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizePath } from '../r2/sanitize.js';
import { debugManager } from '../r2/debug-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatDebugLaunch } from '../utils/formatters.js';
import type { R2DebugInfo } from '../types.js';

export function registerDebugLaunch(server: McpServer): void {
  server.tool(
    'debug_launch',
    'Launch a binary under the radare2 debugger and return a persistent session ID for subsequent debug commands.',
    {
      binary_path: z.string().describe('Absolute path to the binary file to debug'),
    },
    async ({ binary_path }) => {
      try {
        const safePath = sanitizePath(binary_path);
        const entry = await debugManager.launch(safePath);

        // Run basic analysis
        await entry.session.cmd('aaa');

        // Get initial debug info
        let debugInfo: R2DebugInfo | undefined;
        try {
          debugInfo = await entry.session.cmdj<R2DebugInfo>('dij');
        } catch {
          // dij may not be available on all platforms
        }

        // Get initial registers
        const registers = await entry.session.cmdj<Record<string, number>>('drj');

        return mcpFormatted(formatDebugLaunch({
          session_id: entry.sessionId,
          target: safePath,
          pid: entry.pid,
          debug_info: debugInfo,
          registers,
          message: 'Debug session started. Use session_id for all subsequent debug commands.',
        }));
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
