import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizeSessionId, sanitizeAddress } from '../r2/sanitize.js';
import { debugManager } from '../r2/debug-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatReadBytes } from '../utils/formatters.js';

export function registerDebugReadMemory(server: McpServer): void {
  server.tool(
    'debug_read_memory',
    'Read memory from the debugged process at a specific address, returned as hex string or formatted hexdump.',
    {
      session_id: z.string().describe('Debug session ID'),
      address: z.string().describe('Hex address to read from (e.g. "0x08048000")'),
      count: z
        .number()
        .int()
        .min(1)
        .max(65_536)
        .default(64)
        .describe('Number of bytes to read (default 64)'),
      format: z
        .enum(['hex', 'hexdump'])
        .default('hexdump')
        .describe('Output format: "hex" for raw hex, "hexdump" for formatted dump'),
    },
    async ({ session_id, address, count, format }) => {
      try {
        const safeId = sanitizeSessionId(session_id);
        const safeAddr = sanitizeAddress(address);
        const entry = debugManager.get(safeId);

        let data: string;
        if (format === 'hex') {
          const raw = await entry.session.cmd(`p8 ${count} @ ${safeAddr}`);
          data = raw.trim();
        } else {
          const raw = await entry.session.cmd(`px ${count} @ ${safeAddr}`);
          data = raw.trim();
        }

        return mcpFormatted(formatReadBytes({
          address: safeAddr,
          count,
          format,
          data,
        }));
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
