import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizeSessionId, sanitizeAddress } from '../r2/sanitize.js';
import { debugManager } from '../r2/debug-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatDebugContinue } from '../utils/formatters.js';

export function registerDebugContinue(server: McpServer): void {
  server.tool(
    'debug_continue',
    'Continue execution of the debugged process until a breakpoint is hit, an address is reached, or the process exits.',
    {
      session_id: z.string().describe('Debug session ID'),
      until_address: z
        .string()
        .optional()
        .describe('Stop at this address (sets temporary breakpoint). If omitted, continues until next breakpoint or exit.'),
      timeout_ms: z
        .number()
        .int()
        .min(1000)
        .max(600_000)
        .default(300_000)
        .describe('Timeout in milliseconds (default 5 minutes)'),
    },
    async ({ session_id, until_address, timeout_ms }) => {
      try {
        const safeId = sanitizeSessionId(session_id);
        const entry = debugManager.get(safeId);

        if (until_address !== undefined) {
          const safeAddr = sanitizeAddress(until_address);
          await entry.session.cmd(`dcu ${safeAddr}`, timeout_ms);
        } else {
          await entry.session.cmd('dc', timeout_ms);
        }

        // Get state after stopping
        const registers = await entry.session.cmdj<Record<string, number>>('drj');

        // Get current instruction
        let currentInstruction = '';
        try {
          currentInstruction = (await entry.session.cmd('pd 1')).trim();
        } catch {
          // May fail if process exited
        }

        // Check if process is still alive
        let status = 'unknown';
        try {
          const info = await entry.session.cmdj<{ status?: string }>('dij');
          status = info?.status ?? 'unknown';
        } catch {
          status = 'exited';
        }

        return mcpFormatted(formatDebugContinue({
          status,
          currentInstruction: currentInstruction || undefined,
          registers,
        }));
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
