import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizePid } from '../r2/sanitize.js';
import { debugManager } from '../r2/debug-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatDebugSession, formatDebugRegisters } from '../utils/formatters.js';

export function registerDebugAttach(server: McpServer): void {
  server.tool(
    'debug_attach',
    'Attach the radare2 debugger to a running process by PID and return a persistent session ID.',
    {
      pid: z.number().int().positive().describe('Process ID to attach to'),
    },
    async ({ pid }) => {
      try {
        const safePid = sanitizePid(pid);
        const entry = await debugManager.attach(safePid);

        // Run analysis on the attached process
        await entry.session.cmd('aaa');

        // Get initial registers
        const registers = await entry.session.cmdj<Record<string, number>>('drj');

        const lines: string[] = [];
        lines.push(formatDebugSession({ sessionId: entry.sessionId, target: `pid:${safePid}`, pid: safePid }));
        lines.push('');
        if (registers) lines.push(formatDebugRegisters(registers, 'Initial Registers'));
        return mcpFormatted(lines.join('\n'));
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
