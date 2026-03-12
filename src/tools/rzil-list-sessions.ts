import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { rzilManager } from '../rizin/rzil-session-manager.js';
import { mcpFormatted } from '../utils/errors.js';

export function registerRzilListSessions(server: McpServer): void {
  server.tool(
    'rzil_list_sessions',
    'List all active persistent RzIL emulation sessions with their session IDs, binary paths, and creation times.',
    {},
    async () => {
      const sessions = rzilManager.list();

      if (sessions.length === 0) {
        return mcpFormatted('No active RzIL sessions.');
      }

      const lines: string[] = [];
      lines.push(`## Active RzIL Sessions (${sessions.length})\n`);

      for (const entry of sessions) {
        const age = Math.round((Date.now() - entry.createdAt) / 1000);
        const idle = Math.round((Date.now() - entry.lastUsed) / 1000);
        lines.push(`- **\`${entry.sessionId}\`**`);
        lines.push(`  - Binary: \`${entry.binaryPath}\``);
        lines.push(`  - Start address: \`${entry.startAddress ?? 'entry point'}\``);
        lines.push(`  - Age: ${age}s, Idle: ${idle}s`);
      }

      return mcpFormatted(lines.join('\n'));
    },
  );
}
