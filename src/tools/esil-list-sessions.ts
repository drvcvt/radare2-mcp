import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { esilManager } from '../r2/esil-session-manager.js';
import { mcpFormatted } from '../utils/errors.js';

export function registerEsilListSessions(server: McpServer): void {
  server.tool(
    'esil_list_sessions',
    'List all active persistent ESIL sessions with their session IDs, binary paths, and creation times.',
    {},
    async () => {
      const sessions = esilManager.list();

      if (sessions.length === 0) {
        return mcpFormatted('No active ESIL sessions.');
      }

      const lines: string[] = [];
      lines.push(`## Active ESIL Sessions (${sessions.length})\n`);

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
