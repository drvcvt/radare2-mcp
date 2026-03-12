import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { rzilManager } from '../rizin/rzil-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';

export function registerRzilDestroy(server: McpServer): void {
  server.tool(
    'rzil_destroy',
    'Destroy a persistent RzIL session and release its resources. Use this when you are done with a Rizin emulation session.',
    {
      session_id: z.string().describe('RzIL session ID returned by rzil_init'),
    },
    async ({ session_id }) => {
      try {
        // Verify the session exists before destroying
        rzilManager.get(session_id);
        await rzilManager.destroy(session_id);
        return mcpFormatted(`RzIL session \`${session_id}\` destroyed.`);
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
