import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { esilManager } from '../r2/esil-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';

export function registerEsilDestroy(server: McpServer): void {
  server.tool(
    'esil_destroy',
    'Destroy a persistent ESIL session and release its resources. Use this when you are done with an emulation session.',
    {
      session_id: z.string().describe('ESIL session ID returned by esil_init'),
    },
    async ({ session_id }) => {
      try {
        // Verify the session exists before destroying
        esilManager.get(session_id);
        await esilManager.destroy(session_id);
        return mcpFormatted(`ESIL session \`${session_id}\` destroyed.`);
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
