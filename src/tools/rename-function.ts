import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { R2Session } from '../r2/session.js';
import { sanitizePath, sanitizeAddress, sanitizeFunctionName } from '../r2/sanitize.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatRenameFunction } from '../utils/formatters.js';

export function registerRenameFunction(server: McpServer): void {
  server.tool(
    'rename_function',
    'Rename a function at the given address to a new user-defined name.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      address: z.string().describe('Hex address of the function (e.g. "0x08048000")'),
      new_name: z.string().describe('New name for the function'),
    },
    async ({ binary_path, address, new_name }) => {
      try {
        const safePath = sanitizePath(binary_path);
        const safeAddr = sanitizeAddress(address);
        const safeName = sanitizeFunctionName(new_name);
        const session = await R2Session.open(safePath);
        try {
          await session.cmd('aaa');
          await session.cmd(`s ${safeAddr}`);

          const oldNameRaw = await session.cmd('afi.');
          const oldName = oldNameRaw.trim().split('\n')[0] ?? 'unknown';

          await session.cmd(`afn ${safeName}`);

          return mcpFormatted(formatRenameFunction({
            address: safeAddr,
            old_name: oldName,
            new_name: safeName,
            success: true,
          }));
        } finally {
          await session.close();
        }
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
