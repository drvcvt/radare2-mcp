import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { R2Session } from '../r2/session.js';
import { sanitizePath, sanitizeAddress, sanitizeComment } from '../r2/sanitize.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatAddComment } from '../utils/formatters.js';

export function registerAddComment(server: McpServer): void {
  server.tool(
    'add_comment',
    'Add or update a comment at a specific address in the binary.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      address: z.string().describe('Hex address (e.g. "0x08048000")'),
      comment: z.string().describe('Comment text to add at the address'),
    },
    async ({ binary_path, address, comment }) => {
      try {
        const safePath = sanitizePath(binary_path);
        const safeAddr = sanitizeAddress(address);
        const base64Comment = sanitizeComment(comment);
        const session = await R2Session.open(safePath);
        try {
          await session.cmd('aaa');
          await session.cmd(`s ${safeAddr}`);
          await session.cmd(`CCa ${safeAddr} base64:${base64Comment}`);
          return mcpFormatted(formatAddComment({
            address: safeAddr,
            comment: comment.trim(),
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
