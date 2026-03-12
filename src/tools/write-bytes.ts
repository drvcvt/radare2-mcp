import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { R2Session } from '../r2/session.js';
import { sanitizePath, sanitizeAddress, sanitizeCommand } from '../r2/sanitize.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatWriteBytes } from '../utils/formatters.js';

/** Hex-only pattern for raw byte writes. */
const HEX_BYTES_RE = /^[0-9a-fA-F]+$/;

export function registerWriteBytes(server: McpServer): void {
  server.tool(
    'write_bytes',
    'Patch bytes at a specific address in the binary using hex bytes or assembly instructions.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      address: z.string().describe('Hex address to write at (e.g. "0x08048000")'),
      hex_bytes: z
        .string()
        .optional()
        .describe('Hex bytes to write (e.g. "9090" for two NOPs)'),
      assembly: z
        .string()
        .optional()
        .describe('Assembly instruction to assemble and write (e.g. "nop" or "jmp 0x08048100")'),
    },
    async ({ binary_path, address, hex_bytes, assembly }) => {
      if (hex_bytes === undefined && assembly === undefined) {
        return mcpError('Either hex_bytes or assembly must be provided');
      }

      if (hex_bytes !== undefined && !HEX_BYTES_RE.test(hex_bytes)) {
        return mcpError(
          `Invalid hex_bytes: must contain only hex characters (0-9, a-f, A-F), got "${hex_bytes}"`,
        );
      }

      try {
        const safePath = sanitizePath(binary_path);
        const safeAddr = sanitizeAddress(address);
        const session = await R2Session.open(safePath, ['-2', '-w']);
        try {
          await session.cmd('aaa');
          await session.cmd(`s ${safeAddr}`);

          // Read bytes before patch for verification
          const byteCount = hex_bytes !== undefined ? hex_bytes.length / 2 : 16;
          const beforeRaw = await session.cmd(`px ${Math.max(byteCount, 16)}`);
          const before = beforeRaw.trim();

          if (hex_bytes !== undefined) {
            await session.cmd(`wx ${hex_bytes}`);
          } else if (assembly !== undefined) {
            const safeAsm = sanitizeCommand(assembly);
            await session.cmd(`wa ${safeAsm}`);
          }

          // Read bytes after patch for verification
          const afterRaw = await session.cmd(`px ${Math.max(byteCount, 16)}`);
          const after = afterRaw.trim();

          return mcpFormatted(formatWriteBytes({
            address: safeAddr,
            operation: hex_bytes !== undefined ? 'hex_write' : 'assemble',
            input: hex_bytes ?? assembly,
            before,
            after,
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
