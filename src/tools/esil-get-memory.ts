import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { R2Session } from '../r2/session.js';
import { sanitizePath, sanitizeAddress } from '../r2/sanitize.js';
import { esilManager } from '../r2/esil-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatReadBytes } from '../utils/formatters.js';

export function registerEsilGetMemory(server: McpServer): void {
  server.tool(
    'esil_get_memory',
    'Read memory contents from the ESIL emulated memory space at a given address. If session_id is provided, uses a persistent session; otherwise creates a fresh session.',
    {
      binary_path: z
        .string()
        .optional()
        .describe(
          'Absolute path to the binary file. Required when session_id is not provided.',
        ),
      session_id: z
        .string()
        .optional()
        .describe(
          'Persistent ESIL session ID from esil_init. If provided, binary_path is ignored.',
        ),
      address: z.string().describe('Address (hex) to read memory from'),
      size: z
        .number()
        .int()
        .min(1)
        .max(65536)
        .default(64)
        .describe('Number of bytes to read (default 64)'),
      format: z
        .enum(['hex', 'string', 'hexdump'])
        .default('hex')
        .describe(
          'Output format: "hex" (raw hex bytes), "string" (ASCII), or "hexdump" (classic hex dump)',
        ),
    },
    async ({ binary_path, session_id, address, size, format }) => {
      let freshSession: R2Session | undefined;
      try {
        const safeAddr = sanitizeAddress(address);

        let session: R2Session;

        if (session_id) {
          const entry = esilManager.get(session_id);
          session = entry.session;
        } else {
          if (!binary_path) {
            return mcpError('binary_path is required when session_id is not provided.');
          }
          const safePath = sanitizePath(binary_path);
          freshSession = await R2Session.open(safePath);
          session = freshSession;
          await session.cmd('aaa');

          await session.cmd('aei');
          await session.cmd('aeim');
          await session.cmd('aeip');
        }

        // Seek to the requested address
        await session.cmd(`s ${safeAddr}`);

        let data: string;
        switch (format) {
          case 'hex':
            data = (await session.cmd(`p8 ${size}`)).trim();
            break;
          case 'string':
            data = (await session.cmd(`ps ${size}`)).trim();
            break;
          case 'hexdump':
            data = (await session.cmd(`px ${size}`)).trim();
            break;
        }

        return mcpFormatted(
          formatReadBytes({
            address: safeAddr,
            size,
            format,
            data,
          }),
        );
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      } finally {
        if (freshSession) {
          await freshSession.close();
        }
      }
    },
  );
}
