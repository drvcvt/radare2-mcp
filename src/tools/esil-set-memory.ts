import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { R2Session } from '../r2/session.js';
import { sanitizePath, sanitizeAddress } from '../r2/sanitize.js';
import { esilManager } from '../r2/esil-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';

const HEX_BYTES_RE = /^[0-9a-fA-F]+$/;

function sanitizeHexData(data: string): string {
  const trimmed = data.trim();
  if (!HEX_BYTES_RE.test(trimmed)) {
    throw new Error(
      `Invalid hex data: ${trimmed}. Must contain only hex characters (e.g. "90909090").`,
    );
  }
  if (trimmed.length % 2 !== 0) {
    throw new Error(
      'Hex data must have an even number of characters (each byte is 2 hex digits).',
    );
  }
  return trimmed;
}

function sanitizeStringData(data: string): string {
  // Block r2 metacharacters and control characters (newlines, null bytes)
  if (/[;|><`$&!#\r\n\0]/.test(data)) {
    throw new Error(
      'String data contains forbidden characters that could break r2 command parsing.',
    );
  }
  return data;
}

export function registerEsilSetMemory(server: McpServer): void {
  server.tool(
    'esil_set_memory',
    'Write data to the ESIL emulated memory space at a given address. If session_id is provided, uses a persistent session; otherwise creates a fresh session.',
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
      address: z.string().describe('Address (hex) to write memory to'),
      data: z
        .string()
        .describe(
          'Data to write: hex bytes (e.g. "90909090") or a string if as_string is true',
        ),
      as_string: z
        .boolean()
        .default(false)
        .describe(
          'If true, write data as an ASCII string; otherwise write as raw hex bytes',
        ),
    },
    async ({ binary_path, session_id, address, data, as_string }) => {
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

        await session.cmd(`s ${safeAddr}`);

        let bytesWritten: number;
        if (as_string) {
          const safeData = sanitizeStringData(data);
          await session.cmd(`w ${safeData}`);
          bytesWritten = safeData.length;
        } else {
          const safeData = sanitizeHexData(data);
          await session.cmd(`wx ${safeData}`);
          bytesWritten = safeData.length / 2;
        }

        return mcpFormatted(`Wrote **${bytesWritten}** bytes to \`${safeAddr}\``);
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
