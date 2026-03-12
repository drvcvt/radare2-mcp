import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizeAddress } from '../r2/sanitize.js';
import { rzilManager } from '../rizin/rzil-session-manager.js';
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
  // Block r2 metacharacters and newlines/null bytes (Rizin protocol splits on \n)
  if (/[;|><`$&!#\r\n\0]/.test(data)) {
    throw new Error(
      'String data contains forbidden characters that could break Rizin command parsing.',
    );
  }
  return data;
}

export function registerRzilSetMemory(server: McpServer): void {
  server.tool(
    'rzil_set_memory',
    'Write data to the Rizin RzIL emulated memory space at a given address. Requires a persistent session from rzil_init.',
    {
      session_id: z.string().describe('RzIL session ID returned by rzil_init'),
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
    async ({ session_id, address, data, as_string }) => {
      try {
        const safeAddr = sanitizeAddress(address);
        const entry = rzilManager.get(session_id);
        const session = entry.session;

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
      }
    },
  );
}
