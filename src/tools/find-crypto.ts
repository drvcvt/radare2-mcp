import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { withCachedSession } from '../r2/session-cache.js';
import { sanitizePath } from '../r2/sanitize.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatCryptoConstants } from '../utils/formatters.js';

interface CryptoConstant {
  readonly offset: number;
  readonly algorithm: string;
  readonly bits: number;
}

/** Parse `/ca` text output as fallback when `/caj` is unavailable. */
function parseCryptoText(raw: string): CryptoConstant[] {
  const results: CryptoConstant[] = [];
  const lines = raw.trim().split('\n');

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === '') continue;

    // Typical /ca output: "0x00401000 algorithm bits"
    const match = trimmed.match(/^(0x[0-9a-fA-F]+)\s+(.+?)(?:\s+(\d+))?$/);
    if (match) {
      results.push({
        offset: parseInt(match[1] as string, 16),
        algorithm: (match[2] as string).trim(),
        bits: match[3] !== undefined ? parseInt(match[3], 10) : 0,
      });
    }
  }

  return results;
}

export function registerFindCryptoConstants(server: McpServer): void {
  server.tool(
    'find_crypto_constants',
    'Detect cryptographic constants (AES S-boxes, CRC tables, RSA constants, SHA magic numbers) in the binary.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
    },
    async ({ binary_path }) => {
      try {
        const safePath = sanitizePath(binary_path);
        return await withCachedSession(safePath, async (session) => {
          // Try JSON output first
          let results: CryptoConstant[];
          try {
            const json = await session.cmdj<CryptoConstant[]>('/caj');
            results = Array.isArray(json) ? json : [];
          } catch {
            // Fall back to text parsing
            const raw = await session.cmd('/ca');
            results = parseCryptoText(raw);
          }

          return mcpFormatted(formatCryptoConstants({
            results,
            total: results.length,
          }));
        });
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
