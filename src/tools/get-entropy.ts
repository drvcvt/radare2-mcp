import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { R2Session } from '../r2/session.js';
import { withCachedSession } from '../r2/session-cache.js';
import { sanitizePath, sanitizeAddress } from '../r2/sanitize.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatEntropy } from '../utils/formatters.js';

interface EntropyEntry {
  readonly address: string;
  readonly entropy: number;
}

/**
 * r2's `p=ej` returns values scaled 0-255 (byte range). Convert to the
 * standard Shannon entropy scale of 0.0-8.0 (bits per byte).
 */
function scaleTo8(value: number): number {
  return Math.round((value * 8.0 / 255.0) * 1000) / 1000;
}

/**
 * Parse the JSON output of `p=ej`.
 *
 * r2 returns one of two shapes depending on version:
 *   - Wrapped:  `{ "blocksize": N, "entropy": [{ "addr": N, "value": N }, ...] }`
 *   - Direct:   `[{ "addr": N, "value": N }, ...]`
 *
 * Values are in 0-255 range; we scale them to 0.0-8.0.
 */
function parseEntropyJson(raw: string): EntropyEntry[] {
  const trimmed = raw.trim();
  if (trimmed.length === 0) return [];

  const parsed: unknown = JSON.parse(trimmed);

  // Wrapped format: { entropy: [...] }
  if (
    typeof parsed === 'object' &&
    parsed !== null &&
    'entropy' in parsed &&
    Array.isArray((parsed as { entropy: unknown }).entropy)
  ) {
    const arr = (parsed as { entropy: Array<{ addr: number; value: number }> }).entropy;
    return arr.map((e) => ({
      address: `0x${e.addr.toString(16)}`,
      entropy: scaleTo8(e.value),
    }));
  }

  // Direct array format: [{ addr, value }, ...]
  if (Array.isArray(parsed)) {
    return (parsed as Array<{ addr: number; value: number }>).map((e) => ({
      address: `0x${e.addr.toString(16)}`,
      entropy: scaleTo8(e.value),
    }));
  }

  return [];
}

/**
 * Parse text-format entropy output from `p=e`.
 * Lines typically look like:
 *   0x08048000 000 00c7 |#####...
 * We extract the address and the hex entropy value.
 */
function parseEntropyText(raw: string): EntropyEntry[] {
  const entries: EntropyEntry[] = [];
  const lines = raw.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;

    // Match: "0x<addr> <dec> <hex> |..."
    const match = /^(0x[0-9a-fA-F]+)\s+\d+\s+([0-9a-fA-F]+)/.exec(trimmed);
    if (match) {
      const addr = match[1];
      const hexVal = parseInt(match[2] ?? '0', 16);
      if (addr && !isNaN(hexVal)) {
        entries.push({ address: addr, entropy: scaleTo8(hexVal) });
      }
      continue;
    }

    // Fallback: "0x<addr> <float>"
    const matchFloat = /^(0x[0-9a-fA-F]+)\s+([\d.]+)/.exec(trimmed);
    if (matchFloat) {
      const addr = matchFloat[1];
      const ent = parseFloat(matchFloat[2] ?? '0');
      if (addr && !isNaN(ent)) {
        entries.push({ address: addr, entropy: ent });
      }
    }
  }
  return entries;
}

/**
 * Run entropy analysis on the current seek position / block and return entries.
 * Tries JSON output (`p=ej`) first, falls back to text (`p=e`).
 */
async function runEntropyCommand(session: R2Session): Promise<EntropyEntry[]> {
  try {
    const raw = await session.cmd('p=ej');
    const entries = parseEntropyJson(raw);
    if (entries.length > 0) {
      return entries;
    }
  } catch {
    // Fall through to text-based parsing
  }

  const raw = await session.cmd('p=e');
  return parseEntropyText(raw);
}

export function registerGetEntropy(server: McpServer): void {
  server.tool(
    'get_entropy',
    'Calculate entropy for the binary or specific sections to detect packed or encrypted regions.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      address: z
        .string()
        .optional()
        .describe('Start address for entropy calculation (hex)'),
      size: z
        .number()
        .int()
        .min(1)
        .optional()
        .describe('Number of bytes to analyze for entropy'),
    },
    async ({ binary_path, address, size }) => {
      try {
        const safePath = sanitizePath(binary_path);
        return await withCachedSession(safePath, async (session) => {
          let allEntries: EntropyEntry[];

          if (address) {
            // Targeted entropy: seek to the address, optionally set block size
            const safeAddr = sanitizeAddress(address);
            await session.cmd(`s ${safeAddr}`);

            if (size) {
              await session.cmd(`b ${size}`);
            }

            allEntries = await runEntropyCommand(session);
          } else {
            // Full binary entropy: iterate over all sections for complete coverage.
            // Keep the default block size (256) for good granularity — each section
            // will produce section_size/256 entropy data points.
            allEntries = [];

            try {
              const sectionsRaw = await session.cmd('iSj');
              const trimmedSections = sectionsRaw.trim();
              if (trimmedSections.startsWith('[')) {
                const sections = JSON.parse(trimmedSections) as Array<{
                  name: string;
                  vaddr: number;
                  vsize: number;
                  perm: string;
                }>;

                for (const sec of sections) {
                  if (sec.vsize === 0 || sec.vaddr === 0) continue;
                  await session.cmd(`s 0x${sec.vaddr.toString(16)}`);
                  const entries = await runEntropyCommand(session);
                  allEntries.push(...entries);
                }
              }
            } catch {
              // If section iteration fails, try entropy at default position
              allEntries = await runEntropyCommand(session);
            }
          }

          // Calculate overall statistics
          const entropyValues = allEntries.map((e) => e.entropy);
          const avgEntropy =
            entropyValues.length > 0
              ? entropyValues.reduce((sum, v) => sum + v, 0) / entropyValues.length
              : 0;
          const maxEntropy =
            entropyValues.length > 0 ? Math.max(...entropyValues) : 0;
          const minEntropy =
            entropyValues.length > 0 ? Math.min(...entropyValues) : 0;

          return mcpFormatted(formatEntropy({
            entry_count: allEntries.length,
            statistics: {
              average: Math.round(avgEntropy * 1000) / 1000,
              min: Math.round(minEntropy * 1000) / 1000,
              max: Math.round(maxEntropy * 1000) / 1000,
              high_entropy_detected: maxEntropy > 6.5,
            },
            entries: allEntries,
          }));
        });
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
