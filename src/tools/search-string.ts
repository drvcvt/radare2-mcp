import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { withCachedSession } from '../r2/session-cache.js';
import { sanitizePath, sanitizeSearchQuery } from '../r2/sanitize.js';
import { paginate } from '../utils/pagination.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatSearchResults } from '../utils/formatters.js';

interface StringSearchResult {
  readonly address: string;
  readonly string: string;
}

export function registerSearchString(server: McpServer): void {
  server.tool(
    'search_string',
    'Search for a string pattern in the binary and return all matching locations.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      query: z.string().min(1).describe('String pattern to search for'),
      case_sensitive: z
        .boolean()
        .default(true)
        .describe('Whether the search is case-sensitive'),
      offset: z.number().int().min(0).default(0).describe('Pagination offset (0-based)'),
      limit: z
        .number()
        .int()
        .min(1)
        .max(2000)
        .default(100)
        .describe('Max results to return'),
    },
    async ({ binary_path, query, case_sensitive, offset, limit }) => {
      try {
        const safePath = sanitizePath(binary_path);
        return await withCachedSession(safePath, async (session) => {
          const safeQuery = sanitizeSearchQuery(query);

          // Search for both ASCII and wide (UTF-16LE) strings.
          // ASCII: / (case-sensitive) or /i (case-insensitive)
          // Wide:  /w (always case-sensitive in r2)
          const asciiCmd = case_sensitive ? `/ ${safeQuery}` : `/i ${safeQuery}`;
          const wideCmd = `/w ${safeQuery}`;

          const [asciiRaw, wideRaw] = await Promise.all([
            session.cmd(asciiCmd),
            session.cmd(wideCmd),
          ]);

          const results: StringSearchResult[] = [];
          const seen = new Set<string>();

          for (const raw of [asciiRaw, wideRaw]) {
            const lines = raw.split('\n');
            for (const line of lines) {
              const trimmed = line.trim();
              if (trimmed.length === 0) continue;

              // r2 search output format: "0x<addr> hit<n>_<m> <string>"
              const match = /^(0x[0-9a-fA-F]+)\s+\S+\s+(.*)$/.exec(trimmed);
              if (match) {
                const addr = match[1];
                const str = match[2];
                if (addr && str !== undefined && !seen.has(addr)) {
                  seen.add(addr);
                  results.push({
                    address: addr,
                    string: str,
                  });
                }
              }
            }
          }

          const page = paginate(results, offset, limit);
          return mcpFormatted(formatSearchResults(page, 'string'));
        });
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
