import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { withCachedSession } from '../r2/session-cache.js';
import { sanitizePath } from '../r2/sanitize.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatBinaryInfo } from '../utils/formatters.js';

export function registerAnalyzeBinary(server: McpServer): void {
  server.tool(
    'analyze_binary',
    'Open and analyze a binary file, returning architecture, platform, entry point, and binary metadata as JSON.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      analysis_level: z
        .enum(['aa', 'aaa', 'aaaa'])
        .default('aaa')
        .describe('Analysis depth level (aa=basic, aaa=standard, aaaa=experimental)'),
    },
    async ({ binary_path, analysis_level }) => {
      try {
        const safePath = sanitizePath(binary_path);
        return await withCachedSession(
          safePath,
          async (session) => {
            const info = await session.cmdj<Record<string, unknown>>('ij');
            return mcpFormatted(formatBinaryInfo(info as Parameters<typeof formatBinaryInfo>[0]));
          },
          analysis_level,
        );
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
