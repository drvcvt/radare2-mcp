import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { withCachedSession } from '../r2/session-cache.js';
import { sanitizePath, sanitizeAddress, sanitizeFunctionName } from '../r2/sanitize.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatVariables } from '../utils/formatters.js';

interface R2Variable {
  readonly name: string;
  readonly kind: string;
  readonly type: string;
  readonly ref: unknown;
}

interface R2Variables {
  readonly bp: readonly R2Variable[];
  readonly sp: readonly R2Variable[];
  readonly reg: readonly R2Variable[];
}

export function registerListVariables(server: McpServer): void {
  server.tool(
    'list_variables',
    'List all local variables, stack variables, and arguments of a function.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      address: z
        .string()
        .optional()
        .describe('Hex address of the function (e.g. "0x08048000")'),
      function_name: z
        .string()
        .optional()
        .describe('Name of the function (e.g. "main")'),
    },
    async ({ binary_path, address, function_name }) => {
      try {
        if (address === undefined && function_name === undefined) {
          return mcpError('Either address or function_name must be provided');
        }

        const safePath = sanitizePath(binary_path);
        return await withCachedSession(safePath, async (session) => {
          if (address !== undefined) {
            const safeAddr = sanitizeAddress(address);
            await session.cmd(`s ${safeAddr}`);
          } else if (function_name !== undefined) {
            const safeName = sanitizeFunctionName(function_name);
            await session.cmd(`s ${safeName}`);
          }

          const vars = await session.cmdj<R2Variables>('afvj');

          if (vars === null || (Array.isArray(vars) && vars.length === 0)) {
            return mcpFormatted(formatVariables({ bp: [], sp: [], reg: [] }));
          }

          return mcpFormatted(formatVariables(vars as Parameters<typeof formatVariables>[0]));
        });
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
