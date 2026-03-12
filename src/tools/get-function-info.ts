import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { withCachedSession } from '../r2/session-cache.js';
import { sanitizePath, sanitizeAddress, sanitizeFunctionName } from '../r2/sanitize.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatFunctionInfo } from '../utils/formatters.js';

interface R2FunctionInfo {
  readonly offset: number;
  readonly name: string;
  readonly size: number;
  readonly 'is-pure': string;
  readonly realsz: number;
  readonly noreturn: boolean;
  readonly stackframe: number;
  readonly calltype: string;
  readonly cost: number;
  readonly cc: number;
  readonly bits: number;
  readonly type: string;
  readonly nbbs: number;
  readonly edges: number;
  readonly ebbs: number;
  readonly signature: string;
  readonly minbound: number;
  readonly maxbound: number;
  readonly callrefs: readonly { addr: number; type: string; at: number }[];
  readonly datarefs: readonly number[];
  readonly codexrefs: readonly { addr: number; type: string; at: number }[];
  readonly dataxrefs: readonly number[];
  readonly indegree: number;
  readonly outdegree: number;
  readonly nlocals: number;
  readonly nargs: number;
  readonly bpvars: readonly { name: string; kind: string; type: string; ref: { base: string; offset: number } }[];
  readonly spvars: readonly { name: string; kind: string; type: string; ref: { base: string; offset: number } }[];
  readonly regvars: readonly { name: string; kind: string; type: string; ref: string }[];
  readonly difftype: string;
}

export function registerGetFunctionInfo(server: McpServer): void {
  server.tool(
    'get_function_info',
    'Get detailed metadata for a single function including cyclomatic complexity, stack frame, args, locals, and basic block count.',
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

          const info = await session.cmdj<R2FunctionInfo[]>('afij');

          if (!Array.isArray(info) || info.length === 0) {
            return mcpError(
              `No function found at ${address ?? function_name ?? 'current address'}`,
            );
          }

          return mcpFormatted(formatFunctionInfo(info[0] as Parameters<typeof formatFunctionInfo>[0]));
        });
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
