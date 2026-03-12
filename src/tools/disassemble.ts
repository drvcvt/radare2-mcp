import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { withCachedSession } from '../r2/session-cache.js';
import { sanitizePath, sanitizeAddress, sanitizeFunctionName } from '../r2/sanitize.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatDisassemblyFunction, formatDisassemblyInstructions } from '../utils/formatters.js';
import type { R2DisasmFunction, R2Instruction } from '../types.js';

export function registerDisassemble(server: McpServer): void {
  server.tool(
    'disassemble',
    'Disassemble instructions at the given address or function, returning assembly with opcodes and metadata.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      address: z
        .string()
        .optional()
        .describe('Hex address to disassemble at (e.g. "0x08048000")'),
      function_name: z
        .string()
        .optional()
        .describe('Name of the function to disassemble (e.g. "main")'),
      count: z
        .number()
        .int()
        .min(1)
        .max(10000)
        .default(32)
        .describe('Number of instructions to disassemble (used with address mode)'),
    },
    async ({ binary_path, address, function_name, count }) => {
      try {
        if (!address && !function_name) {
          return mcpError('Either address or function_name must be provided');
        }

        const safePath = sanitizePath(binary_path);
        return await withCachedSession(safePath, async (session) => {
          if (function_name) {
            const safeName = sanitizeFunctionName(function_name);
            await session.cmd(`s ${safeName}`);
            const result = await session.cmdj<R2DisasmFunction>('pdfj');
            return mcpFormatted(formatDisassemblyFunction(result));
          } else {
            const safeAddr = sanitizeAddress(address!);
            await session.cmd(`s ${safeAddr}`);
            const instructions = await session.cmdj<R2Instruction[]>(`pdj ${count}`);
            return mcpFormatted(formatDisassemblyInstructions(instructions));
          }
        });
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
