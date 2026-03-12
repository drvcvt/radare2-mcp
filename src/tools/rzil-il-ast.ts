import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizePath, sanitizeAddress } from '../r2/sanitize.js';
import { RizinSession } from '../rizin/rizin-session.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';

export function registerRzilIlAst(server: McpServer): void {
  server.tool(
    'rzil_il_ast',
    'Get the RzIL intermediate language AST for instructions at a given address. Each instruction is lifted to a typed RzIL expression tree with bitvector operations. This is unique to Rizin — r2 ESIL only has flat string expressions.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      address: z
        .string()
        .optional()
        .describe('Address to disassemble from (hex). Defaults to entry point.'),
      count: z
        .number()
        .int()
        .min(1)
        .max(100)
        .default(5)
        .describe('Number of instructions to lift (default 5)'),
    },
    async ({ binary_path, address, count }) => {
      let session: RizinSession | undefined;
      try {
        const safePath = sanitizePath(binary_path);
        session = await RizinSession.open(safePath);
        await session.cmd('aa');

        if (address) {
          const safeAddr = sanitizeAddress(address);
          await session.cmd(`s ${safeAddr}`);
        }

        // aoj returns opcode info including rzil AST for each instruction
        const ops = await session.cmdj<
          Array<{
            opcode?: string;
            disasm?: string;
            offset?: number;
            esil?: string;
            rzil?: Record<string, unknown>;
          }>
        >(`aoj ${count}`);

        const lines: string[] = [];
        lines.push(`## RzIL AST Lifting (${ops.length} instructions)\n`);

        for (const op of ops) {
          const addr = op.offset !== undefined ? `0x${op.offset.toString(16)}` : '?';
          lines.push(`### \`${addr}\`: \`${op.disasm ?? op.opcode ?? '?'}\`\n`);

          if (op.esil) {
            lines.push(`**ESIL:** \`${op.esil}\`\n`);
          }

          if (op.rzil) {
            lines.push('**RzIL AST:**');
            lines.push('```json');
            lines.push(JSON.stringify(op.rzil, null, 2));
            lines.push('```\n');
          } else {
            lines.push('_No RzIL lifting available for this instruction._\n');
          }
        }

        return mcpFormatted(lines.join('\n'));
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      } finally {
        if (session) {
          await session.close();
        }
      }
    },
  );
}
