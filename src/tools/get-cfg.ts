import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { withCachedSession } from '../r2/session-cache.js';
import { sanitizePath, sanitizeAddress, sanitizeFunctionName } from '../r2/sanitize.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatControlFlowGraph } from '../utils/formatters.js';

interface R2BasicBlock {
  readonly offset: number;
  readonly size: number;
  readonly jump?: number;
  readonly fail?: number;
  readonly ops?: readonly {
    readonly offset: number;
    readonly size: number;
    readonly opcode: string;
    readonly disasm: string;
    readonly bytes: string;
    readonly type: string;
  }[];
}

interface R2FunctionGraph {
  readonly name: string;
  readonly offset: number;
  readonly blocks: readonly R2BasicBlock[];
}

export function registerGetControlFlowGraph(server: McpServer): void {
  server.tool(
    'get_control_flow_graph',
    'Get the control flow graph of a function as a JSON structure with basic blocks and edges.',
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
        if (!address && !function_name) {
          return mcpError('Either address or function_name must be provided');
        }

        const safePath = sanitizePath(binary_path);
        return await withCachedSession(safePath, async (session) => {
          // Seek to the target function
          if (address) {
            const safeAddr = sanitizeAddress(address);
            await session.cmd(`s ${safeAddr}`);
          } else if (function_name) {
            const safeName = sanitizeFunctionName(function_name);
            await session.cmd(`s ${safeName}`);
          }

          // agfj returns the function graph as JSON with basic blocks
          const raw = await session.cmd('agfj');
          const trimmed = raw.trim();

          if (trimmed.length === 0) {
            return mcpError(
              'No control flow graph data returned. Make sure the address points to a valid function.',
            );
          }

          let graphData: R2FunctionGraph[] | R2FunctionGraph;
          try {
            graphData = JSON.parse(trimmed) as R2FunctionGraph[] | R2FunctionGraph;
          } catch {
            return mcpError(`Failed to parse CFG JSON: ${trimmed.slice(0, 200)}`);
          }

          // agfj may return an array with one element or a single object
          const graph = Array.isArray(graphData) ? graphData[0] : graphData;
          if (!graph) {
            return mcpError('No control flow graph found for the specified function');
          }

          const blocks = (graph.blocks ?? []).map((block) => ({
            address: `0x${block.offset.toString(16)}`,
            size: block.size,
            jump: block.jump !== undefined ? `0x${block.jump.toString(16)}` : null,
            fail: block.fail !== undefined ? `0x${block.fail.toString(16)}` : null,
            instructions: (block.ops ?? []).map((op) => ({
              address: `0x${op.offset.toString(16)}`,
              opcode: op.opcode,
              disasm: op.disasm,
              bytes: op.bytes,
              type: op.type,
              size: op.size,
            })),
          }));

          return mcpFormatted(formatControlFlowGraph({
            function_name: graph.name,
            function_address: `0x${graph.offset.toString(16)}`,
            block_count: blocks.length,
            blocks,
          }));
        });
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
