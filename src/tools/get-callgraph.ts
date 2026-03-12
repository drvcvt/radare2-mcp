import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { withCachedSession } from '../r2/session-cache.js';
import { sanitizePath, sanitizeAddress, sanitizeFunctionName } from '../r2/sanitize.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatCallgraph } from '../utils/formatters.js';

export function registerGetCallgraph(server: McpServer): void {
  server.tool(
    'get_callgraph',
    'Get the call graph for a function showing all callers and callees as a structured graph.',
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
      format: z
        .enum(['json', 'dot', 'mermaid'])
        .default('json')
        .describe('Output format for the call graph'),
      depth: z
        .number()
        .int()
        .min(1)
        .optional()
        .describe('Maximum recursion depth for the call graph (default: unlimited)'),
    },
    async ({ binary_path, address, function_name, format, depth }) => {
      try {
        const safePath = sanitizePath(binary_path);
        return await withCachedSession(safePath, async (session) => {
          // Seek to the target function if specified
          if (address) {
            const safeAddr = sanitizeAddress(address);
            await session.cmd(`s ${safeAddr}`);
          } else if (function_name) {
            const safeName = sanitizeFunctionName(function_name);
            await session.cmd(`s ${safeName}`);
          }

          // Limit call graph depth if requested
          if (depth !== undefined) {
            await session.cmd(`e anal.depth=${depth}`);
          }

          if (format === 'json') {
            // agCj = global callgraph JSON, agcj = function callgraph JSON
            const command = address || function_name ? 'agcj' : 'agCj';
            const raw = await session.cmd(command);
            const trimmed = raw.trim();

            // Try to parse as JSON; fall back to raw text
            let graphData: unknown;
            try {
              graphData = JSON.parse(trimmed);
            } catch {
              graphData = { raw_output: trimmed };
            }

            return mcpFormatted(formatCallgraph({
              format: 'json',
              function: function_name ?? address ?? 'global',
              graph: graphData,
            }));
          } else if (format === 'dot') {
            // agcd = function callgraph in dot format, agCd = global
            const command = address || function_name ? 'agcd' : 'agCd';
            const dotOutput = await session.cmd(command);
            return mcpFormatted(formatCallgraph({
              format: 'dot',
              function: function_name ?? address ?? 'global',
              graph: dotOutput.trim(),
            }));
          } else {
            // mermaid: use agcm (function) or agCm (global) if available, otherwise
            // fall back to dot and note the format
            const command = address || function_name ? 'agcm' : 'agCm';
            const mermaidOutput = await session.cmd(command);
            const trimmed = mermaidOutput.trim();

            // If r2 does not support mermaid natively, generate from JSON
            if (trimmed.length === 0) {
              const jsonCommand = address || function_name ? 'agcj' : 'agCj';
              const jsonRaw = await session.cmd(jsonCommand);
              return mcpFormatted(formatCallgraph({
                format: 'mermaid',
                function: function_name ?? address ?? 'global',
                note: 'Mermaid output not natively supported; returning JSON graph data instead.',
                graph: jsonRaw.trim(),
              }));
            }

            return mcpFormatted(formatCallgraph({
              format: 'mermaid',
              function: function_name ?? address ?? 'global',
              graph: trimmed,
            }));
          }
        });
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
