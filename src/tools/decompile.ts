import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { withCachedSession } from '../r2/session-cache.js';
import { sanitizePath, sanitizeAddress, sanitizeFunctionName } from '../r2/sanitize.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatDecompilation } from '../utils/formatters.js';

export function registerDecompileFunction(server: McpServer): void {
  server.tool(
    'decompile_function',
    'Decompile a function to pseudo-C representation using the available decompiler backend.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      address: z
        .string()
        .optional()
        .describe('Hex address of the function (e.g. "0x08048000")'),
      function_name: z
        .string()
        .optional()
        .describe('Name of the function to decompile (e.g. "main")'),
      backend: z
        .enum(['auto', 'pdc', 'pdg'])
        .default('auto')
        .describe('Decompiler backend: "auto" tries pdg (r2ghidra) first then falls back to pdc, "pdc" uses r2 native, "pdg" uses r2ghidra'),
    },
    async ({ binary_path, address, function_name, backend }) => {
      try {
        if (!address && !function_name) {
          return mcpError('Either address or function_name must be provided');
        }

        const safePath = sanitizePath(binary_path);
        return await withCachedSession(safePath, async (session) => {
          const seekTarget = address
            ? sanitizeAddress(address)
            : sanitizeFunctionName(function_name!);

          await session.cmd(`s ${seekTarget}`);

          const currentAddr = (await session.cmd('s')).trim();
          const currentName = (await session.cmd('afi.')).trim().split('\n')[0] ?? 'unknown';

          let pseudoC: string;
          if (backend === 'pdg') {
            pseudoC = await session.cmd('pdg');
          } else if (backend === 'pdc') {
            pseudoC = await session.cmd('pdc');
          } else {
            // auto: try pdg first (r2ghidra), fall back to pdc
            try {
              const pdgOutput = await session.cmd('pdg');
              if (pdgOutput.trim().length > 0 && !pdgOutput.includes('Cannot find function')) {
                pseudoC = pdgOutput;
              } else {
                pseudoC = await session.cmd('pdc');
              }
            } catch {
              pseudoC = await session.cmd('pdc');
            }
          }

          return mcpFormatted(formatDecompilation({
            function_name: currentName,
            address: currentAddr,
            pseudo_c: pseudoC,
          }));
        });
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
