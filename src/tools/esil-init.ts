import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizePath, sanitizeAddress } from '../r2/sanitize.js';
import { esilManager } from '../r2/esil-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatEsilInit } from '../utils/formatters.js';

export function registerEsilInit(server: McpServer): void {
  server.tool(
    'esil_init',
    'Initialize the ESIL virtual machine with stack memory and return a persistent session_id for subsequent ESIL tool calls. The session preserves ESIL state (registers, memory, PC) across calls.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      address: z
        .string()
        .optional()
        .describe('Start address (hex). If omitted, entry point is used.'),
      stack_size: z
        .number()
        .int()
        .min(0x1000)
        .default(0x00100000)
        .describe('ESIL stack size in bytes (default 0x100000)'),
      stack_address: z
        .string()
        .default('0x00100000')
        .describe('ESIL stack base address (default "0x00100000")'),
    },
    async ({ binary_path, address, stack_size, stack_address }) => {
      try {
        const safePath = sanitizePath(binary_path);
        const safeStackAddr = sanitizeAddress(stack_address);
        const safeAddr = address ? sanitizeAddress(address) : undefined;

        const createOptions: {
          address?: string;
          stackAddress?: string;
          stackSize?: number;
        } = {
          stackAddress: safeStackAddr,
          stackSize: stack_size,
        };
        if (safeAddr) {
          createOptions.address = safeAddr;
        }

        const entry = await esilManager.create(safePath, createOptions);

        // Read entry point and register state from the persistent session
        let entryPoint: string;
        if (safeAddr) {
          entryPoint = safeAddr;
        } else {
          const info = await entry.session.cmdj<{ bin?: { entry?: number } }>('ij');
          entryPoint =
            info?.bin?.entry !== undefined
              ? `0x${info.bin.entry.toString(16)}`
              : 'unknown';
        }

        const registers = await entry.session.cmdj<Record<string, number>>('aerj');

        const lines: string[] = [];
        lines.push(
          formatEsilInit({
            initialized: true,
            entry_point: entryPoint,
            stack_address: safeStackAddr,
            stack_size,
            registers,
          }),
        );
        lines.push(`\n**Session ID:** \`${entry.sessionId}\``);
        lines.push(
          '\nUse this `session_id` with other ESIL tools (`esil_step`, `esil_run`, `esil_get_registers`, etc.) to preserve state across calls.',
        );

        return mcpFormatted(lines.join('\n'));
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
