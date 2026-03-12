import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { R2Session } from '../r2/session.js';
import { sanitizePath, sanitizeAddress } from '../r2/sanitize.js';
import { esilManager } from '../r2/esil-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatRegisters } from '../utils/formatters.js';

const ESIL_FORBIDDEN_RE = /[;|><`$&!#]/;

function sanitizeEsilExpression(expression: string): string {
  const trimmed = expression.trim();
  if (!trimmed) {
    throw new Error('ESIL expression must not be empty.');
  }
  if (ESIL_FORBIDDEN_RE.test(trimmed)) {
    throw new Error(
      `ESIL expression contains forbidden characters: ${trimmed}. Shell metacharacters are not allowed.`,
    );
  }
  return trimmed;
}

export function registerEsilExpression(server: McpServer): void {
  server.tool(
    'esil_expression',
    'Evaluate a raw ESIL expression string and return the result. If session_id is provided, uses a persistent session; otherwise creates a fresh session.',
    {
      binary_path: z
        .string()
        .optional()
        .describe(
          'Absolute path to the binary file. Required when session_id is not provided.',
        ),
      session_id: z
        .string()
        .optional()
        .describe(
          'Persistent ESIL session ID from esil_init. If provided, binary_path and address are ignored.',
        ),
      expression: z
        .string()
        .describe('ESIL expression to evaluate (postfix/RPN notation, e.g. "1,2,+")'),
      address: z
        .string()
        .optional()
        .describe(
          'Address (hex) to set as program counter before evaluating the expression',
        ),
    },
    async ({ binary_path, session_id, expression, address }) => {
      let freshSession: R2Session | undefined;
      try {
        const safeExpression = sanitizeEsilExpression(expression);

        let session: R2Session;

        if (session_id) {
          const entry = esilManager.get(session_id);
          session = entry.session;
        } else {
          if (!binary_path) {
            return mcpError('binary_path is required when session_id is not provided.');
          }
          const safePath = sanitizePath(binary_path);
          freshSession = await R2Session.open(safePath);
          session = freshSession;
          await session.cmd('aaa');

          await session.cmd('aei');
          await session.cmd('aeim');

          if (address) {
            const safeAddr = sanitizeAddress(address);
            await session.cmd(`aepc ${safeAddr}`);
          } else {
            await session.cmd('aeip');
          }
        }

        const result = (await session.cmd(`ae ${safeExpression}`)).trim();

        const registers = await session.cmdj<Record<string, number>>('aerj');

        const lines: string[] = [];
        lines.push(`## ESIL Expression: \`${safeExpression}\`\n`);
        if (result) lines.push(`**Result:** \`${result}\`\n`);
        lines.push(formatRegisters(registers, 'Registers After'));
        return mcpFormatted(lines.join('\n'));
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      } finally {
        if (freshSession) {
          await freshSession.close();
        }
      }
    },
  );
}
