import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { rzilManager } from '../rizin/rzil-session-manager.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';

export function registerRzilTraceStep(server: McpServer): void {
  server.tool(
    'rzil_trace_step',
    'Step the RzIL emulator and return detailed VM change events showing exactly which variables and memory locations were read or written. Uses aezse which outputs typed events like pc_write(old, new) and var_write(name, old, new). Superior to ESIL tracing because events are typed.',
    {
      session_id: z.string().describe('RzIL session ID returned by rzil_init'),
      count: z
        .number()
        .int()
        .min(1)
        .max(1000)
        .default(1)
        .describe('Number of steps to trace (default 1)'),
    },
    async ({ session_id, count }) => {
      try {
        const entry = rzilManager.get(session_id);
        const session = entry.session;

        // aezse outputs detailed VM events per step
        const events = (await session.cmd(`aezse ${count}`)).trim();

        const vmState = await session.cmdj<Record<string, unknown>>('aezvj');
        const pc = typeof vmState?.['PC'] === 'string' ? vmState['PC'] as string : 'unknown';

        const lines: string[] = [];
        lines.push(`## RzIL Trace (${count} step${count !== 1 ? 's' : ''})\n`);
        lines.push(`**Current PC:** \`${pc}\`\n`);

        if (events) {
          lines.push('### VM Events\n');
          lines.push('```');
          lines.push(events);
          lines.push('```');
        } else {
          lines.push('_No VM events recorded._');
        }

        return mcpFormatted(lines.join('\n'));
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
