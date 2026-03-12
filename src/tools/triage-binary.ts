import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizePath } from '../r2/sanitize.js';
import { withCachedSession } from '../r2/session-cache.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatTriage } from '../utils/formatters.js';
import { detectMitigations } from '../utils/mitigations.js';
import type { R2Function, R2String, R2Import, R2Export, R2Section } from '../types.js';

export function registerTriageBinary(server: McpServer): void {
  server.tool(
    'triage_binary',
    'Perform comprehensive one-shot binary triage: file info, sections, imports, exports, strings, functions, entry points, and security features in a single call.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      analysis_level: z
        .enum(['aa', 'aaa', 'aaaa'])
        .default('aaa')
        .describe('Analysis depth level (aa=basic, aaa=standard, aaaa=experimental)'),
      max_strings: z
        .number()
        .int()
        .min(0)
        .max(500)
        .default(50)
        .describe('Maximum number of interesting strings to include'),
      max_functions: z
        .number()
        .int()
        .min(0)
        .max(500)
        .default(50)
        .describe('Maximum number of functions to include (sorted by size, largest first)'),
    },
    async ({ binary_path, analysis_level, max_strings, max_functions }) => {
      try {
        const safePath = sanitizePath(binary_path);
        return await withCachedSession(
          safePath,
          async (session) => {
            // Gather everything in parallel where possible
            const [fileInfo, sections, imports, exports, allStrings, allFunctions, entryPoints] =
              await Promise.all([
                session.cmdj<Record<string, unknown>>('ij'),
                session.cmdj<R2Section[]>('iSj'),
                session.cmdj<R2Import[]>('iij'),
                session.cmdj<R2Export[]>('iEj'),
                session.cmdj<R2String[]>('izj'),
                session.cmdj<R2Function[]>('aflj'),
                session.cmdj<{ vaddr: number; paddr: number; baddr: number; laddr: number; haddr: number; type: string }[]>('iej'),
              ]);

            // Sort functions by size (largest = most interesting)
            const functions = Array.isArray(allFunctions) ? allFunctions : [];
            const sortedFunctions = [...functions]
              .sort((a, b) => (b.size ?? 0) - (a.size ?? 0))
              .slice(0, max_functions);

            // Filter strings: skip very short ones and duplicates, prioritize interesting ones
            const strings = Array.isArray(allStrings) ? allStrings : [];
            const interestingStrings = filterInterestingStrings(strings, max_strings);

            // Detect main/entry functions
            const mainFunctions = functions.filter(
              (f) =>
                f.name === 'main' ||
                f.name === 'sym.main' ||
                f.name === '_main' ||
                f.name === 'entry0' ||
                f.name === 'WinMain' ||
                f.name.includes('entry'),
            );

            // Get security mitigations
            const security = await detectMitigations(session);

            return mcpFormatted(
              formatTriage({
                fileInfo: fileInfo as Parameters<typeof formatTriage>[0]['fileInfo'],
                sections: Array.isArray(sections) ? sections : [],
                imports: Array.isArray(imports) ? imports : [],
                exports: Array.isArray(exports) ? exports : [],
                strings: interestingStrings,
                functions: sortedFunctions,
                mainFunctions,
                entryPoints: Array.isArray(entryPoints) ? entryPoints : [],
                security,
                totalFunctions: functions.length,
                totalStrings: strings.length,
              }),
            );
          },
          analysis_level,
        );
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}

/** Filter strings to keep the most interesting ones for analysis. */
function filterInterestingStrings(strings: R2String[], max: number): R2String[] {
  // Keywords that suggest interesting strings for reverse engineering
  const highPriority = /password|flag|key|secret|correct|wrong|success|fail|error|invalid|valid|license|serial|crack|hack|auth|login|admin|root|token|encrypt|decrypt|hash|check|verify|compare|input|enter|usage|help|version|debug|test|win|lose|congratulat/i;
  const medPriority = /http|file|path|open|read|write|exec|system|cmd|shell|pipe|socket|connect|send|recv|malloc|free|printf|scanf|strcmp|strlen|memcmp|memcpy|fopen|fclose|getenv|setenv/i;

  const high: R2String[] = [];
  const med: R2String[] = [];
  const low: R2String[] = [];

  const seen = new Set<string>();

  for (const s of strings) {
    if (s.length < 4) continue;
    const val = s.string;
    if (seen.has(val)) continue;
    seen.add(val);

    if (highPriority.test(val)) {
      high.push(s);
    } else if (medPriority.test(val)) {
      med.push(s);
    } else if (val.length >= 6) {
      low.push(s);
    }
  }

  // Prioritize high, then med, then low
  const result: R2String[] = [];
  for (const bucket of [high, med, low]) {
    for (const s of bucket) {
      if (result.length >= max) break;
      result.push(s);
    }
    if (result.length >= max) break;
  }

  return result;
}
