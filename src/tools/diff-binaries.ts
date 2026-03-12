import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizePath } from '../r2/sanitize.js';
import { R2Session } from '../r2/session.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import type { R2Function, R2Import, R2Export, R2String, R2DisasmFunction } from '../types.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface BinaryData {
  readonly info: Record<string, unknown>;
  readonly functions: readonly R2Function[];
  readonly imports: readonly R2Import[];
  readonly exports: readonly R2Export[];
  readonly strings: readonly R2String[];
}

interface FunctionDiff {
  readonly name: string;
  readonly sizeA: number;
  readonly sizeB: number;
  readonly addedOps: readonly string[];
  readonly removedOps: readonly string[];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function collectBinaryData(session: R2Session): Promise<BinaryData> {
  const [info, functions, imports, exports, strings] = await Promise.all([
    session.cmdj<Record<string, unknown>>('ij'),
    session.cmdj<R2Function[]>('aflj'),
    session.cmdj<R2Import[]>('iij'),
    session.cmdj<R2Export[]>('iEj'),
    session.cmdj<R2String[]>('izj'),
  ]);

  return {
    info,
    functions: Array.isArray(functions) ? functions : [],
    imports: Array.isArray(imports) ? imports : [],
    exports: Array.isArray(exports) ? exports : [],
    strings: Array.isArray(strings) ? strings : [],
  };
}

function extractFileInfo(info: Record<string, unknown>): {
  arch: string;
  bits: string;
  format: string;
  size: string;
  os: string;
} {
  const core = (info['core'] ?? {}) as Record<string, unknown>;
  const bin = (info['bin'] ?? {}) as Record<string, unknown>;
  const str = (v: unknown): string => (typeof v === 'string' || typeof v === 'number' ? String(v) : 'unknown');
  return {
    arch: str(bin['arch']),
    bits: str(bin['bits']),
    format: str(core['format']),
    size: str(core['size']),
    os: str(bin['os']),
  };
}

function setFromNames<T extends { readonly name: string }>(
  items: readonly T[],
): Map<string, T> {
  const map = new Map<string, T>();
  for (const item of items) {
    map.set(item.name, item);
  }
  return map;
}

function setFromStrings(items: readonly R2String[]): Map<string, R2String> {
  const map = new Map<string, R2String>();
  for (const item of items) {
    map.set(item.string, item);
  }
  return map;
}

async function diffFunction(
  sessionA: R2Session,
  sessionB: R2Session,
  funcA: R2Function,
  funcB: R2Function,
): Promise<FunctionDiff> {
  const [disasmA, disasmB] = await Promise.all([
    sessionA.cmdj<R2DisasmFunction>(`pdfj @ ${funcA.name}`).catch(() => null),
    sessionB.cmdj<R2DisasmFunction>(`pdfj @ ${funcB.name}`).catch(() => null),
  ]);

  const opsA = (disasmA?.ops ?? []).map((op) => op.disasm ?? op.opcode);
  const opsB = (disasmB?.ops ?? []).map((op) => op.disasm ?? op.opcode);

  const setA = new Set(opsA);
  const setB = new Set(opsB);

  const removed: string[] = [];
  const added: string[] = [];

  for (const op of opsA) {
    if (!setB.has(op)) {
      removed.push(op);
    }
  }

  for (const op of opsB) {
    if (!setA.has(op)) {
      added.push(op);
    }
  }

  return {
    name: funcA.name,
    sizeA: funcA.size,
    sizeB: funcB.size,
    addedOps: added,
    removedOps: removed,
  };
}

// ---------------------------------------------------------------------------
// Markdown formatting
// ---------------------------------------------------------------------------

function formatDiffReport(
  pathA: string,
  pathB: string,
  dataA: BinaryData,
  dataB: BinaryData,
  addedFunctions: readonly R2Function[],
  removedFunctions: readonly R2Function[],
  changedFunctions: readonly FunctionDiff[],
  addedImports: readonly R2Import[],
  removedImports: readonly R2Import[],
  addedExports: readonly R2Export[],
  removedExports: readonly R2Export[],
  addedStrings: readonly R2String[],
  removedStrings: readonly R2String[],
): string {
  const lines: string[] = [];

  // Header
  lines.push('# Binary Diff Report');
  lines.push('');

  // File comparison
  const infoA = extractFileInfo(dataA.info);
  const infoB = extractFileInfo(dataB.info);

  lines.push('## File Comparison');
  lines.push('');
  lines.push('| Property | Binary A | Binary B |');
  lines.push('|----------|----------|----------|');
  lines.push(`| Path | \`${pathA}\` | \`${pathB}\` |`);
  lines.push(`| Architecture | ${infoA.arch} | ${infoB.arch} |`);
  lines.push(`| Bits | ${infoA.bits} | ${infoB.bits} |`);
  lines.push(`| Format | ${infoA.format} | ${infoB.format} |`);
  lines.push(`| Size | ${infoA.size} | ${infoB.size} |`);
  lines.push(`| OS | ${infoA.os} | ${infoB.os} |`);
  lines.push('');

  // Summary
  lines.push('## Summary');
  lines.push('');
  lines.push('| Category | Added | Removed | Changed |');
  lines.push('|----------|-------|---------|---------|');
  lines.push(
    `| Functions | ${addedFunctions.length} | ${removedFunctions.length} | ${changedFunctions.length} |`,
  );
  lines.push(
    `| Imports | ${addedImports.length} | ${removedImports.length} | - |`,
  );
  lines.push(
    `| Exports | ${addedExports.length} | ${removedExports.length} | - |`,
  );
  lines.push(
    `| Strings | ${addedStrings.length} | ${removedStrings.length} | - |`,
  );
  lines.push(
    `| Total functions | ${dataA.functions.length} (A) | ${dataB.functions.length} (B) | |`,
  );
  lines.push('');

  // Added functions
  if (addedFunctions.length > 0) {
    lines.push('## Added Functions (only in B)');
    lines.push('');
    lines.push('| Name | Address | Size |');
    lines.push('|------|---------|------|');
    for (const fn of addedFunctions) {
      lines.push(`| \`${fn.name}\` | \`0x${fn.offset.toString(16)}\` | ${fn.size} |`);
    }
    lines.push('');
  }

  // Removed functions
  if (removedFunctions.length > 0) {
    lines.push('## Removed Functions (only in A)');
    lines.push('');
    lines.push('| Name | Address | Size |');
    lines.push('|------|---------|------|');
    for (const fn of removedFunctions) {
      lines.push(`| \`${fn.name}\` | \`0x${fn.offset.toString(16)}\` | ${fn.size} |`);
    }
    lines.push('');
  }

  // Changed functions with instruction diffs
  if (changedFunctions.length > 0) {
    lines.push('## Changed Functions');
    lines.push('');
    for (const diff of changedFunctions) {
      lines.push(`### \`${diff.name}\``);
      lines.push('');
      lines.push(`- Size A: ${diff.sizeA} bytes`);
      lines.push(`- Size B: ${diff.sizeB} bytes`);
      lines.push(`- Size delta: ${diff.sizeB - diff.sizeA > 0 ? '+' : ''}${diff.sizeB - diff.sizeA} bytes`);
      lines.push('');

      if (diff.removedOps.length > 0 || diff.addedOps.length > 0) {
        lines.push('```diff');
        for (const op of diff.removedOps) {
          lines.push(`- ${op}`);
        }
        for (const op of diff.addedOps) {
          lines.push(`+ ${op}`);
        }
        lines.push('```');
        lines.push('');
      } else {
        lines.push('_Instructions identical (size change may be due to alignment or padding)._');
        lines.push('');
      }
    }
  }

  // Import changes
  if (addedImports.length > 0 || removedImports.length > 0) {
    lines.push('## Import Changes');
    lines.push('');
    if (addedImports.length > 0) {
      lines.push('### Added Imports');
      lines.push('');
      lines.push('| Name | Library | Type |');
      lines.push('|------|---------|------|');
      for (const imp of addedImports) {
        lines.push(`| \`${imp.name}\` | ${imp.lib ?? '-'} | ${imp.type} |`);
      }
      lines.push('');
    }
    if (removedImports.length > 0) {
      lines.push('### Removed Imports');
      lines.push('');
      lines.push('| Name | Library | Type |');
      lines.push('|------|---------|------|');
      for (const imp of removedImports) {
        lines.push(`| \`${imp.name}\` | ${imp.lib ?? '-'} | ${imp.type} |`);
      }
      lines.push('');
    }
  }

  // Export changes
  if (addedExports.length > 0 || removedExports.length > 0) {
    lines.push('## Export Changes');
    lines.push('');
    if (addedExports.length > 0) {
      lines.push('### Added Exports');
      lines.push('');
      lines.push('| Name | Address | Type |');
      lines.push('|------|---------|------|');
      for (const exp of addedExports) {
        lines.push(
          `| \`${exp.name}\` | \`0x${exp.vaddr.toString(16)}\` | ${exp.type} |`,
        );
      }
      lines.push('');
    }
    if (removedExports.length > 0) {
      lines.push('### Removed Exports');
      lines.push('');
      lines.push('| Name | Address | Type |');
      lines.push('|------|---------|------|');
      for (const exp of removedExports) {
        lines.push(
          `| \`${exp.name}\` | \`0x${exp.vaddr.toString(16)}\` | ${exp.type} |`,
        );
      }
      lines.push('');
    }
  }

  // String changes
  if (addedStrings.length > 0 || removedStrings.length > 0) {
    lines.push('## String Changes');
    lines.push('');
    if (addedStrings.length > 0) {
      lines.push('### Added Strings');
      lines.push('');
      lines.push('| String | Section | Address |');
      lines.push('|--------|---------|---------|');
      for (const s of addedStrings.slice(0, 100)) {
        const escaped = s.string.replace(/\|/g, '\\|').replace(/\n/g, '\\n');
        lines.push(`| \`${escaped}\` | ${s.section} | \`0x${s.vaddr.toString(16)}\` |`);
      }
      if (addedStrings.length > 100) {
        lines.push(`| ... and ${addedStrings.length - 100} more | | |`);
      }
      lines.push('');
    }
    if (removedStrings.length > 0) {
      lines.push('### Removed Strings');
      lines.push('');
      lines.push('| String | Section | Address |');
      lines.push('|--------|---------|---------|');
      for (const s of removedStrings.slice(0, 100)) {
        const escaped = s.string.replace(/\|/g, '\\|').replace(/\n/g, '\\n');
        lines.push(`| \`${escaped}\` | ${s.section} | \`0x${s.vaddr.toString(16)}\` |`);
      }
      if (removedStrings.length > 100) {
        lines.push(`| ... and ${removedStrings.length - 100} more | | |`);
      }
      lines.push('');
    }
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Tool registration
// ---------------------------------------------------------------------------

export function registerDiffBinaries(server: McpServer): void {
  server.tool(
    'diff_binaries',
    'Compare two binary versions: find added, removed, and changed functions, imports, strings, and show instruction-level diffs for modified functions.',
    {
      binary_path_a: z.string().describe('Absolute path to the first (original) binary'),
      binary_path_b: z.string().describe('Absolute path to the second (patched) binary'),
      max_function_diffs: z
        .number()
        .int()
        .min(0)
        .max(50)
        .default(10)
        .describe(
          'Maximum number of changed functions to show instruction-level diffs for',
        ),
    },
    async ({ binary_path_a, binary_path_b, max_function_diffs }) => {
      try {
        const safePathA = sanitizePath(binary_path_a);
        const safePathB = sanitizePath(binary_path_b);

        const sessionA = await R2Session.open(safePathA);
        try {
          const sessionB = await R2Session.open(safePathB);
          try {
            // Run analysis on both binaries in parallel
            await Promise.all([sessionA.cmd('aaa'), sessionB.cmd('aaa')]);

            // Collect data from both binaries in parallel
            const [dataA, dataB] = await Promise.all([
              collectBinaryData(sessionA),
              collectBinaryData(sessionB),
            ]);

            // --- Compare functions ---
            const funcMapA = setFromNames(dataA.functions);
            const funcMapB = setFromNames(dataB.functions);

            const addedFunctions: R2Function[] = [];
            const removedFunctions: R2Function[] = [];
            const changedFunctionPairs: { a: R2Function; b: R2Function }[] = [];

            for (const [name, fn] of funcMapB) {
              const fnA = funcMapA.get(name);
              if (fnA === undefined) {
                addedFunctions.push(fn);
              } else if (fnA.size !== fn.size) {
                changedFunctionPairs.push({ a: fnA, b: fn });
              }
            }

            for (const [name, fn] of funcMapA) {
              if (!funcMapB.has(name)) {
                removedFunctions.push(fn);
              }
            }

            // Get instruction-level diffs for changed functions
            const diffLimit = Math.min(changedFunctionPairs.length, max_function_diffs);
            const changedFunctions: FunctionDiff[] = [];

            for (let i = 0; i < diffLimit; i++) {
              const pair = changedFunctionPairs[i];
              if (pair === undefined) break;
              const diff = await diffFunction(sessionA, sessionB, pair.a, pair.b);
              changedFunctions.push(diff);
            }

            // For remaining changed functions beyond the diff limit, add size-only info
            for (let i = diffLimit; i < changedFunctionPairs.length; i++) {
              const pair = changedFunctionPairs[i];
              if (pair === undefined) break;
              changedFunctions.push({
                name: pair.a.name,
                sizeA: pair.a.size,
                sizeB: pair.b.size,
                addedOps: [],
                removedOps: [],
              });
            }

            // --- Compare imports ---
            const importMapA = setFromNames(dataA.imports);
            const importMapB = setFromNames(dataB.imports);

            const addedImports: R2Import[] = [];
            const removedImports: R2Import[] = [];

            for (const [name, imp] of importMapB) {
              if (!importMapA.has(name)) {
                addedImports.push(imp);
              }
            }
            for (const [name, imp] of importMapA) {
              if (!importMapB.has(name)) {
                removedImports.push(imp);
              }
            }

            // --- Compare exports ---
            const exportMapA = setFromNames(dataA.exports);
            const exportMapB = setFromNames(dataB.exports);

            const addedExports: R2Export[] = [];
            const removedExports: R2Export[] = [];

            for (const [name, exp] of exportMapB) {
              if (!exportMapA.has(name)) {
                addedExports.push(exp);
              }
            }
            for (const [name, exp] of exportMapA) {
              if (!exportMapB.has(name)) {
                removedExports.push(exp);
              }
            }

            // --- Compare strings ---
            const stringMapA = setFromStrings(dataA.strings);
            const stringMapB = setFromStrings(dataB.strings);

            const addedStrings: R2String[] = [];
            const removedStrings: R2String[] = [];

            for (const [str, entry] of stringMapB) {
              if (!stringMapA.has(str)) {
                addedStrings.push(entry);
              }
            }
            for (const [str, entry] of stringMapA) {
              if (!stringMapB.has(str)) {
                removedStrings.push(entry);
              }
            }

            // --- Build report ---
            const report = formatDiffReport(
              safePathA,
              safePathB,
              dataA,
              dataB,
              addedFunctions,
              removedFunctions,
              changedFunctions,
              addedImports,
              removedImports,
              addedExports,
              removedExports,
              addedStrings,
              removedStrings,
            );

            return mcpFormatted(report);
          } finally {
            await sessionB.close();
          }
        } finally {
          await sessionA.close();
        }
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
