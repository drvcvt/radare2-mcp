import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizePath } from '../r2/sanitize.js';
import { withCachedSession } from '../r2/session-cache.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { stripImportPrefix } from '../utils/shared-helpers.js';
import { detectMitigations, type MitigationInfo } from '../utils/mitigations.js';
import type { R2Import, R2Xref } from '../types.js';

// ---------------------------------------------------------------------------
// Dangerous function database
// ---------------------------------------------------------------------------

interface DangerousFunction {
  readonly category: string;
  readonly severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  readonly description: string;
  readonly safer_alternative: string;
}

const DANGEROUS_FUNCTIONS: Record<string, DangerousFunction> = {
  // Buffer overflow -- no bounds checking
  gets: {
    category: 'buffer_overflow',
    severity: 'CRITICAL',
    description: 'Reads line without any length limit',
    safer_alternative: 'fgets',
  },
  strcpy: {
    category: 'buffer_overflow',
    severity: 'HIGH',
    description: 'Copies string without bounds checking',
    safer_alternative: 'strncpy / strlcpy',
  },
  strcat: {
    category: 'buffer_overflow',
    severity: 'HIGH',
    description: 'Concatenates without bounds checking',
    safer_alternative: 'strncat / strlcat',
  },
  sprintf: {
    category: 'buffer_overflow',
    severity: 'HIGH',
    description: 'Formatted write without bounds checking',
    safer_alternative: 'snprintf',
  },
  vsprintf: {
    category: 'buffer_overflow',
    severity: 'HIGH',
    description: 'Variadic formatted write without bounds checking',
    safer_alternative: 'vsnprintf',
  },
  scanf: {
    category: 'buffer_overflow',
    severity: 'MEDIUM',
    description: 'Reads input without field width limits by default',
    safer_alternative: 'scanf with explicit width or fgets+sscanf',
  },
  sscanf: {
    category: 'buffer_overflow',
    severity: 'MEDIUM',
    description: 'Parses string without field width limits by default',
    safer_alternative: 'sscanf with explicit width specifiers',
  },
  fscanf: {
    category: 'buffer_overflow',
    severity: 'MEDIUM',
    description: 'Reads from file without field width limits by default',
    safer_alternative: 'fscanf with explicit width specifiers',
  },
  memcpy: {
    category: 'buffer_overflow',
    severity: 'MEDIUM',
    description: 'Copies memory without overlap or bounds validation',
    safer_alternative: 'memcpy_s / memmove with size checks',
  },
  memmove: {
    category: 'buffer_overflow',
    severity: 'LOW',
    description: 'Moves memory; safe for overlap but no bounds validation',
    safer_alternative: 'memmove with explicit size validation',
  },
  wcscpy: {
    category: 'buffer_overflow',
    severity: 'HIGH',
    description: 'Wide-char copy without bounds checking',
    safer_alternative: 'wcsncpy / wcslcpy',
  },
  wcscat: {
    category: 'buffer_overflow',
    severity: 'HIGH',
    description: 'Wide-char concatenation without bounds checking',
    safer_alternative: 'wcsncat / wcslcat',
  },

  // Format string vulnerabilities
  printf: {
    category: 'format_string',
    severity: 'MEDIUM',
    description: 'Format string may be user-controlled',
    safer_alternative: 'printf with constant format string / puts',
  },
  fprintf: {
    category: 'format_string',
    severity: 'MEDIUM',
    description: 'Format string may be user-controlled',
    safer_alternative: 'fprintf with constant format string / fputs',
  },
  syslog: {
    category: 'format_string',
    severity: 'MEDIUM',
    description: 'Format string may be user-controlled',
    safer_alternative: 'syslog with constant format string',
  },

  // Command injection
  system: {
    category: 'command_injection',
    severity: 'CRITICAL',
    description: 'Executes shell command; injection risk if input is unsanitized',
    safer_alternative: 'exec* family with explicit argv / posix_spawn',
  },
  popen: {
    category: 'command_injection',
    severity: 'CRITICAL',
    description: 'Opens shell pipeline; injection risk if input is unsanitized',
    safer_alternative: 'pipe+fork+exec with explicit argv',
  },
  execl: {
    category: 'command_injection',
    severity: 'HIGH',
    description: 'Executes program; PATH-based lookup may be hijacked',
    safer_alternative: 'execve with absolute path',
  },
  execlp: {
    category: 'command_injection',
    severity: 'HIGH',
    description: 'Executes program via PATH; search-order hijack risk',
    safer_alternative: 'execve with absolute path',
  },
  execvp: {
    category: 'command_injection',
    severity: 'HIGH',
    description: 'Executes program via PATH; search-order hijack risk',
    safer_alternative: 'execve with absolute path',
  },

  // Race conditions (TOCTOU)
  access: {
    category: 'race_condition',
    severity: 'MEDIUM',
    description: 'Check-then-use race condition (TOCTOU)',
    safer_alternative: 'Open with O_CREAT|O_EXCL or fstat on fd',
  },
  stat: {
    category: 'race_condition',
    severity: 'LOW',
    description: 'File status check susceptible to TOCTOU',
    safer_alternative: 'fstat on open file descriptor',
  },
  lstat: {
    category: 'race_condition',
    severity: 'LOW',
    description: 'Symlink status check susceptible to TOCTOU',
    safer_alternative: 'fstat / fstatat with AT_SYMLINK_NOFOLLOW',
  },

  // Integer overflow / unsafe conversion
  atoi: {
    category: 'integer_overflow',
    severity: 'MEDIUM',
    description: 'No error detection on invalid/overflow input',
    safer_alternative: 'strtol with errno checking',
  },
  atol: {
    category: 'integer_overflow',
    severity: 'MEDIUM',
    description: 'No error detection on invalid/overflow input',
    safer_alternative: 'strtol with errno checking',
  },
  atof: {
    category: 'integer_overflow',
    severity: 'LOW',
    description: 'No error detection on invalid/overflow input',
    safer_alternative: 'strtod with errno checking',
  },

  // Weak randomness / crypto
  rand: {
    category: 'crypto_weakness',
    severity: 'MEDIUM',
    description: 'Weak PRNG, predictable output',
    safer_alternative: 'getrandom / arc4random / CSPRNG',
  },
  srand: {
    category: 'crypto_weakness',
    severity: 'INFO',
    description: 'Seeds weak PRNG; often seeded with time()',
    safer_alternative: 'Use CSPRNG instead of srand+rand',
  },

  // Memory management
  alloca: {
    category: 'buffer_overflow',
    severity: 'MEDIUM',
    description: 'Stack allocation with no size limit; stack overflow risk',
    safer_alternative: 'malloc with size validation',
  },
  realpath: {
    category: 'buffer_overflow',
    severity: 'MEDIUM',
    description: 'Second argument may be too small for PATH_MAX',
    safer_alternative: 'realpath with NULL second argument (POSIX.1-2008)',
  },
};

// Severity ordering for sorting
const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface VulnerabilityFinding {
  readonly functionName: string;
  readonly category: string;
  readonly severity: string;
  readonly description: string;
  readonly saferAlternative: string;
  readonly importAddress: number;
  readonly callers: readonly CallerInfo[];
  readonly decompiled_context?: string | undefined;
}

interface CallerInfo {
  readonly address: number;
  readonly function_name: string;
  readonly opcode: string;
}

type SecurityMitigations = MitigationInfo;

interface SeverityCounts {
  readonly CRITICAL: number;
  readonly HIGH: number;
  readonly MEDIUM: number;
  readonly LOW: number;
  readonly INFO: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Count findings by severity level.
 */
function countSeverities(findings: readonly VulnerabilityFinding[]): SeverityCounts {
  let CRITICAL = 0;
  let HIGH = 0;
  let MEDIUM = 0;
  let LOW = 0;
  let INFO = 0;

  for (const f of findings) {
    switch (f.severity) {
      case 'CRITICAL': CRITICAL++; break;
      case 'HIGH': HIGH++; break;
      case 'MEDIUM': MEDIUM++; break;
      case 'LOW': LOW++; break;
      case 'INFO': INFO++; break;
    }
  }

  return { CRITICAL, HIGH, MEDIUM, LOW, INFO };
}

/**
 * Format the address as a hex string.
 */
function toHex(addr: number): string {
  return `0x${addr.toString(16)}`;
}

/**
 * Build the markdown report from the scan results.
 */
function formatReport(
  findings: readonly VulnerabilityFinding[],
  mitigations: SecurityMitigations,
  scanDepth: string,
  binaryPath: string,
): string {
  const counts = countSeverities(findings);
  const totalFindings = findings.length;

  const lines: string[] = [];

  lines.push(`# Vulnerability Scan Report`);
  lines.push('');
  lines.push(`**Binary:** \`${binaryPath}\``);
  lines.push(`**Scan depth:** ${scanDepth}`);
  lines.push(`**Total findings:** ${totalFindings}`);
  lines.push('');

  // Summary table
  lines.push('## Summary by Severity');
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('|----------|-------|');
  lines.push(`| CRITICAL | ${counts.CRITICAL} |`);
  lines.push(`| HIGH     | ${counts.HIGH} |`);
  lines.push(`| MEDIUM   | ${counts.MEDIUM} |`);
  lines.push(`| LOW      | ${counts.LOW} |`);
  lines.push(`| INFO     | ${counts.INFO} |`);
  lines.push('');

  // Security mitigations
  lines.push('## Security Mitigations');
  lines.push('');
  lines.push('| Mitigation | Status |');
  lines.push('|------------|--------|');
  lines.push(`| Stack Canary | ${mitigations.canary ? 'Enabled' : 'NOT FOUND'} |`);
  lines.push(`| NX (DEP)     | ${mitigations.nx ? 'Enabled' : 'NOT FOUND'} |`);
  lines.push(`| PIC/PIE      | ${mitigations.pic ? 'Enabled' : 'NOT FOUND'} |`);
  lines.push(`| RELRO        | ${mitigations.relro} |`);
  lines.push('');

  if (!mitigations.canary || !mitigations.nx || !mitigations.pic || mitigations.relro !== 'full') {
    lines.push('> **Warning:** Missing security mitigations increase exploitability of any findings below.');
    lines.push('');
  }

  if (totalFindings === 0) {
    lines.push('## Findings');
    lines.push('');
    lines.push('No dangerous function imports detected.');
    return lines.join('\n');
  }

  // Detailed findings
  lines.push('## Detailed Findings');
  lines.push('');

  // Sort by severity (CRITICAL first)
  const sorted = [...findings].sort((a, b) => {
    const aOrder = SEVERITY_ORDER[a.severity] ?? 99;
    const bOrder = SEVERITY_ORDER[b.severity] ?? 99;
    return aOrder - bOrder;
  });

  for (let i = 0; i < sorted.length; i++) {
    const f = sorted[i];
    if (f === undefined) continue;

    lines.push(`### ${i + 1}. \`${f.functionName}\` [${f.severity}]`);
    lines.push('');
    lines.push(`- **Category:** ${f.category}`);
    lines.push(`- **Import address:** ${toHex(f.importAddress)}`);
    lines.push(`- **Issue:** ${f.description}`);
    lines.push(`- **Recommendation:** Use ${f.saferAlternative}`);

    if (f.callers.length > 0) {
      lines.push(`- **Called from ${f.callers.length} location(s):**`);
      for (const caller of f.callers) {
        lines.push(`  - \`${caller.function_name}\` at ${toHex(caller.address)} (\`${caller.opcode}\`)`);
      }
    } else {
      lines.push('- **Callers:** Imported but no direct call sites found');
    }

    if (f.decompiled_context !== undefined) {
      lines.push('- **Decompiled context:**');
      lines.push('```c');
      lines.push(f.decompiled_context);
      lines.push('```');
    }

    lines.push('');
  }

  // Category summary
  const categories = new Map<string, number>();
  for (const f of sorted) {
    categories.set(f.category, (categories.get(f.category) ?? 0) + 1);
  }

  lines.push('## Findings by Category');
  lines.push('');
  lines.push('| Category | Count |');
  lines.push('|----------|-------|');
  for (const [cat, count] of categories) {
    lines.push(`| ${cat} | ${count} |`);
  }
  lines.push('');

  return lines.join('\n');
}

/**
 * Extract a short context window from decompiled output around a function call.
 * Returns up to 5 lines around the first occurrence of the function name.
 */
function extractCallContext(decompiledOutput: string, funcName: string): string | undefined {
  const lines = decompiledOutput.split('\n');
  const stripped = stripImportPrefix(funcName);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line !== undefined && line.includes(stripped)) {
      const start = Math.max(0, i - 2);
      const end = Math.min(lines.length, i + 3);
      return lines.slice(start, end).join('\n').trim();
    }
  }

  return undefined;
}

// ---------------------------------------------------------------------------
// Tool registration
// ---------------------------------------------------------------------------

export function registerFindVulnerabilities(server: McpServer): void {
  server.tool(
    'find_vulnerabilities',
    'Scan a binary for common vulnerability patterns: dangerous API usage, buffer overflows, format strings, integer overflows, and missing bounds checks.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      scan_depth: z
        .enum(['quick', 'standard', 'deep'])
        .default('standard')
        .describe(
          'Analysis depth: quick=imports only, standard=imports+xrefs, deep=imports+xrefs+decompile',
        ),
    },
    async ({ binary_path, scan_depth }) => {
      try {
        const safePath = sanitizePath(binary_path);
        return await withCachedSession(
          safePath,
          async (session) => {
            // Step 1: Get all imports
            let imports = await session.cmdj<R2Import[]>('iij');
            if (!Array.isArray(imports)) {
              imports = [];
            }

            // Step 2: Match imports against dangerous function database
            const matched: Array<{
              import_entry: R2Import;
              bare_name: string;
              info: DangerousFunction;
            }> = [];

            for (const imp of imports) {
              const bareName = stripImportPrefix(imp.name);
              const info = DANGEROUS_FUNCTIONS[bareName];
              if (info !== undefined) {
                matched.push({ import_entry: imp, bare_name: bareName, info });
              }
            }

            // Step 3: Get security mitigations
            const mitigations = await detectMitigations(session);

            // Step 4: Build findings (optionally with xrefs and decompilation)
            const findings: VulnerabilityFinding[] = [];

            for (const { import_entry, bare_name, info } of matched) {
              let callers: CallerInfo[] = [];

              // Standard and deep: get xrefs to the import
              if (scan_depth === 'standard' || scan_depth === 'deep') {
                const pltAddr = import_entry.plt;
                if (pltAddr !== undefined && pltAddr !== 0) {
                  try {
                    let xrefs = await session.cmdj<R2Xref[]>(`axtj ${toHex(pltAddr)}`);
                    if (!Array.isArray(xrefs)) {
                      xrefs = [];
                    }
                    callers = xrefs.map((x) => ({
                      address: x.from,
                      function_name: x.fcn_name || 'unknown',
                      opcode: x.opcode || '',
                    }));
                  } catch {
                    // xref lookup can fail for some import types; continue
                  }
                }
              }

              // Deep: decompile each unique caller to get context
              let decompiledContext: string | undefined;
              if (scan_depth === 'deep' && callers.length > 0) {
                // Decompile the first caller only to keep output manageable
                const firstCaller = callers[0];
                if (firstCaller !== undefined && firstCaller.function_name !== 'unknown') {
                  try {
                    // Use address (number) instead of function_name (string from binary metadata)
                    // to prevent second-order injection from malicious binaries
                    const decompiled = await session.cmd(
                      `pdc @ ${toHex(firstCaller.address)}`,
                    );
                    if (decompiled.trim().length > 0) {
                      decompiledContext = extractCallContext(decompiled, bare_name);
                    }
                  } catch {
                    // Decompilation can fail for some functions; continue
                  }
                }
              }

              findings.push({
                functionName: bare_name,
                category: info.category,
                severity: info.severity,
                description: info.description,
                saferAlternative: info.safer_alternative,
                importAddress: import_entry.plt ?? 0,
                callers,
                decompiled_context: decompiledContext,
              });
            }

            // Step 5: Format and return the report
            const report = formatReport(findings, mitigations, scan_depth, safePath);
            return mcpFormatted(report);
          },
          'aaa',
        );
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
