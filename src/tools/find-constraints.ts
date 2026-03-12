import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizePath, sanitizeAddress, sanitizeFunctionName } from '../r2/sanitize.js';
import { withCachedSession } from '../r2/session-cache.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatConstraints } from '../utils/formatters.js';
import { isConditionalJump } from '../utils/shared-helpers.js';
import type { R2Instruction, R2DisasmFunction } from '../types.js';

interface Constraint {
  address: string;
  instruction: string;
  type: 'comparison' | 'branch' | 'call' | 'string_ref';
  detail: string;
  jump_target?: string | undefined;
  fail_target?: string | undefined;
}

interface SuccessFailPath {
  address: string;
  type: 'success' | 'fail' | 'unknown';
  evidence: string;
  reachable_from?: string;
}

export function registerFindConstraints(server: McpServer): void {
  server.tool(
    'find_constraints',
    'Extract comparisons, conditional branches, string references, and success/fail paths from a function — ideal for crackme and CTF challenge analysis.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      function_name: z
        .string()
        .optional()
        .describe('Name of the function to analyze (e.g. "main")'),
      address: z
        .string()
        .optional()
        .describe('Hex address of the function (e.g. "0x08048000")'),
      scan_callees: z
        .boolean()
        .default(true)
        .describe('Also scan functions called from this function for constraints'),
    },
    async ({ binary_path, function_name, address, scan_callees }) => {
      if (!function_name && !address) {
        return mcpError('Either function_name or address must be provided');
      }

      try {
        const safePath = sanitizePath(binary_path);
        const safeAddr = address ? sanitizeAddress(address) : undefined;
        const safeName = function_name ? sanitizeFunctionName(function_name) : undefined;

        return await withCachedSession(safePath, async (session) => {
          // Resolve function address
          let funcAddr: string;
          if (safeAddr) {
            funcAddr = safeAddr;
          } else {
            await session.cmd(`s ${safeName!}`);
            funcAddr = (await session.cmd('s')).trim();
          }

          // Get function disassembly
          const disasm = await session.cmdj<R2DisasmFunction>(`pdfj @ ${funcAddr}`).catch(() => null);
          if (!disasm || !disasm.ops) {
            return mcpFormatted('## No disassembly available\n\nCould not disassemble the function.');
          }

          const constraints: Constraint[] = [];
          const paths: SuccessFailPath[] = [];
          const stringRefs = new Map<string, string>(); // address -> string value

          // Phase 1: Extract all string references in the function
          for (const op of disasm.ops) {
            if (op.refs) {
              for (const ref of op.refs) {
                if (ref.type === 'DATA' || ref.type === 'STRING') {
                  try {
                    const strVal = await session.cmd(`ps @ 0x${ref.addr.toString(16)}`);
                    const trimmed = strVal.trim();
                    if (trimmed.length > 0 && trimmed.length < 500) {
                      const addr = `0x${ref.addr.toString(16)}`;
                      stringRefs.set(addr, trimmed);
                      constraints.push({
                        address: `0x${op.offset.toString(16)}`,
                        instruction: op.disasm || op.opcode,
                        type: 'string_ref',
                        detail: `References string: "${trimmed}"`,
                      });
                    }
                  } catch {
                    // Skip unreadable strings
                  }
                }
              }
            }
          }

          // Also try to get string refs via data xrefs from the function
          try {
            const funcXrefs = await session.cmd(`axfj @ ${funcAddr}`);
            const refs = JSON.parse(funcXrefs) as { from: number; to: number; type: string }[];
            if (Array.isArray(refs)) {
              for (const ref of refs) {
                if (ref.type === 'DATA' || ref.type === 'STRING') {
                  const addr = `0x${ref.to.toString(16)}`;
                  if (!stringRefs.has(addr)) {
                    try {
                      const strVal = await session.cmd(`ps @ ${addr}`);
                      const trimmed = strVal.trim();
                      if (trimmed.length > 0 && trimmed.length < 500) {
                        stringRefs.set(addr, trimmed);
                      }
                    } catch {
                      // Skip
                    }
                  }
                }
              }
            }
          } catch {
            // axfj might not work for all binaries
          }

          // Phase 2: Extract comparisons and conditional branches
          for (let i = 0; i < disasm.ops.length; i++) {
            const op = disasm.ops[i]!;
            const opcode = (op.disasm || op.opcode).toLowerCase();
            const addr = `0x${op.offset.toString(16)}`;

            // Comparison instructions
            if (
              opcode.startsWith('cmp') ||
              opcode.startsWith('test') ||
              opcode.startsWith('sub') && isFollowedByConditionalJump(disasm.ops, i)
            ) {
              constraints.push({
                address: addr,
                instruction: op.disasm || op.opcode,
                type: 'comparison',
                detail: extractComparisonDetail(op),
              });
            }

            // Conditional jumps
            if (isConditionalJump(opcode)) {
              const jumpTarget = op.jump !== undefined ? `0x${op.jump.toString(16)}` : undefined;
              const failTarget = op.fail !== undefined ? `0x${op.fail.toString(16)}` : undefined;

              constraints.push({
                address: addr,
                instruction: op.disasm || op.opcode,
                type: 'branch',
                detail: describeBranchCondition(opcode),
                jump_target: jumpTarget,
                fail_target: failTarget,
              });
            }

            // Function calls (interesting for strcmp, memcmp, etc.)
            if (op.type === 'call' || opcode.startsWith('call')) {
              const calleeName = extractCalleeName(op.disasm || op.opcode);
              if (isInterestingCall(calleeName)) {
                constraints.push({
                  address: addr,
                  instruction: op.disasm || op.opcode,
                  type: 'call',
                  detail: `Calls ${calleeName} — likely a validation/comparison function`,
                });
              }
            }
          }

          // Phase 3: Identify success/fail paths by string content
          const SUCCESS_PATTERNS = /correct|success|congrat|win|flag|good|right|valid|accept|welcome|granted|unlock/i;
          const FAIL_PATTERNS = /wrong|fail|error|invalid|bad|incorrect|denied|lose|nope|try again|access denied|rejected/i;

          for (const [strAddr, strVal] of stringRefs) {
            if (SUCCESS_PATTERNS.test(strVal)) {
              paths.push({
                address: strAddr,
                type: 'success',
                evidence: `String: "${strVal}"`,
              });
            } else if (FAIL_PATTERNS.test(strVal)) {
              paths.push({
                address: strAddr,
                type: 'fail',
                evidence: `String: "${strVal}"`,
              });
            }
          }

          // Phase 4: Optionally scan callees
          const calleeConstraints: { callee: string; constraints: Constraint[] }[] = [];
          if (scan_callees) {
            const calledFunctions = new Set<string>();
            for (const op of disasm.ops) {
              if (op.type === 'call' || (op.disasm || op.opcode).toLowerCase().startsWith('call')) {
                if (op.jump !== undefined) {
                  calledFunctions.add(`0x${op.jump.toString(16)}`);
                }
              }
            }

            // Scan up to 10 callees to avoid excessive analysis time
            let scanned = 0;
            for (const calleeAddr of calledFunctions) {
              if (scanned >= 10) break;
              try {
                const calleeDisasm = await session.cmdj<R2DisasmFunction>(`pdfj @ ${calleeAddr}`);
                if (calleeDisasm && calleeDisasm.ops) {
                  const calleeName = calleeDisasm.name || calleeAddr;
                  const subConstraints: Constraint[] = [];

                  for (let i = 0; i < calleeDisasm.ops.length; i++) {
                    const op = calleeDisasm.ops[i]!;
                    const opcode = (op.disasm || op.opcode).toLowerCase();
                    const opAddr = `0x${op.offset.toString(16)}`;

                    if (opcode.startsWith('cmp') || opcode.startsWith('test')) {
                      subConstraints.push({
                        address: opAddr,
                        instruction: op.disasm || op.opcode,
                        type: 'comparison',
                        detail: extractComparisonDetail(op),
                      });
                    }
                  }

                  if (subConstraints.length > 0) {
                    calleeConstraints.push({ callee: calleeName, constraints: subConstraints });
                  }
                }
              } catch {
                // Skip unanalyzable callees
              }
              scanned++;
            }
          }

          return mcpFormatted(
            formatConstraints({
              functionName: disasm.name || funcAddr,
              functionAddress: funcAddr,
              constraints,
              paths,
              calleeConstraints,
              stringRefs: [...stringRefs.entries()].map(([addr, val]) => ({ address: addr, value: val })),
            }),
          );
        });
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isFollowedByConditionalJump(ops: readonly R2Instruction[], index: number): boolean {
  const next = ops[index + 1];
  if (!next) return false;
  return isConditionalJump((next.disasm || next.opcode).toLowerCase());
}

function extractComparisonDetail(op: R2Instruction): string {
  const parts = (op.disasm || op.opcode).split(',').map((s) => s.trim());
  if (parts.length >= 2) {
    return `Compares ${parts[0]!.split(' ').slice(1).join(' ')} with ${parts[1]}`;
  }
  return op.disasm || op.opcode;
}

function describeBranchCondition(opcode: string): string {
  const jump = opcode.split(' ')[0]?.toLowerCase() ?? '';
  const conditions: Record<string, string> = {
    je: 'Jump if equal (ZF=1)',
    jne: 'Jump if not equal (ZF=0)',
    jz: 'Jump if zero (ZF=1)',
    jnz: 'Jump if not zero (ZF=0)',
    jg: 'Jump if greater (signed)',
    jge: 'Jump if greater or equal (signed)',
    jl: 'Jump if less (signed)',
    jle: 'Jump if less or equal (signed)',
    ja: 'Jump if above (unsigned)',
    jae: 'Jump if above or equal (unsigned)',
    jb: 'Jump if below (unsigned)',
    jbe: 'Jump if below or equal (unsigned)',
    js: 'Jump if sign (SF=1)',
    jns: 'Jump if not sign (SF=0)',
    jo: 'Jump if overflow',
    jno: 'Jump if not overflow',
    jc: 'Jump if carry',
    jnc: 'Jump if not carry',
  };
  return conditions[jump] ?? `Conditional: ${jump}`;
}

function extractCalleeName(instruction: string): string {
  // "call sym.strcmp" -> "sym.strcmp"
  // "call 0x401000" -> "0x401000"
  const parts = instruction.split(/\s+/);
  return parts[parts.length - 1] ?? instruction;
}

function isInterestingCall(name: string): boolean {
  const lower = name.toLowerCase();
  return /strcmp|strncmp|memcmp|memcmp|strlen|strtol|atoi|sscanf|scanf|gets|fgets|getline|check|verify|valid|compare|hash|crypt|md5|sha|aes|base64|decode|encode/.test(lower);
}
