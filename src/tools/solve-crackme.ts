import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizePath, sanitizeAddress, sanitizeFunctionName } from '../r2/sanitize.js';
import { withCachedSession } from '../r2/session-cache.js';
import { R2Session } from '../r2/session.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { isConditionalJump } from '../utils/shared-helpers.js';
import type { R2Instruction, R2DisasmFunction } from '../types.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ComparisonSite {
  address: string;
  offset: number;
  instruction: string;
  comparedValue: number | undefined;
  inputOffset: number | undefined;
  branchAddress: string | undefined;
  failAddress: string | undefined;
}

interface CharResult {
  position: number;
  character: string;
  charCode: number;
  comparisonAddress: string | undefined;
  attempts: number;
}

interface SolveResult {
  functionName: string;
  functionAddress: string;
  solved: boolean;
  solution: string;
  characters: CharResult[];
  comparisonSites: ComparisonSite[];
  totalEsilSteps: number;
  inputAddress: string;
  charset: string;
  diagnostics?: {
    totalCharactersTried: number;
    lastPositionAttempted: number;
    lastComparisonValues: string[];
    pathsExplored: { success: number; fail: number; timeout: number; ret: number };
  } | undefined;
}

// ---------------------------------------------------------------------------
// Character set helpers
// ---------------------------------------------------------------------------

const CHARSETS: Record<string, number[]> = {
  printable: buildRange(0x20, 0x7e),
  alpha: [...buildRange(0x41, 0x5a), ...buildRange(0x61, 0x7a)],
  alnum: [...buildRange(0x30, 0x39), ...buildRange(0x41, 0x5a), ...buildRange(0x61, 0x7a)],
  hex: [...buildRange(0x30, 0x39), ...buildRange(0x61, 0x66), ...buildRange(0x41, 0x46)],
  digits: buildRange(0x30, 0x39),
};

function buildRange(start: number, end: number): number[] {
  const result: number[] = [];
  for (let i = start; i <= end; i++) {
    result.push(i);
  }
  return result;
}

// ---------------------------------------------------------------------------
// Tool registration
// ---------------------------------------------------------------------------

export function registerSolveCrackme(server: McpServer): void {
  server.tool(
    'solve_crackme',
    'Automatically attempt to solve a crackme by extracting constraints, identifying success/fail paths, and brute-forcing input character by character using ESIL emulation.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      function_name: z
        .string()
        .optional()
        .describe('Check/validation function name'),
      address: z
        .string()
        .optional()
        .describe('Hex address of the check function'),
      input_length: z
        .number()
        .int()
        .min(1)
        .max(256)
        .default(32)
        .describe('Maximum input length to try'),
      charset: z
        .enum(['printable', 'alpha', 'alnum', 'hex', 'digits'])
        .default('printable')
        .describe('Character set to brute-force'),
      max_steps_per_char: z
        .number()
        .int()
        .min(100)
        .max(100000)
        .default(5000)
        .describe('Max ESIL steps per character attempt'),
      input_address: z
        .string()
        .optional()
        .describe('Memory address where input is stored (auto-detected if omitted)'),
    },
    async ({
      binary_path,
      function_name,
      address,
      input_length,
      charset,
      max_steps_per_char,
      input_address,
    }) => {
      if (!function_name && !address) {
        return mcpError('Either function_name or address must be provided');
      }

      try {
        const safePath = sanitizePath(binary_path);
        const safeAddr = address ? sanitizeAddress(address) : undefined;
        const safeName = function_name ? sanitizeFunctionName(function_name) : undefined;
        const safeInputAddr = input_address ? sanitizeAddress(input_address) : undefined;
        const charValues = CHARSETS[charset] ?? CHARSETS['printable']!;

        // Phase 1: Static analysis — extract constraints and comparison sites
        const staticInfo = await withCachedSession(safePath, async (session) => {
          // Resolve function address
          let funcAddr: string;
          if (safeAddr) {
            funcAddr = safeAddr;
          } else {
            await session.cmd(`s ${safeName!}`);
            funcAddr = (await session.cmd('s')).trim();
          }

          // Disassemble the function
          const disasm = await session.cmdj<R2DisasmFunction>(`pdfj @ ${funcAddr}`).catch(() => null);
          if (!disasm || !disasm.ops) {
            return null;
          }

          // Find comparison instructions (cmp byte [...], imm patterns)
          const comparisons: ComparisonSite[] = [];
          for (let i = 0; i < disasm.ops.length; i++) {
            const op = disasm.ops[i]!;
            const instruction = (op.disasm || op.opcode).toLowerCase();

            if (instruction.startsWith('cmp') || instruction.startsWith('test')) {
              // Try to extract the compared immediate value
              const comparedValue = extractImmediateValue(instruction);
              const inputOffset = extractInputOffset(instruction);

              // Find the following conditional branch
              let branchAddress: string | undefined;
              let failAddress: string | undefined;
              const next = disasm.ops[i + 1];
              if (next && isConditionalJump((next.disasm || next.opcode).toLowerCase())) {
                branchAddress = next.jump !== undefined
                  ? `0x${next.jump.toString(16)}`
                  : undefined;
                failAddress = next.fail !== undefined
                  ? `0x${next.fail.toString(16)}`
                  : undefined;
              }

              comparisons.push({
                address: `0x${op.offset.toString(16)}`,
                offset: op.offset,
                instruction: op.disasm || op.opcode,
                comparedValue,
                inputOffset,
                branchAddress,
                failAddress,
              });
            }
          }

          // Try to find where input is read from (look for rdi/edi as first arg)
          let detectedInputAddr: string | undefined;
          for (const op of disasm.ops) {
            const instr = (op.disasm || op.opcode).toLowerCase();
            // Look for lea rdi, [addr] or mov rdi, addr patterns that set up
            // the input pointer before the comparison loop
            if (
              (instr.includes('lea') || instr.includes('mov')) &&
              (instr.includes('rdi') || instr.includes('edi'))
            ) {
              const addrMatch = /0x[0-9a-f]+/.exec(instr);
              if (addrMatch) {
                detectedInputAddr = addrMatch[0];
                break;
              }
            }
          }

          // Find success/fail strings for path identification
          const SUCCESS_RE = /correct|success|congrat|win|flag|good|right|valid|accept|welcome|granted|unlock/i;
          const FAIL_RE = /wrong|fail|error|invalid|bad|incorrect|denied|lose|nope|try again|access denied|rejected/i;

          let successAddr: string | undefined;
          let failAddr: string | undefined;

          for (const op of disasm.ops) {
            if (op.refs) {
              for (const ref of op.refs) {
                if (ref.type === 'DATA' || ref.type === 'STRING') {
                  try {
                    const strVal = await session.cmd(`ps @ 0x${ref.addr.toString(16)}`);
                    const trimmed = strVal.trim();
                    if (SUCCESS_RE.test(trimmed)) {
                      successAddr = `0x${op.offset.toString(16)}`;
                    } else if (FAIL_RE.test(trimmed)) {
                      failAddr = `0x${op.offset.toString(16)}`;
                    }
                  } catch {
                    // Skip unreadable strings
                  }
                }
              }
            }
          }

          return {
            funcAddr,
            funcName: disasm.name || funcAddr,
            comparisons,
            detectedInputAddr,
            successAddr,
            failAddr,
          };
        });

        if (!staticInfo) {
          return mcpError('Could not disassemble the target function');
        }

        const {
          funcAddr,
          funcName,
          comparisons,
          detectedInputAddr,
          successAddr,
          failAddr,
        } = staticInfo;

        // Phase 2: Try direct constraint extraction (if comparisons have immediate values)
        // This handles the simple `cmp byte [rdi+N], 0xXX` pattern without emulation
        const directSolution = tryDirectSolve(comparisons, input_length);

        if (directSolution) {
          const charResults: CharResult[] = directSolution.map((ch, i) => ({
            position: i,
            character: String.fromCharCode(ch.value),
            charCode: ch.value,
            comparisonAddress: ch.address,
            attempts: 1,
          }));

          const result: SolveResult = {
            functionName: funcName,
            functionAddress: funcAddr,
            solved: true,
            solution: charResults.map((c) => c.character).join(''),
            characters: charResults,
            comparisonSites: comparisons,
            totalEsilSteps: 0,
            inputAddress: safeInputAddr ?? detectedInputAddr ?? '(direct)',
            charset,
          };

          return mcpFormatted(formatSolveResult(result));
        }

        // Phase 3: ESIL brute-force, character by character
        // Use a memory region for input storage
        const INPUT_MEM_ADDR = safeInputAddr ?? detectedInputAddr ?? '0x00200000';
        const discoveredChars: CharResult[] = [];
        let totalSteps = 0;
        let solutionComplete = false;
        let totalCharactersTried = 0;
        let lastPositionAttempted = 0;
        const lastComparisonValues: string[] = [];
        const pathsExplored = { success: 0, fail: 0, timeout: 0, ret: 0 };

        // Run analysis ONCE and export the analysis state as a project
        // so brute-force sessions can reuse it without re-running aaa
        let analysisProject: string | undefined;
        {
          const analysisSession = await R2Session.open(safePath);
          try {
            await analysisSession.cmd('aaa');
            // Save analysis to a temporary r2 project for reuse
            const projName = `crackme_${Date.now()}`;
            await analysisSession.cmd(`Ps ${projName}`);
            analysisProject = projName;
          } finally {
            await analysisSession.close();
          }
        }

        try {
        for (let pos = 0; pos < input_length; pos++) {
          let foundChar = false;
          lastPositionAttempted = pos;

          for (const charCode of charValues) {
            totalCharactersTried++;
            // Open session WITHOUT full analysis — reuse saved project
            const session = await R2Session.open(safePath, ['-2', '-n']);
            try {
              // Restore analysis from the saved project (much faster than re-running aaa)
              if (analysisProject) {
                await session.cmd(`Po ${analysisProject}`);
              }

              // Initialize ESIL
              await session.cmd('aei');
              await session.cmd('aeim');

              // Write the known prefix + current test character
              const prefix = discoveredChars.map((c) => c.charCode);
              const testInput = [...prefix, charCode, 0]; // null-terminate
              const hexInput = testInput.map((b) => b.toString(16).padStart(2, '0')).join('');
              await session.cmd(`wx ${hexInput} @ ${INPUT_MEM_ADDR}`);

              // Set up the function call:
              // Put the input address in rdi (first argument, System V AMD64 ABI)
              await session.cmd(`aepc ${funcAddr}`);
              await session.cmd(`aer rdi = ${INPUT_MEM_ADDR}`);

              // Step through and look for comparisons
              let stepCount = 0;
              let charPassed = false;
              let charFailed = false;
              let comparisonAddr: string | undefined;

              for (let step = 0; step < max_steps_per_char; step++) {
                stepCount++;

                // Get current PC
                const regs = await session.cmdj<Record<string, number>>('aerj');
                const pc = regs['rip'] ?? regs['eip'] ?? regs['ip'] ?? regs['pc'];
                if (pc === undefined) break;

                const currentAddr = `0x${pc.toString(16)}`;

                // Check if we hit the success path
                if (successAddr && currentAddr === successAddr) {
                  charPassed = true;
                  pathsExplored.success++;
                  break;
                }

                // Check if we hit the fail path
                if (failAddr && currentAddr === failAddr) {
                  charFailed = true;
                  pathsExplored.fail++;
                  break;
                }

                // Get current instruction
                let instruction = '';
                try {
                  const ops = await session.cmdj<{ opcode?: string; disasm?: string; type?: string }[]>(
                    `pdj 1 @ ${currentAddr}`,
                  );
                  if (Array.isArray(ops) && ops.length > 0 && ops[0]) {
                    instruction = (ops[0].disasm || ops[0].opcode || '').toLowerCase();
                  }
                } catch {
                  break;
                }

                // On a comparison instruction, record it and check the result
                if (instruction.startsWith('cmp') || instruction.startsWith('test')) {
                  comparisonAddr = currentAddr;
                  // Track last comparison for diagnostics
                  if (lastComparisonValues.length >= 20) lastComparisonValues.shift();
                  lastComparisonValues.push(`${currentAddr}: ${instruction} (char=0x${charCode.toString(16)})`);

                  // Step past the comparison
                  await session.cmd('aes');
                  stepCount++;

                  // Get the next instruction (should be a conditional branch)
                  const regsAfterCmp = await session.cmdj<Record<string, number>>('aerj');
                  const pcAfterCmp = regsAfterCmp['rip'] ?? regsAfterCmp['eip'] ?? regsAfterCmp['ip'] ?? regsAfterCmp['pc'];
                  if (pcAfterCmp === undefined) break;

                  const addrAfterCmp = `0x${pcAfterCmp.toString(16)}`;
                  let branchInstr = '';
                  let jumpTarget: number | undefined;
                  let fallTarget: number | undefined;

                  try {
                    const branchOps = await session.cmdj<{ opcode?: string; disasm?: string; jump?: number; fail?: number }[]>(
                      `pdj 1 @ ${addrAfterCmp}`,
                    );
                    if (Array.isArray(branchOps) && branchOps.length > 0 && branchOps[0]) {
                      branchInstr = (branchOps[0].disasm || branchOps[0].opcode || '').toLowerCase();
                      jumpTarget = branchOps[0].jump;
                      fallTarget = branchOps[0].fail;
                    }
                  } catch {
                    // ignore
                  }

                  if (isConditionalJump(branchInstr)) {
                    // Step through the branch
                    await session.cmd('aes');
                    stepCount++;

                    const regsAfterBranch = await session.cmdj<Record<string, number>>('aerj');
                    const pcAfterBranch = regsAfterBranch['rip'] ?? regsAfterBranch['eip'] ?? regsAfterBranch['ip'] ?? regsAfterBranch['pc'];

                    if (pcAfterBranch !== undefined) {
                      // For jne (jump if not equal): if the jump is taken,
                      // the comparison failed. If fall-through, it passed.
                      const jumped = jumpTarget !== undefined && pcAfterBranch === jumpTarget;
                      const fellThrough = fallTarget !== undefined && pcAfterBranch === fallTarget;

                      // Heuristic: jne after cmp usually means "if not equal, go to fail"
                      if (branchInstr.startsWith('jne') || branchInstr.startsWith('jnz')) {
                        if (jumped) {
                          charFailed = true;
                        } else if (fellThrough) {
                          charPassed = true;
                        }
                      } else if (branchInstr.startsWith('je') || branchInstr.startsWith('jz')) {
                        // je/jz: jump if equal means "if equal, go to success"
                        if (jumped) {
                          charPassed = true;
                        } else if (fellThrough) {
                          charFailed = true;
                        }
                      } else {
                        // Generic: use fail path address if known
                        if (failAddr && jumped && `0x${jumpTarget!.toString(16)}` === failAddr) {
                          charFailed = true;
                        } else if (failAddr && fellThrough && `0x${fallTarget!.toString(16)}` === failAddr) {
                          charFailed = true;
                        } else if (jumped) {
                          // Default: assume jump after failed comparison = fail
                          charFailed = true;
                        } else {
                          charPassed = true;
                        }
                      }
                    }
                    break;
                  }

                  continue;
                }

                // Check for ret (function returned — input may have been accepted)
                if (instruction === 'ret' || instruction === 'retn') {
                  pathsExplored.ret++;
                  // Check return value (rax/eax)
                  const retRegs = await session.cmdj<Record<string, number>>('aerj');
                  const retVal = retRegs['rax'] ?? retRegs['eax'] ?? 0;
                  // Convention: 0 = success (like strcmp), nonzero = fail
                  // or: 1 = true/success, 0 = fail
                  // We cannot know for sure, so mark as passed if first comparison matched
                  if (comparisonAddr) {
                    charPassed = retVal === 0 || retVal === 1;
                  }
                  break;
                }

                // Step
                try {
                  await session.cmd('aes');
                } catch {
                  break;
                }
              }

              totalSteps += stepCount;

              if (!charPassed && !charFailed && stepCount >= max_steps_per_char) {
                pathsExplored.timeout++;
              }

              if (charPassed && !charFailed) {
                discoveredChars.push({
                  position: pos,
                  character: charCode >= 0x20 && charCode <= 0x7e
                    ? String.fromCharCode(charCode)
                    : `\\x${charCode.toString(16).padStart(2, '0')}`,
                  charCode,
                  comparisonAddress: comparisonAddr,
                  attempts: charValues.indexOf(charCode) + 1,
                });
                foundChar = true;
                break; // Move to next position
              }
            } finally {
              await session.close();
            }
          }

          if (!foundChar) {
            // No character worked for this position — the solution might be
            // complete (null terminator), or we failed
            solutionComplete = discoveredChars.length > 0;
            break;
          }
        }

        if (discoveredChars.length === input_length) {
          solutionComplete = true;
        }
        } finally {
          // Clean up the temporary analysis project
          if (analysisProject) {
            try {
              const cleanupSession = await R2Session.open(safePath, ['-2', '-n']);
              try {
                await cleanupSession.cmd(`Pd ${analysisProject}`);
              } finally {
                await cleanupSession.close();
              }
            } catch {
              // Ignore cleanup errors
            }
          }
        }

        const solved = solutionComplete && discoveredChars.length > 0;
        const result: SolveResult = {
          functionName: funcName,
          functionAddress: funcAddr,
          solved,
          solution: discoveredChars.map((c) => c.character).join(''),
          characters: discoveredChars,
          comparisonSites: comparisons,
          totalEsilSteps: totalSteps,
          inputAddress: INPUT_MEM_ADDR,
          charset,
          diagnostics: !solved ? {
            totalCharactersTried,
            lastPositionAttempted,
            lastComparisonValues,
            pathsExplored,
          } : undefined,
        };

        return mcpFormatted(formatSolveResult(result));
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}

// ---------------------------------------------------------------------------
// Direct solve — extract solution from immediate comparison values
// ---------------------------------------------------------------------------

function tryDirectSolve(
  comparisons: ComparisonSite[],
  maxLength: number,
): { value: number; address: string }[] | null {
  // Look for a sequence of comparisons against immediate byte values
  // with sequential input offsets (cmp byte [rdi+0], 0x41; cmp byte [rdi+1], 0x42; ...)
  const byOffset = new Map<number, { value: number; address: string }>();

  for (const cmp of comparisons) {
    if (cmp.comparedValue !== undefined && cmp.inputOffset !== undefined) {
      byOffset.set(cmp.inputOffset, { value: cmp.comparedValue, address: cmp.address });
    }
  }

  if (byOffset.size === 0) return null;

  // Check if we have a contiguous sequence starting from 0
  const result: { value: number; address: string }[] = [];
  for (let i = 0; i < maxLength; i++) {
    const entry = byOffset.get(i);
    if (!entry) break;
    // Only accept printable ASCII or common byte values
    if (entry.value >= 0x01 && entry.value <= 0xff) {
      result.push(entry);
    } else {
      break;
    }
  }

  return result.length > 0 ? result : null;
}

// ---------------------------------------------------------------------------
// Instruction parsing helpers
// ---------------------------------------------------------------------------

function extractImmediateValue(instruction: string): number | undefined {
  // Match patterns like: cmp byte [rdi + 0x5], 0x41
  //                  or: cmp al, 0x41
  //                  or: cmp eax, 0x2a
  const immMatch = /,\s*(?:0x([0-9a-f]+)|(\d+))\s*$/i.exec(instruction);
  if (immMatch) {
    const hexVal = immMatch[1];
    const decVal = immMatch[2];
    if (hexVal !== undefined) return parseInt(hexVal, 16);
    if (decVal !== undefined) return parseInt(decVal, 10);
  }
  return undefined;
}

function extractInputOffset(instruction: string): number | undefined {
  // Match patterns like: cmp byte [rdi + 0x5], 0x41 -> offset 5
  //                  or: cmp byte [rsi + 3], 0x41 -> offset 3
  //                  or: cmp byte [rbp - 0x20 + 3], ... -> harder, skip
  const offsetMatch = /\[\s*\w+\s*\+\s*(?:0x([0-9a-f]+)|(\d+))\s*\]/i.exec(instruction);
  if (offsetMatch) {
    const hexVal = offsetMatch[1];
    const decVal = offsetMatch[2];
    if (hexVal !== undefined) return parseInt(hexVal, 16);
    if (decVal !== undefined) return parseInt(decVal, 10);
  }

  // Match `cmp byte [rdi], 0xXX` -> offset 0
  if (/\[\s*(rdi|rsi|r[0-9]+)\s*\]/.test(instruction)) {
    return 0;
  }

  return undefined;
}

// ---------------------------------------------------------------------------
// Markdown formatter (inline, no separate formatter function)
// ---------------------------------------------------------------------------

function formatSolveResult(result: SolveResult): string {
  const lines: string[] = [];

  lines.push(`## Crackme Solver Results`);
  lines.push('');
  lines.push(`**Function:** \`${result.functionName}\` @ \`${result.functionAddress}\``);
  lines.push(`**Status:** ${result.solved ? 'SOLVED' : 'PARTIAL / UNSOLVED'}`);
  lines.push(`**Charset:** ${result.charset}`);
  lines.push(`**Input address:** \`${result.inputAddress}\``);
  lines.push('');

  if (result.solution.length > 0) {
    lines.push(`### Solution`);
    lines.push('');
    lines.push('```');
    lines.push(result.solution);
    lines.push('```');
    lines.push('');

    // Hex representation
    const hexChars = result.characters
      .map((c) => c.charCode.toString(16).padStart(2, '0'))
      .join(' ');
    lines.push(`**Hex:** \`${hexChars}\``);
    lines.push(`**Length:** ${result.characters.length} characters`);
    lines.push('');
  } else {
    lines.push('> No solution found. The crackme may use a pattern not supported by');
    lines.push('> character-by-character brute-forcing (e.g., hash checks, multi-character');
    lines.push('> comparisons, or non-linear input processing).');
    lines.push('');
  }

  if (result.characters.length > 0) {
    lines.push(`### Character Details`);
    lines.push('');
    lines.push('| Pos | Char | Hex | Comparison At | Attempts |');
    lines.push('|-----|------|-----|---------------|----------|');
    for (const ch of result.characters) {
      const display = ch.character.length === 1 && ch.charCode >= 0x20 && ch.charCode <= 0x7e
        ? `\`${ch.character}\``
        : `\`${ch.character}\``;
      lines.push(
        `| ${ch.position} | ${display} | \`0x${ch.charCode.toString(16).padStart(2, '0')}\` | ${ch.comparisonAddress ? `\`${ch.comparisonAddress}\`` : '-'} | ${ch.attempts} |`,
      );
    }
    lines.push('');
  }

  if (result.comparisonSites.length > 0) {
    lines.push(`### Comparison Sites Found (${result.comparisonSites.length})`);
    lines.push('');
    for (const cmp of result.comparisonSites) {
      const valueStr = cmp.comparedValue !== undefined
        ? ` = 0x${cmp.comparedValue.toString(16)}`
        : '';
      const offsetStr = cmp.inputOffset !== undefined
        ? ` [offset ${cmp.inputOffset}]`
        : '';
      lines.push(`- \`${cmp.address}\`: \`${cmp.instruction}\`${valueStr}${offsetStr}`);
    }
    lines.push('');
  }

  if (result.totalEsilSteps > 0) {
    lines.push(`### ESIL Execution Stats`);
    lines.push('');
    lines.push(`- **Total ESIL steps:** ${result.totalEsilSteps.toLocaleString()}`);
    lines.push(
      `- **Avg steps per character:** ${result.characters.length > 0 ? Math.round(result.totalEsilSteps / result.characters.length).toLocaleString() : 'N/A'}`,
    );
    lines.push('');
  } else if (result.solved) {
    lines.push(`> Solution extracted directly from static comparison analysis (no emulation needed).`);
    lines.push('');
  }

  if (result.diagnostics) {
    lines.push(`### Diagnostics (Failure Analysis)`);
    lines.push('');
    lines.push(`- **Total characters tried:** ${result.diagnostics.totalCharactersTried.toLocaleString()}`);
    lines.push(`- **Last position attempted:** ${result.diagnostics.lastPositionAttempted}`);
    lines.push(`- **Paths explored:** success=${result.diagnostics.pathsExplored.success}, fail=${result.diagnostics.pathsExplored.fail}, timeout=${result.diagnostics.pathsExplored.timeout}, ret=${result.diagnostics.pathsExplored.ret}`);
    lines.push('');
    if (result.diagnostics.lastComparisonValues.length > 0) {
      lines.push(`**Last comparison values observed:**`);
      lines.push('```');
      for (const cmpVal of result.diagnostics.lastComparisonValues) {
        lines.push(cmpVal);
      }
      lines.push('```');
      lines.push('');
    }
  }

  return lines.join('\n');
}
