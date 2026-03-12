import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizePath, sanitizeAddress } from '../r2/sanitize.js';
import { R2Session } from '../r2/session.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatExecutionTrace } from '../utils/formatters.js';
import { isConditionalJump } from '../utils/shared-helpers.js';

interface TraceEvent {
  step: number;
  address: string;
  instruction: string;
  type: 'comparison' | 'branch_taken' | 'branch_not_taken' | 'call' | 'memory_read' | 'memory_write' | 'syscall' | 'regular';
  detail: string;
  registers?: Record<string, number> | undefined;
}

export function registerTraceExecution(server: McpServer): void {
  server.tool(
    'trace_execution',
    'Trace execution using ESIL emulation, logging comparisons, branches, memory access, and register changes at each step.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      address: z
        .string()
        .optional()
        .describe('Start address for emulation (hex). If omitted, entry point is used.'),
      max_steps: z
        .number()
        .int()
        .min(1)
        .max(50000)
        .default(1000)
        .describe('Maximum number of steps to emulate'),
      until_address: z
        .string()
        .optional()
        .describe('Stop emulation when this address is reached (hex)'),
      log_registers: z
        .boolean()
        .default(false)
        .describe('Log full register state at each interesting event (verbose)'),
      stack_address: z
        .string()
        .default('0x00100000')
        .describe('ESIL stack base address'),
      stack_size: z
        .number()
        .int()
        .min(4096)
        .default(1048576)
        .describe('ESIL stack size in bytes'),
    },
    async ({ binary_path, address, max_steps, until_address, log_registers, stack_address, stack_size }) => {
      try {
        const safePath = sanitizePath(binary_path);
        const safeAddr = address ? sanitizeAddress(address) : undefined;
        const safeUntil = until_address ? sanitizeAddress(until_address) : undefined;
        const safeStack = sanitizeAddress(stack_address);

        // ESIL emulation requires its own session (stateful)
        const session = await R2Session.open(safePath);
        try {
          await session.cmd('aaa');

          // Initialize ESIL
          await session.cmd('aei');
          await session.cmd(`aeim ${safeStack} ${stack_size}`);

          if (safeAddr) {
            await session.cmd(`aepc ${safeAddr}`);
          } else {
            await session.cmd('aeip'); // set to entry point
          }

          const events: TraceEvent[] = [];
          let prevRegisters: Record<string, number> | null = null;

          for (let step = 0; step < max_steps; step++) {
            // Batch: get registers + instruction info in one round-trip
            // We use @@c: to chain commands and parse the combined output
            const regs = await session.cmdj<Record<string, number>>('aerj');
            const pc = getPc(regs);
            const currentAddr = pc !== undefined ? `0x${pc.toString(16)}` : 'unknown';

            // Check stop condition
            if (safeUntil && currentAddr === safeUntil) {
              events.push({
                step,
                address: currentAddr,
                instruction: '(reached target)',
                type: 'regular',
                detail: `Stopped at target address ${safeUntil}`,
                registers: log_registers ? regs : undefined,
              });
              break;
            }

            // Get current instruction (includes jump/fail targets for branch detection)
            let instruction = '';
            let opType = '';
            let jumpTarget: number | undefined;
            let failTarget: number | undefined;
            try {
              const ops = await session.cmdj<{ opcode?: string; disasm?: string; type?: string; jump?: number; fail?: number }[]>(`pdj 1 @ ${currentAddr}`);
              if (Array.isArray(ops) && ops.length > 0) {
                const op = ops[0]!;
                instruction = op.disasm || op.opcode || '';
                opType = op.type || '';
                jumpTarget = op.jump;
                failTarget = op.fail;
              }
            } catch {
              instruction = '(read failed)';
            }

            // Classify the event
            const lower = instruction.toLowerCase();
            let eventType: TraceEvent['type'] = 'regular';
            let detail = '';

            if (lower.startsWith('cmp') || lower.startsWith('test')) {
              eventType = 'comparison';
              detail = describeComparison(instruction, regs);
            } else if (isConditionalJump(lower)) {
              // We already have jump target from the pdj 1 call above — no extra IPC needed
              const jumpAddr = jumpTarget !== undefined ? `0x${jumpTarget.toString(16)}` : null;
              await session.cmd('aes');
              const newRegs = await session.cmdj<Record<string, number>>('aerj');
              const newPc = getPc(newRegs);
              const newAddr = newPc !== undefined ? `0x${newPc.toString(16)}` : 'unknown';

              if (jumpAddr && newAddr === jumpAddr) {
                eventType = 'branch_taken';
                detail = `Branch taken → ${jumpAddr}`;
              } else {
                eventType = 'branch_not_taken';
                detail = `Branch NOT taken (fall through to ${newAddr})`;
              }

              events.push({
                step,
                address: currentAddr,
                instruction,
                type: eventType,
                detail,
                registers: log_registers ? regs : undefined,
              });

              prevRegisters = newRegs;
              continue; // Already stepped
            } else if (opType === 'call' || lower.startsWith('call')) {
              eventType = 'call';
              const target = extractCallTarget(instruction);
              detail = `Calling ${target}`;
            } else if (lower.startsWith('syscall') || lower.startsWith('int ')) {
              eventType = 'syscall';
              detail = `Syscall/interrupt: ${instruction}`;
            } else {
              // Check for register changes (only log if something interesting changed)
              if (prevRegisters) {
                const changes = getRegisterChanges(prevRegisters, regs);
                if (changes.length > 0) {
                  detail = changes.join(', ');
                }
              }
            }

            // Only log interesting events (comparisons, branches, calls, syscalls)
            // or every Nth regular instruction for context
            const isInteresting = eventType !== 'regular';
            const isContextStep = step % 50 === 0;

            if (isInteresting || isContextStep) {
              events.push({
                step,
                address: currentAddr,
                instruction,
                type: eventType,
                detail: detail || instruction,
                registers: log_registers && isInteresting ? regs : undefined,
              });
            }

            // Step
            try {
              await session.cmd('aes');
            } catch {
              events.push({
                step,
                address: currentAddr,
                instruction,
                type: 'regular',
                detail: 'ESIL emulation error — stopping',
              });
              break;
            }

            prevRegisters = regs;
          }

          // Get final register state
          const finalRegs = await session.cmdj<Record<string, number>>('aerj');

          return mcpFormatted(
            formatExecutionTrace({
              start_address: safeAddr ?? 'entry',
              total_steps: events.length > 0 ? (events[events.length - 1]?.step ?? 0) + 1 : 0,
              events,
              final_registers: finalRegs,
              stopped_reason: events.length >= max_steps ? 'max_steps reached' : 'completed',
            }),
          );
        } finally {
          await session.close();
        }
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getPc(regs: Record<string, number>): number | undefined {
  return regs['rip'] ?? regs['eip'] ?? regs['ip'] ?? regs['pc'];
}

function extractCallTarget(instruction: string): string {
  const parts = instruction.split(/\s+/);
  return parts.slice(1).join(' ') || instruction;
}

function describeComparison(instruction: string, regs: Record<string, number>): string {
  const parts = instruction.split(/[,\s]+/).filter(Boolean);
  if (parts.length >= 3) {
    const op1Name = parts[1]!;
    const op2 = parts[2]!;
    const op1Value = regs[op1Name.toLowerCase()];
    if (op1Value !== undefined) {
      return `${op1Name}=${formatHexDec(op1Value)} vs ${op2}`;
    }
  }
  return instruction;
}

function formatHexDec(value: number): string {
  if (value >= 0x20 && value <= 0x7e) {
    return `0x${value.toString(16)} ('${String.fromCharCode(value)}')`;
  }
  return `0x${value.toString(16)}`;
}

function getRegisterChanges(
  prev: Record<string, number>,
  curr: Record<string, number>,
): string[] {
  const changes: string[] = [];
  const interestingRegs = new Set(['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi']);

  for (const reg of interestingRegs) {
    const oldVal = prev[reg];
    const newVal = curr[reg];
    if (oldVal !== undefined && newVal !== undefined && oldVal !== newVal) {
      changes.push(`${reg}: 0x${oldVal.toString(16)} → 0x${newVal.toString(16)}`);
    }
  }

  return changes;
}
