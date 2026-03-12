import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { R2Session } from '../r2/session.js';
import { sanitizeAddress } from '../r2/sanitize.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatShellcode } from '../utils/formatters.js';
import { writeTempBinary, cleanupTempFile } from '../utils/temp-files.js';

const ARCH_MAP: Record<string, { arch: string; bits: number }> = {
  x86: { arch: 'x86', bits: 32 },
  x64: { arch: 'x86', bits: 64 },
  arm: { arch: 'arm', bits: 32 },
  arm64: { arch: 'arm', bits: 64 },
  mips: { arch: 'mips', bits: 32 },
};

interface ShellcodeInstruction {
  readonly offset: number;
  readonly size: number;
  readonly opcode: string;
  readonly disasm: string;
  readonly bytes: string;
  readonly type: string;
}

interface ShellcodeString {
  readonly vaddr: number;
  readonly string: string;
  readonly size: number;
  readonly type: string;
}

export function registerShellcodeAnalyze(server: McpServer): void {
  server.tool(
    'shellcode_analyze',
    'Analyze raw shellcode bytes by loading them as a memory blob, disassembling, and identifying syscalls and patterns.',
    {
      hex_bytes: z
        .string()
        .regex(/^[0-9a-fA-F]+$/, 'Must be hex-encoded bytes (e.g. "31c050...")')
        .describe('Hex-encoded shellcode bytes'),
      architecture: z
        .enum(['x86', 'x64', 'arm', 'arm64', 'mips'])
        .default('x86')
        .describe('Target architecture for disassembly'),
      base_address: z
        .string()
        .default('0x10000')
        .describe('Base address for the shellcode mapping'),
    },
    async ({ hex_bytes, architecture, base_address }) => {
      let tempPath: string | undefined;
      let session: R2Session | undefined;
      try {
        const safeBase = sanitizeAddress(base_address);
        const archConfig = ARCH_MAP[architecture];
        if (!archConfig) {
          return mcpError(`Unsupported architecture: ${architecture}`);
        }

        tempPath = await writeTempBinary(hex_bytes);
        session = await R2Session.open(tempPath, [
          '-2',
          '-a',
          archConfig.arch,
          '-b',
          String(archConfig.bits),
        ]);

        await session.cmd(`e asm.arch=${archConfig.arch}`);
        await session.cmd(`e asm.bits=${archConfig.bits}`);
        await session.cmd(`e anal.from=${safeBase}`);
        await session.cmd('aaa');

        // Disassemble instructions
        let instructions: ShellcodeInstruction[] = [];
        try {
          const raw = await session.cmdj<ShellcodeInstruction[]>('pdj 100');
          if (Array.isArray(raw)) {
            instructions = raw;
          }
        } catch {
          // pdj may fail if there are no valid instructions
        }

        // Extract embedded strings
        let strings: ShellcodeString[] = [];
        try {
          const rawStrings = await session.cmdj<ShellcodeString[]>('izj');
          if (Array.isArray(rawStrings)) {
            strings = rawStrings;
          }
        } catch {
          // izj may return nothing for shellcode blobs
        }

        return mcpFormatted(formatShellcode({
          architecture: archConfig.arch,
          bits: archConfig.bits,
          entry_point: safeBase,
          instruction_count: instructions.length,
          instructions: instructions.map((inst) => ({
            address: `0x${inst.offset.toString(16)}`,
            opcode: inst.opcode,
            disasm: inst.disasm,
            bytes: inst.bytes,
            type: inst.type,
            size: inst.size,
          })),
          strings: strings.map((s) => ({
            address: `0x${s.vaddr.toString(16)}`,
            value: s.string,
            size: s.size,
            type: s.type,
          })),
        }));
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      } finally {
        if (session) {
          await session.close();
        }
        if (tempPath) {
          await cleanupTempFile(tempPath);
        }
      }
    },
  );
}
