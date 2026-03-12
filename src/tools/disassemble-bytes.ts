import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { R2Session } from '../r2/session.js';
import { sanitizeAddress } from '../r2/sanitize.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatDisassembleBytes } from '../utils/formatters.js';
import { writeTempBinary, cleanupTempFile } from '../utils/temp-files.js';

const ARCH_MAP: Record<string, string> = {
  x86: 'x86',
  x64: 'x86',
  arm: 'arm',
  arm64: 'arm',
  mips: 'mips',
};

interface RawInstruction {
  readonly offset: number;
  readonly size: number;
  readonly opcode: string;
  readonly disasm: string;
  readonly bytes: string;
}

export function registerDisassembleBytes(server: McpServer): void {
  server.tool(
    'disassemble_bytes',
    'Disassemble raw bytes into assembly instructions without loading a full binary.',
    {
      hex_bytes: z
        .string()
        .regex(/^[0-9a-fA-F]+$/, 'Must be hex-encoded bytes')
        .describe('Hex-encoded bytes to disassemble'),
      architecture: z
        .enum(['x86', 'x64', 'arm', 'arm64', 'mips'])
        .default('x86')
        .describe('Target architecture'),
      bits: z
        .enum(['16', '32', '64'])
        .default('32')
        .describe('Address size in bits'),
      offset: z
        .string()
        .default('0x0')
        .describe('Base offset for the disassembly listing'),
    },
    async ({ hex_bytes, architecture, bits, offset }) => {
      let tempPath: string | undefined;
      let session: R2Session | undefined;
      try {
        const safeOffset = sanitizeAddress(offset);
        const archName = ARCH_MAP[architecture];
        if (!archName) {
          return mcpError(`Unsupported architecture: ${architecture}`);
        }
        const bitsNum = parseInt(bits, 10);

        tempPath = await writeTempBinary(hex_bytes);
        session = await R2Session.open(tempPath, [
          '-2',
          '-a',
          archName,
          '-b',
          String(bitsNum),
        ]);

        await session.cmd(`e asm.arch=${archName}`);
        await session.cmd(`e asm.bits=${bitsNum}`);

        // Seek to the user-specified base offset so disassembly addresses are correct
        if (safeOffset !== '0x0' && safeOffset !== '0x00' && safeOffset !== '0') {
          await session.cmd(`s ${safeOffset}`);
        }

        // Calculate number of instructions to disassemble (estimate: hex_bytes / 2 = bytes)
        const byteCount = hex_bytes.length / 2;
        const maxInstructions = Math.max(Math.ceil(byteCount), 1);

        const raw = await session.cmdj<RawInstruction[]>(`pdj ${maxInstructions}`);
        const instructions = Array.isArray(raw) ? raw : [];

        return mcpFormatted(formatDisassembleBytes({
          architecture: archName,
          bits: bitsNum,
          base_offset: safeOffset,
          instruction_count: instructions.length,
          instructions: instructions.map((inst) => ({
            address: `0x${inst.offset.toString(16)}`,
            opcode: inst.opcode,
            disasm: inst.disasm,
            bytes: inst.bytes,
            size: inst.size,
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
