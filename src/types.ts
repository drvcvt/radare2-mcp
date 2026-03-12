import { z } from 'zod';

// ---------------------------------------------------------------------------
// Zod schemas for tool parameters
// ---------------------------------------------------------------------------

/** Hex address string: optional 0x prefix followed by hex digits. */
export const addressSchema = z
  .string()
  .regex(/^(0x)?[0-9a-fA-F]+$/, 'Must be a hex address (e.g. "0x08048000")')
  .describe('Hex address string (e.g. "0x08048000")');

/** Absolute file system path to a binary. */
export const pathSchema = z
  .string()
  .min(1, 'Path must not be empty')
  .describe('Absolute path to the binary file');

/** Pagination offset – zero-based index of the first result to return. */
export const offsetSchema = z
  .number()
  .int()
  .min(0)
  .default(0)
  .describe('Pagination offset (0-based)');

/** Pagination limit – maximum number of results to return. */
export const limitSchema = z
  .number()
  .int()
  .min(1)
  .max(2000)
  .default(100)
  .describe('Max results to return');

/** Reusable pagination parameter group. */
export const paginationSchema = z.object({
  offset: offsetSchema,
  limit: limitSchema,
});

/** Function name or address identifier for flexible lookup. */
export const functionIdentifierSchema = z
  .object({
    function_name: z
      .string()
      .optional()
      .describe('Name of the function (e.g. "main", "sym.main")'),
    address: addressSchema.optional().describe('Hex address of the function'),
  })
  .refine((val) => val.function_name !== undefined || val.address !== undefined, {
    message: 'Either function_name or address must be provided',
  });

/** Number of ESIL emulation steps. */
export const stepsSchema = z
  .number()
  .int()
  .min(1)
  .max(10_000)
  .default(10)
  .describe('Number of ESIL emulation steps');

/** Minimum string length for string extraction. */
export const minLengthSchema = z
  .number()
  .int()
  .min(1)
  .default(5)
  .describe('Minimum string length');

/** Number of bytes to read. */
export const byteLengthSchema = z
  .number()
  .int()
  .min(1)
  .max(65_536)
  .default(256)
  .describe('Number of bytes to read');

/** Hex byte pattern for search. */
export const hexPatternSchema = z
  .string()
  .regex(/^[0-9a-fA-F]+$/, 'Must be a hex byte string (e.g. "90909090")')
  .describe('Hex byte pattern to search for');

// ---------------------------------------------------------------------------
// r2 JSON output types
// ---------------------------------------------------------------------------

/** Binary info returned by `ij` / `iIj`. */
export interface R2BinaryInfo {
  readonly arch: string;
  readonly bits: number;
  readonly bintype: string;
  readonly class: string;
  readonly compiler: string;
  readonly endian: string;
  readonly lang: string;
  readonly machine: string;
  readonly os: string;
  readonly stripped: boolean;
  readonly subsys: string;
}

/** Core info from `ij`. */
export interface R2CoreInfo {
  readonly file: string;
  readonly format: string;
  readonly size: number;
  readonly mode: string;
  readonly type: string;
}

/** Combined `ij` output. */
export interface R2FileInfo {
  readonly core: R2CoreInfo;
  readonly bin: R2BinaryInfo;
}

/** Single function from `aflj`. */
export interface R2Function {
  readonly offset: number;
  readonly name: string;
  readonly size: number;
  readonly nargs: number;
  readonly nlocals: number;
  readonly nbbs: number;
  readonly calltype: string;
  readonly type: string;
  readonly signature: string;
}

/** String entry from `izj` / `izzj`. */
export interface R2String {
  readonly vaddr: number;
  readonly paddr: number;
  readonly ordinal: number;
  readonly size: number;
  readonly length: number;
  readonly section: string;
  readonly type: string;
  readonly string: string;
}

/** Import entry from `iij`. */
export interface R2Import {
  readonly ordinal: number;
  readonly bind: string;
  readonly type: string;
  readonly name: string;
  readonly lib: string;
  readonly plt: number;
}

/** Export entry from `iEj`. */
export interface R2Export {
  readonly name: string;
  readonly flagname: string;
  readonly realname: string;
  readonly ordinal: number;
  readonly bind: string;
  readonly size: number;
  readonly type: string;
  readonly vaddr: number;
  readonly paddr: number;
}

/** Section entry from `iSj`. */
export interface R2Section {
  readonly name: string;
  readonly size: number;
  readonly vsize: number;
  readonly vaddr: number;
  readonly paddr: number;
  readonly perm: string;
  readonly type: string;
}

/** Cross-reference entry from `axtj` / `axfj`. */
export interface R2Xref {
  readonly from: number;
  readonly to: number;
  readonly type: string;
  readonly opcode: string;
  readonly fcn_name: string;
  readonly refname: string;
}

/** Disassembly instruction from `pdfj` / `pdj`. */
export interface R2Instruction {
  readonly offset: number;
  readonly size: number;
  readonly opcode: string;
  readonly disasm: string;
  readonly bytes: string;
  readonly type: string;
  readonly esil: string;
  readonly jump?: number | undefined;
  readonly fail?: number | undefined;
  readonly refs?: readonly { addr: number; type: string }[] | undefined;
}

/** Disassembled function from `pdfj`. */
export interface R2DisasmFunction {
  readonly name: string;
  readonly addr: number;
  readonly ops: readonly R2Instruction[];
}

// ---------------------------------------------------------------------------
// ESIL emulation types
// ---------------------------------------------------------------------------

/** ESIL register state – register name to numeric value. */
export type EsilRegisters = Record<string, number>;

/** A single snapshot of ESIL emulation state after one step. */
export interface EsilState {
  readonly step: number;
  readonly address: number;
  readonly registers: EsilRegisters;
}

/** Full ESIL emulation result. */
export interface EsilEmulationResult {
  readonly startAddress: string;
  readonly steps: readonly EsilState[];
  readonly finalRegisters: EsilRegisters;
}

// ---------------------------------------------------------------------------
// Pagination types (re-exported from utils/pagination.ts for backward compat)
// ---------------------------------------------------------------------------

export type { PaginatedResult } from './utils/pagination.js';

// ---------------------------------------------------------------------------
// MCP response types
// ---------------------------------------------------------------------------

/** A single MCP text content block. */
export interface McpTextContent {
  type: 'text';
  text: string;
}

/** Successful MCP tool response. */
export interface McpSuccessResponse {
  content: McpTextContent[];
}

/** Error MCP tool response. */
export interface McpErrorResponse {
  content: McpTextContent[];
  isError: true;
}

/** Union of possible MCP tool responses. */
export type McpToolResponse = McpSuccessResponse | McpErrorResponse;

// ---------------------------------------------------------------------------
// Debug types
// ---------------------------------------------------------------------------

/** Breakpoint entry from `dbj`. */
export interface R2Breakpoint {
  readonly addr: number;
  readonly size: number;
  readonly perm: string;
  readonly hw: boolean;
  readonly trace: boolean;
  readonly enabled: boolean;
  readonly valid: boolean;
  readonly data: string;
  readonly cond: string;
  readonly name: string;
}

/** Debug info from `dij`. */
export interface R2DebugInfo {
  readonly pid: number;
  readonly tid: number;
  readonly uid: number;
  readonly gid: number;
  readonly usr: string;
  readonly exe: string;
  readonly cmdline: string;
  readonly status: string;
  readonly signum: number;
  readonly signame: string;
}

/** Thread entry from `dptj`. */
export interface R2Thread {
  readonly pid: number;
  readonly tid: number;
  readonly status: string;
  readonly path: string;
}

/** Memory map entry from `dmj`. */
export interface R2MemoryMap {
  readonly name: string;
  readonly file: string;
  readonly addr: number;
  readonly addr_end: number;
  readonly size: number;
  readonly perm: string;
}

/** Backtrace frame from `dbtj`. */
export interface R2BacktraceFrame {
  readonly idx: number;
  readonly pc: number;
  readonly sp: number;
  readonly frame_size: number;
  readonly name: string;
  readonly desc: string;
}

// ---------------------------------------------------------------------------
// Relocation & Class types
// ---------------------------------------------------------------------------

/** Relocation entry from `irj`. */
export interface R2Relocation {
  readonly name: string;
  readonly demname: string;
  readonly type: string;
  readonly vaddr: number;
  readonly paddr: number;
  readonly is_ifunc: boolean;
}

/** Class entry from `icj`. */
export interface R2Class {
  readonly classname: string;
  readonly addr: number;
  readonly methods: readonly { name: string; addr: number; type: string }[];
  readonly fields: readonly { name: string; addr: number; type: string }[];
}

// ---------------------------------------------------------------------------
// Type analysis types
// ---------------------------------------------------------------------------

/** Type definition entry from `tj`, `tsj`, `tej`. */
export interface R2Type {
  readonly name: string;
  readonly kind?: string;
  readonly type?: string;
  readonly size?: number;
  readonly members?: readonly R2TypeMember[];
  readonly values?: readonly R2EnumValue[];
}

/** Struct/union member from `tsj`. */
export interface R2TypeMember {
  readonly name: string;
  readonly type: string;
  readonly offset: number;
  readonly size: number;
}

/** Enum value from `tej`. */
export interface R2EnumValue {
  readonly name: string;
  readonly value: number;
}

// ---------------------------------------------------------------------------
// Binary header types
// ---------------------------------------------------------------------------

/** Header field entry from `ihj`. */
export interface R2Header {
  readonly name: string;
  readonly value: string | number | boolean;
}
