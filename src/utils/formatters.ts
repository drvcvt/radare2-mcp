// ---------------------------------------------------------------------------
// Output formatters — convert raw tool data into readable markdown
// ---------------------------------------------------------------------------

import type {
  R2Function,
  R2String,
  R2Import,
  R2Export,
  R2Section,
  R2Xref,
  R2Instruction,
  R2DisasmFunction,
  R2Breakpoint,
  R2MemoryMap,
  R2BacktraceFrame,
  R2Relocation,
  R2Class,
  R2Type,
  R2Header,
  PaginatedResult,
} from '../types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Format a number as padded hex string: `0x00401000` */
function hex(n: number, pad = 8): string {
  return `0x${n.toString(16).padStart(pad, '0')}`;
}

/** Pagination summary line. */
function paginationLine(total: number, offset: number, limit: number): string {
  const from = offset + 1;
  const to = Math.min(offset + limit, total);
  return `Showing **${from}–${to}** of **${total}** results`;
}

/** Escape pipe characters in markdown table cells. */
function esc(s: string | null | undefined): string {
  if (s == null) return '';
  return s.replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

/** Truncate a string to a max length, appending `...` if needed. */
function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max - 1) + '\u2026';
}

// ---------------------------------------------------------------------------
// analyze_binary
// ---------------------------------------------------------------------------

interface BinaryInfoData {
  core?: {
    file?: string;
    format?: string;
    size?: number;
    mode?: string;
    type?: string;
  };
  bin?: {
    arch?: string;
    bits?: number;
    bintype?: string;
    class?: string;
    compiler?: string;
    endian?: string;
    lang?: string;
    machine?: string;
    os?: string;
    stripped?: boolean;
    subsys?: string;
  };
}

export function formatBinaryInfo(info: BinaryInfoData): string {
  const lines: string[] = [];
  const c = info.core;
  const b = info.bin;

  lines.push('## Binary Analysis\n');

  if (c) {
    lines.push('### File Info\n');
    lines.push('| Property | Value |');
    lines.push('|----------|-------|');
    if (c.file) lines.push(`| File | \`${esc(c.file)}\` |`);
    if (c.format) lines.push(`| Format | ${c.format} |`);
    if (c.type) lines.push(`| Type | ${c.type} |`);
    if (c.size !== undefined) lines.push(`| Size | ${c.size.toLocaleString()} bytes |`);
    if (c.mode) lines.push(`| Mode | ${c.mode} |`);
    lines.push('');
  }

  if (b) {
    lines.push('### Binary Properties\n');
    lines.push('| Property | Value |');
    lines.push('|----------|-------|');
    if (b.arch) lines.push(`| Arch | \`${b.arch}\` |`);
    if (b.bits !== undefined) lines.push(`| Bits | ${b.bits} |`);
    if (b.os) lines.push(`| OS | ${b.os} |`);
    if (b.machine) lines.push(`| Machine | ${b.machine} |`);
    if (b.endian) lines.push(`| Endian | ${b.endian} |`);
    if (b.bintype) lines.push(`| Bin Type | ${b.bintype} |`);
    if (b.class) lines.push(`| Class | ${b.class} |`);
    if (b.lang) lines.push(`| Language | ${b.lang} |`);
    if (b.compiler) lines.push(`| Compiler | ${esc(b.compiler)} |`);
    if (b.subsys) lines.push(`| Subsystem | ${b.subsys} |`);
    if (b.stripped !== undefined) lines.push(`| Stripped | ${b.stripped ? 'yes' : 'no'} |`);
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// list_functions
// ---------------------------------------------------------------------------

export function formatFunctionList(page: PaginatedResult<R2Function>): string {
  const lines: string[] = [];
  lines.push('## Functions\n');
  lines.push(paginationLine(page.total, page.offset, page.limit));
  lines.push('');
  lines.push('| Address | Name | Size | Args | Locals | BBs | Type |');
  lines.push('|---------|------|-----:|-----:|-------:|----:|------|');

  for (const fn of page.results) {
    const addr = hex(fn.offset);
    lines.push(
      `| \`${addr}\` | \`${esc(fn.name)}\` | ${fn.size} | ${fn.nargs} | ${fn.nlocals} | ${fn.nbbs} | ${fn.type ?? ''} |`,
    );
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// disassemble
// ---------------------------------------------------------------------------

export function formatDisassemblyFunction(func: R2DisasmFunction): string {
  const lines: string[] = [];
  const addr = hex(func.addr);
  lines.push(`## Disassembly: \`${func.name}\` @ \`${addr}\`\n`);
  lines.push('```asm');

  for (const op of func.ops) {
    const a = hex(op.offset);
    const bytes = (op.bytes ?? '').padEnd(20);
    lines.push(`${a}  ${bytes}  ${op.disasm ?? op.opcode}`);
  }

  lines.push('```');
  return lines.join('\n');
}

export function formatDisassemblyInstructions(instructions: readonly R2Instruction[]): string {
  const lines: string[] = [];
  lines.push(`## Disassembly (${instructions.length} instructions)\n`);
  lines.push('```asm');

  for (const op of instructions) {
    const a = hex(op.offset);
    const bytes = (op.bytes ?? '').padEnd(20);
    lines.push(`${a}  ${bytes}  ${op.disasm ?? op.opcode}`);
  }

  lines.push('```');
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// decompile
// ---------------------------------------------------------------------------

interface DecompileData {
  function_name: string;
  address: string;
  pseudo_c: string;
}

export function formatDecompilation(data: DecompileData): string {
  const lines: string[] = [];
  lines.push(`## Decompilation: \`${data.function_name}\` @ \`${data.address}\`\n`);
  lines.push('```c');
  lines.push(data.pseudo_c);
  lines.push('```');
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// list_strings
// ---------------------------------------------------------------------------

export function formatStringList(page: PaginatedResult<R2String>): string {
  const lines: string[] = [];
  lines.push('## Strings\n');
  lines.push(paginationLine(page.total, page.offset, page.limit));
  lines.push('');
  lines.push('| Address | Section | Len | Type | String |');
  lines.push('|---------|---------|----:|------|--------|');

  for (const s of page.results) {
    const addr = hex(s.vaddr);
    const str = truncate(esc(s.string), 80);
    lines.push(
      `| \`${addr}\` | ${esc(s.section)} | ${s.length} | ${s.type} | \`${str}\` |`,
    );
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// list_imports
// ---------------------------------------------------------------------------

export function formatImportList(page: PaginatedResult<R2Import>): string {
  const lines: string[] = [];
  lines.push('## Imports\n');
  lines.push(paginationLine(page.total, page.offset, page.limit));
  lines.push('');
  lines.push('| PLT Address | Name | Type | Bind | Library |');
  lines.push('|-------------|------|------|------|---------|');

  for (const imp of page.results) {
    const addr = hex(imp.plt);
    lines.push(
      `| \`${addr}\` | \`${esc(imp.name)}\` | ${imp.type} | ${imp.bind} | ${esc(imp.lib ?? '')} |`,
    );
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// list_exports
// ---------------------------------------------------------------------------

export function formatExportList(page: PaginatedResult<R2Export>): string {
  const lines: string[] = [];
  lines.push('## Exports\n');
  lines.push(paginationLine(page.total, page.offset, page.limit));
  lines.push('');
  lines.push('| Address | Name | Size | Type | Bind |');
  lines.push('|---------|------|-----:|------|------|');

  for (const exp of page.results) {
    const addr = hex(exp.vaddr);
    lines.push(
      `| \`${addr}\` | \`${esc(exp.name)}\` | ${exp.size} | ${exp.type} | ${exp.bind} |`,
    );
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// list_sections
// ---------------------------------------------------------------------------

export function formatSectionList(page: PaginatedResult<R2Section>): string {
  const lines: string[] = [];
  lines.push('## Sections\n');
  lines.push(paginationLine(page.total, page.offset, page.limit));
  lines.push('');
  lines.push('| Address | Name | Size | VSize | Perm | Type |');
  lines.push('|---------|------|-----:|------:|------|------|');

  for (const sec of page.results) {
    const addr = hex(sec.vaddr);
    lines.push(
      `| \`${addr}\` | \`${esc(sec.name)}\` | ${sec.size.toLocaleString()} | ${sec.vsize.toLocaleString()} | \`${sec.perm}\` | ${sec.type} |`,
    );
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// get_xrefs
// ---------------------------------------------------------------------------

export function formatXrefs(
  xrefs: readonly R2Xref[],
  direction: string,
  address: string,
): string {
  const lines: string[] = [];
  const arrow = direction === 'to' ? '\u2192' : '\u2190';
  lines.push(`## Cross-References ${arrow} \`${address}\`\n`);
  lines.push(`**${xrefs.length}** references found (direction: ${direction})\n`);

  if (xrefs.length === 0) return lines.join('\n');

  lines.push('| From | To | Type | Opcode | Function |');
  lines.push('|------|----|------|--------|----------|');

  for (const x of xrefs) {
    lines.push(
      `| \`${hex(x.from)}\` | \`${hex(x.to)}\` | ${x.type} | \`${esc(x.opcode ?? '')}\` | \`${esc(x.fcn_name ?? '')}\` |`,
    );
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Registers (shared between ESIL and debug)
// ---------------------------------------------------------------------------

/** Well-known x86/x64 register groups for visual grouping. */
const GP_REGS_64 = new Set([
  'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp',
  'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
]);
const GP_REGS_32 = new Set([
  'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp',
]);
const IP_REGS = new Set(['rip', 'eip', 'ip', 'pc']);
const FLAG_REGS = new Set(['eflags', 'rflags', 'flags']);
const SEG_REGS = new Set(['cs', 'ds', 'es', 'fs', 'gs', 'ss']);

function classifyRegister(name: string): 'gp' | 'ip' | 'flags' | 'segment' | 'other' {
  const lower = name.toLowerCase();
  if (GP_REGS_64.has(lower) || GP_REGS_32.has(lower)) return 'gp';
  if (IP_REGS.has(lower)) return 'ip';
  if (FLAG_REGS.has(lower)) return 'flags';
  if (SEG_REGS.has(lower)) return 'segment';
  return 'other';
}

export function formatRegisters(regs: Record<string, number>, title = 'Registers'): string {
  const lines: string[] = [];
  lines.push(`## ${title}\n`);

  const entries = Object.entries(regs);
  if (entries.length === 0) {
    lines.push('*No registers available*');
    return lines.join('\n');
  }

  // Group registers
  const groups: Record<string, [string, number][]> = {
    'Instruction Pointer': [],
    'General Purpose': [],
    Flags: [],
    Segment: [],
    Other: [],
  };

  for (const [name, value] of entries) {
    const cls = classifyRegister(name);
    switch (cls) {
      case 'ip': groups['Instruction Pointer']!.push([name, value]); break;
      case 'gp': groups['General Purpose']!.push([name, value]); break;
      case 'flags': groups['Flags']!.push([name, value]); break;
      case 'segment': groups['Segment']!.push([name, value]); break;
      default: groups['Other']!.push([name, value]); break;
    }
  }

  for (const [groupName, regsInGroup] of Object.entries(groups)) {
    if (regsInGroup.length === 0) continue;

    lines.push(`### ${groupName}\n`);
    lines.push('| Register | Value |');
    lines.push('|----------|-------|');

    for (const [name, value] of regsInGroup) {
      const hexVal = `0x${value.toString(16).padStart(16, '0')}`;
      lines.push(`| \`${name}\` | \`${hexVal}\` |`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// ESIL step / debug step
// ---------------------------------------------------------------------------

interface StepData {
  address: string;
  instruction: string;
  registers: Record<string, number>;
}

export function formatSteps(
  steps: readonly StepData[],
  opts?: { title?: string; showRegisters?: boolean },
): string {
  const lines: string[] = [];
  const title = opts?.title ?? 'Emulation Steps';
  const showRegs = opts?.showRegisters !== false;

  lines.push(`## ${title}\n`);
  lines.push(`**${steps.length}** step(s) executed\n`);

  for (let i = 0; i < steps.length; i++) {
    const step = steps[i]!;
    lines.push(`### Step ${i + 1}: \`${step.address}\`\n`);
    if (step.instruction) {
      lines.push(`\`\`\`asm\n${step.instruction}\n\`\`\`\n`);
    }

    if (showRegs && step.registers && Object.keys(step.registers).length > 0) {
      // Compact register display for steps — horizontal layout
      const regEntries = Object.entries(step.registers);
      const gpRegs = regEntries.filter(([n]) => {
        const cls = classifyRegister(n);
        return cls === 'gp' || cls === 'ip';
      });

      if (gpRegs.length > 0) {
        lines.push('| Register | Value |');
        lines.push('|----------|-------|');
        for (const [name, value] of gpRegs) {
          lines.push(`| \`${name}\` | \`0x${value.toString(16).padStart(16, '0')}\` |`);
        }
        lines.push('');
      }
    }
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// ESIL run result
// ---------------------------------------------------------------------------

interface EsilRunData {
  stopped_at: string;
  reason: string;
  steps_taken: number;
  final_registers: Record<string, number>;
}

export function formatEsilRunResult(data: EsilRunData): string {
  const lines: string[] = [];
  lines.push('## ESIL Emulation Result\n');
  lines.push(`| Property | Value |`);
  lines.push(`|----------|-------|`);
  lines.push(`| Stopped at | \`${data.stopped_at}\` |`);
  lines.push(`| Reason | **${data.reason}** |`);
  lines.push(`| Steps taken | ${data.steps_taken === -1 ? 'N/A (aecu mode)' : data.steps_taken} |`);
  lines.push('');

  if (data.final_registers && Object.keys(data.final_registers).length > 0) {
    lines.push(formatRegisters(data.final_registers, 'Final Registers'));
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// ESIL init
// ---------------------------------------------------------------------------

interface EsilInitData {
  initialized: boolean;
  entry_point: string;
  stack_address: string;
  stack_size: number;
  registers: Record<string, number>;
}

export function formatEsilInit(data: EsilInitData): string {
  const lines: string[] = [];
  lines.push('## ESIL VM Initialized\n');
  lines.push('| Property | Value |');
  lines.push('|----------|-------|');
  lines.push(`| Entry Point | \`${data.entry_point}\` |`);
  lines.push(`| Stack Address | \`${data.stack_address}\` |`);
  lines.push(`| Stack Size | ${data.stack_size.toLocaleString()} bytes |`);
  lines.push('');

  if (data.registers && Object.keys(data.registers).length > 0) {
    lines.push(formatRegisters(data.registers, 'Initial Registers'));
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// read_bytes / esil_get_memory / debug_read_memory
// ---------------------------------------------------------------------------

interface ReadBytesData {
  address: string;
  count?: number;
  size?: number;
  format: string;
  data: string;
}

export function formatReadBytes(data: ReadBytesData): string {
  const lines: string[] = [];
  const bytes = data.count ?? data.size ?? 0;
  lines.push(`## Memory @ \`${data.address}\` (${bytes} bytes, format: ${data.format})\n`);

  if (data.format === 'hexdump') {
    lines.push('```');
    lines.push(data.data);
    lines.push('```');
  } else if (data.format === 'string') {
    lines.push('```');
    lines.push(data.data);
    lines.push('```');
  } else {
    // Raw hex
    lines.push(`\`${data.data}\``);
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// get_entropy
// ---------------------------------------------------------------------------

interface EntropyData {
  entry_count: number;
  statistics: {
    average: number;
    min: number;
    max: number;
    high_entropy_detected: boolean;
  };
  entries: readonly { address: string; entropy: number }[];
}

export function formatEntropy(data: EntropyData): string {
  const lines: string[] = [];
  lines.push('## Entropy Analysis\n');

  const s = data.statistics;
  lines.push('### Statistics\n');
  lines.push('| Metric | Value |');
  lines.push('|--------|------:|');
  lines.push(`| Entries | ${data.entry_count} |`);
  lines.push(`| Average | ${s.average.toFixed(3)} |`);
  lines.push(`| Min | ${s.min.toFixed(3)} |`);
  lines.push(`| Max | ${s.max.toFixed(3)} |`);
  lines.push(`| High entropy | ${s.high_entropy_detected ? '**YES** (> 6.5)' : 'no'} |`);
  lines.push('');

  if (data.entries.length > 0) {
    lines.push('### Entropy Map\n');
    lines.push('| Address | Entropy | Bar |');
    lines.push('|---------|--------:|-----|');

    for (const entry of data.entries) {
      const barLen = Math.round((entry.entropy / 8.0) * 20);
      const bar = '\u2588'.repeat(barLen) + '\u2591'.repeat(20 - barLen);
      lines.push(`| \`${entry.address}\` | ${entry.entropy.toFixed(3)} | \`${bar}\` |`);
    }
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// search_bytes / search_string
// ---------------------------------------------------------------------------

interface SearchHit {
  address: string;
  offset_in_file?: number;
  data?: string;
  string?: string;
}

export function formatSearchResults(
  page: PaginatedResult<SearchHit>,
  searchType: string,
): string {
  const lines: string[] = [];
  lines.push(`## Search Results (${searchType})\n`);
  lines.push(paginationLine(page.total, page.offset, page.limit));
  lines.push('');
  lines.push('| # | Address | Data |');
  lines.push('|--:|---------|------|');

  for (let i = 0; i < page.results.length; i++) {
    const hit = page.results[i]!;
    const content = hit.data ?? hit.string ?? '';
    lines.push(`| ${page.offset + i + 1} | \`${hit.address}\` | \`${truncate(esc(content), 60)}\` |`);
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// search_rop_gadgets
// ---------------------------------------------------------------------------

interface RopGadget {
  address: string;
  instructions: string;
}

export function formatRopGadgets(page: PaginatedResult<RopGadget>): string {
  const lines: string[] = [];
  lines.push('## ROP Gadgets\n');
  lines.push(paginationLine(page.total, page.offset, page.limit));
  lines.push('');
  lines.push('| Address | Gadget |');
  lines.push('|---------|--------|');

  for (const g of page.results) {
    lines.push(`| \`${g.address}\` | \`${esc(g.instructions)}\` |`);
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// shellcode_analyze
// ---------------------------------------------------------------------------

interface ShellcodeData {
  architecture: string;
  bits: number;
  entry_point: string;
  instruction_count: number;
  instructions: readonly {
    address: string;
    opcode: string;
    disasm: string;
    bytes: string;
    type: string;
    size: number;
  }[];
  strings: readonly {
    address: string;
    value: string;
    size: number;
    type: string;
  }[];
}

export function formatShellcode(data: ShellcodeData): string {
  const lines: string[] = [];
  lines.push('## Shellcode Analysis\n');
  lines.push('| Property | Value |');
  lines.push('|----------|-------|');
  lines.push(`| Architecture | \`${data.architecture}\` |`);
  lines.push(`| Bits | ${data.bits} |`);
  lines.push(`| Entry Point | \`${data.entry_point}\` |`);
  lines.push(`| Instructions | ${data.instruction_count} |`);
  lines.push('');

  if (data.instructions.length > 0) {
    lines.push('### Disassembly\n');
    lines.push('```asm');
    for (const inst of data.instructions) {
      const bytes = inst.bytes.padEnd(20);
      lines.push(`${inst.address}  ${bytes}  ${inst.disasm ?? inst.opcode}`);
    }
    lines.push('```');
    lines.push('');
  }

  if (data.strings.length > 0) {
    lines.push('### Embedded Strings\n');
    lines.push('| Address | Type | String |');
    lines.push('|---------|------|--------|');
    for (const s of data.strings) {
      lines.push(`| \`${s.address}\` | ${s.type} | \`${truncate(esc(s.value), 60)}\` |`);
    }
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// disassemble_bytes
// ---------------------------------------------------------------------------

interface DisassembleBytesData {
  architecture: string;
  bits: number;
  base_offset: string;
  instruction_count: number;
  instructions: readonly {
    address: string;
    opcode: string;
    disasm: string;
    bytes: string;
    size: number;
  }[];
}

export function formatDisassembleBytes(data: DisassembleBytesData): string {
  const lines: string[] = [];
  lines.push(`## Raw Byte Disassembly (\`${data.architecture}\` ${data.bits}-bit)\n`);
  lines.push('```asm');
  for (const inst of data.instructions) {
    const bytes = inst.bytes.padEnd(20);
    lines.push(`${inst.address}  ${bytes}  ${inst.disasm ?? inst.opcode}`);
  }
  lines.push('```');
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// get_callgraph
// ---------------------------------------------------------------------------

interface CallgraphData {
  format: string;
  function: string;
  graph: unknown;
  note?: string;
}

export function formatCallgraph(data: CallgraphData): string {
  const lines: string[] = [];
  lines.push(`## Call Graph: \`${data.function}\`\n`);
  if (data.note) {
    lines.push(`> ${data.note}\n`);
  }

  if (data.format === 'dot') {
    lines.push('```dot');
    lines.push(String(data.graph));
    lines.push('```');
  } else if (data.format === 'mermaid') {
    lines.push('```mermaid');
    lines.push(String(data.graph));
    lines.push('```');
  } else {
    lines.push('```json');
    lines.push(JSON.stringify(data.graph, null, 2));
    lines.push('```');
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// get_control_flow_graph
// ---------------------------------------------------------------------------

interface CfgBlock {
  address: string;
  size: number;
  jump: string | null;
  fail: string | null;
  instructions: readonly {
    address: string;
    opcode: string;
    disasm: string;
    bytes: string;
    type: string;
    size: number;
  }[];
}

interface CfgData {
  function_name: string;
  function_address: string;
  block_count: number;
  blocks: readonly CfgBlock[];
}

export function formatControlFlowGraph(data: CfgData): string {
  const lines: string[] = [];
  lines.push(`## CFG: \`${data.function_name}\` @ \`${data.function_address}\`\n`);
  lines.push(`**${data.block_count}** basic blocks\n`);

  for (const block of data.blocks) {
    const targets: string[] = [];
    if (block.jump) targets.push(`jump \u2192 \`${block.jump}\``);
    if (block.fail) targets.push(`fail \u2192 \`${block.fail}\``);
    const targetStr = targets.length > 0 ? `  (${targets.join(', ')})` : '';

    lines.push(`### Block \`${block.address}\` (${block.size} bytes)${targetStr}\n`);

    if (block.instructions.length > 0) {
      lines.push('```asm');
      for (const inst of block.instructions) {
        const bytes = inst.bytes.padEnd(20);
        lines.push(`${inst.address}  ${bytes}  ${inst.disasm ?? inst.opcode}`);
      }
      lines.push('```');
      lines.push('');
    }
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// get_function_info
// ---------------------------------------------------------------------------

interface FunctionInfoData {
  offset: number;
  name: string;
  size: number;
  realsz: number;
  noreturn: boolean;
  stackframe: number;
  calltype: string;
  cost: number;
  cc: number;
  bits: number;
  type: string;
  nbbs: number;
  edges: number;
  ebbs: number;
  signature: string;
  minbound: number;
  maxbound: number;
  nlocals: number;
  nargs: number;
  indegree: number;
  outdegree: number;
  callrefs?: readonly { addr: number; type: string; at: number }[];
  datarefs?: readonly number[];
  codexrefs?: readonly { addr: number; type: string; at: number }[];
  dataxrefs?: readonly number[];
  bpvars?: readonly { name: string; kind: string; type: string; ref: { base: string; offset: number } }[];
  spvars?: readonly { name: string; kind: string; type: string; ref: { base: string; offset: number } }[];
  regvars?: readonly { name: string; kind: string; type: string; ref: string }[];
}

export function formatFunctionInfo(info: FunctionInfoData): string {
  const lines: string[] = [];
  lines.push(`## Function: \`${info.name}\` @ \`${hex(info.offset)}\`\n`);

  if (info.signature) {
    lines.push(`**Signature:** \`${info.signature}\`\n`);
  }

  lines.push('### Metadata\n');
  lines.push('| Property | Value |');
  lines.push('|----------|-------|');
  lines.push(`| Address range | \`${hex(info.minbound)}\` \u2013 \`${hex(info.maxbound)}\` |`);
  lines.push(`| Size | ${info.size} bytes (real: ${info.realsz}) |`);
  lines.push(`| Type | ${info.type} |`);
  lines.push(`| Call convention | ${info.calltype} |`);
  lines.push(`| Bits | ${info.bits} |`);
  lines.push(`| No return | ${info.noreturn ? 'yes' : 'no'} |`);
  lines.push('');

  lines.push('### Complexity\n');
  lines.push('| Metric | Value |');
  lines.push('|--------|------:|');
  lines.push(`| Cyclomatic complexity | ${info.cc} |`);
  lines.push(`| Basic blocks | ${info.nbbs} |`);
  lines.push(`| Edges | ${info.edges} |`);
  lines.push(`| Exit blocks | ${info.ebbs} |`);
  lines.push(`| Cost | ${info.cost} |`);
  lines.push(`| In-degree | ${info.indegree} |`);
  lines.push(`| Out-degree | ${info.outdegree} |`);
  lines.push('');

  lines.push('### Variables\n');
  lines.push('| Metric | Count |');
  lines.push('|--------|------:|');
  lines.push(`| Arguments | ${info.nargs} |`);
  lines.push(`| Locals | ${info.nlocals} |`);
  lines.push(`| Stack frame | ${info.stackframe} bytes |`);

  // Stack/register variables detail
  const allVars = [
    ...(info.bpvars ?? []).map((v) => ({ ...v, storage: 'bp' })),
    ...(info.spvars ?? []).map((v) => ({ ...v, storage: 'sp' })),
    ...(info.regvars ?? []).map((v) => ({ ...v, storage: 'reg' })),
  ];

  if (allVars.length > 0) {
    lines.push('');
    lines.push('| Name | Kind | Type | Storage |');
    lines.push('|------|------|------|---------|');
    for (const v of allVars) {
      lines.push(`| \`${v.name}\` | ${v.kind} | \`${v.type}\` | ${v.storage} |`);
    }
  }

  // Call references
  if (info.callrefs && info.callrefs.length > 0) {
    lines.push('');
    lines.push('### Calls Out\n');
    lines.push('| Address | Target | Type |');
    lines.push('|---------|--------|------|');
    for (const ref of info.callrefs) {
      lines.push(`| \`${hex(ref.at)}\` | \`${hex(ref.addr)}\` | ${ref.type} |`);
    }
  }

  if (info.codexrefs && info.codexrefs.length > 0) {
    lines.push('');
    lines.push('### Called From\n');
    lines.push('| Address | Source | Type |');
    lines.push('|---------|--------|------|');
    for (const ref of info.codexrefs) {
      lines.push(`| \`${hex(ref.at)}\` | \`${hex(ref.addr)}\` | ${ref.type} |`);
    }
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// list_variables
// ---------------------------------------------------------------------------

interface VariableEntry {
  name: string;
  kind: string;
  type: string;
  ref: unknown;
}

interface VariablesData {
  bp: readonly VariableEntry[];
  sp: readonly VariableEntry[];
  reg: readonly VariableEntry[];
}

export function formatVariables(data: VariablesData): string {
  const lines: string[] = [];
  lines.push('## Function Variables\n');

  const total = data.bp.length + data.sp.length + data.reg.length;
  if (total === 0) {
    lines.push('*No variables found*');
    return lines.join('\n');
  }

  const formatGroup = (title: string, vars: readonly VariableEntry[]): void => {
    if (vars.length === 0) return;
    lines.push(`### ${title} (${vars.length})\n`);
    lines.push('| Name | Kind | Type |');
    lines.push('|------|------|------|');
    for (const v of vars) {
      lines.push(`| \`${v.name}\` | ${v.kind} | \`${v.type}\` |`);
    }
    lines.push('');
  };

  formatGroup('Base Pointer Variables', data.bp);
  formatGroup('Stack Pointer Variables', data.sp);
  formatGroup('Register Variables', data.reg);

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// rename_function
// ---------------------------------------------------------------------------

interface RenameFunctionData {
  address: string;
  old_name: string;
  new_name: string;
  success: boolean;
}

export function formatRenameFunction(data: RenameFunctionData): string {
  return `Renamed function at \`${data.address}\`: \`${data.old_name}\` \u2192 \`${data.new_name}\``;
}

// ---------------------------------------------------------------------------
// add_comment
// ---------------------------------------------------------------------------

interface AddCommentData {
  address: string;
  comment: string;
  success: boolean;
}

export function formatAddComment(data: AddCommentData): string {
  return `Comment added at \`${data.address}\`: "${data.comment}"`;
}

// ---------------------------------------------------------------------------
// r2_command
// ---------------------------------------------------------------------------

interface R2CommandData {
  command: string;
  output: string;
}

export function formatR2Command(data: R2CommandData): string {
  const lines: string[] = [];
  lines.push(`## r2 command: \`${data.command}\`\n`);
  lines.push('```');
  lines.push(data.output);
  lines.push('```');
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// find_crypto_constants
// ---------------------------------------------------------------------------

interface CryptoData {
  results: readonly { offset: number; algorithm: string; bits: number }[];
  total: number;
}

export function formatCryptoConstants(data: CryptoData): string {
  const lines: string[] = [];
  lines.push('## Cryptographic Constants\n');
  lines.push(`**${data.total}** constant(s) detected\n`);

  if (data.results.length === 0) {
    lines.push('*No cryptographic constants found*');
    return lines.join('\n');
  }

  lines.push('| Address | Algorithm | Bits |');
  lines.push('|---------|-----------|-----:|');
  for (const c of data.results) {
    lines.push(`| \`${hex(c.offset)}\` | **${esc(c.algorithm)}** | ${c.bits} |`);
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// write_bytes
// ---------------------------------------------------------------------------

interface WriteBytesData {
  address: string;
  operation: string;
  input: string | undefined;
  before: string;
  after: string;
  success: boolean;
}

export function formatWriteBytes(data: WriteBytesData): string {
  const lines: string[] = [];
  lines.push(`## Patch @ \`${data.address}\` (${data.operation})\n`);
  if (data.input) lines.push(`**Input:** \`${data.input}\`\n`);
  lines.push('### Before\n');
  lines.push('```');
  lines.push(data.before);
  lines.push('```');
  lines.push('');
  lines.push('### After\n');
  lines.push('```');
  lines.push(data.after);
  lines.push('```');
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Debug tools
// ---------------------------------------------------------------------------

interface DebugLaunchData {
  session_id: string;
  target: string;
  pid: number | undefined;
  debug_info?: unknown;
  registers: Record<string, number>;
  message: string;
}

export function formatDebugLaunch(data: DebugLaunchData): string {
  const lines: string[] = [];
  lines.push('## Debug Session Started\n');
  lines.push('| Property | Value |');
  lines.push('|----------|-------|');
  lines.push(`| Session ID | \`${data.session_id}\` |`);
  lines.push(`| Target | \`${esc(data.target)}\` |`);
  lines.push(`| PID | ${data.pid ?? 'N/A'} |`);
  lines.push('');

  if (data.registers && Object.keys(data.registers).length > 0) {
    lines.push(formatRegisters(data.registers, 'Initial Registers'));
  }

  return lines.join('\n');
}

interface DebugStepData {
  steps_executed: number;
  step_type: string;
  steps: readonly StepData[];
  final_registers: Record<string, number>;
}

export function formatDebugSteps(data: DebugStepData): string {
  const lines: string[] = [];
  lines.push(`## Debug Step (${data.step_type})\n`);

  const result = formatSteps(data.steps, {
    title: `${data.steps_executed} Step(s)`,
    showRegisters: data.steps_executed <= 5,
  });
  lines.push(result);

  if (data.steps_executed > 5 && data.final_registers) {
    lines.push('');
    lines.push(formatRegisters(data.final_registers, 'Final Registers'));
  }

  return lines.join('\n');
}

export function formatDebugMaps(maps: readonly R2MemoryMap[]): string {
  const lines: string[] = [];
  lines.push(`## Memory Maps (${maps.length})\n`);

  if (maps.length === 0) {
    lines.push('*No memory maps available*');
    return lines.join('\n');
  }

  lines.push('| Start | End | Size | Perm | Name |');
  lines.push('|-------|-----|-----:|------|------|');

  for (const m of maps) {
    lines.push(
      `| \`${hex(m.addr)}\` | \`${hex(m.addr_end)}\` | ${m.size.toLocaleString()} | \`${m.perm}\` | ${esc(m.name)} |`,
    );
  }

  return lines.join('\n');
}

export function formatDebugBacktrace(frames: readonly R2BacktraceFrame[]): string {
  const lines: string[] = [];
  lines.push(`## Backtrace (${frames.length} frames)\n`);

  if (frames.length === 0) {
    lines.push('*No backtrace available*');
    return lines.join('\n');
  }

  lines.push('| # | PC | SP | Frame Size | Name |');
  lines.push('|--:|----|----|----------:|------|');

  for (const f of frames) {
    lines.push(
      `| ${f.idx} | \`${hex(f.pc)}\` | \`${hex(f.sp)}\` | ${f.frame_size} | \`${esc(f.name ?? f.desc ?? '')}\` |`,
    );
  }

  return lines.join('\n');
}

export function formatDebugBreakpoints(breakpoints: readonly R2Breakpoint[]): string {
  const lines: string[] = [];
  lines.push(`## Breakpoints (${breakpoints.length})\n`);

  if (breakpoints.length === 0) {
    lines.push('*No breakpoints set*');
    return lines.join('\n');
  }

  lines.push('| Address | Size | HW | Enabled | Name |');
  lines.push('|---------|-----:|----|---------|------|');

  for (const bp of breakpoints) {
    lines.push(
      `| \`${hex(bp.addr)}\` | ${bp.size} | ${bp.hw ? 'yes' : 'no'} | ${bp.enabled ? 'yes' : 'no'} | ${esc(bp.name ?? '')} |`,
    );
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// list_resources
// ---------------------------------------------------------------------------

interface ResourceEntry {
  index: number;
  type: string;
  name: string;
  language: string;
  vaddr: number;
  size: number;
}

export function formatResources(page: PaginatedResult<ResourceEntry>): string {
  const lines: string[] = [];
  lines.push('## PE Resources\n');
  lines.push(paginationLine(page.total, page.offset, page.limit));
  lines.push('');
  lines.push('| Address | Type | Name | Language | Size |');
  lines.push('|---------|------|------|----------|-----:|');

  for (const r of page.results) {
    lines.push(
      `| \`${hex(r.vaddr)}\` | ${esc(r.type)} | ${esc(r.name)} | ${esc(r.language)} | ${r.size} |`,
    );
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// triage_binary
// ---------------------------------------------------------------------------

interface TriageData {
  fileInfo: {
    core?: { file?: string; format?: string; size?: number; type?: string };
    bin?: {
      arch?: string;
      bits?: number;
      os?: string;
      machine?: string;
      endian?: string;
      stripped?: boolean;
    };
  };
  sections: readonly {
    name: string;
    size: number;
    vsize: number;
    vaddr: number;
    paddr: number;
    perm: string;
    type: string;
  }[];
  imports: readonly { name: string; lib: string; plt: number; type: string }[];
  exports: readonly { name: string; vaddr: number; size: number; type: string }[];
  strings: readonly {
    vaddr: number;
    string: string;
    length: number;
    section: string;
    type: string;
  }[];
  functions: readonly {
    offset: number;
    name: string;
    size: number;
    nbbs: number;
    nargs: number;
    cc?: number;
  }[];
  mainFunctions: readonly { offset: number; name: string; size: number }[];
  entryPoints: readonly { vaddr: number; type: string }[];
  security: { relro: string; canary: boolean; nx: boolean; pic: boolean };
  totalFunctions: number;
  totalStrings: number;
}

export function formatTriage(data: TriageData): string {
  const lines: string[] = [];
  lines.push('## Binary Triage\n');

  // File Info
  const c = data.fileInfo.core;
  const b = data.fileInfo.bin;

  lines.push('### File Info\n');
  lines.push('| Property | Value |');
  lines.push('|----------|-------|');
  if (c?.file) lines.push(`| File | \`${esc(c.file)}\` |`);
  if (c?.format) lines.push(`| Format | ${c.format} |`);
  if (c?.type) lines.push(`| Type | ${c.type} |`);
  if (c?.size !== undefined) lines.push(`| Size | ${c.size.toLocaleString()} bytes |`);
  if (b?.arch) lines.push(`| Arch | \`${b.arch}\` |`);
  if (b?.bits !== undefined) lines.push(`| Bits | ${b.bits} |`);
  if (b?.os) lines.push(`| OS | ${b.os} |`);
  if (b?.endian) lines.push(`| Endian | ${b.endian} |`);
  if (b?.stripped !== undefined) lines.push(`| Stripped | ${b.stripped ? 'yes' : 'no'} |`);
  lines.push('');

  // Security features
  const sec = data.security;
  lines.push('### Security Features\n');
  lines.push('| Feature | Status |');
  lines.push('|---------|--------|');
  lines.push(`| RELRO | ${sec.relro} |`);
  lines.push(`| Stack Canary | ${sec.canary ? '\u2714 enabled' : '\u2716 disabled'} |`);
  lines.push(`| NX | ${sec.nx ? '\u2714 enabled' : '\u2716 disabled'} |`);
  lines.push(`| PIC | ${sec.pic ? '\u2714 enabled' : '\u2716 disabled'} |`);
  lines.push('');

  // Entry Points
  if (data.entryPoints.length > 0) {
    lines.push('### Entry Points\n');
    lines.push('| Address | Type |');
    lines.push('|---------|------|');
    for (const ep of data.entryPoints) {
      lines.push(`| \`${hex(ep.vaddr)}\` | ${ep.type} |`);
    }
    lines.push('');
  }

  // Main/Entry Functions
  if (data.mainFunctions.length > 0) {
    lines.push('### Main/Entry Functions\n');
    lines.push('| Address | Name | Size |');
    lines.push('|---------|------|-----:|');
    for (const fn of data.mainFunctions) {
      lines.push(`| \`${hex(fn.offset)}\` | \`${esc(fn.name)}\` | ${fn.size} |`);
    }
    lines.push('');
  }

  // Top Functions by Size
  if (data.functions.length > 0) {
    lines.push(`### Top Functions by Size (${data.totalFunctions} total)\n`);
    lines.push('| Address | Name | Size | BBs | Args | CC |');
    lines.push('|---------|------|-----:|----:|-----:|---:|');
    for (const fn of data.functions) {
      lines.push(
        `| \`${hex(fn.offset)}\` | \`${esc(fn.name)}\` | ${fn.size} | ${fn.nbbs} | ${fn.nargs} | ${fn.cc ?? ''} |`,
      );
    }
    lines.push('');
  }

  // Key Imports
  if (data.imports.length > 0) {
    const shown = data.imports.slice(0, 30);
    lines.push(`### Key Imports (${shown.length} of ${data.imports.length})\n`);
    lines.push('| PLT Address | Name | Type | Library |');
    lines.push('|-------------|------|------|---------|');
    for (const imp of shown) {
      lines.push(
        `| \`${hex(imp.plt)}\` | \`${esc(imp.name)}\` | ${imp.type} | ${esc(imp.lib)} |`,
      );
    }
    lines.push('');
  }

  // Interesting Strings
  if (data.strings.length > 0) {
    lines.push(`### Interesting Strings (${data.totalStrings} total)\n`);
    lines.push('| Address | Section | Len | String |');
    lines.push('|---------|---------|----:|--------|');
    for (const s of data.strings) {
      lines.push(
        `| \`${hex(s.vaddr)}\` | ${esc(s.section)} | ${s.length} | \`${truncate(esc(s.string), 80)}\` |`,
      );
    }
    lines.push('');
  }

  // Sections
  if (data.sections.length > 0) {
    lines.push('### Sections\n');
    lines.push('| Address | PAddr | Name | Size | VSize | Perm | Type |');
    lines.push('|---------|-------|------|-----:|------:|------|------|');
    for (const sec of data.sections) {
      lines.push(
        `| \`${hex(sec.vaddr)}\` | \`${hex(sec.paddr)}\` | \`${esc(sec.name)}\` | ${sec.size.toLocaleString()} | ${sec.vsize.toLocaleString()} | \`${sec.perm}\` | ${sec.type} |`,
      );
    }
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// analyze_function_deep
// ---------------------------------------------------------------------------

interface FunctionDeepData {
  info: {
    offset: number;
    name: string;
    size: number;
    cc: number;
    nbbs: number;
    edges: number;
    nargs: number;
    nlocals: number;
    stackframe: number;
    calltype: string;
    signature: string;
    type: string;
  } | null;
  disasm: {
    name: string;
    addr: number;
    ops: readonly { offset: number; disasm: string; opcode: string; bytes: string }[];
  } | null;
  decompiled: string;
  xrefsTo: readonly { from: number; to: number; type: string; fcn_name: string }[];
  xrefsFrom: readonly { from: number; to: number; type: string; refname: string }[];
  variables: readonly { name: string; kind: string; type: string }[];
  strings: readonly { address: string; value: string }[];
  callees: readonly { address: string; name: string }[];
  callers: readonly { address: string; name: string }[];
}

export function formatFunctionDeep(data: FunctionDeepData): string {
  const lines: string[] = [];
  const name = data.info?.name ?? 'unknown';
  const addr = data.info ? hex(data.info.offset) : '???';
  lines.push(`## Deep Analysis: \`${name}\` @ \`${addr}\`\n`);

  // Metadata
  if (data.info) {
    const i = data.info;
    lines.push('### Metadata\n');
    lines.push('| Property | Value |');
    lines.push('|----------|-------|');
    lines.push(`| Size | ${i.size} bytes |`);
    lines.push(`| Cyclomatic complexity | ${i.cc} |`);
    lines.push(`| Basic blocks | ${i.nbbs} |`);
    lines.push(`| Edges | ${i.edges} |`);
    lines.push(`| Arguments | ${i.nargs} |`);
    lines.push(`| Locals | ${i.nlocals} |`);
    lines.push(`| Stack frame | ${i.stackframe} bytes |`);
    lines.push(`| Call convention | ${i.calltype} |`);
    lines.push(`| Type | ${i.type} |`);
    lines.push('');

    if (i.signature) {
      lines.push(`**Signature:** \`${esc(i.signature)}\`\n`);
    }
  }

  // Decompiled code
  if (data.decompiled) {
    lines.push('### Decompiled Code\n');
    lines.push('```c');
    lines.push(data.decompiled);
    lines.push('```');
    lines.push('');
  }

  // Disassembly
  if (data.disasm && data.disasm.ops.length > 0) {
    lines.push('### Disassembly\n');
    lines.push('```asm');
    for (const op of data.disasm.ops) {
      const a = hex(op.offset);
      const bytes = op.bytes.padEnd(20);
      lines.push(`${a}  ${bytes}  ${op.disasm ?? op.opcode}`);
    }
    lines.push('```');
    lines.push('');
  }

  // Variables
  if (data.variables.length > 0) {
    lines.push('### Variables\n');
    lines.push('| Name | Kind | Type |');
    lines.push('|------|------|------|');
    for (const v of data.variables) {
      lines.push(`| \`${esc(v.name)}\` | ${v.kind} | \`${esc(v.type)}\` |`);
    }
    lines.push('');
  }

  // Strings Referenced
  if (data.strings.length > 0) {
    lines.push('### Strings Referenced\n');
    lines.push('| Address | String |');
    lines.push('|---------|--------|');
    for (const s of data.strings) {
      lines.push(`| \`${s.address}\` | \`${truncate(esc(s.value), 80)}\` |`);
    }
    lines.push('');
  }

  // Callees
  if (data.callees.length > 0) {
    lines.push('### Callees (functions called)\n');
    lines.push('| Address | Name |');
    lines.push('|---------|------|');
    for (const c of data.callees) {
      lines.push(`| \`${c.address}\` | \`${esc(c.name)}\` |`);
    }
    lines.push('');
  }

  // Callers
  if (data.callers.length > 0) {
    lines.push('### Callers (called by)\n');
    lines.push('| Address | Name |');
    lines.push('|---------|------|');
    for (const c of data.callers) {
      lines.push(`| \`${c.address}\` | \`${esc(c.name)}\` |`);
    }
    lines.push('');
  }

  // Xrefs summary
  if (data.xrefsTo.length > 0 || data.xrefsFrom.length > 0) {
    lines.push('### Cross-References\n');

    if (data.xrefsTo.length > 0) {
      lines.push(`**Xrefs to** (${data.xrefsTo.length}):\n`);
      lines.push('| From | To | Type | Function |');
      lines.push('|------|----|------|----------|');
      for (const x of data.xrefsTo) {
        lines.push(
          `| \`${hex(x.from)}\` | \`${hex(x.to)}\` | ${x.type} | \`${esc(x.fcn_name)}\` |`,
        );
      }
      lines.push('');
    }

    if (data.xrefsFrom.length > 0) {
      lines.push(`**Xrefs from** (${data.xrefsFrom.length}):\n`);
      lines.push('| From | To | Type | Target |');
      lines.push('|------|----|------|--------|');
      for (const x of data.xrefsFrom) {
        lines.push(
          `| \`${hex(x.from)}\` | \`${hex(x.to)}\` | ${x.type} | \`${esc(x.refname)}\` |`,
        );
      }
    }
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// find_constraints
// ---------------------------------------------------------------------------

interface ConstraintsData {
  functionName: string;
  functionAddress: string;
  constraints: readonly {
    address: string;
    instruction: string;
    type: 'comparison' | 'branch' | 'call' | 'string_ref';
    detail: string;
    jump_target?: string | undefined;
    fail_target?: string | undefined;
  }[];
  paths: readonly { address: string; type: 'success' | 'fail' | 'unknown'; evidence: string }[];
  calleeConstraints: readonly {
    callee: string;
    constraints: readonly {
      address: string;
      instruction: string;
      type: string;
      detail: string;
    }[];
  }[];
  stringRefs: readonly { address: string; value: string }[];
}

export function formatConstraints(data: ConstraintsData): string {
  const lines: string[] = [];
  lines.push(`## Constraint Analysis: \`${esc(data.functionName)}\`\n`);
  lines.push(`**Address:** \`${data.functionAddress}\`\n`);

  // Summary counts
  const comparisons = data.constraints.filter((c) => c.type === 'comparison');
  const branches = data.constraints.filter((c) => c.type === 'branch');
  const calls = data.constraints.filter((c) => c.type === 'call');
  const stringRefs = data.constraints.filter((c) => c.type === 'string_ref');

  lines.push('### Summary\n');
  lines.push('| Type | Count |');
  lines.push('|------|------:|');
  lines.push(`| Comparisons | ${comparisons.length} |`);
  lines.push(`| Branches | ${branches.length} |`);
  lines.push(`| Calls | ${calls.length} |`);
  lines.push(`| String refs | ${stringRefs.length} |`);
  lines.push('');

  // Success/Fail Paths
  if (data.paths.length > 0) {
    lines.push('### Success/Fail Paths\n');
    lines.push('| Address | Type | Evidence |');
    lines.push('|---------|------|----------|');
    for (const p of data.paths) {
      const marker =
        p.type === 'success'
          ? '**SUCCESS**'
          : p.type === 'fail'
            ? '**FAIL**'
            : 'unknown';
      lines.push(`| \`${p.address}\` | ${marker} | ${truncate(esc(p.evidence), 60)} |`);
    }
    lines.push('');
  }

  // String References
  if (data.stringRefs.length > 0) {
    lines.push('### String References\n');
    lines.push('| Address | String |');
    lines.push('|---------|--------|');
    for (const s of data.stringRefs) {
      lines.push(`| \`${s.address}\` | \`${truncate(esc(s.value), 80)}\` |`);
    }
    lines.push('');
  }

  // Constraints grouped by type
  const groups: [string, readonly ConstraintsData['constraints'][number][]][] = [
    ['Comparisons', comparisons],
    ['Branches', branches],
    ['Calls', calls],
    ['String References', stringRefs],
  ];

  for (const [groupName, items] of groups) {
    if (items.length === 0) continue;
    lines.push(`### ${groupName}\n`);
    lines.push('| Address | Instruction | Detail |');
    lines.push('|---------|-------------|--------|');
    for (const c of items) {
      let detail = truncate(esc(c.detail), 60);
      if (c.jump_target) detail += ` \u2192 \`${c.jump_target}\``;
      if (c.fail_target) detail += ` / fail \u2192 \`${c.fail_target}\``;
      lines.push(`| \`${c.address}\` | \`${esc(c.instruction)}\` | ${detail} |`);
    }
    lines.push('');
  }

  // Callee Constraints
  if (data.calleeConstraints.length > 0) {
    lines.push('### Callee Constraints\n');
    for (const cc of data.calleeConstraints) {
      lines.push(`#### \`${esc(cc.callee)}\`\n`);
      lines.push('| Address | Instruction | Type | Detail |');
      lines.push('|---------|-------------|------|--------|');
      for (const c of cc.constraints) {
        lines.push(
          `| \`${c.address}\` | \`${esc(c.instruction)}\` | ${c.type} | ${truncate(esc(c.detail), 60)} |`,
        );
      }
      lines.push('');
    }
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// trace_execution
// ---------------------------------------------------------------------------

interface ExecutionTraceData {
  start_address: string;
  total_steps: number;
  events: readonly {
    step: number;
    address: string;
    instruction: string;
    type:
      | 'comparison'
      | 'branch_taken'
      | 'branch_not_taken'
      | 'call'
      | 'memory_read'
      | 'memory_write'
      | 'syscall'
      | 'regular';
    detail: string;
    registers?: Record<string, number> | undefined;
  }[];
  final_registers: Record<string, number>;
  stopped_reason: string;
}

export function formatExecutionTrace(data: ExecutionTraceData): string {
  const lines: string[] = [];
  lines.push(`## Execution Trace\n`);
  lines.push(`**Start:** \`${data.start_address}\` | **Steps:** ${data.total_steps} | **Stopped:** ${esc(data.stopped_reason)}\n`);

  // Summary counts
  const cmpCount = data.events.filter((e) => e.type === 'comparison').length;
  const takenCount = data.events.filter((e) => e.type === 'branch_taken').length;
  const notTakenCount = data.events.filter((e) => e.type === 'branch_not_taken').length;
  const callCount = data.events.filter((e) => e.type === 'call').length;
  const sysCount = data.events.filter((e) => e.type === 'syscall').length;

  lines.push('### Summary\n');
  lines.push('| Event Type | Count |');
  lines.push('|------------|------:|');
  lines.push(`| Comparisons | ${cmpCount} |`);
  lines.push(`| Branches taken | ${takenCount} |`);
  lines.push(`| Branches not taken | ${notTakenCount} |`);
  lines.push(`| Calls | ${callCount} |`);
  if (sysCount > 0) lines.push(`| Syscalls | ${sysCount} |`);
  lines.push('');

  // Event log
  if (data.events.length > 0) {
    lines.push('### Event Log\n');
    lines.push('| Step | Address | Type | Instruction | Detail |');
    lines.push('|-----:|---------|------|-------------|--------|');

    const typeMarker = (type: string): string => {
      switch (type) {
        case 'comparison': return 'CMP';
        case 'branch_taken': return '\u2192';
        case 'branch_not_taken': return '\u2717';
        case 'call': return 'CALL';
        case 'syscall': return 'SYS';
        case 'memory_read': return 'RD';
        case 'memory_write': return 'WR';
        default: return '';
      }
    };

    for (const evt of data.events) {
      const marker = typeMarker(evt.type);
      lines.push(
        `| ${evt.step} | \`${evt.address}\` | **${marker}** | \`${esc(evt.instruction)}\` | ${truncate(esc(evt.detail), 50)} |`,
      );

      // Show compact registers if present
      if (evt.registers && Object.keys(evt.registers).length > 0) {
        const regPairs = Object.entries(evt.registers)
          .filter(([n]) => {
            const cls = classifyRegister(n);
            return cls === 'gp' || cls === 'ip';
          })
          .map(([n, v]) => `${n}=\`0x${v.toString(16)}\``)
          .join(' ');
        if (regPairs) {
          lines.push(`| | | | ${regPairs} | |`);
        }
      }
    }
    lines.push('');
  }

  // Final registers
  if (data.final_registers && Object.keys(data.final_registers).length > 0) {
    lines.push(formatRegisters(data.final_registers, 'Final Registers'));
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// list_relocations
// ---------------------------------------------------------------------------

export function formatRelocationList(page: PaginatedResult<R2Relocation>): string {
  const lines: string[] = [];
  lines.push('## Relocations\n');
  lines.push(paginationLine(page.total, page.offset, page.limit));
  lines.push('');
  lines.push('| VAddr | PAddr | Type | Name | Demangled | iFUNC |');
  lines.push('|-------|-------|------|------|-----------|-------|');

  for (const rel of page.results) {
    const vaddr = hex(rel.vaddr);
    const paddr = hex(rel.paddr);
    const name = esc(rel.name ?? '');
    const demname = esc(rel.demname ?? '');
    const ifunc = rel.is_ifunc ? 'yes' : 'no';
    lines.push(
      `| \`${vaddr}\` | \`${paddr}\` | ${esc(rel.type ?? '')} | \`${name}\` | ${truncate(demname, 60)} | ${ifunc} |`,
    );
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// list_classes
// ---------------------------------------------------------------------------

export function formatClassList(page: PaginatedResult<R2Class>): string {
  const lines: string[] = [];
  lines.push('## Classes\n');
  lines.push(paginationLine(page.total, page.offset, page.limit));
  lines.push('');

  for (const cls of page.results) {
    const addr = hex(cls.addr);
    lines.push(`### \`${esc(cls.classname)}\` @ \`${addr}\`\n`);

    const methods = cls.methods ?? [];
    if (methods.length > 0) {
      lines.push('**Methods:**\n');
      lines.push('| Address | Name | Type |');
      lines.push('|---------|------|------|');
      for (const m of methods) {
        lines.push(`| \`${hex(m.addr)}\` | \`${esc(m.name)}\` | ${esc(m.type ?? '')} |`);
      }
      lines.push('');
    }

    const fields = cls.fields ?? [];
    if (fields.length > 0) {
      lines.push('**Fields:**\n');
      lines.push('| Address | Name | Type |');
      lines.push('|---------|------|------|');
      for (const f of fields) {
        lines.push(`| \`${hex(f.addr)}\` | \`${esc(f.name)}\` | ${esc(f.type ?? '')} |`);
      }
      lines.push('');
    }
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// analyze_types
// ---------------------------------------------------------------------------

export function formatTypeList(page: PaginatedResult<R2Type>): string {
  const lines: string[] = [];
  lines.push('## Type Definitions\n');
  lines.push(paginationLine(page.total, page.offset, page.limit));
  lines.push('');

  if (page.results.length === 0) {
    lines.push('No types found.');
    return lines.join('\n');
  }

  lines.push('| Name | Kind | Type | Size |');
  lines.push('|------|------|------|------|');

  for (const t of page.results) {
    const kind = t.kind ?? t.type ?? '';
    const size = t.size !== undefined ? `${t.size}` : '';
    lines.push(`| \`${esc(t.name)}\` | ${esc(kind)} | ${esc(t.type ?? '')} | ${size} |`);
  }
  lines.push('');

  // Show members for structs that have them
  for (const t of page.results) {
    const members = t.members ?? [];
    if (members.length > 0) {
      lines.push(`### \`${esc(t.name)}\` members\n`);
      lines.push('| Offset | Name | Type | Size |');
      lines.push('|--------|------|------|------|');
      for (const m of members) {
        lines.push(`| ${m.offset} | \`${esc(m.name)}\` | \`${esc(m.type)}\` | ${m.size} |`);
      }
      lines.push('');
    }

    const values = t.values ?? [];
    if (values.length > 0) {
      lines.push(`### \`${esc(t.name)}\` values\n`);
      lines.push('| Name | Value |');
      lines.push('|------|-------|');
      for (const v of values) {
        lines.push(`| \`${esc(v.name)}\` | ${v.value} (0x${v.value.toString(16)}) |`);
      }
      lines.push('');
    }
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// binary_headers
// ---------------------------------------------------------------------------

export function formatBinaryHeaders(headers: readonly R2Header[]): string {
  const lines: string[] = [];
  lines.push('## Binary Headers\n');

  if (headers.length === 0) {
    lines.push('No headers found.');
    return lines.join('\n');
  }

  lines.push(`Found **${headers.length}** header fields.\n`);
  lines.push('| Field | Value |');
  lines.push('|-------|-------|');

  for (const h of headers) {
    const val = typeof h.value === 'string' ? esc(h.value) : String(h.value);
    lines.push(`| \`${esc(h.name)}\` | ${val} |`);
  }
  lines.push('');

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// hash_binary
// ---------------------------------------------------------------------------

interface HashResultData {
  algorithm: string;
  hash: string;
  mode: string;
  binary_path: string;
}

export function formatHashResult(data: HashResultData): string {
  const lines: string[] = [];
  lines.push('## Hash Result\n');
  lines.push('| Property | Value |');
  lines.push('|----------|-------|');
  lines.push(`| File | \`${esc(data.binary_path)}\` |`);
  lines.push(`| Algorithm | **${data.algorithm.toUpperCase()}** |`);
  lines.push(`| Scope | ${data.mode} |`);
  lines.push(`| Hash | \`${esc(data.hash)}\` |`);
  lines.push('');

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Debug session formatters (shared across debug-*.ts tools)
// ---------------------------------------------------------------------------

/** Format debug session info for launch/attach responses. */
export function formatDebugSession(entry: {
  sessionId: string;
  target: string;
  pid?: number | undefined;
}): string {
  const lines: string[] = [];
  lines.push('## Debug Session\n');
  lines.push('| Property | Value |');
  lines.push('|----------|-------|');
  lines.push(`| Session ID | \`${entry.sessionId}\` |`);
  lines.push(`| Target | \`${esc(entry.target)}\` |`);
  lines.push(`| PID | ${entry.pid ?? 'N/A'} |`);
  return lines.join('\n');
}

/** Format debug detach confirmation. */
export function formatDebugDetach(sessionId: string): string {
  return `Detached from session \`${sessionId}\`. Process continues running.`;
}

/** Format debug registers as a key-value table. */
export function formatDebugRegisters(
  registers: Record<string, number>,
  title?: string | undefined,
): string {
  return formatRegisters(registers, title ?? 'Debug Registers');
}

/** Format debug continue result. */
export function formatDebugContinue(result: {
  status: string;
  currentInstruction?: string | undefined;
  registers?: Record<string, number> | undefined;
}): string {
  const lines: string[] = [];
  lines.push(`## Continue — status: **${result.status}**\n`);
  if (result.currentInstruction) {
    lines.push('```asm');
    lines.push(result.currentInstruction);
    lines.push('```\n');
  }
  if (result.registers) lines.push(formatRegisters(result.registers));
  return lines.join('\n');
}

/** Format debug thread list. */
export function formatDebugThreadList(
  threads: readonly { pid: number; tid?: number | undefined; status: string; path?: string | undefined }[],
): string {
  const lines: string[] = [];
  lines.push(`## Threads (${threads.length})\n`);
  if (threads.length === 0) {
    lines.push('*No threads available*');
    return lines.join('\n');
  }
  lines.push('| PID | Status | Path |');
  lines.push('|----:|--------|------|');
  for (const t of threads) {
    lines.push(`| ${t.pid} | ${t.status} | ${esc(t.path ?? '')} |`);
  }
  return lines.join('\n');
}

/** Format debug session list. */
export function formatDebugSessionList(
  entries: readonly {
    sessionId: string;
    target: string;
    pid?: number | undefined;
    attachedAt: number;
    lastUsed: number;
  }[],
): string {
  const lines: string[] = [];
  lines.push(`## Debug Sessions (${entries.length})\n`);
  if (entries.length === 0) {
    lines.push('*No active debug sessions*');
    return lines.join('\n');
  }
  lines.push('| Session ID | Target | PID | Idle |');
  lines.push('|------------|--------|----:|-----:|');
  for (const s of entries) {
    const idle = Math.round((Date.now() - s.lastUsed) / 1000);
    lines.push(`| \`${s.sessionId}\` | \`${esc(s.target)}\` | ${s.pid ?? 'N/A'} | ${idle}s |`);
  }
  return lines.join('\n');
}

/** Format debug process info. */
export function formatDebugProcessInfo(info: {
  sessionId: string;
  target: string;
  pid: number | undefined;
  attachedAt: number;
  debugInfo?: { status?: string | undefined; exe?: string | undefined; cmdline?: string | undefined } | undefined;
}): string {
  const lines: string[] = [];
  lines.push('## Debug Session Info\n');
  lines.push('| Property | Value |');
  lines.push('|----------|-------|');
  lines.push(`| Session ID | \`${info.sessionId}\` |`);
  lines.push(`| Target | \`${esc(info.target)}\` |`);
  lines.push(`| PID | ${info.pid ?? 'N/A'} |`);
  lines.push(`| Attached | ${new Date(info.attachedAt).toISOString()} |`);
  if (info.debugInfo) {
    if (info.debugInfo.status) lines.push(`| Status | ${info.debugInfo.status} |`);
    if (info.debugInfo.exe) lines.push(`| Executable | \`${esc(info.debugInfo.exe)}\` |`);
    if (info.debugInfo.cmdline) lines.push(`| Command Line | \`${esc(info.debugInfo.cmdline)}\` |`);
  }
  return lines.join('\n');
}
