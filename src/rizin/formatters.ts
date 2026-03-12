// ---------------------------------------------------------------------------
// RzIL output formatters — convert raw tool data into readable markdown
// ---------------------------------------------------------------------------

/** Format a number as padded hex string: `0x00401000` */
function hex(n: number, pad = 8): string {
  return `0x${n.toString(16).padStart(pad, '0')}`;
}

// ---------------------------------------------------------------------------
// rzil_init
// ---------------------------------------------------------------------------

interface RzilInitData {
  initialized: boolean;
  entry_point: string;
  registers: Record<string, number>;
}

export function formatRzilInit(data: RzilInitData): string {
  const lines: string[] = [];
  lines.push('## RzIL VM Initialized\n');
  lines.push(`| Property | Value |`);
  lines.push(`|----------|-------|`);
  lines.push(`| Status | ${data.initialized ? 'Ready' : 'Failed'} |`);
  lines.push(`| Entry Point | \`${data.entry_point}\` |`);

  if (data.registers && Object.keys(data.registers).length > 0) {
    lines.push('\n### Initial Registers\n');
    lines.push('| Register | Value |');
    lines.push('|----------|-------|');
    for (const [name, value] of Object.entries(data.registers)) {
      lines.push(`| \`${name}\` | \`${hex(value)}\` |`);
    }
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// rzil_get_registers
// ---------------------------------------------------------------------------

export function formatRzilRegisters(
  regs: Record<string, number>,
  title = 'RzIL Registers',
): string {
  const lines: string[] = [];
  lines.push(`## ${title}\n`);
  lines.push('| Register | Hex | Decimal |');
  lines.push('|----------|-----|---------|');

  for (const [name, value] of Object.entries(regs)) {
    lines.push(`| \`${name}\` | \`${hex(value)}\` | ${value} |`);
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// rzil_step
// ---------------------------------------------------------------------------

interface RzilStepEntry {
  address: string;
  instruction: string;
  registers: Record<string, number>;
}

export function formatRzilSteps(steps: RzilStepEntry[]): string {
  const lines: string[] = [];
  lines.push(`## RzIL Step (${steps.length} instruction${steps.length !== 1 ? 's' : ''})\n`);

  for (let i = 0; i < steps.length; i++) {
    const step = steps[i]!;
    lines.push(`### Step ${i + 1}: \`${step.address}\`\n`);
    lines.push(`**Instruction:** \`${step.instruction}\`\n`);

    if (Object.keys(step.registers).length > 0) {
      lines.push('| Register | Value |');
      lines.push('|----------|-------|');
      for (const [name, value] of Object.entries(step.registers)) {
        lines.push(`| \`${name}\` | \`${hex(value)}\` |`);
      }
      lines.push('');
    }
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// rzil_run
// ---------------------------------------------------------------------------

interface RzilRunData {
  stopped_at: string;
  reason: 'address_reached' | 'max_steps' | 'breakpoint' | 'error';
  steps_taken: number;
  final_registers: Record<string, number>;
}

export function formatRzilRunResult(data: RzilRunData): string {
  const lines: string[] = [];
  lines.push('## RzIL Run Result\n');
  lines.push('| Property | Value |');
  lines.push('|----------|-------|');
  lines.push(`| Stopped At | \`${data.stopped_at}\` |`);
  lines.push(`| Reason | ${data.reason} |`);
  if (data.steps_taken >= 0) {
    lines.push(`| Steps Taken | ${data.steps_taken} |`);
  }

  if (Object.keys(data.final_registers).length > 0) {
    lines.push('\n### Final Registers\n');
    lines.push('| Register | Value |');
    lines.push('|----------|-------|');
    for (const [name, value] of Object.entries(data.final_registers)) {
      lines.push(`| \`${name}\` | \`${hex(value)}\` |`);
    }
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// rzil_get_memory
// ---------------------------------------------------------------------------

interface RzilMemoryData {
  address: string;
  size: number;
  format: string;
  data: string;
}

export function formatRzilMemory(data: RzilMemoryData): string {
  const lines: string[] = [];
  lines.push('## RzIL Memory Read\n');
  lines.push(`| Property | Value |`);
  lines.push(`|----------|-------|`);
  lines.push(`| Address | \`${data.address}\` |`);
  lines.push(`| Size | ${data.size} bytes |`);
  lines.push(`| Format | ${data.format} |`);
  lines.push('');

  if (data.format === 'hexdump') {
    lines.push('```');
    lines.push(data.data);
    lines.push('```');
  } else {
    lines.push(`\`\`\`\n${data.data}\n\`\`\``);
  }

  return lines.join('\n');
}
