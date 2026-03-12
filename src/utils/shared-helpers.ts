// ---------------------------------------------------------------------------
// Shared helper functions — deduplicated from tool implementations
// ---------------------------------------------------------------------------

/**
 * Check if an x86 opcode mnemonic is a conditional jump instruction.
 * Matches j<cond> patterns (je, jne, jz, jnz, jg, jl, etc.) but NOT jmp.
 *
 * @param opcode - The instruction mnemonic (e.g. "je 0x401000"). Only the
 *   first whitespace-delimited token is examined.
 * @returns `true` if the instruction is a conditional jump.
 */
export function isConditionalJump(opcode: string): boolean {
  const first = opcode.split(' ')[0] ?? '';
  return /^j[neblgaoscz]|^j[neblgaoscz]{2}|^jn?[eblgaoscz]/.test(first) && first !== 'jmp';
}

/**
 * Strip common import prefixes that r2 adds to symbol names.
 * Handles `sym.imp.`, `imp.`, `reloc.`, and `sym.` prefixes.
 *
 * @param name - The r2 symbol name (e.g. "sym.imp.strcpy").
 * @returns The bare function name (e.g. "strcpy").
 */
export function stripImportPrefix(name: string | null | undefined): string {
  if (name == null) return '';
  return name
    .replace(/^sym\.imp\./, '')
    .replace(/^imp\./, '')
    .replace(/^reloc\./, '')
    .replace(/^sym\./, '');
}
