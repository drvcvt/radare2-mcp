import type { R2Session } from './session.js';
import type {
  R2FileInfo,
  R2Function,
  R2String,
  R2Import,
  R2Export,
  R2Section,
  R2Xref,
  R2DisasmFunction,
  R2Instruction,
  R2Relocation,
  R2Class,
} from '../types.js';
import { sanitizeAddress } from './sanitize.js';

// ---------------------------------------------------------------------------
// Typed wrappers around common r2 JSON commands.
// Each function takes an open R2Session and returns parsed, typed data.
// ---------------------------------------------------------------------------

/** Get binary info (`ij`). */
export async function getBinaryInfo(session: R2Session): Promise<R2FileInfo> {
  return session.cmdj<R2FileInfo>('ij');
}

/** List all functions (`aflj`). */
export async function listFunctions(session: R2Session): Promise<R2Function[]> {
  const result = await session.cmdj<R2Function[]>('aflj');
  return Array.isArray(result) ? result : [];
}

/** List strings in data sections (`izj`). */
export async function listStrings(session: R2Session): Promise<R2String[]> {
  const result = await session.cmdj<R2String[]>('izj');
  return Array.isArray(result) ? result : [];
}

/** List all strings including non-data sections (`izzj`). */
export async function listAllStrings(session: R2Session): Promise<R2String[]> {
  const result = await session.cmdj<R2String[]>('izzj');
  return Array.isArray(result) ? result : [];
}

/** List imports (`iij`). */
export async function listImports(session: R2Session): Promise<R2Import[]> {
  const result = await session.cmdj<R2Import[]>('iij');
  return Array.isArray(result) ? result : [];
}

/** List exports (`iEj`). */
export async function listExports(session: R2Session): Promise<R2Export[]> {
  const result = await session.cmdj<R2Export[]>('iEj');
  return Array.isArray(result) ? result : [];
}

/** List sections (`iSj`). */
export async function listSections(session: R2Session): Promise<R2Section[]> {
  const result = await session.cmdj<R2Section[]>('iSj');
  return Array.isArray(result) ? result : [];
}

/** Get cross-references to an address (`axtj`). */
export async function getXrefsTo(session: R2Session, address: string): Promise<R2Xref[]> {
  const safeAddr = sanitizeAddress(address);
  const result = await session.cmdj<R2Xref[]>(`axtj ${safeAddr}`);
  return Array.isArray(result) ? result : [];
}

/** Get cross-references from an address (`axfj`). */
export async function getXrefsFrom(session: R2Session, address: string): Promise<R2Xref[]> {
  const safeAddr = sanitizeAddress(address);
  const result = await session.cmdj<R2Xref[]>(`axfj ${safeAddr}`);
  return Array.isArray(result) ? result : [];
}

/** Disassemble a function at the current seek (`pdfj`). */
export async function disassembleFunction(session: R2Session): Promise<R2DisasmFunction> {
  return session.cmdj<R2DisasmFunction>('pdfj');
}

/** Disassemble N instructions at the current seek (`pdj`). */
export async function disassembleInstructions(
  session: R2Session,
  count: number,
): Promise<R2Instruction[]> {
  const result = await session.cmdj<R2Instruction[]>(`pdj ${count}`);
  return Array.isArray(result) ? result : [];
}

/** List relocations (`irj`). */
export async function listRelocations(session: R2Session): Promise<R2Relocation[]> {
  const result = await session.cmdj<R2Relocation[]>('irj');
  return Array.isArray(result) ? result : [];
}

/** List classes and methods (`icj`). */
export async function listClasses(session: R2Session): Promise<R2Class[]> {
  const result = await session.cmdj<R2Class[]>('icj');
  return Array.isArray(result) ? result : [];
}
