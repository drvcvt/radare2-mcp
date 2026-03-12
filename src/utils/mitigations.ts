// ---------------------------------------------------------------------------
// Shared mitigation detection — deduplicated from triage-binary, find-vulnerabilities, exploit-hunter
// ---------------------------------------------------------------------------

import type { R2Session } from '../r2/session.js';

/** Security mitigation information detected from a binary. */
export interface MitigationInfo {
  readonly canary: boolean;
  readonly nx: boolean;
  readonly pic: boolean;
  readonly relro: string;
}

/**
 * Detect security mitigations from r2's binary info output.
 *
 * Parses the `iI` command output for canary, NX, PIC/PIE, and RELRO settings.
 *
 * @param session - An open R2Session with analysis already run.
 * @returns Detected mitigation flags.
 */
export async function detectMitigations(session: R2Session): Promise<MitigationInfo> {
  let canary = false;
  let nx = false;
  let pic = false;
  let relro = 'unknown';

  try {
    const checksec = await session.cmd('iI~canary,nx,pic,relro');
    if (checksec.includes('canary=true') || checksec.includes('canary true')) canary = true;
    if (checksec.includes('nx=true') || checksec.includes('nx true')) nx = true;
    if (checksec.includes('pic=true') || checksec.includes('pic true')) pic = true;
    if (checksec.includes('relro=full') || checksec.includes('relro full')) relro = 'full';
    else if (checksec.includes('relro=partial') || checksec.includes('relro partial'))
      relro = 'partial';
    else if (checksec.includes('relro=no') || checksec.includes('relro none')) relro = 'none';
  } catch {
    // Security check not available for all binary types
  }

  return { canary, nx, pic, relro };
}
