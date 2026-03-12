import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizePath, sanitizeAddress, sanitizeFunctionName } from '../r2/sanitize.js';
import { withCachedSession } from '../r2/session-cache.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatFunctionDeep } from '../utils/formatters.js';
import type { R2Xref, R2String } from '../types.js';

interface R2FunctionInfo {
  readonly offset: number;
  readonly name: string;
  readonly size: number;
  readonly realsz: number;
  readonly noreturn: boolean;
  readonly stackframe: number;
  readonly calltype: string;
  readonly cost: number;
  readonly cc: number;
  readonly bits: number;
  readonly type: string;
  readonly nbbs: number;
  readonly edges: number;
  readonly ebbs: number;
  readonly signature: string;
  readonly minbound: number;
  readonly maxbound: number;
  readonly nlocals: number;
  readonly nargs: number;
  readonly callrefs?: readonly { addr: number; type: string; at: number }[];
  readonly codexrefs?: readonly { addr: number; type: string; at: number }[];
}

interface R2DisasmOp {
  readonly offset: number;
  readonly size: number;
  readonly opcode: string;
  readonly disasm: string;
  readonly bytes: string;
  readonly type: string;
  readonly esil: string;
}

interface R2DisasmFunc {
  readonly name: string;
  readonly addr: number;
  readonly ops: readonly R2DisasmOp[];
}

interface R2Variable {
  readonly name: string;
  readonly kind: string;
  readonly type: string;
  readonly ref: unknown;
}

export function registerAnalyzeFunctionDeep(server: McpServer): void {
  server.tool(
    'analyze_function_deep',
    'Deep single-function analysis: disassembly, decompilation, variables, xrefs, callers, callees, strings, and complexity metrics in one call.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      function_name: z
        .string()
        .optional()
        .describe('Name of the function to analyze (e.g. "main")'),
      address: z
        .string()
        .optional()
        .describe('Hex address of the function (e.g. "0x08048000")'),
    },
    async ({ binary_path, function_name, address }) => {
      if (!function_name && !address) {
        return mcpError('Either function_name or address must be provided');
      }

      try {
        const safePath = sanitizePath(binary_path);
        const safeAddr = address ? sanitizeAddress(address) : undefined;
        const safeName = function_name ? sanitizeFunctionName(function_name) : undefined;

        return await withCachedSession(safePath, async (session) => {
          // Resolve function address if given by name
          let funcAddr: string;
          if (safeAddr) {
            funcAddr = safeAddr;
          } else {
            // Seek to function by name and get its address
            const seekResult = await session.cmd(`s ${safeName!}`);
            void seekResult;
            const currentAddr = (await session.cmd('s')).trim();
            funcAddr = currentAddr;
          }

          // Gather all data in parallel
          const [funcInfo, disasm, decompiled, xrefsTo, xrefsFrom, variables] =
            await Promise.all([
              session.cmdj<R2FunctionInfo>(`afij @ ${funcAddr}`).then((r) => {
                // afij returns an array with one element
                if (Array.isArray(r) && r.length > 0) return r[0] as R2FunctionInfo;
                return r;
              }),
              session.cmdj<R2DisasmFunc>(`pdfj @ ${funcAddr}`).catch(() => null),
              session.cmd(`pdc @ ${funcAddr}`).catch(() => ''),
              session.cmdj<R2Xref[]>(`axtj @ ${funcAddr}`).catch(() => []),
              session.cmdj<R2Xref[]>(`axfj @ ${funcAddr}`).catch(() => []),
              session.cmdj<R2Variable[]>(`afvj @ ${funcAddr}`).catch(() => []),
            ]);

          // Extract strings referenced by this function
          const funcStrings: { address: string; value: string }[] = [];
          const dataRefs = Array.isArray(xrefsFrom) ? xrefsFrom : [];
          for (const ref of dataRefs) {
            if (ref.type === 'DATA' || ref.type === 'STRING') {
              try {
                // Only use numeric address (ref.to) — never ref.refname (binary metadata, injection risk)
                if (ref.to === undefined) continue;
                const strVal = await session.cmd(`ps @ 0x${ref.to.toString(16)}`);
                const trimmed = strVal.trim();
                if (trimmed.length > 0 && trimmed.length < 200) {
                  funcStrings.push({
                    address: `0x${(ref.to ?? 0).toString(16)}`,
                    value: trimmed,
                  });
                }
              } catch {
                // String read failed, skip
              }
            }
          }

          // Also look for strings in the function's address range
          if (funcInfo && typeof funcInfo === 'object' && 'minbound' in funcInfo) {
            try {
              const rangeStrings = await session.cmdj<R2String[]>(
                `izj~{vaddr>=${funcInfo.minbound},vaddr<=${funcInfo.maxbound}}`,
              );
              if (Array.isArray(rangeStrings)) {
                for (const s of rangeStrings) {
                  const exists = funcStrings.some((fs) => fs.address === `0x${s.vaddr.toString(16)}`);
                  if (!exists) {
                    funcStrings.push({
                      address: `0x${s.vaddr.toString(16)}`,
                      value: s.string,
                    });
                  }
                }
              }
            } catch {
              // Range string search failed, skip
            }
          }

          // Resolve callee names
          const callees: { address: string; name: string }[] = [];
          if (funcInfo && typeof funcInfo === 'object' && 'callrefs' in funcInfo) {
            const refs = funcInfo.callrefs;
            if (refs) {
              for (const ref of refs) {
                if (ref.type === 'CALL' || ref.type === 'C') {
                  try {
                    const nameResult = await session.cmd(`fd @ 0x${ref.addr.toString(16)}`);
                    callees.push({
                      address: `0x${ref.addr.toString(16)}`,
                      name: nameResult.trim() || 'unknown',
                    });
                  } catch {
                    callees.push({
                      address: `0x${ref.addr.toString(16)}`,
                      name: 'unknown',
                    });
                  }
                }
              }
            }
          }

          // Resolve caller names
          const callers: { address: string; name: string }[] = [];
          const xrefsToArr = Array.isArray(xrefsTo) ? xrefsTo : [];
          for (const ref of xrefsToArr) {
            if (ref.type === 'CALL' || ref.type === 'C') {
              callers.push({
                address: `0x${ref.from.toString(16)}`,
                name: ref.fcn_name || 'unknown',
              });
            }
          }

          return mcpFormatted(
            formatFunctionDeep({
              info: funcInfo,
              disasm: disasm,
              decompiled: decompiled.trim(),
              xrefsTo: xrefsToArr,
              xrefsFrom: dataRefs,
              variables: Array.isArray(variables) ? variables : [],
              strings: funcStrings,
              callees,
              callers,
            }),
          );
        });
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
