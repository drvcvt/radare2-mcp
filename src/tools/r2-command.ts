import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { R2Session } from '../r2/session.js';
import { sanitizePath, sanitizeCommand } from '../r2/sanitize.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import { formatR2Command } from '../utils/formatters.js';

/**
 * Allowlist of safe r2 command prefixes.
 * Only commands starting with one of these prefixes are permitted.
 */
const ALLOWED_PREFIXES = [
  'a',   // analysis commands (aa, aaa, afl, af, ag, ax, etc.)
  'p',   // print commands (pd, px, pf, pi, etc.)
  'i',   // info commands (ij, iS, iE, ii, iz, etc.)
  's',   // seek commands
  'f',   // flags
  '/',   // search commands (/x, /R, /, etc.)
  'e',   // eval/config commands
  'af',  // analysis function commands
  'ag',  // analysis graph commands
  'ax',  // analysis xrefs commands
  'CC',  // comments
  'dr',  // debug registers (read-only)
  'om',  // open file map
];

/**
 * Characters and sequences that are BLOCKED even if the command prefix is allowed.
 * These could chain commands, redirect output, or escape to a shell.
 *
 * Note: `@@` is explicitly allowed as it is a safe r2 iterator.
 * The single `@` is allowed for seeking (e.g. `pd 10 @ main`).
 */
const BLOCKED_CHARS_RE = /[;|><`!~{}()$]/;
const HASHBANG_RE = /#!/;

/**
 * Dangerous eval key prefixes that could alter r2 behavior in security-sensitive ways.
 * Writing to these config keys can execute commands, change I/O backends, or alter
 * the analysis engine in ways that bypass security controls.
 */
const DANGEROUS_EVAL_PREFIXES = [
  'cfg.sandbox', // Sandbox enforcement — must not be disabled
  'cmd.',    // Execute commands on events (e.g. cmd.hit, cmd.open)
  'io.',     // I/O backend config (e.g. io.cache)
  'bin.',    // Binary loader config
  'asm.arch', // Change architecture (could load plugins)
  'asm.cpu',  // Change CPU
  'asm.os',   // Change OS
  'http.',   // HTTP server config
  'tcp.',    // TCP server/listener config
  'rap.',    // Remote r2 protocol config
  'scr.',    // Screen/scripting config (e.g. scr.html)
  'dbg.',    // Debugger config
];

/**
 * Validate that a command is on the allowlist and does not contain
 * dangerous characters or sequences.
 */
function validateCommand(command: string): string {
  // First pass: use the generic sanitizeCommand to catch dangerous chars
  const sanitized = sanitizeCommand(command);

  // Additional check: reject blocked characters that sanitizeCommand might not cover
  if (BLOCKED_CHARS_RE.test(sanitized)) {
    throw new Error(
      `Command contains blocked characters (; | > < \` ! ~ { } ( ) $): ${sanitized}`,
    );
  }

  if (HASHBANG_RE.test(sanitized)) {
    throw new Error(`Command contains forbidden sequence (#!): ${sanitized}`);
  }

  // Check that the command starts with an allowed prefix
  const isAllowed = ALLOWED_PREFIXES.some((prefix) => sanitized.startsWith(prefix));
  if (!isAllowed) {
    throw new Error(
      `Command '${sanitized}' is not in the allowlist. ` +
        `Allowed prefixes: ${ALLOWED_PREFIXES.join(', ')}`,
    );
  }

  // Block writes to dangerous eval keys (e key=value).
  // Read-only eval (e key without =) is safe and allowed.
  if (sanitized.startsWith('e ') && sanitized.includes('=')) {
    // Extract the key portion: "e some.key=value" -> "some.key"
    const afterE = sanitized.slice(2).trimStart();
    const eqIndex = afterE.indexOf('=');
    if (eqIndex > 0) {
      const evalKey = afterE.slice(0, eqIndex).trim();
      const isDangerous = DANGEROUS_EVAL_PREFIXES.some(
        (prefix) => evalKey === prefix || evalKey.startsWith(prefix),
      );
      if (isDangerous) {
        throw new Error(
          `Writing to eval key '${evalKey}' is blocked for security reasons. ` +
            `Dangerous prefixes: ${DANGEROUS_EVAL_PREFIXES.join(', ')}`,
        );
      }
    }
  }

  return sanitized;
}

export function registerR2Command(server: McpServer): void {
  server.tool(
    'r2_command',
    'Execute a radare2 command directly and return the raw output. Only commands starting with these prefixes are allowed: a (analysis: aa, aaa, afl, af, ag, ax), p (print: pd, px, pf, pi), i (info: ij, iS, iE, ii, iz), s (seek), f (flags), / (search: /x, /R), e (eval/config), af (analysis functions), ag (analysis graphs), ax (analysis xrefs), CC (comments), dr (debug registers), om (open file map). Blocked characters: ; | > < ` ! ~ { } ( ) $ #!.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      command: z.string().min(1).describe('The r2 command to execute (must be on the allowlist)'),
      analysis_level: z
        .enum(['none', 'aa', 'aaa', 'aaaa'])
        .default('aaa')
        .describe('Analysis level to run before executing the command'),
    },
    async ({ binary_path, command, analysis_level }) => {
      let session: R2Session | undefined;
      try {
        const safePath = sanitizePath(binary_path);
        const safeCommand = validateCommand(command);

        session = await R2Session.open(safePath);

        if (analysis_level !== 'none') {
          await session.cmd(analysis_level);
        }

        const output = await session.cmd(safeCommand);

        return mcpFormatted(formatR2Command({
          command: safeCommand,
          output: output.trim(),
        }));
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      } finally {
        if (session) {
          await session.close();
        }
      }
    },
  );
}
