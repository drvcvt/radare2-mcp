import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { sanitizePath } from '../r2/sanitize.js';
import { withCachedSession } from '../r2/session-cache.js';
import { mcpError, mcpFormatted } from '../utils/errors.js';
import type { R2Session } from '../r2/session.js';
import type { R2String, R2Import, R2Xref } from '../types.js';

// ---------------------------------------------------------------------------
// IOC type definitions
// ---------------------------------------------------------------------------

type IocType =
  | 'ipv4'
  | 'ipv6'
  | 'url'
  | 'domain'
  | 'email'
  | 'windows_path'
  | 'unix_path'
  | 'registry_key'
  | 'btc_wallet'
  | 'user_agent'
  | 'pe_path'
  | 'suspicious_command';

interface Ioc {
  readonly type: IocType;
  readonly value: string;
  readonly address: string;
  readonly section: string;
  readonly xrefs: readonly IocXref[];
}

interface IocXref {
  readonly from: string;
  readonly function: string;
  readonly opcode: string;
}

interface SuspiciousApi {
  readonly name: string;
  readonly category: string;
  readonly address: string;
  readonly xrefCount: number;
}

interface IocReport {
  readonly summary: Record<string, number>;
  readonly iocs: readonly Ioc[];
  readonly suspiciousApis: readonly SuspiciousApi[];
  readonly totalStringsScanned: number;
}

// ---------------------------------------------------------------------------
// IOC regex patterns
// ---------------------------------------------------------------------------

const IOC_PATTERNS: ReadonlyArray<{ type: IocType; pattern: RegExp }> = [
  { type: 'ipv4', pattern: /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/ },
  {
    type: 'ipv6',
    pattern: /\b([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7}|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4})\b/,
  },
  { type: 'url', pattern: /https?:\/\/[^\s"']+/i },
  {
    type: 'domain',
    pattern:
      /\b[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.(com|net|org|io|ru|cn|info|biz|xyz|top|cc|tk|ml|ga|cf|gq|pw|pro|dev|app)\b/i,
  },
  { type: 'email', pattern: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/ },
  { type: 'windows_path', pattern: /[A-Z]:\\[\w\\.-]+/ },
  {
    type: 'unix_path',
    pattern: /\/(?:usr|etc|tmp|var|home|opt|bin|sbin|dev|proc)\/[\w/.-]+/,
  },
  { type: 'registry_key', pattern: /HKEY_[\w\\]+|(?:HKLM|HKCU|HKU)\\[\w\\]+/ },
  { type: 'btc_wallet', pattern: /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/ },
  { type: 'user_agent', pattern: /Mozilla\/[^\s"']+|User-Agent:\s*[^\s"']+/i },
  { type: 'pe_path', pattern: /.+\.(exe|dll|sys|bat|cmd|ps1|vbs|js)\b/i },
  {
    type: 'suspicious_command',
    pattern: /cmd\.exe|powershell|bash|sh -c|wget|curl|net user|reg add/i,
  },
];

// ---------------------------------------------------------------------------
// Suspicious API categories
// ---------------------------------------------------------------------------

const SUSPICIOUS_APIS: ReadonlyMap<string, string> = new Map([
  // Network
  ['WinHttpOpen', 'network'],
  ['WinHttpConnect', 'network'],
  ['WinHttpOpenRequest', 'network'],
  ['WinHttpSendRequest', 'network'],
  ['InternetOpenA', 'network'],
  ['InternetOpenW', 'network'],
  ['InternetOpenUrlA', 'network'],
  ['InternetOpenUrlW', 'network'],
  ['InternetConnectA', 'network'],
  ['InternetConnectW', 'network'],
  ['HttpOpenRequestA', 'network'],
  ['HttpOpenRequestW', 'network'],
  ['HttpSendRequestA', 'network'],
  ['HttpSendRequestW', 'network'],
  ['URLDownloadToFileA', 'network'],
  ['URLDownloadToFileW', 'network'],
  ['socket', 'network'],
  ['connect', 'network'],
  ['send', 'network'],
  ['recv', 'network'],
  ['WSAStartup', 'network'],
  ['WSASocketA', 'network'],
  ['WSASocketW', 'network'],
  ['getaddrinfo', 'network'],
  ['gethostbyname', 'network'],

  // File
  ['CreateFileA', 'file'],
  ['CreateFileW', 'file'],
  ['WriteFile', 'file'],
  ['ReadFile', 'file'],
  ['DeleteFileA', 'file'],
  ['DeleteFileW', 'file'],
  ['MoveFileA', 'file'],
  ['MoveFileW', 'file'],
  ['CopyFileA', 'file'],
  ['CopyFileW', 'file'],

  // Process
  ['CreateProcessA', 'process'],
  ['CreateProcessW', 'process'],
  ['ShellExecuteA', 'process'],
  ['ShellExecuteW', 'process'],
  ['ShellExecuteExA', 'process'],
  ['ShellExecuteExW', 'process'],
  ['WinExec', 'process'],
  ['system', 'process'],
  ['execve', 'process'],
  ['fork', 'process'],

  // Registry
  ['RegOpenKeyA', 'registry'],
  ['RegOpenKeyW', 'registry'],
  ['RegOpenKeyExA', 'registry'],
  ['RegOpenKeyExW', 'registry'],
  ['RegSetValueA', 'registry'],
  ['RegSetValueW', 'registry'],
  ['RegSetValueExA', 'registry'],
  ['RegSetValueExW', 'registry'],
  ['RegCreateKeyA', 'registry'],
  ['RegCreateKeyW', 'registry'],
  ['RegCreateKeyExA', 'registry'],
  ['RegCreateKeyExW', 'registry'],
  ['RegDeleteKeyA', 'registry'],
  ['RegDeleteKeyW', 'registry'],

  // Injection
  ['VirtualAlloc', 'injection'],
  ['VirtualAllocEx', 'injection'],
  ['VirtualProtect', 'injection'],
  ['VirtualProtectEx', 'injection'],
  ['WriteProcessMemory', 'injection'],
  ['ReadProcessMemory', 'injection'],
  ['CreateRemoteThread', 'injection'],
  ['CreateRemoteThreadEx', 'injection'],
  ['NtUnmapViewOfSection', 'injection'],
  ['NtWriteVirtualMemory', 'injection'],
  ['RtlCreateUserThread', 'injection'],
  ['QueueUserAPC', 'injection'],
  ['SetWindowsHookExA', 'injection'],
  ['SetWindowsHookExW', 'injection'],

  // Anti-analysis
  ['IsDebuggerPresent', 'anti_analysis'],
  ['CheckRemoteDebuggerPresent', 'anti_analysis'],
  ['NtQueryInformationProcess', 'anti_analysis'],
  ['OutputDebugStringA', 'anti_analysis'],
  ['OutputDebugStringW', 'anti_analysis'],
  ['GetTickCount', 'anti_analysis'],
  ['QueryPerformanceCounter', 'anti_analysis'],
  ['NtQuerySystemInformation', 'anti_analysis'],

  // Crypto
  ['CryptEncrypt', 'crypto'],
  ['CryptDecrypt', 'crypto'],
  ['CryptAcquireContextA', 'crypto'],
  ['CryptAcquireContextW', 'crypto'],
  ['CryptCreateHash', 'crypto'],
  ['CryptHashData', 'crypto'],
  ['CryptDeriveKey', 'crypto'],
]);

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

function isValidIpv4(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  for (const part of parts) {
    const num = Number(part);
    if (!Number.isFinite(num) || num < 0 || num > 255) return false;
  }
  // Exclude common non-IOC addresses
  const excluded = ['0.0.0.0', '127.0.0.1', '255.255.255.255'];
  if (excluded.includes(ip)) return false;
  // Exclude common version-like patterns (e.g., "2.0.0.0", "1.0.0.0")
  if (/^\d+\.0\.0\.0$/.test(ip)) return false;
  return true;
}

function classifyString(str: string): IocType | undefined {
  for (const { type, pattern } of IOC_PATTERNS) {
    const match = pattern.exec(str);
    if (match) {
      // Extra validation for IPv4
      if (type === 'ipv4') {
        const ipMatch = match[1];
        if (ipMatch !== undefined && !isValidIpv4(ipMatch)) continue;
      }
      return type;
    }
  }
  return undefined;
}

function extractIocValue(str: string, type: IocType): string {
  for (const entry of IOC_PATTERNS) {
    if (entry.type === type) {
      const match = entry.pattern.exec(str);
      if (match) {
        return match[0];
      }
    }
  }
  return str;
}

function toHex(addr: number): string {
  return `0x${addr.toString(16)}`;
}

async function getXrefsForAddress(
  session: R2Session,
  addr: number,
): Promise<readonly IocXref[]> {
  try {
    const xrefs = await session.cmdj<R2Xref[]>(`axtj @ ${toHex(addr)}`);
    if (!Array.isArray(xrefs)) return [];
    return xrefs.map((x) => ({
      from: toHex(x.from),
      function: x.fcn_name ?? 'unknown',
      opcode: x.opcode ?? '',
    }));
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Markdown formatting
// ---------------------------------------------------------------------------

function formatIocType(type: IocType): string {
  const labels: Record<IocType, string> = {
    ipv4: 'IPv4 Address',
    ipv6: 'IPv6 Address',
    url: 'URL',
    domain: 'Domain',
    email: 'Email Address',
    windows_path: 'Windows Path',
    unix_path: 'Unix Path',
    registry_key: 'Registry Key',
    btc_wallet: 'BTC Wallet',
    user_agent: 'User-Agent',
    pe_path: 'PE/Script Path',
    suspicious_command: 'Suspicious Command',
  };
  return labels[type];
}

function formatReport(report: IocReport): string {
  const lines: string[] = [];

  lines.push('# IOC Extraction Report');
  lines.push('');

  // Summary
  lines.push('## Summary');
  lines.push('');
  lines.push(`- **Total strings scanned:** ${report.totalStringsScanned}`);
  lines.push(`- **Total IOCs found:** ${report.iocs.length}`);
  lines.push(`- **Suspicious APIs:** ${report.suspiciousApis.length}`);
  lines.push('');

  if (Object.keys(report.summary).length > 0) {
    lines.push('| IOC Type | Count |');
    lines.push('|----------|-------|');
    for (const [type, count] of Object.entries(report.summary)) {
      lines.push(`| ${type} | ${count} |`);
    }
    lines.push('');
  }

  // Network IOCs
  const networkTypes: ReadonlyArray<IocType> = ['ipv4', 'ipv6', 'url', 'domain'];
  const networkIocs = report.iocs.filter((i) => networkTypes.includes(i.type));
  if (networkIocs.length > 0) {
    lines.push('## Network IOCs');
    lines.push('');
    lines.push('| Type | Value | Address | Section | Referenced By |');
    lines.push('|------|-------|---------|---------|---------------|');
    for (const ioc of networkIocs) {
      const refs = ioc.xrefs.length > 0
        ? ioc.xrefs.map((x) => `${x.function}`).join(', ')
        : '-';
      lines.push(
        `| ${formatIocType(ioc.type)} | \`${ioc.value}\` | ${ioc.address} | ${ioc.section} | ${refs} |`,
      );
    }
    lines.push('');
  }

  // Email addresses
  const emailIocs = report.iocs.filter((i) => i.type === 'email');
  if (emailIocs.length > 0) {
    lines.push('## Email Addresses');
    lines.push('');
    lines.push('| Value | Address | Section | Referenced By |');
    lines.push('|-------|---------|---------|---------------|');
    for (const ioc of emailIocs) {
      const refs = ioc.xrefs.length > 0
        ? ioc.xrefs.map((x) => `${x.function}`).join(', ')
        : '-';
      lines.push(`| \`${ioc.value}\` | ${ioc.address} | ${ioc.section} | ${refs} |`);
    }
    lines.push('');
  }

  // File System IOCs
  const fsTypes: ReadonlyArray<IocType> = ['windows_path', 'unix_path', 'pe_path'];
  const fsIocs = report.iocs.filter((i) => fsTypes.includes(i.type));
  if (fsIocs.length > 0) {
    lines.push('## File System IOCs');
    lines.push('');
    lines.push('| Type | Value | Address | Section | Referenced By |');
    lines.push('|------|-------|---------|---------|---------------|');
    for (const ioc of fsIocs) {
      const refs = ioc.xrefs.length > 0
        ? ioc.xrefs.map((x) => `${x.function}`).join(', ')
        : '-';
      lines.push(
        `| ${formatIocType(ioc.type)} | \`${ioc.value}\` | ${ioc.address} | ${ioc.section} | ${refs} |`,
      );
    }
    lines.push('');
  }

  // Registry IOCs
  const regIocs = report.iocs.filter((i) => i.type === 'registry_key');
  if (regIocs.length > 0) {
    lines.push('## Registry IOCs');
    lines.push('');
    lines.push('| Value | Address | Section | Referenced By |');
    lines.push('|-------|---------|---------|---------------|');
    for (const ioc of regIocs) {
      const refs = ioc.xrefs.length > 0
        ? ioc.xrefs.map((x) => `${x.function}`).join(', ')
        : '-';
      lines.push(`| \`${ioc.value}\` | ${ioc.address} | ${ioc.section} | ${refs} |`);
    }
    lines.push('');
  }

  // Suspicious APIs
  if (report.suspiciousApis.length > 0) {
    lines.push('## Suspicious APIs');
    lines.push('');
    lines.push('| API | Category | Address | Xref Count |');
    lines.push('|-----|----------|---------|------------|');
    for (const api of report.suspiciousApis) {
      lines.push(`| \`${api.name}\` | ${api.category} | ${api.address} | ${api.xrefCount} |`);
    }
    lines.push('');

    // Anti-analysis indicators (subset)
    const antiAnalysis = report.suspiciousApis.filter((a) => a.category === 'anti_analysis');
    if (antiAnalysis.length > 0) {
      lines.push('### Anti-Analysis Indicators');
      lines.push('');
      for (const api of antiAnalysis) {
        lines.push(`- \`${api.name}\` at ${api.address} (${api.xrefCount} xrefs)`);
      }
      lines.push('');
    }
  }

  // Crypto / Wallet addresses
  const cryptoIocs = report.iocs.filter((i) => i.type === 'btc_wallet');
  if (cryptoIocs.length > 0) {
    lines.push('## Crypto Wallet Addresses');
    lines.push('');
    lines.push('| Value | Address | Section | Referenced By |');
    lines.push('|-------|---------|---------|---------------|');
    for (const ioc of cryptoIocs) {
      const refs = ioc.xrefs.length > 0
        ? ioc.xrefs.map((x) => `${x.function}`).join(', ')
        : '-';
      lines.push(`| \`${ioc.value}\` | ${ioc.address} | ${ioc.section} | ${refs} |`);
    }
    lines.push('');
  }

  // User-Agent strings
  const uaIocs = report.iocs.filter((i) => i.type === 'user_agent');
  if (uaIocs.length > 0) {
    lines.push('## User-Agent Strings');
    lines.push('');
    for (const ioc of uaIocs) {
      const refs = ioc.xrefs.length > 0
        ? ioc.xrefs.map((x) => `${x.function}`).join(', ')
        : '-';
      lines.push(`- \`${ioc.value}\` at ${ioc.address} (refs: ${refs})`);
    }
    lines.push('');
  }

  // Suspicious Commands
  const cmdIocs = report.iocs.filter((i) => i.type === 'suspicious_command');
  if (cmdIocs.length > 0) {
    lines.push('## Suspicious Commands');
    lines.push('');
    lines.push('| Value | Address | Section | Referenced By |');
    lines.push('|-------|---------|---------|---------------|');
    for (const ioc of cmdIocs) {
      const refs = ioc.xrefs.length > 0
        ? ioc.xrefs.map((x) => `${x.function}`).join(', ')
        : '-';
      lines.push(`| \`${ioc.value}\` | ${ioc.address} | ${ioc.section} | ${refs} |`);
    }
    lines.push('');
  }

  if (report.iocs.length === 0 && report.suspiciousApis.length === 0) {
    lines.push('*No IOCs or suspicious APIs detected.*');
    lines.push('');
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Tool registration
// ---------------------------------------------------------------------------

export function registerExtractIocs(server: McpServer): void {
  server.tool(
    'extract_iocs',
    'Extract Indicators of Compromise from a binary: IP addresses, URLs, domains, file paths, registry keys, email addresses, crypto wallets, and embedded payloads.',
    {
      binary_path: z.string().describe('Absolute path to the binary file'),
      scan_all_bytes: z
        .boolean()
        .default(false)
        .describe('Search all bytes (slower) vs only data sections'),
      include_context: z
        .boolean()
        .default(true)
        .describe('Include xref context for each IOC'),
    },
    async ({ binary_path, scan_all_bytes, include_context }) => {
      try {
        const safePath = sanitizePath(binary_path);
        return await withCachedSession(safePath, async (session) => {
          // 1. Get strings from the binary
          const stringsCmd = scan_all_bytes ? 'izzj' : 'izj';
          const [allStrings, allImports] = await Promise.all([
            session.cmdj<R2String[]>(stringsCmd),
            session.cmdj<R2Import[]>('iij'),
          ]);

          const strings = Array.isArray(allStrings) ? allStrings : [];
          const imports = Array.isArray(allImports) ? allImports : [];

          // 2. Classify strings into IOC types
          const seen = new Set<string>();
          const iocs: Ioc[] = [];

          for (const s of strings) {
            const val = s.string;
            if (!val || val.length < 4) continue;

            const iocType = classifyString(val);
            if (iocType === undefined) continue;

            const extracted = extractIocValue(val, iocType);
            const dedupeKey = `${iocType}::${extracted}`;
            if (seen.has(dedupeKey)) continue;
            seen.add(dedupeKey);

            // 3. Get xrefs if requested
            let xrefs: readonly IocXref[] = [];
            if (include_context) {
              xrefs = await getXrefsForAddress(session, s.vaddr);
            }

            iocs.push({
              type: iocType,
              value: extracted,
              address: toHex(s.vaddr),
              section: s.section ?? 'unknown',
              xrefs,
            });
          }

          // 4. Check imports for suspicious APIs
          const suspiciousApis: SuspiciousApi[] = [];
          for (const imp of imports) {
            // Match against known suspicious API names (strip imp. prefix if present)
            const cleanName = imp.name.replace(/^imp\./, '');
            const category = SUSPICIOUS_APIS.get(cleanName);
            if (category === undefined) continue;

            // Get xref count for this import
            let xrefCount = 0;
            if (imp.plt !== 0) {
              try {
                const xrefs = await session.cmdj<R2Xref[]>(`axtj @ ${toHex(imp.plt)}`);
                if (Array.isArray(xrefs)) {
                  xrefCount = xrefs.length;
                }
              } catch {
                // Skip if xrefs fail
              }
            }

            suspiciousApis.push({
              name: cleanName,
              category,
              address: toHex(imp.plt),
              xrefCount,
            });
          }

          // 5. Build summary counts
          const summary: Record<string, number> = {};
          for (const ioc of iocs) {
            const label = formatIocType(ioc.type);
            summary[label] = (summary[label] ?? 0) + 1;
          }

          // Group suspicious APIs by category in summary
          const apiCategories = new Map<string, number>();
          for (const api of suspiciousApis) {
            apiCategories.set(api.category, (apiCategories.get(api.category) ?? 0) + 1);
          }
          for (const [cat, count] of apiCategories) {
            summary[`Suspicious API (${cat})`] = count;
          }

          const report: IocReport = {
            summary,
            iocs,
            suspiciousApis,
            totalStringsScanned: strings.length,
          };

          return mcpFormatted(formatReport(report));
        });
      } catch (error) {
        return mcpError(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
