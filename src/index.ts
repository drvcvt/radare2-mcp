#!/usr/bin/env node

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createServer } from './server.js';
import { debugManager } from './r2/debug-session-manager.js';
import { esilManager } from './r2/esil-session-manager.js';
import { rzilManager } from './rizin/rzil-session-manager.js';
import { sessionCache } from './r2/session-cache.js';

async function main(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();

  await server.connect(transport);

  const shutdown = async (): Promise<void> => {
    await sessionCache.closeAll();
    await esilManager.closeAll();
    await rzilManager.closeAll();
    await debugManager.closeAll();
    await server.close();
    process.exit(0);
  };

  process.on('SIGINT', () => void shutdown());
  process.on('SIGTERM', () => void shutdown());
}

main().catch((error: unknown) => {
  process.stderr.write(`Fatal error: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
