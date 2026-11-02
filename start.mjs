import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startSetup } from './setup.js';

const root = path.dirname(fileURLToPath(import.meta.url));
const configPath = path.resolve(process.env.CLEANDNS_CONFIG || path.join(root, 'config.json'));
if (fs.existsSync(configPath)) {
  await import('./server.js');
} else {
  const handlers = new Map();
  const setup = await startSetup({
    configPath,
    dataDir: process.env.CLEANDNS_DATA_DIR || path.join(path.dirname(configPath), 'data'),
    host: process.env.CLEANDNS_SETUP_HOST || '127.0.0.1',
    port: Number(process.env.CLEANDNS_SETUP_PORT || 3000),
    tokenFile: process.env.CLEANDNS_SETUP_TOKEN_FILE,
    onComplete: async () => { for (const [signal, handler] of handlers) process.removeListener(signal, handler); await import('./server.js'); }
  });
  console.log(`CleanDNS first-run setup: http://${setup.host.includes(':') ? '[' + setup.host + ']' : setup.host}:${setup.port}/setup/`);
  if (process.env.CLEANDNS_SETUP_TOKEN_FILE) console.log(`Setup access token file: ${process.env.CLEANDNS_SETUP_TOKEN_FILE} (readable only by the service owner).`);
  else console.log(`Open the setup URL with #${setup.token} appended. This token becomes invalid after setup.`);
  for (const signal of ['SIGINT', 'SIGTERM']) { const handler = () => { setup.close().finally(() => process.exit(0)); }; handlers.set(signal, handler); process.once(signal, handler); }
}
