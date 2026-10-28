import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tests = fs.readdirSync(path.join(root, 'cmd'))
  .filter((name) => /^test-.*\.mjs$/.test(name)).sort();
let passed = 0;
for (const test of tests) {
  console.log(`\n=== ${test} ===`);
  const result = spawnSync(process.execPath, [path.join(root, 'cmd', test)], {
    cwd: root, stdio: 'inherit', timeout: 120_000,
  });
  if (result.error || result.status !== 0) {
    console.error(result.error?.message || `Failed: ${test} (exit ${result.status})`);
    process.exit(1);
  }
  passed++;
}
console.log(`\nPassed ${passed} CleanDNS regression suites.`);
