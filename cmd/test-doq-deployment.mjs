import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const appDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const mainUnit = fs.readFileSync(path.join(appDir, 'systemd', 'cleandns.service'), 'utf8');
const compatibilityScript = fs.readFileSync(path.join(appDir, 'apply-doq-port'), 'utf8');

assert.equal(fs.existsSync(path.join(appDir, 'systemd', 'cleandns-doq.service')), false);
assert.match(mainUnit, /^Description=CleanDNS unified DNS core and protocol services$/m);
assert.match(mainUnit, /^KillMode=control-group$/m);
assert.match(compatibilityScript, /systemctl restart cleandns\.service/);
assert.doesNotMatch(compatibilityScript, /systemctl (?:enable|restart) cleandns-doq\.service/);

console.log('DoQ deployment ownership tests passed');
