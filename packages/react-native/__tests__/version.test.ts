import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

/**
 * `library/Cargo.toml` is the single source of every package's version, read
 * through `scripts/get-version.sh`. Every other package generates its manifest
 * at build time and so cannot disagree with it; this one is tracked in git,
 * because the suite around this file needs `devDependencies` and the lockfile
 * resolves against them. That makes it the only manifest whose version can
 * silently fall behind a release bump — which it has done once already. This
 * check is what makes the next one fail loudly instead.
 */
it('the tracked manifest version matches scripts/get-version.sh', () => {
  const root = path.join(__dirname, '../../..');
  const expected = execFileSync(path.join(root, 'scripts/get-version.sh'), {
    encoding: 'utf8',
  }).trim();

  const manifest = JSON.parse(
    fs.readFileSync(path.join(__dirname, '../package.json'), 'utf8'),
  ) as { version: string };

  expect(manifest.version).toBe(expected);
});
