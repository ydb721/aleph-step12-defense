import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { after, test } from 'node:test';
import { mkdtemp, readFile, readdir, realpath, rm, symlink, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { prepareDeviceHttps } from '../scripts/prepare-device-https.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const temporary = await mkdtemp(join(tmpdir(), 'byteback-https-prepare-tests-'));
const config = JSON.parse(await readFile(join(root, 'aleph.config.json')));
assert.ok(config.step >= 11 && config.step <= 12,
  'the device HTTPS preparation profile must keep the Step 11-or-later contract');
const origin = 'https://s11-isolated-fixture.vercel.app';
// Nonexistent synthetic project reference and nonsecret dummy values: no network calls.
const supabaseRef = 'a'.repeat(20);
const backend = `https://${supabaseRef}.supabase.co`;
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
let counter = 0;
const destination = () => join(temporary, `snapshot-${++counter}`);
const prepare = (overrides = {}) => prepareDeviceHttps({ root, origin, supabaseRef,
  outputDir: destination(), ...overrides });
const git = (...args) => execFileSync('git', ['-C', root, ...args], {
  encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
});
const expectedSourceState = () => git('status', '--porcelain', '--untracked-files=all').trim()
  ? 'uncommitted-snapshot'
  : 'local-snapshot';
const originals = new Map(await Promise.all(git('ls-files', '--cached', '--others',
  '--exclude-standard', '-z').split('\0').filter(Boolean).map(async path =>
  [path, sha(await readFile(join(root, path)))])));

after(async () => {
  // Check the absolute resolved target before recursive removal; never delete source paths.
  const absolute = await realpath(temporary);
  const parent = await realpath(tmpdir());
  const child = relative(parent, absolute);
  assert.ok(child && !isAbsolute(child) && !child.startsWith('..'));
  assert.ok(basename(absolute).startsWith('byteback-https-prepare-tests-'));
  await rm(temporary, { recursive: true });
});

test('snapshot includes current uncommitted device runtime with isolated configuration', async () => {
  const outputDir = destination();
  const receipt = await prepare({ outputDir });
  const snapshot = JSON.parse(await readFile(join(outputDir, 'aleph.config.json')));
  assert.equal(snapshot.publicAppUrl, origin);
  assert.equal(snapshot.identityProvider.issuer, backend + '/auth/v1');
  assert.equal(snapshot.identityProvider.jwksUrl, backend + '/auth/v1/.well-known/jwks.json');
  assert.equal(snapshot.originalApiUrl, backend + '/rest/v1/memos');
  for (const key of ['step', 'judgeIssuer', 'restoreRoute', 'allowedRoutes']) {
    assert.deepEqual(snapshot[key], config[key]);
  }
  assert.equal(receipt.baselineCommit, git('rev-parse', 'HEAD').trim());
  assert.equal(receipt.commit, null);
  assert.equal(receipt.notForSubmission, true);
  assert.equal(receipt.sourceState, expectedSourceState());
  assert.equal(receipt.rpID, new URL(origin).hostname);
  // 10 baseline handlers plus the Step 11 device endpoint and two static
  // item routes that avoid Vercel dynamic-route query rewriting.
  assert.equal(receipt.files.filter(x => /^api\/.*\.js$/u.test(x.path)).length, 12);
  assert.ok(receipt.files.some(x => x.path === 'api/devices.js'));
  assert.equal(sha(await readFile(join(outputDir, 'src/device-auth.mjs'))),
    sha(await readFile(join(root, 'src/device-auth.mjs'))));
});

test('snapshot excludes private files, old public metadata and operational key fallback', async () => {
  const outputDir = destination();
  const receipt = await prepare({ outputDir });
  const names = receipt.files.map(x => x.path);
  assert.ok(names.every(path => !/^(?:\.git|\.vercel|\.env|node_modules|artifacts|test|docs|supabase|policy)(?:\/|\.|$)/u.test(path)));
  assert.ok(!names.includes('public/aleph.json'));
  assert.ok(!names.includes('vercel.json'), 'Vercel CLI owns the remote deployment config');
  assert.equal(receipt.deploymentConfigSha256,
    sha(await readFile(join(outputDir, 'vercel.json'))));
  const deploymentConfig = JSON.parse(await readFile(join(outputDir, 'vercel.json')));
  assert.equal(deploymentConfig.buildCommand, 'npm run build');
  assert.equal(deploymentConfig.installCommand, 'npm ci');
  assert.equal(deploymentConfig.outputDirectory, 'public');
  assert.ok(!names.includes('bundle-notes.json'));
  for (const path of ['data.json', 'public/data.json']) {
    assert.deepEqual(JSON.parse(await readFile(join(outputDir, path))), { notes: [] });
  }
  const auth = await readFile(join(outputDir, 'api/auth.js'), 'utf8');
  assert.ok(!auth.includes('sb_publishable_'));
  assert.match(auth, /const authKey = process\.env\.SUPABASE_PUBLISHABLE_KEY;/u);
  assert.deepEqual(receipt.requiredEnvironment,
    ['SUPABASE_URL', 'SUPABASE_PUBLISHABLE_KEY', 'SUPABASE_SECRET_KEY']);
  assert.ok(!JSON.stringify(receipt).includes(new URL(config.identityProvider.issuer).hostname));
  const upload = await readFile(join(outputDir, '.vercelignore'), 'utf8');
  assert.ok(!upload.startsWith('*\n'), 'Do not exclude api/src/public with a blanket rule');
  for (const deny of ['.env.*', '.vercel/**', 'node_modules/**', '.git/**']) {
    assert.ok(upload.split('\n').includes(deny));
  }
  assert.ok(!upload.includes('!.env'));
});

test('source and prepared fingerprints are deterministic and all prepared file hashes match', async () => {
  const firstDir = destination();
  const first = await prepare({ outputDir: firstDir });
  const second = await prepare();
  assert.equal(first.sourceFingerprint, second.sourceFingerprint);
  assert.equal(first.preparedFingerprint, second.preparedFingerprint);
  assert.notEqual(first.sourceFingerprint, first.preparedFingerprint);
  const entries = [];
  for (const file of first.files) {
    const hash = sha(await readFile(join(firstDir, file.path)));
    assert.equal(hash, file.sha256);
    entries.push({ path: file.path, sha256: hash });
  }
  assert.equal(sha(JSON.stringify(entries)), first.preparedFingerprint);
});

for (const [name, overrides, error] of [
  ['production origin', { origin: config.publicAppUrl }, /PRODUCTION_ORIGIN_FORBIDDEN/u],
  ['production alias', { origin: 'https://choi-bujang-secret-vault-git-main-example.vercel.app' }, /PRODUCTION_ORIGIN_FORBIDDEN/u],
  ['unencrypted origin', { origin: 'http://s11-isolated-fixture.vercel.app' }, /INVALID_ORIGIN/u],
  ['origin with path', { origin: origin + '/notes' }, /INVALID_ORIGIN/u],
  ['origin with query', { origin: origin + '?trial=1' }, /INVALID_ORIGIN/u],
  ['production database', { supabaseRef: new URL(config.identityProvider.issuer).hostname.split('.')[0] }, /PRODUCTION_DATABASE_FORBIDDEN/u],
  ['invalid database ref', { supabaseRef: 'invalid-ref' }, /INVALID_SUPABASE_REF/u],
]) {
  test(`preparation rejects ${name} before creating any output`, async () => {
    const outputDir = destination();
    await assert.rejects(prepare({ outputDir, ...overrides }), error);
    await assert.rejects(readdir(outputDir), { code: 'ENOENT' });
  });
}

test('existing destination and source-tree destination cannot be overwritten', async () => {
  const outputDir = destination();
  await prepare({ outputDir });
  const receiptBefore = await readFile(join(outputDir, 'https-snapshot.json'));
  await assert.rejects(prepare({ outputDir }), /OUTPUT_EXISTS/u);
  assert.deepEqual(await readFile(join(outputDir, 'https-snapshot.json')), receiptBefore);
  await assert.rejects(prepare({ outputDir: join(root, 'api', 'snapshot') }), /OUTPUT_MUST_BE_ARTIFACTS_OR_TEMP/u);
});

function build(outputDir, overrides = {}) {
  // Only OS runtime essentials enter the child; no existing application credentials.
  const env = {};
  for (const key of ['PATH', 'Path', 'SystemRoot', 'SYSTEMROOT', 'TEMP', 'TMP', 'COMSPEC']) {
    if (process.env[key] !== undefined) env[key] = process.env[key];
  }
  Object.assign(env, { SUPABASE_URL: backend,
    SUPABASE_PUBLISHABLE_KEY: 'NONSECRET_SYNTHETIC_PUBLISHABLE_VALUE',
    SUPABASE_SECRET_KEY: 'NONSECRET_SYNTHETIC_SERVER_VALUE' }, overrides);
  try {
    const stdout = execFileSync(process.execPath, ['scripts/build-device-https.mjs'], {
      cwd: outputDir, env, encoding: 'utf8', windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'], timeout: 20000,
    });
    return { status: 0, stdout, stderr: '' };
  } catch (error) {
    return { status: error.status, stdout: String(error.stdout), stderr: String(error.stderr) };
  }
}

test('test build refuses missing trial credentials and production backend configuration', async () => {
  const outputDir = destination();
  await prepare({ outputDir });
  for (const overrides of [{ SUPABASE_PUBLISHABLE_KEY: '' }, { SUPABASE_SECRET_KEY: '' },
    { SUPABASE_URL: new URL(config.identityProvider.issuer).origin }]) {
    const result = build(outputDir, overrides);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /HTTPS_TEST_ENVIRONMENT_REQUIRED/u);
    assert.ok(!result.stderr.includes('NONSECRET_SYNTHETIC_'));
  }
});

test('Vercel-managed config normalization cannot break application source verification', async () => {
  const outputDir = destination();
  const receipt = await prepare({ outputDir });
  // Simulate Vercel adding its internal normalized deployment settings.
  const configFile = join(outputDir, 'vercel.json');
  const configBefore = JSON.parse(await readFile(configFile, 'utf8'));
  await writeFile(configFile, JSON.stringify({
    ...configBefore,
    platformGeneratedSettings: { normalized: true },
  }) + '\n');
  assert.notEqual(sha(await readFile(configFile)), receipt.deploymentConfigSha256);
  await symlink(join(root, 'node_modules'), join(outputDir, 'node_modules'),
    process.platform === 'win32' ? 'junction' : 'dir');
  try {
    const result = build(outputDir);
    assert.equal(result.status, 0, result.stderr);
    const metadata = JSON.parse(await readFile(join(outputDir, 'public/aleph.json')));
    assert.equal(metadata.deploymentConfigSha256, receipt.deploymentConfigSha256);
  } finally {
    await unlink(join(outputDir, 'node_modules'));
  }
});

test('test build rejects changed source before loading application dependencies', async () => {
  const outputDir = destination();
  await prepare({ outputDir });
  await writeFile(join(outputDir, 'api/devices.js'), '// Changed after preparation.\n');
  const result = build(outputDir);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /HTTPS_SNAPSHOT_CHANGED/u);
});

test('isolated local build emits explicit dirty-snapshot metadata and no production identity', async () => {
  const outputDir = destination();
  const receipt = await prepare({ outputDir });
  const link = join(outputDir, 'node_modules');
  await symlink(join(root, 'node_modules'), link, process.platform === 'win32' ? 'junction' : 'dir');
  try {
    const result = build(outputDir);
    assert.equal(result.status, 0, result.stderr);
    const metadata = JSON.parse(await readFile(join(outputDir, 'public/aleph.json')));
    assert.equal(metadata.commit, null);
    assert.equal(metadata.baselineCommit, receipt.baselineCommit);
    assert.equal(metadata.notForSubmission, true);
    assert.equal(metadata.sourceState, expectedSourceState());
    assert.equal(metadata.preparedFingerprint, receipt.preparedFingerprint);
    assert.equal(metadata.publicAppUrl, origin);
    assert.equal(metadata.rpID, new URL(origin).hostname);
    assert.equal(metadata.step, config.step);
    assert.equal(metadata.restoreRoute, config.restoreRoute);
    assert.deepEqual(JSON.parse(await readFile(join(outputDir, 'public/data.json'))), { notes: [] });
    const operations = JSON.parse(await readFile(join(outputDir, 'public/operations-manifest.json'), 'utf8'));
    assert.equal(operations.deployment.publicOrigin, origin);
    assert.equal(operations.deployment.step, config.step);
  } finally {
    await unlink(link);
  }
});

test('test-only base SQL guards existing application data before any schema creation', async () => {
  const sql = await readFile(join(root, 'test/fixtures/device-https-base.sql'), 'utf8');
  const guard = sql.indexOf('TEST_FIXTURE_REQUIRES_EMPTY_APPLICATION_DATABASE');
  assert.ok(guard > 0 && guard < sql.indexOf('create schema'));
  for (const table of ['memos', 'memo_restore_backups', 'memo_restore_audit', 'vault_notices', 'vault_instructors']) {
    assert.ok(sql.includes(`alter table public.${table} enable row level security;`));
  }
  assert.ok(!/^insert\s+into/im.test(sql));
  assert.match(sql, /public_id uuid unique not null/u);
  assert.match(sql, /from public, anon, authenticated, service_role;/u);
  assert.match(sql, /\bbegin;[\s\S]*\bcommit;/u);
});

test('preparation and local builds preserve every original tracked and uncommitted source file', async () => {
  for (const [path, hash] of originals) {
    assert.equal(sha(await readFile(join(root, path))), hash, `Original file changed: ${path}`);
  }
});
