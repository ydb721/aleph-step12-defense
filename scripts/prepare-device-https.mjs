import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, mkdir, readFile, readdir, realpath, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, extname, isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const SHA = /^[a-f0-9]{40}$/u;
const REF = /^[a-z]{20}$/u;
const APP = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.vercel\.app$/u;
const RECEIPT = 'https-snapshot.json';
const ROOT_FILES = ['package.json', 'package-lock.json', 'aleph.config.json', 'vercel.json'];
const BUILD_FILES = ['scripts/build-public.mjs', 'scripts/deployment-identity.mjs'];
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const digest = value => createHash('sha256').update(value).digest('hex');
const posix = value => value.split(sep).join('/');
const within = (parent, child) => {
  const path = relative(parent, child);
  return path === '' || path !== '..' && !path.startsWith('..' + sep) && !isAbsolute(path);
};
const fail = code => { throw new Error(code); };

async function noLinks(path) {
  let current = resolve(path);
  for (;;) {
    try {
      const stat = await lstat(current);
      if (stat.isSymbolicLink()) fail('HTTPS_SNAPSHOT_LINK_NOT_ALLOWED');
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
    const parent = dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

async function sourceFile(root, path) {
  const target = resolve(root, path);
  if (!within(root, target)) fail('HTTPS_SNAPSHOT_SOURCE_OUTSIDE_ROOT');
  await noLinks(target);
  const stat = await lstat(target);
  if (!stat.isFile() || !within(root, await realpath(target))) fail('HTTPS_SNAPSHOT_INVALID_SOURCE');
  return readFile(target);
}

async function runtimePaths(root, directory) {
  const result = [];
  async function visit(path) {
    const absolute = resolve(root, path);
    await noLinks(absolute);
    for (const entry of await readdir(absolute, { withFileTypes: true })) {
      const name = posix(path + '/' + entry.name);
      if (entry.isSymbolicLink()) fail('HTTPS_SNAPSHOT_LINK_NOT_ALLOWED');
      if (entry.name.startsWith('.') || entry.name === 'node_modules') continue;
      if (entry.isDirectory()) { await visit(name); continue; }
      if (!entry.isFile()) fail('HTTPS_SNAPSHOT_INVALID_SOURCE');
      if (name === 'public/aleph.json' || name === 'public/data.json') continue;
      const extension = extname(entry.name).toLowerCase();
      const allowed = directory === 'public'
        ? ['.html', '.css', '.js', '.mjs', '.webmanifest', '.png', '.svg', '.ico'].includes(extension)
          || name === 'public/vendor/simplewebauthn-LICENSE.md'
        : ['.js', '.mjs'].includes(extension);
      if (allowed) result.push(name);
    }
  }
  await visit(directory);
  return result;
}

function trialOrigin(value, productionOrigin) {
  let url;
  let production;
  try { url = new URL(value); production = new URL(productionOrigin); }
  catch { fail('HTTPS_SNAPSHOT_INVALID_ORIGIN'); }
  if (typeof value !== 'string' || value !== value.trim() || url.protocol !== 'https:'
      || !APP.test(url.hostname) || url.username || url.password || url.port
      || url.pathname !== '/' || url.search || url.hash) fail('HTTPS_SNAPSHOT_INVALID_ORIGIN');
  const productionName = production.hostname.replace(/\.vercel\.app$/u, '')
    .replace(/-(?:pink|git-main-[a-z0-9-]+)$/u, '');
  if (url.origin === production.origin || url.hostname === production.hostname
      || url.hostname === productionName + '.vercel.app'
      || url.hostname.startsWith(productionName + '-')) fail('HTTPS_SNAPSHOT_PRODUCTION_ORIGIN_FORBIDDEN');
  return url.origin;
}

// This generated wrapper belongs to the isolated snapshot, never the production tree.
const BUILD_WRAPPER = String.raw`import { createHash } from 'node:crypto';
import { lstat, readFile, readdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const root = resolve(import.meta.dirname, '..');
const receipt = JSON.parse(await readFile(resolve(root, 'https-snapshot.json'), 'utf8'));
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const invalid = () => { throw new Error('HTTPS_TEST_ENVIRONMENT_REQUIRED'); };
let backend;
try { backend = new URL(process.env.SUPABASE_URL); } catch { invalid(); }
if (backend.origin !== receipt.supabaseOrigin || backend.pathname !== '/' || backend.search
    || backend.hash || backend.username || backend.password || backend.port) invalid();
for (const name of ['SUPABASE_PUBLISHABLE_KEY', 'SUPABASE_SECRET_KEY']) {
  const key = process.env[name];
  if (typeof key !== 'string' || key.length < 20 || key !== key.trim()) invalid();
}
if (receipt.forbiddenPublishableKeyHashes.includes(digest(process.env.SUPABASE_PUBLISHABLE_KEY))) invalid();

async function verifySnapshot() {
  const entries = [];
  const expected = new Set(receipt.files.map(file => file.path));
  async function walk(directory) {
    for (const entry of await readdir(resolve(root, directory), { withFileTypes: true })) {
      const path = directory + '/' + entry.name;
      if (entry.isSymbolicLink()) throw new Error('HTTPS_SNAPSHOT_CHANGED');
      if (path === 'public/aleph.json') continue;
      if (entry.isDirectory()) { await walk(path); continue; }
      if (!entry.isFile() || !expected.has(path)) throw new Error('HTTPS_SNAPSHOT_CHANGED');
    }
  }
  for (const directory of ['api', 'src', 'public', 'scripts']) await walk(directory);
  for (const file of receipt.files) {
    const path = resolve(root, file.path);
    const stat = await lstat(path);
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('HTTPS_SNAPSHOT_CHANGED');
    const sha256 = digest(await readFile(path));
    if (sha256 !== file.sha256) throw new Error('HTTPS_SNAPSHOT_CHANGED');
    entries.push({ path: file.path, sha256 });
  }
  if (digest(JSON.stringify(entries)) !== receipt.preparedFingerprint) throw new Error('HTTPS_SNAPSHOT_CHANGED');
}

await verifySnapshot();
// --local omits the production Git identity writer. It does not change any API guard.
const previousArgs = process.argv;
process.argv = [...process.argv, '--local'];
try { await import(pathToFileURL(resolve(root, 'scripts/build-public.mjs')).href); }
finally { process.argv = previousArgs; }
await verifySnapshot();
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
const metadata = {
  schema: 'byteback.device-https.test-deployment.v1', notForSubmission: true,
  sourceState: receipt.sourceState, sourceFingerprint: receipt.sourceFingerprint,
  preparedFingerprint: receipt.preparedFingerprint,
  baselineCommit: receipt.baselineCommit, commit: null, step: config.step,
  deploymentConfigSha256: receipt.deploymentConfigSha256,
  publicAppUrl: config.publicAppUrl, rpID: new URL(config.publicAppUrl).hostname,
  judgeIssuer: config.judgeIssuer, allowedRoutes: config.allowedRoutes,
  originalApiUrl: config.originalApiUrl, restoreRoute: config.restoreRoute,
};
await writeFile(resolve(root, 'public/aleph.json'), JSON.stringify(metadata, null, 2) + '\n', 'utf8');
console.log('Isolated HTTPS test snapshot built; not a judge submission or production commit.');
`;

/** Create an offline deployment snapshot. No resources, credentials, Git refs or deployments are created. */
export async function prepareDeviceHttps({ root = ROOT, outputDir, origin, supabaseRef } = {}) {
  root = resolve(root);
  await noLinks(root);
  root = await realpath(root);
  const config = JSON.parse(await sourceFile(root, 'aleph.config.json'));
  // The snapshot remains explicitly non-submission, but it must be able to
  // exercise the current Step 10+ candidate without rewriting its step.
  if (!Number.isInteger(config.step) || config.step < 10 || config.step > 12) {
    fail('HTTPS_SNAPSHOT_SUPPORTED_STEP_REQUIRED');
  }
  const appOrigin = trialOrigin(origin, config.publicAppUrl);
  if (!REF.test(supabaseRef || '')) fail('HTTPS_SNAPSHOT_INVALID_SUPABASE_REF');
  const supabaseOrigin = 'https://' + supabaseRef + '.supabase.co';
  if (new URL(config.identityProvider.issuer).origin === supabaseOrigin
      || new URL(config.originalApiUrl).origin === supabaseOrigin) {
    fail('HTTPS_SNAPSHOT_PRODUCTION_DATABASE_FORBIDDEN');
  }
  const git = (...args) => execFileSync('git', ['-C', root, ...args], {
    encoding: 'utf8', timeout: 5000, maxBuffer: 1024 * 1024, windowsHide: true,
    env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0' },
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
  let baselineCommit;
  let sourceDirty;
  try {
    baselineCommit = git('rev-parse', '--verify', 'HEAD');
    sourceDirty = git('status', '--porcelain', '--untracked-files=all') !== '';
  } catch { fail('HTTPS_SNAPSHOT_GIT_BASELINE_REQUIRED'); }
  if (!SHA.test(baselineCommit)) fail('HTTPS_SNAPSHOT_GIT_BASELINE_REQUIRED');
  const destination = resolve(outputDir ?? resolve(root, 'artifacts', 'device-https-lab'));
  if (within(root, destination) && !within(resolve(root, 'artifacts'), destination)
      || !within(root, destination) && !within(resolve(tmpdir()), destination)) {
    fail('HTTPS_SNAPSHOT_OUTPUT_MUST_BE_ARTIFACTS_OR_TEMP');
  }
  if (destination === resolve(root, 'artifacts') || destination === resolve(tmpdir())) {
    fail('HTTPS_SNAPSHOT_OUTPUT_MUST_BE_NEW_DIRECTORY');
  }
  await noLinks(destination);
  try { await lstat(destination); fail('HTTPS_SNAPSHOT_OUTPUT_EXISTS'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }

  const paths = [...ROOT_FILES, ...BUILD_FILES];
  for (const directory of ['api', 'src', 'public']) paths.push(...await runtimePaths(root, directory));
  const files = new Map();
  for (const path of paths.sort()) {
    const bytes = await sourceFile(root, path);
    // Reject obvious embedded credentials; never include matching bytes in the error.
    if (!['.png', '.ico'].includes(extname(path).toLowerCase())
        && /-----BEGIN [A-Z ]*PRIVATE KEY-----|\bsb_secret_[A-Za-z0-9_-]{12,}|\bBearer\s+[A-Za-z0-9._~+/-]{20,}/u.test(bytes.toString('utf8'))) {
      fail('HTTPS_SNAPSHOT_EMBEDDED_SECRET_REJECTED');
    }
    files.set(path, bytes);
  }
  const sourceEntries = [...files].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
    .map(([path, bytes]) => ({ path, sha256: digest(bytes) }));
  const authSource = files.get('api/auth.js').toString('utf8');
  const fallbackPattern = /const authKey = process\.env\.SUPABASE_PUBLISHABLE_KEY\s*\|\|\s*'(sb_publishable_[A-Za-z0-9_-]+)';/gu;
  const fallbackMatches = [...authSource.matchAll(fallbackPattern)];
  if (fallbackMatches.length !== 1) fail('HTTPS_SNAPSHOT_AUTH_FALLBACK_PATTERN_CHANGED');
  const forbiddenPublishableKeyHashes = [digest(fallbackMatches[0][1])];
  files.set('api/auth.js', Buffer.from(authSource.replace(fallbackPattern,
    'const authKey = process.env.SUPABASE_PUBLISHABLE_KEY;')));
  const trialConfig = structuredClone(config);
  trialConfig.publicAppUrl = appOrigin;
  trialConfig.identityProvider.issuer = supabaseOrigin + '/auth/v1';
  trialConfig.identityProvider.jwksUrl = supabaseOrigin + '/auth/v1/.well-known/jwks.json';
  trialConfig.originalApiUrl = supabaseOrigin + '/rest/v1/memos';
  const packageJson = JSON.parse(files.get('package.json'));
  packageJson.scripts.build = 'node scripts/build-device-https.mjs';
  const vercel = JSON.parse(files.get('vercel.json'));
  // Deployment configuration is consumed/normalized by Vercel CLI and is not
  // an immutable runtime source file. Validate its security-sensitive source
  // contents before uploading; never rely on byte equality after CLI handling.
  const allowedDeploymentKeys = new Set(['$schema', 'framework', 'buildCommand',
    'outputDirectory', 'headers']);
  const expectedHeaders = [{ source: '/(.*)', headers: [
    { key: 'X-Content-Type-Options', value: 'nosniff' },
  ] }];
  if (Object.keys(vercel).some(key => !allowedDeploymentKeys.has(key))
      || vercel.framework !== null || vercel.buildCommand !== 'npm run build'
      || vercel.outputDirectory !== 'public'
      || JSON.stringify(vercel.headers) !== JSON.stringify(expectedHeaders)) {
    fail('HTTPS_SNAPSHOT_INVALID_DEPLOYMENT_CONFIG');
  }
  vercel.buildCommand = 'npm run build';
  vercel.installCommand = 'npm ci';
  for (const [path, value] of [['aleph.config.json', trialConfig], ['package.json', packageJson], ['vercel.json', vercel]]) {
    files.set(path, Buffer.from(JSON.stringify(value, null, 2) + '\n'));
  }
  // npm ci preserves the dependency graph. Normalize only Windows line endings in this copy.
  files.set('package-lock.json', Buffer.from(files.get('package-lock.json').toString('utf8').replace(/\r\n/gu, '\n')));
  files.set('data.json', Buffer.from('{\n  "notes": []\n}\n'));
  files.set('public/data.json', Buffer.from('{\n  "notes": []\n}\n'));
  files.set('scripts/build-device-https.mjs', Buffer.from(BUILD_WRAPPER));
  // A second boundary: only the deployment runtime and its nonsecret receipt are uploaded.
  // The snapshot is constructed from an explicit allowlist. Do not apply a
  // second broad '*' ignore here: Vercel CLI ignores the negated directories
  // and can upload only a handful of root files instead of api/src/public.
  // Deny unexpected local tooling and credentials added later by `vercel link`.
  files.set('.vercelignore', Buffer.from([
    '.env', '.env.*', '**/.env', '**/.env.*',
    '.git', '.git/**', '.vercel', '.vercel/**',
    'node_modules', 'node_modules/**',
    'artifacts', 'artifacts/**',
    '*.log', 'npm-debug.log*',
    '',
  ].join('\n')));
  const forbiddenReferences = [new URL(config.publicAppUrl).hostname,
    new URL(config.identityProvider.issuer).hostname.split('.')[0]];
  for (const [path, bytes] of files) {
    if (['.png', '.ico'].includes(extname(path).toLowerCase())) continue;
    const text = bytes.toString('utf8');
    if (forbiddenReferences.some(reference => text.includes(reference))
        || /\bsb_publishable_[A-Za-z0-9_-]+/u.test(text)) {
      fail('HTTPS_SNAPSHOT_PRODUCTION_REFERENCE_REJECTED');
    }
  }
  // Vercel CLI may normalize vercel.json between upload and remote build,
  // including changing JSON properties. Its prepared bytes are attested here,
  // but remote source integrity is checked for the *application* files only.
  // Likewise, .vercelignore is an upload policy and may not be uploaded.
  const deploymentConfigSha256 = digest(files.get('vercel.json'));
  const entries = [...files].filter(([path]) => !['.vercelignore', 'vercel.json'].includes(path))
    .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
    .map(([path, bytes]) => ({ path, sha256: digest(bytes) }));
  const receipt = {
    schema: 'byteback.device-https.snapshot.v1', notForSubmission: true,
    baselineCommit, commit: null, sourceDirty,
    sourceState: sourceDirty ? 'uncommitted-snapshot' : 'local-snapshot',
    sourceFingerprint: digest(JSON.stringify(sourceEntries)),
    preparedFingerprint: digest(JSON.stringify(entries)), origin: appOrigin,
    rpID: new URL(appOrigin).hostname, supabaseOrigin,
    requiredEnvironment: ['SUPABASE_URL', 'SUPABASE_PUBLISHABLE_KEY', 'SUPABASE_SECRET_KEY'],
    uploadPolicySha256: digest(files.get('.vercelignore')),
    deploymentConfigSha256,
    forbiddenPublishableKeyHashes,
    sourceFiles: sourceEntries,
    files: entries,
  };
  // No creation occurs until every input and source file has passed validation.
  await mkdir(dirname(destination), { recursive: true });
  await noLinks(dirname(destination));
  await mkdir(destination);
  for (const [path, bytes] of files) {
    const target = resolve(destination, path);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, bytes, { flag: 'wx' });
  }
  await writeFile(resolve(destination, RECEIPT), JSON.stringify(receipt, null, 2) + '\n', { flag: 'wx' });
  return receipt;
}

async function cli(args) {
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    console.log('Offline preparation only; creates no remote resources or deployments.\n'
      + 'node scripts/prepare-device-https.mjs --origin https://TRIAL-NAME.vercel.app '
      + '--supabase-ref NEW_20_LETTER_REF [--output artifacts/device-https-lab]\n'
      + 'Use a new trial project. Never supply keys as command arguments.');
    return;
  }
  const options = {};
  const names = new Map([['--origin', 'origin'], ['--supabase-ref', 'supabaseRef'], ['--output', 'outputDir']]);
  for (let index = 0; index < args.length; index += 2) {
    const name = names.get(args[index]);
    if (!name || options[name] !== undefined || typeof args[index + 1] !== 'string'
        || args[index + 1].startsWith('--')) fail('HTTPS_SNAPSHOT_INVALID_ARGUMENTS');
    options[name] = args[index + 1];
  }
  const receipt = await prepareDeviceHttps(options);
  console.log(JSON.stringify({ preparedLocally: true, remoteCreated: false, deployed: false,
    origin: receipt.origin, rpID: receipt.rpID, baselineCommit: receipt.baselineCommit,
    sourceFingerprint: receipt.sourceFingerprint, preparedFingerprint: receipt.preparedFingerprint,
    sourceState: receipt.sourceState,
    notForSubmission: true, fileCount: receipt.files.length }, null, 2));
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  cli(process.argv.slice(2)).catch(error => {
    console.error(/^HTTPS_[A-Z_]+$/u.test(error?.message ?? '') ? error.message : 'HTTPS_SNAPSHOT_PREPARATION_FAILED');
    process.exitCode = 1;
  });
}
