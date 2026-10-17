import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const source = resolve(root, 'data.json');
const output = resolve(root, 'public', 'data.json');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));

await mkdir(resolve(root, 'public'), { recursive: true });

// A pinned local browser library; no CDN execution or private credentials.
const browserPackage = resolve(root, 'node_modules', '@simplewebauthn', 'browser');
const browserMetadata = JSON.parse(await readFile(resolve(browserPackage, 'package.json'), 'utf8'));
if (browserMetadata.version !== '14.0.0') throw new Error('Unexpected WebAuthn browser library version');
const vendor = resolve(root, 'public', 'vendor');
await mkdir(vendor, { recursive: true });
await copyFile(resolve(browserPackage, 'dist', 'bundle', 'index.umd.min.js'),
  resolve(vendor, 'simplewebauthn-browser.umd.js'));
await copyFile(resolve(browserPackage, 'LICENSE.md'), resolve(vendor, 'simplewebauthn-LICENSE.md'));
await writeFile(resolve(vendor, 'simplewebauthn-browser.js'),
  "import './simplewebauthn-browser.umd.js';\n"
    + 'export const { startRegistration, startAuthentication } = window.SimpleWebAuthnBrowser;\n', 'utf8');

if (config.step === 1) {
  const data = JSON.parse(await readFile(source, 'utf8'));
  if (!Array.isArray(data.notes)) {
    throw new Error('실습용 공개 자료 형식을 확인하세요. 실제 학생 자료를 넣으면 안 됩니다.');
  }
  await copyFile(source, output);
  console.log('1단계 실습용 공개 자료를 public/data.json에 복사했습니다.');
} else {
  await writeFile(
    output,
    `${JSON.stringify({ notes: [] }, null, 2)}\n`,
    'utf8',
  );
  console.log('2단계 이후 정적 data.json에는 메모와 1단계 확인 표시를 포함하지 않습니다.');
}

if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(
    resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`,
    'utf8',
  );
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}
