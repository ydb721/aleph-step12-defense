import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';

// Static localhost preview only. No production API proxy, credentials or database.
const files = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/index.html', ['index.html', 'text/html; charset=utf-8']],
  ['/offline.html', ['offline.html', 'text/html; charset=utf-8']],
  ['/manifest.webmanifest', ['manifest.webmanifest', 'application/manifest+json; charset=utf-8']],
  ['/pwa.mjs', ['pwa.mjs', 'text/javascript; charset=utf-8']],
  ['/device.mjs', ['device.mjs', 'text/javascript; charset=utf-8']],
  ['/operations.mjs', ['operations.mjs', 'text/javascript; charset=utf-8']],
  ['/operations-manifest.json', ['operations-manifest.json', 'application/json; charset=utf-8']],
  ['/vendor/simplewebauthn-browser.js', ['vendor/simplewebauthn-browser.js', 'text/javascript; charset=utf-8']],
  ['/vendor/simplewebauthn-browser.umd.js', ['vendor/simplewebauthn-browser.umd.js', 'text/javascript; charset=utf-8']],
  ['/vendor/simplewebauthn-LICENSE.md', ['vendor/simplewebauthn-LICENSE.md', 'text/plain; charset=utf-8']],
  ['/sw.js', ['sw.js', 'text/javascript; charset=utf-8']],
  ['/icons/icon-192.png', ['icons/icon-192.png', 'image/png']],
  ['/icons/icon-512.png', ['icons/icon-512.png', 'image/png']],
  ['/icons/apple-touch-icon.png', ['icons/apple-touch-icon.png', 'image/png']],
]);

createServer(async (request, response) => {
  const pathname = new URL(request.url, 'http://127.0.0.1:4173').pathname;
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Cache-Control', 'no-store');
  if (pathname === '/api' || pathname.startsWith('/api/')) {
    response.writeHead(503, { 'Content-Type': 'application/json; charset=utf-8' });
    response.end(JSON.stringify({ error: 'LOCAL_STATIC_PREVIEW_ONLY' }));
    return;
  }
  if (!['GET', 'HEAD'].includes(request.method)) {
    response.writeHead(405, { Allow: 'GET, HEAD' });
    response.end();
    return;
  }
  const file = files.get(pathname);
  if (!file) {
    response.writeHead(404);
    response.end();
    return;
  }
  try {
    const body = await readFile(new URL('../public/' + file[0], import.meta.url));
    response.writeHead(200, {
      'Content-Type': file[1],
      'Cache-Control': pathname === '/sw.js' ? 'no-store' : 'public, max-age=0, must-revalidate',
    });
    response.end(request.method === 'HEAD' ? undefined : body);
  } catch {
    response.writeHead(404);
    response.end();
  }
}).listen(4173, '127.0.0.1', () => {
  console.log('PWA 정적 미리보기: http://127.0.0.1:4173/');
  console.log('로그인·메모·복원 API는 제공하지 않으며 운영 서버로 전달하지 않습니다. 종료: Ctrl+C');
});
