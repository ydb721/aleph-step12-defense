// Preserve the bytes received by the server before any JSON or compatibility
// transformation. A parsed object cannot be used to reconstruct signed bytes.
export const RAW_BODY = Symbol.for('byteback.rawBody');
const MAX_BODY_BYTES = 1024 * 1024;
const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';

function requestError(status, code) {
  return Object.assign(new Error(code), { status, code });
}

export function requestTarget(req) {
  const target = req?.url;
  if (typeof target !== 'string' || !target.startsWith('/') || target.startsWith('//')
      || target.length > 8192 || /[\u0000-\u0020\u007f#\\]/u.test(target)) {
    throw requestError(400, 'DEVICE_INVALID_TARGET');
  }
  const separator = target.indexOf('?');
  return separator === -1 ? { path: target, query: '' }
    : { path: target.slice(0, separator), query: target.slice(separator) };
}

// Item actions use static Function routes so Vercel never adds a dynamic route
// parameter to req.url. The entire external query remains request-bound.
function itemTarget(req, path) {
  const target = requestTarget(req);
  if (target.path !== path) return { id: '', exact: false };
  const match = new RegExp('^\\?id=(' + UUID + ')(?:&|$)', 'iu').exec(target.query);
  const id = match?.[1] ?? '';
  return { id, exact: Boolean(id && target.query === '?id=' + id) };
}

export function memoItemTarget(req) {
  return itemTarget(req, '/api/memos/item');
}

export function restoreItemTarget(req) {
  return itemTarget(req, '/api/restore/item');
}

export async function readVerifiedRequest(req) {
  if (Buffer.isBuffer(req?.[RAW_BODY])) return req[RAW_BODY];
  if (!req || typeof req !== 'object') throw requestError(503, 'RAW_BODY_UNAVAILABLE');
  const bodyProperty = Object.getOwnPropertyDescriptor(req, 'body');
  const supplied = bodyProperty && Object.hasOwn(bodyProperty, 'value') ? bodyProperty.value : undefined;
  let raw;
  if (Buffer.isBuffer(supplied) || typeof supplied === 'string') {
    raw = Buffer.isBuffer(supplied) ? supplied : Buffer.from(supplied, 'utf8');
  } else if (['GET', 'HEAD'].includes(req.method)) {
    // Fetch never sends a GET body. Reject transfer encodings and nonempty
    // lengths instead of silently leaving unsigned data on the stream.
    const length = req.headers?.['content-length'];
    if (req.headers?.['transfer-encoding'] || (length !== undefined && String(length) !== '0')
        || supplied !== undefined && supplied !== null) {
      throw requestError(400, 'DEVICE_BODY_NOT_ALLOWED');
    }
    raw = Buffer.alloc(0);
  } else if (typeof req.on === 'function') {
    // Vercel restores an already-read body by replaying data/end through on().
    // readableEnded and async iteration do not reliably see that restored body.
    raw = await new Promise((resolve, reject) => {
      const chunks = [];
      let length = 0;
      let settled = false;
      const timer = setTimeout(() => finish(requestError(503, 'RAW_BODY_UNAVAILABLE')), 5000);
      timer.unref?.();
      function finish(error, bytes) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error) reject(error); else resolve(bytes);
      }
      req.on('error', () => finish(requestError(400, 'DEVICE_INVALID_BODY')));
      req.on('data', chunk => {
        if (settled) return;
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        length += bytes.length;
        if (length > MAX_BODY_BYTES) return finish(requestError(413, 'DEVICE_BODY_TOO_LARGE'));
        chunks.push(bytes);
      });
      req.on('end', () => finish(null, Buffer.concat(chunks)));
    });
  } else {
    throw requestError(503, 'RAW_BODY_UNAVAILABLE');
  }
  if (raw.length > MAX_BODY_BYTES) throw requestError(413, 'DEVICE_BODY_TOO_LARGE');
  if (['GET', 'HEAD'].includes(req.method) && raw.length) {
    throw requestError(400, 'DEVICE_BODY_NOT_ALLOWED');
  }
  Object.defineProperty(req, RAW_BODY, { value: raw, enumerable: true, configurable: false });
  // Existing routes parse JSON themselves. Preserve the original text so null,
  // malformed JSON and JSON strings cannot become an implicit empty command.
  Object.defineProperty(req, 'body', { value: raw.length ? raw.toString('utf8') : undefined,
    writable: true, enumerable: true, configurable: true });
  return raw;
}
