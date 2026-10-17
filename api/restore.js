import { handleRestore } from './restore/[id].js';
import { createRequestTrace, traceRequestShape } from '../src/request-trace.mjs';
import { readVerifiedRequest } from '../src/device-request.mjs';

// Both entry points use the same authenticated recovery and pinned backup.
export default async function handler(req, res) {
  const trace = createRequestTrace(req, res, 'restore_compat');
  if (req.method !== 'POST') return handleRestore(req, res);
  try { await readVerifiedRequest(req); }
  catch (error) {
    res.setHeader('Cache-Control', 'no-store');
    return res.status(Number.isInteger(error?.status) ? error.status : 400)
      .json({ error: 'INVALID_RESTORE_REQUEST' });
  }
  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { body = null; }
  }
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
  if (!body || typeof body !== 'object' || Array.isArray(body)
      || typeof body.id !== 'string' || !uuid.test(body.id)) {
    res.setHeader('Cache-Control', 'no-store');
    return res.status(400).json({ error: 'INVALID_RESTORE_REQUEST' });
  }
  const { id, ...options } = body;
  trace.target(id);
  traceRequestShape(trace, body);
  trace('route_delegated', { route: 'restore_by_id' });
  return handleRestore(req, res, id, options);
}
