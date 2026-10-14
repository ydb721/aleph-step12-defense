import restoreById from './restore/[id].js';

// Both entry points use the same authenticated recovery and pinned backup.
export default async function handler(req, res) {
  if (req.method !== 'POST') return restoreById(req, res);
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
  return restoreById({ ...req, query: { ...req.query, id }, body: options }, res);
}
