import { handleRestore } from './[id].js';
import { restoreItemTarget } from '../../src/device-request.mjs';

// The legacy /api/restore/:id route remains for step 10 compatibility. The
// step 11 UI uses this static Function route so its signed external query is
// not confused with a Vercel dynamic-route parameter.
export default async function handler(req, res) {
  const target = restoreItemTarget(req);
  if (!target.exact) {
    res.setHeader('Cache-Control', 'no-store');
    return res.status(400).json({ error: 'INVALID_RESTORE_TARGET' });
  }
  return handleRestore(req, res, target.id);
}
