import { handleMemos } from '../memos.js';
import { memoItemTarget } from '../../src/device-request.mjs';

// A static Function route keeps the user-supplied item id in the exact query
// that signedFetch binds. Dynamic [id] routes cannot distinguish framework
// parameters from an external ?id query after Vercel has routed the request.
export default async function handler(req, res) {
  const target = memoItemTarget(req);
  return handleMemos(req, res, target.id, { targetValid: target.exact });
}
