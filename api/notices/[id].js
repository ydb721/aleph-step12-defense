import { handleNotices } from '../notices.js';

export default async function handler(req, res) {
  const pathId = new URL(req.url, 'https://example.invalid').pathname
    .match(/^\/api\/notices\/([^/]+)\/?$/)?.[1];
  const noticeId = req.query?.id ?? pathId ?? '';
  return handleNotices(req, res, noticeId);
}
