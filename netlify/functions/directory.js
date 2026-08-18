/* Revival Team Directory — server endpoint (Netlify Function).
 *
 * The browser never sees a storage credential. It only knows this path.
 *   GET  /api/directory   → public. Returns the directory, or null if empty.
 *   POST /api/directory   → {action:'auth', password} → checks the admin password.
 *   PUT  /api/directory   → {data} with an x-admin-key header. Saves.
 *
 * Storage is Netlify Blobs — built into the platform, nothing to provision.
 * The only thing you configure is ADMIN_KEY.
 */
import { getStore } from '@netlify/blobs';
import { timingSafeEqual } from 'node:crypto';

const KEY = 'current';

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' }
  });

/* Compare in constant time so the response time can't be used to guess the
   password one character at a time. */
function sameSecret(given, expected) {
  const a = Buffer.from(String(given || ''), 'utf8');
  const b = Buffer.from(String(expected || ''), 'utf8');
  if (a.length !== b.length) { timingSafeEqual(a, a); return false; }
  return timingSafeEqual(a, b);
}

function looksLikeDirectory(d) {
  return !!d && Array.isArray(d.sites) && Array.isArray(d.depts) && Array.isArray(d.admins);
}

export default async (req) => {
  const store = getStore('revival-directory');
  const adminKey = process.env.ADMIN_KEY || '';

  if (req.method === 'GET') {
    try {
      const data = await store.get(KEY, { type: 'json' });
      return json(data ?? null);
    } catch (e) {
      return json({ error: 'Could not read storage.' }, 500);
    }
  }

  if (req.method === 'POST') {
    let body = {};
    try { body = await req.json(); } catch (e) {}
    if (body.action !== 'auth') return json({ error: 'Unknown action.' }, 400);
    /* Slow every attempt down equally — makes guessing impractical. */
    await new Promise(r => setTimeout(r, 250));
    if (!adminKey) return json({ error: 'ADMIN_KEY is not set on the server.' }, 500);
    if (!sameSecret(body.password, adminKey)) return json({ error: 'Wrong password.' }, 401);
    return json({ ok: true });
  }

  if (req.method === 'PUT') {
    if (!adminKey) return json({ error: 'ADMIN_KEY is not set on the server.' }, 500);
    if (!sameSecret(req.headers.get('x-admin-key'), adminKey))
      return json({ error: 'Not authorised.' }, 401);

    let body = null;
    try { body = await req.json(); } catch (e) {}
    if (!body || !looksLikeDirectory(body.data))
      return json({ error: 'That payload does not look like directory data.' }, 400);

    try {
      await store.setJSON(KEY, body.data);
      return json({ ok: true });
    } catch (e) {
      return json({ error: 'Could not write to storage.' }, 500);
    }
  }

  return json({ error: 'Method not allowed.' }, 405);
};

/* Serve this function at /api/directory, which is the path the page expects. */
export const config = { path: '/api/directory' };
