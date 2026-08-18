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
  /* Optional. Leave READER_KEY unset and the directory stays open to anyone
     with the link, exactly as before. Set it and nothing is served without it. */
  const readerKey = process.env.READER_KEY || '';

  /* An admin password also opens the door, so editors need only one password. */
  const mayRead = () => {
    if (!readerKey) return true;
    const given = req.headers.get('x-reader-key') || '';
    return sameSecret(given, readerKey) || (adminKey && sameSecret(given, adminKey));
  };

  if (req.method === 'GET') {
    if (!mayRead()) return json({ error: 'A password is required to view this directory.', needsReader: true }, 401);
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
    if (body.action === 'reader') {
      /* Same deliberate delay as the admin check, so guessing is impractical. */
      await new Promise(r => setTimeout(r, 250));
      if (!readerKey) return json({ ok: true, open: true });
      const given = String(body.password || '');
      if (!sameSecret(given, readerKey) && !(adminKey && sameSecret(given, adminKey)))
        return json({ error: 'Wrong password.' }, 401);
      return json({ ok: true });
    }
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

    /* Refuse to let a page that never received the stored directory overwrite it.
       This happens when a deploy or a blip makes the read fail: the page falls back
       to the built-in starting template, and the first edit would otherwise save
       that template over real content. */
    if (body.data.meta && body.data.meta.loadedFrom === 'seed') {
      let existing = null;
      try { existing = await store.get(KEY, { type: 'json' }); } catch (e) {}
      if (existing) return json({ error: 'Stored directory already exists; refusing to overwrite it with the starting template.' }, 409);
    }

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
