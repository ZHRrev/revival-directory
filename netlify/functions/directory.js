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
import { timingSafeEqual, createHash } from 'node:crypto';

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

/* ────────────────────────────────────────────────────────────────────────────
   Paychex connection check.

   Answers three questions in one go: are the two credentials the right way
   round, does the app have the scope it needs, and what shape is a worker
   record. The last one matters because the directory has to be told which
   payroll field is which, and nobody should have to read that off a screen
   full of real staff data.

   So the reply is built to be safe to pass on: it carries field names, not
   people. Anything personal is replaced before it leaves here, and an email
   address is reduced to its domain, which is the only part that is useful
   for working out which addresses are work ones.

   Credentials live in PAYCHEX_KEY and PAYCHEX_SECRET and are never returned.
   ──────────────────────────────────────────────────────────────────────── */

const PAYCHEX_HOSTS = ['https://api.paychex.com', 'https://api.n1.paychex.com'];
const PRIVATE_FIELD =
  /first|last|middle|given|family|sur|preferred|nick|birth|ssn|tax|social|email|phone|mobile|address|street|postal|line\d|zip|city|county/i;

function fieldPaths(o, prefix = '', out = new Set()) {
  if (Array.isArray(o)) { o.forEach(x => fieldPaths(x, prefix + '[]', out)); return out; }
  if (o && typeof o === 'object') {
    for (const k of Object.keys(o)) fieldPaths(o[k], prefix ? prefix + '.' + k : k, out);
    return out;
  }
  if (prefix) out.add(prefix);
  return out;
}

function redact(o, key = '') {
  if (Array.isArray(o)) return o.slice(0, 4).map(x => redact(x, key));
  if (o && typeof o === 'object') {
    const r = {};
    for (const k of Object.keys(o)) r[k] = redact(o[k], k);
    return r;
  }
  if (typeof o !== 'string' || !o) return o;

  /* Judge the value, not only the name of the field it sits in. Paychex keeps
     an address under "uri" inside a list of contact methods, so a redactor
     that went by field name alone would hand the whole address straight out. */
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(o)) return '(removed)@' + o.split('@').pop();
  const digits = o.replace(/\D/g, '');
  const dateLike = /^\d{4}-\d{2}-\d{2}/.test(o) || /^\d{1,2}\/\d{1,2}\/\d{2,4}$/.test(o);
  if (!dateLike && digits.length >= 7 && /[\s().+-]/.test(o) && /^[+(]?[\d][\d\s().+-]*$/.test(o))
    return '(removed, phone)';

  if (PRIVATE_FIELD.test(key)) return '(removed, ' + o.length + ' chars)';
  return o;
}

async function grab(url, opts, ms = 7000) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), ms);
  try {
    const r = await fetch(url, { ...opts, signal: ac.signal });
    const text = await r.text();
    let body = null; try { body = JSON.parse(text); } catch (e) {}
    /* Paging often lives in a header rather than the body. */
    const headers = {};
    ['link', 'x-total-count', 'x-page-count', 'content-range'].forEach(h => {
      const v = r.headers.get(h); if (v) headers[h] = String(v).slice(0, 300);
    });
    return { status: r.status, body, headers, text: text.slice(0, 400) };
  } catch (e) {
    return { status: 0, body: null, text: String(e && e.message || e) };
  } finally { clearTimeout(t); }
}

async function token(host, id, secret) {
  return grab(host + '/auth/oauth/v2/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'client_credentials', client_id: id, client_secret: secret })
  });
}

async function paychexCheck() {
  const A = process.env.PAYCHEX_KEY || '';
  const B = process.env.PAYCHEX_SECRET || '';
  const steps = [];
  if (!A || !B) {
    return { ok: false, steps,
      problem: !A && !B ? 'Neither PAYCHEX_KEY nor PAYCHEX_SECRET is set on the server.'
             : !A ? 'PAYCHEX_SECRET is set but PAYCHEX_KEY is not.'
                  : 'PAYCHEX_KEY is set but PAYCHEX_SECRET is not.' };
  }

  /* Try each host, and each way round, until something authenticates. */
  let got = null, lastErr = '';
  for (const host of PAYCHEX_HOSTS) {
    for (const [id, secret, order] of [[A, B, 'as set'], [B, A, 'swapped']]) {
      const r = await token(host, id, secret);
      if (r.status === 200 && r.body && r.body.access_token) {
        got = { host, order, access: r.body.access_token, expires: r.body.expires_in };
        break;
      }
      lastErr = (r.body && (r.body.error_description || r.body.error)) || r.text || ('HTTP ' + r.status);
    }
    if (got) break;
  }

  if (!got) {
    return { ok: false, steps,
      problem: 'Neither value worked as the key, in either order.',
      detail: lastErr,
      hint: 'Check the two values came from the same app in Company Settings → Integrated Apps, and that the app is still active.' };
  }
  steps.push({ step: 'Signed in', ok: true,
    detail: got.order === 'as set'
      ? 'PAYCHEX_KEY is the API Key and PAYCHEX_SECRET is the API Secret. Correct as set.'
      : 'The two are the wrong way round — swap the values of PAYCHEX_KEY and PAYCHEX_SECRET in Netlify.',
    host: got.host, swapped: got.order === 'swapped', expiresIn: got.expires });

  const auth = { headers: { authorization: 'Bearer ' + got.access, accept: 'application/json' } };

  const co = await grab(got.host + '/companies?limit=5', auth);
  if (co.status !== 200) {
    steps.push({ step: 'Read companies', ok: false,
      detail: co.status === 401 || co.status === 403
        ? 'Authenticated, but not allowed to read companies. Switch on "Company and worker APIs" (read-only) for the app in Paychex Flex.'
        : 'HTTP ' + co.status + ' — ' + co.text });
    return { ok: false, steps, problem: 'The credentials work, but the app cannot read company data yet.' };
  }
  const companies = (co.body && (co.body.content || co.body.companies || [])) || [];
  steps.push({ step: 'Read companies', ok: true,
    detail: companies.length + ' visible',
    companies: companies.map(c => ({ id: c.companyId || c.id || null, name: c.legalName || c.displayId || c.name || null })) });

  const companyId = companies.length ? (companies[0].companyId || companies[0].id) : null;
  if (!companyId) return { ok: true, steps, problem: 'Signed in, but no company came back to read workers from.' };

  /* Ask for a real sample, not one record. The questions that decide whether
     this can work at all are answered only in bulk: does a terminated worker
     ever come back from this endpoint, how is a status actually spelled, and
     do these people have work addresses on file. None of that can be guessed
     from the documentation, and getting it wrong means a wasted deploy. */
  const wk = await grab(got.host + '/companies/' + encodeURIComponent(companyId) + '/workers?limit=100', auth, 9000);
  if (wk.status !== 200) {
    steps.push({ step: 'Read workers', ok: false, detail: 'HTTP ' + wk.status + ' — ' + wk.text });
    return { ok: false, steps, problem: 'Companies can be read, but workers cannot.' };
  }
  const envelope = wk.body && typeof wk.body === 'object' && !Array.isArray(wk.body)
    ? Object.keys(wk.body) : ['(an array)'];
  const workers = Array.isArray(wk.body) ? wk.body
                : (wk.body && (wk.body.content || wk.body.workers || wk.body.data || [])) || [];
  const sample = workers[0] || null;
  steps.push({ step: 'Read workers', ok: true, detail: workers.length + ' returned (asked for 100)' });

  /* Aggregate counts only. Nothing below identifies anybody. */
  const tally = {};
  const bump = (bucket, v) => {
    if (!v) return;
    tally[bucket] = tally[bucket] || {};
    tally[bucket][v] = (tally[bucket][v] || 0) + 1;
  };
  const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  let withEmail = 0;
  const scan = (o, key, found) => {
    if (Array.isArray(o)) { o.forEach(x => scan(x, key, found)); return; }
    if (o && typeof o === 'object') { for (const k of Object.keys(o)) scan(o[k], k, found); return; }
    if (typeof o !== 'string' || !o) return;
    /* Anything filed under a key with "status" in it, wherever it sits. */
    if (/status|type/i.test(key) && o.length < 40) bump(key, o);
    if (EMAIL.test(o)) { found.mail = true; bump('emailDomains', o.split('@').pop().toLowerCase()); }
  };
  workers.forEach(w => { const found = {}; scan(w, '', found); if (found.mail) withEmail++; });

  /* Field names across the whole sample, not just the first record — an
     optional field that only some people have would otherwise be missed. */
  const allFields = new Set();
  workers.forEach(w => fieldPaths(w, '', allFields));

  return {
    ok: true,
    steps,
    swapped: got.order === 'swapped',
    host: got.host,
    companyId,
    /* Everything below is counts and field names. It is meant to be passed on. */
    recon: {
      returned: workers.length,
      envelope,
      headers: wk.headers || {},
      withAnyEmail: withEmail,
      withoutEmail: workers.length - withEmail,
      values: tally
    },
    fields: [...allFields].sort(),
    sample: sample ? redact(sample) : null
  };
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
      const body = JSON.stringify(data ?? null);
      /* Tag the response so a browser that already has this exact directory gets
         a 304 and downloads nothing. 'no-cache' still means it checks every time,
         so an edit is visible immediately — it just stops re-sending the photos
         on every page load. */
      const etag = 'W/"' + createHash('sha1').update(body).digest('base64') + '"';
      const headers = {
        'content-type': 'application/json',
        'cache-control': 'no-cache',
        'vary': 'x-reader-key',
        etag
      };
      if (req.headers.get('if-none-match') === etag) {
        return new Response(null, { status: 304, headers });
      }
      return new Response(body, { status: 200, headers });
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
    /* Behind the admin key: it reports on the company's payroll setup, which
       is nobody else's business. */
    if (body.action === 'paychex-test') {
      if (!adminKey) return json({ error: 'ADMIN_KEY is not set on the server.' }, 500);
      if (!sameSecret(req.headers.get('x-admin-key'), adminKey))
        return json({ error: 'Not authorised.' }, 401);
      try { return json(await paychexCheck()); }
      catch (e) { return json({ ok: false, problem: 'The check itself failed.', detail: String(e && e.message || e) }, 500); }
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
