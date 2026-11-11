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
/* A blocklist of field names is the wrong shape for this job and it failed:
   Paychex files a Social Security number as legalId.legalIdValue, which names
   neither "ssn" nor "social", so it went straight through. Three defences now,
   because any one of them can be defeated by an unfamiliar field name.      */
const PRIVATE_FIELD =
  /first|last|middle|given|family|sur|preferred|nick|birth|ssn|tax|social|email|phone|mobile|address|street|postal|line\d|zip|city|county|legal|identificat|national|passport|licen[cs]e|account|routing|iban|pronoun|ethnic|race|\bsex\b|sexual|gender|marital|disab|veteran|salary|wage|compensation|payRate|hourlyRate/i;

function fieldPaths(o, prefix = '', out = new Set()) {
  if (Array.isArray(o)) { o.forEach(x => fieldPaths(x, prefix + '[]', out)); return out; }
  if (o && typeof o === 'object') {
    for (const k of Object.keys(o)) fieldPaths(o[k], prefix ? prefix + '.' + k : k, out);
    return out;
  }
  if (prefix) out.add(prefix);
  return out;
}

function redact(o, key = '', parent = '') {
  if (Array.isArray(o)) return o.slice(0, 4).map(x => redact(x, key, parent));
  if (o && typeof o === 'object') {
    /* Defence two: judge the container. A box holding an identifier announces
       itself through a sibling — {legalIdType:'SSN', legalIdValue:'…'} — so
       when the type says identifier, nothing scalar inside it comes out. */
    const declaresId = Object.keys(o).some(k =>
      /type$/i.test(k) && /^(ssn|sin|itin|ein|nationalid|passport|license|licence|tax)/i.test(String(o[k] || '').replace(/[\s_-]/g, '')));
    const r = {};
    for (const k of Object.keys(o)) r[k] = redact(o[k], k, declaresId ? 'legal' : key);
    return r;
  }
  if (typeof o !== 'string' || !o) return o;

  /* Judge the value, not only the name of the field it sits in. Paychex keeps
     an address under "uri" inside a list of contact methods, so a redactor
     that went by field name alone would hand the whole address straight out. */
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(o)) return '(removed)@' + o.split('@').pop();
  /* Defence three: a run of exactly nine digits is a Social Security number
     until proved otherwise. Checked before the phone rule, which would
     otherwise swallow the hyphenated form and mislabel it. Internal record
     ids here are either shorter or far longer, so nothing useful is lost. */
  if (/^\d{9}$/.test(o) || /^\d{3}-\d{2}-\d{4}$/.test(o)) return '(removed, looks like an SSN)';

  const digits = o.replace(/\D/g, '');
  const dateLike = /^\d{4}-\d{2}-\d{2}/.test(o) || /^\d{1,2}\/\d{1,2}\/\d{2,4}$/.test(o);
  if (!dateLike && digits.length >= 7 && /[\s().+-]/.test(o) && /^[+(]?[\d][\d\s().+-]*$/.test(o))
    return '(removed, phone)';

  if (PRIVATE_FIELD.test(key) || PRIVATE_FIELD.test(parent)) return '(removed, ' + o.length + ' chars)';
  return o;
}

/* ────────────────────────────────────────────────────────────────────────────
   What may be taken out of Paychex.

   This is an allowlist, and it is the whole of the privacy design. The earlier
   approach — read the record, then try to strip the sensitive parts out — is
   the wrong shape for the job, and it failed in exactly the way that approach
   always fails: a Social Security number was filed under "legalIdValue", which
   matched none of the patterns that were looking for it.

   So nothing is stripped. Ten fields are copied out by name and the rest of
   the record is dropped on the floor, unread. A worker's pay, bank details,
   Social Security number, date of birth, sex, ethnicity, home address and
   phone number are never copied anywhere, so there is no code path by which
   they can reach the browser, the stored directory, an export or a log.

   The point of a list like this is what happens to the field nobody
   anticipated. If Paychex adds one tomorrow, it is ignored, because it is not
   on the list. Nothing has to be updated for that to be true.

   Every field below is one the directory already shows on a page today.
   ──────────────────────────────────────────────────────────────────────── */

const str = v => (v === 0 ? '0' : String(v == null ? '' : v)).trim();

function workerRow(w, locationName) {
  const n = (w && w.name) || {};
  const st = (w && w.currentStatus) || {};
  const first = str(n.preferredName) || str(n.givenName);
  return {
    empid:  str(w && w.employeeId),                 /* how a person is matched   */
    wid:    str(w && w.workerId),                   /* to ask for an address     */
    name:   [first, str(n.familyName)].filter(Boolean).join(' '),
    title:  str(w && w.job && w.job.title),
    status: str(st.statusType),
    reason: str(st.statusReason),
    since:  str(st.effectiveDate).slice(0, 10),
    loc:    str(locationName || ''),
    dept:   str(w && w.organization && w.organization.name),
    kind:   str(w && w.workerType)                  /* employee or contractor    */
  };
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

/* Sign in, trying each host and each order, so a swapped pair never matters. */
async function paychexAuth() {
  const A = process.env.PAYCHEX_KEY || '';
  const B = process.env.PAYCHEX_SECRET || '';
  if (!A || !B) return { error: 'The Paychex credentials are not set on the server.' };
  let lastErr = '';
  for (const host of PAYCHEX_HOSTS) {
    for (const [id, secret] of [[A, B], [B, A]]) {
      const r = await token(host, id, secret);
      if (r.status === 200 && r.body && r.body.access_token)
        return { host, auth: { headers: { authorization: 'Bearer ' + r.body.access_token, accept: 'application/json' } } };
      lastErr = (r.body && (r.body.error_description || r.body.error)) || r.text || ('HTTP ' + r.status);
    }
  }
  return { error: 'Paychex would not accept those credentials. ' + lastErr };
}

async function firstCompany(host, auth) {
  const co = await grab(host + '/companies?limit=5', auth);
  if (co.status !== 200) return { error: co.status === 401 || co.status === 403
    ? 'The app is not allowed to read company data. Switch on "Company and worker APIs" in Paychex Flex.'
    : 'Could not read companies (HTTP ' + co.status + ').' };
  const list = (co.body && (co.body.content || co.body.companies || [])) || [];
  const id = list.length ? (list[0].companyId || list[0].id) : null;
  return id ? { companyId: id } : { error: 'No company came back to read workers from.' };
}

/* Location names, so a site is something a person recognises rather than a
   sixteen-digit id. Not fatal if it fails — the id still works as a label. */
async function locationNames(host, auth, companyId) {
  const r = await grab(host + '/companies/' + encodeURIComponent(companyId) + '/locations?limit=200', auth);
  const map = {};
  if (r.status !== 200) return map;
  const list = Array.isArray(r.body) ? r.body
             : (r.body && (r.body.content || r.body.locations || r.body.data || [])) || [];
  list.forEach(l => {
    const id = str(l.locationId || l.id);
    const nm = str(l.name || l.locationName || l.displayName || l.description);
    if (id && nm) map[id] = nm;
  });
  return map;
}

/* The roster.

   Only workers whose status changed inside the window are considered at all.
   The directory is already right about everybody else, so the rest of the
   history is noise — and filtering here means the untouched records are
   dropped before anything is copied out of them. */
async function paychexPull(days) {
  const a = await paychexAuth();
  if (a.error) return { ok: false, problem: a.error };
  const c = await firstCompany(a.host, a.auth);
  if (c.error) return { ok: false, problem: c.error };

  const wk = await grab(a.host + '/companies/' + encodeURIComponent(c.companyId) + '/workers?limit=1000', a.auth, 9000);
  if (wk.status !== 200) return { ok: false, problem: 'Could not read workers (HTTP ' + wk.status + ').' };
  const all = Array.isArray(wk.body) ? wk.body
            : (wk.body && (wk.body.content || wk.body.workers || wk.body.data || [])) || [];

  /* A nonsense window falls back to the default rather than clamping to one
     day, which would quietly take nobody and look like nothing had changed. */
  const n = Number(days);
  const span = (isFinite(n) && n >= 1) ? Math.min(3650, Math.floor(n)) : 30;
  const cutoff = Date.now() - span * 86400000;
  const inWindow = all.filter(w => {
    const d = Date.parse((w && w.currentStatus && w.currentStatus.effectiveDate) || '');
    return isFinite(d) && d >= cutoff;
  });

  const locs = inWindow.length ? await locationNames(a.host, a.auth, c.companyId) : {};

  /* The only place a Paychex record is read. Ten fields out, record dropped. */
  const rows = inWindow.map(w => workerRow(w, locs[str(w && w.locationId)] || str(w && w.locationId)));

  return { ok: true, seen: all.length, days: span, rows };
}

/* An address, asked for one person at a time and only when the directory is
   about to add them. The work domains come from the directory, and anything
   that is not on one of them stays here: a personal address is useful for
   nothing the directory does, so it is never passed on. */
async function paychexEmails(ids, domains) {
  const a = await paychexAuth();
  if (a.error) return { ok: false, problem: a.error };
  const doms = (Array.isArray(domains) ? domains : []).map(d => str(d).toLowerCase()).filter(Boolean);
  const out = {};
  for (const id of (Array.isArray(ids) ? ids : []).slice(0, 12)) {
    const wid = str(id);
    if (!wid) continue;
    const r = await grab(a.host + '/workers/' + encodeURIComponent(wid) + '/communications', a.auth, 5000);
    if (r.status !== 200) { out[wid] = { email: '', had: false }; continue; }
    const list = Array.isArray(r.body) ? r.body
               : (r.body && (r.body.content || r.body.communications || r.body.data || [])) || [];
    const mails = [];
    list.forEach(cm => {
      const v = str(cm && (cm.uri || cm.emailAddress || cm.address || cm.value)).toLowerCase();
      if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) mails.push(v);
    });
    const work = mails.find(m => !doms.length || doms.indexOf(m.split('@').pop()) >= 0);
    out[wid] = { email: work || '', had: mails.length > 0 };
  }
  return { ok: true, found: out };
}

/* ────────────────────────────────────────────────────────────────────────────
   The digest.

   A count and a link, nothing else. No staff names go out by email: the
   message exists to say "there is something to look at", and the looking
   happens in the directory where the full rules apply. A departure is
   somebody's bad week, and it does not need to sit in an inbox.
   ──────────────────────────────────────────────────────────────────────── */

const gone   = s => /\b(terminat|separat|inactive|former|offboard)/i.test(String(s || ''));
const here   = s => /\b(active|employed|current|hired)/i.test(String(s || ''));
const plain  = v => String(v || '').trim().replace(/\s+/g, ' ').toLowerCase();

/* Every name and address the directory already holds, flattened. Deliberately
   simpler than the full matcher in the page: this only has to be right about
   how many things need looking at, not about what to do with them. */
function knownPeople(d) {
  const names = new Set(), mails = new Set(), ids = new Set();
  const take = o => {
    if (!o || typeof o !== 'object' || !o.name) return;
    String(o.name).split(',').forEach(n => { if (plain(n)) names.add(plain(n)); });
    String(o.email || '').split(',').forEach(e => { if (plain(e)) mails.add(plain(e)); });
  };
  (d.sites || []).forEach(x => {
    ['crm', 'lead', 'backup'].forEach(k => take(x[k]));
    (x.pis || []).forEach(take); (x.team || []).forEach(take);
  });
  (d.depts || []).forEach(x => { take(x.head); (x.team || []).forEach(take); });
  (d.admins || []).forEach(take);
  /* People already added under a payroll id keep being recognised by it. */
  const link = (d.sync && d.sync.link) || {};
  Object.keys(link).forEach(k => { if (k.indexOf('emp:') === 0) ids.add(k.slice(4)); });
  return { names, mails, ids };
}

function digestCount(rows, d) {
  const k = knownPeople(d);
  let joiners = 0, leavers = 0;
  rows.forEach(r => {
    const known = (r.empid && k.ids.has(r.empid)) || (r.name && k.names.has(plain(r.name)));
    if (gone(r.status)) { if (known) leavers++; }
    else if (here(r.status)) { if (!known) joiners++; }
  });
  return { joiners, leavers, total: joiners + leavers };
}

async function sendDigest({ to, counts, days, siteUrl, subjectNote }) {
  const key = process.env.RESEND_API_KEY || '';
  if (!key) return { ok: false, problem: 'RESEND_API_KEY is not set on the server.' };
  const list = (Array.isArray(to) ? to : String(to || '').split(','))
    .map(x => String(x).trim()).filter(x => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(x));
  if (!list.length) return { ok: false, problem: 'No valid address to send to.' };

  const from = process.env.RESEND_FROM || 'onboarding@resend.dev';
  const bits = [];
  if (counts.joiners) bits.push(counts.joiners + (counts.joiners === 1 ? ' person has' : ' people have') + ' joined');
  if (counts.leavers) bits.push(counts.leavers + (counts.leavers === 1 ? ' person has' : ' people have') + ' left');
  const line = bits.join(' and ') || 'Something has changed';
  const link = siteUrl || '';

  const html =
    '<div style="font-family:Helvetica,Arial,sans-serif;font-size:15px;line-height:1.6;color:#0E2748;max-width:520px">' +
    '<p style="margin:0 0 14px"><strong>' + line + '</strong> in Paychex in the last ' + days + ' days, ' +
    'and the directory does not reflect it yet.</p>' +
    '<p style="margin:0 0 18px">Open the directory, go to Manage \u2192 Paychex, and press <em>Pull from Paychex</em> to see what it proposes. ' +
    'Nothing changes until you approve it.</p>' +
    (link ? '<p style="margin:0 0 18px"><a href="' + link + '" style="background:#0E2748;color:#fff;text-decoration:none;padding:10px 18px;border-radius:999px;display:inline-block">Open the directory</a></p>' : '') +
    '<p style="margin:0;font-size:12.5px;color:#8696AC">No names are included in this message on purpose. ' +
    'Sent automatically by the Revival directory.</p></div>';

  const r = await grab('https://api.resend.com/emails', {
    method: 'POST',
    headers: { authorization: 'Bearer ' + key, 'content-type': 'application/json' },
    body: JSON.stringify({
      from, to: list,
      subject: 'Revival directory \u2014 ' + counts.total + ' to review' + (subjectNote ? ' ' + subjectNote : ''),
      html
    })
  }, 8000);
  if (r.status >= 200 && r.status < 300) return { ok: true, sent: list.length, to: list };
  return { ok: false, problem: 'Resend refused it (HTTP ' + r.status + ').', detail: r.text };
}

/* Run by the schedule, and by the Send a test button. */
async function digestRun(store, { test } = {}) {
  let d = null;
  try { d = await store.get(KEY, { type: 'json' }); } catch (e) {}
  if (!d) return { ok: false, problem: 'No stored directory to compare against.' };
  const cfg = (d.sync && d.sync.digest) || {};
  const to = cfg.to || process.env.DIGEST_TO || '';
  if (!to) return { ok: false, problem: 'No address set. Add one under Manage \u2192 Paychex.' };
  const days = ((d.sync && d.sync.map && d.sync.map.days) || 30);

  const pulled = await paychexPull(days);
  if (!pulled.ok) return { ok: false, problem: pulled.problem };
  const counts = digestCount(pulled.rows || [], d);

  if (!counts.total && !test)
    return { ok: true, sent: 0, counts, note: 'Nothing to report, so nothing was sent.' };

  const res = await sendDigest({
    to, days, counts: test && !counts.total ? { joiners: 0, leavers: 0, total: 0 } : counts,
    siteUrl: process.env.URL || '',
    subjectNote: test ? '(test)' : ''
  });
  return Object.assign({ counts, days }, res);
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
    /* Counts of enumerated codes only — short, shouty, no spaces or digits
       beyond a code. Free text in a field that happens to be named "...Type"
       would otherwise be counted out into the open one value at a time. */
    if (/status|type/i.test(key) && o.length < 40 && /^[A-Z0-9_\- ]+$/.test(o) && !/^\d{5,}$/.test(o))
      bump(key, o);
    if (EMAIL.test(o)) { found.mail = true; bump('emailDomains', o.split('@').pop().toLowerCase()); }
  };
  workers.forEach(w => { const found = {}; scan(w, '', found); if (found.mail) withEmail++; });

  /* Field names across the whole sample, not just the first record — an
     optional field that only some people have would otherwise be missed. */
  const allFields = new Set();
  workers.forEach(w => fieldPaths(w, '', allFields));

  /* No record is returned, redacted or otherwise. A sample of one real person
     is how the Social Security number escaped the first time, and nothing is
     learnt from it that the field names and the counts do not already say. */
  return {
    ok: true,
    steps,
    swapped: got.order === 'swapped',
    host: got.host,
    companyId,
    recon: {
      returned: workers.length,
      envelope,
      headers: wk.headers || {},
      withAnyEmail: withEmail,
      withoutEmail: workers.length - withEmail,
      values: tally
    },
    fields: [...allFields].sort(),
    /* What the sync would actually take, so it can be seen before it is used. */
    taking: Object.keys(workerRow({}, '')),
    sample: null
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
    if (body.action === 'paychex-test' || body.action === 'paychex-pull' || body.action === 'paychex-emails' || body.action === 'digest-run') {
      if (!adminKey) return json({ error: 'ADMIN_KEY is not set on the server.' }, 500);
      if (!sameSecret(req.headers.get('x-admin-key'), adminKey))
        return json({ error: 'Not authorised.' }, 401);
      try {
        if (body.action === 'digest-run')     return json(await digestRun(store, { test: !!body.test }));
        if (body.action === 'paychex-pull')   return json(await paychexPull(body.days));
        if (body.action === 'paychex-emails') return json(await paychexEmails(body.ids, body.domains));
        return json(await paychexCheck());
      } catch (e) {
        return json({ ok: false, problem: 'That did not complete.', detail: String(e && e.message || e) }, 500);
      }
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
