/* Revival Team Directory — the weekly nudge.
 *
 * Runs on a schedule and asks the main endpoint to do the work, so there is
 * one copy of the Paychex logic rather than two drifting apart. If nothing
 * has changed, nothing is sent — an email that arrives every week saying
 * "nothing to report" is an email nobody reads by the third week.
 *
 * To change when it runs, edit the schedule below and redeploy. The time is
 * UTC, so "0 13 * * 1" is Monday 8am Eastern in winter and 9am in summer.
 *
 *   "0 13 * * 1"   Monday mornings            (the default)
 *   "0 13 * * 1-5" every weekday morning
 *   "0 13 1 * *"   the first of the month
 */

export default async () => {
  const site = process.env.URL || process.env.DEPLOY_PRIME_URL || '';
  const adminKey = process.env.ADMIN_KEY || '';

  if (!site || !adminKey) {
    console.log('digest: skipped — site URL or ADMIN_KEY missing');
    return;
  }

  try {
    const r = await fetch(site + '/api/directory', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-admin-key': adminKey },
      body: JSON.stringify({ action: 'digest-run' })
    });
    const out = await r.json().catch(() => ({}));
    /* Counts only in the log. Netlify keeps function logs, and a staff name
       in a log is the same mistake as a staff name in an email. */
    console.log('digest:', JSON.stringify({
      ok: !!out.ok, sent: out.sent || 0,
      joiners: out.counts ? out.counts.joiners : null,
      leavers: out.counts ? out.counts.leavers : null,
      problem: out.problem || null
    }));
  } catch (e) {
    console.log('digest: failed —', String((e && e.message) || e));
  }
};

export const config = { schedule: '0 13 * * 1' };
