import { USER_AGENT } from '../user-agent.js';

const DAY = 86_400_000;

/**
 * Registration data comes from RDAP, the JSON successor to WHOIS. rdap.org
 * bootstraps to the right registry for the TLD, so one URL covers everything
 * and there is no WHOIS text to scrape.
 */
export async function fetchRdap(domain, { endpoint = 'https://rdap.org/domain/', timeout = 10_000, fetchImpl = fetch } = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetchImpl(`${endpoint}${encodeURIComponent(domain)}`, {
      headers: { accept: 'application/rdap+json', 'user-agent': USER_AGENT },
      redirect: 'follow',
      signal: ctrl.signal,
    });
    if (res.status === 404) return { ok: false, error: 'not_registered' };
    if (!res.ok) return { ok: false, error: `http_${res.status}` };
    return { ok: true, data: await res.json() };
  } catch (err) {
    return { ok: false, error: err.name === 'AbortError' ? 'timeout' : (err.code ?? 'request_failed') };
  } finally {
    clearTimeout(timer);
  }
}

function eventDate(events, action) {
  const e = events?.find((x) => x.eventAction === action);
  return e?.eventDate ? new Date(e.eventDate) : null;
}

function registrarName(entities) {
  const reg = entities?.find((e) => e.roles?.includes('registrar'));
  const vcard = reg?.vcardArray?.[1];
  const fn = vcard?.find((f) => f[0] === 'fn');
  return fn?.[3] ?? null;
}

/** Turn an RDAP response into findings. Pure, so it is unit testable. */
export function evaluateRdap(response, now = Date.now()) {
  if (!response.ok) {
    if (response.error === 'not_registered') {
      return { registered: false, issues: [{ level: 'critical', code: 'domain_not_registered', message: 'No registration record found. The domain may be unregistered or the TLD may not publish RDAP.' }] };
    }
    return { registered: null, error: response.error, issues: [{ level: 'info', code: 'rdap_unavailable', message: `Registration data unavailable (${response.error}).` }] };
  }

  const d = response.data;
  const expiry = eventDate(d.events, 'expiration');
  const created = eventDate(d.events, 'registration');
  const statuses = d.status ?? [];
  const issues = [];

  let daysLeft = null;
  if (expiry) {
    daysLeft = Math.floor((expiry.getTime() - now) / DAY);
    if (daysLeft < 0) {
      issues.push({ level: 'critical', code: 'domain_expired', message: `Domain registration expired ${Math.abs(daysLeft)} days ago.` });
    } else if (daysLeft <= 30) {
      issues.push({ level: 'critical', code: 'domain_expiring', message: `Domain registration expires in ${daysLeft} days.` });
    } else if (daysLeft <= 60) {
      issues.push({ level: 'warning', code: 'domain_expiring_soon', message: `Domain registration expires in ${daysLeft} days.` });
    }
  }

  const locked = statuses.some((s) => /client transfer prohibited/i.test(s));
  if (!locked && statuses.length) {
    issues.push({ level: 'warning', code: 'domain_unlocked', message: 'Transfer lock is off, which makes an unauthorised transfer easier.' });
  }

  return {
    registered: true,
    registrar: registrarName(d.entities),
    created: created?.toISOString() ?? null,
    expires: expiry?.toISOString() ?? null,
    daysLeft,
    statuses,
    locked,
    issues,
  };
}

export async function checkRdap(domain, options = {}) {
  return evaluateRdap(await fetchRdap(domain, options), options.now);
}
