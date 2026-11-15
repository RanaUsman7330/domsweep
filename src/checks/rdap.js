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
    if (res.status === 404) return { ok: false, error: 'not_found' };
    if (!res.ok) return { ok: false, error: `http_${res.status}` };
    return { ok: true, data: await res.json() };
  } catch (err) {
    return { ok: false, error: err.name === 'AbortError' ? 'timeout' : (err.code ?? 'request_failed') };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Many ccTLDs publish no RDAP at all. Without this list a 404 from the
 * bootstrap service looks exactly like "this domain is not registered",
 * which turns every .ae or .villas domain into a false alarm.
 *
 * The IANA bootstrap file is the authoritative list of which TLDs have RDAP.
 * It is fetched at most once per process and cached.
 */
let bootstrapPromise = null;

export async function rdapTlds({ url = 'https://data.iana.org/rdap/dns.json', timeout = 10_000, fetchImpl = fetch, refresh = false } = {}) {
  if (refresh) bootstrapPromise = null;
  bootstrapPromise ??= (async () => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeout);
    try {
      const res = await fetchImpl(url, { headers: { accept: 'application/json', 'user-agent': USER_AGENT }, signal: ctrl.signal });
      if (!res.ok) return null;
      const body = await res.json();
      const tlds = new Set();
      for (const [names] of body.services ?? []) {
        for (const name of names) tlds.add(String(name).toLowerCase());
      }
      return tlds.size ? tlds : null;
    } catch {
      return null; // unknown, which the caller treats as "cannot say"
    } finally {
      clearTimeout(timer);
    }
  })();
  return bootstrapPromise;
}

export function tldOf(domain) {
  const parts = String(domain).toLowerCase().split('.');
  return parts.length > 1 ? parts[parts.length - 1] : null;
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

/**
 * Turn an RDAP response into findings. Pure, so it is unit testable.
 * `tldSupported` is true, false, or null when it could not be determined.
 */
export function evaluateRdap(response, { now = Date.now(), tldSupported = null, tld = null } = {}) {
  if (!response.ok) {
    if (response.error === 'not_found') {
      if (tldSupported === false) {
        return {
          registered: null,
          supported: false,
          issues: [{ level: 'info', code: 'rdap_not_supported', message: `The ${tld ? `.${tld}` : ''} registry does not publish RDAP, so registration data is unavailable.`.replace('  ', ' ') }],
        };
      }
      if (tldSupported === true) {
        return { registered: false, issues: [{ level: 'critical', code: 'domain_not_registered', message: 'No registration record found. The domain appears to be unregistered.' }] };
      }
      return { registered: null, issues: [{ level: 'info', code: 'rdap_unavailable', message: 'No registration record returned, and it could not be confirmed whether this TLD publishes RDAP.' }] };
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
  const response = await fetchRdap(domain, options);
  const tld = tldOf(domain);

  let tldSupported = null;
  if (!response.ok && response.error === 'not_found') {
    const tlds = await rdapTlds(options);
    if (tlds) tldSupported = tlds.has(tld);
  }

  return evaluateRdap(response, { now: options.now, tldSupported, tld });
}
