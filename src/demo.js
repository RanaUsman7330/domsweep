import { sweepDomain } from './runner.js';
import { evaluateCertificate } from './checks/ssl.js';
import { evaluateRdap } from './checks/rdap.js';

/**
 * A fixed sample used by `domsweep --demo` and by the test suite. It runs the
 * real checks against a stub resolver, so what you see in the demo is produced
 * by the same code that runs against live domains.
 */

const DAY = 86_400_000;
export const DEMO_NOW = Date.parse('2026-06-01T00:00:00Z');

const ZONES = {
  // Healthy: strict SPF, DMARC at reject, DKIM published.
  'well-run.example': {
    a: ['203.0.113.10'],
    ns: ['ns1.example-dns.net', 'ns2.example-dns.net'],
    mx: [{ priority: 10, exchange: 'aspmx.l.google.com' }],
    txt: ['v=spf1 include:_spf.google.com -all'],
    '_dmarc': ['v=DMARC1; p=reject; rua=mailto:dmarc@well-run.example; pct=100'],
    dkim: { google: 'v=DKIM1; k=rsa; p=MIIBIjANBg...' },
  },
  // The usual state of a domain nobody owns: SPF only, DMARC monitoring.
  'half-done.example': {
    a: ['203.0.113.20'],
    ns: ['ns1.example-dns.net', 'ns2.example-dns.net'],
    mx: [{ priority: 10, exchange: 'mx.zoho.com' }],
    txt: ['v=spf1 include:zoho.com ~all'],
    '_dmarc': ['v=DMARC1; p=none'],
    dkim: {},
  },
  // Two SPF records, so SPF silently does nothing. Added a vendor, forgot to merge.
  'two-spf.example': {
    a: ['203.0.113.30'],
    ns: ['ns1.other-dns.net'],
    mx: [{ priority: 10, exchange: 'mail.two-spf.example' }],
    txt: ['v=spf1 include:_spf.google.com ~all', 'v=spf1 include:sendgrid.net ~all'],
    '_dmarc': [],
    dkim: {},
  },
  // Nothing configured at all, and the certificate has run out.
  'forgotten.example': {
    a: ['203.0.113.40'],
    ns: ['ns1.example-dns.net', 'ns2.example-dns.net'],
    mx: [{ priority: 10, exchange: 'mail.forgotten.example' }],
    txt: [],
    '_dmarc': [],
    dkim: {},
  },
};

const SSL = {
  'well-run.example': { daysLeft: 74, issuer: "Let's Encrypt" },
  'half-done.example': { daysLeft: 21, issuer: "Let's Encrypt" },
  'two-spf.example': { daysLeft: 210, issuer: 'DigiCert Inc' },
  'forgotten.example': { daysLeft: -12, issuer: "Let's Encrypt" },
};

const RDAP = {
  'well-run.example': { daysLeft: 300, registrar: 'Example Registrar', locked: true },
  'half-done.example': { daysLeft: 140, registrar: 'Example Registrar', locked: true },
  'two-spf.example': { daysLeft: 55, registrar: 'Another Registrar', locked: true },
  'forgotten.example': { daysLeft: 9, registrar: 'Another Registrar', locked: false },
};

/** Stub resolver driven by the zone table above. */
export function demoResolver(zones = ZONES) {
  const base = (name) => {
    for (const domain of Object.keys(zones)) {
      if (name === domain) return { zone: zones[domain], kind: 'apex' };
      if (name === `_dmarc.${domain}`) return { zone: zones[domain], kind: 'dmarc' };
      const dkim = name.match(new RegExp(`^(.+)\\._domainkey\\.${domain.replace('.', '\\.')}$`));
      if (dkim) return { zone: zones[domain], kind: 'dkim', selector: dkim[1] };
    }
    return null;
  };

  const reply = (records) => ({ records, error: null, nxdomain: records.length === 0 });

  return {
    name: 'demo',
    a: async (d) => reply(base(d)?.kind === 'apex' ? base(d).zone.a ?? [] : []),
    aaaa: async () => reply([]),
    ns: async (d) => reply(base(d)?.kind === 'apex' ? base(d).zone.ns ?? [] : []),
    mx: async (d) => reply(base(d)?.kind === 'apex' ? base(d).zone.mx ?? [] : []),
    cname: async () => reply([]),
    txt: async (d) => {
      const hit = base(d);
      if (!hit) return reply([]);
      if (hit.kind === 'apex') return reply(hit.zone.txt ?? []);
      if (hit.kind === 'dmarc') return reply(hit.zone._dmarc ?? []);
      const key = hit.zone.dkim?.[hit.selector];
      return reply(key ? [key] : []);
    },
  };
}

const stubSsl = (domain, { now = DEMO_NOW } = {}) => {
  const s = SSL[domain];
  if (!s) return Promise.resolve(evaluateCertificate({ reachable: false, error: 'ENOTFOUND' }, domain, now));
  return Promise.resolve(evaluateCertificate({
    reachable: true,
    authorized: s.daysLeft >= 0,
    authorizationError: s.daysLeft < 0 ? 'CERT_HAS_EXPIRED' : null,
    protocol: 'TLSv1.3',
    cert: {
      valid_from: new Date(now - 90 * DAY).toUTCString(),
      valid_to: new Date(now + s.daysLeft * DAY).toUTCString(),
      issuer: { O: s.issuer },
      subject: { CN: domain },
      subjectaltname: `DNS:${domain}, DNS:www.${domain}`,
    },
  }, domain, now));
};

const stubRdap = (domain, { now = DEMO_NOW } = {}) => {
  const r = RDAP[domain];
  if (!r) return Promise.resolve(evaluateRdap({ ok: false, error: 'not_found' }, { now, tldSupported: true }));
  return Promise.resolve(evaluateRdap({
    ok: true,
    data: {
      events: [
        { eventAction: 'registration', eventDate: new Date(now - 900 * DAY).toISOString() },
        { eventAction: 'expiration', eventDate: new Date(now + r.daysLeft * DAY).toISOString() },
      ],
      status: r.locked ? ['client transfer prohibited'] : ['active'],
      entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', r.registrar]]] }],
    },
  }, { now }));
};

export function demoOptions(zones = ZONES) {
  return {
    resolver: demoResolver(zones),
    // The demo runs entirely offline, so the second opinion comes from the
    // same fixtures; in a real sweep it is an independent resolver.
    confirmResolver: demoResolver(zones),
    now: DEMO_NOW,
    sslCheck: stubSsl,
    rdapCheck: stubRdap,
  };
}

export async function demoResults() {
  const options = demoOptions();
  return Promise.all(Object.keys(ZONES).map((d) => sweepDomain(d, options)));
}

export { ZONES as DEMO_ZONES };
