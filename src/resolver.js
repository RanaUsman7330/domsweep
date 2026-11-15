import dnsPromises from 'node:dns/promises';
import { USER_AGENT } from './user-agent.js';

/**
 * DNS access is isolated behind this interface so the checks can be unit
 * tested without touching the network. Two implementations ship with
 * domsweep: the system resolver (default) and DNS-over-HTTPS.
 *
 * Every method resolves to { records, error, nxdomain }. The distinction
 * matters: "the server said there is no such record" and "the lookup did not
 * complete" look identical if you only return an empty array, and reporting
 * the second as the first tells people their SPF is missing when in fact
 * nothing was learned about it at all.
 */

/** The name resolved, and there is genuinely nothing of this type. */
const NO_RECORDS = new Set(['ENODATA', 'ENOTFOUND', 'NOTFOUND']);

const ok = (records) => ({ records, error: null, nxdomain: false });
const empty = (nxdomain = false) => ({ records: [], error: null, nxdomain });
const failed = (error) => ({ records: [], error, nxdomain: false });

/** Resolver backed by the machine's own DNS settings. */
export function systemResolver({ timeout = 5000, servers } = {}) {
  const r = new dnsPromises.Resolver({ timeout, tries: 2 });
  if (servers?.length) r.setServers(servers);

  const call = async (method, name) => {
    try {
      return ok(await r[method](name));
    } catch (err) {
      const code = err?.code ?? 'EUNKNOWN';
      if (NO_RECORDS.has(code)) return empty(code !== 'ENODATA');
      return failed(code);
    }
  };

  return {
    name: 'system',
    a: (d) => call('resolve4', d),
    aaaa: (d) => call('resolve6', d),
    ns: (d) => call('resolveNs', d),
    mx: (d) => call('resolveMx', d),
    // node returns TXT as arrays of chunks; RFC 1035 says to join them.
    txt: async (d) => {
      const res = await call('resolveTxt', d);
      return { ...res, records: res.records.map((chunks) => chunks.join('')) };
    },
    cname: (d) => call('resolveCname', d),
  };
}

/**
 * Resolver that queries a DNS-over-HTTPS endpoint. Useful when the local
 * resolver is slow, filtered, rate limited or simply unreliable for some
 * zones, and when you want every machine in a team to see identical results.
 */
export function dohResolver({ endpoint = 'https://cloudflare-dns.com/dns-query', timeout = 5000, fetchImpl = fetch } = {}) {
  const query = async (name, type) => {
    const url = `${endpoint}?name=${encodeURIComponent(name)}&type=${type}`;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeout);
    try {
      const res = await fetchImpl(url, {
        headers: { accept: 'application/dns-json', 'user-agent': USER_AGENT },
        signal: ctrl.signal,
      });
      if (!res.ok) return { answers: null, error: `http_${res.status}` };
      const body = await res.json();
      // RFC 8484 / Google-style JSON: 0 NOERROR, 3 NXDOMAIN, everything else a failure.
      if (body.Status === 3) return { answers: [], error: null, nxdomain: true };
      if (body.Status !== 0) return { answers: null, error: `dns_status_${body.Status}` };
      return { answers: body.Answer ?? [], error: null, nxdomain: false };
    } catch (err) {
      return { answers: null, error: err.name === 'AbortError' ? 'ETIMEOUT' : (err.code ?? 'request_failed') };
    } finally {
      clearTimeout(timer);
    }
  };

  const strip = (s) => s.replace(/\.$/, '');
  // DoH returns TXT data as one quoted string per chunk: "part one" "part two"
  const unquote = (s) => {
    const parts = s.match(/"(?:\\.|[^"\\])*"/g);
    if (!parts) return s.replace(/^"|"$/g, '');
    return parts.map((p) => p.slice(1, -1).replace(/\\(.)/g, '$1')).join('');
  };

  const lookup = async (name, type, code, map) => {
    const { answers, error, nxdomain } = await query(name, type);
    if (error) return failed(error);
    const records = answers.filter((a) => a.type === code).map(map);
    return { records, error: null, nxdomain: Boolean(nxdomain) };
  };

  return {
    name: 'doh',
    a: (d) => lookup(d, 'A', 1, (x) => x.data),
    aaaa: (d) => lookup(d, 'AAAA', 28, (x) => x.data),
    ns: (d) => lookup(d, 'NS', 2, (x) => strip(x.data)),
    mx: (d) => lookup(d, 'MX', 15, (x) => {
      const [priority, exchange] = x.data.split(/\s+/);
      return { priority: Number(priority), exchange: strip(exchange) };
    }),
    txt: (d) => lookup(d, 'TXT', 16, (x) => unquote(x.data)),
    cname: (d) => lookup(d, 'CNAME', 5, (x) => strip(x.data)),
  };
}

export function createResolver(options = {}) {
  return options.doh ? dohResolver(options) : systemResolver(options);
}
