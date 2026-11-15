import dnsPromises from 'node:dns/promises';
import { USER_AGENT } from './user-agent.js';

/**
 * DNS access is isolated behind this interface so the checks can be unit
 * tested without touching the network. Two implementations ship with
 * domsweep: the system resolver (default) and DNS-over-HTTPS.
 *
 * Every method resolves to an array and never throws: a lookup that fails
 * returns [] so a single missing record type cannot abort a sweep.
 */

const EMPTY_CODES = new Set([
  'ENODATA', 'ENOTFOUND', 'ESERVFAIL', 'EREFUSED', 'ETIMEOUT', 'ECANCELLED',
]);

function softFail(err) {
  if (EMPTY_CODES.has(err?.code)) return [];
  throw err;
}

/** Resolver backed by the machine's own DNS settings. */
export function systemResolver({ timeout = 5000, servers } = {}) {
  const r = new dnsPromises.Resolver({ timeout, tries: 2 });
  if (servers?.length) r.setServers(servers);

  const call = async (method, name) => {
    try {
      return await r[method](name);
    } catch (err) {
      return softFail(err);
    }
  };

  return {
    name: 'system',
    a: (d) => call('resolve4', d),
    aaaa: (d) => call('resolve6', d),
    ns: (d) => call('resolveNs', d),
    mx: (d) => call('resolveMx', d),
    // node returns TXT as arrays of chunks; RFC 1035 says to join them.
    txt: async (d) => (await call('resolveTxt', d)).map((chunks) => chunks.join('')),
    cname: (d) => call('resolveCname', d),
  };
}

/**
 * Resolver that queries a DNS-over-HTTPS endpoint. Useful when the local
 * resolver is slow, cached, filtered or hijacked by a captive portal, and
 * when you want every machine in a team to see identical results.
 */
export function dohResolver({ endpoint = 'https://cloudflare-dns.com/dns-query', timeout = 5000 } = {}) {
  const query = async (name, type) => {
    const url = `${endpoint}?name=${encodeURIComponent(name)}&type=${type}`;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeout);
    try {
      const res = await fetch(url, {
        headers: { accept: 'application/dns-json', 'user-agent': USER_AGENT },
        signal: ctrl.signal,
      });
      if (!res.ok) return [];
      const body = await res.json();
      return body.Answer ?? [];
    } catch {
      return [];
    } finally {
      clearTimeout(timer);
    }
  };

  const ofType = (answers, type) => answers.filter((a) => a.type === type);
  const strip = (s) => s.replace(/\.$/, '');
  // DoH returns TXT data as one quoted string per chunk: "part one" "part two"
  const unquote = (s) => {
    const parts = s.match(/"(?:\\.|[^"\\])*"/g);
    if (!parts) return s.replace(/^"|"$/g, '');
    return parts.map((p) => p.slice(1, -1).replace(/\\(.)/g, '$1')).join('');
  };

  return {
    name: 'doh',
    a: async (d) => ofType(await query(d, 'A'), 1).map((x) => x.data),
    aaaa: async (d) => ofType(await query(d, 'AAAA'), 28).map((x) => x.data),
    ns: async (d) => ofType(await query(d, 'NS'), 2).map((x) => strip(x.data)),
    mx: async (d) => ofType(await query(d, 'MX'), 15).map((x) => {
      const [priority, exchange] = x.data.split(/\s+/);
      return { priority: Number(priority), exchange: strip(exchange) };
    }),
    txt: async (d) => ofType(await query(d, 'TXT'), 16).map((x) => unquote(x.data)),
    cname: async (d) => ofType(await query(d, 'CNAME'), 5).map((x) => strip(x.data)),
  };
}

export function createResolver(options = {}) {
  return options.doh ? dohResolver(options) : systemResolver(options);
}
