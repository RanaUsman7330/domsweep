import { checkDns } from './checks/dns.js';
import { checkEmail } from './checks/email.js';
import { checkSsl } from './checks/ssl.js';
import { checkRdap } from './checks/rdap.js';
import { scoreIssues, grade, worstLevel } from './score.js';

/** Run `task` over `items` with at most `limit` in flight at once. */
export async function pool(items, limit, task) {
  const results = new Array(items.length);
  let next = 0;

  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await task(items[i], i);
    }
  });

  await Promise.all(workers);
  return results;
}

export async function sweepDomain(domain, options = {}) {
  const {
    resolver, skip = [], expectNs, dkimSelectors, now, sslTimeout, rdapTimeout,
    // The TLS and RDAP checks reach the network directly rather than through
    // the resolver, so they are injectable too. That is what makes the whole
    // pipeline testable offline.
    sslCheck = checkSsl,
    rdapCheck = checkRdap,
  } = options;

  const run = (name, fn) => (skip.includes(name) ? Promise.resolve(null) : fn());

  const [dns, email, ssl, rdap] = await Promise.all([
    run('dns', () => checkDns(domain, resolver, { expectNs })),
    run('email', () => checkEmail(domain, resolver, { dkimSelectors })),
    run('ssl', () => sslCheck(domain, { now, timeout: sslTimeout })),
    run('rdap', () => rdapCheck(domain, { now, timeout: rdapTimeout })),
  ]);

  // When DNS did not answer, everything downstream fails for the same single
  // reason. Repeating it as four findings turns one unknown into a panic.
  const dnsUnresolved = Boolean(dns?.lookupFailed || dns?.nxdomain);
  const consequential = new Set(['tls_unreachable', 'tls_no_certificate']);

  const issues = [
    ...(dns?.issues ?? []).map((i) => ({ ...i, area: 'dns' })),
    ...(email?.issues ?? []).map((i) => ({ ...i, area: 'email' })),
    ...(ssl?.issues ?? []).filter((i) => !(dnsUnresolved && consequential.has(i.code))).map((i) => ({ ...i, area: 'ssl' })),
    ...(rdap?.issues ?? []).map((i) => ({ ...i, area: 'domain' })),
  ];

  const { score, counts } = scoreIssues(issues);

  return {
    domain,
    score,
    grade: grade(score),
    level: worstLevel(issues),
    counts,
    dns,
    email,
    ssl,
    rdap,
    issues,
  };
}

export async function sweep(domains, options = {}) {
  const { concurrency = 8, onResult } = options;
  return pool(domains, concurrency, async (domain) => {
    const result = await sweepDomain(domain, options);
    onResult?.(result);
    return result;
  });
}
