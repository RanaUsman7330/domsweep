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

  // Everything below DNS depends on DNS. When it did not answer, the same
  // single cause would otherwise be restated as four separate problems.
  const nxdomain = Boolean(dns?.nxdomain);
  const lookupFailed = Boolean(dns?.lookupFailed);
  const consequential = new Set(['tls_unreachable', 'tls_no_certificate']);

  // "Publish v=spf1 -all" is not advice you can act on for a name that does
  // not exist. Registration still is: it says whether the name is gone.
  const emailIssues = nxdomain ? [] : (email?.issues ?? []);
  const sslIssues = (ssl?.issues ?? []).filter(
    (i) => !((nxdomain || lookupFailed) && consequential.has(i.code)),
  );

  const issues = [
    ...(dns?.issues ?? []).map((i) => ({ ...i, area: 'dns' })),
    ...emailIssues.map((i) => ({ ...i, area: 'email' })),
    ...(nxdomain ? [] : sslIssues).map((i) => ({ ...i, area: 'ssl' })),
    ...(rdap?.issues ?? []).map((i) => ({ ...i, area: 'domain' })),
  ];

  const { counts } = scoreIssues(issues);

  // A domain that does not resolve is as broken as a domain gets, whatever
  // else did or did not get checked. A domain whose lookups never completed
  // is not graded at all: an A for a domain nothing is known about is worse
  // than no answer, because it looks like an answer.
  let score;
  if (nxdomain) score = 0;
  else if (lookupFailed) score = null;
  else score = scoreIssues(issues).score;

  return {
    domain,
    score,
    grade: grade(score),
    checked: !lookupFailed,
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
