/**
 * Basic resolution and delegation checks.
 *
 * `confirm` is a second, independent resolver used for one job only: checking
 * a negative before it is reported as a fact. "This domain does not exist" is
 * the most alarming thing a sweep can say, and a single resolver — the same
 * one that may be timing out on its neighbours — is not enough evidence for
 * it.
 */
export async function checkDns(domain, resolver, { expectNs = null, confirm = null } = {}) {
  const [a, aaaa, ns] = await Promise.all([
    resolver.a(domain),
    resolver.aaaa(domain),
    resolver.ns(domain),
  ]);

  const issues = [];
  const lookupFailed = Boolean(a.error && aaaa.error && ns.error);

  if (lookupFailed) {
    // Nothing was learned about this domain, so saying anything is "missing"
    // would be an invention. One honest finding, and the other checks are
    // told to stay quiet.
    issues.push({
      level: 'warning',
      code: 'dns_lookup_failed',
      message: `DNS lookups did not complete (${a.error}). The domain may be fine; try again, or use --doh to bypass the local resolver.`,
    });
    return { a: [], aaaa: [], ns: [], lookupFailed, error: a.error, issues };
  }

  if (a.nxdomain && ns.nxdomain) {
    const second = confirm ? await confirmNxdomain(domain, confirm) : 'unavailable';

    if (second === 'agrees') {
      issues.push({
        level: 'critical',
        code: 'dns_nxdomain',
        message: 'The name does not exist in DNS, confirmed against a second resolver.',
      });
      return { a: [], aaaa: [], ns: [], nxdomain: true, nxdomainConfirmed: true, issues };
    }

    if (second === 'resolves') {
      // The resolver we were using is wrong about this domain, so nothing
      // else it told us about it can be trusted either.
      issues.push({
        level: 'warning',
        code: 'dns_resolver_disagreement',
        message: `The ${resolver.name ?? 'primary'} resolver reports this name as non-existent, but a second resolver resolves it. Re-run with --doh; the local resolver is unreliable for this domain.`,
      });
      return { a: [], aaaa: [], ns: [], unreliable: true, issues };
    }

    // No second opinion available. A single unconfirmed negative is reported,
    // but not as a fact.
    issues.push({
      level: 'warning',
      code: 'dns_nxdomain_unconfirmed',
      message: 'One resolver reports this name as non-existent, and it could not be confirmed against a second. Re-run with --doh before acting on it.',
    });
    return { a: [], aaaa: [], ns: [], nxdomain: true, nxdomainConfirmed: false, issues };
  }

  const addresses = [...a.records, ...aaaa.records];
  const nsSet = ns.records.map((h) => h.toLowerCase().replace(/\.$/, '')).sort();

  if (ns.error) {
    issues.push({ level: 'info', code: 'ns_lookup_failed', message: `Nameserver lookup did not complete (${ns.error}).` });
  } else if (nsSet.length === 0) {
    issues.push({ level: 'critical', code: 'dns_no_ns', message: 'No nameservers found. The domain is not delegated.' });
  } else if (nsSet.length === 1) {
    issues.push({ level: 'warning', code: 'dns_single_ns', message: 'Only one nameserver. A single failure takes the whole domain offline.' });
  }

  if (!a.error && !aaaa.error && addresses.length === 0) {
    // A delegated domain with no address is parked rather than broken, so this
    // is worth knowing but not an emergency.
    issues.push({ level: 'warning', code: 'dns_no_address', message: 'No A or AAAA record, so the domain does not point at a server.' });
  }

  if (expectNs?.length && nsSet.length) {
    const expected = expectNs.map((h) => h.toLowerCase().replace(/\.$/, '')).sort();
    const unexpected = nsSet.filter((h) => !expected.includes(h));
    const missing = expected.filter((h) => !nsSet.includes(h));
    if (unexpected.length || missing.length) {
      issues.push({
        level: 'warning',
        code: 'ns_drift',
        message: `Nameservers differ from the expected set (found: ${nsSet.join(', ') || 'none'}).`,
      });
    }
  }

  return {
    a: a.records,
    aaaa: aaaa.records,
    ns: nsSet,
    parked: addresses.length === 0 && nsSet.length > 0,
    issues,
  };
}

/** 'agrees' | 'resolves' | 'unavailable' — a second opinion on a missing name. */
async function confirmNxdomain(domain, confirm) {
  const [a, ns] = await Promise.all([confirm.a(domain), confirm.ns(domain)]);
  if (a.error && ns.error) return 'unavailable';
  if (a.nxdomain && ns.nxdomain) return 'agrees';
  if (a.records.length || ns.records.length) return 'resolves';
  // The name exists but holds neither addresses nor delegation at this
  // resolver. That is not the non-existence we were asked to confirm.
  return a.nxdomain || ns.nxdomain ? 'unavailable' : 'resolves';
}
