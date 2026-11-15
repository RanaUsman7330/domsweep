/** Basic resolution and delegation checks. */
export async function checkDns(domain, resolver, { expectNs = null } = {}) {
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

  const nxdomain = a.nxdomain && ns.nxdomain;
  if (nxdomain) {
    issues.push({ level: 'critical', code: 'dns_nxdomain', message: 'The name does not exist in DNS.' });
    return { a: [], aaaa: [], ns: [], nxdomain, issues };
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
