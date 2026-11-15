/** Basic resolution and delegation checks. */
export async function checkDns(domain, resolver, { expectNs = null } = {}) {
  const [a, aaaa, ns] = await Promise.all([
    resolver.a(domain),
    resolver.aaaa(domain),
    resolver.ns(domain),
  ]);

  const issues = [];

  if (a.length === 0 && aaaa.length === 0) {
    issues.push({ level: 'critical', code: 'dns_no_address', message: 'No A or AAAA record, so the domain does not point anywhere.' });
  }

  if (ns.length === 0) {
    issues.push({ level: 'critical', code: 'dns_no_ns', message: 'No nameservers found. The domain is not delegated.' });
  } else if (ns.length === 1) {
    issues.push({ level: 'warning', code: 'dns_single_ns', message: 'Only one nameserver. A single failure takes the whole domain offline.' });
  }

  const nsSet = ns.map((h) => h.toLowerCase().replace(/\.$/, '')).sort();

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

  return { a, aaaa, ns: nsSet, issues };
}
