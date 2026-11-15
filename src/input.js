/**
 * Domain lists arrive as plain text, CSV exported from a registrar, or
 * arguments on the command line. All three end up here.
 */

const DOMAIN_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i;

export function isDomain(value) {
  return DOMAIN_RE.test(value);
}

/** Strip scheme, credentials, port, path and a trailing dot off one entry. */
export function normaliseDomain(value) {
  let d = String(value).trim().toLowerCase();
  if (!d) return null;
  d = d.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  d = d.replace(/^[^@/]*@/, '');
  d = d.split(/[/?#]/)[0];
  d = d.replace(/:\d+$/, '');
  d = d.replace(/\.$/, '');
  return d || null;
}

/**
 * Read a list from text. Blank lines and lines starting with # are skipped.
 * For CSV the first column is used, so a registrar export works unchanged.
 * Anything that is not a domain is returned in `skipped` rather than dropped
 * silently, because a 1,200-line file hides mistakes well.
 */
export function parseDomainList(text) {
  const domains = [];
  const skipped = [];
  const seen = new Set();

  for (const rawLine of String(text).split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    const firstField = line.split(/[,;\t]/)[0].trim().replace(/^"|"$/g, '');
    const domain = normaliseDomain(firstField);
    if (!domain) continue;

    if (!isDomain(domain)) {
      skipped.push({ line: rawLine, reason: 'not a domain' });
      continue;
    }
    if (seen.has(domain)) continue;

    seen.add(domain);
    domains.push(domain);
  }

  return { domains, skipped };
}
