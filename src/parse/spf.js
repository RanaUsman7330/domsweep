/**
 * SPF record parsing (RFC 7208). Pure functions: no network, no I/O.
 */

/** Mechanisms that cost a DNS lookup against the limit of 10. */
export const LOOKUP_MECHANISMS = new Set(['include', 'a', 'mx', 'ptr', 'exists']);

const QUALIFIERS = { '+': 'pass', '-': 'fail', '~': 'softfail', '?': 'neutral' };

/** Pick the SPF records out of a domain's TXT records. */
export function findSpfRecords(txtRecords = []) {
  return txtRecords.filter((r) => /^v=spf1(\s|$)/i.test(r.trim()));
}

/**
 * Parse one SPF record into its terms.
 * @returns {{terms: Array, all: {qualifier: string}|null, lookups: number, includes: string[], redirect: string|null}}
 */
export function parseSpf(record) {
  const terms = [];
  const includes = [];
  let all = null;
  let redirect = null;
  let lookups = 0;

  const raw = record.trim().split(/\s+/).slice(1); // drop v=spf1

  for (const term of raw) {
    // Modifiers are name=value; mechanisms are [qualifier]name[:value]
    const modifier = term.match(/^([a-z0-9_-]+)=(.*)$/i);
    if (modifier && !/^(include|a|mx|ptr|exists|ip4|ip6|all)$/i.test(modifier[1])) {
      const name = modifier[1].toLowerCase();
      if (name === 'redirect') {
        redirect = modifier[2];
        lookups += 1;
      }
      terms.push({ type: 'modifier', name, value: modifier[2] });
      continue;
    }

    const m = term.match(/^([+\-~?])?([a-z0-9]+)(?::(.*))?$/i);
    if (!m) {
      terms.push({ type: 'unknown', raw: term });
      continue;
    }

    const qualifier = QUALIFIERS[m[1] ?? '+'];
    const name = m[2].toLowerCase();
    const value = m[3] ?? null;

    if (name === 'all') {
      all = { qualifier, raw: term };
    } else if (LOOKUP_MECHANISMS.has(name)) {
      lookups += 1;
      if (name === 'include') includes.push(value);
    }

    terms.push({ type: 'mechanism', name, qualifier, value });
  }

  return { record, terms, all, lookups, includes, redirect };
}

/**
 * Turn a domain's TXT records into SPF findings.
 * `totalLookups` is supplied by the recursive walker when available; without
 * it the count covers only the top-level record.
 */
export function evaluateSpf(txtRecords, { totalLookups = null } = {}) {
  const records = findSpfRecords(txtRecords);

  if (records.length === 0) {
    return {
      present: false,
      issues: [{ level: 'critical', code: 'spf_missing', message: 'No SPF record. Anyone can send mail claiming to be this domain.' }],
    };
  }

  if (records.length > 1) {
    // RFC 7208 4.5: more than one SPF record is a permerror, so SPF is simply
    // off. This is a common and silent breakage after a vendor is added.
    return {
      present: true,
      records,
      issues: [{ level: 'critical', code: 'spf_multiple', message: `${records.length} SPF records found. Receivers treat this as an error, so SPF does not apply at all.` }],
    };
  }

  const parsed = parseSpf(records[0]);
  const lookups = totalLookups ?? parsed.lookups;
  const issues = [];

  if (!parsed.all && !parsed.redirect) {
    issues.push({ level: 'warning', code: 'spf_no_all', message: 'SPF record has no "all" mechanism, so unlisted senders are neither allowed nor denied.' });
  }

  const q = parsed.all?.qualifier;
  if (q === 'pass') {
    issues.push({ level: 'critical', code: 'spf_plus_all', message: '"+all" allows the whole internet to send as this domain. This is worse than having no SPF.' });
  } else if (q === 'neutral') {
    issues.push({ level: 'warning', code: 'spf_neutral_all', message: '"?all" is neutral, so SPF gives receivers nothing to act on.' });
  } else if (q === 'softfail') {
    issues.push({ level: 'info', code: 'spf_softfail', message: '"~all" is a soft fail. Move to "-all" once you are confident every sender is listed.' });
  }

  if (lookups > 10) {
    issues.push({ level: 'critical', code: 'spf_lookup_limit', message: `${lookups} DNS lookups, over the limit of 10. Receivers return permerror and SPF fails.` });
  } else if (lookups >= 8) {
    issues.push({ level: 'warning', code: 'spf_lookup_near_limit', message: `${lookups} of 10 DNS lookups used. Adding one more sender is likely to break SPF.` });
  }

  if (parsed.terms.some((t) => t.name === 'ptr')) {
    issues.push({ level: 'warning', code: 'spf_ptr', message: 'The "ptr" mechanism is deprecated by RFC 7208 and some receivers ignore it.' });
  }

  return { present: true, records, parsed, lookups, issues };
}
