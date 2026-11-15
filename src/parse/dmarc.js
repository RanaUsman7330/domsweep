/**
 * DMARC record parsing (RFC 7489). Pure functions: no network, no I/O.
 */

export function findDmarcRecords(txtRecords = []) {
  return txtRecords.filter((r) => /^v=DMARC1(\s*;|$)/i.test(r.trim()));
}

/** Parse the tag=value pairs of a DMARC record. */
export function parseDmarc(record) {
  const tags = {};
  for (const part of record.split(';')) {
    const m = part.trim().match(/^([a-z]+)\s*=\s*(.*)$/i);
    if (m) tags[m[1].toLowerCase()] = m[2].trim();
  }
  return tags;
}

export function evaluateDmarc(txtRecords) {
  const records = findDmarcRecords(txtRecords);

  if (records.length === 0) {
    return {
      present: false,
      policy: null,
      issues: [{ level: 'critical', code: 'dmarc_missing', message: 'No DMARC record. Nothing tells receivers what to do with mail that fails SPF or DKIM.' }],
    };
  }

  if (records.length > 1) {
    return {
      present: true,
      policy: null,
      records,
      issues: [{ level: 'critical', code: 'dmarc_multiple', message: `${records.length} DMARC records found. Receivers ignore all of them.` }],
    };
  }

  const tags = parseDmarc(records[0]);
  const policy = (tags.p ?? '').toLowerCase() || null;
  const issues = [];

  if (!policy) {
    issues.push({ level: 'critical', code: 'dmarc_no_policy', message: 'DMARC record has no "p" tag, so it does nothing.' });
  } else if (policy === 'none') {
    issues.push({ level: 'warning', code: 'dmarc_policy_none', message: 'Policy is "p=none", which only monitors. Spoofed mail is still delivered.' });
  } else if (!['quarantine', 'reject'].includes(policy)) {
    issues.push({ level: 'warning', code: 'dmarc_policy_unknown', message: `Unrecognised policy "${policy}".` });
  }

  if (!tags.rua) {
    issues.push({ level: 'warning', code: 'dmarc_no_rua', message: 'No "rua" address, so you never receive aggregate reports and cannot see who sends as you.' });
  }

  const pct = tags.pct ? Number(tags.pct) : 100;
  if (Number.isFinite(pct) && pct < 100) {
    issues.push({ level: 'info', code: 'dmarc_partial', message: `Policy applies to only ${pct}% of mail.` });
  }

  if (policy === 'reject' && (tags.sp ?? '').toLowerCase() === 'none') {
    issues.push({ level: 'warning', code: 'dmarc_subdomain_none', message: 'Subdomain policy "sp=none" leaves every subdomain spoofable.' });
  }

  return { present: true, policy, tags, records, pct, issues };
}
