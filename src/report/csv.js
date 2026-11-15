const COLUMNS = [
  'domain', 'score', 'grade', 'level', 'critical', 'warning',
  'spf', 'spf_policy', 'spf_lookups', 'dmarc', 'dmarc_policy',
  'dkim_selectors', 'mx_provider', 'ssl_days_left', 'ssl_issuer',
  'domain_days_left', 'registrar', 'nameservers', 'issues',
];

function escape(value) {
  const s = value === null || value === undefined ? '' : String(value);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function renderCsv(results) {
  const lines = [COLUMNS.join(',')];

  for (const r of results) {
    lines.push([
      r.domain,
      r.score,
      r.grade,
      r.level,
      r.counts.critical,
      r.counts.warning,
      r.email ? (r.email.spf.present ? 'yes' : 'no') : '',
      r.email?.spf?.parsed?.all?.qualifier ?? '',
      r.email?.spfLookups?.total ?? '',
      r.email ? (r.email.dmarc.present ? 'yes' : 'no') : '',
      r.email?.dmarc?.policy ?? '',
      r.email?.dkim?.map((d) => d.selector).join(' ') ?? '',
      r.email?.provider ?? '',
      r.ssl?.daysLeft ?? '',
      r.ssl?.issuer ?? '',
      r.rdap?.daysLeft ?? '',
      r.rdap?.registrar ?? '',
      r.dns?.ns?.join(' ') ?? '',
      r.issues.filter((i) => i.level !== 'info').map((i) => i.code).join(' '),
    ].map(escape).join(','));
  }

  return lines.join('\n');
}
