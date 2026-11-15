import { createColour, pad, width } from './colour.js';

const dash = '-';

function days(n) {
  if (n === null || n === undefined) return dash;
  return n < 0 ? 'expired' : `${n}d`;
}

function spfCell(email) {
  if (!email) return dash;
  if (email.spf.present === null) return 'unknown';
  if (!email.spf.present) return 'missing';
  // More than one SPF record is a permerror, so there is no policy to show.
  if (!email.spf.parsed) return `${email.spf.records?.length ?? 2} records`;
  const lookups = email.spfLookups?.total;
  const policy = email.spf.parsed?.all?.qualifier;
  const label = { fail: '-all', softfail: '~all', neutral: '?all', pass: '+all' }[policy] ?? 'ok';
  return lookups ? `${label} (${lookups}/10)` : label;
}

function dmarcCell(email) {
  if (!email) return dash;
  if (email.dmarc.present === null) return 'unknown';
  if (!email.dmarc.present) return 'missing';
  return `p=${email.dmarc.policy ?? '?'}`;
}

function levelColour(colour, level) {
  if (level === 'critical') return colour.red;
  if (level === 'warning') return colour.yellow;
  return colour.green;
}

export function renderTable(results, { colour: useColour = true, details = true } = {}) {
  const c = createColour(useColour);
  const rows = [...results].sort((a, b) => a.score - b.score || a.domain.localeCompare(b.domain));

  const header = ['DOMAIN', 'SCORE', 'SPF', 'DMARC', 'DKIM', 'SSL', 'EXPIRES'];
  const body = rows.map((r) => [
    r.domain,
    `${r.score} ${r.grade}`,
    spfCell(r.email),
    dmarcCell(r.email),
    r.email ? (r.email.dkim.length ? `${r.email.dkim.length} found` : (r.email.dkimProbed ? 'none' : 'n/a')) : dash,
    r.ssl ? (r.ssl.reachable ? days(r.ssl.daysLeft) : 'unreachable') : dash,
    r.rdap ? (r.rdap.daysLeft === null || r.rdap.daysLeft === undefined ? 'n/a' : days(r.rdap.daysLeft)) : dash,
  ]);

  const widths = header.map((h, i) => Math.max(width(h), ...body.map((row) => width(row[i]))));

  const lines = [];
  lines.push(c.bold(header.map((h, i) => pad(h, widths[i])).join('  ')));
  lines.push(c.grey(widths.map((w) => dash.repeat(w)).join('  ')));

  rows.forEach((r, idx) => {
    const paint = levelColour(c, r.level);
    const cells = body[idx].map((cell, i) => (i === 1 ? paint(pad(cell, widths[i])) : pad(cell, widths[i])));
    lines.push(cells.join('  '));
  });

  if (details) {
    const withIssues = rows.filter((r) => r.issues.some((i) => i.level !== 'info'));
    if (withIssues.length) {
      lines.push('');
      lines.push(c.bold('Findings'));
      for (const r of withIssues) {
        lines.push('');
        lines.push(`${c.bold(r.domain)} ${c.grey(`(${r.score}/100)`)}`);
        for (const issue of r.issues) {
          if (issue.level === 'info') continue;
          const tag = issue.level === 'critical' ? c.red('critical') : c.yellow('warning ');
          lines.push(`  ${tag} ${c.grey(`[${issue.area}]`)} ${issue.message}`);
        }
      }
    }
  }

  const totals = results.reduce((acc, r) => {
    acc[r.level] = (acc[r.level] ?? 0) + 1;
    return acc;
  }, {});

  lines.push('');
  lines.push([
    `${results.length} domains`,
    c.red(`${totals.critical ?? 0} critical`),
    c.yellow(`${totals.warning ?? 0} warning`),
    c.green(`${totals.ok ?? 0} clean`),
  ].join('  ·  '));

  return lines.join('\n');
}
