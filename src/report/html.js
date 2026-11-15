const esc = (v) => String(v ?? '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;');

const days = (n) => (n === null || n === undefined ? '—' : n < 0 ? 'expired' : `${n} days`);

export function renderHtml(results, { title = 'Domain health report', generatedAt = new Date() } = {}) {
  const rank = (r) => (r.score === null || r.score === undefined ? Infinity : r.score);
  const rows = [...results].sort((a, b) => rank(a) - rank(b) || a.domain.localeCompare(b.domain));
  const totals = results.reduce((acc, r) => { acc[r.level] = (acc[r.level] ?? 0) + 1; return acc; }, {});

  const cards = rows.map((r) => {
    const issues = r.issues.filter((i) => i.level !== 'info');
    return `<article class="card ${esc(r.level)}">
  <header>
    <h2>${esc(r.domain)}</h2>
    <span class="score" aria-label="score">${r.score === null || r.score === undefined
      ? 'not checked'
      : `${r.score}<small>/100</small> <b>${esc(r.grade)}</b>`}</span>
  </header>
  <dl>
    <div><dt>SPF</dt><dd>${r.email ? (r.email.spf.present ? `${esc(r.email.spf.parsed?.all?.raw ?? 'present')} · ${r.email.spfLookups?.total ?? 0}/10 lookups` : 'missing') : '—'}</dd></div>
    <div><dt>DMARC</dt><dd>${r.email ? (r.email.dmarc.present ? `p=${esc(r.email.dmarc.policy ?? '?')}` : 'missing') : '—'}</dd></div>
    <div><dt>DKIM</dt><dd>${r.email ? (r.email.dkim.length ? esc(r.email.dkim.map((d) => d.selector).join(', ')) : 'none found') : '—'}</dd></div>
    <div><dt>Mail</dt><dd>${esc(r.email?.provider ?? r.email?.mx?.[0] ?? '—')}</dd></div>
    <div><dt>Certificate</dt><dd>${r.ssl ? (r.ssl.reachable ? `${days(r.ssl.daysLeft)} · ${esc(r.ssl.issuer ?? 'unknown issuer')}` : `unreachable (${esc(r.ssl.error)})`) : '—'}</dd></div>
    <div><dt>Registration</dt><dd>${r.rdap ? `${days(r.rdap.daysLeft)} · ${esc(r.rdap.registrar ?? 'unknown registrar')}` : '—'}</dd></div>
    <div><dt>Nameservers</dt><dd>${esc(r.dns?.ns?.join(', ') || '—')}</dd></div>
  </dl>
  ${issues.length ? `<ul class="issues">${issues.map((i) => `<li class="${esc(i.level)}"><span>${esc(i.level)}</span> ${esc(i.message)}</li>`).join('')}</ul>` : '<p class="clean">No problems found.</p>'}
</article>`;
  }).join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<style>
  :root {
    --bg: #f6f7f9; --panel: #ffffff; --ink: #11181c; --muted: #5b6770;
    --line: #e3e8ec; --critical: #c7362f; --warning: #9a6700; --ok: #1a7f46;
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --bg: #0d1117; --panel: #161b22; --ink: #e6edf3; --muted: #9198a1;
      --line: #2a313a; --critical: #ff7b72; --warning: #e3b341; --ok: #3fb950;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 32px 16px; background: var(--bg); color: var(--ink);
    font: 15px/1.55 ui-sans-serif, -apple-system, "Segoe UI", Roboto, sans-serif;
  }
  .wrap { max-width: 920px; margin: 0 auto; }
  h1 { font-size: 24px; margin: 0 0 4px; }
  .meta { color: var(--muted); font-size: 14px; margin: 0 0 24px; }
  .summary { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 24px; }
  .pill { border: 1px solid var(--line); background: var(--panel); border-radius: 999px; padding: 6px 14px; font-size: 14px; }
  .pill b { font-weight: 650; }
  .card { background: var(--panel); border: 1px solid var(--line); border-left: 3px solid var(--line); border-radius: 10px; padding: 18px 20px; margin-bottom: 14px; }
  .card.critical { border-left-color: var(--critical); }
  .card.warning { border-left-color: var(--warning); }
  .card.ok { border-left-color: var(--ok); }
  .card header { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; flex-wrap: wrap; }
  .card h2 { font-size: 17px; margin: 0; font-weight: 650; overflow-wrap: anywhere; }
  .score { font-variant-numeric: tabular-nums; color: var(--muted); font-size: 15px; }
  .score small { font-size: 12px; }
  .score b { color: var(--ink); margin-left: 4px; }
  dl { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 8px 20px; margin: 14px 0 0; }
  dl div { min-width: 0; }
  dt { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
  dd { margin: 2px 0 0; overflow-wrap: anywhere; }
  .issues { list-style: none; margin: 16px 0 0; padding: 14px 0 0; border-top: 1px solid var(--line); }
  .issues li { margin-bottom: 7px; padding-left: 0; }
  .issues li span { display: inline-block; min-width: 62px; font-size: 12px; font-weight: 650; text-transform: uppercase; letter-spacing: .03em; }
  .issues li.critical span { color: var(--critical); }
  .issues li.warning span { color: var(--warning); }
  .clean { color: var(--ok); margin: 14px 0 0; font-size: 14px; }
  footer { color: var(--muted); font-size: 13px; margin-top: 28px; text-align: center; }
  footer a { color: inherit; }
</style>
</head>
<body>
<div class="wrap">
  <h1>${esc(title)}</h1>
  <p class="meta">${results.length} domains · generated ${esc(generatedAt.toISOString().replace('T', ' ').slice(0, 16))} UTC</p>
  <div class="summary">
    <span class="pill"><b>${totals.critical ?? 0}</b> critical</span>
    <span class="pill"><b>${totals.warning ?? 0}</b> warning</span>
    <span class="pill"><b>${totals.ok ?? 0}</b> clean</span>
  </div>
${cards}
  <footer>Generated by <a href="https://github.com/RanaUsman7330/domsweep">domsweep</a></footer>
</div>
</body>
</html>`;
}
