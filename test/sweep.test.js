import test from 'node:test';
import assert from 'node:assert/strict';
import { sweep, sweepDomain, pool } from '../src/runner.js';
import { demoOptions, demoResults, DEMO_NOW } from '../src/demo.js';
import { renderTable } from '../src/report/table.js';
import { renderCsv } from '../src/report/csv.js';
import { renderHtml } from '../src/report/html.js';

test('pool respects the concurrency limit', async () => {
  let inFlight = 0;
  let peak = 0;
  const items = Array.from({ length: 20 }, (_, i) => i);

  const out = await pool(items, 4, async (n) => {
    inFlight += 1;
    peak = Math.max(peak, inFlight);
    await new Promise((r) => setTimeout(r, 1));
    inFlight -= 1;
    return n * 2;
  });

  assert.equal(peak, 4);
  assert.deepEqual(out, items.map((n) => n * 2)); // order preserved
});

test('a well configured domain scores 100 and has no findings', async () => {
  const r = await sweepDomain('well-run.example', demoOptions());
  assert.equal(r.score, 100);
  assert.equal(r.grade, 'A');
  assert.equal(r.level, 'ok');
  assert.equal(r.email.spf.present, true);
  assert.equal(r.email.dmarc.policy, 'reject');
  assert.deepEqual(r.email.dkim.map((d) => d.selector), ['google']);
  assert.equal(r.email.provider, 'Google Workspace');
});

test('a neglected domain reports every area at once', async () => {
  const r = await sweepDomain('forgotten.example', demoOptions());
  const codes = r.issues.map((i) => i.code);
  assert.ok(codes.includes('spf_missing'));
  assert.ok(codes.includes('dmarc_missing'));
  assert.ok(codes.includes('tls_expired'));
  assert.ok(codes.includes('domain_expiring'));
  assert.equal(r.level, 'critical');
  assert.equal(r.score, 0);
});

test('two SPF records are caught', async () => {
  const r = await sweepDomain('two-spf.example', demoOptions());
  assert.ok(r.issues.some((i) => i.code === 'spf_multiple'));
});

test('every issue carries the area it came from', async () => {
  const r = await sweepDomain('forgotten.example', demoOptions());
  const areas = new Set(r.issues.map((i) => i.area));
  assert.deepEqual([...areas].sort(), ['domain', 'email', 'ssl']);
});

test('skip leaves the skipped areas null and off the score', async () => {
  const r = await sweepDomain('forgotten.example', { ...demoOptions(), skip: ['ssl', 'rdap'] });
  assert.equal(r.ssl, null);
  assert.equal(r.rdap, null);
  assert.ok(!r.issues.some((i) => i.area === 'ssl'));
});

test('expectNs reports drift away from the portfolio standard', async () => {
  const options = { ...demoOptions(), expectNs: ['ns1.example-dns.net', 'ns2.example-dns.net'] };
  const ok = await sweepDomain('well-run.example', options);
  const drifted = await sweepDomain('two-spf.example', options);
  assert.ok(!ok.issues.some((i) => i.code === 'ns_drift'));
  assert.ok(drifted.issues.some((i) => i.code === 'ns_drift'));
});

test('a sweep returns one result per domain in order', async () => {
  const domains = ['well-run.example', 'forgotten.example', 'half-done.example'];
  const results = await sweep(domains, { ...demoOptions(), concurrency: 2 });
  assert.deepEqual(results.map((r) => r.domain), domains);
});

test('an unknown domain degrades gracefully instead of throwing', async () => {
  const r = await sweepDomain('not-in-fixtures.example', demoOptions());
  assert.equal(r.domain, 'not-in-fixtures.example');
  assert.ok(r.issues.some((i) => i.code === 'dns_no_address'));
});

// --- reports --------------------------------------------------------------

test('the table report lists every domain, worst first', async () => {
  const out = renderTable(await demoResults(), { colour: false });
  const order = ['forgotten.example', 'two-spf.example', 'half-done.example', 'well-run.example'];
  const positions = order.map((d) => out.indexOf(d));
  assert.deepEqual(positions, [...positions].sort((a, b) => a - b));
  assert.ok(out.includes('4 domains'));
});

test('the CSV has one header and one row per domain', async () => {
  const lines = renderCsv(await demoResults()).trim().split('\n');
  assert.equal(lines.length, 5);
  assert.ok(lines[0].startsWith('domain,score,grade'));
});

test('CSV escapes fields containing commas', () => {
  const row = renderCsv([{
    domain: 'x.com', score: 50, grade: 'D', level: 'warning',
    counts: { critical: 0, warning: 1 }, issues: [],
    dns: { ns: ['a.com', 'b.com'] }, ssl: { issuer: 'Big CA, Inc.' }, rdap: {}, email: null,
  }]);
  assert.ok(row.includes('"Big CA, Inc."'));
});

test('the HTML report is self contained and escapes input', async () => {
  const html = renderHtml(await demoResults(), { generatedAt: new Date(DEMO_NOW) });
  assert.ok(html.startsWith('<!DOCTYPE html>'));
  assert.ok(!/<script/i.test(html));
  assert.ok(!/src=["']http/i.test(html)); // no external assets
  const hostile = renderHtml([{
    domain: '<img src=x onerror=alert(1)>', score: 0, grade: 'F', level: 'critical',
    counts: {}, issues: [], dns: null, ssl: null, rdap: null, email: null,
  }]);
  assert.ok(!hostile.includes('<img src=x'));
  assert.ok(hostile.includes('&lt;img'));
});
