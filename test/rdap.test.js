import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateRdap } from '../src/checks/rdap.js';

const DAY = 86_400_000;
const NOW = Date.parse('2026-06-01T00:00:00Z');
const codes = (r) => r.issues.map((i) => i.code);

function response(daysLeft, { locked = true, registrar = 'Example Registrar' } = {}) {
  return {
    ok: true,
    data: {
      events: [
        { eventAction: 'registration', eventDate: new Date(NOW - 400 * DAY).toISOString() },
        { eventAction: 'expiration', eventDate: new Date(NOW + daysLeft * DAY).toISOString() },
      ],
      status: locked ? ['client transfer prohibited'] : ['active'],
      entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', registrar]]] }],
    },
  };
}

test('reads expiry, registrar and lock state', () => {
  const r = evaluateRdap(response(200), { now: NOW });
  assert.equal(r.daysLeft, 200);
  assert.equal(r.registrar, 'Example Registrar');
  assert.equal(r.locked, true);
  assert.deepEqual(codes(r), []);
});

test('expiry thresholds escalate', () => {
  assert.deepEqual(codes(evaluateRdap(response(45), { now: NOW })), ['domain_expiring_soon']);
  assert.deepEqual(codes(evaluateRdap(response(10), { now: NOW })), ['domain_expiring']);
  assert.ok(codes(evaluateRdap(response(-5), { now: NOW })).includes('domain_expired'));
});

test('an unlocked domain is reported', () => {
  assert.ok(codes(evaluateRdap(response(300, { locked: false }), { now: NOW })).includes('domain_unlocked'));
});

test('a 404 for a TLD that does publish RDAP means unregistered', () => {
  const r = evaluateRdap({ ok: false, error: 'not_found' }, { now: NOW, tldSupported: true });
  assert.equal(r.registered, false);
  assert.deepEqual(codes(r), ['domain_not_registered']);
});

test('a 404 for a TLD without RDAP is not an unregistered domain', () => {
  // .ae and many other ccTLDs publish no RDAP at all. Reading that 404 as
  // "not registered" turns every such domain into a false critical.
  const r = evaluateRdap({ ok: false, error: 'not_found' }, { now: NOW, tldSupported: false, tld: 'ae' });
  assert.equal(r.registered, null);
  assert.deepEqual(codes(r), ['rdap_not_supported']);
  assert.match(r.issues[0].message, /\.ae/);
});

test('a 404 with no bootstrap answer stays non-committal', () => {
  const r = evaluateRdap({ ok: false, error: 'not_found' }, { now: NOW, tldSupported: null });
  assert.equal(r.registered, null);
  assert.deepEqual(codes(r), ['rdap_unavailable']);
  assert.equal(r.issues[0].level, 'info');
});

test('a TLD without RDAP is info, not a failure', () => {
  const r = evaluateRdap({ ok: false, error: 'http_501' }, { now: NOW });
  assert.equal(r.registered, null);
  assert.deepEqual(codes(r).map((c) => c), ['rdap_unavailable']);
});

test('a response with no expiry event does not invent one', () => {
  const r = evaluateRdap({ ok: true, data: { events: [], status: ['client transfer prohibited'] } }, { now: NOW });
  assert.equal(r.daysLeft, null);
  assert.deepEqual(codes(r), []);
});

test('a User-Agent is sent, because some RDAP servers answer 403 without one', async () => {
  const { fetchRdap } = await import('../src/checks/rdap.js');
  let seen = null;
  await fetchRdap('example.com', {
    fetchImpl: async (url, init) => {
      seen = { url, headers: init.headers };
      return { ok: true, status: 200, json: async () => ({ events: [] }) };
    },
  });
  assert.ok(seen.url.includes('example.com'));
  assert.match(seen.headers['user-agent'], /^domsweep\//);
  assert.equal(seen.headers.accept, 'application/rdap+json');
});

test('a non-200 response is reported rather than parsed', async () => {
  const { fetchRdap } = await import('../src/checks/rdap.js');
  const r = await fetchRdap('example.com', { fetchImpl: async () => ({ ok: false, status: 403 }) });
  assert.deepEqual(r, { ok: false, error: 'http_403' });
});
