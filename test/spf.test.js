import test from 'node:test';
import assert from 'node:assert/strict';
import { parseSpf, evaluateSpf, findSpfRecords } from '../src/parse/spf.js';
import { countSpfLookups } from '../src/checks/email.js';

const codes = (r) => r.issues.map((i) => i.code);

test('finds SPF among unrelated TXT records', () => {
  const txt = ['google-site-verification=abc', 'v=spf1 -all', 'MS=ms12345'];
  assert.deepEqual(findSpfRecords(txt), ['v=spf1 -all']);
});

test('is not fooled by a record that merely mentions spf', () => {
  assert.deepEqual(findSpfRecords(['spf2.0/pra include:x', 'v=spf10 -all']), []);
});

test('counts only lookup mechanisms', () => {
  const p = parseSpf('v=spf1 ip4:1.2.3.4 ip6:::1 include:a.com a mx exists:b.com -all');
  // include, a, mx, exists -> 4. ip4 and ip6 cost nothing.
  assert.equal(p.lookups, 4);
  assert.deepEqual(p.includes, ['a.com']);
  assert.equal(p.all.qualifier, 'fail');
});

test('counts the redirect modifier as a lookup', () => {
  const p = parseSpf('v=spf1 redirect=_spf.example.com');
  assert.equal(p.lookups, 1);
  assert.equal(p.redirect, '_spf.example.com');
  assert.equal(p.all, null);
});

test('reads every qualifier on all', () => {
  assert.equal(parseSpf('v=spf1 ~all').all.qualifier, 'softfail');
  assert.equal(parseSpf('v=spf1 ?all').all.qualifier, 'neutral');
  assert.equal(parseSpf('v=spf1 +all').all.qualifier, 'pass');
  assert.equal(parseSpf('v=spf1 all').all.qualifier, 'pass');
});

test('missing SPF is critical', () => {
  const r = evaluateSpf([]);
  assert.equal(r.present, false);
  assert.deepEqual(codes(r), ['spf_missing']);
});

test('two SPF records is critical and stops further analysis', () => {
  const r = evaluateSpf(['v=spf1 include:a.com ~all', 'v=spf1 include:b.com ~all']);
  assert.deepEqual(codes(r), ['spf_multiple']);
});

test('+all is flagged as critical', () => {
  assert.ok(codes(evaluateSpf(['v=spf1 +all'])).includes('spf_plus_all'));
});

test('a clean strict record raises nothing', () => {
  assert.deepEqual(codes(evaluateSpf(['v=spf1 include:_spf.google.com -all'])), []);
});

test('over ten lookups is critical, eight is a warning', () => {
  assert.ok(codes(evaluateSpf(['v=spf1 -all'], { totalLookups: 11 })).includes('spf_lookup_limit'));
  assert.ok(codes(evaluateSpf(['v=spf1 -all'], { totalLookups: 8 })).includes('spf_lookup_near_limit'));
  assert.deepEqual(codes(evaluateSpf(['v=spf1 -all'], { totalLookups: 7 })), []);
});

test('deprecated ptr is reported', () => {
  assert.ok(codes(evaluateSpf(['v=spf1 ptr -all'])).includes('spf_ptr'));
});

// --- recursive lookup counting -------------------------------------------

function fakeResolver(zones) {
  return { txt: async (name) => zones[name] ?? [] };
}

test('counts lookups through nested includes', async () => {
  const resolver = fakeResolver({
    'example.com': ['v=spf1 include:a.com include:b.com -all'],   // 2
    'a.com': ['v=spf1 include:c.com ip4:1.1.1.1 -all'],           // 1
    'b.com': ['v=spf1 a mx -all'],                                // 2
    'c.com': ['v=spf1 ip4:2.2.2.2 -all'],                         // 0
  });
  const { total } = await countSpfLookups('example.com', resolver);
  assert.equal(total, 5);
});

test('an include loop terminates instead of hanging', async () => {
  const resolver = fakeResolver({
    'loop.com': ['v=spf1 include:back.com -all'],
    'back.com': ['v=spf1 include:loop.com -all'],
  });
  const { total } = await countSpfLookups('loop.com', resolver);
  assert.equal(total, 2);
});

test('a domain with no SPF costs no lookups', async () => {
  const { total } = await countSpfLookups('nothing.com', fakeResolver({}));
  assert.equal(total, 0);
});
