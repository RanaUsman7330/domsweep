import test from 'node:test';
import assert from 'node:assert/strict';
import { parseDmarc, evaluateDmarc, findDmarcRecords } from '../src/parse/dmarc.js';

const codes = (r) => r.issues.map((i) => i.code);

test('parses tags regardless of spacing', () => {
  const tags = parseDmarc('v=DMARC1;p = reject;  rua=mailto:a@b.com ; pct=50');
  assert.equal(tags.p, 'reject');
  assert.equal(tags.rua, 'mailto:a@b.com');
  assert.equal(tags.pct, '50');
});

test('ignores TXT records that are not DMARC', () => {
  assert.deepEqual(findDmarcRecords(['v=spf1 -all', 'some note']), []);
});

test('missing DMARC is critical', () => {
  assert.deepEqual(codes(evaluateDmarc([])), ['dmarc_missing']);
});

test('p=none is a warning, not a pass', () => {
  const r = evaluateDmarc(['v=DMARC1; p=none; rua=mailto:a@b.com']);
  assert.equal(r.policy, 'none');
  assert.ok(codes(r).includes('dmarc_policy_none'));
});

test('a full reject policy with reporting raises nothing', () => {
  assert.deepEqual(codes(evaluateDmarc(['v=DMARC1; p=reject; rua=mailto:a@b.com'])), []);
});

test('missing rua is reported', () => {
  assert.ok(codes(evaluateDmarc(['v=DMARC1; p=reject'])).includes('dmarc_no_rua'));
});

test('partial rollout is reported as info', () => {
  const r = evaluateDmarc(['v=DMARC1; p=reject; rua=mailto:a@b.com; pct=20']);
  assert.equal(r.pct, 20);
  assert.ok(codes(r).includes('dmarc_partial'));
});

test('sp=none under p=reject leaves subdomains open', () => {
  const r = evaluateDmarc(['v=DMARC1; p=reject; sp=none; rua=mailto:a@b.com']);
  assert.ok(codes(r).includes('dmarc_subdomain_none'));
});

test('two DMARC records disable DMARC', () => {
  assert.deepEqual(codes(evaluateDmarc(['v=DMARC1; p=reject', 'v=DMARC1; p=none'])), ['dmarc_multiple']);
});

test('a record with no policy tag is critical', () => {
  assert.ok(codes(evaluateDmarc(['v=DMARC1; rua=mailto:a@b.com'])).includes('dmarc_no_policy'));
});
