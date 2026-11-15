import test from 'node:test';
import assert from 'node:assert/strict';
import { parseDomainList, normaliseDomain, isDomain } from '../src/input.js';

test('strips scheme, port, path and trailing dot', () => {
  assert.equal(normaliseDomain('https://Example.COM:8443/some/path?x=1'), 'example.com');
  assert.equal(normaliseDomain('example.com.'), 'example.com');
  assert.equal(normaliseDomain('  example.com  '), 'example.com');
});

test('strips credentials and takes the host from an email-like entry', () => {
  assert.equal(normaliseDomain('user@example.com'), 'example.com');
});

test('keeps subdomains intact', () => {
  assert.equal(normaliseDomain('shop.example.co.uk'), 'shop.example.co.uk');
});

test('rejects things that are not domains', () => {
  assert.equal(isDomain('localhost'), false);
  assert.equal(isDomain('-bad.com'), false);
  assert.equal(isDomain('bad-.com'), false);
  assert.equal(isDomain('example.com'), true);
  assert.equal(isDomain('xn--80ak6aa92e.com'), true);
});

test('reads a plain list and skips blanks and comments', () => {
  const { domains } = parseDomainList(`
# portfolio
example.com

  https://second.example.org/
`);
  assert.deepEqual(domains, ['example.com', 'second.example.org']);
});

test('reads the first column of a CSV, header included', () => {
  const { domains, skipped } = parseDomainList(
    'domain,registrar,expiry\nexample.com,GoDaddy,2027-01-01\n"quoted.com",Namecheap,2027-02-01',
  );
  assert.deepEqual(domains, ['example.com', 'quoted.com']);
  // The header row is not a domain, and is reported rather than dropped silently.
  assert.equal(skipped.length, 1);
});

test('removes duplicates however they are written', () => {
  const { domains } = parseDomainList('example.com\nEXAMPLE.COM\nhttps://example.com/path');
  assert.deepEqual(domains, ['example.com']);
});
