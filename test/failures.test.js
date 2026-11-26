import test from 'node:test';
import assert from 'node:assert/strict';
import { checkDns } from '../src/checks/dns.js';
import { checkEmail } from '../src/checks/email.js';
import { evaluateSpf } from '../src/parse/spf.js';
import { evaluateDmarc } from '../src/parse/dmarc.js';
import { sweepDomain } from '../src/runner.js';

const codes = (r) => (r.issues ?? []).map((i) => i.code);

/** A resolver where every lookup fails the way a flaky or rate-limited one does. */
function brokenResolver(error = 'ETIMEOUT') {
  const fail = async () => ({ records: [], error, nxdomain: false });
  return { name: 'broken', a: fail, aaaa: fail, ns: fail, mx: fail, txt: fail, cname: fail };
}

/** A resolver that reports every name as not existing. */
function nxResolver() {
  const nx = async () => ({ records: [], error: null, nxdomain: true });
  return { name: 'nx', a: nx, aaaa: nx, ns: nx, mx: nx, txt: nx, cname: nx };
}

/** A resolver for a registered, delegated domain that sends and receives nothing. */
function parkedResolver() {
  const none = async () => ({ records: [], error: null, nxdomain: false });
  return {
    name: 'parked',
    a: async () => ({ records: ['203.0.113.1'], error: null, nxdomain: false }),
    aaaa: none,
    ns: async () => ({ records: ['ns1.parking.example', 'ns2.parking.example'], error: null, nxdomain: false }),
    mx: none,
    txt: none,
    cname: none,
  };
}

// --- a failed lookup is not an absent record ------------------------------

test('a failed DNS lookup is reported as such, not as a missing record', async () => {
  const r = await checkDns('example.com', brokenResolver('ETIMEOUT'));
  assert.equal(r.lookupFailed, true);
  assert.deepEqual(codes(r), ['dns_lookup_failed']);
  // The dangerous outcome would be claiming the domain points nowhere.
  assert.ok(!codes(r).includes('dns_no_address'));
  assert.ok(!codes(r).includes('dns_no_ns'));
});

test('the failure message points at the workaround', async () => {
  const r = await checkDns('example.com', brokenResolver('EAI_AGAIN'));
  assert.match(r.issues[0].message, /EAI_AGAIN/);
  assert.match(r.issues[0].message, /--doh/);
});

test('SPF is unknown, not missing, when the TXT lookup fails', () => {
  const r = evaluateSpf([], { lookupError: 'ETIMEOUT' });
  assert.equal(r.present, null);
  assert.deepEqual(codes(r), ['spf_unknown']);
  assert.equal(r.issues[0].level, 'info');
});

test('DMARC is unknown, not missing, when the TXT lookup fails', () => {
  const r = evaluateDmarc([], { lookupError: 'ESERVFAIL' });
  assert.equal(r.present, null);
  assert.deepEqual(codes(r), ['dmarc_unknown']);
});

test('a domain whose lookups all fail raises no false criticals', async () => {
  const r = await sweepDomain('example.com', {
    resolver: brokenResolver(),
    skip: ['ssl', 'rdap'],
  });
  assert.equal(r.counts.critical, 0);
  assert.ok(!codes(r).includes('spf_missing'));
  assert.ok(!codes(r).includes('dmarc_missing'));
});

test('an NXDOMAIN confirmed by a second resolver is a real problem', async () => {
  const r = await checkDns('nope.example', nxResolver(), { confirm: nxResolver() });
  assert.deepEqual(codes(r), ['dns_nxdomain']);
  assert.equal(r.nxdomainConfirmed, true);
});

test('an NXDOMAIN no second resolver can confirm is only a warning', async () => {
  // The resolver that reports a name as missing may be the same one timing
  // out on its neighbours. "This domain does not exist" is too alarming a
  // claim to make on one unverified answer.
  const r = await checkDns('nope.example', nxResolver(), { confirm: brokenResolver() });
  assert.deepEqual(codes(r), ['dns_nxdomain_unconfirmed']);
  assert.equal(r.issues[0].level, 'warning');
  assert.equal(r.nxdomainConfirmed, false);
});

test('with no second resolver at all, an NXDOMAIN stays a warning', async () => {
  const r = await checkDns('nope.example', nxResolver());
  assert.deepEqual(codes(r), ['dns_nxdomain_unconfirmed']);
});

test('a resolver contradicted by a second one is reported as unreliable', async () => {
  const live = {
    name: 'live',
    a: async () => ({ records: ['203.0.113.9'], error: null, nxdomain: false }),
    ns: async () => ({ records: ['ns1.example.net'], error: null, nxdomain: false }),
  };
  const r = await checkDns('actually-fine.example', nxResolver(), { confirm: live });
  assert.deepEqual(codes(r), ['dns_resolver_disagreement']);
  assert.equal(r.unreliable, true);
  assert.match(r.issues[0].message, /--doh/);
});

test('an unreliable resolver leaves the domain ungraded', async () => {
  const live = {
    name: 'live',
    a: async () => ({ records: ['203.0.113.9'], error: null, nxdomain: false }),
    ns: async () => ({ records: ['ns1.example.net'], error: null, nxdomain: false }),
  };
  const r = await sweepDomain('actually-fine.example', {
    resolver: nxResolver(), confirmResolver: live, skip: ['ssl', 'rdap'],
  });
  assert.equal(r.score, null);
  assert.equal(r.grade, '?');
  // Above all: no critical claiming the domain does not exist.
  assert.ok(!codes(r).includes('dns_nxdomain'));
});

// --- parked domains ------------------------------------------------------

test('a parked domain gets warnings about spoofing, not criticals', async () => {
  // Most of a large portfolio is parked. Treating those like an unprotected
  // mailbox domain buries the handful that actually matter.
  const r = await checkEmail('parked.example', parkedResolver());
  const spf = r.issues.find((i) => i.code === 'spf_missing');
  const dmarc = r.issues.find((i) => i.code === 'dmarc_missing');
  assert.equal(spf.level, 'warning');
  assert.equal(dmarc.level, 'warning');
  assert.match(spf.message, /receives no mail/);
});

test('DKIM selectors are not probed on a domain with no MX', async () => {
  // 21 selectors is 42 DNS queries per domain; across a portfolio that load
  // is what makes a resolver start dropping answers.
  let queries = 0;
  const base = parkedResolver();
  const counting = {
    ...base,
    txt: async (n) => { queries += 1; return base.txt(n); },
    cname: async (n) => { queries += 1; return base.cname(n); },
  };
  const r = await checkEmail('parked.example', counting);
  assert.equal(r.dkimProbed, false);
  assert.equal(r.dkim.length, 0);
  // apex TXT, _dmarc TXT, and the SPF walk. Nowhere near 42.
  assert.ok(queries <= 4, `expected a handful of queries, made ${queries}`);
});

test('DKIM is still probed when the domain receives mail', async () => {
  const base = parkedResolver();
  const withMail = {
    ...base,
    mx: async () => ({ records: [{ priority: 10, exchange: 'mx.example.net' }], error: null, nxdomain: false }),
  };
  const r = await checkEmail('live.example', withMail);
  assert.equal(r.dkimProbed, true);
  assert.ok(codes(r).includes('dkim_not_found'));
});

// --- no cascading findings ------------------------------------------------

test('an unreachable certificate is not reported when DNS never resolved', async () => {
  const r = await sweepDomain('example.com', {
    resolver: brokenResolver(),
    skip: ['rdap'],
    sslCheck: async () => ({
      reachable: false,
      error: 'EAI_AGAIN',
      issues: [{ level: 'warning', code: 'tls_unreachable', message: 'Could not open an HTTPS connection (EAI_AGAIN).' }],
    }),
  });
  // One honest finding about DNS beats the same cause restated four times.
  assert.ok(!codes(r).includes('tls_unreachable'));
  assert.ok(codes(r).includes('dns_lookup_failed'));
});

// --- an unknown is not an A ----------------------------------------------

test('a domain whose lookups failed is not graded', async () => {
  // Reporting 92/A for a domain nothing is known about is worse than
  // reporting nothing, because it looks like an answer.
  const r = await sweepDomain('example.com', { resolver: brokenResolver(), skip: ['ssl', 'rdap'] });
  assert.equal(r.score, null);
  assert.equal(r.grade, '?');
  assert.equal(r.checked, false);
});

test('a domain that does not exist scores zero', async () => {
  const resolver = nxResolver();
  const r = await sweepDomain('gone.example', { resolver, confirmResolver: nxResolver(), skip: ['ssl', 'rdap'] });
  assert.equal(r.score, 0);
  assert.equal(r.grade, 'F');
});

test('a domain that does not exist gets no advice about SPF', async () => {
  // "Publish v=spf1 -all" is not something you can act on for a name that
  // does not exist.
  const r = await sweepDomain('gone.example', { resolver: nxResolver(), confirmResolver: nxResolver(), skip: ['ssl', 'rdap'] });
  assert.deepEqual(codes(r), ['dns_nxdomain']);
});

test('the table says unchecked rather than inventing a grade', async () => {
  const { renderTable } = await import('../src/report/table.js');
  const r = await sweepDomain('example.com', { resolver: brokenResolver(), skip: ['ssl', 'rdap'] });
  const out = renderTable([r], { colour: false, details: false });
  assert.match(out, /unchecked/);
  assert.ok(!/\b92\b/.test(out), 'must not print a score for an unchecked domain');
});
