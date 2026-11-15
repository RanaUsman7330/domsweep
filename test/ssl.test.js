import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateCertificate } from '../src/checks/ssl.js';

const DAY = 86_400_000;
const NOW = Date.parse('2026-06-01T00:00:00Z');
const codes = (r) => r.issues.map((i) => i.code);

function cert(daysLeft, extra = {}) {
  return {
    reachable: true,
    authorized: daysLeft >= 0,
    authorizationError: daysLeft < 0 ? 'CERT_HAS_EXPIRED' : null,
    protocol: 'TLSv1.3',
    cert: {
      valid_from: new Date(NOW - 60 * DAY).toUTCString(),
      valid_to: new Date(NOW + daysLeft * DAY).toUTCString(),
      issuer: { O: "Let's Encrypt" },
      subject: { CN: 'example.com' },
      subjectaltname: 'DNS:example.com, DNS:www.example.com',
      ...extra,
    },
  };
}

test('an unreachable host is a warning, not a crash', () => {
  const r = evaluateCertificate({ reachable: false, error: 'ECONNREFUSED' }, 'example.com', NOW);
  assert.equal(r.reachable, false);
  assert.deepEqual(codes(r), ['tls_unreachable']);
});

test('a healthy certificate raises nothing', () => {
  const r = evaluateCertificate(cert(80), 'example.com', NOW);
  assert.equal(r.daysLeft, 80);
  assert.equal(r.issuer, "Let's Encrypt");
  assert.deepEqual(codes(r), []);
});

test('expiry thresholds escalate', () => {
  assert.deepEqual(codes(evaluateCertificate(cert(25), 'example.com', NOW)), ['tls_expiring_soon']);
  assert.deepEqual(codes(evaluateCertificate(cert(10), 'example.com', NOW)), ['tls_expiring']);
  assert.ok(codes(evaluateCertificate(cert(-3), 'example.com', NOW)).includes('tls_expired'));
});

test('an expired certificate is not also reported as untrusted', () => {
  // One clear finding is more useful than two that describe the same cause.
  assert.deepEqual(codes(evaluateCertificate(cert(-3), 'example.com', NOW)), ['tls_expired']);
});

test('a hostname mismatch is critical', () => {
  const raw = cert(90);
  raw.authorized = false;
  raw.authorizationError = 'ERR_TLS_CERT_ALTNAME_INVALID';
  assert.ok(codes(evaluateCertificate(raw, 'other.com', NOW)).includes('tls_hostname_mismatch'));
});

test('a self-signed certificate is critical', () => {
  const raw = cert(90);
  raw.authorized = false;
  raw.authorizationError = 'DEPTH_ZERO_SELF_SIGNED_CERT';
  assert.ok(codes(evaluateCertificate(raw, 'example.com', NOW)).includes('tls_self_signed'));
});

test('subject alternative names are listed', () => {
  const r = evaluateCertificate(cert(90), 'example.com', NOW);
  assert.deepEqual(r.names, ['example.com', 'www.example.com']);
});
