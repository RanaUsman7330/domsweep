import tls from 'node:tls';

const DAY = 86_400_000;

/**
 * Open a TLS connection and read the certificate. Verification failures are
 * reported rather than thrown, because an expired or mismatched certificate
 * is exactly what we want to see and describe.
 */
export function fetchCertificate(host, { port = 443, timeout = 10_000, servername = host } = {}) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (value) => { if (!settled) { settled = true; resolve(value); } };

    const socket = tls.connect(
      { host, port, servername, timeout, rejectUnauthorized: false, ALPNProtocols: ['http/1.1'] },
      () => {
        const cert = socket.getPeerCertificate(true);
        const result = {
          reachable: true,
          authorized: socket.authorized,
          authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
          protocol: socket.getProtocol(),
          cert: cert && Object.keys(cert).length ? cert : null,
        };
        socket.destroy();
        done(result);
      },
    );

    socket.on('error', (err) => {
      socket.destroy();
      done({ reachable: false, error: err.code ?? String(err.message ?? err), cert: null });
    });
    socket.on('timeout', () => {
      socket.destroy();
      done({ reachable: false, error: 'ETIMEDOUT', cert: null });
    });
  });
}

/** Turn a certificate into findings. Pure, so it is unit testable. */
export function evaluateCertificate(result, host, now = Date.now()) {
  if (!result.reachable) {
    return {
      reachable: false,
      error: result.error,
      issues: [{ level: 'warning', code: 'tls_unreachable', message: `Could not open an HTTPS connection (${result.error}).` }],
    };
  }

  const cert = result.cert;
  if (!cert?.valid_to) {
    return {
      reachable: true,
      issues: [{ level: 'warning', code: 'tls_no_certificate', message: 'Connected but no certificate was presented.' }],
    };
  }

  const validTo = new Date(cert.valid_to);
  const validFrom = new Date(cert.valid_from);
  const daysLeft = Math.floor((validTo.getTime() - now) / DAY);
  const issues = [];

  if (daysLeft < 0) {
    issues.push({ level: 'critical', code: 'tls_expired', message: `Certificate expired ${Math.abs(daysLeft)} days ago. Browsers show a full-page warning.` });
  } else if (daysLeft <= 14) {
    issues.push({ level: 'critical', code: 'tls_expiring', message: `Certificate expires in ${daysLeft} days.` });
  } else if (daysLeft <= 30) {
    issues.push({ level: 'warning', code: 'tls_expiring_soon', message: `Certificate expires in ${daysLeft} days.` });
  }

  if (validFrom.getTime() > now) {
    issues.push({ level: 'critical', code: 'tls_not_yet_valid', message: 'Certificate is not valid yet.' });
  }

  if (result.authorizationError && daysLeft >= 0) {
    const code = result.authorizationError;
    // Node reports a name mismatch as ERR_TLS_CERT_ALTNAME_INVALID, and as
    // "Hostname/IP does not match" when the message is surfaced instead.
    if (/ALTNAME|HOSTNAME|Hostname\/IP/i.test(code)) {
      issues.push({ level: 'critical', code: 'tls_hostname_mismatch', message: `Certificate does not cover ${host}.` });
    } else if (/SELF_SIGNED/i.test(code)) {
      issues.push({ level: 'critical', code: 'tls_self_signed', message: 'Certificate is self-signed, so browsers will not trust it.' });
    } else {
      issues.push({ level: 'warning', code: 'tls_not_trusted', message: `Certificate did not verify (${code}).` });
    }
  }

  const names = (cert.subjectaltname ?? '')
    .split(',')
    .map((s) => s.trim().replace(/^DNS:/, ''))
    .filter(Boolean);

  return {
    reachable: true,
    daysLeft,
    validFrom: validFrom.toISOString(),
    validTo: validTo.toISOString(),
    issuer: cert.issuer?.O ?? cert.issuer?.CN ?? null,
    subject: cert.subject?.CN ?? null,
    names,
    authorized: result.authorized,
    protocol: result.protocol ?? null,
    issues,
  };
}

export async function checkSsl(domain, options = {}) {
  const raw = await fetchCertificate(domain, options);
  return evaluateCertificate(raw, domain, options.now);
}
