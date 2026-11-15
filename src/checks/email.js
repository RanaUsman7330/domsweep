import { evaluateSpf, findSpfRecords, parseSpf } from '../parse/spf.js';
import { evaluateDmarc } from '../parse/dmarc.js';

/**
 * Selectors worth probing when no selector is configured. A DKIM key lives at
 * <selector>._domainkey.<domain> and there is no way to enumerate selectors,
 * so the best a scanner can do is try the ones the major senders use.
 */
export const COMMON_DKIM_SELECTORS = [
  'google', 'selector1', 'selector2', 'default', 'dkim', 'mail', 'k1', 'k2',
  's1', 's2', 'zoho', 'pm', 'mandrill', 'mailjet', 'sendgrid', 'everlytickey1',
  'hs1', 'hs2', 'protonmail', 'amazonses', 'smtp',
];

/** Well-known mail providers, matched against MX hostnames. */
const MX_PROVIDERS = [
  [/aspmx.*google|googlemail\.com$/i, 'Google Workspace'],
  [/outlook\.com$|protection\.outlook\.com$/i, 'Microsoft 365'],
  [/zoho/i, 'Zoho Mail'],
  [/protonmail|proton\.me$/i, 'Proton Mail'],
  [/messagingengine\.com$/i, 'Fastmail'],
  [/yandex/i, 'Yandex'],
  [/secureserver\.net$/i, 'GoDaddy'],
  [/hostinger/i, 'Hostinger'],
  [/titan\.email$|flockmail/i, 'Titan'],
  [/mimecast/i, 'Mimecast'],
  [/pphosted\.com$/i, 'Proofpoint'],
];

function detectProvider(exchanges) {
  for (const [pattern, name] of MX_PROVIDERS) {
    if (exchanges.some((e) => pattern.test(e))) return name;
  }
  return null;
}

/**
 * Walk include: and redirect= to count the DNS lookups SPF really costs.
 * The RFC limit of 10 applies to the whole recursive evaluation, not just the
 * top record, which is why "my SPF looks short but still fails" is so common.
 */
export async function countSpfLookups(domain, resolver, { maxDepth = 10 } = {}) {
  const seen = new Set();
  let total = 0;
  let truncated = false;

  async function walk(name, depth) {
    if (depth > maxDepth) { truncated = true; return; }
    if (seen.has(name)) return; // a loop costs lookups but must not hang us
    seen.add(name);

    const { records: txt, error } = await resolver.txt(name);
    if (error) return;

    const records = findSpfRecords(txt);
    if (records.length !== 1) return;

    const parsed = parseSpf(records[0]);
    total += parsed.lookups;

    for (const inc of parsed.includes) {
      if (inc) await walk(inc, depth + 1);
    }
    if (parsed.redirect) await walk(parsed.redirect, depth + 1);
  }

  await walk(domain, 0);
  return { total, truncated, visited: seen.size };
}

export async function probeDkim(domain, resolver, selectors = COMMON_DKIM_SELECTORS) {
  const found = [];
  await Promise.all(selectors.map(async (sel) => {
    const name = `${sel}._domainkey.${domain}`;
    const [txt, cname] = await Promise.all([resolver.txt(name), resolver.cname(name)]);
    const record = txt.records.find((r) => /v=DKIM1|k=rsa|p=/i.test(r));
    if (record) found.push({ selector: sel, via: 'txt', record });
    else if (cname.records.length) found.push({ selector: sel, via: 'cname', target: cname.records[0] });
  }));
  return found.sort((a, b) => a.selector.localeCompare(b.selector));
}

/**
 * A domain that receives no mail is still spoofable, so SPF and DMARC are
 * worth publishing on it. It is not an emergency the way an unprotected
 * mailbox domain is, and treating the two the same buries the real problems
 * in a portfolio where most domains are parked.
 */
function adjustForNoMail(issues) {
  return issues.map((issue) => {
    if (issue.code === 'spf_missing') {
      return { ...issue, level: 'warning', message: 'No SPF record. The domain receives no mail, but it can still be spoofed; publish "v=spf1 -all".' };
    }
    if (issue.code === 'dmarc_missing') {
      return { ...issue, level: 'warning', message: 'No DMARC record. The domain receives no mail, but it can still be spoofed; publish "v=DMARC1; p=reject".' };
    }
    return issue;
  });
}

export async function checkEmail(domain, resolver, { dkimSelectors, skipIfNoMail = true } = {}) {
  const [mx, txt, dmarcTxt] = await Promise.all([
    resolver.mx(domain),
    resolver.txt(domain),
    resolver.txt(`_dmarc.${domain}`),
  ]);

  const exchanges = mx.records.map((m) => m.exchange);
  const hasMail = exchanges.length > 0;

  // Probing 21 selectors costs 42 DNS queries. On a parked domain that is
  // wasted load, and across a large portfolio it is enough to make a resolver
  // start dropping answers.
  const [lookupInfo, dkim] = await Promise.all([
    txt.error ? Promise.resolve({ total: 0, truncated: false, visited: 0 }) : countSpfLookups(domain, resolver),
    hasMail || !skipIfNoMail ? probeDkim(domain, resolver, dkimSelectors) : Promise.resolve([]),
  ]);

  const spf = evaluateSpf(txt.records, { totalLookups: lookupInfo.total || null, lookupError: txt.error });
  const dmarc = evaluateDmarc(dmarcTxt.records, { lookupError: dmarcTxt.error });

  let issues = [...spf.issues, ...dmarc.issues];

  if (mx.error) {
    issues.push({ level: 'info', code: 'mx_lookup_failed', message: `MX lookup did not complete (${mx.error}).` });
  } else if (!hasMail) {
    issues.push({ level: 'info', code: 'mx_missing', message: 'No MX records, so this domain does not receive mail.' });
    issues = adjustForNoMail(issues);
  }

  if (hasMail && dkim.length === 0) {
    issues.push({
      level: 'warning',
      code: 'dkim_not_found',
      message: 'No DKIM key found at any common selector. It may use a custom selector, which you can pass with --dkim-selectors.',
    });
  }

  return {
    mx: exchanges,
    hasMail,
    provider: detectProvider(exchanges),
    spf,
    dmarc,
    dkim,
    dkimProbed: hasMail || !skipIfNoMail,
    spfLookups: lookupInfo,
    issues,
  };
}
