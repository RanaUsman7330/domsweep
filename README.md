# domsweep

Check DNS, email authentication, SSL and registration expiry across a whole
domain portfolio with one command.

Most domain checkers take one domain at a time in a browser. That is fine for
one domain and useless for two hundred. `domsweep` takes a list, checks every
domain in parallel and gives you one report sorted by what is most broken.

No dependencies, no account, no API key. It only reads: DNS queries, one TLS
handshake and public registration data. It never changes anything.

```bash
npx domsweep example.com
```

Or install it once and use the `domsweep` command anywhere:

```bash
npm install -g domsweep
domsweep example.com
```

## What it reports

| Area | Checks |
| --- | --- |
| **SPF** | present, exactly one record, qualifier on `all`, deprecated `ptr`, and the real DNS lookup count followed through every `include:` and `redirect=` |
| **DMARC** | present, policy, reporting address, percentage, subdomain policy |
| **DKIM** | probes 21 common selectors, or your own |
| **Mail** | MX records and which provider they point at |
| **TLS** | days to expiry, issuer, hostname match, self-signed, not-yet-valid |
| **Registration** | expiry date, registrar, transfer lock, via RDAP |
| **DNS** | A/AAAA present, nameserver count, drift from your expected nameservers |

Each finding is `critical`, `warning` or `info`, and each domain gets a score
out of 100 so a long list sorts itself.

## Try it without a network call

```bash
node bin/domsweep.js --demo
```

```
DOMAIN             SCORE  SPF          DMARC     DKIM     SSL      EXPIRES
-----------------  -----  -----------  --------  -------  -------  -------
forgotten.example  0 F    missing      missing   none     expired  9d
two-spf.example    26 F   2 records    missing   none     210d     55d
half-done.example  68 C   ~all (1/10)  p=none    none     21d      140d
well-run.example   100 A  -all (1/10)  p=reject  1 found  74d      300d

Findings

forgotten.example (0/100)
  critical [email] No SPF record. Anyone can send mail claiming to be this domain.
  critical [email] No DMARC record. Nothing tells receivers what to do with mail that fails SPF or DKIM.
  critical [ssl] Certificate expired 12 days ago. Browsers show a full-page warning.
  critical [domain] Domain registration expires in 9 days.
  warning  [domain] Transfer lock is off, which makes an unauthorised transfer easier.

two-spf.example (26/100)
  warning  [dns] Only one nameserver. A single failure takes the whole domain offline.
  critical [email] 2 SPF records found. Receivers treat this as an error, so SPF does not apply at all.
  critical [email] No DMARC record. Nothing tells receivers what to do with mail that fails SPF or DKIM.
  warning  [domain] Domain registration expires in 55 days.

4 domains  ·  2 critical  ·  1 warning  ·  1 clean
```

## A whole portfolio

Put the domains in a file, one per line. A CSV exported from your registrar
works too: the first column is used, and anything that is not a domain is
reported rather than dropped silently.

```bash
domsweep -f domains.txt
domsweep -f domains.txt --format html -o report.html
domsweep -f domains.csv --format csv -o audit.csv
cat domains.txt | domsweep -f -
```

The HTML report is a single self-contained file with no external assets, so
you can email it or drop it in a ticket.

### Nameserver drift

If every domain in your portfolio should sit on the same nameservers, say so
and the odd one out is reported:

```bash
domsweep -f domains.txt --expect-ns ns1.example-dns.net,ns2.example-dns.net
```

### In CI

`--fail-on` turns findings into an exit code. Nothing fails the build unless
you ask it to.

```yaml
- run: node bin/domsweep.js -f domains.txt --fail-on critical --quiet
```

Exit codes: `0` fine, `1` warnings (with `--fail-on warning`), `2` something
critical, `64` bad usage.

### A weekly check by email

```bash
domsweep -f domains.txt --format html -o report.html --quiet \
  && mail -s "Domain health" you@example.com < report.html
```

## The SPF lookup limit

SPF allows ten DNS lookups during evaluation. Go over and receivers return
`permerror`, which means SPF stops working — but the record still looks
perfectly fine when you read it.

The limit counts the whole recursive evaluation, not the record in front of
you. A two-line record can be well over it:

```
v=spf1 include:_spf.google.com include:sendgrid.net include:servers.mcsv.net -all
```

`domsweep` follows every `include:` and `redirect=` and reports the real
total, so `3/10` or `12/10` tells you whether you can add another sender.

## A failed lookup is not a missing record

If a resolver times out and the scanner returns an empty list, "nothing came
back" turns into "you have no SPF record" — and you go and fix a problem you
never had. domsweep keeps the two apart. A lookup that does not complete is
reported as unknown, at info level, and nothing downstream is inferred from
it:

```
example.com  —  SPF unknown  DMARC unknown
  warning [dns] DNS lookups did not complete (EAI_AGAIN). The domain may be
                fine; try again, or use --doh to bypass the local resolver.
```

Likewise, "this domain does not exist" is the most alarming thing a sweep can
say, so domsweep does not say it on one resolver's word — least of all a
resolver that may be timing out on the neighbouring domains in the same run.
A name reported as missing is re-checked against an independent resolver
(DoH when you are using the system one, the system one when you pass
`--doh`), and only a negative both agree on is reported as a fact. If the
second resolver cannot be reached you get a warning instead of a critical,
and if it resolves the name, the finding is about your resolver rather than
your domain:

```
actually-fine.example  —  unchecked
  warning [dns] The system resolver reports this name as non-existent, but a
                second resolver resolves it. Re-run with --doh; the local
                resolver is unreliable for this domain.
```

The second resolver is consulted only for a name that came back missing, so a
healthy sweep pays nothing for it.

A domain in that state gets no grade at all. It shows as `unchecked`, and
the columns below DNS show `-` rather than a result nothing established — an
A for a domain nothing is known about is worse than no answer, because it
looks like one. A domain that really does not exist in DNS scores 0 and is
spared the advice about publishing SPF records for a name that isn't there.

This is also why `--doh` exists. Local resolvers rate limit, filter, and are
sometimes simply unreliable for particular zones, and a sweep of hundreds of
domains is exactly the load that provokes it.

## Parked domains

In a portfolio of any size most domains are registered and pointed nowhere.
They are still spoofable, so a missing SPF or DMARC is worth knowing about,
but it is not the same emergency as an unprotected mailbox domain. domsweep
reports those as warnings rather than criticals, with wording that says what
to publish, and it skips DKIM probing on them entirely — which also keeps 42
DNS queries per domain off your resolver.

## Options

```
-f, --file <path>         file with one domain per line, or a CSV whose first
                          column is the domain ("-" reads stdin)
-o, --out <path>          write the report to a file instead of stdout
    --format <name>       table (default), json, csv or html
-c, --concurrency <n>     domains checked at once (default 8)
    --skip <list>         skip checks: dns, email, ssl, rdap
    --expect-ns <list>    nameservers every domain should be using
    --dkim-selectors <l>  DKIM selectors to probe instead of the defaults
    --doh                 resolve over DNS-over-HTTPS instead of the system
                          resolver, for identical results everywhere
    --dns <servers>       use these DNS servers (comma separated)
    --timeout <ms>        per-connection timeout (default 10000)
    --fail-on <level>     exit non-zero on findings: critical, warning, never
    --no-details          table report without the per-domain findings
    --no-color            plain output
-q, --quiet               no progress on stderr
    --demo                print a sample report using built-in data
```

`--doh` is worth knowing about: a corporate resolver, a VPN or a cached
negative answer can make the same domain look different on two machines.
DNS-over-HTTPS skips the local resolver so a team sees one answer.

## As a library

```js
import { sweep, createResolver } from 'domsweep';

const results = await sweep(['example.com', 'example.org'], {
  resolver: createResolver(),
  concurrency: 10,
});

for (const r of results) {
  if (r.level === 'critical') {
    console.log(r.domain, r.score, r.issues.map((i) => i.code));
  }
}
```

Everything is exported: `checkDns`, `checkEmail`, `checkSsl`, `checkRdap`, the
pure parsers `parseSpf`, `evaluateSpf`, `parseDmarc`, `evaluateDmarc`,
`evaluateCertificate`, `evaluateRdap`, and `parseDomainList`.

DNS goes through an injectable resolver, and the TLS and RDAP checks can be
replaced too, so you can test code that uses `domsweep` without a network:

```js
import { sweepDomain } from 'domsweep';

const reply = (records) => ({ records, error: null, nxdomain: false });

const result = await sweepDomain('example.com', {
  resolver: {
    a: async () => reply(['1.2.3.4']),
    aaaa: async () => reply([]),
    ns: async () => reply(['ns1.example.com']),
    mx: async () => reply([]),
    txt: async () => reply(['v=spf1 -all']),
    cname: async () => reply([]),
  },
  skip: ['ssl', 'rdap'],
});
```

Every resolver method returns `{ records, error, nxdomain }`. The three are
kept apart on purpose: see below.

## Install

```bash
npx domsweep --help           # run it without installing
npm install -g domsweep       # or put `domsweep` on your path
```

To use it as a library:

```bash
npm install domsweep
```

To run from a clone instead:

```bash
git clone https://github.com/RanaUsman7330/domsweep.git
cd domsweep
node bin/domsweep.js --help
```

Node 18.17 or newer. No dependencies.

## What it does not do

- It does not validate DKIM keys cryptographically, only that one is published.
- It cannot enumerate DKIM selectors, because DNS does not allow it. Without a
  match from the common list, pass `--dkim-selectors`.
- It reads one TLS certificate on port 443. It is not a full TLS configuration
  audit: use [testssl.sh](https://testssl.sh) for cipher suites and protocols.
- Many ccTLDs publish no RDAP at all, so no expiry date is available for
  them. domsweep checks the IANA bootstrap list before deciding, so an
  unsupported TLD reads as `rdap_not_supported` rather than being mistaken
  for an unregistered domain.
- It is a point-in-time check, not a monitor. Run it on a schedule.

## Contributing

Issues and pull requests are welcome, especially new provider patterns and
DKIM selectors.

```bash
git clone https://github.com/RanaUsman7330/domsweep.git
cd domsweep
node --test
```

Tests use the built-in Node test runner against fixtures, so the suite runs
offline.

## Licence

MIT © [Rana Usman](https://mrusman.com)
