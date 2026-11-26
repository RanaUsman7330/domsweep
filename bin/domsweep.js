#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { readFile, writeFile } from 'node:fs/promises';
import process from 'node:process';
import { confirmResolverFor, createResolver } from '../src/resolver.js';
import { sweep } from '../src/runner.js';
import { parseDomainList } from '../src/input.js';
import { renderTable } from '../src/report/table.js';
import { renderCsv } from '../src/report/csv.js';
import { renderHtml } from '../src/report/html.js';
import { demoResults } from '../src/demo.js';

const VERSION = '0.1.0';

const HELP = `
domsweep ${VERSION} — sweep a domain portfolio for DNS, email and SSL problems

USAGE
  domsweep <domain...>                 check one or more domains
  domsweep -f domains.txt              check every domain in a file
  cat domains.csv | domsweep -f -      read the list from stdin

OPTIONS
  -f, --file <path>         file with one domain per line, or a CSV whose
                            first column is the domain ("-" reads stdin)
  -o, --out <path>          write the report to a file instead of stdout
      --format <name>       table (default), json, csv or html
  -c, --concurrency <n>     domains checked at once (default 8)
      --skip <list>         skip checks: dns, email, ssl, rdap
      --expect-ns <list>    nameservers every domain should be using, so
                            drift across a portfolio is reported
      --dkim-selectors <l>  DKIM selectors to probe instead of the defaults
      --doh                 resolve over DNS-over-HTTPS instead of the system
                            resolver, for identical results everywhere
      --dns <servers>       use these DNS servers (comma separated)
      --timeout <ms>        per-connection timeout (default 10000)
      --fail-on <level>     exit non-zero on findings: critical, warning, never
                            (default never)
      --no-details          table report without the per-domain findings
      --no-color            plain output
  -q, --quiet               no progress on stderr
      --demo                print a sample report using built-in data
  -h, --help                show this help
  -v, --version             show the version

EXAMPLES
  domsweep mrusman.com
  domsweep -f domains.txt --format html -o report.html
  domsweep -f domains.txt --expect-ns ns1.hostinger.com,ns2.hostinger.com
  domsweep -f domains.txt --fail-on critical --quiet --format json

Every check is read-only: domsweep makes DNS queries, opens a TLS connection
and reads public registration data. It never changes anything.
`;

function fail(message) {
  process.stderr.write(`domsweep: ${message}\n`);
  process.exit(64);
}

const list = (v) => (v ? v.split(',').map((s) => s.trim()).filter(Boolean) : null);

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

async function main() {
  let parsed;
  try {
    parsed = parseArgs({
      allowPositionals: true,
      options: {
        file: { type: 'string', short: 'f' },
        out: { type: 'string', short: 'o' },
        format: { type: 'string', default: 'table' },
        concurrency: { type: 'string', short: 'c', default: '8' },
        skip: { type: 'string' },
        'expect-ns': { type: 'string' },
        'dkim-selectors': { type: 'string' },
        doh: { type: 'boolean', default: false },
        dns: { type: 'string' },
        timeout: { type: 'string', default: '10000' },
        'fail-on': { type: 'string', default: 'never' },
        'no-details': { type: 'boolean', default: false },
        'no-color': { type: 'boolean', default: false },
        quiet: { type: 'boolean', short: 'q', default: false },
        demo: { type: 'boolean', default: false },
        help: { type: 'boolean', short: 'h', default: false },
        version: { type: 'boolean', short: 'v', default: false },
      },
    });
  } catch (err) {
    fail(err.message);
  }

  const { values: opts, positionals } = parsed;

  if (opts.help) { process.stdout.write(HELP); return 0; }
  if (opts.version) { process.stdout.write(`${VERSION}\n`); return 0; }

  const format = opts.format.toLowerCase();
  if (!['table', 'json', 'csv', 'html'].includes(format)) {
    fail(`unknown format "${opts.format}". Use table, json, csv or html.`);
  }

  const failOn = opts['fail-on'].toLowerCase();
  if (!['critical', 'warning', 'never'].includes(failOn)) {
    fail(`unknown --fail-on "${opts['fail-on']}". Use critical, warning or never.`);
  }

  let results;

  if (opts.demo) {
    results = await demoResults();
  } else {
    let text = positionals.join('\n');
    if (opts.file) {
      text = opts.file === '-' ? await readStdin() : await readFile(opts.file, 'utf8');
    } else if (!positionals.length && !process.stdin.isTTY) {
      text = await readStdin();
    }

    const { domains, skipped } = parseDomainList(text);

    if (!domains.length) {
      process.stderr.write(`${HELP}\n`);
      fail('no domains given.');
    }
    if (skipped.length && !opts.quiet) {
      process.stderr.write(`domsweep: skipped ${skipped.length} line(s) that are not domains\n`);
    }

    const concurrency = Math.max(1, Number(opts.concurrency) || 8);
    const timeout = Math.max(1000, Number(opts.timeout) || 10_000);
    const resolverOptions = {
      doh: opts.doh,
      timeout: Math.min(timeout, 8000),
      servers: list(opts.dns) ?? undefined,
    };
    const resolver = createResolver(resolverOptions);
    // Only ever consulted to double-check a name reported as non-existent,
    // so it costs nothing on a healthy sweep.
    const confirmResolver = confirmResolverFor(resolverOptions);

    let done = 0;
    const showProgress = !opts.quiet && process.stderr.isTTY;

    results = await sweep(domains, {
      resolver,
      confirmResolver,
      concurrency,
      skip: list(opts.skip) ?? [],
      expectNs: list(opts['expect-ns']),
      dkimSelectors: list(opts['dkim-selectors']) ?? undefined,
      sslTimeout: timeout,
      rdapTimeout: timeout,
      onResult: () => {
        done += 1;
        if (showProgress) {
          process.stderr.write(`\rchecked ${done}/${domains.length}`.padEnd(32));
        }
      },
    });

    if (showProgress) process.stderr.write('\r'.padEnd(34) + '\r');
  }

  const useColour = !opts['no-color'] && !process.env.NO_COLOR && (opts.out ? false : process.stdout.isTTY !== false);

  let output;
  if (format === 'json') output = `${JSON.stringify(results, null, 2)}\n`;
  else if (format === 'csv') output = `${renderCsv(results)}\n`;
  else if (format === 'html') output = `${renderHtml(results)}\n`;
  else output = `${renderTable(results, { colour: useColour, details: !opts['no-details'] })}\n`;

  if (opts.out) {
    await writeFile(opts.out, output, 'utf8');
    if (!opts.quiet) process.stderr.write(`domsweep: wrote ${opts.out}\n`);
  } else {
    process.stdout.write(output);
  }

  if (failOn === 'never') return 0;
  const hasCritical = results.some((r) => r.level === 'critical');
  const hasWarning = results.some((r) => r.level === 'warning');
  if (hasCritical) return 2;
  if (failOn === 'warning' && hasWarning) return 1;
  return 0;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    process.stderr.write(`domsweep: ${err?.stack ?? err}\n`);
    process.exit(70);
  });
