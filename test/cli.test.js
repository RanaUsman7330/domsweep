import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const run = promisify(execFile);
const BIN = fileURLToPath(new URL('../bin/domsweep.js', import.meta.url));

/** Run the CLI and return stdout, stderr and the exit code, never throwing. */
async function cli(args) {
  try {
    const { stdout, stderr } = await run(process.execPath, [BIN, ...args], { env: { ...process.env, NO_COLOR: '1' } });
    return { stdout, stderr, code: 0 };
  } catch (err) {
    return { stdout: err.stdout ?? '', stderr: err.stderr ?? '', code: err.code };
  }
}

/** Same, but writes `input` to stdin and closes it. */
function pipe(args, input) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [BIN, ...args], { env: { ...process.env, NO_COLOR: '1' } });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c; });
    child.stderr.on('data', (c) => { stderr += c; });
    child.on('close', (code) => resolve({ stdout, stderr, code }));
    child.stdin.end(input);
  });
}

test('--version prints just the version', async () => {
  const { stdout, code } = await cli(['--version']);
  assert.equal(code, 0);
  assert.match(stdout.trim(), /^\d+\.\d+\.\d+$/);
});

test('--help explains usage and exits cleanly', async () => {
  const { stdout, code } = await cli(['--help']);
  assert.equal(code, 0);
  assert.ok(stdout.includes('USAGE'));
  assert.ok(stdout.includes('--fail-on'));
});

test('--demo produces a readable table', async () => {
  const { stdout, code } = await cli(['--demo']);
  assert.equal(code, 0);
  assert.ok(stdout.includes('DOMAIN'));
  assert.ok(stdout.includes('well-run.example'));
});

test('--format json emits valid JSON', async () => {
  const { stdout, code } = await cli(['--demo', '--format', 'json']);
  assert.equal(code, 0);
  const data = JSON.parse(stdout);
  assert.equal(data.length, 4);
  assert.ok(data.every((r) => typeof r.score === 'number'));
});

test('--fail-on critical exits 2 when something is critical', async () => {
  const { code } = await cli(['--demo', '--fail-on', 'critical', '--format', 'csv']);
  assert.equal(code, 2);
});

test('without --fail-on the exit code stays 0', async () => {
  const { code } = await cli(['--demo', '--format', 'csv']);
  assert.equal(code, 0);
});

test('an unknown format is rejected with a usage error', async () => {
  const { code, stderr } = await cli(['--demo', '--format', 'xml']);
  assert.equal(code, 64);
  assert.ok(stderr.includes('unknown format'));
});

test('an unknown flag is rejected rather than ignored', async () => {
  const { code } = await cli(['--demo', '--nope']);
  assert.equal(code, 64);
});

test('domains can be piped in on stdin', async () => {
  // Reading the list from stdin is what makes it composable with other tools.
  const { stdout, code } = await pipe(
    ['-f', '-', '--format', 'csv', '--skip', 'dns,email,ssl,rdap', '--quiet'],
    'first.example\nsecond.example\n',
  );
  assert.equal(code, 0);
  const lines = stdout.trim().split('\n');
  assert.ok(lines[0].startsWith('domain,score'));
  assert.equal(lines.length, 3);
});
