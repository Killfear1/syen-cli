'use strict';
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { execFileSync, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { jcs } = require('../lib/jcs');
const { verifyBundle } = require('../lib/verifier');

test('jcs canonicalizes per RFC 8785', () => {
  assert.strictEqual(jcs({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.strictEqual(jcs({ '1': true, '\n': [1] }), '{"\\n":[1],"1":true}');
  assert.strictEqual(jcs([56.8, { x: {} }]), '[56.8,{"x":{}}]');
  assert.strictEqual(jcs(1e21), '1e+21');
  assert.strictEqual(jcs('hi "there"'), '"hi \\"there\\""');
  assert.throws(() => jcs(NaN));
});

const PUB = fs.readFileSync(path.join(__dirname, 'fixtures', 'demo-pubkey.b64'), 'utf8').trim();
const loadFixture = (n) => JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', n), 'utf8'));

test('verify matches the real verifier: well-formed bundle passes', () => {
  const r = verifyBundle(loadFixture('valid-bundle.json'), PUB, 'acme-prod');
  assert.strictEqual(r.verdict, 'PASS_WITH_LIMITS'); // MANIFEST_NOT_AUTHENTICATED is always warned by design
  assert.deepStrictEqual(r.failures, []);
  assert.strictEqual(r.checked.events, 2);
  assert.strictEqual(r.checked.chain_links, 1);
  assert.strictEqual(r.checked.receipt_references, 2);
  assert.strictEqual(r.checked.signatures_verified, 2);
});

test('verify matches the real verifier: tampered event fails HASH_MISMATCH', () => {
  const r = verifyBundle(loadFixture('tampered-bundle.json'), PUB, 'acme-prod');
  assert.strictEqual(r.verdict, 'FAIL');
  assert.ok(r.failures.some((f) => f.code === 'HASH_MISMATCH'));
});

test('verify matches the real verifier: broken chain fails BROKEN_CHAIN', () => {
  const r = verifyBundle(loadFixture('broken-chain.json'), PUB, 'acme-prod');
  assert.strictEqual(r.verdict, 'FAIL');
  assert.ok(r.failures.some((f) => f.code === 'BROKEN_CHAIN'));
});

test('verify enforces tenant pinning and never trusts the bundle key', () => {
  const r = verifyBundle(loadFixture('valid-bundle.json'), PUB, 'other-tenant');
  assert.strictEqual(r.verdict, 'FAIL');
  assert.ok(r.failures.some((f) => f.code === 'TENANT_MISMATCH'));
  const r2 = verifyBundle(loadFixture('valid-bundle.json'), null, 'acme-prod');
  assert.strictEqual(r2.checked.signatures_verified, 0);
  assert.ok(r2.warnings.some((w) => w.code === 'SIGNATURES_NOT_CHECKED'));
});

test('verify fails closed on malformed input', () => {
  const r = verifyBundle(null);
  assert.strictEqual(r.verdict, 'FAIL');
  assert.strictEqual(r.failures[0].code, 'MALFORMED_BUNDLE');
  assert.strictEqual(verifyBundle({}).failures[0].detail, 'no events list');
});


test('cli meta and news read the public API', async () => {
  const { spawn } = require('node:child_process');
  const srv = spawn('node', ['test/fixture-server.js'], { stdio: ['ignore', 'pipe', 'inherit'] });
  const port = await new Promise((resolve) => srv.stdout.once('data', (d) => resolve(d.toString().trim())));
  try {
    const env = { ...process.env, SYEN_API_BASE: `http://127.0.0.1:${port}` };
    const meta = execFileSync('node', ['bin/syen.js', 'meta'], { env, encoding: 'utf8' });
    assert.match(meta, /SYEN Comply/);
    assert.match(meta, /Pro: \$33,000\/mo/);
    const news = execFileSync('node', ['bin/syen.js', 'news', '--json'], { env, encoding: 'utf8' });
    assert.strictEqual(JSON.parse(news).items[0].source, 'Reuters');
  } finally {
    srv.kill();
  }
});

test('cli verify exits 0 on pass, 1 on tamper, 2 on usage error', () => {
  const dir = path.join(__dirname, 'fixtures');
  const pub = fs.readFileSync(path.join(dir, 'demo-pubkey.b64'), 'utf8').trim();
  const pass = spawnSync('node', ['bin/syen.js', 'verify', path.join(dir, 'valid-bundle.json'), '--trusted-pubkey', pub, '--tenant', 'acme-prod'], { encoding: 'utf8' });
  assert.strictEqual(pass.status, 0, pass.stderr);
  assert.match(pass.stdout, /^PASS_WITH_LIMITS /);
  const fail = spawnSync('node', ['bin/syen.js', 'verify', path.join(dir, 'tampered-bundle.json'), '--trusted-pubkey', pub, '--tenant', 'acme-prod'], { encoding: 'utf8' });
  assert.strictEqual(fail.status, 1);
  assert.match(fail.stdout, /FAIL.*HASH_MISMATCH/s);
  const usage = spawnSync('node', ['bin/syen.js', 'verify'], { encoding: 'utf8' });
  assert.strictEqual(usage.status, 2);
});
