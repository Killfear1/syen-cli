'use strict';
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { execFileSync, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { jcs } = require('../lib/jcs');
const { verifyBundle, GENESIS } = require('../lib/verify');

test('jcs canonicalizes per RFC 8785', () => {
  assert.strictEqual(jcs({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.strictEqual(jcs({ '1': true, '\n': [1] }), '{"\\n":[1],"1":true}');
  assert.strictEqual(jcs([56.8, { x: {} }]), '[56.8,{"x":{}}]');
  assert.strictEqual(jcs(1e21), '1e+21');
  assert.strictEqual(jcs('hi "there"'), '"hi \\"there\\""');
  assert.throws(() => jcs(NaN));
});

function makeBundle() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const payloads = [
    { event: 'receipt.issued', amount: 42, currency: 'USD' },
    { event: 'receipt.verified', amount: 42, currency: 'USD' },
  ];
  let prev = GENESIS;
  const records = payloads.map((payload, i) => {
    const hash = crypto.createHash('sha256').update(prev, 'utf8').update(jcs(payload), 'utf8').digest('hex');
    prev = hash;
    return { id: `rec-${i}`, payload, hash, signature: crypto.sign(null, Buffer.from(hash, 'utf8'), privateKey).toString('base64') };
  });
  return { format: 'syen-evidence-bundle/v1', public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }), records };
}

test('verify passes a well-formed bundle', () => {
  const r = verifyBundle(makeBundle());
  assert.strictEqual(r.ok, true);
  assert.deepStrictEqual(r.records.map((x) => x.chain), ['PASS', 'PASS']);
  assert.deepStrictEqual(r.records.map((x) => x.signature), ['PASS', 'PASS']);
});

test('verify fails a tampered payload and a broken chain', () => {
  const b = makeBundle();
  b.records[1].payload.amount = 43;
  const r = verifyBundle(b);
  assert.strictEqual(r.ok, false);
  // tampering the payload breaks the chain link; the stored hash is still validly
  // signed, which is exactly how the mismatch gets exposed.
  assert.strictEqual(r.records[1].chain, 'FAIL');
  assert.strictEqual(r.records[1].signature, 'PASS');
  assert.strictEqual(r.records[0].chain, 'PASS');
});

test('verify rejects wrong format and non-ed25519 keys', () => {
  assert.throws(() => verifyBundle({ format: 'nope', records: [{}] }), /unrecognized bundle format/);
  const b = makeBundle();
  b.public_key_pem = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'spki', format: 'pem' });
  assert.throws(() => verifyBundle(b), /not Ed25519/);
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

test('cli verify exits 0 on pass, 1 on tamper', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'syen-'));
  const good = path.join(dir, 'good.json');
  fs.writeFileSync(good, JSON.stringify(makeBundle()));
  const pass = spawnSync('node', ['bin/syen.js', 'verify', good], { encoding: 'utf8' });
  assert.strictEqual(pass.status, 0, pass.stderr);
  assert.match(pass.stdout, /PASS - 2 record\(s\) verified offline/);
  const bad = JSON.parse(fs.readFileSync(good, 'utf8'));
  bad.records[0].hash = '0'.repeat(64);
  const badfile = path.join(dir, 'bad.json');
  fs.writeFileSync(badfile, JSON.stringify(bad));
  const fail = spawnSync('node', ['bin/syen.js', 'verify', badfile], { encoding: 'utf8' });
  assert.strictEqual(fail.status, 1);
});
