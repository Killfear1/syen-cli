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
  assert.strictEqual(r.verdict, 'PASS_WITH_LIMITS'); // fixture predates signed manifests: legacy-classified
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

// --- signed manifest + simulation provenance (port of syen_verify.py F5.x semantics) ---
const { publicKey: SK_PUB, privateKey: SK_PRIV } = crypto.generateKeyPairSync('ed25519');
const SPUB = SK_PUB.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64');
const sha = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const T = 'acme-prod';
function mkEvent(seq, prev, extra = {}) {
  const sid = `${T}:authority:records`;
  const ed = { tenant_id: T, stream_id: sid, event_type: 'authority.outcome', seq, ...extra };
  const h = sha(jcs({ previous_hash: prev, event: ed }));
  return { event_id: crypto.randomUUID(), stream_id: sid, sequence_counter: seq, previous_event_hash: prev, event_data: ed,
           integrity_hash: h, tee_signature: crypto.sign(null, Buffer.from(h, 'hex'), SK_PRIV).toString('base64') };
}
function mkBundle({ grade = 'SIMULATED', basis = grade, signed = true, schema = true } = {}) {
  const e1 = mkEvent(1, null, grade ? { execution_grade: grade } : {});
  const e2 = mkEvent(2, e1.integrity_hash);
  const b = { tenant_id: T, events: [e1, e2] };
  if (!schema) return b;
  Object.assign(b, { schema: 'syen.evidence-bundle/1', exported_at: '2026-10-28T00:00:00Z',
    receipts: [{ receipt_id: 'r1', family: 'authority', tenant_id: T, evidence_basis: basis,
      signed_receipt: { stages: { outcome: { event_id: e1.event_id, integrity_hash: e1.integrity_hash } } } }],
    simulated_activity: grade === 'SIMULATED' || basis === 'SIMULATED' });
  if (signed) b.manifest_auth = { alg: 'Ed25519' };
  return seal(b, signed);
}
function seal(b, signed = 'manifest_auth' in b) {
  const body = { ...b }; delete body.manifest;
  const h = sha(jcs(body));
  b.manifest = signed ? { alg: 'sha256-jcs', sha256: h, signature: { alg: 'Ed25519', value: crypto.sign(null, Buffer.from(h, 'hex'), SK_PRIV).toString('base64') } }
                      : { alg: 'sha256-jcs', sha256: h };
  return b;
}
const codes = (r) => r.failures.map((f) => f.code);

test('signed manifest: genuine bundle + trusted key is AUTHENTICATED and PASS', () => {
  const r = verifyBundle(mkBundle(), SPUB, T);
  assert.deepStrictEqual(r.failures, []);
  assert.strictEqual(r.presentation_authentication, 'AUTHENTICATED');
  assert.strictEqual(r.verdict, 'PASS');
  assert.ok(!r.warnings.some((w) => w.code === 'MANIFEST_NOT_AUTHENTICATED'));
  assert.ok(!r.limits.some((l) => /unsigned/.test(l)));
  assert.strictEqual(r.provenance.declared_simulated_activity, true);
  assert.deepStrictEqual(r.provenance.grades_seen, ['SIMULATED']);
  const nk = verifyBundle(mkBundle(), null, T);
  assert.strictEqual(nk.presentation_authentication, 'SIGNED_NOT_CHECKED_NO_TRUSTED_KEY');
  assert.ok(nk.warnings.some((w) => w.code === 'MANIFEST_SIGNATURE_NOT_CHECKED'));
});

test('signed manifest: forged manifest fails MANIFEST_SIGNATURE_INVALID', () => {
  const b = mkBundle();
  b.receipts[0].notes = 'edited after export';
  b.manifest.sha256 = sha(jcs(Object.fromEntries(Object.entries(b).filter(([k]) => k !== 'manifest')))); // recompute hash, keep old signature
  const r = verifyBundle(b, SPUB, T);
  assert.strictEqual(r.verdict, 'FAIL');
  assert.deepStrictEqual(codes(r), ['MANIFEST_SIGNATURE_INVALID']);
  assert.strictEqual(r.presentation_authentication, 'FAILED');
  const bad = mkBundle(); bad.manifest.signature.extra = 1;
  assert.ok(codes(verifyBundle(bad, SPUB, T)).includes('MANIFEST_SIGNATURE_INVALID'));
});

test('signed manifest: stripped signature fails MANIFEST_SIGNATURE_MISSING', () => {
  const b = mkBundle(); delete b.manifest.signature;
  const r = verifyBundle(b, SPUB, T);
  assert.deepStrictEqual(codes(r), ['MANIFEST_SIGNATURE_MISSING']);
  assert.strictEqual(r.presentation_authentication, 'FAILED');
});

test('marker and signature stripped: legacy PASS_WITH_LIMITS, refused by --require-signed-manifest', () => {
  const b = mkBundle(); delete b.manifest_auth; seal(b, false);
  const r = verifyBundle(b, SPUB, T);
  assert.strictEqual(r.verdict, 'PASS_WITH_LIMITS');
  assert.strictEqual(r.presentation_authentication, 'NOT_AUTHENTICATED_LEGACY_UNSIGNED_MANIFEST');
  assert.ok(r.warnings.some((w) => w.code === 'MANIFEST_NOT_AUTHENTICATED'));
  const rr = verifyBundle(b, SPUB, T, true);
  assert.strictEqual(rr.verdict, 'FAIL');
  assert.deepStrictEqual(codes(rr), ['MANIFEST_SIGNATURE_REQUIRED']);
  const f = path.join(os.tmpdir(), `syen-legacy-${process.pid}.json`);
  fs.writeFileSync(f, JSON.stringify(b));
  try {
    const ok = spawnSync('node', ['bin/syen.js', 'verify', f, '--trusted-pubkey', SPUB, '--tenant', T], { encoding: 'utf8' });
    assert.strictEqual(ok.status, 0, ok.stderr);
    assert.match(ok.stdout, /presentation_authentication NOT_AUTHENTICATED_LEGACY_UNSIGNED_MANIFEST/);
    assert.match(ok.stdout, /^provenance \{/m);
    const req = spawnSync('node', ['bin/syen.js', 'verify', f, '--trusted-pubkey', SPUB, '--tenant', T, '--require-signed-manifest', '--json'], { encoding: 'utf8' });
    assert.strictEqual(req.status, 1);
    const j = JSON.parse(req.stdout);
    assert.strictEqual(j.failures[0].code, 'MANIFEST_SIGNATURE_REQUIRED');
    assert.ok('provenance' in j && 'presentation_authentication' in j);
  } finally { fs.unlinkSync(f); }
});

test('receipt SOURCE_EVIDENCE_ATTACHED over a SIMULATED event fails RECEIPT_GRADE_CONTRADICTS_EVENT', () => {
  const r = verifyBundle(mkBundle({ grade: 'SIMULATED', basis: 'SOURCE_EVIDENCE_ATTACHED' }), SPUB, T);
  assert.deepStrictEqual(codes(r), ['RECEIPT_GRADE_CONTRADICTS_EVENT']);
  assert.strictEqual(r.failures[0].event_execution_grade, 'SIMULATED');
});

test('current-format bundle stripped of marker and simulated_activity fails PROVENANCE_DOWNGRADE', () => {
  const b = mkBundle(); delete b.manifest_auth; delete b.simulated_activity; seal(b, false);
  const r = verifyBundle(b, SPUB, T);
  assert.deepStrictEqual(codes(r), ['PROVENANCE_DOWNGRADE']);
});

test('events-only legacy bundle with graded events is PASS_WITH_LIMITS, grades still reported', () => {
  const r = verifyBundle(mkBundle({ schema: false }), SPUB, T);
  assert.deepStrictEqual(r.failures, []);
  assert.strictEqual(r.verdict, 'PASS_WITH_LIMITS');
  assert.strictEqual(r.presentation_authentication, 'NOT_AUTHENTICATED_LEGACY_FORMAT');
  assert.strictEqual(r.provenance.events_with_provenance, 1);
  assert.strictEqual(r.provenance.declared_present, false);
});

// --- operator commands against an in-process fixture HTTP server ---
const http = require('node:http');
async function opServer(handler) {
  const seen = [];
  const srv = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      const body = raw ? JSON.parse(raw) : undefined;
      seen.push({ method: req.method, url: req.url, auth: req.headers.authorization, body });
      const [status, out] = handler(req, body);
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(out));
    });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { seen, url: `http://127.0.0.1:${srv.address().port}`, close: () => new Promise((r) => srv.close(r)) };
}
function cli(args, env) {
  const { spawn } = require('node:child_process');
  return new Promise((resolve) => {
    const p = spawn('node', ['bin/syen.js', ...args], { env: { ...process.env, SYEN_API_KEY: '', SYEN_EXPORT_API_KEY: '', ...env } });
    let stdout = '', stderr = '';
    p.stdout.on('data', (d) => { stdout += d; });
    p.stderr.on('data', (d) => { stderr += d; });
    p.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

test('cli check: ALLOW exits 0, DENY 3, REQUIRE_APPROVAL 4, --json carries the decision', async () => {
  const s = await opServer((req, body) => [200, { decision: body.action.kind, decision_id: 'd-1' }]);
  try {
    for (const [decision, code] of [['ALLOW', 0], ['DENY', 3], ['REQUIRE_APPROVAL', 4]]) {
      const r = await cli(['check', '--mandate', 'm-1', '--action', JSON.stringify({ kind: decision }), '--amount', '5', '--token', 'tk', '--json', '--base-url', s.url]);
      assert.strictEqual(r.status, code, r.stderr);
      assert.strictEqual(JSON.parse(r.stdout).decision, decision);
      const t = await cli(['check', '--mandate', 'm-1', '--action', JSON.stringify({ kind: decision }), '--request-id', 'rq-1', '--token', 'tk', '--base-url', s.url]);
      assert.strictEqual(t.status, code);
      assert.match(t.stdout, new RegExp(`^${decision} `));
    }
    const b = s.seen[0];
    assert.strictEqual(b.url, '/api/v1/authority/check');
    assert.strictEqual(b.auth, 'Bearer tk');
    assert.deepStrictEqual(Object.keys(b.body).sort(), ['action', 'mandate_id', 'request_id']);
    assert.deepStrictEqual(b.body.action, { kind: 'ALLOW', amount: 5 });
    assert.ok(b.body.request_id); // generated when --request-id is absent
    assert.strictEqual(s.seen[1].body.request_id, 'rq-1');
  } finally { await s.close(); }
});

test('cli evidence export without the export key exits 5 on the server 403', async () => {
  const s = await opServer((req, body) => body && body.scope === 'evidence:export' && body.api_key !== 'export-key'
    ? [403, { detail: 'evidence:export requires the export key' }] : [200, { access_token: 'x', expires_in: 60 }]);
  try {
    const r = await cli(['evidence', 'export', '--tenant', 't', '--agent', 'a', '--code-hash', 'h', '--json'],
      { SYEN_BASE_URL: s.url, SYEN_API_KEY: 'ordinary-key', SYEN_EXPORT_API_KEY: 'ordinary-key' });
    assert.strictEqual(r.status, 5, r.stderr);
    assert.strictEqual(JSON.parse(r.stdout).status, 403);
    assert.ok(!r.stdout.includes('ordinary-key') && !r.stderr.includes('ordinary-key'));
  } finally { await s.close(); }
});

test('cli mandate create attests then sends the MandateIn body', async () => {
  const s = await opServer((req, body) => req.url === '/api/v1/attest' ? [200, { access_token: 'minted', expires_in: 60 }] : [201, { mandate_id: 'm-9' }]);
  try {
    const r = await cli(['mandate', 'create', '--tenant', 't', '--agent', 'a', '--code-hash', 'h', '--principal', 'p@x', '--actions', 'pay,refund',
      '--max-amount', '100', '--currency', 'USD', '--ttl-seconds', '600', '--parent', 'm-0', '--forbidden-fields', 'ssn,dob'], { SYEN_BASE_URL: s.url, SYEN_API_KEY: 'k' });
    assert.strictEqual(r.status, 0, r.stderr);
    assert.match(r.stdout, /mandate created: m-9/);
    assert.deepStrictEqual(s.seen[0].body, { tenant_id: 't', agent_id: 'a', agent_code_hash: 'h', api_key: 'k' });
    const m = s.seen[1];
    assert.strictEqual(m.url, '/api/v1/authority/mandates');
    assert.strictEqual(m.auth, 'Bearer minted');
    assert.deepStrictEqual(Object.keys(m.body).sort(), ['agent_id', 'allowed_actions', 'currency', 'expires_at', 'forbidden_fields', 'max_amount', 'parent_mandate_id', 'principal']);
    assert.deepStrictEqual(m.body.allowed_actions, ['pay', 'refund']);
    assert.deepStrictEqual(m.body.forbidden_fields, ['ssn', 'dob']);
    assert.strictEqual(m.body.max_amount, 100);
    assert.ok(Math.abs(Date.parse(m.body.expires_at) - Date.now() - 600000) < 60000);
  } finally { await s.close(); }
});

test('cli doctor reports pass/fail per check and never prints a key', async () => {
  const s = await opServer((req, body) => req.url === '/api/v1/health' ? [200, { ok: true }]
    : body && body.scope === 'evidence:export' ? [403, { detail: `bad key ${body.api_key}` }] : [200, { access_token: 'x', expires_in: 60 }]);
  try {
    const env = { SYEN_BASE_URL: s.url, SYEN_API_KEY: 'SECRET-API-KEY', SYEN_EXPORT_API_KEY: 'SECRET-EXPORT-KEY' };
    const ids = ['--tenant', 't', '--agent', 'a', '--code-hash', 'h'];
    const r = await cli(['doctor', ...ids], env);
    assert.strictEqual(r.status, 1);
    assert.match(r.stderr, /PASS connectivity/);
    assert.match(r.stderr, /PASS api_key/);
    assert.match(r.stderr, /FAIL export_key/);
    const j = await cli(['doctor', ...ids, '--json'], env);
    assert.deepStrictEqual(JSON.parse(j.stdout).checks.map((c) => [c.name, c.pass]), [['connectivity', true], ['api_key', true], ['export_key', false]]);
    for (const out of [r.stdout, r.stderr, j.stdout, j.stderr]) assert.ok(!/SECRET-/.test(out), out);
    assert.strictEqual(s.seen[0].url, '/api/v1/health');
    assert.match(r.stderr, /Portal \(browser access\): https:\/\/portal\.syensystems\.com/);
  } finally { await s.close(); }
});

// Production shape: no status / revoked fields; revoked_at is null when active. List is wrapped.
const MANDATES = { 'm-1': { mandate_id: 'm-1', agent_id: 'agent-1', digest: 'd1', revoked_at: null },
  'm-2': { mandate_id: 'm-2', agent_id: 'agent-1', digest: 'd2', revoked_at: '2026-10-30T00:00:00Z' } };
const mandateRoutes = (req) => {
  if (req.url === '/api/v1/authority/mandates') return [200, { mandates: Object.values(MANDATES) }];
  const m = MANDATES[decodeURIComponent(req.url.replace('/api/v1/authority/mandates/', ''))];
  return m ? [200, m] : [404, { detail: 'not found' }];
};

test('cli mandate get reads GET /authority/mandates/{id} and renders id + status', async () => {
  const s = await opServer(mandateRoutes);
  try {
    const r = await cli(['mandate', 'get', '--id', 'm-1', '--token', 'tk', '--base-url', s.url]);
    assert.strictEqual(r.status, 0, r.stderr);
    assert.match(r.stdout, /^mandate m-1: ACTIVE/);
    assert.ok(!/decision|approximation|no direct mandate GET/i.test(r.stdout), r.stdout);
    assert.strictEqual(s.seen[0].method, 'GET');
    assert.strictEqual(s.seen[0].url, '/api/v1/authority/mandates/m-1');
    assert.strictEqual(s.seen[0].auth, 'Bearer tk');
    const j = await cli(['mandate', 'get', '--id', 'm-1', '--token', 'tk', '--json', '--base-url', s.url]);
    assert.deepStrictEqual(JSON.parse(j.stdout), MANDATES['m-1']);
  } finally { await s.close(); }
});

test('cli mandate get renders a revoked mandate as REVOKED', async () => {
  const s = await opServer(mandateRoutes);
  try {
    const r = await cli(['mandate', 'get', '--id', 'm-2', '--token', 'tk', '--base-url', s.url]);
    assert.strictEqual(r.status, 0, r.stderr);
    assert.match(r.stdout, /^mandate m-2: REVOKED/);
    const j = await cli(['mandate', 'get', '--id', 'm-2', '--token', 'tk', '--json', '--base-url', s.url]);
    assert.deepStrictEqual(JSON.parse(j.stdout), MANDATES['m-2']);
  } finally { await s.close(); }
});

test('cli mandate list renders one line per mandate and exits 0', async () => {
  const s = await opServer(mandateRoutes);
  try {
    const r = await cli(['mandate', 'list', '--token', 'tk', '--base-url', s.url]);
    assert.strictEqual(r.status, 0, r.stderr);
    assert.deepStrictEqual(r.stdout.trim().split('\n'), ['m-1: ACTIVE', 'm-2: REVOKED']);
    assert.strictEqual(s.seen[0].url, '/api/v1/authority/mandates');
    const j = await cli(['mandate', 'list', '--token', 'tk', '--json', '--base-url', s.url]);
    assert.strictEqual(j.status, 0, j.stderr);
    assert.deepStrictEqual(JSON.parse(j.stdout), { mandates: Object.values(MANDATES) });
  } finally { await s.close(); }
});

test('cli help shows the portal page', () => {
  const r = spawnSync('node', ['bin/syen.js', '--help'], { encoding: 'utf8' });
  assert.strictEqual(r.status, 0);
  assert.match(r.stdout, /Portal \(browser access\): https:\/\/portal\.syensystems\.com/);
});
