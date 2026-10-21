'use strict';
// Offline verification of a SYEN evidence bundle (format "syen-evidence-bundle/v1").
// Per record: (1) SHA-256 chain link over previous hash + RFC 8785 canonical payload,
// (2) Ed25519 signature over the record hash, checked against the bundle public key.
// RFC 3161 timestamp tokens, when present, are checked for parseable structure only;
// trusting them requires the timestamp authority's root certificates.
const crypto = require('node:crypto');
const { jcs } = require('./jcs');

const GENESIS = '0'.repeat(64);

function verifyBundle(bundle) {
  if (!bundle || typeof bundle !== 'object') throw new Error('bundle is not a JSON object');
  if (bundle.format !== 'syen-evidence-bundle/v1')
    throw new Error(`unrecognized bundle format: ${JSON.stringify(bundle.format)} (expected syen-evidence-bundle/v1)`);
  if (typeof bundle.public_key_pem !== 'string' || !bundle.public_key_pem.includes('BEGIN PUBLIC KEY'))
    throw new Error('bundle.public_key_pem must be an Ed25519 SubjectPublicKeyInfo PEM');
  if (!Array.isArray(bundle.records) || bundle.records.length === 0)
    throw new Error('bundle.records must be a non-empty array');
  const key = crypto.createPublicKey(bundle.public_key_pem);
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('public key is not Ed25519');

  let prev = GENESIS;
  const records = bundle.records.map((rec, i) => {
    const out = { index: i, id: rec.id ?? null, chain: 'FAIL', signature: 'FAIL', timestamp: 'ABSENT' };
    if (typeof rec.hash !== 'string' || !/^[0-9a-f]{64}$/.test(rec.hash)) {
      out.error = 'record.hash must be 64 lowercase hex characters';
      return out;
    }
    let canonical;
    try { canonical = jcs(rec.payload); } catch (e) { out.error = 'payload: ' + e.message; return out; }
    const computed = crypto.createHash('sha256').update(prev, 'utf8').update(canonical, 'utf8').digest('hex');
    if (computed === rec.hash) out.chain = 'PASS';
    let sig = null;
    try { sig = Buffer.from(String(rec.signature ?? ''), 'base64'); } catch { sig = null; }
    if (sig && sig.length === 64 && crypto.verify(null, Buffer.from(rec.hash, 'utf8'), key, sig)) out.signature = 'PASS';
    if (rec.timestamp_token != null) {
      try {
        const der = Buffer.from(String(rec.timestamp_token), 'base64');
        out.timestamp = der.length > 16 && der[0] === 0x30 ? 'PRESENT (structure ok, trust not checked)' : 'PRESENT (unparseable)';
      } catch { out.timestamp = 'PRESENT (unparseable)'; }
    }
    prev = rec.hash;
    return out;
  });

  const ok = records.every((r) => r.chain === 'PASS' && r.signature === 'PASS');
  return { ok, records_checked: records.length, records };
}
module.exports = { verifyBundle, GENESIS };
