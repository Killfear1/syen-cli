'use strict';
// Offline verifier for a SYEN evidence bundle (schema syen.evidence-bundle/1).
// A faithful JavaScript port of the standalone verifier the SYEN Comply API
// ships (verifier/syen_verify.py): same chain math, verdicts, failure codes,
// and the same trust rule - a public key embedded in the bundle is never
// trusted; signatures are checked only against a caller-supplied key.
const crypto = require('node:crypto');
const { jcs } = require('./jcs');

const BUNDLE_SCHEMA = 'syen.evidence-bundle/1';
const MANIFEST_AUTH_FIELD = 'manifest_auth';
const MANIFEST_SIGNATURE_ALG = 'Ed25519';
const MANIFEST_ALG = 'sha256-jcs';
const PRES_AUTHENTICATED = 'AUTHENTICATED';
const PRES_NOT_CHECKED = 'SIGNED_NOT_CHECKED_NO_TRUSTED_KEY';
const PRES_LEGACY_UNSIGNED = 'NOT_AUTHENTICATED_LEGACY_UNSIGNED_MANIFEST';
const PRES_LEGACY_FORMAT = 'NOT_AUTHENTICATED_LEGACY_FORMAT';
const PRES_FAILED = 'FAILED';
const PROVENANCE_FIELD = 'execution_grade';
const SIMULATED_GRADE = 'SIMULATED';
const SIMULATED_ACTIVITY_FIELD = 'simulated_activity';

function sha256hex(s) { return crypto.createHash('sha256').update(s, 'utf8').digest('hex'); }
function chainHash(eventData, previousHash) { return sha256hex(jcs({ previous_hash: previousHash ?? null, event: eventData })); }
function manifestHash(body) { return sha256hex(jcs(body)); }

function tsOk(s) {
  if (typeof s !== 'string') return false;
  const t = Date.parse(s.replace('Z', '+00:00'));
  return !Number.isNaN(t) && /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/.test(s);
}

function ed25519KeyFromRawB64(pubB64) {
  const raw = Buffer.from(pubB64, 'base64');
  if (raw.length !== 32) throw new Error('bad key length');
  const der = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]);
  return crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
}

function sigOk(pubB64, sigB64, integrityHash) {
  try {
    const key = ed25519KeyFromRawB64(pubB64);
    return crypto.verify(null, Buffer.from(integrityHash, 'hex'), key, Buffer.from(sigB64, 'base64'));
  } catch { return false; }
}

function isObj(x) { return x !== null && typeof x === 'object' && !Array.isArray(x); }
const sameKeys = (o, ks) => { const k = Object.keys(o).sort(); return k.length === ks.length && ks.slice().sort().every((x, i) => x === k[i]); };

// Mirrors _check_manifest_signature in syen_verify.py: every inconsistency in a signed/marked manifest FAILS.
function checkManifestSignature(m, marked, hasSig, computed, trustedPubkey, fail, warn) {
  if (marked && !hasSig) {
    fail('MANIFEST_SIGNATURE_MISSING', { detail: 'the bundle body declares a signed manifest (manifest_auth) but the manifest carries no signature: the signature was stripped or the bundle was rebuilt' });
    return PRES_FAILED;
  }
  if (hasSig && !marked) {
    fail('MANIFEST_SIGNATURE_INVALID', { detail: 'a manifest signature is present but the signed body has no manifest_auth marker; no genuine exporter produces this (marker removed after signing)' });
    return PRES_FAILED;
  }
  const sig = m.signature;
  if (!sameKeys(m, ['alg', 'sha256', 'signature']) || m.alg !== MANIFEST_ALG) {
    fail('MANIFEST_SIGNATURE_INVALID', { detail: 'signed manifest must be exactly {alg: sha256-jcs, sha256, signature}' });
    return PRES_FAILED;
  }
  if (!isObj(sig) || !sameKeys(sig, ['alg', 'value']) || sig.alg !== MANIFEST_SIGNATURE_ALG || typeof sig.value !== 'string' || !sig.value) {
    fail('MANIFEST_SIGNATURE_INVALID', { detail: 'manifest signature must be exactly {alg: Ed25519, value: base64}' });
    return PRES_FAILED;
  }
  if (!trustedPubkey) {
    warn('MANIFEST_SIGNATURE_NOT_CHECKED', { detail: 'the manifest is signed, but no --trusted-pubkey was supplied, so the signature was not verified: receipt presentation fields (summary, evidence_basis, notes, links) are only hash-checked here; supply the trusted key to authenticate them' });
    return PRES_NOT_CHECKED;
  }
  // verified over the RECOMPUTED digest, so a valid signature authenticates the bytes actually present
  if (!sigOk(trustedPubkey, sig.value, computed)) {
    fail('MANIFEST_SIGNATURE_INVALID', { detail: 'the manifest signature does not verify against the trusted key for this bundle\'s content: receipt fields or the manifest were changed after export, or another key signed it' });
    return PRES_FAILED;
  }
  return PRES_AUTHENTICATED;
}

function verifyBundle(bundle, trustedPubkey = null, expectedTenant = null, requireSignedManifest = false) {
  try {
    return doVerify(bundle, trustedPubkey, expectedTenant, requireSignedManifest);
  } catch (e) {
    return { verdict: 'FAIL', failures: [{ code: 'MALFORMED_BUNDLE', detail: e.constructor.name }], warnings: [],
             checked: {}, meaning: 'The bundle could not be read safely, so nothing in it is verified.' };
  }
}

function doVerify(bundle, trustedPubkey, expectedTenant, requireSignedManifest) {
  if (!isObj(bundle)) throw new TypeError('bundle is not an object');
  const fails = [], warns = [];
  const fail = (code, kw = {}) => fails.push({ code, ...kw });
  const warn = (code, kw = {}) => warns.push({ code, ...kw });

  const legacy = bundle.schema !== BUNDLE_SCHEMA;
  const events = bundle.events;
  if (!Array.isArray(events))
    return { verdict: 'FAIL', failures: [{ code: 'MALFORMED_BUNDLE', detail: 'no events list' }], warnings: [], checked: {} };
  const tenant = bundle.tenant_id;
  const receipts = bundle.receipts || [];
  if (!Array.isArray(receipts) || !receipts.every(isObj) || !events.every(isObj))
    throw new TypeError('receipts and events must be lists of objects');
  if (tenant != null && typeof tenant !== 'string') throw new TypeError('tenant_id must be a string');
  for (const e of events) {
    const sc = e.sequence_counter;
    if (!Number.isInteger(sc)) throw new TypeError('sequence_counter must be an integer');
    if (!isObj(e.event_data)) throw new TypeError('event_data must be an object');
  }
  for (const r of receipts) {
    const stages = (r.signed_receipt || {}).stages || {};
    if (!isObj(stages)) throw new TypeError('receipt stages must be an object');
  }
  if (!legacy && !tenant)
    fail('MISSING_TENANT', { detail: 'a v1 bundle must name its tenant; tenant checks cannot run without it' });
  if (expectedTenant != null && tenant !== expectedTenant) {
    fail('TENANT_MISMATCH', { expected: expectedTenant, found: tenant ?? null });
  } else if (expectedTenant == null) {
    warn('TENANT_NOT_PINNED', { detail: 'no expected tenant supplied: a genuine bundle from any tenant verifies as itself' });
  }
  const incomplete = bundle.complete === false || !!(bundle.truncated_streams && bundle.truncated_streams.length) || !!(bundle.truncated_tables && bundle.truncated_tables.length);
  if (incomplete)
    warn('INCOMPLETE_EXPORT', { truncated_streams: bundle.truncated_streams ?? null, truncated_tables: bundle.truncated_tables ?? null,
      detail: 'the exporter reported a truncated set; absence of a record here proves nothing' });
  let presentation;
  if (legacy) {
    presentation = PRES_LEGACY_FORMAT;
    warn('LEGACY_FORMAT', { detail: 'no syen.evidence-bundle/1 schema: only event hashes, chain links and signatures were checked; there are no receipts or manifest to check' });
  } else {
    if (!tsOk(bundle.exported_at)) fail('INVALID_TIMESTAMP', { where: 'exported_at', value: bundle.exported_at ?? null });
    const body = {}; for (const k of Object.keys(bundle)) if (k !== 'manifest') body[k] = bundle[k];
    const m = bundle.manifest || {};
    if (!isObj(m)) throw new TypeError('manifest must be an object');
    const computed = manifestHash(body);
    if (m.sha256 !== computed) fail('MANIFEST_MISMATCH', { detail: 'bundle content changed after export (or manifest missing)' });
    const marked = MANIFEST_AUTH_FIELD in body, hasSig = 'signature' in m;
    if (!marked && !hasSig) {
      warn('MANIFEST_NOT_AUTHENTICATED', { detail: 'the manifest hash detects edits; it is not signed, so it does not show who exported, and receipt presentation fields (summary, evidence_basis, notes, links) are NOT authenticated: anyone can edit them and recompute this hash (pre-fix bundle, or a new bundle whose manifest_auth marker and signature were both removed - the two are indistinguishable offline)' });
      presentation = PRES_LEGACY_UNSIGNED;
    } else {
      presentation = checkManifestSignature(m, marked, hasSig, computed, trustedPubkey, fail, warn);
    }
    if (m.sha256 !== computed) presentation = PRES_FAILED; // a manifest that does not match the content authenticates nothing
  }
  if (requireSignedManifest && presentation !== PRES_AUTHENTICATED)
    fail('MANIFEST_SIGNATURE_REQUIRED', { presentation_authentication: presentation,
      detail: '--require-signed-manifest: only a bundle whose manifest signature verifies against the trusted key is accepted (legacy and unsigned bundles are refused in this mode)' });

  const byId = {}, streams = new Map();
  let sigChecked = 0, sigUnchecked = 0;
  const hashOk = new Set(), sigOkIds = new Set();
  for (const e of events) {
    const eid = String(e.event_id);
    if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(eid)) { fail('BAD_EVENT_ID', { event_id: eid }); continue; }
    byId[eid] = e;
    const ed = e.event_data || {};
    if (tenant && ed.tenant_id !== tenant) fail('CROSS_TENANT_EVENT', { event_id: eid, event_tenant: ed.tenant_id ?? null });
    if (tenant && !String(e.stream_id ?? '').startsWith(tenant + ':')) fail('CROSS_TENANT_STREAM', { event_id: eid, stream_id: e.stream_id ?? null });
    if (ed.stream_id !== e.stream_id) fail('STREAM_MISMATCH', { event_id: eid });
    if ('timestamp_utc' in e && !tsOk(e.timestamp_utc)) fail('INVALID_TIMESTAMP', { event_id: eid, value: e.timestamp_utc ?? null });
    if (chainHash(ed, e.previous_event_hash ?? null) !== e.integrity_hash) fail('HASH_MISMATCH', { event_id: eid, sequence: e.sequence_counter ?? null });
    else hashOk.add(eid);
    const sid = e.stream_id;
    if (!streams.has(sid)) streams.set(sid, []);
    streams.get(sid).push(e);
    const sig = e.tee_signature;
    if (!sig) {
      if (trustedPubkey) fail('UNSIGNED_EVENT_WITH_TRUSTED_KEY', { event_id: eid, detail: 'a trusted key was supplied but this event carries no signature' });
      else warn('UNSIGNED_EVENT', { event_id: eid });
      continue;
    }
    if (trustedPubkey) {
      sigChecked++;
      if (!sigOk(trustedPubkey, sig, e.integrity_hash || '')) fail('SIGNATURE_INVALID_FOR_TRUSTED_KEY', { event_id: eid });
      else sigOkIds.add(eid);
    } else sigUnchecked++;
  }
  if (sigUnchecked)
    warn('SIGNATURES_NOT_CHECKED', { count: sigUnchecked, detail: 'no --trusted-pubkey supplied; the key embedded in the bundle is not trusted' });

  let links = 0;
  for (const [sid, evs] of streams) {
    evs.sort((a, b) => (a.sequence_counter || 0) - (b.sequence_counter || 0));
    for (let i = 0; i + 1 < evs.length; i++) {
      const a = evs[i], b = evs[i + 1];
      if (b.sequence_counter === a.sequence_counter + 1) {
        links++;
        if ((b.previous_event_hash ?? null) !== (a.integrity_hash ?? null)) fail('BROKEN_CHAIN', { stream_id: sid, at_sequence: b.sequence_counter });
      } else if (b.sequence_counter <= a.sequence_counter) {
        fail('DUPLICATE_SEQUENCE', { stream_id: sid, sequence: b.sequence_counter });
      } else {
        warn('SEQUENCE_GAP', { stream_id: sid, after: a.sequence_counter, next: b.sequence_counter });
      }
    }
    if (evs.length && evs[0].sequence_counter === 1 && (evs[0].previous_event_hash ?? null) !== null)
      fail('BROKEN_CHAIN', { stream_id: sid, at_sequence: 1, detail: 'first event has a predecessor' });
  }

  const vsnap = bundle.readings_verdicts || [];
  if (!Array.isArray(vsnap) || !vsnap.every(isObj)) throw new TypeError('readings_verdicts must be a list of objects');
  const vby = {};
  for (const x of vsnap) {
    const k = String(x.event_id);
    if (k in vby) fail('DUPLICATE_VERDICT_ROW', { event_id: k, detail: 'more than one exported verdict payload for the same event' });
    vby[k] = x;
  }
  let verdictsBound = 0;
  for (const [eid, e] of Object.entries(byId)) {
    const want = (e.event_data || {}).payload_sha256;
    if (!want) continue;
    const snap = vby[eid];
    if (snap === undefined) {
      warn('VERDICT_PAYLOAD_NOT_INCLUDED', { event_id: eid, detail: 'the signed event commits to a payload hash but the bundle carries no payload to check it against' });
      continue;
    }
    let got = null;
    try { got = sha256hex(jcs(snap.payload ?? null)); } catch { got = null; }
    if (got !== want || snap.payload_sha256 !== want) fail('VERDICT_PAYLOAD_MISMATCH', { event_id: eid, detail: 'exported verdict text does not match the hash the event signed' });
    else verdictsBound++;
  }
  for (const eid of Object.keys(vby)) if (!(eid in byId)) fail('VERDICT_WITHOUT_EVENT', { event_id: eid });

  let refs = 0;
  for (const r of receipts) {
    const sr = r.signed_receipt || {};
    for (const [stage, ref] of Object.entries(sr.stages || {})) {
      refs++;
      const ev = byId[String((ref || {}).event_id)];
      if (ev === undefined) { fail('MISSING_EVIDENCE', { receipt_id: r.receipt_id ?? null, stage, event_id: (ref || {}).event_id ?? null }); continue; }
      if ((ev.integrity_hash ?? null) !== ((ref || {}).integrity_hash ?? null)) fail('RECEIPT_HASH_MISMATCH', { receipt_id: r.receipt_id ?? null, stage });
      if (r.family === 'authority' && ev.stream_id !== `${tenant}:authority:records`)
        fail('WRONG_SOURCE_ATTRIBUTION', { receipt_id: r.receipt_id ?? null, stream_id: ev.stream_id ?? null });
      else if (tenant && !String(ev.stream_id ?? '').startsWith(`${tenant}:`))
        fail('WRONG_SOURCE_ATTRIBUTION', { receipt_id: r.receipt_id ?? null, stream_id: ev.stream_id ?? null });
    }
    if (r.tenant_id && tenant && r.tenant_id !== tenant) fail('CROSS_TENANT_RECEIPT', { receipt_id: r.receipt_id ?? null });
    if (r.created_at != null && !tsOk(r.created_at)) fail('INVALID_TIMESTAMP', { receipt_id: r.receipt_id ?? null, value: r.created_at });
    if (r.independently_confirmed)
      warn('UNSUPPORTED_CONFIRMATION_CLAIM', { receipt_id: r.receipt_id ?? null, detail: 'a bundle cannot establish independent confirmation; ignored' });
    // F5.2: receipt basis must not contradict the signed execution_grade of a hash-verified event it references.
    const basis = 'evidence_basis' in r ? r.evidence_basis : r.evidence_grade;
    if (basis != null) {
      for (const [stage, ref] of Object.entries(sr.stages || {})) {
        const refId = String((ref || {}).event_id);
        const ev = byId[refId];
        if (ev === undefined || !hashOk.has(refId)) continue;
        const ed = ev.event_data || {};
        if (PROVENANCE_FIELD in ed && ed[PROVENANCE_FIELD] != null && ed[PROVENANCE_FIELD] !== basis)
          fail('RECEIPT_GRADE_CONTRADICTS_EVENT', { receipt_id: r.receipt_id ?? null, stage, event_id: refId, receipt_basis: basis,
            event_execution_grade: ed[PROVENANCE_FIELD], detail: 'the receipt\'s evidence basis differs from the execution_grade signed into the event it references' });
      }
    }
  }

  const evRows = [], simEvents = [], grades = new Set();
  for (const [eid, e] of Object.entries(byId)) {
    const ed = e.event_data || {};
    const present = PROVENANCE_FIELD in ed, grade = present ? ed[PROVENANCE_FIELD] : null, simulated = grade === SIMULATED_GRADE;
    if (present) grades.add(grade);
    if (simulated) simEvents.push(eid);
    evRows.push({ event_id: eid, event_type: ed.event_type ?? null, provenance_present: present, execution_grade: grade, simulated,
                  covered_by_verified_signature: present && hashOk.has(eid) && sigOkIds.has(eid) });
  }
  const withField = evRows.filter((x) => x.provenance_present).length;
  const simReceipts = receipts.filter((r) => r.evidence_basis === SIMULATED_GRADE).map((r) => r.receipt_id ?? null);
  const derived = !!(simEvents.length || simReceipts.length);
  const declaredPresent = !legacy && SIMULATED_ACTIVITY_FIELD in bundle;
  const declared = declaredPresent ? bundle[SIMULATED_ACTIVITY_FIELD] : null;
  let consistent = null;
  if (declaredPresent) {
    if (typeof declared !== 'boolean') {
      consistent = false;
      fail('SIMULATION_INDICATOR_INVALID', { value: declared, detail: 'simulated_activity must be a boolean derived from the bundle\'s own content' });
    } else {
      consistent = declared === derived;
      if (!consistent) fail('SIMULATION_INDICATOR_MISMATCH', { declared, derived, simulated_event_ids: simEvents.slice(0, 20), simulated_receipt_ids: simReceipts.slice(0, 20),
        detail: 'the bundle-level simulated_activity indicator contradicts the bundle\'s own events and receipts: synthetic activity is understated or misstated' });
    }
  }
  // F5.4: bounded to current-format bundles; legacy-format bundles get legacy handling with grades still reported.
  if (!legacy && withField > 0 && !(MANIFEST_AUTH_FIELD in bundle) && !declaredPresent)
    fail('PROVENANCE_DOWNGRADE', { events_with_provenance: withField,
      detail: 'events carry a signed execution_grade, so this bundle was exported after simulation provenance existed, yet it has neither a manifest_auth marker nor simulated_activity: the manifest signature and simulation indicator were stripped' });
  const provenance = { event_field: PROVENANCE_FIELD, events: evRows, events_with_provenance: withField, grades_seen: [...grades],
    simulated_event_ids: simEvents, simulated_receipt_ids: simReceipts, declared_present: declaredPresent,
    declared_simulated_activity: declared, derived_simulated_activity: derived, consistent,
    manifest_signature_verified: presentation === PRES_AUTHENTICATED };

  const verdict = fails.length ? 'FAIL' : (incomplete ? 'INCOMPLETE' : (warns.length ? 'PASS_WITH_LIMITS' : 'PASS'));
  return {
    verdict, failures: fails, warnings: warns, presentation_authentication: presentation, provenance,
    checked: { events: Object.keys(byId).length, chain_links: links, receipt_references: refs,
               signatures_verified: sigChecked, signatures_unchecked: sigUnchecked, verdict_payloads_bound: verdictsBound, legacy_format: legacy },
    limits: ['tail truncation is undetectable if the referencing receipt is dropped too', 'no freshness check on exported_at',
             'legacy-format bundles skip manifest and receipt checks',
             presentation === PRES_LEGACY_UNSIGNED ? 'this manifest is unsigned (legacy): receipt presentation fields are not authenticated'
               : 'a manifest signature is only as trustworthy as the supplied trusted key'],
    meaning: 'Integrity and signer attribution only. A valid record does not show that its claims are true.'
  };
}

module.exports = { verifyBundle, BUNDLE_SCHEMA, PRES_AUTHENTICATED, PRES_LEGACY_UNSIGNED, PRES_LEGACY_FORMAT, PRES_FAILED };
