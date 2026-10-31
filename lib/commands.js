'use strict';
// SYEN operator commands. Each: async (client, args) -> {exitCode, json, text}.
// No console output, no process.exit, no prompts. Exit codes:
// 0 success/ALLOW, 1 other API error, 2 usage, 3 DENY, 4 REQUIRE_APPROVAL, 5 refusal (403), 6 transport/unsupported.
const { TransportError, RefusalError, ApiError } = require('./api');

const ok = (json, text) => ({ exitCode: 0, json, text });
const usage = (msg) => ({ exitCode: 2, json: { error: 'usage', message: msg }, text: `usage: ${msg}` });
const list = (v) => v == null ? undefined : Array.isArray(v) ? v : String(v).split(',').map((s) => s.trim()).filter(Boolean);
const num = (v) => v == null ? undefined : Number(v);
const clean = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined));
const need = (args, ...keys) => { const m = keys.filter((k) => args[k] == null || args[k] === ''); return m.length ? usage(`missing --${m.map(flag).join(', --')}`) : null; };
const flag = (k) => ({ allowedActions: 'actions', ttl: 'ttl-seconds' })[k] || k.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`);
const show = (d) => typeof d === 'string' ? d : JSON.stringify(d);
const enc = encodeURIComponent;
class UsageError extends Error {}
// JSON object flag: accepts an object or a JSON string; anything else is a usage error.
const obj = (v, flag) => {
  if (v == null) return undefined;
  let o = v;
  if (typeof v === 'string') { try { o = JSON.parse(v); } catch { throw new UsageError(`--${flag} must be a JSON object`); } }
  if (!o || typeof o !== 'object' || Array.isArray(o)) throw new UsageError(`--${flag} must be a JSON object`);
  return o;
};
const oneOf = (v, flag, allowed) => { if (!allowed.includes(v)) throw new UsageError(`--${flag} must be one of ${allowed.join('|')}`); return v; };

function fail(e) {
  if (e instanceof UsageError) return usage(e.message);
  if (e instanceof RefusalError) return { exitCode: 5, json: { error: 'refused', status: 403, detail: e.detail }, text: `REFUSED (403): ${show(e.detail)}` };
  if (e instanceof TransportError) return { exitCode: 6, json: { error: 'transport', message: e.message }, text: `transport error: ${e.message}` };
  if (e instanceof ApiError) return { exitCode: 1, json: { error: 'api', status: e.status, detail: e.detail }, text: e.message };
  throw e;
}
const run = (fn) => async (client, args = {}) => { try { return await fn(client, args); } catch (e) { return fail(e); } };

// Bearer token: --token, else mint one via attest when tenant/agent/codeHash are given.
async function tok(client, a) {
  if (a.token) return a.token;
  if (a.tenant && a.agent && a.codeHash) return (await client.attest({ tenantId: a.tenant, agentId: a.agent, agentCodeHash: a.codeHash })).accessToken;
  return undefined;
}
const call = async (client, a, method, path, body) => client.request(method, path, { body, token: await tok(client, a) });
const exportScope = (a) => ({ tenantId: a.tenant, agentId: a.agent, agentCodeHash: a.codeHash });

const attest = run(async (client, a) => {
  const u = need(a, 'tenant', 'agent', 'codeHash'); if (u) return u;
  const r = await client.attest({ tenantId: a.tenant, agentId: a.agent, agentCodeHash: a.codeHash, scope: a.scope });
  return ok({ access_token: r.accessToken, expires_in: r.expiresIn, scope: a.scope || null },
    `attested${a.scope ? ` (scope ${a.scope})` : ''}; token expires in ${r.expiresIn}s (use --json to obtain the token)`);
});

const mandateCreate = run(async (client, a) => {
  const u = need(a, 'principal', 'agent', 'allowedActions', 'maxAmount'); if (u) return u;
  // MandateIn has no ttl_seconds/tenant_id: --ttl-seconds becomes expires_at (omitted = server default lifetime).
  const ttl = num(a.ttl);
  if (ttl !== undefined && !(ttl > 0)) return usage('--ttl-seconds must be a positive number');
  const body = clean({
    principal: a.principal, agent_id: a.agent, allowed_actions: list(a.allowedActions), max_amount: num(a.maxAmount),
    currency: a.currency, not_before: a.notBefore, expires_at: ttl === undefined ? undefined : new Date(Date.now() + ttl * 1000).toISOString(),
    approval_required_over: num(a.approvalRequiredOver), parent_mandate_id: a.parent, forbidden_fields: list(a.forbiddenFields),
  });
  const d = await call(client, a, 'POST', '/api/v1/authority/mandates', body);
  return ok(d, `mandate created: ${d && (d.mandate_id || d.id) || show(d)}`);
});

// Mandate status from production fields: revoked_at non-null (or revoked === true) => REVOKED, else ACTIVE.
const mstatus = (m) => !m || typeof m !== 'object' ? 'unknown' : m.revoked === true || m.revoked_at != null ? 'REVOKED' : 'ACTIVE';
const mandateGet = run(async (client, a) => {
  const u = need(a, 'id'); if (u) return u;
  const d = await call(client, a, 'GET', `/api/v1/authority/mandates/${enc(a.id)}`);
  return ok(d, `mandate ${d && (d.mandate_id || d.id) || a.id}: ${mstatus(d)}\n${show(d)}`);
});

const mandateRevoke = run(async (client, a) => {
  const u = need(a, 'id'); if (u) return u;
  const d = await call(client, a, 'POST', `/api/v1/authority/mandates/${enc(a.id)}/revoke`, clean({ reason: a.reason }));
  return ok(d, `mandate ${a.id} revoked`);
});

const mandateList = run(async (client, a) => {
  const d = await call(client, a, 'GET', '/api/v1/authority/mandates');
  const rows = Array.isArray(d) ? d : d && (d.mandates || d.items);
  const text = Array.isArray(rows) ? rows.map((m) => `${m.mandate_id || m.id}: ${mstatus(m)}`).join('\n') || 'no mandates' : JSON.stringify(d, null, 2);
  return ok(d, text);
});

const VERDICT = { ALLOW: [0, 'ALLOW  - action permitted'], DENY: [3, 'DENY   - action blocked'], REQUIRE_APPROVAL: [4, 'REQUIRE_APPROVAL - human approval needed before proceeding'] };
const check = run(async (client, a) => {
  const u = need(a, 'mandate', 'action'); if (u) return u;
  // CheckIn: request_id, mandate_id, action (plain object), approval. --amount goes into action.amount.
  const action = { ...obj(a.action, 'action') };
  if (a.amount != null) action.amount = num(a.amount);
  const generated = !a.requestId;
  const requestId = a.requestId || require('node:crypto').randomUUID();
  const body = clean({ request_id: requestId, mandate_id: a.mandate, action, approval: obj(a.approval, 'approval') });
  const d = await call(client, a, 'POST', '/api/v1/authority/check', body);
  const v = String(d && (d.decision || d.verdict || d.outcome) || '').toUpperCase();
  const [code, label] = VERDICT[v] || [1, `UNKNOWN decision: ${show(d)}`];
  const extra = [`request_id: ${requestId}${generated ? ' (generated)' : ''}`, d && d.decision_id && `decision_id: ${d.decision_id}`, d && d.reason && `reason: ${show(d.reason)}`].filter(Boolean);
  return { exitCode: code, json: d, text: [label, ...extra].join('\n') };
});

const hitlRequest = run(async (client, a) => {
  const u = need(a, 'actionId', 'eventType', 'actor', 'riskLevel', 'approver'); if (u) return u;
  // HITLRequestBody has no mandate/action/decision fields: --mandate and --action travel inside details.
  const details = clean({ ...obj(a.details, 'details'), mandate_id: a.mandate, action: obj(a.action, 'action') });
  const body = clean({ action_id: a.actionId, event_type: a.eventType, actor_id: a.actor,
    risk_level: oneOf(a.riskLevel, 'risk-level', ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']), details,
    approver_id: a.approver, approval_timeout_seconds: num(a.timeoutSeconds) });
  if (body.approval_timeout_seconds !== undefined && !(body.approval_timeout_seconds >= 10 && body.approval_timeout_seconds <= 3600)) return usage('--timeout-seconds must be 10..3600');
  const d = await call(client, a, 'POST', '/api/v1/hitl/request', body);
  return ok(d, `approval requested from ${a.approver}${d && d.request_id ? ` (request ${d.request_id})` : ''}`);
});

// B8: caller authenticates as the designated approver; action + action_id bind the exact action.
const hitlRespond = run(async (client, a) => {
  const u = need(a, 'request', 'decision', 'action', 'actionId'); if (u) return u;
  // HITLRespondBody: approval_token (--request), decision APPROVED|DENIED, action_id, action object.
  const body = { approval_token: a.request, decision: oneOf(a.decision, 'decision', ['APPROVED', 'DENIED']), action_id: a.actionId, action: obj(a.action, 'action') };
  const d = await call(client, a, 'POST', '/api/v1/hitl/respond', body);
  return ok(d, `response ${a.decision} recorded for action ${a.actionId}`);
});

const outcomeRecord = run(async (client, a) => {
  const u = need(a, 'decision', 'status', 'grade', 'actionHash'); if (u) return u;
  const body = clean({ decision_id: a.decision, status: oneOf(a.status, 'status', ['EXECUTED', 'FAILED', 'NOT_EXECUTED']),
    evidence_grade: oneOf(a.grade, 'grade', ['SIMULATED', 'SELF_REPORTED', 'SOURCE_EVIDENCE_ATTACHED']), action_hash: a.actionHash,
    source: a.source, source_reference: a.sourceRef, source_evidence_hash: a.sourceEvidenceHash, details: obj(a.details, 'details') || {} });
  if (body.source_evidence_hash !== undefined && !/^[0-9a-f]{64}$/.test(body.source_evidence_hash)) return usage('--source-evidence-hash must be 64 lowercase hex');
  if (body.evidence_grade === 'SOURCE_EVIDENCE_ATTACHED') { const m = need(a, 'source', 'sourceRef', 'sourceEvidenceHash'); if (m) return m; }
  const d = await call(client, a, 'POST', '/api/v1/authority/outcomes', body);
  return ok(d, `outcome ${a.status} recorded for decision ${a.decision}`);
});

const evidenceExport = async (client, a = {}) => {
  const u = need(a, 'tenant', 'agent', 'codeHash'); if (u) return u;
  try {
    const d = await client.request('GET', '/api/v1/evidence/export', { exportScope: exportScope(a) });
    const n = d && Array.isArray(d.events) ? ` (${d.events.length} events)` : '';
    return ok(d, `evidence bundle exported${n}; use --json to write it`);
  } catch (e) {
    if (e instanceof RefusalError) {
      return { exitCode: 5, json: { error: 'refused', status: 403, detail: e.detail },
        text: `REFUSED: evidence export requires the evidence:export scope (set SYEN_EXPORT_API_KEY). detail: ${show(e.detail)}` };
    }
    return fail(e);
  }
};

const coverage = run(async (client, a) => {
  const d = await call(client, a, 'GET', '/api/v1/authority/coverage');
  return ok(d, JSON.stringify(d, null, 2));
});

const driftStatus = run(async (client, a) => {
  const d = await call(client, a, 'GET', '/api/v1/drift/controls');
  const rows = Array.isArray(d) ? d : d && (d.controls || d.items);
  const text = Array.isArray(rows) ? rows.map((c) => `${c.key || c.id}: ${c.status || c.state || show(c)}`).join('\n') || 'no controls' : JSON.stringify(d, null, 2);
  return ok(d, text);
});

const version = async (client, a = {}) => ok({ version: a.version || null }, String(a.version || 'unknown'));

const doctor = async (client, a = {}) => {
  const checks = [];
  const add = (name, pass, info) => checks.push({ name, pass, info });
  try { await client.request('GET', a.healthPath || '/api/v1/health'); add('connectivity', true, client.base); }
  catch (e) { add('connectivity', false, `${client.base}: ${e.name}${e.status ? ` ${e.status}` : ''}`); }
  const ids = a.tenant && a.agent && a.codeHash;
  for (const [name, has, scope] of [['api_key', client.hasApiKey, undefined], ['export_key', client.hasExportKey, 'evidence:export']]) {
    if (!has) { add(name, null, 'not set (skipped)'); continue; }
    if (!ids) { add(name, null, 'present; pass --tenant --agent --code-hash to self-check'); continue; }
    try { const r = await client.attest({ tenantId: a.tenant, agentId: a.agent, agentCodeHash: a.codeHash, scope }); add(name, !!r.accessToken, `attest ok${scope ? ` (${scope})` : ''}`); }
    catch (e) { add(name, false, `${e.name}${e.status ? ` ${e.status}` : ''}`); }
  }
  const failed = checks.some((c) => c.pass === false);
  const text = checks.map((c) => `${c.pass === true ? 'PASS' : c.pass === false ? 'FAIL' : 'SKIP'} ${c.name}: ${c.info}`).join('\n')
    + '\nPortal (browser access): https://portal.syensystems.com';
  return { exitCode: failed ? (checks[0].pass === false ? 6 : 1) : 0, json: { ok: !failed, checks }, text };
};

module.exports = {
  attest, mandateCreate, mandateGet, mandateRevoke, mandateList, check,
  approve: hitlRequest, hitlRequest, hitlRespond, outcomeRecord, evidenceExport,
  coverage, driftStatus, version, doctor,
};
