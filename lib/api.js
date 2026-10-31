'use strict';
// SYEN Comply API client. Zero dependencies, Node 18+ (global fetch).
// Credentials come only from env and are never logged or placed in errors.

class TransportError extends Error { constructor(m) { super(m); this.name = 'TransportError'; } }
class ApiError extends Error {
  constructor(status, detail, m) { super(m || `HTTP ${status}: ${fmt(detail)}`); this.name = 'ApiError'; this.status = status; this.detail = detail; }
}
class RefusalError extends ApiError {
  constructor(detail) { super(403, detail, `refused (HTTP 403): ${fmt(detail)}`); this.name = 'RefusalError'; }
}
function fmt(d) { return typeof d === 'string' ? d : JSON.stringify(d); }

function createClient(env = process.env) {
  const base = (env.SYEN_BASE_URL || 'https://api.syensystems.com').replace(/\/+$/, '');
  const apiKey = env.SYEN_API_KEY || null;
  const exportKey = env.SYEN_EXPORT_API_KEY || null;
  const secrets = [apiKey, exportKey].filter(Boolean);
  // Strip any credential the server might echo back before it reaches an error.
  const scrub = (v) => {
    if (v == null) return v;
    let s = typeof v === 'string' ? v : JSON.stringify(v);
    for (const k of secrets) s = s.split(k).join('[redacted]');
    return typeof v === 'string' ? s : JSON.parse(s);
  };

  async function send(method, path, body, token) {
    const headers = { accept: 'application/json' };
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (token) headers.authorization = `Bearer ${token}`;
    let res;
    try { res = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }); }
    catch (e) { throw new TransportError(`${method} ${path} failed: ${scrub(e.cause?.code || e.message)}`); }
    const raw = await res.text().catch(() => '');
    let data = null;
    try { data = raw ? JSON.parse(raw) : null; } catch { data = raw; }
    if (res.ok) return data;
    const detail = scrub(data && typeof data === 'object' && 'detail' in data ? data.detail : data);
    if (res.status === 403) throw new RefusalError(detail);
    throw new ApiError(res.status, detail);
  }

  async function attestWith(key, { tenantId, agentId, agentCodeHash, scope } = {}) {
    if (!key) throw new ApiError(0, 'missing_credentials', 'missing credentials: set ' + (key === exportKey ? 'SYEN_EXPORT_API_KEY' : 'SYEN_API_KEY'));
    const body = { tenant_id: tenantId, agent_id: agentId, agent_code_hash: agentCodeHash, api_key: key };
    if (scope) body.scope = scope;
    const d = await send('POST', '/api/v1/attest', body);
    return { accessToken: d && d.access_token, expiresIn: d && d.expires_in };
  }

  // scope "evidence:export" presents SYEN_EXPORT_API_KEY; anything else presents SYEN_API_KEY.
  const attest = (o = {}) => attestWith(o.scope === 'evidence:export' ? exportKey : apiKey, o);

  // exportScope: {tenantId, agentId, agentCodeHash} -> mint an evidence:export token first.
  async function request(method, path, { body, token, exportScope } = {}) {
    if (exportScope) token = (await attest({ ...exportScope, scope: 'evidence:export' })).accessToken;
    return send(method, path, body, token);
  }

  return { base, request, attest, hasApiKey: !!apiKey, hasExportKey: !!exportKey };
}

module.exports = { createClient, TransportError, RefusalError, ApiError };
