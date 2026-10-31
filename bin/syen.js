#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const { verifyBundle } = require('../lib/verifier');

const BASE = (process.env.SYEN_API_BASE || 'https://www.syensystems.com').replace(/\/+$/, '');
const VERSION = require('../package.json').version;

const HELP = `syen - command line for SYEN Comply

Usage:
  syen meta [--json]              Product facts: vendor, verification scheme, pricing, availability
  syen news [--json] [--limit N]  Regulatory intelligence feed (curated AI-governance headlines)
  syen verify <bundle.json>       Verify an exported SYEN evidence bundle (syen.evidence-bundle/1)
                                  offline: SHA-256 chain + Ed25519 signatures; no network needed
    --trusted-pubkey <base64>     Tenant Ed25519 public key to check signatures against
    --tenant <tenant-id>          Tenant the bundle must belong to (recommended)
    --require-signed-manifest     FAIL unless the manifest signature verifies against --trusted-pubkey
    --json                        Full report as JSON (verdict, failures, warnings, counts)

Operator commands (exit: 0 ok/ALLOW, 1 API error, 2 usage, 3 DENY, 4 REQUIRE_APPROVAL, 5 refused/403, 6 transport/unsupported):
  syen attest --tenant T --agent A --code-hash H [--scope evidence:export]
  syen mandate create --principal P --agent A --actions a,b --max-amount N
                      [--currency USD] [--ttl-seconds N] [--not-before ISO] [--approval-required-over N]
                      [--parent ID] [--forbidden-fields f1,f2]
  syen mandate get --id ID | mandate revoke --id ID | mandate list
                                  mandate commands need --token, or --tenant --agent --code-hash to attest
  syen check --mandate ID --action JSON [--amount N] [--request-id ID] [--approval JSON]
                                  --request-id is generated when absent
  syen approve | hitl request --approver ID --action-id ID --event-type E --actor ID
                      --risk-level LOW|MEDIUM|HIGH|CRITICAL [--mandate ID] [--action JSON]
                      [--details JSON] [--timeout-seconds 10..3600]
  syen hitl respond --request TOKEN --decision APPROVED|DENIED --action JSON --action-id ID
                                  authenticate as the designated approver via --token
  syen outcome record --decision ID --status EXECUTED|FAILED|NOT_EXECUTED --action-hash H
                      --grade SIMULATED|SELF_REPORTED|SOURCE_EVIDENCE_ATTACHED
                      [--source S] [--source-ref R] [--source-evidence-hash HEX64] [--details JSON]
  syen evidence export --tenant T --agent A --code-hash H [--out FILE]
  syen coverage | drift status | version
  syen doctor [--tenant T --agent A --code-hash H]
  Global: --json  --base-url URL (overrides SYEN_BASE_URL)  --token TK (bearer token)
  syen --version
  syen --help

Portal (browser access): https://portal.syensystems.com

Environment:
  SYEN_API_BASE         Override the API origin for meta/news (default https://www.syensystems.com)
  SYEN_BASE_URL         API origin for operator commands (default https://api.syensystems.com)
  SYEN_API_KEY          API key for attest (never printed)
  SYEN_EXPORT_API_KEY   Export key for evidence export (never printed)
`;

const OPS = {
  attest: 'attest', check: 'check', approve: 'approve', coverage: 'coverage', version: 'version', doctor: 'doctor',
  'mandate create': 'mandateCreate', 'mandate get': 'mandateGet', 'mandate revoke': 'mandateRevoke', 'mandate list': 'mandateList',
  'hitl request': 'hitlRequest', 'hitl respond': 'hitlRespond', 'outcome record': 'outcomeRecord',
  'evidence export': 'evidenceExport', 'drift status': 'driftStatus',
};
const BOOL = new Set(['json', 'help']);
const RENAME = { actions: 'allowedActions', ttlSeconds: 'ttl' };
function parseFlags(argv) {
  const a = {};
  for (let i = 0; i < argv.length; i++) {
    if (!argv[i].startsWith('--')) return { error: `unexpected argument: ${argv[i]}` };
    const name = argv[i].slice(2), key0 = name.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    const key = RENAME[key0] || key0;
    if (BOOL.has(name)) { a[key] = true; continue; }
    if (i + 1 >= argv.length || argv[i + 1].startsWith('--')) return { error: `--${name} needs a value` };
    a[key] = argv[++i];
  }
  return { a };
}

async function runOp(name, argv) {
  const { a, error } = parseFlags(argv);
  const json = argv.includes('--json');
  if (error) { console.error(`usage: ${error}`); process.exitCode = 2; return; }
  if (a.help) { process.stdout.write(HELP); return; }
  const { createClient } = require('../lib/api');
  const commands = require('../lib/commands');
  const client = createClient(a.baseUrl ? { ...process.env, SYEN_BASE_URL: a.baseUrl } : process.env);
  if (name === 'version') a.version = VERSION;
  const r = await commands[name](client, a);
  if (name === 'evidenceExport' && r.exitCode === 0 && a.out) {
    fs.writeFileSync(a.out, JSON.stringify(r.json, null, 1));
    r.text = `evidence bundle written to ${a.out}`;
  }
  if (json) console.log(JSON.stringify(r.json, null, 2));
  else (r.exitCode === 0 || r.exitCode === 3 || r.exitCode === 4 ? console.log : console.error)(r.text);
  process.exitCode = r.exitCode;
}

function argsHas(flag) { return process.argv.includes(flag); }
function argValue(flag, dflt) {
  const i = process.argv.indexOf(flag);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : dflt;
}

async function getJson(path) {
  const res = await fetch(BASE + path, { headers: { accept: 'application/json' } });
  if (!res.ok) throw new Error(`GET ${path} returned HTTP ${res.status}`);
  return res.json();
}

async function main() {
  const cmd = process.argv[2];
  if (!cmd || cmd === '--help' || cmd === '-h') { process.stdout.write(HELP); return; }
  if (cmd === '--version' || cmd === '-v') { console.log(VERSION); return; }

  if (cmd === 'meta') {
    const data = await getJson('/api/v1/meta');
    if (argsHas('--json')) { console.log(JSON.stringify(data, null, 2)); return; }
    console.log(`${data.name} - ${data.category}`);
    console.log(`Vendor: ${data.vendor.name} (${data.vendor.location})`);
    console.log(`Verification: ${data.verification.signature}, ${data.verification.chaining}, ${data.verification.anchoring}`);
    for (const p of data.pricing) {
      if (p.price_usd_monthly) console.log(`  ${p.plan}: $${p.price_usd_monthly.toLocaleString()}/mo - ${p.includes}`);
      else console.log(`  ${p.plan}: $${p.price_usd_per_verified_receipt}/verified receipt, $${p.monthly_minimum_usd.toLocaleString()} monthly minimum`);
    }
    console.log(`Demo: ${data.links.demo}`);
    console.log(`OpenAPI: ${data.links.openapi}`);
    return;
  }

  if (cmd === 'news') {
    const data = await getJson('/api/v1/news');
    const limit = Number(argValue('--limit', data.items.length));
    const items = data.items.slice(0, limit);
    if (argsHas('--json')) { console.log(JSON.stringify({ items }, null, 2)); return; }
    for (const it of items) {
      console.log(`- [${it.source}] ${it.title}`);
      if (it.url) console.log(`  ${it.url}`);
      console.log(`  ${it.framing}`);
    }
    return;
  }

  if (cmd === 'verify') {
    const file = process.argv[3];
    if (!file || file.startsWith('--')) { console.error('usage: syen verify <bundle.json> [--trusted-pubkey B64] [--tenant ID] [--require-signed-manifest] [--json]'); process.exit(2); }
    let bundle;
    try { bundle = JSON.parse(fs.readFileSync(file, 'utf8')); }
    catch (e) { console.error(`cannot read bundle: ${e.message}`); process.exit(2); }
    const report = verifyBundle(bundle, argValue('--trusted-pubkey', null), argValue('--tenant', null), argsHas('--require-signed-manifest'));
    if (argsHas('--json')) { console.log(JSON.stringify(report, null, 1)); }
    else {
      console.log(report.verdict, JSON.stringify(report.checked));
      console.log('presentation_authentication', report.presentation_authentication ?? null);
      console.log('provenance', JSON.stringify(report.provenance ?? null));
      for (const x of report.failures) console.log('FAIL', JSON.stringify(x));
      for (const x of report.warnings) console.log('warn', JSON.stringify(x));
      console.log(report.meaning);
    }
    process.exit(report.verdict === 'FAIL' ? 1 : report.verdict === 'INCOMPLETE' ? 2 : 0);
  }

  const two = `${cmd} ${process.argv[3]}`;
  if (OPS[two]) return runOp(OPS[two], process.argv.slice(4));
  if (OPS[cmd]) return runOp(OPS[cmd], process.argv.slice(3));
  if (['mandate', 'hitl', 'outcome', 'evidence', 'drift'].includes(cmd) && process.argv[3] === '--help') { process.stdout.write(HELP); return; }

  console.error(`unknown command: ${cmd}\n`);
  process.stderr.write(HELP);
  process.exit(2);
}

main().catch((e) => { console.error(e.message); process.exit(1); });
