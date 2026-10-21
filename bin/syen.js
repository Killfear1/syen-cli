#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const { verifyBundle } = require('../lib/verify');

const BASE = (process.env.SYEN_API_BASE || 'https://www.syensystems.com').replace(/\/+$/, '');
const VERSION = require('../package.json').version;

const HELP = `syen - command line for SYEN Comply

Usage:
  syen meta [--json]              Product facts: vendor, verification scheme, pricing, availability
  syen news [--json] [--limit N]  Regulatory intelligence feed (curated AI-governance headlines)
  syen verify <bundle.json>       Verify an exported evidence bundle offline
                                  (SHA-256 chain + Ed25519 signatures; no network, no SYEN account)
  syen --version
  syen --help

Environment:
  SYEN_API_BASE   Override the API origin (default https://www.syensystems.com)
`;

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
    if (!file || file.startsWith('--')) { console.error('usage: syen verify <bundle.json>'); process.exit(2); }
    let bundle;
    try { bundle = JSON.parse(fs.readFileSync(file, 'utf8')); }
    catch (e) { console.error(`cannot read bundle: ${e.message}`); process.exit(2); }
    let result;
    try { result = verifyBundle(bundle); }
    catch (e) { console.error(`FAIL - ${e.message}`); process.exit(1); }
    if (argsHas('--json')) { console.log(JSON.stringify(result, null, 2)); }
    else {
      for (const r of result.records)
        console.log(`record ${r.index}${r.id ? ' (' + r.id + ')' : ''}: chain ${r.chain}, signature ${r.signature}, timestamp ${r.timestamp}${r.error ? ' - ' + r.error : ''}`);
      console.log(`${result.ok ? 'PASS' : 'FAIL'} - ${result.records_checked} record(s) verified offline`);
    }
    process.exit(result.ok ? 0 : 1);
  }

  console.error(`unknown command: ${cmd}\n`);
  process.stderr.write(HELP);
  process.exit(2);
}

main().catch((e) => { console.error(e.message); process.exit(1); });
