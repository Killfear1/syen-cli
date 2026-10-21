# syen-cli

Command line interface for **SYEN Comply** (syensystems.com), the system of record for regulated agent actions.

Three things, in plain words:

1. `syen meta` - reads the public product facts endpoint (vendor, verification scheme, pricing, marketplace availability).
2. `syen news` - reads the regulatory intelligence feed: curated AI-governance and enforcement headlines as JSON or text.
3. `syen verify <bundle.json>` - verifies an exported SYEN evidence bundle **offline**: no network, no account, no SYEN systems involved. This is the auditor story from the site: the proof checks out without SYEN being online.

Zero dependencies. Requires Node.js 18 or newer.

## Install

Until the package is published, run it from a clone:

```sh
node bin/syen.js --help
# or link it onto your PATH:
npm link
syen --help
```

## Usage

```sh
syen meta [--json]              # product facts
syen news [--json] [--limit N]  # regulatory intelligence feed
syen verify <bundle.json>       # offline evidence-bundle verification
```

`SYEN_API_BASE` overrides the API origin for `meta` and `news` (default `https://www.syensystems.com`). `verify` never makes network requests.

## What verify checks, and what it does not

Bundle format `syen-evidence-bundle/v1`:

```json
{
  "format": "syen-evidence-bundle/v1",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n... Ed25519 SubjectPublicKeyInfo ...",
  "records": [
    {
      "id": "rec-0",
      "payload": { "event": "receipt.issued", "amount": 42 },
      "hash": "<64 hex chars>",
      "signature": "<base64 Ed25519 signature over the hash>",
      "timestamp_token": "<optional base64 RFC 3161 token>"
    }
  ]
}
```

For each record, in order:

- **Chain** - recomputes `sha256(previous_hash || rfc8785_canonical(payload))` and compares it to `record.hash`. The first record chains from 64 zeroes. A tampered payload breaks the link; a tampered hash breaks every later link.
- **Signature** - verifies the Ed25519 signature over `record.hash` against the bundle's public key.
- **Timestamp** - if an RFC 3161 token is present, checks that it decodes and parses structurally. **Trust is not checked**: deciding a timestamp token is genuine requires the timestamp authority's root certificates, which this tool does not bundle. The output says exactly that.

Exit code 0 only when every chain link and every signature verifies. Canonicalization is RFC 8785 (JSON Canonicalization Scheme); numbers serialize per the ECMAScript algorithm the RFC specifies.

## Tests

```sh
npm test
```

Six tests: RFC 8785 canonicalization vectors, PASS on a well-formed bundle, FAIL on a tampered payload, rejection of wrong formats and non-Ed25519 keys, the `meta`/`news` commands against a fixture server, and exit codes.

## Honest scope

`syen meta` and `syen news` return public data already published on syensystems.com. `syen verify` verifies the mathematics of a bundle you already hold. It does not contact SYEN, does not prove the events in a bundle actually happened in a particular system, and does not establish trust in RFC 3161 timestamps. Verification of a real tenant export uses the tenant's own key material as described on the site's support page.
