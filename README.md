# syen-cli

Command line interface for **SYEN Comply** (syensystems.com), the system of record for regulated agent actions.

Three things, in plain words:

1. `syen meta` - reads the public product facts endpoint (vendor, verification scheme, pricing, marketplace availability).
2. `syen news` - reads the regulatory intelligence feed: curated AI-governance and enforcement headlines as JSON or text.
3. `syen verify <bundle.json>` - verifies an exported SYEN evidence bundle **offline**: no network, no account, no SYEN systems involved. This is the auditor story from the site: the proof checks out without SYEN being online.

Zero dependencies. Requires Node.js 18 or newer.

## Install

```sh
npm install -g @syensystems/syen-cli
syen --help
```

From a clone instead: `node bin/syen.js --help`, or `npm link` to put `syen` on your PATH.

## Usage

```sh
syen meta [--json]              # product facts
syen news [--json] [--limit N]  # regulatory intelligence feed
syen verify <bundle.json>       # offline evidence-bundle verification
```

`SYEN_API_BASE` overrides the API origin for `meta` and `news` (default `https://www.syensystems.com`). `verify` never makes network requests.

## What verify checks, and what it does not

`syen verify` reads an exported SYEN evidence bundle (schema `syen.evidence-bundle/1`, what the
SYEN Comply API's `GET /api/v1/evidence/export` produces for a tenant) and checks it entirely
offline, with the same rules as the verifier SYEN ships:

- every event's SHA-256 chain hash recomputes from its RFC 8785 (JCS) canonical content,
- events link to their predecessors, with gap and duplicate detection,
- receipt references match event hashes,
- Ed25519 signatures verify - only against a key YOU supply: `--trusted-pubkey <base64>`.
  A public key embedded in the bundle is never trusted, because whoever edits a bundle can swap it.

```sh
syen verify bundle.json --trusted-pubkey <base64> --tenant <tenant-id>
syen verify bundle.json --json     # full report: verdict, failures, warnings, counts
```

Verdicts: `PASS`, `PASS_WITH_LIMITS`, `INCOMPLETE`, `FAIL`. Exit codes: 0 pass, 1 fail,
2 incomplete export. A passing verdict means integrity and signer attribution only - not that
any claim inside a record is true.

## Tests

```sh
npm test
```

Six tests: RFC 8785 canonicalization vectors, PASS on a well-formed bundle, FAIL on a tampered payload, rejection of wrong formats and non-Ed25519 keys, the `meta`/`news` commands against a fixture server, and exit codes.

## Honest scope

`syen meta` and `syen news` return public data already published on syensystems.com. `syen verify` verifies the mathematics of a bundle you already hold. It does not contact SYEN, does not prove the events in a bundle actually happened in a particular system, and does not establish trust in RFC 3161 timestamps. Verification of a real tenant export uses the tenant's own key material as described on the site's support page.
