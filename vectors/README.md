# SEMP Test Vectors (machine-readable)

This directory holds machine-readable test vectors that any SEMP implementation, in any language, can load and assert against. The purpose is to make cross-language conformance testable without re-reading prose: an implementation that produces every expected output in every applicable file is interoperable at that layer; an implementation that does not has a bug.

These vectors are language-neutral by design. They exist for the spec, not for any one implementation. Go, TypeScript, Dart, Rust, Swift, Kotlin, or anything else — every consumer hits the same JSON contract. No SEMP implementation has any privileged status as the "ground truth"; the JSON is the contract, and the JSON is produced by the standalone Python generator under [`generators/`](generators/).

The JSON files here are the executable contract. Each vector carries a `spec_reference` pointing at the normative section of the relevant draft (under [`../`](../)) that defines the operation under test. When a vector and the spec drafts disagree, the spec drafts win and the JSON is regenerated to match.

## Layout

```
vectors/
  README.md                        ← this file
  v1.0.0/                          ← per protocol version
    hkdf.json                      ← Layer 1: HKDF-SHA-512 derivations
    session-mac.json               ← Layer 1: HMAC-SHA-256 envelope MAC
    confirmation-hash.json         ← Layer 1: handshake confirmation hash
    envelope-canonical.json        ← Layer 3: canonical envelope JSON encoding
    ...
```

Each subdirectory `vN.M.P/` corresponds to a frozen protocol version. Vectors are immutable once a version is published — bug-fix-driven changes get a new patch version. Implementations declare which vector versions they support.

## File schema

Every vectors file has this top-level shape:

```json
{
  "version": "1.0.0",
  "category": "hkdf",
  "description": "Single-line summary of what this file covers.",
  "spec_reference": "handshake.md §2",
  "vectors": [
    {
      "id": "hkdf-baseline",
      "description": "Single-line summary of this vector.",
      "spec_reference": "handshake.md §2.1",
      "inputs": { ... },
      "expected": { ... }
    }
  ]
}
```

* `version` — the protocol version this file targets.
* `category` — short identifier for the operation under test.
* `description` — human-readable summary.
* `spec_reference` — pointer to the normative spec section.
* `vectors[]` — one entry per test case. Each carries its own `spec_reference` so a failing test points the implementer at the relevant text.

Some vectors describe a single operation (one `inputs`, one `expected`); others enumerate a table of related cases. The two supported shapes:

```json
// Single-case shape:
{
  "id": "...",
  "inputs":   { "x_hex": "..." },
  "expected": { "y_hex": "..." }
}

// Table shape (used when the same algorithm has many small input/output pairs,
// e.g. envelope size buckets):
{
  "id": "...",
  "rule": "human-readable summary of the algorithm",
  "samples": [
    { "input_field_a": ..., "expected_field_b": ... },
    { "input_field_a": ..., "expected_field_b": ... }
  ]
}
```

A runner SHOULD detect which shape a vector uses by checking for `samples` first, then falling back to `inputs`/`expected`.

Inputs and expected outputs are **encoded as strings** with explicit encoding suffixes:

| Suffix       | Encoding                                                |
|--------------|---------------------------------------------------------|
| `_hex`       | Lowercase hexadecimal, no separators (RFC 4648 §8).     |
| `_b64`       | Standard base64 with padding (RFC 4648 §4).             |
| `_utf8`      | UTF-8 string, shown literally.                          |
| `_json`      | Embedded JSON value (object or string).                 |
| `_canonical` | Canonical bytes per `ENVELOPE.md` §4.3, hex-encoded.    |

So `ikm_hex`, `client_nonce_hex`, `prk_hex`, etc.

## Running vectors

Every implementation SHOULD ship a vectors-runner that:

1. Loads every `*.json` file in a chosen `vN.M.P/` directory.
2. For each vector entry, runs the operation named by `category` with the given `inputs`.
3. Asserts every field in `expected` matches byte-for-byte.
4. Reports `id` plus `spec_reference` on any mismatch.

A runner is a small, language-idiomatic test harness — typically a few hundred lines. The exact shape varies (Go: a `_test.go` driver; TypeScript: a Vitest/Jest suite; Dart: `package:test`; Rust: a `#[test]` module pointing at `vectors/v1.0.0/`). What matters is that running it against a fresh checkout of any SEMP implementation produces the same pass/fail result.

## Coverage

| Category                            | File                              | Status        |
|-------------------------------------|-----------------------------------|---------------|
| HKDF-SHA-512 key derivation         | `hkdf.json`                       | seeded        |
| HMAC-SHA-256 envelope MAC           | `session-mac.json`                | seeded        |
| Confirmation hash                   | `confirmation-hash.json`          | seeded        |
| Proof of work                       | `pow.json`                        | seeded        |
| Canonical JSON serialization        | `envelope-canonical.json`         | seeded        |
| Envelope size + recipient buckets   | `envelope-buckets.json`           | seeded        |
| Discovery response + TXT parsing    | `discovery.json`                  | seeded        |
| Rejection-code recoverability       | `rejection-codes.json`            | seeded        |
| Extension entry validation          | `extension-entries.json`          | seeded        |
| Session lifecycle                   | `session-lifecycle.json`          | seeded        |
| Delivery + submission status        | `delivery-status.json`            | seeded        |
| Key revocation handling             | `key-revocation.json`             | seeded        |
| Scoped device certificates          | `device-certificates.json`        | seeded        |
| Recipient status visibility         | `recipient-status.json`           | seeded        |
| Seal wrap / unwrap (round-trip)     | `seal-roundtrip.json`             | seeded (baseline + PQ) |
| Envelope compose / open             | `envelope-roundtrip.json`         | seeded (baseline + PQ) |
| Sender identity signature           | `sender-signature.json`           | seeded        |
| Forwarding primitive (3-step)       | `forwarding.json`                 | seeded        |
| Signed delivery receipt             | `delivery-receipt.json`           | seeded        |
| Large-attachment AEAD               | `large-attachment.json`           | seeded (baseline + PQ) |
| Handshake message bytes (baseline)  | `handshake-messages.json`         | seeded        |
| Handshake message bytes (PQ)        | `handshake-messages-pq.json`      | seeded        |
| Session resumption ticket           | `session-resumption.json`         | seeded        |
| First-contact token                 | `first-contact-token.json`        | seeded        |
| Clock tolerance boundaries          | `clock-tolerance.json`            | seeded        |
| Discovery signature verification    | `discovery-signed.json`           | seeded        |
| Configuration versioning            | `configuration-update.json`       | seeded        |
| Key transparency proofs             | `transparency.json`               | seeded (STH + inclusion + consistency + §4 augmented fetch) |
| Account recovery bundle             | `account-recovery.json`           | seeded        |
| Shamir device-split recovery        | `recovery-shamir.json`            | seeded        |
| Provider migration                  | `migration.json`                  | seeded        |
| Account closure                     | `account-closure.json`            | seeded        |
| User policy update                  | `user-policy.json`                | seeded        |
| Envelope-level rejection            | `negative-envelope-rejection.json`| seeded        |
| Must-reject coverage index          | `must-reject-index.json`          | seeded        |

`seeded` means the file exists with a starter set of vectors. Additional
detailed cases (PoW solutions, extension entries, scoped device
certificates, session lifecycle, recipient status, etc.) are next on the
porting list as the spec drafts settle.

## Must-reject coverage

A "must-reject" vector pins an input that conformant implementations
MUST refuse and asserts the refusal at generation time. They split into
three buckets by where they live:

1. **Operation-specific tampers** (e.g. a flipped bit in a forwarded
   envelope, a sender_signature signed by the wrong key, a tampered
   large-attachment ciphertext) live alongside the positive case for
   the same operation. They share pinned inputs with the positive
   case so a single regeneration keeps the two in lock-step. Examples:
   `sender-signature-tampered-body`, `forward-tampered-original-content`,
   `delivery-receipt-tampered-envelope`, `large-attachment-tampered-ciphertext`.
2. **Envelope-level rejection** (expired postmark, invalid seal, invalid
   session MAC) lives in `negative-envelope-rejection.json`. These reject
   reasons are not tied to any single operation, so a dedicated file is
   the right home.
3. **Reject-code decision tables** (which numeric code, which is
   recoverable, what the client/server next-step is) live in
   `rejection-codes.json`.

Every must-reject vector entry carries a `must_reject: true` flag and a
`rejection_class` identifier (e.g. `envelope.seal-invalid`,
`sender.signature-tampered`, `forwarding.original-content-tampered`).
A runner can enumerate the must-reject coverage by walking all `*.json`
files under `vN.M.P/` and collecting entries with the flag.

`must-reject-index.json` is a generated cross-reference that lists every
must-reject vector across all files, grouped by `rejection_class`, with
a pointer of the form `<file>#<vector_id>` and the spec section it
exercises. The index is regenerated by `generators/generate.py` whenever
the underlying flags change; do not edit it by hand.

## Round-trip layers

Layers 3+ test operations that include encryption with random keys. They cannot be tested by static input → static output comparison. The convention is:

* Pin every random input (ephemeral keys, nonces, fresh symmetric keys) as part of `inputs`.
* The implementation MUST expose a "deterministic" compose / handshake path that takes those pinned inputs instead of generating them. Conventionally this is gated behind a test-only build tag, feature flag, or internal API so production code paths can never accidentally accept caller-controlled key material.
* The `expected` block carries the resulting byte sequence — both directions (compose AND open) MUST round-trip cleanly.

The Python generator under [`generators/`](generators/) is the source of byte values for every layer, including Layer 3+. It does NOT call into any specific SEMP implementation; it implements the SEMP construction independently from public-standard primitives so the vectors stay decoupled from any single language's reference code.

## Versioning

* `v1.0.0` tracks SEMP protocol version 1.0.0.
* Bug fixes that change expected outputs land as `v1.0.1`, `v1.0.2`, ... with a `CHANGES.md` listing what changed and why.
* Adding new vectors that do not change existing outputs does NOT bump the version; new files (or new entries in existing files) appear under the same version.
* A new protocol version (e.g. `v1.1.0`) gets a new directory; old directories remain so older implementations stay testable.

## Contributing

Open a PR against `semp-spec`. New vectors MUST:

1. Cite the normative section they exercise (`spec_reference`).
2. Be deterministic — fixed inputs, no implementation-dependent fields.
3. Be produced by the Python generator under [`generators/`](generators/), not hand-authored. Run `python3 generators/generate.py --verify` in CI; the build fails on any drift between generator and JSON.
4. Round-trip (where applicable) through at least one independent SEMP implementation before being merged, as a sanity check on the generator.
5. Include a one-sentence `description` explaining what the vector confirms.
