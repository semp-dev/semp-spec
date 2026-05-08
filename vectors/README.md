# SEMP Test Vectors (machine-readable)

This directory holds machine-readable test vectors that any SEMP implementation can load and assert against. The pose is to make cross-language conformance testable without re-reading prose: an implementation that produces every expected output in every applicable file is interoperable at that layer; an implementation that does not has a bug.

The companion document [`VECTORS.md`](../VECTORS.md) at the repository root is the human-readable normative source. JSON files here MIRROR the inputs and expected outputs from `VECTORS.md` and reference the section that defines them. When the two disagree, `VECTORS.md` wins.

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
  "spec_reference": "VECTORS.md §2",
  "vectors": [
    {
      "id": "hkdf-baseline",
      "description": "Single-line summary of this vector.",
      "spec_reference": "VECTORS.md §2.1",
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

A reference runner ships with [`semp.dev/semp-go`](https://github.com/semp-dev/semp-go) under `cmd/semp-vectors-runner` (forthcoming).

## Coverage

| Layer | Category                        | File                       | Status        |
|-------|---------------------------------|----------------------------|---------------|
| 1     | HKDF-SHA-512 key derivation     | `hkdf.json`                | seeded        |
| 1     | HMAC-SHA-256 envelope MAC       | `session-mac.json`         | seeded        |
| 1     | Confirmation hash               | `confirmation-hash.json`   | seeded        |
| 1     | Proof of work                   | `pow.json`                 | TODO          |
| 2     | Canonical JSON serialization    | `envelope-canonical.json`  | seeded        |
| 3     | Seal wrap / unwrap (round-trip) | `seal-roundtrip.json`      | TODO          |
| 3     | Envelope compose / open         | `envelope-roundtrip.json`  | TODO          |
| 4     | Handshake message bytes         | `handshake-*.json`         | TODO          |
| 5     | Discovery configuration         | `discovery.json`           | TODO          |
| 6     | Negative tests (must-reject)    | `negative-*.json`          | TODO          |

`seeded` means the file exists with a starter set of vectors. `TODO` means the layer is acknowledged but not yet machine-readable.

The rich human-readable vectors in `VECTORS.md` (PoW solutions, extension entries, scoped device certificates, session lifecycle, recipient status, etc.) are next on the porting list.

## Round-trip layers

Layers 3+ test operations that include encryption with random keys. They cannot be tested by static input → static output comparison. The convention is:

* Pin every random input (ephemeral keys, nonces, fresh symmetric keys) as part of `inputs`.
* The implementation MUST expose a "deterministic" compose / handshake path that takes those pinned inputs instead of generating them.
* The `expected` block carries the resulting byte sequence — both directions (compose AND open) MUST round-trip cleanly.

`semp-go` currently exposes deterministic test paths through internal test helpers; making these public (or providing a `vectorgen` build tag) is a prerequisite for shipping Layer 3+ vectors.

## Versioning

* `v1.0.0` tracks SEMP protocol version 1.0.0.
* Bug fixes that change expected outputs land as `v1.0.1`, `v1.0.2`, ... with a `CHANGES.md` listing what changed and why.
* Adding new vectors that do not change existing outputs does NOT bump the version; new files (or new entries in existing files) appear under the same version.
* A new protocol version (e.g. `v1.1.0`) gets a new directory; old directories remain so older implementations stay testable.

## Contributing

Open a PR against `semp-spec`. New vectors MUST:

1. Cite the normative section they exercise (`spec_reference`).
2. Be deterministic — fixed inputs, no implementation-dependent fields.
3. Round-trip (where applicable) through at least the `semp-go` reference implementation before being merged.
4. Include a one-sentence `description` explaining what the vector confirms.
