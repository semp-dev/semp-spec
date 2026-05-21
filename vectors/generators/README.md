# Test Vector Generators

This directory holds the scripts that produce the JSON test vectors under `../v1.0.0/`. The generators are the authoritative source for byte values: the JSON files are committed for the convenience of consumers, but they are derived artifacts. If a JSON value disagrees with the generator's output for the same inputs, the generator wins and the JSON is regenerated.

## Why generated, not hand-authored

A test vector is only useful if any compliant implementation produces the same bytes. Hand-authoring those bytes is risky -- a copy-paste error in `expected.prk_hex` would silently bless an incorrect output forever. Generating from publicly-specified primitives (HKDF/RFC 5869, HMAC/RFC 2104, SHA/FIPS 180-4) means anyone can audit the script, anyone can rerun it, and the generator is decoupled from any specific SEMP implementation.

In particular: the JSON files are NOT generated from `semp.dev/semp-go`. The reference implementation is a CONSUMER of these vectors, not their source. If `semp-go` and the JSON disagree, the bug is in `semp-go` (or the spec), never in the JSON.

## Layer coverage

| Layer | What                                | Generator              | Dependencies              |
|-------|-------------------------------------|------------------------|---------------------------|
| 1     | HKDF, HMAC, SHA-256                 | `generate.py`          | Python stdlib only        |
| 2     | Canonical JSON, envelope rules      | `generate.py`          | Python stdlib only        |
| 3     | Seal wrap/unwrap, envelope round-trip | future `generate.py` extension | requires SEMP construction logic in Python |
| 4     | Handshake message bytes             | future                 | requires SEMP construction logic in Python |
| 5     | Discovery configuration             | future                 | requires Ed25519 (e.g. `cryptography` package) |
| 6     | Negative tests (must-reject)        | future                 | mostly hand-authored      |

Layer 3+ requires implementing the SEMP composition (seal construction, wrapping rules, signing) a SECOND time in Python. That work is gated on a deliberate decision to take on a full Python SEMP reference implementation; it has its own value as a sanity check on the spec but is non-trivial. Layer 1-2 needs no such second implementation -- the primitives are all standard.

## Usage

```sh
cd vectors/generators
python3 generate.py            # write JSON files
python3 generate.py --verify   # exit non-zero if anything would change
python3 generate.py --diff     # show diffs without writing
```

CI should run `--verify`; any drift between the script and the committed JSON fails the build.

## Dependency policy

The generator depends on the Python standard library plus a small, explicit allowlist of widely-audited cryptography packages declared in [`requirements.txt`](requirements.txt). The allowlist is policy, not convenience:

* **Stdlib only** for any primitive Python ships out of the box. That covers HKDF/HMAC/SHA (Layer 1), canonical JSON / base64 (Layer 2), and the SEMP-specific composition rules (canonicalization, bucket selection, PoW preimage).
* **`cryptography`** (pyca/cryptography) when Layer 3+ needs Ed25519, X25519, AES-256-GCM, or ChaCha20-Poly1305. This package implements the IETF/NIST primitives, is actively maintained by the Python Cryptographic Authority, and is the de-facto baseline used by Django, Requests, AWS CLI, and similar mainstream projects.
* **`pqcrypto`** or **`kyber-py`** when Layer 3+ needs Kyber768. PQ primitives are not yet in stdlib in any language; these packages wrap the NIST reference implementations. The generator currently uses `kyber-py` because it exposes the FIPS 203 deterministic-internal API needed for byte-reproducible vectors.
* **`pynacl`** when Layer 3+ needs XChaCha20-Poly1305 (used by the post-quantum suite's large-attachment AEAD per ATTACHMENTS.md §3.2). pyca/cryptography 45 does not expose XChaCha20-Poly1305; PyNaCl wraps libsodium's binding.

Other dependencies are NOT permitted. The point is that anyone -- auditing the spec, building a SEMP implementation in any language, or porting the vectors -- can `pip install -r requirements.txt && python3 generate.py` and reproduce every byte from primitives that already have public RFC/NIST test vectors.

The reference implementation `semp.dev/semp-go` is NEVER a dependency of the generator. Implementations consume the JSON; the generator does not consume them.

Layer 1 + Layer 2 currently use only stdlib. The current `requirements.txt` is empty. Layer 3 work will add the lines above as it lands.

### Stdlib usage

* `hmac`, `hashlib` -- HKDF, HMAC, SHA primitives
* `json` -- canonical JSON encoding (`sort_keys=True`, `separators=(",", ":")`)
* `base64` -- base64 encoding for `_b64` fields
* `copy`, `difflib`, `pathlib`, `argparse` -- utilities

## Reproducing values manually

The HKDF baseline derivation in 10 lines, for verification by inspection:

```python
import hmac, hashlib

ikm  = bytes([0x0b]*32 + [0x0c]*32)
salt = bytes([0xaa]*32) + bytes([0xbb]*32)

prk = hmac.new(salt, ikm, hashlib.sha512).digest()

def expand(prk, info, length):
    out, t = b"", b""
    for i in range(1, (length + 63) // 64 + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha512).digest()
        out += t
    return out[:length]

print(expand(prk, b"SEMP-v1-session-enc-c2s", 32).hex())
# cf74d91d41de6ac8f838715bc44a31d7e23b8e9b4dd7dab6be6ad4b8d0567af6
```

Compare against `vectors/v1.0.0/hkdf.json` -> `hkdf-baseline` -> `expected.keys.K_enc_c2s_hex`.

## Adding a new vector

1. Write the new vector's `build_*_json()` function in `generate.py`.
2. Add it to the `files` list in `main()`.
3. Run `python3 generate.py` to write the new JSON.
4. Verify the values by inspection or against an independent implementation.
5. Commit both `generate.py` and the new JSON file.
6. Update `vectors/README.md`'s coverage table.

Vectors that change bytes for an EXISTING entry require a patch-version bump (e.g. `v1.0.0` -> `v1.0.1`) plus a `CHANGES.md` entry explaining what changed and why. Adding NEW entries to existing files keeps the version unchanged.
