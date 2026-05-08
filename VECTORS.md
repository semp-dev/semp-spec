# SEMP Test Vectors

**Sealed Envelope Messaging Protocol**
Status: Internet-Draft
Version: 0.2.0-draft
Related: `DESIGN.md`, `ENVELOPE.md`, `HANDSHAKE.md`, `SESSION.md`, `KEY.md`,
`DISCOVERY.md`, `CONFORMANCE.md`

---

## Abstract

This document provides canonical test vectors for SEMP implementations. Each
vector specifies deterministic inputs and expected outputs for a single
protocol operation. An implementation that produces the expected output for
every applicable vector is interoperable at that operation. An implementation
that produces different output has a bug.

These vectors cover only deterministic operations: key derivation, canonical
serialization, MAC computation, challenge verification, and confirmation
hashing. Operations that depend on random input (key generation, nonce
generation, encryption) cannot be tested with static vectors. Those operations
are tested indirectly through round-trip vectors where both encryption and
decryption inputs are provided.

Machine-readable JSON copies of the vectors in this document live under
[`vectors/`](vectors/). Implementations SHOULD ship a runner that loads
those files and asserts every expected output. The JSON files are the
executable contract; the prose in this document is the normative
explanation. When the two disagree, this document wins and the JSON
file is amended to match.

---

## 1. Notation

All byte strings are represented as hexadecimal unless otherwise noted. Base64
values are standard base64 with padding (RFC 4648 §4). JSON strings are UTF-8.

| Notation        | Meaning                                              |
|-----------------|------------------------------------------------------|
| `hex:`          | Hexadecimal-encoded byte string.                     |
| `b64:`          | Standard base64-encoded byte string.                 |
| `utf8:`         | UTF-8 encoded string, shown as literal text.         |
| `||`            | Byte concatenation.                                  |
| `len: N`        | Length in bytes.                                      |

---

## 2. HKDF-SHA-512 Session Key Derivation

Reference: `HANDSHAKE.md` §2.4, `SESSION.md` §2.1, `ENVELOPE.md` §7.3.1.

These vectors verify that an implementation correctly derives the five session
keys from a known shared secret, client nonce, and server nonce. The KDF
(HKDF-SHA-512) and MAC (HMAC-SHA-256) used in these vectors are determined by
the negotiated algorithm suite. Both currently defined suites,
`x25519-chacha20-poly1305` and `pq-kyber768-x25519`, specify HKDF-SHA-512
for key derivation and HMAC-SHA-256 for MAC operations. Future suites may
specify different primitives; test vectors for those suites would be added
when they are defined.

### 2.1 Vector: Baseline Key Derivation

**Procedure:**

1. Compute salt: `client_nonce || server_nonce` (64 bytes).
2. HKDF-Extract(salt, IKM) → PRK.
3. For each of the five keys, HKDF-Expand(PRK, info_label, 32) → key, using
   the per-key UTF-8 info labels:
   - `K_enc_c2s` ← `"SEMP-v1-session-enc-c2s"`
   - `K_enc_s2c` ← `"SEMP-v1-session-enc-s2c"`
   - `K_mac_c2s` ← `"SEMP-v1-session-mac-c2s"`
   - `K_mac_s2c` ← `"SEMP-v1-session-mac-s2c"`
   - `K_env_mac` ← `"SEMP-v1-session-env-mac"`

The IKM in this vector is a synthetic 64-byte value (32 bytes of `0x0b`
followed by 32 bytes of `0x0c`) representing the combined output of a hybrid
key agreement (`K_kyber || K_x25519`). It is not the output of a real Kyber768
or X25519 operation. The client nonce is 32 bytes of `0xaa`; the server nonce
is 32 bytes of `0xbb`.

**Bytes:** see [`vectors/v1.0.0/hkdf.json`](vectors/v1.0.0/hkdf.json), entry
`id: hkdf-baseline`. The JSON carries the IKM, both nonces, the info labels,
the expected PRK, and the five expected derived keys.

**Verification:** An implementation MUST derive all five keys from the inputs
in the JSON and compare against `expected.prk_hex` and the five
`expected.keys.K_*_hex` values. Any mismatch indicates incorrect HKDF-SHA-512
usage, incorrect label encoding, or incorrect salt construction.

### 2.2 Vector: Rekey Derivation

Reference: `SESSION.md` §3.3.

Rekeying uses the same five per-key info labels as §2.1, applied to a fresh
PRK derived from new key material. The salt is
`rekey_nonce || responder_nonce` (64 bytes). The IKM in this vector is 32
bytes of `0xd1` followed by 32 bytes of `0xe2`; the rekey nonce is 32 bytes
of `0xcc`; the responder nonce is 32 bytes of `0xdd`.

**Note:** The info labels for rekey derivation use the same key-specific labels
as the initial derivation (`"SEMP-v1-session-enc-c2s"`, etc.). The
`"SEMP-v1-rekey"` context string distinguishes the rekey from the initial
derivation through the different salt (rekey nonces vs. session nonces), not
through the per-key expand labels. Implementations MUST produce identical keys
when given the same IKM, salt, and labels, regardless of whether the
derivation occurs during an initial handshake or a rekey. The PRK will differ
because the salt differs.

**Bytes:** see [`vectors/v1.0.0/hkdf.json`](vectors/v1.0.0/hkdf.json), entry
`id: hkdf-rekey`.

---

## 3. Envelope Canonicalization

Reference: `ENVELOPE.md` §4.3.

These vectors verify that an implementation produces the correct canonical byte
sequence from a given envelope, which is the input to both `seal.signature` and
`seal.session_mac` computation.

### 3.1 Vector: Minimal Envelope

**Canonicalization rules:**

1. `seal.signature` → set to `""`
2. `seal.session_mac` → set to `""`
3. `postmark.hop_count` → omitted entirely
4. `padding` → omitted entirely
5. All keys sorted lexicographically at every nesting level
6. No insignificant whitespace
7. UTF-8 encoding

**Bytes:** see [`vectors/v1.0.0/envelope-canonical.json`](vectors/v1.0.0/envelope-canonical.json),
entry `id: envelope-canonical-minimal`. The JSON carries the input envelope
under `inputs.envelope_json` and the expected canonical UTF-8 string under
`expected.canonical_utf8`.

**Key observations for implementers:**

- `hop_count` is absent from the canonical output even though it was present
  in the input (value `2`).
- `padding` is absent from the canonical output even though it was present
  in the input. Padding never enters the signature or MAC computation.
- `seal.signature` and `seal.session_mac` are present as empty strings, not
  omitted.
- Top-level keys are sorted: `brief`, `enclosure`, `postmark`, `seal`, `type`,
  `version`.
- `postmark` keys are sorted: `expires`, `extensions`, `from_domain`, `id`,
  `session_id`, `to_domain`. Note `hop_count` is missing.
- `seal` keys are sorted: `algorithm`, `brief_recipients`,
  `enclosure_recipients`, `extensions`, `key_id`, `session_mac`, `signature`.
- Empty objects `{}` are preserved, not omitted.

### 3.2 Vector: Envelope with Extensions

This vector adds two postmark extensions and two brief recipients to confirm
that nested-object keys (extensions and recipient maps) sort lexicographically
just like top-level keys.

**Bytes:** see [`vectors/v1.0.0/envelope-canonical.json`](vectors/v1.0.0/envelope-canonical.json),
entry `id: envelope-canonical-with-extensions`.

**Key observations:**

- Extension keys within `postmark.extensions` are sorted lexicographically:
  `another.example.com/class` before `vendor.example.com/priority`.
- `brief_recipients` keys are sorted: `client-key-fp` before `server-key-fp`.
- No `hop_count` was present in the input, so none appears in the output.
  The canonicalization is the same whether `hop_count` was absent or present.

### 3.3 Vector: Envelope Size Bucket Computation

Reference: `ENVELOPE.md` §2.4.1.

**Rule:** `bucket = max(1024, smallest power of two >= unpadded_size)`. The
final value is then clamped to the operator-configured `max_envelope_size`
(typically 25 MiB / 26 214 400 bytes).

The padding-byte count is `selected_bucket - unpadded_size`. The padding
bytes, base64-encoded in `padding`, will enlarge the envelope by a factor
slightly larger than 1 (4 base64 output bytes per 3 input bytes plus JSON
string overhead); implementations MUST iterate to convergence or compute the
padding budget with the base64 overhead accounted for, so that the final
serialized envelope matches the selected bucket exactly.

**Bytes:** see [`vectors/v1.0.0/envelope-buckets.json`](vectors/v1.0.0/envelope-buckets.json),
entry `id: envelope-size-buckets` (`samples` array of unpadded-size →
bucket-size mappings).

### 3.4 Vector: Recipient-Count Bucket Computation

Reference: `ENVELOPE.md` §4.4.2.

**Rule:** `bucket = 1` if (`real_recipients == 1` and the single recipient is
single-domain and not part of a group send); otherwise the next power of two
with floor 2 and ceiling 1024. Real counts above 1024 force recomposition into
multiple envelopes.

**Bytes:** see [`vectors/v1.0.0/envelope-buckets.json`](vectors/v1.0.0/envelope-buckets.json),
entry `id: recipient-count-buckets`.

---

## 4. Proof-of-Work Verification

Reference: `HANDSHAKE.md` §2.2b, `REPUTATION.md` §8.3.

These vectors verify that an implementation correctly validates proof of work
challenge solutions.

### 4.1 Vector: Valid Proof of Work Solution (Difficulty 16)

**Verification procedure:**

1. Confirm `challenge_id` matches an issued, unexpired challenge.
2. Reconstruct the preimage string from the components per §4.3.
3. Compute SHA-256 over the UTF-8 bytes of the preimage string.
4. Confirm the hash has at least N leading zero bits, where N is the
   advertised difficulty.
5. Confirm the submitted hash matches the computed hash.

**Bytes:** see [`vectors/v1.0.0/pow.json`](vectors/v1.0.0/pow.json), entry
`id: pow-difficulty-16-valid`. The JSON carries the prefix (hex and base64),
challenge_id, nonce, full preimage string, expected hash, and computed
`leading_zero_bits` (16 for this vector → satisfies difficulty 16).

### 4.2 Vector: Failed Proof of Work Solution (Insufficient Difficulty)

Same prefix and challenge_id as §4.1, with a nonce that produces only 7
leading zero bits — short of the required 16. Implementations MUST reject.

**Bytes:** see [`vectors/v1.0.0/pow.json`](vectors/v1.0.0/pow.json), entry
`id: pow-difficulty-16-insufficient`.

### 4.3 Proof of Work Preimage Construction Reference

The preimage is always constructed as:

```
base64(prefix) + ":" + challenge_id + ":" + base64(nonce)
```

All three components are encoded as UTF-8 strings. The colons are literal
`":"` characters (UTF-8 byte `0x3a`). The SHA-256 hash is computed over the
raw UTF-8 bytes of this string, not over any further encoding of it.

Difficulty `N` requires the first `N` bits of the SHA-256 output to be zero.
For `N = 16`, the first 2 bytes must be `0x0000`. For `N = 20`, the first 2
bytes must be `0x0000` and the high nibble of the third byte must be `0x0`.

---

## 5. Confirmation Hash

Reference: `HANDSHAKE.md` §2.5.3.

The confirmation hash binds the client's identity proof to the specific
handshake exchange.

### 5.1 Vector: Confirmation Hash Computation

**Procedure:**

```
confirmation_hash = SHA-256( canonical(message_1) || canonical(message_2) )
```

Where `canonical()` produces the UTF-8 bytes of the sorted, minified JSON
(the same canonicalization used for envelope seals, see §3). The two byte
sequences are concatenated directly with no separator. The client then signs
`session_id || confirmation_hash` with its long-term identity key.

**Bytes:** see [`vectors/v1.0.0/confirmation-hash.json`](vectors/v1.0.0/confirmation-hash.json),
entry `id: confirmation-hash-pq-kyber-baseline`. The JSON carries the canonical
forms of message 1 (init, party=client) and message 2 (response, party=server)
under `inputs.message_1_canonical_utf8` and `inputs.message_2_canonical_utf8`,
plus the expected hash under `expected.hash_hex` / `expected.hash_b64`.

**Verification:** Given the exact canonical forms in the JSON, two
implementations MUST produce the SHA-256 output shown. Any difference indicates
a canonicalization or encoding bug.

---

## 6. Envelope Session MAC

Reference: `ENVELOPE.md` §4.3, `SESSION.md` §2.1.

The `seal.session_mac` is an HMAC computed using `K_env_mac` over the canonical
envelope bytes.

### 6.1 Vector: Session MAC Computation

**Procedure:**

```
session_mac = HMAC-SHA-256(K_env_mac, canonical_envelope_bytes)
```

`K_env_mac` is the `K_env_mac` derived in §2.1 (vector `hkdf-baseline`); the
canonical envelope bytes are the UTF-8 output from §3.1 (vector
`envelope-canonical-minimal`). The base64 encoding of the resulting MAC is
stored in `seal.session_mac`.

**Bytes:** see [`vectors/v1.0.0/session-mac.json`](vectors/v1.0.0/session-mac.json),
entry `id: session-mac-minimal-envelope`. The JSON carries the key under
`inputs.key_hex`, the canonical message under `inputs.message_canonical_utf8`,
and the expected MAC under `expected.mac_hex` / `expected.mac_b64`.

**Verification:** Given the same key and the same canonical bytes, two
implementations MUST produce the HMAC-SHA-256 output shown. Any difference
indicates incorrect canonicalization, incorrect key usage, or an HMAC
implementation bug.

---

## 7. Discovery Response Validation

Reference: `DISCOVERY.md` §4.3, §4.6, §8.1.

These vectors verify that implementations correctly parse and validate
discovery responses.

### 7.1 Vector: Well-Formed Discovery Response

A SEMP_DISCOVERY response carries a list of per-address results; each result
status (`semp`, `legacy`, `not_found`) drives a different sender action. Every
result is cached for its individual `ttl`. The response signature MUST be
verified against the responding server's published domain key BEFORE any
result is acted on or cached. Unknown fields in the response or in per-result
objects MUST be ignored, not rejected.

**Bytes:** see [`vectors/v1.0.0/discovery.json`](vectors/v1.0.0/discovery.json),
entry `id: discovery-response-parsing`. The JSON carries the full response
under `inputs.response_json` and the per-address expected actions under
`expected.per_address_actions`.

### 7.2 Vector: DNS TXT Capability Record Parsing

A SEMP TXT capability record advertises protocol version and optional
capability hints under semicolon-separated `key=value` pairs. Known keys:
`v` (version, required), `pq` (post-quantum readiness), `c` (transport ids),
`f` (optional features). Unknown keys MUST be ignored, not treated as an
error.

**Bytes:** see [`vectors/v1.0.0/discovery.json`](vectors/v1.0.0/discovery.json),
entry `id: discovery-txt-parsing`.

---

## 8. Rejection Reason Code Validation

Reference: `HANDSHAKE.md` §4.1, `ENVELOPE.md` §9.3.

These vectors verify that implementations correctly categorize rejection
reason codes as recoverable or non-recoverable.

### 8.1 Handshake Rejection Codes

Twelve codes carried in a SEMP_HANDSHAKE rejection. Each is classified as
recoverable or not, and each prescribes an expected sender behavior.

**Bytes:** see [`vectors/v1.0.0/rejection-codes.json`](vectors/v1.0.0/rejection-codes.json),
entry `id: handshake-rejection-codes`.

### 8.2 Envelope Rejection Codes

Twelve codes carried in a per-recipient `SubmissionResult`. Each is classified
as recoverable or not, with a prescribed sender behavior.

**Bytes:** see [`vectors/v1.0.0/rejection-codes.json`](vectors/v1.0.0/rejection-codes.json),
entry `id: envelope-rejection-codes`.

---

## 9. Session Lifecycle Validation

Reference: `SESSION.md` §2.3, §2.4, §2.5, §3.

These vectors verify correct session state transitions.

### 9.1 Vector: Session State Transitions

The authoritative state machine: each transition is a (from_state, event) ->
(to_state, actions) tuple. Implementations MUST drive their session state
through these and only these transitions.

**Bytes:** see [`vectors/v1.0.0/session-lifecycle.json`](vectors/v1.0.0/session-lifecycle.json),
entry `id: session-state-transitions` (samples table of seven transitions).

### 9.2 Vector: Concurrent Session Limits

Behavior when a new handshake arrives while one or more sessions are already
active for the same identity, or when the server reaches its concurrent-session
ceiling.

**Bytes:** see [`vectors/v1.0.0/session-lifecycle.json`](vectors/v1.0.0/session-lifecycle.json),
entry `id: concurrent-session-limits`.

### 9.3 Vector: Rekey Limits

Per-session rekey constraints: minimum elapsed time, maximum count per
session, and post-expiry handling.

**Bytes:** see [`vectors/v1.0.0/session-lifecycle.json`](vectors/v1.0.0/session-lifecycle.json),
entry `id: rekey-limits`.

---

## 10. Delivery Acknowledgment Mapping

Reference: `DELIVERY.md` §1.4, `CLIENT.md` §7.1.

These vectors verify that implementations correctly map server acknowledgments
to user-facing delivery states.

### 10.1 Vector: Acknowledgment to UI State

Maps the server acknowledgment status carried in a submission response to
the client UI state and any additional behavior the client MUST drive.

**Bytes:** see [`vectors/v1.0.0/delivery-status.json`](vectors/v1.0.0/delivery-status.json),
entry `id: acknowledgment-to-ui-state`.

### 10.2 Vector: Queued → Final State Transitions

After a queued submission, the asynchronous delivery event drives the final
UI state. A client MUST NOT display a confirmed delivery indicator for a
queued envelope until a delivered event is received.

**Bytes:** see [`vectors/v1.0.0/delivery-status.json`](vectors/v1.0.0/delivery-status.json),
entry `id: queued-to-final-transitions`.

---

## 11. Submission Status Mapping

Reference: `DISCOVERY.md` §7.1, `CLIENT.md` §6.3.

### 11.1 Vector: Discovery Outcome to Submission Status

Maps the per-recipient discovery outcome to the submission status returned to
the client and the client action that follows.

**Bytes:** see [`vectors/v1.0.0/delivery-status.json`](vectors/v1.0.0/delivery-status.json),
entry `id: discovery-outcome-to-submission-status`.

### 11.2 Vector: Multi-Recipient Mixed Outcomes

An envelope addressed to three recipients with different discovery outcomes.
The server returns per-recipient results in the submission response. The
client surfaces each recipient's status individually and MUST NOT suppress or
aggregate partial failure. `legacy_required` for any recipient MUST await
user confirmation before SMTP fallback.

**Bytes:** see [`vectors/v1.0.0/delivery-status.json`](vectors/v1.0.0/delivery-status.json),
entry `id: multi-recipient-mixed-outcomes`.

---

## 12. Key Revocation Handling

Reference: `KEY.md` §8.

### 12.1 Vector: Revoked Key Response

A SEMP_KEYS response carrying a `revocation` block. The sender MUST NOT use
the revoked key; SHOULD fetch and use the replacement when present; MUST
invalidate any locally cached copy of the revoked key; and MUST treat the
recipient as undeliverable when no replacement is supplied.

**Bytes:** see [`vectors/v1.0.0/key-revocation.json`](vectors/v1.0.0/key-revocation.json),
entry `id: revoked-key-response`. The JSON carries the example revoked-key
record under `inputs.revoked_key_record` and the conditional behavior rules
under `expected.rules`.

---

## 13. Extension Entry Validation

Reference: `EXTENSIONS.md` §2, §3, §4.

These vectors verify correct parsing and enforcement of extension entries,
criticality signaling, and size limits.

### 13.1 Vector: Extension Entry Structure

An optional extension whose key is unknown to the receiver MUST be silently
ignored; envelope processing continues.

**Bytes:** see [`vectors/v1.0.0/extension-entries.json`](vectors/v1.0.0/extension-entries.json),
entry `id: extension-optional-unknown`.

### 13.2 Vector: Required Extension, Known

A required extension whose key the receiver supports is parsed and processed.
A required extension whose key the receiver does NOT support causes rejection
with reason code `extension_unsupported`; the rejection MUST include the
offending key so the sender can identify which extension caused the failure.

**Bytes:** see [`vectors/v1.0.0/extension-entries.json`](vectors/v1.0.0/extension-entries.json),
entries `id: extension-required-known-supported` and
`id: extension-required-known-unsupported`.

### 13.3 Vector: Required Extension, Unknown

A required extension with a vendor key the receiver does not recognize is
rejected with `extension_unsupported`.

**Bytes:** see [`vectors/v1.0.0/extension-entries.json`](vectors/v1.0.0/extension-entries.json),
entry `id: extension-required-unknown`.

### 13.4 Vector: Extension Size Enforcement

Per-layer size limits on the serialized UTF-8 JSON byte length of each
`extensions` object: `postmark.extensions` and `seal.extensions` cap at 4 KB;
`brief.extensions` at 16 KB; `enclosure.extensions` at 64 KB. Size enforcement
MUST occur before signature verification to prevent resource exhaustion.

**Bytes:** see [`vectors/v1.0.0/extension-entries.json`](vectors/v1.0.0/extension-entries.json),
entry `id: extension-size-limits` (samples table covering accept and reject
cases at each layer).

### 13.5 Vector: Mixed Required and Optional Extensions

An optional supported extension does not rescue an envelope carrying an
unknown required extension; rejection is driven by the
required-and-unsupported entry.

**Bytes:** see [`vectors/v1.0.0/extension-entries.json`](vectors/v1.0.0/extension-entries.json),
entry `id: extension-mixed-required-and-optional`.

### 13.6 Vector: Extension Canonicalization

Extensions are included in the canonical form for seal computation. Extension
keys within each `extensions` object MUST be sorted lexicographically,
consistent with `ENVELOPE.md` §4.3. See §3.2 (vector
`envelope-canonical-with-extensions`) for an envelope canonicalization vector
that exercises nested extension key sorting.

---

## 14. Scoped Device Certificate Validation

Reference: `KEY.md` §10.3, `CLIENT.md` §2.3, §2.4.

These vectors verify correct validation and enforcement of scoped device
certificates.

### 14.1 Vector: Valid Scoped Certificate

A well-formed `SEMP_DEVICE_CERTIFICATE`. Five validation checks (signature
verifies against primary key, primary device authorized for account,
certificate not expired, scope well-formed, certificate registered) all
pass; the certificate is accepted.

**Bytes:** see [`vectors/v1.0.0/device-certificates.json`](vectors/v1.0.0/device-certificates.json),
entry `id: valid-device-certificate`. The JSON carries the full certificate
under `inputs.certificate_json` and the per-check expected outcomes under
`expected.checks`.

### 14.2 Vector: Certificate Validation Failures

Conditions under which a registration MUST be rejected, with the reason_code
surfaced where the spec defines one (most are `scope_invalid`).

**Bytes:** see [`vectors/v1.0.0/device-certificates.json`](vectors/v1.0.0/device-certificates.json),
entry `id: certificate-validation-failures`.

### 14.3 Vector: Scope Enforcement at Submission

Per-recipient enforcement of `scope.send` for the §14.1 certificate.
Mixed-recipient submissions reject atomically when ANY recipient is outside
scope.

**Bytes:** see [`vectors/v1.0.0/device-certificates.json`](vectors/v1.0.0/device-certificates.json),
entry `id: scope-enforcement-by-recipient`.

### 14.4 Vector: Scope Mode Enforcement

`scope.send.mode` semantics across all four modes (`unrestricted`,
`restricted`, `denylist`, `none`).

**Bytes:** see [`vectors/v1.0.0/device-certificates.json`](vectors/v1.0.0/device-certificates.json),
entry `id: scope-mode-enforcement`.

### 14.4.1 Vector: Receive Matcher Enforcement

`scope.receive` enforcement. Multiple devices on the same account can have
independent matchers; an inbound envelope is delivered to each device whose
matcher accepts the sender.

**Bytes:** see [`vectors/v1.0.0/device-certificates.json`](vectors/v1.0.0/device-certificates.json),
entry `id: receive-matcher-enforcement`.

### 14.4.2 Vector: Rate Limit Enforcement

`scope.send.rate_limits` and `scope.blocklist.rate_limits` behavior across
single-tier, two-tier, and empty-cap configurations. Counters MUST NOT
record rejected attempts.

**Bytes:** see [`vectors/v1.0.0/device-certificates.json`](vectors/v1.0.0/device-certificates.json),
entry `id: rate-limit-enforcement`.

### 14.4.3 Vector: Resource Read/Write Enforcement

Operations on managed resources (blocklist, keys, devices) are gated by
per-resource read/write flags in the scope. Nested delegation (a delegated
device issuing another delegated certificate) is forbidden.

**Bytes:** see [`vectors/v1.0.0/device-certificates.json`](vectors/v1.0.0/device-certificates.json),
entry `id: resource-read-write-enforcement`.

### 14.5 Vector: Certificate Lifecycle Operations

Effect of certificate lifecycle operations (scope update, key rotation,
revocation, expiry) on existing delegated sessions.

**Bytes:** see [`vectors/v1.0.0/device-certificates.json`](vectors/v1.0.0/device-certificates.json),
entry `id: certificate-lifecycle-operations`.

### 14.6 Vector: Staged Delivery

Multi-stage delivery with at least one filter device (stage 1) and a primary
device (stage 2). The filter emits `delivery-disposition` envelopes that
drive whether the original envelope advances to stage 2.

**Bytes:** see [`vectors/v1.0.0/device-certificates.json`](vectors/v1.0.0/device-certificates.json),
entry `id: staged-delivery`. The JSON carries the device topology under
`inputs.devices`, an example delivery-disposition envelope under
`inputs.disposition_envelope_example`, the per-step server actions under
`expected.single_filter_steps`, three-filter aggregation outcomes under
`expected.three_filter_aggregation`, and the disposition-verification rules
under `expected.disposition_verification`.

---

## 15. Recipient Status Validation

Reference: `DELIVERY.md` §1.6.

These vectors verify correct inclusion and omission of recipient status in
delivery acknowledgments.

### 15.1 Vector: Status Visibility Rules

When the sender does NOT match the recipient's visibility configuration, the
acknowledgment MUST omit the `recipient_status` field entirely. Omission MUST
be indistinguishable from a recipient who has not configured status at all.

**Bytes:** see [`vectors/v1.0.0/recipient-status.json`](vectors/v1.0.0/recipient-status.json),
entry `id: status-visibility-rules` (eight visibility-mode + sender-identity
samples).

### 15.2 Vector: Status Does Not Affect Delivery

Status MUST NOT influence the delivery decision. An invalid envelope is
rejected regardless of recipient status; a valid envelope is delivered
regardless of recipient status.

**Bytes:** see [`vectors/v1.0.0/recipient-status.json`](vectors/v1.0.0/recipient-status.json),
entry `id: status-does-not-affect-delivery`.

---

## 16. Implementation Notes

### 16.1 Generating Authoritative Vectors

The byte values in [`vectors/v1.0.0/`](vectors/v1.0.0/) are produced by
[`vectors/generators/generate.py`](vectors/generators/generate.py), a
standalone Python script with no dependencies beyond the standard library
(`hmac`, `hashlib`, `json`, `base64`). The generator is the authoritative
source for those values; reference implementations (including
`semp.dev/semp-go`) consume the JSON, they do not produce it.

Run modes:

```sh
python3 vectors/generators/generate.py            # write JSON files
python3 vectors/generators/generate.py --verify   # exit non-zero on diff
python3 vectors/generators/generate.py --diff     # show diffs without writing
```

CI for any SEMP implementation SHOULD invoke `--verify` on every commit so
drift between the prose, the generator, and the JSON is caught immediately.

### 16.2 Canonicalization Testing Strategy

Envelope canonicalization is the most common source of interoperability
failures. Implementers SHOULD:

1. Start with the minimal envelope vector (§3.1).
2. Verify byte-for-byte identical output.
3. Progress to the extensions vector (§3.2) to confirm nested key sorting.
4. Generate additional test envelopes with edge cases: Unicode domain names,
   long base64 values, deeply nested extensions, and empty string values.

### 16.3 Coverage Gaps

The following mechanisms are specified in normative documents but do not
yet have dedicated vectors in this file. Implementers extending the
vector set SHOULD contribute vectors for these areas. Listed in rough
priority order:

- **Sender identity signature on enclosure** (`ENVELOPE.md` §6.5):
  canonical-form computation of the enclosure bytes for signing, a
  valid signature case, and failure cases (modified body, modified
  subject, wrong identity key).
- **Forwarding primitive** (`ENVELOPE.md` §6.6): verified three-step
  chain of original sender signature, forwarder attestation, outer
  sender signature, plus a nested forward-of-a-forward case and
  failure modes.
- **Queuing, retry, and cancellation** (`DELIVERY.md` §2,
  `CLIENT.md` §6.6): backoff schedule sanity, effective deadline
  computation, cancellation race with in-flight delivery, terminal
  state transitions.
- **Signed delivery receipt** (`DELIVERY.md` §1.1.1): canonical
  envelope-bytes digest, canonical receipt-bytes form with
  `signature.value` blanked, `SEMP-DELIVERY-RECEIPT:` prefix
  application, valid verification case, and failure cases (wrong
  envelope hash, wrong `key_id`, modified `accepted_at`, signature by
  non-recipient domain).
- **User policy synchronization** (`DELIVERY.md` §7): signed
  `SEMP_USER_POLICY` message with operations across multiple `kind`
  values (`semp.dev/block`, `semp.dev/accepted_sender`,
  `semp.dev/first_contact`), monotonic `policy_version` enforcement,
  atomic rejection on unknown `kind` (`policy_kind_unsupported`),
  verb+kind validity (`policy_op_invalid` for `add` on singleton
  kinds), and stale-version rejection (`policy_version_stale`).
- **Session resumption** (`HANDSHAKE.md` §2.8): ticket round-trip,
  resumption key derivation mixing `K_resumption` with fresh DH, and
  `resumption_failed` fallback cases.
- **First-contact enforcement** (`DELIVERY.md` §6.4,
  `HANDSHAKE.md` §2.2a.3): token binding to
  (sender_domain, recipient_address, postmark_id), per-envelope
  single-use enforcement, rejection of cross-envelope token reuse,
  and indistinguishable rejection for non-existent addresses.
- **Configuration versioning** (`DISCOVERY.md` §3.5): revision
  monotonicity enforcement, STH signature on `SEMP_CONFIGURATION_UPDATE`,
  handshake revision mismatch handling.
- **Clock tolerance** (`CONFORMANCE.md` §9.3.1): tiered
  future-dated and expires-at boundary cases covering 0, 5, 15, and
  30 minutes of skew.
- **Account recovery** (`RECOVERY.md`): bundle encryption and
  decryption round-trip, KDF output determinism given fixed inputs,
  Shamir share reconstruction from M of N.
- **Provider migration** (`MIGRATION.md`): migration record signature
  chain verification (cooperative vs unilateral), local-part
  reassignment rules, and key-bound carry-over semantics.
- **Account closure** (`CLOSURE.md`): closure request authentication,
  finalization effects, ingress response indistinguishability during
  retention window.
- **Key transparency** (`TRANSPARENCY.md`): Merkle tree leaf hashing,
  inclusion proof verification, consistency proof verification,
  equivocation observation structure.
- **Large attachment extension** (`ATTACHMENTS.md`): HKDF derivation
  of `K_attachment` from `K_enclosure`, AEAD with bound
  additional-data, ciphertext hash verification.

These gaps do not block implementation; each mechanism's normative
document defines its behavior exhaustively. Vectors accelerate
implementer testing but are not a substitute for the normative text.

### 16.4 Test Vector Limitations

These vectors test deterministic operations only. The following operations
require round-trip testing between two independent implementations rather
than static vectors:

- Envelope encryption and decryption (depends on random `K_brief`,
  `K_enclosure`).
- Handshake key exchange (depends on random ephemeral keys).
- Ed25519 / Kyber768 / X25519 key generation.
- Nonce generation.

For these operations, two implementations demonstrate interoperability by
successfully completing a handshake and exchanging an envelope, not by
producing identical intermediate values.

---

## 17. Round-Trip Vectors

Sections 2 through 15 cover deterministic operations: given fixed inputs, an
implementation produces a single fixed output, and conformance is byte
equality. Sections 17 and onward cover **round-trip** operations: encryption
and signing flows whose outputs in production depend on random inputs
(ephemeral keys, nonces, fresh symmetric keys). To make these flows
testable as vectors, the random inputs are pinned as part of the vector
itself, and the implementation MUST expose a "deterministic" code path
that accepts those inputs instead of generating them.

The deterministic code path is test-only. Production senders MUST NOT
accept caller-controlled key material; doing so trivially breaks
confidentiality. Conformant implementations conventionally gate the
deterministic path behind a build tag, feature flag, internal API, or
similar mechanism that is unreachable from production code paths.

### 17.1 Seal Wrap (Baseline Suite)

Reference: `ENVELOPE.md` §4.4.1.

The seal wrap operation encrypts a per-envelope symmetric key (`K_brief` or
`K_enclosure`) under each recipient's public encryption key, producing one
entry in `seal.brief_recipients` or `seal.enclosure_recipients`. The
construction is HPKE-Base shaped: ephemeral key agreement, HKDF-SHA-512 key
derivation with a recipient-binding salt, and ChaCha20-Poly1305 sealing
with the recipient public key as AEAD AAD.

Vectors pin the recipient key pair, the ephemeral private key, and the
symmetric key. Implementations match by reproducing the wrapped output
byte-for-byte, then by recovering the symmetric key on unwrap.

**Baseline suite vectors:** `id: seal-wrap-baseline-32B-key`,
`id: seal-wrap-baseline-distinct-recipient`,
`id: seal-wrap-baseline-ephemeral-changes-output`. The third confirms that
changing only the ephemeral private key produces a different wrapped output
while round-trip still recovers `K`, isolating the ephemeral as the source
of nonce-uniqueness.

**Post-quantum suite vectors:** `id: seal-wrap-pq-32B-key`,
`id: seal-wrap-pq-distinct-recipient`. The recipient public key is the
1216-byte concatenation `kyber_ek (1184 B) || x25519_pub (32 B)`; the
recipient private key is `kyber_dk (2400 B) || x25519_priv (32 B)`. The
wrap output is 1168 bytes (1088 Kyber ciphertext + 32 X25519 ephemeral
public + 48 AEAD ciphertext+tag). Both the X25519 ephemeral private key
and the ML-KEM-768 encaps randomness `m` are pinned in the inputs so the
wrapped output is byte-deterministic; implementations MUST use the
FIPS 203 internal-encaps API (or equivalent) that accepts the
randomness explicitly.

**Bytes:** see [`vectors/v1.0.0/seal-roundtrip.json`](vectors/v1.0.0/seal-roundtrip.json).
Each vector lists its `intermediates` (Kyber ciphertext and shared secret
for PQ cases, plus the X25519 shared secret, combined shared secret, salt,
PRK, wrap key, and AEAD inputs) so implementers can localise mismatches
to a specific step of the construction.

### 17.2 Sender Signature

Reference: `ENVELOPE.md` §6.5.

`enclosure.sender_signature` is an Ed25519 signature produced by the sending
user's published identity key over the canonical bytes of the enclosure.
It binds the enclosure plaintext to the sender's identity independently of
`seal.signature` (which binds ciphertext at the sender's domain) and is the
foundation of forward provenance per §6.6.

Construction: blank `enclosure.sender_signature.value` to `""`, canonicalize
the enclosure per §4.3 (sorted keys, no whitespace, UTF-8), prefix the
result with the literal UTF-8 bytes `SEMP-ENCLOSURE-SENDER:`, sign with the
identity private key, base64-encode the signature, and place it back in
`sender_signature.value`. Verification reverses the construction and uses
the sender's published identity key indicated by `sender_signature.key_id`
(a lowercase hex SHA-256 fingerprint per `KEY.md` §4.4).

Three vectors:

- `sender-signature-valid`: pinned identity key signs a pinned enclosure;
  verification with the matching public key MUST succeed.
- `sender-signature-tampered-body`: the previous case's signed enclosure
  with one byte of the body altered. The reconstructed canonical bytes
  differ from what was signed; verification MUST reject.
- `sender-signature-wrong-key`: an enclosure whose `sender_signature.key_id`
  points at identity A but was actually signed by identity B's private
  key. Verification against A's public key MUST reject; the JSON also
  records that verification against B's public key succeeds, isolating
  the failure to the key-mismatch path rather than a corruption issue.

A receiving client that observes a verification failure MUST NOT render
the enclosure content as authored by the claimed sender (`ENVELOPE.md`
§6.5.3).

**Bytes:** see [`vectors/v1.0.0/sender-signature.json`](vectors/v1.0.0/sender-signature.json).
Each vector also lists `intermediates` (the canonical enclosure bytes with
the signature blanked, the prefixed signing input, and the raw signature
bytes) so an implementer who fails byte equality can localise the
divergence to a specific construction step.

### 17.3 Forwarded Envelope (Three-Signature Chain)

Reference: `ENVELOPE.md` §6.6.

A forwarded envelope carries three Ed25519 signatures: the outer enclosure
sender_signature (forwarder), the forwarder_attestation inside the
forwarded_from block (forwarder, with prefix `SEMP-FORWARDER-ATTESTATION:`),
and the preserved original_enclosure_plaintext.sender_signature (original
author). A new recipient performs the §6.6.4 three-step verification chain:
forwarder identity, forwarding act, original author. Any step failing
prevents the recipient from rendering the original content as attributed
to the claimed original sender.

The forwarder_attestation construction is structurally identical to the
sender_signature in §6.5: blank the relevant `.value`, canonicalize the
enclosing object per §4.3, prefix with the context-specific domain
separator, sign Ed25519, base64-encode, and replace the value.

Three vectors:

- `forward-valid-three-step-chain`: B forwards A's signed enclosure to C.
  All three steps verify. The vector pins both identity seeds, all
  intermediate canonical bytes, and the final signed outer enclosure.
- `forward-tampered-original-content`: take the valid output and alter one
  byte of `forwarded_from.original_enclosure_plaintext.body`. The recorded
  step results show that this tampering invalidates multiple signatures
  (the outer canonicalization covers the forwarded_from contents, so the
  outer sender_signature also fails alongside the original author's).
- `forward-spoofed-outer-signer`: outer enclosure has
  `sender_signature.key_id == forwarder_attestation.key_id == fp_B`,
  satisfying the syntactic cross-check from §6.6.3, but the outer
  signature was actually produced by identity A. Verification against B's
  public key fails. Demonstrates that the cross-check on key_ids does not
  substitute for the cryptographic verification.

**Bytes:** see [`vectors/v1.0.0/forwarding.json`](vectors/v1.0.0/forwarding.json).

### 17.4 Envelope Round-Trip (Baseline Suite)

Reference: `ENVELOPE.md` §7.1, §7.1.1, §7.2.

This vector covers the full encryption flow end-to-end: brief and enclosure
canonicalization, ChaCha20-Poly1305 sealing under fresh symmetric keys
with `postmark.id` as AEAD AAD, seal wrapping for both the recipient
client and the recipient server's domain key, the outer canonical
envelope bytes, the domain-key Ed25519 signature with the
`SEMP-ENVELOPE:` prefix, and the HMAC-SHA-256 session MAC under
`K_env_mac`.

The vector pins every random input: identity and domain key seeds, the
recipient client and recipient server domain keys, the symmetric
`K_brief` / `K_enclosure`, the AEAD nonces, and the three ephemeral X25519
private keys used for seal wraps (one per wrapped recipient entry).
Generation runs all seven §7.2 verification steps as `assert`s, so a
generator bug crashes before any JSON is written:

1. `seal.signature` verifies against the sender domain public key.
2. `seal.session_mac` verifies under `K_env_mac`.
3. The recipient server unwraps `K_brief` from its domain entry.
4. The server decrypts `envelope.brief` and recovers the brief JSON.
5. The recipient client unwraps `K_brief` from its client entry.
6. The client unwraps `K_enclosure` from its client entry.
7. The client decrypts `envelope.enclosure` and verifies
   `enclosure.sender_signature` against the sender's identity key.

Padding (`envelope.padding`) and recipient-count obfuscation (§4.4.2) are
omitted from this vector to keep the byte trace minimal; both layers are
covered by their own §3.3 / §3.4 vectors and compose with this vector
deterministically when applied.

**Two vectors, one per suite:**

- `envelope-roundtrip-baseline-single-recipient`: the baseline
  (`x25519-chacha20-poly1305`) flow described above. Seal wraps use
  X25519 ephemeral key agreement; brief/enclosure AEAD is ChaCha20-Poly1305
  with `postmark.id` as AAD.
- `envelope-roundtrip-pq-single-recipient`: identical compose flow under
  the post-quantum suite (`pq-kyber768-x25519`). Seal wraps use the
  Kyber768+X25519 hybrid KEM per §4.4.1's PQ branch; brief/enclosure AEAD
  is still ChaCha20-Poly1305 (per the §7.3 suite table). Recipient public
  keys are the 1216-byte concatenation `kyber_ek (1184) || x25519_pub (32)`,
  recipient private keys are the 2432-byte concatenation
  `kyber_dk (2400) || x25519_priv (32)`. The Kyber encaps randomness `m` is
  pinned alongside the X25519 ephemeral private keys so each of the three
  wrapped seal entries is byte-deterministic.

**Bytes:** see [`vectors/v1.0.0/envelope-roundtrip.json`](vectors/v1.0.0/envelope-roundtrip.json).
Each vector's `intermediates` block records the canonical brief, canonical
enclosure, canonical envelope-for-signature bytes, the seal-signature
hex, and the session-MAC hex so an implementer who fails byte equality
can drill into the specific construction step that diverged.

### 17.5 Signed Delivery Receipt

Reference: `DELIVERY.md` §1.1.1.

A signed delivery receipt is a portable artifact the recipient server
returns alongside every `delivered` acknowledgment. It binds three values
under the recipient domain's Ed25519 signing key with the
`SEMP-DELIVERY-RECEIPT:` prefix:

- `envelope_hash.value` — SHA-256 of the canonical envelope bytes per
  §4.3 (the same canonical form `seal.signature` covers).
- `recipient_domain` — the recipient server's domain.
- `accepted_at` — ISO 8601 UTC timestamp at second precision.

Construction parallels §6.5 sender_signature: blank `signature.value`,
canonicalize per §4.3, prefix with `SEMP-DELIVERY-RECEIPT:`, sign Ed25519,
base64-encode, and replace the value.

Three vectors:

- `delivery-receipt-valid`: pinned domain key signs a receipt over a
  pinned reference envelope. The intermediates include the canonical
  envelope-for-hash bytes, the SHA-256 digest, and the canonical receipt
  with the signature blanked. Both the §1.1.1.7 signature verification
  (step 3) and the envelope_hash recomputation (step 4) succeed.
- `delivery-receipt-tampered-envelope`: receipt is genuine but the
  inspected envelope differs from the one the receipt was issued for.
  The signature still verifies (the receipt body is intact), but the
  recomputed SHA-256 of the tampered envelope's canonical bytes does
  NOT match `envelope_hash.value`. The receipt MUST NOT be accepted
  as proof for this envelope.
- `delivery-receipt-tampered-body`: take the valid receipt and change
  `accepted_at` by one second. Ed25519 verify rejects, isolating the
  failure to receipt-body tampering rather than envelope tampering.

**Bytes:** see [`vectors/v1.0.0/delivery-receipt.json`](vectors/v1.0.0/delivery-receipt.json).

### 17.6 Large Attachment AEAD

Reference: `ATTACHMENTS.md` §3.

Each external attachment is encrypted under a per-item key derived from
`K_enclosure`:

```
K_attachment = HKDF-Expand(PRK = K_enclosure,
                            info = "semp-attachment:" || item.id,
                            L    = 32)
```

The AEAD plaintext is the file bytes; the AEAD AAD is the canonical JSON
of the item with `ciphertext_hash`, `aead_nonce`, and `extensions`
blanked. This binds the item's metadata (filename, mime_type,
plaintext_size, url, aead_algorithm, id) into the Poly1305 tag so that
swapping any field after upload invalidates the ciphertext.

The bytes stored at `item.url` are the raw AEAD ciphertext (ciphertext
concatenated with the 16-byte authentication tag), with no framing.
`item.ciphertext_hash` is `"sha256:" || hex(SHA-256(aead_ct))`, providing
an integrity check that a downloader applies before invoking AEAD.Open.

Three vectors:

- `large-attachment-baseline-valid`: round-trip encrypt + decrypt of a
  64-byte plaintext under the baseline ChaCha20-Poly1305 AEAD. Both
  the ciphertext_hash check and the AEAD tag verify.
- `large-attachment-tampered-metadata`: take the valid output and change
  `item.filename`. The recomputed AEAD AAD differs from the AAD used at
  encryption time and the Poly1305 tag fails. Demonstrates the §3.2
  metadata binding.
- `large-attachment-tampered-ciphertext`: flip one bit of the ciphertext
  at `item.url`. Two independent integrity layers reject: SHA-256
  (`ciphertext_hash` mismatch, surfaced before decryption) and the
  Poly1305 tag on AEAD.Open. A receiver SHOULD short-circuit on the hash
  check to avoid feeding adversarial input to the AEAD.

A fourth vector covers the post-quantum suite:

- `large-attachment-pq-valid`: same construction shape (per-item key
  derivation, metadata-bound AAD, SHA-256 integrity), but with
  XChaCha20-Poly1305 and a 24-byte nonce per §3.2.

**Bytes:** see [`vectors/v1.0.0/large-attachment.json`](vectors/v1.0.0/large-attachment.json).

### 17.7 Negative Envelope Rejection

Reference: `ENVELOPE.md` §7.2; `ERRORS.md`.

Three concrete must-reject cases that exercise the §7.2 decryption flow's
rejection paths. Each vector targets exactly one §7.2 step so that a failed
implementation can pinpoint which check is broken without confounding
errors elsewhere in the structure.

- `envelope-expired`: postmark.expires is in the past. Step 1 (seal
  signature) passes; step 2 MUST reject with reason_code
  `envelope_expired`.
- `seal-signature-invalid`: seal.signature is replaced with a well-formed
  Ed25519 signature over different bytes. Step 1 MUST reject with
  reason_code `seal_invalid`. Routing servers perform this check.
- `session-mac-invalid`: seal.session_mac is forged under a different HMAC
  key. Step 1 still passes because §4.3 canonicalization blanks both
  signature and session_mac before signing; step 4 MUST reject with
  reason_code `session_mac_invalid`. Recipient servers perform this check;
  routing servers cannot (they do not hold K_env_mac).

Together with the tampered cases inside `sender-signature.json`,
`forwarding.json`, `delivery-receipt.json`, and `large-attachment.json`,
this file covers every must-reject path exercised by the Layer 3
construction vectors.

**Bytes:** see [`vectors/v1.0.0/negative-envelope-rejection.json`](vectors/v1.0.0/negative-envelope-rejection.json).

### 17.8 Handshake Messages (Layer 4)

Reference: `HANDSHAKE.md` §2.

Five vectors cover the four-message handshake plus a rejection. The
construction is identical for every signed handshake message: blank the
relevant signature field, canonicalize per §4.3 (sorted keys, no
whitespace, UTF-8), prefix with `SEMP-HANDSHAKE:` per §4.3's
domain-separation table, sign Ed25519, base64-encode, replace the field.

- `handshake-init-canonical`: ClientInit. The init message is anonymous
  by design and NOT outer-signed (§2.2). Pinned for the canonical bytes
  used as input to the §5.1 confirmation_hash.
- `handshake-response-signed`: ServerResponse. Outer `server_signature`
  uses the construction above. The inner `server_identity_proof.signature`
  (over server_ephemeral_key || nonces) is left as a pinned placeholder
  in this vector; its construction will be exercised separately by future
  identity-proof vectors.
- `handshake-confirm-canonical`: ClientConfirm. No outer signature; the
  inner `identity_proof` is encrypted under `K_enc_c2s` and is treated
  as opaque ciphertext at the outer level. The `confirmation_hash` field
  matches the §5.1 vector exactly, demonstrating cross-vector
  consistency.
- `handshake-accepted-signed`: ServerAccepted carrying session_ttl,
  permissions, and a resumption_ticket. Same construction as response.
- `handshake-rejected-signed`: ServerRejected carrying reason_code and
  human-readable reason. Same construction as accepted.

**Bytes:** see [`vectors/v1.0.0/handshake-messages.json`](vectors/v1.0.0/handshake-messages.json).
Each signed vector lists its `intermediates` (canonical bytes with the
signature blanked, prefixed signing input hex, raw signature hex) so a
failed implementation can drill into the specific construction step
that diverged.

PQ-suite handshakes use the same construction; the only differences
are the advertised algorithm strings in the message bodies and the
sizes of the `client_ephemeral_key.key` / `server_ephemeral_key.key`
fields. PQ handshake message vectors land in a follow-up.

### 17.9 Signed Documents (Closure, User Policy, Migration)

Three signed-document categories share the same Ed25519 + canonical-bytes
+ domain-separation construction but use different prefixes per
`ENVELOPE.md` §4.3:

- `account-closure.json` — `SEMP-ACCOUNT-CLOSURE:` over a closure
  request signed by a full-access device key. Reference:
  `CLOSURE.md` §2.
- `user-policy.json` — `SEMP-USER-POLICY:` over a `SEMP_USER_POLICY`
  update carrying multiple operations across distinct kinds, signed
  by the originating device. Reference: `DELIVERY.md` §7.
- `migration.json` — `SEMP-MIGRATION-RECORD:` over a four-signature
  migration record. Cooperative migrations carry signatures in the
  §3.3 order: old_identity, new_identity, new_domain, old_domain.
  Each signature is computed over the canonical record with all
  prior signatures at their final values and the signing
  signature's value blanked. The vector asserts every signature in
  the chain at generation time. Reference: `MIGRATION.md` §3.

**Bytes:** see [`vectors/v1.0.0/account-closure.json`](vectors/v1.0.0/account-closure.json),
[`vectors/v1.0.0/user-policy.json`](vectors/v1.0.0/user-policy.json),
[`vectors/v1.0.0/migration.json`](vectors/v1.0.0/migration.json).

### 17.10 Discovery Signing and Key Transparency (Layer 5)

References: `DISCOVERY.md` §7; `TRANSPARENCY.md` §2-§3; RFC 6962.

Two related vector files cover the §4.3 prefixes that Layer 5 introduces.

**`discovery-signed.json`** — `SEMP-DISCOVERY:` over a SEMP_DISCOVERY
response. Companion to `discovery.json`'s structural-parsing vectors;
this one covers the signature path. Verifiers MUST check the response
signature before caching or acting on per-address results.

**`transparency.json`** — `SEMP-TRANSPARENCY-STH:` over a Signed Tree
Head per `TRANSPARENCY.md` §2.3, plus an RFC 6962 inclusion proof.

- `transparency-sth-signed`: domain key signs an STH over a small
  Merkle tree (8 leaves with deterministic payloads). The pinned
  inputs include the leaf payloads so any implementation can
  reproduce the leaf hashes and root.
- `transparency-inclusion-proof`: an inclusion proof for leaf 4 of
  the same tree. The vector pins both the valid path and a
  one-bit-flipped variant; verification rejects the latter,
  demonstrating the proof's integrity.

- `transparency-consistency-proof`: RFC 6962 §2.1.2 consistency proof
  from an earlier 5-leaf tree to the current 8-leaf tree. Holding two
  STHs and the proof, the verifier recomputes both roots and confirms
  they match. Tampering one bit of the proof rejects, demonstrating
  the append-only-log property.

The Merkle hash construction follows RFC 6962:
`leaf_hash = SHA-256(0x00 || leaf_data)` and
`internal_hash = SHA-256(0x01 || left || right)`. The §4 augmented
key-fetch path is TODO.

**Bytes:** see [`vectors/v1.0.0/discovery-signed.json`](vectors/v1.0.0/discovery-signed.json),
[`vectors/v1.0.0/transparency.json`](vectors/v1.0.0/transparency.json).

### 17.11 Session Resumption

Reference: `HANDSHAKE.md` §2.8.

Three vectors covering the resume exchange and the §2.8.3 key derivation.

- `resume-request-canonical`: ClientResume request canonical bytes. The
  outer message is unsigned; the resumption_ticket alone authenticates
  the holder, and the fresh ephemeral DH provides forward secrecy.
- `resume-accepted-signed`: ServerResume accepted with a fresh
  session_id, server_ephemeral_key, and replacement resumption_ticket.
  Signed under `SEMP-HANDSHAKE:` like other server-signed handshake
  messages.
- `resume-key-derivation`: HKDF derivation that mixes the ephemeral
  shared secret with K_resumption from the ticket per §2.8.3. The salt
  and per-key info labels match the initial-handshake schedule (§2.1);
  the only change is the IKM construction.

**Bytes:** see [`vectors/v1.0.0/session-resumption.json`](vectors/v1.0.0/session-resumption.json).

### 17.12 First-Contact Token and Clock Tolerance

References: `HANDSHAKE.md` §2.2a.4; `CONFORMANCE.md` §9.3.1.

`first-contact-token.json` covers the postmark-binding semantics that
prevent first-contact PoW tokens from being replayed across envelopes.

- `first-contact-token-valid`: token presented inside an envelope whose
  postmark.id matches the token's bound `postmark_id`. Both the
  difficulty check (`H(prefix || nonce)` has at least
  `token.difficulty` leading zero bits) and the binding check
  (`token.postmark_id == envelope.postmark.id`) succeed.
- `first-contact-token-replay-rejected`: same valid token presented
  inside a different envelope. PoW still passes; binding fails;
  recipient server MUST reject with `policy_forbidden`.

`clock-tolerance.json` enumerates the §9.3.1 boundary samples for
future-dated and `expires_at` fields. Boundaries: 0, 5 minutes, 10
minutes, 15 minutes. The expected verdicts use three labels — `accept`,
`reject`, `accept_or_reject_at_implementor_choice` — to capture cases
where the spec uses MUST vs SHOULD vs MAY differently.

**Bytes:** see [`vectors/v1.0.0/first-contact-token.json`](vectors/v1.0.0/first-contact-token.json),
[`vectors/v1.0.0/clock-tolerance.json`](vectors/v1.0.0/clock-tolerance.json).

### 17.13 Account Recovery Bundle

Reference: `RECOVERY.md` §2.

`account-recovery.json` covers the backup-bundle round-trip end to end.
Argon2id (RFC 9106, via libsodium's crypto_pwhash_argon2id13) derives
`K_bundle` from the recovery secret and the bundle's KDF parameters;
XChaCha20-Poly1305 encrypts the payload under `K_bundle`; the user's
currently active identity key signs the canonical bundle bytes with
the `SEMP-RECOVERY-BUNDLE:` prefix.

The vector pins the recovery secret, the Argon2id parameters (modest
64 MiB / 3 iterations so it regenerates quickly; production deployments
follow §2.5's RECOMMENDED 256 MiB), the payload nonce, and the
identity Ed25519 seed. Round-trip is asserted at generation time:
re-deriving `K_bundle` from the same inputs yields the same key, the
AEAD decrypts, and the bundle signature verifies.

Shamir device-split backup (§2 alternative recovery mechanism) is TODO.

**Bytes:** see [`vectors/v1.0.0/account-recovery.json`](vectors/v1.0.0/account-recovery.json).

### 17.14 Configuration Update + PQ Handshake

References: `DISCOVERY.md` §3.5.4; `HANDSHAKE.md` §2.

`configuration-update.json` covers the `SEMP_CONFIGURATION_UPDATE`
notification a server may send to active federation peers when its
configuration revision changes. Signed by the issuing domain's current
signing key with the `SEMP-CONFIGURATION-UPDATE:` prefix. The vector
pins the domain seed and the revision-18 message; verification of the
signature MUST precede any out-of-band re-fetch.

`handshake-messages-pq.json` covers the post-quantum suite variants of
the outer-signed handshake messages. The construction matches §17.8
exactly; only the message-body strings change (algorithm becomes
`pq-kyber768-x25519`; the ephemeral_key payload is the 1216-byte
hybrid `kyber_ek (1184) || x25519_pub (32)` base64-encoded). Two
vectors — response and accepted — exercise the signed messages whose
canonical bytes meaningfully change with PQ payloads. Init and confirm
differ only in body strings and are covered by their §17.8 counterparts
plus the algorithm-string change.

**Bytes:** see [`vectors/v1.0.0/configuration-update.json`](vectors/v1.0.0/configuration-update.json),
[`vectors/v1.0.0/handshake-messages-pq.json`](vectors/v1.0.0/handshake-messages-pq.json).

---

## 18. Relationship to Other Specifications

| Specification    | Relationship                                                      |
|------------------|-------------------------------------------------------------------|
| `CONFORMANCE.md` | Defines the requirements these vectors verify. Each vector section references the conformance requirement it tests. |
| `HANDSHAKE.md`   | Handshake message formats, HKDF derivation, confirmation hash, and challenge verification are tested here. |
| `SESSION.md`     | Session key derivation, lifecycle, rekeying, and concurrent session behavior are tested here. |
| `ENVELOPE.md`    | Envelope canonicalization, seal computation, and rejection codes are tested here. |
| `DISCOVERY.md`   | Discovery response parsing and outcome mapping are tested here. |
| `KEY.md`         | Key revocation handling and scoped device certificate validation are tested here. |
| `DELIVERY.md`    | Acknowledgment types, delivery state mapping, and recipient status are tested here. |
| `CLIENT.md`      | Submission status mapping, UI state requirements, scope enforcement, and message history sync constraints are tested here. |
| `EXTENSIONS.md`  | Extension entry structure, criticality signaling, and size limit enforcement are tested here. |
| `ERRORS.md`      | Rejection reason codes including `extension_unsupported`, `extension_size_exceeded`, and `scope_exceeded` are tested here. |

---

*This document is an Internet-Draft. It is subject to revision prior to
finalization as a stable specification.*