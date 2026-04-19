# SEMP Key Transparency

**Sealed Envelope Messaging Protocol**  
Status: Internet-Draft  
Version: 0.2.0-draft  
Related: `KEY.md`, `DISCOVERY.md`, `REPUTATION.md`, `CONFORMANCE.md`

---

## Abstract

This specification defines the key transparency (KT) extension for SEMP.
Each supporting domain publishes an append-only Merkle-tree log of every
user key event. Clients fetching a user's key receive an inclusion
proof and a signed tree head. Third-party monitors cross-check the log
via the existing `SEMP_OBSERVATIONS` gossip mechanism, detecting
equivocation without a separate monitor protocol. The goal is to make
a malicious or compelled home server unable to silently serve different
keys to different correspondents.

---

## 1. Overview

### 1.1 Problem Statement

Without key transparency, a user's home server is the sole authority on
that user's keys. A malicious or compelled server can publish one key
widely and a different, server-controlled key to a targeted
correspondent, intercepting traffic between them. Domain signatures and
web-of-trust cross-signatures do not prevent this because the server is
the signer and the cross-signature path is rarely complete.

Key transparency addresses this by requiring the server to append every
key event (publish, rotate, revoke) to an auditable public log, and by
giving every key fetch an inclusion proof. Third-party monitors
observing the log detect any attempt to serve different views to
different parties.

### 1.2 Goals and Non-Goals

In scope:

- An append-only Merkle-tree log per supporting domain.
- Inclusion proofs on every key fetch.
- Signed tree heads (STHs) refreshed hourly.
- Consistency proofs between log states.
- Gossip via the existing `SEMP_OBSERVATIONS` mechanism with three
  observation types (snapshot, verification, equivocation).
- Client verification obligations on key acceptance.

Not in scope:

- A mandatory monitor network. Operators and third parties MAY run
  monitors; the protocol does not define a monitor onboarding or
  election process.
- Trust of individual monitors. Clients choose which observations they
  trust based on operator policy.
- Logging of non-key events (scoped device certificates, account
  closure, migration records). v1 logs user identity and encryption
  key events only; future revisions MAY extend coverage.

### 1.3 Conformance Status

This specification is a RECOMMENDED optional core module. A SEMP
server MAY omit support. A server that claims key transparency support
MUST comply with every requirement in this document and MUST advertise
the `transparency_log` endpoint in its discovery configuration.

Clients SHOULD prefer operators that support key transparency for
accounts where targeted MITM by the home server is a concern in the
threat model.

### 1.4 Terminology

| Term                   | Definition                                                                                    |
|------------------------|-----------------------------------------------------------------------------------------------|
| Log                    | The append-only Merkle tree of key events published by a domain.                              |
| Leaf                   | One entry in the log, representing a single key event (publish, rotate, revoke).              |
| Signed Tree Head (STH) | A domain-signed snapshot of the log at a point in time: `{log_size, root_hash, timestamp, signature}`. |
| Inclusion proof        | A set of Merkle hashes proving a specific leaf is included in a tree of a specific size.      |
| Consistency proof      | A set of Merkle hashes proving that an earlier tree state is a prefix of a later tree state.  |
| Monitor                | A third party that fetches STHs and proofs from domains, verifies them, and publishes observations. |
| Equivocation           | A domain signing two STHs for the same `log_size` with different `root_hash` values.          |

---

## 2. Transparency Log

### 2.1 Structure

Each domain supporting key transparency maintains a single append-only
Merkle tree. The tree follows RFC 6962 construction: binary, complete
except at the rightmost level, SHA-256 over domain-separated leaf and
interior node encodings.

Leaves are ordered by insertion time. Once inserted, a leaf is
permanent; the domain MUST NOT remove or modify a leaf.

### 2.2 Log Entries

Each leaf is a canonical JSON encoding of a key event:

```json
{
    "event": "publish" | "rotate" | "revoke",
    "user_id": "alice@example.com",
    "key_id": "key-fingerprint",
    "key_type": "identity" | "encryption",
    "algorithm": "ed25519",
    "public_key": "base64-public-key",
    "created": "2026-04-19T10:00:00Z",
    "expires": "2027-04-19T10:00:00Z",
    "revoked_at": null,
    "revoked_reason": null,
    "supersedes": "prior-key-id-or-null",
    "log_timestamp": "2026-04-19T10:00:05Z"
}
```

| Field            | Type            | Required | Description                                                               |
|------------------|-----------------|----------|---------------------------------------------------------------------------|
| `event`          | `string`        | Yes      | One of: `publish`, `rotate`, `revoke`.                                    |
| `user_id`        | `string`        | Yes      | Full SEMP address the key belongs to.                                     |
| `key_id`         | `string`        | Yes      | Key fingerprint.                                                          |
| `key_type`       | `string`        | Yes      | `identity` or `encryption`.                                               |
| `algorithm`      | `string`        | Yes      | Algorithm identifier per `KEY.md`.                                        |
| `public_key`     | `string`        | Yes      | Base64-encoded public key.                                                |
| `created`        | `string`        | Yes      | Key creation timestamp from the key record.                               |
| `expires`        | `string\|null`  | Yes      | Key expiry timestamp, or `null` for non-expiring keys.                    |
| `revoked_at`     | `string\|null`  | Yes      | Present only on `revoke` events, matching the revocation record.          |
| `revoked_reason` | `string\|null`  | Yes      | Present only on `revoke` events, matching the revocation record's reason. |
| `supersedes`     | `string\|null`  | Yes      | `key_id` of the key being rotated out, or `null` for initial publication. |
| `log_timestamp`  | `string`        | Yes      | Server-assigned ISO 8601 UTC timestamp of log insertion.                  |

The leaf hash is `SHA-256(0x00 || canonical_json_bytes)` per RFC 6962
domain separation.

### 2.3 Signed Tree Head

The domain publishes a Signed Tree Head (STH) periodically:

```json
{
    "log_size": 12847,
    "root_hash": "base64-root-hash",
    "timestamp": "2026-04-19T12:00:00Z",
    "signature": {
        "algorithm": "ed25519",
        "key_id": "example.com-domain-signing-key-fingerprint",
        "value": "base64-signature"
    }
}
```

The `signature` covers the canonical JSON encoding of the STH object
with `signature.value` set to `""`. The signing key is the domain's
current signing key published per `KEY.md` section 2.

Domains MUST publish a fresh STH at least every hour. A stale STH
(timestamp older than 1 hour by the clock tolerance in
`CONFORMANCE.md` section 9.3.1) is unacceptable to clients and
monitors.

### 2.4 Log Endpoint

The `transparency_log` endpoint advertised in the discovery
configuration (`DISCOVERY.md` section 3.1.1) serves the log. The
endpoint is a base URL supporting the following operations as path
or query suffixes:

| Operation          | Method | Description                                                                 |
|--------------------|--------|-----------------------------------------------------------------------------|
| `GET /sth`         | GET    | Current STH.                                                                |
| `GET /sth/<timestamp>` | GET | STH that was current at the given UTC ISO 8601 timestamp, or the latest STH signed at or before it. |
| `GET /inclusion?log_size=N&leaf_hash=H` | GET | Inclusion proof for the leaf identified by `leaf_hash` in a tree of size `N`. |
| `GET /consistency?from=N1&to=N2` | GET | Consistency proof that the tree of size `N1` is a prefix of the tree of size `N2`. |
| `GET /entries?start=X&end=Y` | GET | Leaf entries in the range `[X, Y)`. Monitors use this to replay the log locally. |

Responses are JSON. The exact response schema for each operation
follows RFC 6962 conventions, encoding Merkle hashes as base64-URL
strings.

### 2.5 Retention

The log is append-only and retained indefinitely. Removing entries
would invalidate outstanding consistency proofs across the window
covering the removed entries. Operators MUST NOT remove or modify
leaves. Storage grows linearly with key events but is bounded in
practice by the number of users and keys per user, which grows
slowly.

An operator discontinuing transparency support MUST continue to serve
the existing log for at least 2 years after withdrawing the
`transparency_log` endpoint. Clients relying on historical inclusion
proofs need the log to remain resolvable.

---

## 3. Proofs

### 3.1 Inclusion Proofs

An inclusion proof for leaf `L` in a tree of size `N` is the sequence
of sibling hashes along the path from `L` to the root, per RFC 6962.
Verifiers recompute the root from `L`, the path, and the tree size;
the result MUST equal the STH's `root_hash` for size `N`.

Proof size is `O(log N)`, approximately 30 hashes for a million-entry
log. Response format:

```json
{
    "log_size": 12847,
    "leaf_hash": "base64-leaf-hash",
    "leaf_index": 4217,
    "path": [
        "base64-sibling-hash-1",
        "base64-sibling-hash-2",
        "..."
    ]
}
```

### 3.2 Consistency Proofs

A consistency proof between an earlier STH of size `N1` and a later
STH of size `N2` (where `N1 < N2`) is the sequence of hashes that
lets a verifier reconstruct the earlier root from subsets of the
later tree, per RFC 6962.

Response format:

```json
{
    "from_size": 10000,
    "to_size": 12847,
    "path": [
        "base64-hash-1",
        "base64-hash-2",
        "..."
    ]
}
```

A valid consistency proof attests that the log was not rewritten
between size `N1` and size `N2`: the earlier tree's leaves are
preserved exactly as the first `N1` leaves of the later tree.

---

## 4. Key Fetch With Transparency

### 4.1 Augmented Response Schema

When a key fetch is served from a domain supporting transparency,
the `SEMP_KEYS` response (`KEY.md` section 3.1) is augmented with an
inclusion proof and a current STH for each returned key:

```json
{
    "type": "SEMP_KEYS",
    "step": "response",
    "version": "1.0.0",
    "id": "request-id",
    "timestamp": "2026-04-19T12:00:00Z",
    "keys": [
        {
            "address": "alice@example.com",
            "key_type": "identity",
            "public_key": "base64",
            "key_id": "key-fingerprint",
            "transparency": {
                "sth": { /* signed tree head */ },
                "inclusion_proof": { /* proof of this key's event leaf */ }
            }
        }
    ],
    "signature": { /* domain signature over response */ }
}
```

The `transparency.sth` is the current STH at response time (signed
within the last hour). The `transparency.inclusion_proof` proves
that the most recent key event for this key (publication, rotation,
or revocation) is a leaf of the tree described by the STH.

A domain that supports transparency MUST include the `transparency`
field on every key returned. A domain that does not support
transparency omits the field entirely.

### 4.2 Client Verification Obligations

On receiving a key response with a `transparency` field, a client
MUST:

1. Verify the domain signature on the STH against the subject
   domain's current signing key.
2. Verify the STH's `timestamp` is within 1 hour of the client's
   clock per `CONFORMANCE.md` section 9.3.1.
3. Verify the inclusion proof against the STH's `root_hash`.
4. Verify the leaf being proven corresponds to the returned key
   (i.e., the leaf's `key_id` and `public_key` match).

If any verification fails, the client MUST NOT use the returned key.
The client SHOULD surface a security warning identifying the subject
domain and the failure mode. The client MAY offer the user the
option to proceed with an explicit acknowledgment, but MUST NOT
proceed silently.

### 4.3 STH Freshness

The STH accompanying a key fetch MUST be signed within the last hour.
This corresponds to the RECOMMENDED hourly STH publication cadence in
section 2.3. A stale STH widens the equivocation attack window; the
hourly cap bounds it.

A client receiving an STH older than 1 hour MUST refuse the key and
treat the situation as a verification failure per section 4.2.

---

## 5. Gossip via Observations

### 5.1 Observation Kind

Monitors publish their observations of other domains' transparency
logs via `SEMP_OBSERVATIONS` (`REPUTATION.md` section 4). A new
observation kind `key_transparency` is registered for this purpose.
The observation record carries a `type` discriminator and one or two
STH records:

```json
{
    "kind": "key_transparency",
    "type": "snapshot" | "verification" | "equivocation",
    "subject_domain": "example.com",
    "observed_at": "2026-04-19T12:00:00Z",
    "sth_records": [
        {
            "log_size": 12847,
            "root_hash": "base64-root-hash",
            "timestamp": "2026-04-19T11:58:00Z",
            "signature": {
                "algorithm": "ed25519",
                "key_id": "example.com-domain-signing-key-fingerprint",
                "value": "base64"
            }
        }
    ],
    "consistency_proof": null
}
```

| Field               | Type            | Required | Description                                                               |
|---------------------|-----------------|----------|---------------------------------------------------------------------------|
| `kind`              | `string`        | Yes      | MUST be `"key_transparency"`.                                             |
| `type`              | `string`        | Yes      | One of: `snapshot`, `verification`, `equivocation`. See section 5.2.       |
| `subject_domain`    | `string`        | Yes      | Domain the STH records are about.                                         |
| `observed_at`       | `string`        | Yes      | ISO 8601 UTC timestamp of the observer's action.                          |
| `sth_records`       | `array`         | Yes      | One or two domain-signed STHs. Length and ordering rules per section 5.2. |
| `consistency_proof` | `array\|null`   | Yes      | Merkle hashes of the consistency proof. Present only when `type` is `verification`. |

### 5.2 Types

**`type: "snapshot"`.** `sth_records` MUST contain exactly one STH.
The observer attests "I fetched this STH from `subject_domain` at
`observed_at`." `consistency_proof` MUST be `null`.

**`type: "verification"`.** `sth_records` MUST contain exactly two
STHs. Index 0 is the earlier STH; index 1 is the later STH (ordered
by the STH `timestamp` field). The observer fetched a consistency
proof from the subject domain, verified it, and publishes the proof
in `consistency_proof` so downstream verifiers can re-verify without
refetching. Both STH signatures MUST verify against the subject
domain's signing key.

**`type: "equivocation"`.** `sth_records` MUST contain exactly two
STHs with the same `log_size` and different `root_hash` values. Both
signatures MUST verify against the subject domain's signing key.
This is mutually contradictory domain-signed evidence: no honest
domain would sign two different roots at the same size.
`consistency_proof` MUST be `null`; the two conflicting signed STHs
are themselves the proof.

### 5.3 Verification by Downstream Clients

A client consuming `key_transparency` observations MUST:

- Verify the signature on every STH in `sth_records` against the
  subject domain's current or recently-rotated signing key.
- For `type: "verification"`: recompute the consistency proof
  against the two STHs' roots. Reject the observation if
  verification fails.
- For `type: "equivocation"`: verify that both STHs are signed by
  the subject domain and that they have the same `log_size` with
  different `root_hash`. Either property failing means the
  observation is malformed.

A malformed observation is silently discarded. A verified
`equivocation` observation MUST be treated as strong evidence that
the subject domain is misbehaving; the client SHOULD refuse to
accept keys from that domain until the equivocation is explained or
mitigated by operator action.

A verified `verification` or `snapshot` observation whose STH
contradicts the STH the client received on a key fetch (same
subject domain and similar `log_size`, different `root_hash`)
constitutes client-level equivocation detection. The client SHOULD
treat this equivalently to a verified `equivocation` observation.

---

## 6. Monitor Behavior

This section is informative. The protocol does not require or elect
monitors; operators and third parties MAY run monitors on any
policy they choose.

A typical monitor:

- Periodically fetches the current STH from every domain it
  monitors.
- Publishes `snapshot` observations for each fetched STH.
- At intervals (daily, weekly), fetches consistency proofs between
  its latest observed STH and older observed STHs, verifies them,
  and publishes `verification` observations.
- Compares observed STHs against STHs published by other monitors
  (via their observation records) for the same domain and close
  timestamps. On mismatch with verified signatures on both, publishes
  an `equivocation` observation.
- Alerts the operator on any detected anomaly.

Monitors MAY specialize: some focus on a single domain they care
about; others monitor broadly. There is no onboarding or registry.

---

## 7. Security Considerations

### 7.1 Signing Key Compromise

If the domain's signing key is compromised, the attacker can sign
arbitrary STHs, including ones consistent with a rewritten log. This
defeats transparency for the compromise window.

Mitigations are the same as for any domain-key compromise:
revocation (`KEY.md` section 8), rotation, and reputation
consequences. Monitors that continue to fetch STHs after signing-key
rotation will observe the new signing key. Observations signed under
the old key after rotation MUST be rejected by verifiers.

### 7.2 Split-World Attacks

A domain could maintain two parallel consistent logs: one shown to
the intended victim, another shown to the rest of the world. Both
are internally consistent, both are signed. Equivocation detection
depends on monitors diversifying their fetch paths (IPs, transports,
times) enough that a split-world attacker cannot reliably segregate
victim observations from monitor observations.

This is the same threat model CT faces. It is mitigated by monitor
diversity, not by a protocol-level defense. Operators concerned
about split-world attacks SHOULD encourage and fund multiple
independent monitors.

### 7.3 Monitor Trust

Clients rely on observations from monitors they trust. The
protocol does not specify monitor trust; operators and users
choose which monitors to weight. A hostile or compromised monitor
can publish fraudulent observations, but:

- Fraudulent `snapshot` observations are detectable: the signed STH
  must verify against the domain, and if the domain did not sign
  that STH, the observation is malformed.
- Fraudulent `verification` observations are detectable: the
  consistency proof is included and re-verifiable.
- Fraudulent `equivocation` observations are detectable: the two
  STHs must both verify against the domain.

A monitor can only publish observations that reflect real domain
signatures. It cannot forge domain-signed STHs without the domain's
signing key. The worst it can do is selectively publish or withhold
observations, which weakens but does not break the system.

### 7.4 Privacy of User Key Events

The log makes every user's key event (publication, rotation,
revocation) publicly observable with timestamp. This is already
true of individual key fetches, which are anonymous per `DISCOVERY.md`
section 1.2, but the log makes the full history queryable in bulk.

Users sensitive to this exposure MUST be informed that using a
transparency-supporting domain means their key history is public.
Operators SHOULD document transparency participation in their
privacy policy.

### 7.5 Relationship to Revocation

Revocation records published per `KEY.md` section 8 are accompanied
by a corresponding `revoke` event leaf in the log. A client fetching
a key whose log entry shows revocation MUST treat the key as
revoked, even if the key record itself is cached from a time before
the revocation.

---

## 8. Privacy Considerations

### 8.1 What the Log Reveals

Every key event (publish, rotate, revoke) is recorded with:

- The `user_id` (full SEMP address).
- The public key.
- Timestamps.
- For revocation, the reason.

The log does not reveal correspondence, envelope contents, or
session data. It reveals the users' key rotation patterns, which
could be used for traffic analysis (for example, inferring device
provisioning events from key publications).

Users who require unobservable key events SHOULD operate on domains
that do not participate in key transparency. The trade-off is
explicit: transparency is incompatible with hidden key lifecycle.

### 8.2 Monitor Correlation

A monitor observing a domain's log over time builds a picture of
every user on that domain. Monitors SHOULD NOT be used to profile
individual users. Operators concerned about monitor profiling MAY
publish only aggregate observations, but doing so weakens
equivocation detection.

This trade-off, like split-world resistance, is a deployment
concern rather than a protocol property.

---

## 9. Conformance

### 9.1 Server Conformance

A server claiming key transparency support MUST:

- Maintain an append-only Merkle-tree log per section 2.
- Append a leaf for every user identity and encryption key event
  (publish, rotate, revoke) before the event takes effect for key
  fetches.
- Publish a fresh STH at least every hour, signed by the domain
  signing key. (Section 2.3)
- Serve the `transparency_log` endpoint with the operations in
  section 2.4.
- Augment every `SEMP_KEYS` response with per-key `transparency`
  including an inclusion proof and a current STH. (Section 4.1)
- Never remove or modify a leaf. (Section 2.5)
- Continue serving the log for at least 2 years after withdrawing
  transparency support. (Section 2.5)
- Advertise the `transparency_log` endpoint in discovery. Absence
  of the endpoint means the server does not support transparency.
  (`DISCOVERY.md` section 3.1.1)

A server claiming transparency support MUST NOT:

- Serve an inclusion proof that does not verify against the
  accompanying STH.
- Sign two STHs with the same `log_size` and different `root_hash`
  values under any circumstance (this is equivocation and is
  provably misbehavior per section 5.2).

### 9.2 Client Conformance

A client that accepts keys from transparency-supporting domains
MUST:

- Verify the STH signature, freshness, and inclusion proof on every
  key fetch per section 4.2.
- Refuse to use a key whose transparency verification fails.
- Refuse to use an STH older than 1 hour.
- Surface verification failures to the user as security warnings,
  not generic connection errors.

A client consuming `key_transparency` observations MUST verify
every STH signature and, for `verification` observations,
re-verify the consistency proof. (Section 5.3)

### 9.3 Monitor Conformance

Monitor behavior is informative per section 6. Conformance is
defined only by the observation schema (section 5.1): a monitor
claiming to follow this specification MUST publish observations
that are well-formed per section 5.2 and MUST NOT publish
observations whose contained STH signatures do not verify against
the subject domain's signing key.

---

## 10. Relationship to Other Specifications

| Specification      | Relationship                                                                                       |
|--------------------|----------------------------------------------------------------------------------------------------|
| `KEY.md`           | Key events logged here parallel the records in section 3 and revocations in section 8.             |
| `DISCOVERY.md`     | The `transparency_log` endpoint is advertised in the configuration document.                       |
| `REPUTATION.md`    | Observations use the `SEMP_OBSERVATIONS` mechanism and the new `key_transparency` kind.            |
| `CONFORMANCE.md`   | Server and client conformance bullets are referenced from `CONFORMANCE.md`.                        |
| `DESIGN.md`        | Supports the trust model in section 5: domain-based identity with observable key history.          |

---

*This document is an Internet-Draft. It is subject to revision prior
to finalization as a stable specification.*
