# SEMP Handshake Specification

**Sealed Envelope Messaging Protocol**  
Status: Internet-Draft  
Version: 0.1.0  
Related: `DESIGN.md`, `KEY.md`, `DISCOVERY.md`, `ENVELOPE.md`

---

## Abstract

The SEMP handshake establishes a secure, authenticated session between two
parties before any envelopes are exchanged. It provides mutual authentication,
capability negotiation, and a shared session context. This document defines the
client-to-server handshake and the server-to-server federation handshake.

All handshake packets share a single message type (`SEMP_HANDSHAKE`) with
the discriminating details carried in the `step` and `party` fields. The schema
for any given packet is fully determined by the combination of those three
fields.

---

## 1. Overview

The handshake occurs after the TLS connection is established and before any
envelope exchange. A successful handshake results in mutual authentication,
agreed cryptographic parameters, and a session context that both parties
reference for the duration of the exchange.

Handshakes in SEMP are **transaction-level**, not connection-level. They are
performed per logical messaging transaction or batch of related messages. This
enables per-transaction access control and blocking without requiring persistent
connections.

### 1.1 Privacy Constraint

A core requirement of the SEMP handshake is that client identity MUST NOT
appear in plaintext on the wire at any point. The init message is intentionally
anonymous: it carries only an ephemeral key and capabilities. Client identity
is revealed only after a shared secret is established, encrypted under that
secret, and therefore invisible to passive observers.

A passive observer sees that a connection was made to a server but MUST NOT be able to
determine who made it or who they intend to reach.

### 1.2 Connection Model

SEMP enforces a strict connection topology:

```
Sender Client → Sender's Server → Recipient's Server → Recipient Client
```

Clients MUST only connect to their own home server. A client never connects
directly to a remote domain's server. Cross-domain message delivery is always
server-to-server. A server that receives a client handshake from an address
outside its own domain SHOULD treat this as suspicious and MAY reject it.

How the server signals to a client that messages are waiting (polling,
WebSocket, or platform notification services) is outside the scope of this
specification. See section 4.6.

### 1.3 Handshake Variants

SEMP defines two handshake variants:

- **Client handshake**:  a user's client connecting to their home server.
- **Federation handshake**:  two servers establishing a cross-domain session.

When both parties identify as `server`, the session is a federation session.
No additional field is needed to discriminate; the combination of `party`
values determines the context.

### 1.4 Packet Discrimination

SEMP defines two message types at the session layer: `SEMP_HANDSHAKE` for
session establishment, and `SEMP_REKEY` for in-session key rotation.

#### SEMP_HANDSHAKE

Every handshake packet has:

```json
{
    "type": "SEMP_HANDSHAKE",
    "step": "<step>",
    "party": "<party>",
    ...
}
```

The full discriminator matrix:

| `step`         | `party`  | Sent by  | Meaning                                         |
|----------------|----------|----------|-------------------------------------------------|
| `init`         | `client` | Client   | Client opens handshake with home server         |
| `init`         | `server` | Server A | Server A opens federation with Server B         |
| `response`     | `server` | Server   | Server responds to either init type             |
| `challenge`          | `server` | Server   | Server requires a challenge to be solved before proceeding |
| `challenge_response` | `client` | Client   | Client submits challenge solution                          |
| `challenge_response` | `server` | Server A | Server A submits challenge solution (federation)           |
| `confirm`      | `client` | Client   | Client confirms after key exchange              |
| `confirm`      | `server` | Server A | Server A confirms federation after key exchange |
| `accepted`     | `server` | Server   | Server accepts the session                      |
| `rejected`     | `server` | Server   | Server rejects the session explicitly           |

`response`, `accepted`, and `rejected` always come from the server, since the party
being connected to always controls the final outcome.

#### SEMP_REKEY

Once a session is established, either party may initiate a rekeying exchange
to rotate session keys without a full re-authentication. Rekey packets use a
separate message type to distinguish them unambiguously from handshake traffic:

```json
{
    "type": "SEMP_REKEY",
    "step": "<step>",
    ...
}
```

| `step`     | Sent by    | Meaning                                               |
|------------|------------|-------------------------------------------------------|
| `init`     | Either     | Initiates a rekeying exchange on an active session    |
| `accepted` | Responder  | Accepts the rekey; carries responder ephemeral key    |
| `rejected` | Responder  | Declines the rekey; session continues under old keys  |

`SEMP_REKEY` packets are encrypted and MACed under the current session keys.
Receipt of a valid `SEMP_REKEY` message therefore implies the sender holds the
active session keys, so no separate identity proof is required.

The full rekeying protocol, new key derivation procedure, key transition rules,
and rate limits are defined in `SESSION.md` section 3.

---

## 2. Client Handshake

### 2.1 Sequence

```
Client                                          Home Server
  |                                               |
  |--- 1. type=SEMP_HANDSHAKE                 --> |
  |        step=init, party=client                |
  |   (ephemeral key, capabilities only)          |
  |   (no identity, no client ID)                 |
  |                                               |
  |          (server checks reputation,           |
  |           domain age, rate limits)            |
  |                                               |
  |   [if challenge required]                      |
  | <-- 1b. type=SEMP_HANDSHAKE               --- |
  |          step=challenge, party=server         |
  |   (challenge_type, parameters, expiry)        |
  |                                               |
  |--- 1c. type=SEMP_HANDSHAKE                --> |
  |         step=challenge_response, party=client |
  |   (solution)                                  |
  |                                               |
  |   [challenge verified, continue]              |
  |                                               |
  |                (verify capabilities,          |
  |                 generate ephemeral key)        |
  |                                               |
  | <-- 2. type=SEMP_HANDSHAKE                --- |
  |         step=response, party=server           |
  |   (server ephemeral key, negotiated params)   |
  |                                               |
  |   (both sides derive shared secret)           |
  |                                               |
  |--- 3. type=SEMP_HANDSHAKE                 --> |
  |        step=confirm, party=client             |
  |   (identity + auth, encrypted under secret)   |
  |                                               |
  |          (server verifies identity + auth)    |
  |                                               |
  | <-- 4. type=SEMP_HANDSHAKE                --- |
  |         step=accepted, party=server           |
  |      OR step=rejected, party=server           |
  |                                               |
  |         SESSION ESTABLISHED                   |
  |                                               |
  |--- Begin envelope exchange ---------------→   |
```

The challenge round trip (steps 1b and 1c) is conditional. It occurs only when
the server determines a challenge is required per `REPUTATION.md` section 8.3.
When no challenge is required, the handshake proceeds directly from step 1 to
step 2. The four-message structure is preserved in both cases; the challenge is
an optional interstitial, not a replacement for any existing step.

### 2.2 Message 1: init / client

The init message is anonymous. It carries the client's ephemeral public key and
capabilities. Nothing in this message identifies the client.

```json
{
    "type": "SEMP_HANDSHAKE",
    "step": "init",
    "party": "client",
    "version": "1.0.0",
    "nonce": "base64-random-32-bytes",
    "transport": "ws",
    "client_ephemeral_key": {
        "algorithm": "pq-kyber768-x25519",
        "key": "base64-encoded-ephemeral-public-key",
        "key_id": "ephemeral-key-fingerprint"
    },
    "capabilities": {
        "encryption_algorithms": [
            "pq-kyber768-x25519",
            "x25519-chacha20-poly1305"
        ],
        "extensions": [
            "semp.dev/device-sync",
            "semp.dev/read-receipts",
            "semp.dev/message-expiry"
        ]
    },
    "extensions": {}
}
```

#### 2.2.1 Init Fields

| Field                  | Type     | Required | Description                                                    |
|------------------------|----------|----------|----------------------------------------------------------------|
| `type`                 | `string` | Yes      | MUST be `"SEMP_HANDSHAKE"`                                |
| `version`              | `string` | Yes      | SEMP protocol version (semver)                                 |
| `nonce`                | `string` | Yes      | Cryptographically random value, base64-encoded, min 32 bytes. Used for replay prevention and key derivation. |
| `transport`            | `string` | Yes      | Transport in use. One of the identifiers defined in `TRANSPORT.md` section 4 (`ws`, `h2`, `quic`) or an extended binding identifier per `TRANSPORT.md` section 7. |
| `client_ephemeral_key` | `object` | Yes      | Ephemeral public key for this session only. MUST NOT be reused.|
| `capabilities`         | `object` | Yes      | Supported cryptographic algorithms and extension identifiers advertised for this session. The `capabilities.extensions` array lists extension identifiers the client supports, per `EXTENSIONS.md` section 6. |
| `extensions`           | `object` | No       | Handshake-layer extension entries (distinct from `capabilities.extensions`, which advertises session-wide extension support). See `EXTENSIONS.md` section 1. |

The init message is NOT signed. Signing would require a key identifier, which
would link this message to a client identity. Integrity of the init is
established through the confirmation hash in message 3.

### 2.2a Message 1b: challenge / server (conditional)

When the server determines a challenge is required before proceeding (based on
domain reputation, registration age, or operator policy per `REPUTATION.md`
section 8.3), it MUST respond with a `challenge` message instead of proceeding
directly to the `response` step. No session resources are allocated and no
ephemeral key material is generated until the challenge is verified.

The challenge mechanism is type agnostic. The `challenge_type` field identifies
which kind of challenge the server is issuing, and the `parameters` object
carries the type specific data needed by the client to compute a solution. This
design allows new challenge types to be introduced in future revisions without
altering the handshake structure.

```json
{
    "type": "SEMP_HANDSHAKE",
    "step": "challenge",
    "party": "server",
    "version": "1.0.0",
    "challenge_id": "challenge-ulid",
    "challenge_type": "proof_of_work",
    "parameters": {
        "algorithm": "sha256",
        "prefix": "base64-random-bytes-min-16",
        "difficulty": 20
    },
    "expires": "2025-06-10T20:35:00Z",
    "server_signature": "signature-over-entire-message"
}
```

#### 2.2a.1 Challenge Fields

| Field              | Type      | Required | Description                                                         |
|--------------------|-----------|----------|---------------------------------------------------------------------|
| `challenge_id`     | `string`  | Yes      | Unique challenge identifier. ULID RECOMMENDED.                      |
| `challenge_type`   | `string`  | Yes      | Identifies the challenge type. See section 2.2a.2 for defined types.|
| `parameters`       | `object`  | Yes      | Type specific challenge data. Structure depends on `challenge_type`. |
| `expires`          | `string`  | Yes      | ISO 8601 UTC timestamp. Solution MUST be submitted before expiry.   |
| `server_signature` | `string`  | Yes      | Signature over the entire message using the server's domain key.    |

The initiator MUST verify `server_signature` before computing a solution. A
`challenge` message with an invalid signature MUST be treated as a rejection
and the handshake MUST be aborted. This obligation applies to both client
initiators performing client-to-server handshakes and federation peers
performing server-to-server handshakes (section 5).

An initiator that does not recognize the `challenge_type` MUST abort the
handshake. It MUST NOT silently ignore the challenge and proceed, since the
server will reject any subsequent handshake message that lacks a valid
solution.

#### 2.2a.2 Challenge Type: proof_of_work

The `proof_of_work` challenge type requires the client to find a nonce that
produces a hash with a specified number of leading zero bits. It is the
baseline challenge type and MUST be supported by all implementations.

**Parameters for `proof_of_work`:**

| Field       | Type      | Required | Description                                                              |
|-------------|-----------|----------|--------------------------------------------------------------------------|
| `algorithm` | `string`  | Yes      | Hash algorithm. MUST be `sha256`.                                        |
| `prefix`    | `string`  | Yes      | Base64-encoded random bytes. Minimum 16 bytes of entropy.                |
| `difficulty`| `integer` | Yes      | Leading zero bits required in the solution hash. MUST be in the range 0 to 28 inclusive. See `REPUTATION.md` section 8.3.2. |

**Difficulty cap.** A conformant server MUST NOT issue a `proof_of_work`
challenge with `difficulty` greater than 28. A conformant handshake
initiator MUST abort the handshake with
`reason_code: "challenge_invalid"` if it receives a `proof_of_work`
challenge with `difficulty` greater than 28, and MUST NOT attempt to solve
a challenge that exceeds the cap even if it has sufficient compute to do
so. This requirement applies equally to clients performing client-to-server
handshakes and to federation peers performing server-to-server handshakes
(section 5). A federation peer receiving a challenge above the cap MUST
treat the issuing server as misbehaving and MUST NOT retry under the same
conditions.

The cap prevents a malicious or compromised server from issuing
prohibitively expensive challenges against either clients (exhausting
device resources or draining batteries) or federation peers (consuming CPU
on shared infrastructure and degrading legitimate mail flow for unrelated
correspondents). The cap applies to every `proof_of_work` challenge
regardless of the initiator's role, reputation, the operator's policy, or
the handshake context. Servers that require stronger gating than
difficulty 28 provides MUST use a different challenge type or a
non-challenge mechanism such as block listing (`DELIVERY.md` section 5).

**Minimum expiry.** The `expires` timestamp MUST be far enough in the
future to allow a legitimate initiator on constrained hardware or a high
latency network to compute a solution. A conformant server MUST NOT issue a
`proof_of_work` challenge whose `expires` value is less than the floor
corresponding to its `difficulty`:

| Difficulty range | Minimum `expires` relative to issuance |
|------------------|-----------------------------------------|
| 0 to 20          | 30 seconds                              |
| 21 to 24         | 60 seconds                              |
| 25 to 28         | 120 seconds                             |

A conformant initiator MUST abort the handshake with
`reason_code: "challenge_invalid"` if it receives a `proof_of_work`
challenge whose `expires` value, measured against the initiator's clock at
receipt, is shorter than the floor for its difficulty. The initiator MUST
NOT attempt to solve such a challenge. The floor prevents a server from
issuing a technically conformant challenge that is unsolvable in practice
for legitimate initiators on mobile devices, over Tor, or on otherwise
constrained links. The floor is intentionally generous relative to 2024
compute baselines; faster hardware in future years only widens the margin
for legitimate initiators and does not require revision of this table.

Servers MAY issue longer expiry values than the floor and SHOULD do so
when operator policy anticipates clients on slow links. Initiators MUST
accept any expiry at or above the floor and MUST NOT impose their own
upper bound on `expires` beyond ordinary clock skew tolerance.

#### 2.2a.3 First-Contact Proof of Work

A `proof_of_work` challenge MAY be issued by a recipient server in response
to an envelope submission, not only during a handshake, when the recipient's
first-contact policy announces `mode: "challenge"` with
`challenge_type: "proof_of_work"` (`KEY.md` section 3.2, `DELIVERY.md`
section 6.4). The challenge format is identical to the in-handshake
`proof_of_work` challenge defined in section 2.2a.2 and is delivered as a
field of a `policy_forbidden` rejection response.

`proof_of_work` is the first defined first-contact challenge type. Future
challenge types MAY be defined per `KEY.md` section 3.2.2 and this section
MAY be extended with analogous first-contact binding rules for them.

The challenge is bound to a (sender_domain, recipient_address, hour_bucket)
tuple by including those values in the `prefix` derivation. The exact
binding is defined as:

```
prefix = base64( random_bytes(16) || H( sender_domain || recipient_address || hour_bucket ) )
```

Where `hour_bucket` is the integer hour-precision Unix timestamp at the
time of issuance, `H` is SHA-256, and `||` denotes byte concatenation.

The recipient server MUST NOT vary `difficulty` based on whether the
recipient address exists. The same difficulty MUST be issued for
non-existent and existent recipients, in conformance with the existence
indistinguishability requirement in `DESIGN.md` section 2.7.

The sender's server, on receiving a `policy_forbidden` rejection that
carries a `challenge` body, MAY compute a solution and resubmit the
envelope. The solved token is carried in `seal.first_contact_token` per
section 2.2a.4.

The recipient server MUST accept a valid `first_contact_token` for any
envelope from the same sender_domain to the same recipient_address within
the bound hour_bucket and the next hour_bucket (a two-hour acceptance
window). Tokens older than two hour_buckets MUST be rejected as expired.

#### 2.2a.4 first_contact_token Schema

The `seal.first_contact_token` field on an envelope (`ENVELOPE.md` section
4.2) carries a previously solved first-contact challenge:

```json
{
    "challenge_id": "challenge-ulid-from-original-rejection",
    "algorithm": "sha256",
    "prefix": "base64-prefix-from-original-challenge",
    "difficulty": 22,
    "hour_bucket": 489657,
    "nonce": "base64-solution-nonce",
    "issued_by": "recipient.example.com"
}
```

| Field          | Type      | Required | Description                                                                  |
|----------------|-----------|----------|------------------------------------------------------------------------------|
| `challenge_id` | `string`  | Yes      | The `challenge_id` of the rejection response that issued this challenge.     |
| `algorithm`    | `string`  | Yes      | Hash algorithm. MUST be `sha256`.                                            |
| `prefix`       | `string`  | Yes      | Base64-encoded prefix as issued by the recipient server.                     |
| `difficulty`   | `integer` | Yes      | Leading zero bits required, as issued. Subject to the difficulty cap.        |
| `hour_bucket`  | `integer` | Yes      | Hour-precision Unix timestamp from issuance.                                 |
| `nonce`        | `string`  | Yes      | Base64-encoded nonce that satisfies the difficulty when hashed with prefix.  |
| `issued_by`    | `string`  | Yes      | Hostname of the recipient server that issued the challenge.                  |

A recipient server MUST verify that:

1. `challenge_id` matches a challenge it previously issued.
2. `prefix` matches the prefix recorded for that challenge.
3. `H(prefix || nonce)` has at least `difficulty` leading zero bits.
4. The challenge's `hour_bucket` is the current hour_bucket or the
   immediately preceding one.

If verification succeeds, the recipient server MUST treat the envelope as
having satisfied the first-contact policy for the binding tuple. If
verification fails, the recipient server MUST reject the envelope with
`reason_code: "policy_forbidden"` per the indistinguishability requirement
in `DESIGN.md` section 2.7; the rejection MAY include a fresh challenge.

#### 2.2a.5 Future Challenge Types

Additional challenge types MAY be defined in future revisions of this
specification or via extensions using the standard namespacing convention
(`"vendor.example.com/challenge-name"`). Each new type MUST define its
`parameters` schema, its solution format within `challenge_response`, and the
server side verification procedure. All challenge types share the same
`challenge` / `challenge_response` message structure and the same lifecycle
rules (single use, expiry, signature verification).

### 2.2b Message 1c: challenge_response / client (conditional)

The client submits its solution to the challenge. The `challenge_type` field
echoes the type from the `challenge` message. The `solution` object carries
type specific data that the server uses for verification.

```json
{
    "type": "SEMP_HANDSHAKE",
    "step": "challenge_response",
    "party": "client",
    "version": "1.0.0",
    "challenge_id": "echoed-challenge-ulid",
    "challenge_type": "proof_of_work",
    "solution": {
        "nonce": "base64-encoded-nonce",
        "hash": "hex-encoded-sha256-hash"
    }
}
```

#### 2.2b.1 Challenge Response Fields

| Field            | Type     | Required | Description                                                     |
|------------------|----------|----------|-----------------------------------------------------------------|
| `challenge_id`   | `string` | Yes      | Echo of `challenge_id` from the `challenge` message.            |
| `challenge_type` | `string` | Yes      | Echo of `challenge_type` from the `challenge` message.          |
| `solution`       | `object` | Yes      | Type specific solution data. Structure depends on `challenge_type`. |

#### 2.2b.2 Solution Format: proof_of_work

For `proof_of_work` challenges, the client finds a nonce such that:

```
SHA-256(prefix || ":" || challenge_id || ":" || nonce)
```

produces a hash with at least `difficulty` leading zero bits. The nonce is an
arbitrary byte string chosen by the client.

**Solution fields for `proof_of_work`:**

| Field   | Type     | Required | Description                                         |
|---------|----------|----------|-----------------------------------------------------|
| `nonce` | `string` | Yes      | Base64-encoded nonce that satisfies the difficulty.  |
| `hash`  | `string` | Yes      | Hex-encoded SHA-256 hash of the full preimage.       |

The server MUST verify the solution before proceeding:

1. Confirm `challenge_id` matches an issued, unexpired challenge.
2. Recompute `SHA-256(prefix || ":" || challenge_id || ":" || nonce)`.
3. Confirm the result matches the submitted `hash`.
4. Confirm the hash has at least `difficulty` leading zero bits.

If verification passes, the handshake continues to step 2 (`response`). If
verification fails or the challenge has expired, the server MUST respond with
`step=rejected` and `reason_code: "challenge_failed"`. Each challenge MUST be
single-use: the server MUST reject a duplicate `challenge_id` submission even
if the solution is valid.

A valid challenge solution permits the handshake to proceed. It does not grant
trust or bypass any subsequent identity verification steps.

### 2.3 Message 2: response / server

The server responds with its own ephemeral key and the negotiated session
parameters. After this message, both parties have enough material to derive
the shared session secret.

```json
{
    "type": "SEMP_HANDSHAKE",
    "step": "response",
    "party": "server",
    "version": "1.0.0",
    "session_id": "server-generated-ulid",
    "client_nonce": "echoed-client-nonce",
    "server_nonce": "base64-random-32-bytes",
    "server_ephemeral_key": {
        "algorithm": "pq-kyber768-x25519",
        "key": "base64-encoded-ephemeral-public-key",
        "key_id": "ephemeral-key-fingerprint"
    },
    "server_identity_proof": {
        "domain": "example.com",
        "key_id": "server-long-term-key-fingerprint",
        "signature": "signature-over-server-ephemeral-key-and-nonces"
    },
    "negotiated": {
        "encryption_algorithm": "pq-kyber768-x25519",
        "extensions": [
            "semp.dev/device-sync",
            "semp.dev/read-receipts"
        ],
        "max_envelope_size": 26214400
    },
    "server_signature": "signature-over-entire-message",
    "extensions": {}
}
```

#### 2.3.1 Response Fields

| Field                  | Type     | Required | Description                                                       |
|------------------------|----------|----------|-------------------------------------------------------------------|
| `type`                 | `string` | Yes      | MUST be `"SEMP_HANDSHAKE"`                               |
| `version`              | `string` | Yes      | SEMP protocol version (semver)                                    |
| `session_id`           | `string` | Yes      | Server-generated session identifier. ULID RECOMMENDED.            |
| `client_nonce`         | `string` | Yes      | Echo of the client's nonce from message 1.                        |
| `server_nonce`         | `string` | Yes      | Server-generated random nonce, min 32 bytes.                      |
| `server_ephemeral_key` | `object` | Yes      | Server's ephemeral public key for this session.                   |
| `server_identity_proof`| `object` | Yes      | Proof that the server controls the domain's long-term key.        |
| `negotiated`           | `object` | Yes      | Agreed session parameters selected from client capabilities.      |
| `server_signature`     | `string` | Yes      | Signature over the entire message using the server's domain key.  |
| `extensions`           | `object` | No       | Handshake-layer extensions.                                       |

The `negotiated` object MUST include `max_envelope_size`, which declares the
maximum envelope size in bytes that this server will accept. Clients MUST NOT
submit envelopes exceeding this value. In federation handshakes, the negotiated
`max_envelope_size` is the minimum of both servers' advertised limits.

The server MUST sign message 2 with its long-term domain key. The client
verifies this signature using the server's published domain key before
proceeding to message 3. If verification fails, the client MUST abort.

### 2.4 Shared Secret Derivation

After message 2, both parties derive the shared session secret using HKDF
(RFC 5869):

- **Input keying material**: shared secret from ephemeral key agreement
  (Kyber768 + X25519 for pq-hybrid)
- **Salt**: `client_nonce || server_nonce` (concatenation)
- **Info context**: `"SEMP-v1-session"`

Five keys are derived from this material:

| Key | Purpose |
|-----|---------|
| `K_enc_c2s` | Encryption: client → server handshake messages |
| `K_enc_s2c` | Encryption: server → client handshake messages |
| `K_mac_c2s` | MAC: client → server handshake messages |
| `K_mac_s2c` | MAC: server → client handshake messages |
| `K_env_mac` | MAC: envelope session authentication. Used in `seal.session_mac`. |

Separate directional keys prevent cross-channel attacks where a message sent
in one direction could be replayed in the other. `K_env_mac` is distinct from
the handshake MAC keys and is used exclusively for authenticating envelopes
sent within this session, as defined in `ENVELOPE.md` section 4.3.

### 2.5 Message 3: confirm / client

The confirmation message carries the client's identity and authentication,
encrypted under the shared session secret derived in section 2.4. A passive
observer sees only an opaque encrypted blob alongside the confirmation hash.

```json
{
    "type": "SEMP_HANDSHAKE",
    "step": "confirm",
    "party": "client",
    "version": "1.0.0",
    "session_id": "echoed-session-id",
    "confirmation_hash": "hash-of-messages-1-and-2",
    "identity_proof": "<base64-encrypted-identity-block>",
    "extensions": {}
}
```

The `identity_proof` field is an encrypted JSON object containing:

```json
{
    "client_id": "client-ulid",
    "client_identity": "user@example.com",
    "client_long_term_key_id": "long-term-key-fingerprint",
    "identity_signature": "signature-over-session-id-and-confirmation-hash",
    "auth": {
        "method": "identity_key",
        "params": {}
    }
}
```

This block is encrypted under `K_enc_c2s` and is opaque to any party that does
not hold the session secret.

#### 2.5.1 Confirm Fields

| Field               | Type     | Required | Description                                                          |
|---------------------|----------|----------|----------------------------------------------------------------------|
| `type`              | `string` | Yes      | MUST be `"SEMP_HANDSHAKE"`                                   |
| `version`           | `string` | Yes      | SEMP protocol version (semver)                                       |
| `session_id`        | `string` | Yes      | Echo of `session_id` from message 2.                                 |
| `confirmation_hash` | `string` | Yes      | Hash of the canonical serializations of messages 1 and 2.           |
| `identity_proof`    | `string` | Yes      | Encrypted identity block. See section 2.5.2.                         |
| `extensions`        | `object` | No       | Handshake-layer extensions.                                          |

#### 2.5.2 Identity Proof Block (Decrypted)

| Field                    | Type     | Required | Description                                                    |
|--------------------------|----------|----------|----------------------------------------------------------------|
| `client_id`              | `string` | Yes      | Client's unique identifier. ULID RECOMMENDED.                  |
| `client_identity`        | `string` | Yes      | Client's full address: `user@domain`.                          |
| `client_long_term_key_id`| `string` | Yes      | Fingerprint of the client's long-term identity key.            |
| `identity_signature`     | `string` | Yes      | Signature over `session_id || confirmation_hash` using the client's long-term key. |
| `auth`                   | `object` | Yes      | Authentication method and parameters. See section 2.6.         |

#### 2.5.3 Confirmation Hash

The `confirmation_hash` is computed as:

```
SHA-256(canonical(message_1) || canonical(message_2))
```

Where `canonical()` is the same canonicalization used for envelope seal
signatures: lexicographically sorted keys, no insignificant whitespace. This
binds the confirmation to the specific exchange that preceded it, preventing
message substitution attacks.

### 2.6 Authentication Methods

SEMP treats all authentication methods as equally first-class. The `auth`
object in the identity proof block specifies the method and carries its
parameters. Servers declare which methods they accept during discovery.

Defined methods:

#### Identity Key

```json
"auth": {
    "method": "identity_key",
    "params": {}
}
```

Authentication is provided entirely by `identity_signature` in the identity
proof block. No additional parameters required.

#### Token

```json
"auth": {
    "method": "token",
    "params": {
        "token": "jwt-or-opaque-token"
    }
}
```

A JWT or opaque token issued by the server or a trusted identity provider.
Token validation semantics are server-defined.

#### Password

```json
"auth": {
    "method": "password",
    "params": {
        "response": "base64-challenge-response"
    }
}
```

Challenge-response password authentication. The server MAY issue a challenge
in message 2 via `extensions` when password auth is expected. The response is
computed over the challenge using the agreed password hash scheme.

#### Multi-Factor

```json
"auth": {
    "method": "mfa",
    "params": {
        "primary": {
            "method": "identity_key",
            "params": {}
        },
        "factor": {
            "type": "totp",
            "code": "123456"
        }
    }
}
```

Combines a primary method with an additional factor. Factor types are
extensible. Servers declare supported factor types during discovery.

Additional authentication methods MAY be defined in extensions using the
standard namespacing convention: `"vendor.example.com/method-name"`.

### 2.7 Message 4: accepted / server  or  rejected / server

The server's final message confirms the session is open, or rejects it
explicitly with a reason.

```json
{
    "type": "SEMP_HANDSHAKE",
    "step": "accepted",
    "party": "server",
    "version": "1.0.0",
    "session_id": "echoed-session-id",
    "session_ttl": 300,
    "permissions": ["send", "receive", "create_group"],
    "server_signature": "signature-over-entire-message",
    "extensions": {}
}
```

On rejection:

```json
{
    "type": "SEMP_HANDSHAKE",
    "step": "rejected",
    "party": "server",
    "version": "1.0.0",
    "session_id": "echoed-session-id",
    "reason_code": "AUTH_FAILED",
    "reason": "Identity signature could not be verified.",
    "server_signature": "signature-over-entire-message",
    "extensions": {}
}
```

#### 2.7.1 Accepted Fields

| Field             | Type      | Required | Description                                                          |
|-------------------|-----------|----------|----------------------------------------------------------------------|
| `type`            | `string`  | Yes      | MUST be `"SEMP_HANDSHAKE"`                                           |
| `version`         | `string`  | Yes      | SEMP protocol version (semver)                                       |
| `session_id`      | `string`  | Yes      | Echo of session identifier.                                          |
| `session_ttl`     | `integer` | Yes      | Session lifetime in seconds from `established_at`. The client uses this to compute `expires_at` and to schedule proactive rekeying per `SESSION.md` section 2.6. A client that receives an `accepted` message without this field MUST assume 300 seconds and SHOULD log a warning. |
| `permissions`     | `array`   | No       | Granted permissions. Present in `accepted` step only.                |
| `reason_code`     | `string`  | No       | Machine-readable reason. Present in `rejected` step only. See section 4.1. |
| `reason`          | `string`  | No       | Human-readable description. Present in `rejected` step only.         |
| `server_signature`| `string`  | Yes      | Signature over the entire message.                                   |
| `extensions`      | `object`  | No       | Handshake-layer extensions.                                          |

If the server cannot complete the handshake for any reason, it MUST send a
`rejected` response rather than closing the connection without explanation.

---

## 3. Session Lifetime and Caching

### 3.1 TTL via DNS

Domains publish their preferred handshake TTL in DNS:

```
_semp.example.com.  IN  TXT  "v=semp1;handshake-ttl=300;min-ttl=30;max-ttl=3600"
```

| Parameter       | Description                              | Default |
|-----------------|------------------------------------------|---------|
| `handshake-ttl` | Default session validity in seconds      | 300     |
| `min-ttl`       | Minimum TTL this domain will accept      | 30      |
| `max-ttl`       | Maximum TTL this domain will honor       | 3600    |

Implementations MUST respect published TTL values. When DNS records are
unavailable, implementations SHOULD use the default values above.

### 3.2 Caching Rules

Servers MAY cache established sessions up to the TTL. Cached sessions are
keyed by `session_id`. Session IDs MUST be unique per session even for
the same client.

Clients SHOULD NOT reuse sessions beyond their TTL. Messages sent on an
expired session MUST be rejected by the server with an explicit reason code.

Servers MAY extend a session's lifetime with each valid message exchange,
up to the original TTL duration.

---

## 4. Session Invalidation and Blocking

Session invalidation in SEMP is a local server concern. There is no published
invalidation message, no gossip, and no network-level invalidation protocol.
When a server invalidates a session, whether due to a block, a security event,
or expiry, it simply updates its local state and enforces the consequence on
subsequent interactions.

### 4.1 Reason Codes

All rejections MUST carry a machine-readable reason code. The following reason
codes are defined for session and envelope rejection:

| Reason code          | Meaning                                                                 |
|----------------------|-------------------------------------------------------------------------|
| `blocked`            | The sender or their domain is blocked. No session will be accepted.     |
| `handshake_invalid`  | The session referenced by the envelope has been invalidated.            |
| `handshake_expired`  | The session TTL has elapsed. A new handshake is required.               |
| `no_session`         | The envelope does not reference a valid session identifier.             |
| `auth_failed`        | Identity or authentication verification failed during handshake.        |
| `policy_violation`   | The request violates a server or federation policy.                     |
| `rate_limited`       | The sender has exceeded the server's rate limits.                       |
| `challenge_failed`    | The submitted challenge solution was invalid or the challenge expired. The sender MAY request a new challenge by restarting the handshake. |
| `server_at_capacity` | The server has reached its concurrent session limit per `SESSION.md` section 2.5.3. The sender SHOULD retry after a delay. |

Additional reason codes MAY be defined in extensions using the standard
namespacing convention.

### 4.2 Blocking Behavior

Servers MUST check block lists before processing a handshake `init` message.
This check occurs before any session resources are allocated.

- A blocked sender's `init` MUST be rejected immediately with `step=rejected`
  and `reason_code: "blocked"`.
- A blocked sender's envelope, if somehow received on an existing session, MUST
  be rejected with `reason_code: "blocked"`.
- Blocked senders MUST NOT be silently dropped or left waiting.

When a block is applied after a session is already established, the server
invalidates the session locally. No message is sent to the blocked party. All
subsequent envelopes referencing that session are rejected with
`reason_code: "blocked"`. All subsequent handshake attempts are rejected with
`reason_code: "blocked"`.

### 4.3 Non-Block Invalidation

When a session is invalidated for a reason other than a block (for example,
a key revocation event or a security policy change), subsequent envelopes
referencing that session MUST be rejected with `reason_code: "handshake_invalid"`.
The sender server MUST treat this as a signal to establish a new session and
resend the envelope.

### 4.4 Envelope-Session Binding

Every envelope MUST reference a valid session via `postmark.session_id`. An
envelope without a `session_id` MUST be rejected with `reason_code: "no_session"`.

The receiving server verifies that the `session_id` in the postmark corresponds
to an active, non-expired, non-invalidated session before processing the
envelope further. This check occurs after seal verification and expiry checks,
and before any content is processed.

### 4.5 Sender Server Retry Responsibility

The sender server is responsible for retry logic. Envelope rejections that
indicate a recoverable session state MUST trigger automatic retry:

| Received reason code  | Sender server action                                      |
|-----------------------|-----------------------------------------------------------|
| `handshake_expired`   | Establish a new session, resend the envelope.             |
| `handshake_invalid`   | Establish a new session, resend the envelope.             |
| `no_session`          | Establish a session, resend the envelope.                 |
| `blocked`             | Do not retry. Surface the failure to the sending user.    |
| `rate_limited`        | Retry after exponential backoff.                          |
| `challenge_failed`  | Restart the handshake from step 1 to obtain a fresh challenge. Do not surface to the sending user unless retries are exhausted. |
| `server_at_capacity`  | Retry after exponential backoff. Do not surface to the sending user unless retries are exhausted. |
| `auth_failed`         | Do not retry automatically. Surface to the sending user.  |

The sender server MUST NOT retry indefinitely. A maximum retry count and
backoff ceiling SHOULD be configured per operator policy.

### 4.6 Client Delivery Transport

How a server notifies a client that incoming messages are waiting is outside
the scope of this specification. SEMP is an application-layer protocol and is
not opinionated about transport wakeup mechanisms. Implementations MAY use
persistent WebSocket connections, long polling, or platform notification
services such as APNs or FCM, consistent with the approach used by similar
applications. The client always initiates the handshake with its home server
regardless of what wakeup mechanism triggered the connection.

---

## 5. Federation Handshake

The server-to-server handshake follows the same four-message structure as the
client-to-server handshake. The key differences are:

- Both parties authenticate as domains, not as individual users
- Domain ownership is proved cryptographically via multiple methods
- Federation policies are negotiated during the handshake
- Sessions are typically longer-lived

### 5.1 Sequence

```
Server A                                        Server B
  |                                               |
  |--- 1. type=SEMP_HANDSHAKE                 --> |
  |        step=init, party=server                |
  |   (ephemeral key, capabilities, domain proof) |
  |                                               |
  | <-- 2. type=SEMP_HANDSHAKE                --- |
  |         step=response, party=server           |
  |   (ephemeral key, negotiated params,          |
  |    domain verification result)               |
  |                                               |
  |   (both derive shared secret)                 |
  |                                               |
  |--- 3. type=SEMP_HANDSHAKE                 --> |
  |        step=confirm, party=server             |
  |   (confirmation hash, federation acceptance)  |
  |                                               |
  | <-- 4. type=SEMP_HANDSHAKE                --- |
  |         step=accepted, party=server           |
  |      OR step=rejected, party=server           |
  |                                               |
  |         FEDERATION SESSION ESTABLISHED        |
```

### 5.2 Message 1: init / server

Unlike the client init, the server init includes domain identity in plaintext.
Server-to-server connections are domain-to-domain by nature, so the initiating
domain is not a secret in a federated protocol. The privacy constraint that
applies to user identity does not apply here.

```json
{
    "type": "SEMP_HANDSHAKE",
    "step": "init",
    "party": "server",
    "version": "1.0.0",
    "nonce": "base64-random-32-bytes",
    "server_id": "originating-server-ulid",
    "server_domain": "example.com",
    "peer_configuration_revision": 17,
    "server_ephemeral_key": {
        "algorithm": "pq-kyber768-x25519",
        "key": "base64-encoded-ephemeral-public-key",
        "key_id": "ephemeral-key-fingerprint"
    },
    "server_identity_proof": {
        "key_id": "server-long-term-key-fingerprint",
        "signature": "signature-over-ephemeral-key-and-nonce"
    },
    "domain_proof": {
        "method": "dns-txt",
        "data": "verification-data-per-method"
    },
    "capabilities": {
        "encryption_algorithms": [
            "pq-kyber768-x25519",
            "x25519-chacha20-poly1305"
        ],
        "extensions": [
            "semp.dev/device-sync",
            "semp.dev/read-receipts",
            "semp.dev/message-expiry"
        ],
        "max_envelope_size": 52428800,
        "max_batch_size": 1000
    },
    "server_signature": "signature-over-entire-message",
    "extensions": {}
}
```

#### 5.2.1 Peer Configuration Revision

The `peer_configuration_revision` field carries the initiator's
cached revision of the responding peer's configuration document per
`DISCOVERY.md` section 3.5.1. On handshake processing the responder
compares the received value against its own current configuration
`revision`:

- If the values match, the initiator's cache is current; the handshake
  proceeds normally.
- If the initiator's value is less than the responder's current
  revision, the initiator's cache is stale. The responder MUST still
  accept the handshake but SHOULD emit a `SEMP_CONFIGURATION_UPDATE`
  message over the established session at first opportunity
  (`DISCOVERY.md` section 3.5.4). The initiator, on observing the
  mismatch in its own message 2 processing (the responder echoes its
  own current revision in the response), MUST re-fetch the
  configuration before relying on any cached endpoint or capability
  of the responder for subsequent operations.
- If the initiator's value is greater than the responder's current
  revision, one of the two peers has a broken cache. The responder
  MUST NOT roll its own revision forward on the basis of an
  initiator's claim; revision is owned by the publishing operator.
  The responder MUST proceed with the handshake under its own
  revision and MAY log the anomaly.

The initiator MAY omit `peer_configuration_revision` (value `null` or
field absent) when it has no cached configuration for the responder,
for example during first-ever federation. A responder that receives
no revision hint treats the initiator's cache as empty and
unambiguously current.

Response messages (section 5.5) echo the responder's current
`revision` in a `server_configuration_revision` field so the
initiator can detect staleness symmetrically.

#### 5.2.2 Federation Is Single-Mode with Per-Peer Policy

SEMP defines a single federation mode. The protocol does not encode
named federation types such as "full" or "relay" at the handshake
layer. Every federation session grants the same baseline: establish a
session and exchange envelopes subject to the standard delivery
pipeline (`DELIVERY.md` section 3).

Operators express per-peer restrictions through local policy rather
than through a wire-level federation-type field. Typical policies
include accept from specific domains only, reject envelopes matching
specific patterns, rate-limit submissions, or require additional
challenges. These are local-policy decisions made by each operator
independently; they are not negotiated in the handshake.

Capability differences (supported algorithms, supported extensions,
maximum envelope size) continue to be negotiated via the
`capabilities` object in this section. Capability negotiation is
distinct from policy and remains on the wire.

### 5.3 Domain Key Bootstrap

Before a federation handshake can proceed, both sides need each other's domain
signing public key to verify handshake message signatures. The domain key
bootstrap follows this order:

1. Check the local cache for the peer's domain key. If present and not expired,
   use it.
2. Resolve `_semp._tcp.<peer-domain>` via DNS SRV to find the peer's server
   hostname (see `DISCOVERY.md` section 2.1).
3. Fetch `https://<srv-target>/.well-known/semp/configuration` from the
   resolved hostname, read `endpoints.domain_keys` from the configuration
   document, and fetch the domain keys from that URL (see `DISCOVERY.md`
   section 3.3). The HTTPS certificate chain serves as the trust anchor.
4. Store the fetched domain key in the local cache for future handshakes.

This bootstrap is performed lazily: the initiating server fetches the peer's
domain key the first time it needs to federate with that domain. Subsequent
handshakes (including rekeys) use the cached key.

When the SRV target hostname differs from the email domain (e.g. SRV target
`semp.example.com` for email domain `example.com`), the well-known fetch
MUST use the SRV target hostname, not the email domain. See `DISCOVERY.md`
section 5.5.

### 5.4 Domain Verification Methods

Server-to-server handshakes require domain ownership verification. SEMP
supports multiple methods, ordered by operator preference consistent with the
extensibility principle:

#### DNS TXT Record

```
_semp-verify.example.com.  IN  TXT  "v=semp1;id=<server_id>;s=<signature>"
```

#### Certificate Verification

Domain ownership established via the TLS certificate presented during the
underlying mTLS connection. The certificate common name or SAN MUST match
`server_domain`.

#### Configuration Verify Endpoint

The initiating server advertises a `verify` endpoint in its configuration
document (`DISCOVERY.md` section 3.1.1). The verification token is
derived from the server's identity proof signature and appended to the
advertised base URL:

```
GET <endpoints.verify><verification-token>
```

The responding server resolves the initiator's configuration document,
reads `endpoints.verify`, and fetches the resulting URL to confirm domain
control. A server that does not advertise a `verify` endpoint does not
support this verification method and MUST use certificate or DNS TXT
verification instead.

Servers MAY support multiple verification methods. The method used is declared
in `domain_proof.method` and MUST be verifiable by the receiving server before
message 2 is sent.

### 5.5 Message 2: response / server

```json
{
    "type": "SEMP_HANDSHAKE",
    "step": "response",
    "party": "server",
    "version": "1.0.0",
    "session_id": "server-b-generated-ulid",
    "client_nonce": "echoed-server-a-nonce",
    "server_nonce": "base64-random-32-bytes",
    "server_id": "responding-server-ulid",
    "server_domain": "otherdomain.com",
    "server_configuration_revision": 42,
    "server_ephemeral_key": {
        "algorithm": "pq-kyber768-x25519",
        "key": "base64-encoded-ephemeral-public-key",
        "key_id": "ephemeral-key-fingerprint"
    },
    "server_identity_proof": {
        "key_id": "server-long-term-key-fingerprint",
        "signature": "signature-over-ephemeral-key-and-nonces"
    },
    "domain_verification_result": {
        "status": "verified",
        "method": "dns-txt"
    },
    "negotiated": {
        "encryption_algorithm": "pq-kyber768-x25519",
        "extensions": [
            "semp.dev/device-sync",
            "semp.dev/read-receipts"
        ],
        "max_envelope_size": 26214400,
        "max_batch_size": 500
    },
    "federation_policy": {
        "message_retention": "7d",
        "user_discovery": "allowed",
        "relay_allowed": true
    },
    "server_signature": "signature-over-entire-message",
    "extensions": {}
}
```

### 5.6 Message 3: confirm / server

```json
{
    "type": "SEMP_HANDSHAKE",
    "step": "confirm",
    "party": "server",
    "version": "1.0.0",
    "session_id": "echoed-session-id",
    "confirmation_hash": "hash-of-messages-1-and-2",
    "federation_acceptance": {
        "accepted": true,
        "policy_acknowledged": true
    },
    "server_signature": "signature-over-entire-message",
    "extensions": {}
}
```

The `federation_acceptance.policy_acknowledged` field MUST be `true` if the
initiating server accepts the federation policy terms returned in message 2.
If the policy is unacceptable, the initiating server MUST send
`accepted: false` with a reason rather than silently closing the connection.

### 5.7 Message 4: accepted / server  or  rejected / server

```json
{
    "type": "SEMP_HANDSHAKE",
    "step": "accepted",
    "party": "server",
    "version": "1.0.0",
    "session_id": "echoed-session-id",
    "status": "accepted",
    "server_signature": "signature-over-entire-message",
    "extensions": {}
}
```

On rejection, `step` is `"rejected"` and the message carries `reason_code` and `reason` fields, consistent with the client handshake `rejected` structure.

---

## 6. Security Considerations

### 6.1 Identity Confidentiality

Client identity is never transmitted in plaintext. The init message carries
no identifying information. The identity proof is encrypted under the session
secret established by ephemeral key exchange. Passive observers MUST NOT be able to
determine who initiated a session.

The residual leak is that a connection to a specific server was made. This is
documented in `DESIGN.md` section 2.6 as an irreducible minimum for federated
messaging. Operators with stronger requirements MAY proxy connections through
intermediaries.

### 6.2 Replay Prevention

Each handshake uses a fresh client nonce and server nonce. The confirmation
hash in message 3 binds the identity proof to the specific exchange that
preceded it. A captured message 3 from one session MUST NOT be accepted for replay in
a different session.

The nonce MUST be cryptographically random, minimum 32 bytes. Implementations
MUST reject handshakes with nonces they have seen within the session TTL window.

### 6.3 Downgrade Prevention

Capability negotiation is covered by the confirmation hash. A man-in-the-middle
that modifies the capabilities in message 1 to downgrade the negotiated
algorithm will cause the confirmation hash in message 3 to fail verification,
aborting the handshake.

The `capabilities` and `extensions` fields in handshake messages also serve as
the primary negotiation point for protocol extensions. Extension support
advertised in the init message informs the server's negotiation response.
Required extensions (`EXTENSIONS.md` §3) that are not mutually supported
result in rejection with reason code `extension_unsupported`. The formal
extension negotiation rules, criticality signaling, and size constraints are
defined in `EXTENSIONS.md`.

### 6.4 Algorithm Selection

Servers MUST prefer the strongest mutually supported algorithm. If a client
offers both `pq-kyber768-x25519` and `x25519-chacha20-poly1305`, the server
MUST select the post-quantum hybrid unless it cannot support it. Selecting a
weaker algorithm when a stronger one is available is a policy violation.

### 6.5 Clock Synchronization

Timestamp validation in handshake messages, challenge expiry, and
session lifetime is subject to the clock tolerance, authority, and
fail-closed rules in `CONFORMANCE.md` section 9.3.

### 6.6 Handshake Timeout

Implementations MUST enforce a timeout on handshake completion. If a handshake
is not completed within the timeout, the connection MUST be closed. A timeout
of 30 seconds is RECOMMENDED. Incomplete handshakes MUST NOT consume session
resources beyond what is needed to enforce the timeout.

---

## 7. Privacy Considerations

The client-to-server handshake exposes the following to a passive observer:

- A connection was made to a SEMP server at a specific domain
- The protocol version and transport type
- The set of extensions the client supports (from message 1 capabilities)

It does not expose:

- Who made the connection
- Who they intend to send to
- Any message content

A distinctive capability set in message 1 could fingerprint a specific client
implementation. Clients SHOULD advertise all capabilities they support rather
than a minimal subset, to reduce fingerprinting surface.

---

## 8. Relationship to Other Specifications

| Specification | Relationship |
|---|---|
| `DESIGN.md` | Governing principles. Privacy constraint from section 2.1 implements DESIGN.md section 2.6. |
| `KEY.md` | Long-term keys used in identity proofs are defined and published per the key specification. Scoped device certificates (section 10.3) affect post-handshake authorization. |
| `DISCOVERY.md` | Discovery determines server addresses and declared auth methods before handshake begins. |
| `ENVELOPE.md` | Envelopes are exchanged within sessions established by this handshake. |
| `DELIVERY.md` | Block list checks occur at message 1 reception, before any session resources are allocated. |
| `SESSION.md` | Defines the forward secrecy lifecycle of the session keys derived in section 2.4, the `SEMP_REKEY` protocol introduced in section 1.4, and key erasure requirements. |
| `REPUTATION.md` | Challenge criteria (section 8.3) determine when `challenge` is issued. PoW difficulty calibration is defined there. |
| `EXTENSIONS.md` | Extension negotiation rules, criticality signaling, and size constraints for handshake-layer extensions. |

---

*This document is an Internet-Draft. It is subject to revision prior to
finalization as a stable specification.*