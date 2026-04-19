# SEMP Key Specification

**Sealed Envelope Messaging Protocol**  
Status: Internet-Draft  
Version: 0.1.0  
Related: `DESIGN.md`, `HANDSHAKE.md`, `ENVELOPE.md`, `DISCOVERY.md`

---

## Abstract

The SEMP key specification defines how cryptographic keys are typed, discovered,
published, verified, stored, rotated, revoked, and synchronized across devices.
Keys are the root of identity and trust in SEMP. This document covers both
domain keys (which establish server identity and sign envelopes) and user keys
(which encrypt message content for individual recipients).

---

## 1. Key Types

SEMP defines five key types, each serving a distinct purpose:

| Key type   | Scope  | Purpose                                                              |
|------------|--------|----------------------------------------------------------------------|
| `domain`   | Server | Identifies a SEMP server. Produces `seal.signature` on envelopes and signs handshake messages. Provides routing-layer integrity, verifiable by any server without prior session. Published via DNS/DANE. |
| `identity` | User   | Long-term key establishing a user's identity. Signs handshake identity proofs. |
| `encryption` | User | Used to encrypt symmetric keys in the envelope seal. One per active device or key rotation period. |
| `device`   | User   | Device-specific key used to authorize and synchronize keys across devices. |
| `session`  | Ephemeral | Generated fresh per handshake. Used for the shared session secret. Never stored. |

Session keys are defined in `HANDSHAKE.md` and are not
discoverable; they exist only within a handshake exchange. All other key
types are covered by this specification.

### 1.1 Domain Keys vs User Keys

Domain keys and user keys serve different roles and are published through
different mechanisms.

**Domain keys** are controlled by the server operator. They sign envelopes at
the postmark/seal layer, authenticate the server during handshakes, and
establish the server's identity to the rest of the network. They are published
via DNS and DANE, making them verifiable without contacting the server directly.

**User keys** are controlled by individual users. Identity keys sign
authentication proofs during handshakes. Encryption keys are used by senders
to wrap the symmetric key in the envelope seal. They are published via the
well-known URI at the user's home server.

This separation means a server operator cannot impersonate a user's encryption
key, and a user cannot forge a domain-level signature. The two trust chains are
independent.

---

## 2. Domain Key Publication

### 2.1 DNS/DANE (Primary)

Domain keys are published via DANE TLSA records, making them verifiable through
the DNS infrastructure independently of any SEMP-specific lookup:

```
_semp-key._tcp.example.com.  IN  TLSA  3 0 1  <hash-of-domain-signing-key>
```

The TLSA record parameters follow RFC 6698:
- `3`: Certificate usage (domain-issued)
- `0`: Selector (full key)
- `1`: Matching type (SHA-256 hash)

DNSSEC is RECOMMENDED for domains publishing SEMP key records. Without DNSSEC,
the DNS record is unauthenticated and susceptible to spoofing.

### 2.2 Relationship to Session MAC

The domain key provides routing-layer integrity via `seal.signature`. It is
independently verifiable by any server that can fetch the sender's domain key.
It does not prove that a valid session exists.

The session MAC (`seal.session_mac`) provides delivery-layer session enforcement.
It is computed using `K_env_mac` derived during the handshake and is verifiable
only by the receiving server. Together they form a two-layer proof: integrity
for the network, session enforcement for delivery. See
`ENVELOPE.md` section 4.3.

### 2.3 Configuration Endpoint (Fallback)

When DNS/DANE is unavailable or unverifiable, the domain key is discoverable
through the `domain_keys` endpoint advertised in the server's configuration
document (`DISCOVERY.md` section 3.1.1, 3.3):

```
GET <endpoints.domain_keys>
```

The hostname that serves the configuration document is the SRV target (e.g.
`semp.example.com`), not necessarily the email domain. See `DISCOVERY.md`
section 5.5 for how SRV targets map to configuration hostnames.

Response:

```json
{
    "type": "SEMP_DOMAIN_KEYS",
    "version": "1.0.0",
    "domain": "example.com",
    "signing_key": {
        "algorithm": "ed25519",
        "public_key": "base64-encoded-ed25519-public-key",
        "key_id": "sha256-fingerprint"
    },
    "encryption_key": {
        "algorithm": "x25519-chacha20-poly1305",
        "public_key": "base64-encoded-x25519-public-key",
        "key_id": "sha256-fingerprint"
    }
}
```

| Field            | Type     | Required | Description                              |
|------------------|----------|----------|------------------------------------------|
| `type`           | `string` | Yes      | MUST be `"SEMP_DOMAIN_KEYS"`             |
| `version`        | `string` | Yes      | SEMP protocol version (semver)           |
| `domain`         | `string` | Yes      | The email domain this server operates for |
| `signing_key`    | `object` | Yes      | The domain's Ed25519 signing public key   |
| `encryption_key` | `object` | Yes      | The domain's encryption public key        |

Each key object contains `algorithm`, `public_key` (base64-encoded), and `key_id`
(SHA-256 fingerprint of the raw public key bytes, hex-encoded).

The HTTPS certificate chain is the trust anchor. If the TLS certificate is valid
for the hostname, the domain keys it publishes are trusted. HTTPS and DNS are
roughly equivalent in domain ownership proof: both require control of the
domain. The difference is verifiability independence. A key published only via
the well-known URI cannot be verified without contacting the server. A key
corroborated by DNS/DANE can be verified independently via the DNS
infrastructure. Relying parties SHOULD cross-check against DNS/DANE records
where possible. Implementations MAY require DNS corroboration for
routing-layer verification.

---

## 3. User Key Publication

### 3.1 Configuration Endpoint (Primary)

User public keys are published at the user's home server through the `keys`
endpoint advertised in the server's configuration document (`DISCOVERY.md`
sections 3.1.1 and 3.4). The full fetch URL for a given user is the base URL
with the user's address appended:

```
GET <endpoints.keys><user@example.com>
```

Response:

```json
{
    "type": "SEMP_KEYS",
    "step": "response",
    "version": "1.0.0",
    "id": "echoed-request-id",
    "timestamp": "2025-06-10T19:56:34Z",
    "keys": [
        {
            "address": "user@example.com",
            "key_type": "identity",
            "algorithm": "ed25519",
            "public_key": "base64-encoded-public-key",
            "key_id": "key-fingerprint",
            "created": "2025-01-15T08:30:00Z",
            "expires": "2026-01-15T08:30:00Z",
            "signatures": [
                {
                    "signer": "example.com",
                    "key_id": "domain-key-fingerprint",
                    "value": "base64-domain-signature",
                    "timestamp": "2025-01-15T08:30:05Z"
                }
            ]
        },
        {
            "address": "user@example.com",
            "key_type": "encryption",
            "algorithm": "pq-kyber768-x25519",
            "public_key": "base64-encoded-public-key",
            "key_id": "key-fingerprint",
            "created": "2025-01-15T08:30:00Z",
            "expires": "2026-01-15T08:30:00Z",
            "signatures": [
                {
                    "signer": "user@example.com",
                    "key_id": "identity-key-fingerprint",
                    "value": "base64-self-signature",
                    "timestamp": "2025-01-15T08:30:10Z"
                }
            ]
        }
    ],
    "signature": {
        "algorithm": "ed25519",
        "key_id": "domain-key-fingerprint",
        "value": "base64-signature-over-response"
    }
}
```

The response is signed by the serving domain's key. Recipients MUST verify
this signature using the domain's published domain key before trusting the
user keys.

For batch requests, the request is a `POST` to the `endpoints.keys` base URL
with no address suffix. A server that supports batch fetch MUST accept a
`POST` at `<endpoints.keys>`. A server that does not support batch fetch
MUST respond with HTTP 405. The request body is the standard `SEMP_KEYS`
request message:

```json
{
    "type": "SEMP_KEYS",
    "step": "request",
    "version": "1.0.0",
    "id": "request-ulid",
    "timestamp": "2025-06-10T19:49:15Z",
    "addresses": [
        "user1@example.com",
        "user2@example.com"
    ],
    "key_types": ["identity", "encryption"],
    "extensions": {}
}
```

### 3.2 First-Contact Policy

The `SEMP_KEYS` response MAY include a `first_contact_policy` block per
key record subject. The policy advises senders that have no prior
correspondence with the subject what additional friction the recipient's
home server will apply. Publication of the policy is opt-in; absent
publication, senders MUST assume `mode: "open"`.

```json
{
    "type": "SEMP_KEYS",
    "step": "response",
    "version": "1.0.0",
    "id": "echoed-request-id",
    "timestamp": "2025-06-10T19:56:34Z",
    "keys": [ ],
    "first_contact_policy": {
        "mode": "challenge",
        "challenge_type": "proof_of_work",
        "parameters": {
            "algorithm": "sha256",
            "difficulty": 22
        }
    },
    "signature": { }
}
```

| Field            | Type              | Required               | Description                                                                  |
|------------------|-------------------|------------------------|------------------------------------------------------------------------------|
| `mode`           | `string`          | Yes                    | One of: `open`, `challenge`. See section 3.2.1.                              |
| `challenge_type` | `string`          | When `mode == challenge` | Identifier of the challenge type the recipient's home server will apply on first contact. See section 3.2.2. |
| `parameters`     | `object`          | When `mode == challenge` | Challenge-type-specific parameters. Schema is defined per challenge type.    |

#### 3.2.1 Modes

| Mode        | Behavior                                                                                                    |
|-------------|-------------------------------------------------------------------------------------------------------------|
| `open`      | No first-contact friction. All envelopes proceed through the standard delivery pipeline.                    |
| `challenge` | First-contact envelopes from unknown sender domains MUST satisfy the challenge identified by `challenge_type`. Satisfaction evidence is carried in `seal.first_contact_token` per `HANDSHAKE.md` section 2.2a.4. |

#### 3.2.2 Challenge Types

The set of defined `challenge_type` values extends over time. This
revision defines one:

| `challenge_type`   | Status | Defined in                           | Parameters                                    |
|--------------------|--------|--------------------------------------|-----------------------------------------------|
| `proof_of_work`    | Core   | `HANDSHAKE.md` section 2.2a.2        | `algorithm` (string), `difficulty` (integer). |

A sender's home server encountering a `challenge_type` it does not
recognize MUST treat the policy as non-satisfiable by that sender and
MUST surface the envelope as undeliverable, not silently downgrade to
`open`. Future challenge types (such as `invite_token`, human
verification, or third-party identity proof) MAY be added by subsequent
revisions or by published extensions using the standard namespacing
convention in `EXTENSIONS.md`.

A recipient server MUST NOT announce a `challenge_type` it is not
prepared to verify. A sender server that satisfies the challenge MUST
expect the recipient server to validate the token per the rules of the
challenge type.

#### 3.2.3 Caching and Enforcement

A sender's home server fetching the recipient's key record MUST cache the
`first_contact_policy` alongside the key record and MUST honor it when
composing envelopes to that recipient.

The recipient's home server MUST enforce the published policy regardless
of what the sender's server caches. The published policy is advisory to
senders; it is normative to the recipient server.

#### 3.2.4 Indistinguishability

A recipient server MUST publish the same `first_contact_policy` for all
addresses on its domain that have published any policy at all, OR MUST
publish no policy and apply a per-recipient policy internally. A
per-address policy publication that varies by address would constitute
an existence oracle. See `DESIGN.md` section 2.7.

When a recipient has no published key record, the home server SHOULD
behave as if the recipient's policy were `mode: "challenge"` with
`challenge_type: "proof_of_work"` at the operator's default difficulty,
in order to prevent enumeration via missing-key inference.

### 3.3 DNS-Based User Key Publication (Future Consideration)

Whether user keys can be published directly in DNS (for example via CERT or
URI resource records) is an open question. DNS-based user key publication
would allow key discovery without contacting the user's home server, reducing
the privacy surface of the well-known URI fetch. However, DNS record sizes,
key rotation frequency, and the operational complexity of per-user DNS records
present practical challenges. This is a candidate for a future revision of this
specification.

---

## 4. Key Request and Response

### 4.1 Key Request

Key requests are anonymous by default. There is no `requester` field. The
querying server is identified only by the TLS connection at the domain level,
not at the user level.

```json
{
    "type": "SEMP_KEYS",
    "step": "request",
    "version": "1.0.0",
    "id": "request-ulid",
    "timestamp": "2025-06-10T19:49:15Z",
    "addresses": [
        "user1@example.com",
        "user2@example.com"
    ],
    "key_types": ["identity", "encryption"],
    "extensions": {}
}
```

Servers MAY rate-limit anonymous key requests. Authenticated requests MAY be
declared in `extensions` using the same pattern as discovery:

```json
"extensions": {
    "semp.dev/auth": {
        "method": "domain_key",
        "key_id": "querying-server-key-fingerprint",
        "signature": "base64-signature-over-request-id-and-timestamp"
    }
}
```

Servers MUST NOT require authenticated requests as a condition of publishing
public keys. Public keys are by definition public.

### 4.2 Key Request Fields

| Field       | Type     | Required | Description                                                          |
|-------------|----------|----------|----------------------------------------------------------------------|
| `type`      | `string` | Yes      | MUST be `"SEMP_KEYS"`                                                |
| `step`      | `string` | Yes      | MUST be `"request"`                                                  |
| `version`   | `string` | Yes      | SEMP protocol version (semver)                                       |
| `id`        | `string` | Yes      | Unique request identifier. ULID RECOMMENDED.                         |
| `timestamp` | `string` | Yes      | ISO 8601 UTC timestamp.                                              |
| `addresses` | `array`  | Yes      | Addresses whose keys are requested. MAY include noise addresses.     |
| `key_types` | `array`  | No       | Key types requested. If absent, all current keys are returned.       |
| `extensions`| `object` | No       | Optional authenticated request. See section 4.1.                     |

### 4.3 Key Response Fields

| Field       | Type     | Required | Description                                                          |
|-------------|----------|----------|----------------------------------------------------------------------|
| `type`      | `string` | Yes      | MUST be `"SEMP_KEYS"`                                                |
| `step`      | `string` | Yes      | MUST be `"response"`                                                 |
| `version`   | `string` | Yes      | SEMP protocol version (semver)                                       |
| `id`        | `string` | Yes      | Echo of request `id`.                                                |
| `timestamp` | `string` | Yes      | ISO 8601 UTC timestamp.                                              |
| `keys`      | `array`  | Yes      | Key records. See section 4.4.                                        |
| `signature` | `object` | Yes      | Signature over the response using the serving domain's key.          |
| `extensions`| `object` | No       | Response extensions.                                                 |

### 4.4 Key Record Fields

| Field        | Type     | Required | Description                                                      |
|--------------|----------|----------|------------------------------------------------------------------|
| `address`    | `string` | Yes      | The address this key belongs to.                                 |
| `key_type`   | `string` | Yes      | One of: `identity`, `encryption`, `device`, `domain`.           |
| `algorithm`  | `string` | Yes      | Cryptographic algorithm identifier.                              |
| `public_key` | `string` | Yes      | Base64-encoded public key material.                              |
| `key_id`     | `string` | Yes      | Key fingerprint. Derived as SHA-256 of the public key bytes.     |
| `created`    | `string` | Yes      | ISO 8601 UTC creation timestamp.                                 |
| `expires`    | `string` | Yes      | ISO 8601 UTC expiry timestamp.                                   |
| `signatures` | `array`  | No       | Web of trust signatures. See section 5.                          |

---

## 5. Key Verification

### 5.1 Domain Signature

Every user key response is signed by the serving domain. This is the baseline
verification: the domain vouches that the keys it publishes for its users are
the keys those users registered. Relying parties MUST verify the domain
signature before trusting any key material.

### 5.2 Self-Signature

Encryption keys SHOULD be self-signed by the user's identity key. This provides
an additional binding: not only has the domain published this key, but the user
whose identity key is trusted has also attested to it. Relying parties SHOULD
verify self-signatures where present.

### 5.3 Web of Trust

Additional trust signals may be attached to a key as third-party signatures:

```json
"signatures": [
    {
        "signer": "trusted@other-domain.com",
        "key_id": "signer-identity-key-fingerprint",
        "value": "base64-signature",
        "timestamp": "2025-02-20T14:15:30Z",
        "trust_level": "high"
    }
]
```

Web of trust signatures are informational. Relying parties MAY use them to
increase confidence in a key. They MUST NOT be the sole basis for trusting a
key; domain and self-signatures are required first.

### 5.4 Out-of-Band Verification

For high-trust relationships, users SHOULD verify key fingerprints out of band:

- Safety numbers displayed in the client UI (similar to Signal)
- QR code scanning between devices or users
- Out-of-band verification phrases read aloud

Out-of-band verification is the strongest assurance available and is RECOMMENDED
for sensitive correspondence.

### 5.5 Domain Verification via DANE

Domain keys SHOULD be cross-checked against DANE TLSA records where DNSSEC is
available. A domain key retrieved from the well-known URI that matches the DANE
record has the highest available assurance level. A mismatch MUST be treated as
a potential compromise and SHOULD be surfaced to the operator.

---

## 6. Key Fetching Mechanisms

Fetching a public key before sending reveals communication intent: an observer
can infer that the querying server intends to send a message to the target.
SEMP mitigates this through multiple fetching mechanisms with different privacy
tradeoffs.

### 6.1 Available Mechanisms

| Mechanism                 | Privacy  | Latency       | Infrastructure cost |
|---------------------------|----------|---------------|---------------------|
| Speculative batch crawling | High    | Low (cached)  | High                |
| Third-party key relay      | Medium  | Medium        | Medium              |
| Direct well-known fetch    | Low     | Low           | Low                 |

**Speculative batch crawling**:  the server proactively fetches and caches keys
from domains it interacts with on a schedule, independent of any pending
message. The fetch is decoupled from the send intent. An observer cannot infer
from a key fetch that a message is imminent.

**Third-party key relay**:  the fetch is proxied through a trusted intermediary.
The target domain sees the relay's identity, not the querying server's. The
relay learns the querying server and the target but not the purpose.

**Direct well-known fetch**:  keys are fetched on demand from the target
domain's well-known URI immediately before sending. Low infrastructure cost but
the timing correlation between fetch and send is observable.

### 6.2 Operator Configuration

Operators configure which mechanisms are enabled and their fallback order.
The protocol does not mandate a default order. Each mechanism has documented
tradeoffs; operators choose based on their threat model and infrastructure
capacity.

A future revision of this specification MAY define a recommended default order
to improve interoperability and consistency across implementations.

### 6.3 Client Key Proxy

Clients do not fetch keys from remote domains directly. Per the connection
model in `HANDSHAKE.md` section 1.2, clients only connect to their home server.
When a client needs recipient keys for envelope composition, it sends a
`SEMP_KEYS` message with `step: request` to its home server, which fulfills
the request using whatever fetching mechanism its operator has configured
(section 6.1).

The client-facing key request protocol is defined in `CLIENT.md` section 5.4.
The home server acts as a proxy: it fetches keys from the remote domain's
well-known URI (or from its cache), and returns them to the client with the
remote domain's original signature intact. This allows the client to verify
key authenticity against the remote domain's published domain key without
connecting to the remote domain directly.

This design preserves the privacy benefits of server-level fetching (the
client's identity is never revealed to the remote domain) while allowing the
client to perform all cryptographic verification locally.

---

## 7. Key Rotation

### 7.1 Rotation Schedule

SEMP recommends the following rotation intervals:

| Key type     | Recommended rotation interval |
|--------------|-------------------------------|
| `domain`     | 12–24 months                  |
| `identity`   | 12–24 months                  |
| `encryption` | 6–12 months                   |
| `device`     | On device change or compromise |
| `session`    | Per handshake (automatic)     |

These are recommendations. Operators and users MAY rotate more frequently.
Rotation MUST follow the publication and revocation process defined in sections
2, 3, and 8.

### 7.2 Rotation Process

1. Generate the new key pair.
2. Publish the new public key at the appropriate endpoint (DNS/DANE for domain
   keys, well-known URI for user keys).
3. Issue a revocation record for the old key citing `superseded`, with
   `replacement_key_id` pointing to the new key.
4. Continue accepting messages encrypted under the old key for a transition
   period to avoid delivery failures during cache propagation. The transition
   period SHOULD match the maximum expected cache TTL.
5. After the transition period, the old private key MAY be securely erased.

---

## 8. Key Revocation

### 8.1 Revocation Record

```json
{
    "type": "SEMP_KEY_REVOCATION",
    "version": "1.0.0",
    "revoked_keys": [
        {
            "key_id": "key-fingerprint",
            "address": "user@example.com",
            "reason": "key_compromise",
            "revoked_at": "2025-06-10T19:49:15Z",
            "replacement_key_id": "new-key-fingerprint"
        }
    ],
    "signature": {
        "algorithm": "ed25519",
        "key_id": "identity-or-domain-key-fingerprint",
        "value": "base64-signature"
    }
}
```

### 8.2 Revocation Reasons

| Reason                   | Meaning                                                     |
|--------------------------|-------------------------------------------------------------|
| `key_compromise`         | Key has been or is suspected of being compromised.          |
| `superseded`             | Key has been replaced by a newer key.                       |
| `cessation_of_operation` | The user or domain no longer uses this key.                 |
| `temporary_hold`         | Temporary suspension pending investigation.                  |

### 8.3 Revocation Publication

Revocation is pull-based. Servers have no obligation to push revocation notices
to other parties. The obligation is to publish: a revocation record MUST be
made discoverable at the same endpoint where the key was originally published,
and MUST be returned in key responses for the revoked key's identifier.

When a sender fetches keys and receives a revocation record, it MUST NOT use
the revoked key. If a `replacement_key_id` is present, the sender SHOULD fetch
the replacement key and use it instead.

Senders that have cached a key that is later found to be revoked MUST invalidate
the cached entry and re-fetch before sending.

### 8.4 Revocation Response

When a revoked key is requested, the response includes the key record with a
`revocation` field:

```json
{
    "address": "user@example.com",
    "key_type": "encryption",
    "key_id": "revoked-key-fingerprint",
    "revocation": {
        "reason": "key_compromise",
        "revoked_at": "2025-06-10T19:49:15Z",
        "replacement_key_id": "new-key-fingerprint"
    }
}
```

Servers MUST retain revocation records indefinitely. A revoked key that
disappears from the published record cannot be distinguished from a key that
never existed, which opens substitution attack vectors.

---

## 9. Private Key Storage

### 9.1 Storage Requirements

Private keys MUST be encrypted at rest. Access MUST be gated behind user
authentication (password, biometric, or hardware token). Implementations SHOULD
use hardware security modules (HSM, TPM, Secure Enclave) where available.

### 9.2 Storage Schema

`SEMP_KEY_STORE` is a local storage format, not a wire message. It defines
the on-device representation of private key material.

```json
{
    "type": "SEMP_KEY_STORE",
    "format_version": "1.0",
    "key_entries": [
        {
            "key_id": "key-fingerprint",
            "key_type": "identity",
            "algorithm": "ed25519",
            "public_key": "base64-encoded-public-key",
            "encrypted_private_key": "base64-encrypted-key-material",
            "encryption_method": {
                "algorithm": "aes-256-gcm",
                "iv": "base64-iv",
                "key_derivation": "argon2id",
                "parameters": {
                    "memory": 65536,
                    "iterations": 3,
                    "parallelism": 4
                }
            },
            "created": "2025-01-15T08:30:00Z",
            "last_used": "2025-06-10T19:30:00Z",
            "metadata": {
                "device_id": "device-ulid",
                "purpose": "primary-identity"
            }
        }
    ]
}
```

### 9.3 Key Backup and Recovery

Account recovery (restoration of identity and encryption keys after loss of
all devices) is specified in `RECOVERY.md` as a RECOMMENDED optional core module.
Two mechanisms are defined there: server-assisted encrypted backup and
Shamir device-split backup. Clients and servers claiming recovery support
MUST comply with `RECOVERY.md`.

Loss of all backup copies, including the recovery secret and the required
threshold of Shamir device shares, means permanent loss of the account's
private key material. SEMP does not provide a recovery path that bypasses
user-held recovery material. A server operator MUST NOT possess, broker,
or gate recovery secrets.

---

## 10. Multi-Device Support

### 10.1 Device Registration

```json
{
    "type": "SEMP_DEVICE",
    "step": "register",
    "version": "1.0.0",
    "user_id": "user@example.com",
    "device_id": "device-ulid",
    "device_name": "Alice's Laptop",
    "device_type": "computer",
    "device_public_key": "base64-device-public-key",
    "authorization": {
        "method": "qr_scan",
        "proof_of_possession": "signature-from-existing-device-over-new-device-key"
    },
    "timestamp": "2025-06-10T19:49:15Z"
}
```

### 10.2 Synchronization Flow

1. New device generates its own device key pair.
2. User authorizes the new device from an existing trusted device via QR code
   scan, verification code, or equivalent out-of-band confirmation.
3. Existing device encrypts the user's identity key under the new device's
   public key.
4. New device receives and decrypts the identity key.
5. New device generates its own encryption key pair and publishes it.
6. All registered devices are updated with the new device's information.

The authorization proof in step 2 MUST be a signature from an existing trusted
device over the new device's public key. A device registration without a valid
authorization proof MUST be rejected by the home server.

### 10.3 Scoped Device Certificates

A scoped device certificate authorizes a delegated device to act on
behalf of a user within a restricted permission scope. Delegated
devices include mailing list clients, spam filter clients, vacation
autoresponders, read-only viewers, and any other program that holds
its own device key and requires less than full-account authority.

The certificate is issued by a full-access device of the account (the
primary device). It binds the delegated device's public key to a
permission scope and a validity window. The home server enforces the
scope at envelope submission and at inbound delivery.

A full-access device is any device registered for the account that has
no scoped device certificate. Full-access devices have the implicit
authority to compose, receive, manage keys, manage block lists, and
register further devices.

#### 10.3.1 Certificate Schema and Signing

```json
{
    "type": "SEMP_DEVICE_CERTIFICATE",
    "version": "1.0.0",
    "device_id": "01JDELEGATE0000000000000000",
    "device_public_key": "base64-delegated-device-public-key",
    "account": "user@example.com",
    "issued_by": "01JPRIMARY00000000000000000",
    "issued_at": "2025-06-15T10:00:00Z",
    "expires_at": "2025-12-15T10:00:00Z",
    "scope": {
        "send": {
            "mode": "restricted",
            "allow": [
                { "type": "user", "address": "subscriber1@example.com" },
                { "type": "domain", "domain": "company.example" }
            ],
            "rate_limits": [
                { "period_seconds": 3600, "amount_allowed": 200 },
                { "period_seconds": 86400, "amount_allowed": 2000 }
            ]
        },
        "receive": { "mode": "none", "rate_limits": [], "delivery_stage": 1 },
        "blocklist": { "read": false, "write": false, "rate_limits": [] },
        "keys":      { "read": false, "write": false, "rate_limits": [] },
        "devices":   { "read": false, "write": false, "rate_limits": [] }
    },
    "signature": {
        "algorithm": "ed25519",
        "key_id": "primary-device-key-fingerprint",
        "value": "base64-signature"
    }
}
```

The certificate MUST be signed by the device key of a full-access
device (the issuer), identified in `issued_by`. The issuer MUST hold
a registered, non-revoked device key for the account at the time of
signing. The signature is computed over the canonical UTF-8 JSON
encoding of the certificate with `signature.value` set to `""`, per
the canonicalization rules in `ENVELOPE.md` section 4.3.

#### 10.3.2 Certificate Fields

| Field               | Type      | Required | Description                                                                                     |
|---------------------|-----------|----------|-------------------------------------------------------------------------------------------------|
| `type`              | `string`  | Yes      | MUST be `"SEMP_DEVICE_CERTIFICATE"`.                                                            |
| `version`           | `string`  | Yes      | Certificate format version (semver).                                                            |
| `device_id`         | `string`  | Yes      | Stable identifier of the delegated device. ULID RECOMMENDED.                                    |
| `device_public_key` | `string`  | Yes      | Base64-encoded public key of the delegated device.                                              |
| `account`           | `string`  | Yes      | Full SEMP address the delegated device is bound to.                                             |
| `issued_by`         | `string`  | Yes      | `device_id` of the issuing full-access device.                                                  |
| `issued_at`         | `string`  | Yes      | ISO 8601 UTC issuance timestamp.                                                                |
| `expires_at`        | `string`  | Yes      | ISO 8601 UTC expiry timestamp. Subject to the lifetime bounds in section 10.3.8.                |
| `scope`             | `object`  | Yes      | Permission scope. See section 10.3.3.                                                           |
| `signature`         | `object`  | Yes      | Issuer's signature over the canonical certificate bytes.                                        |

#### 10.3.3 Scope Object

The scope object has five fields, one per authorizable action class.
Every field is an object of uniform shape: a permission declaration
plus a `rate_limits` array. `send` and `receive` use the matcher
shape. `blocklist`, `keys`, and `devices` use the resource shape.

```json
{
    "send": {
        "mode": "restricted",
        "allow": [ { "type": "user", "address": "subscriber@example.com" } ],
        "rate_limits": [
            { "period_seconds": 3600,  "amount_allowed": 100 },
            { "period_seconds": 86400, "amount_allowed": 1000 }
        ]
    },
    "receive": {
        "mode": "unrestricted",
        "rate_limits": [],
        "delivery_stage": 1
    },
    "blocklist": {
        "read": true,
        "write": true,
        "rate_limits": [
            { "period_seconds": 86400, "amount_allowed": 50 }
        ]
    },
    "keys": {
        "read": false,
        "write": false,
        "rate_limits": []
    },
    "devices": {
        "read": true,
        "write": false,
        "rate_limits": []
    }
}
```

| Field       | Permission type        | Description                                                                        |
|-------------|------------------------|------------------------------------------------------------------------------------|
| `send`      | Matcher (§10.3.3.1)    | Recipients this device may send to.                                                |
| `receive`   | Matcher (§10.3.3.1)    | Senders whose envelopes this device may receive (matched against `brief.from`).    |
| `blocklist` | Resource (§10.3.3.2)   | Access to the account's block list (`DELIVERY.md` §5).                             |
| `keys`      | Resource (§10.3.3.2)   | Access to the account's key rotation history and per-device key metadata.          |
| `devices`   | Resource (§10.3.3.2)   | Access to the account's registered-devices list and their scoped certificates.     |

Every scope field above is REQUIRED, including its `rate_limits`
array (which MAY be empty). A certificate missing any field, or a
field missing its `rate_limits`, MUST be rejected at issuance with
`reason_code: "scope_invalid"`.

##### 10.3.3.1 Matcher Shape

`send` and `receive` use the matcher shape:

```json
{
    "mode": "restricted" | "unrestricted" | "denylist" | "none",
    "allow": [ { "type": "...", "..." } ],
    "deny":  [ { "type": "...", "..." } ],
    "rate_limits": [ { "period_seconds": N, "amount_allowed": N } ],
    "delivery_stage": 1
}
```

| `mode`         | Meaning                                                                                                  |
|----------------|----------------------------------------------------------------------------------------------------------|
| `unrestricted` | All peers are permitted. `allow` and `deny` MUST be absent or empty.                                     |
| `restricted`   | Only peers matching an entry in `allow` are permitted. `allow` MUST be present and non-empty. `deny` MUST be absent. |
| `denylist`     | All peers are permitted except those matching an entry in `deny`. `deny` MUST be present and non-empty. `allow` MUST be absent. |
| `none`         | No peers are permitted. `allow` and `deny` MUST be absent or empty.                                      |

Entries in `allow` and `deny` use the same entity types defined in
`DELIVERY.md` section 5.3: `user`, `domain`, `server`. A single
matcher MUST NOT mix `allow` and `deny`; `mode` disambiguates.

Peer semantics depend on the side:

- For `send`, a peer is the recipient address of an outbound envelope.
  Enforcement happens at submission, per section 10.3.4.
- For `receive`, a peer is the sender address of an inbound envelope
  after the home server has decrypted the brief and can read
  `brief.from`. The home server evaluates the matcher against
  `brief.from` before delivering to this device's session.

The combined size of `allow` and `deny` in a single matcher MUST NOT
exceed 10,000 entries. A certificate violating this cap MUST be
rejected at issuance with `reason_code: "scope_invalid"`.

The `delivery_stage` field is present only on the `receive` matcher.
It MUST be omitted from the `send` matcher; a certificate that places
`delivery_stage` on `send` MUST be rejected with
`reason_code: "scope_invalid"`. `delivery_stage` is a positive integer
(`>= 1`) declaring this device's position in the staged-delivery
ordering enforced by the home server (`DELIVERY.md` section 3.2).
Lower stages receive inbound envelopes first and decide via
`delivery-disposition` sync messages (`CLIENT.md` section 4.5.7)
whether the envelope advances to higher stages.

Full-access devices have no certificate and therefore no declared
`delivery_stage`. The home server treats full-access devices as
implicitly positioned at `max(delegated_stages) + 1`, where the
maximum is taken over all delegated devices of the account that have
a `receive` matcher whose `mode` is not `none`. When no such delegated
device exists, full-access devices are at stage 1 and no staging
applies.

##### 10.3.3.2 Resource Shape

`blocklist`, `keys`, and `devices` use the resource shape. Each
resource has a `read` and a `write` permission, granted independently.

```json
{
    "read": true | false,
    "write": true | false,
    "rate_limits": [ { "period_seconds": N, "amount_allowed": N } ]
}
```

| Field         | Type      | Required | Description                                                                |
|---------------|-----------|----------|----------------------------------------------------------------------------|
| `read`        | `boolean` | Yes      | Whether the device may list or inspect this resource.                      |
| `write`       | `boolean` | Yes      | Whether the device may modify this resource.                               |
| `rate_limits` | `array`   | Yes      | Rate-limit tiers applied to any operation on this resource, regardless of whether it is a read or write. See section 10.3.3.3. MAY be empty. |

Operations gated by each field:

| Resource    | `read` grants                                                                                        | `write` grants                                                                                    |
|-------------|------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|
| `blocklist` | Listing block entries (`DELIVERY.md` §5).                                                            | Add, modify, remove block entries.                                                                |
| `keys`      | Reading the account's key rotation history and per-device key metadata through the home server's key-management endpoint. | Publishing a new user key, rotating, or revoking. Does not include publishing domain-level keys (those are the operator's, not the user's). |
| `devices`   | Listing registered devices for the account with their scoped certificates (for audit tooling).       | Registering new delegated devices (subject to §10.3.9) and revoking devices.                      |

When `read` is `false`, the home server MUST reject list/inspect
operations on the corresponding resource with
`reason_code: "scope_exceeded"`. When `write` is `false`, the home
server MUST reject modify operations with the same reason code. A
device with both `read: false` and `write: false` has no access to
the resource at all.

Rate limits on a resource are evaluated for every operation that
passes the `read` or `write` gate, regardless of which gate it
passed. Operators wishing to cap reads and writes separately MAY
achieve this by revoking one of the two permissions or by using
multiple rate-limit tiers tuned to the expected read-to-write ratio.

##### 10.3.3.3 Rate Limits

Every scope field carries a `rate_limits` array. Each element is a
single rate-limit tier:

```json
{
    "period_seconds": 3600,
    "amount_allowed": 100
}
```

| Field            | Type      | Required | Description                                                                |
|------------------|-----------|----------|----------------------------------------------------------------------------|
| `period_seconds` | `integer` | Yes      | Length of the rolling window in seconds. MUST be >= 1.                     |
| `amount_allowed` | `integer` | Yes      | Maximum number of operations permitted within any rolling window of `period_seconds`. MUST be >= 0. |

Multiple tiers in the same array are evaluated independently. An
operation is permitted only if it would not exceed **any** tier's
cap. This allows short-burst and long-run limits to coexist (for
example: 100/hour plus 1000/day).

An empty `rate_limits` array means the protocol imposes no rate cap
on this scope field. The home server MAY still apply operator-defined
caps outside the certificate.

A tier with `amount_allowed: 0` prohibits the operation for the
duration of `period_seconds` (equivalent to `mode: "none"` for
matchers, or `read: false` / `write: false` for resources, but
expressed as a rate rather than a permission). This form is
RECOMMENDED only for temporary suspensions expressed by a short-lived
certificate update; permanent prohibition SHOULD use the primary
`mode` or `read`/`write` fields instead.

A certificate MUST NOT contain a tier with `period_seconds < 1` or
`amount_allowed < 0`, or more than 16 tiers in a single `rate_limits`
array. A certificate violating these constraints MUST be rejected
with `reason_code: "scope_invalid"`.

The home server MUST expose the current per-tier counters to the
owning account's authenticated clients (through an
implementation-defined endpoint) so that the primary device can
observe how close any delegate is to its caps.

#### 10.3.4 Scope Enforcement

The home server enforces the scope at every relevant operation:

- **Send.** On every envelope submission from the delegated device,
  the server evaluates `scope.send` per section 10.3.3.1 against
  each recipient. If any recipient is not permitted, the submission
  MUST be rejected with `reason_code: "scope_exceeded"`, identifying
  the rejected recipients. For `mode: "none"`, every submission is
  rejected.
- **Receive.** On every inbound envelope whose recipient is the
  delegating account, the server evaluates `scope.receive` against
  `brief.from`. If the sender is not permitted, the server MUST NOT
  deliver the envelope to this device's session and MUST NOT wrap
  `K_brief` or `K_enclosure` to this device's keys for that envelope.
  Other devices authorized to receive the envelope are unaffected.
- **Resource access (blocklist, keys, devices).** On every operation
  addressing one of these resources, the server first dispatches on
  operation class (read or write). If the corresponding permission on
  the resource field is `false`, the server MUST reject with
  `reason_code: "scope_exceeded"`.
- **Rate limits.** On every operation that passes the matcher or
  boolean check above, the server evaluates the scope field's
  `rate_limits` array. If any tier would be exceeded, the server
  MUST reject with `reason_code: "rate_limited"` and MUST NOT
  record the operation against the counters.

Scope enforcement uses the current certificate at the time of each
operation, not the certificate that was active when the session was
established. A certificate update by the primary device takes effect
immediately on the next operation within an existing session.

Receive-matcher enforcement is applied per-device, not per-account.
An inbound envelope that is blocked for a delegated device by its
receive matcher is still delivered to other devices of the same
account whose certificates (or full-access status) permit it.

#### 10.3.5 Issuance Flow

1. The delegated device generates its device key pair locally.
2. The delegated device conveys its public key to the primary device
   through an out-of-band channel (QR code, secure paste, API
   integration). The primary device is the source of truth for the
   account; the delegated public key is trusted only through this
   primary-device mediation.
3. The primary device composes the `SEMP_DEVICE_CERTIFICATE` with the
   desired scope and the computed `expires_at`.
4. The primary device signs the certificate with its own device
   private key.
5. The primary device submits the certificate to the home server via
   the standard device registration flow (`DISCOVERY.md` endpoint
   `device_register`).
6. The home server verifies: signature against the issuer's
   registered device key, issuer is a full-access device of the
   account, issuer is not revoked, all required fields are present,
   `allow` list is within limits, `expires_at` is within the bounds
   of section 10.3.8.
7. On successful verification, the home server stores the certificate
   and associates it with `device_id`.
8. The delegated device connects using its own device key via the
   standard handshake (`HANDSHAKE.md` section 2). The home server
   looks up the certificate by `device_id` and applies the scope to
   every operation on the resulting session.

A certificate submission that fails verification MUST be rejected
with a specific reason code from `ERRORS.md`. The home server MUST
NOT store a certificate whose signature or scope does not validate.

#### 10.3.6 Certificate Update

A primary device MAY issue a new certificate for an existing
delegated `device_id` to change scope or extend `expires_at`. The
home server stores the new certificate and enforces its scope on the
next operation after acceptance.

An active session held by the delegated device MUST NOT be
invalidated by certificate update alone. The session continues, and
the updated scope applies to the next operation within it. This
permits instantaneous scope changes without requiring the delegated
device to reconnect.

The home server MUST preserve the delegated device's existing session
through certificate update. Rotating or revoking the delegated device
key (not the certificate) invalidates sessions per section 10.3.7.

#### 10.3.7 Revocation

Revocation of a scoped certificate is accomplished either by revoking
the delegated device key itself (a device revocation record) or by
publishing a certificate revocation record that supersedes the
current certificate without rotating the device key.

##### 10.3.7.1 Revocation Record

```json
{
    "type": "SEMP_DEVICE_CERTIFICATE_REVOCATION",
    "version": "1.0.0",
    "account": "user@example.com",
    "device_id": "01JDELEGATE0000000000000000",
    "revoked_at": "2025-08-01T12:00:00Z",
    "reason": "delegated_role_ended",
    "issued_by": "01JPRIMARY00000000000000000",
    "signature": {
        "algorithm": "ed25519",
        "key_id": "primary-device-key-fingerprint",
        "value": "base64-signature"
    }
}
```

##### 10.3.7.2 Revocation Reasons

| Reason                     | Meaning                                                                                        |
|----------------------------|------------------------------------------------------------------------------------------------|
| `delegated_role_ended`     | The delegation is no longer needed. Non-security motive. Routine shutdown of a delegated service. |
| `suspected_compromise`     | The delegated device or its operator is believed compromised. Session termination is urgent.   |
| `scope_change`             | Scope is being changed. The revocation is paired with issuance of a new certificate.           |
| `policy`                   | Revoked for account policy reasons. The primary device MAY elaborate in a separate channel.    |

Implementations MUST NOT define additional reason codes without
registration.

##### 10.3.7.3 Effects

On acceptance of a revocation record, the home server MUST:

1. Terminate the delegated device's active session immediately.
2. Reject any subsequent handshake from `device_id` using the
   associated device key, with `reason_code: "revoked"` per
   `HANDSHAKE.md` section 4.1.
3. Stop delivering inbound envelopes to `device_id` regardless of
   the receive matcher that had been in effect.
4. Publish the revocation record alongside the user's key history
   so that third-party domains can observe the revocation.

A revocation record MUST be signed by a full-access device of the
account. A revocation record signed by a device that is not the
original issuer MAY still be accepted if signed by any current
full-access device of the account. Revocation is an account-level
authority, not an issuer-specific authority.

#### 10.3.8 Lifetime

The `expires_at` value MUST satisfy:

```
issued_at < expires_at <= issued_at + 365 days
```

RECOMMENDED lifetime is 180 days from issuance. Shorter lifetimes
limit the blast radius of an undetected compromise; longer lifetimes
reduce the frequency with which a primary device must be online to
renew. The cap of 365 days prevents certificates from outliving the
user's operational context.

A certificate whose `expires_at` has passed MUST be treated by the
home server as invalid. All submissions from the delegated device
MUST be rejected with `reason_code: "certificate_expired"`. The
delegated device's existing session MUST be terminated on expiry.

Renewal is performed by the primary device issuing a new certificate
for the same `device_id` per section 10.3.6.

#### 10.3.9 Nested Delegation

A delegated device MUST NOT issue a `SEMP_DEVICE_CERTIFICATE`. Only
a full-access device of the account may issue certificates.

`scope.devices.write: true` on a delegated device authorizes it to
**submit** device registrations to the home server on the primary
device's behalf, but the certificate of any resulting device MUST
still be signed by a full-access device. The home server enforces
this by verifying that `issued_by` refers to a device without a
scoped certificate. A submission from a delegate with
`scope.devices.write: true` whose `issued_by` points at another
delegated device (creating a chain) MUST be rejected with
`reason_code: "scope_invalid"`.

The purpose of keeping delegation shallow is auditability: every
certificate traces to a full-access device in one hop. Deeper chains
create ambiguity about which party authorized which action and
complicate revocation.

#### 10.3.10 Common Delegation Patterns (Informative)

This section is informative. It shows example scope configurations
for three common delegated-client roles.

**Mailing list client.** Accepts envelopes addressed to the user's
list address, redistributes to subscribers.

```json
{
    "send": {
        "mode": "restricted",
        "allow": [
            { "type": "user", "address": "subscriber1@example.com" },
            { "type": "user", "address": "subscriber2@example.com" }
        ],
        "rate_limits": [
            { "period_seconds": 3600,  "amount_allowed": 200 },
            { "period_seconds": 86400, "amount_allowed": 2000 }
        ]
    },
    "receive": {
        "mode": "restricted",
        "allow": [ { "type": "user", "address": "list-owner@example.com" } ],
        "rate_limits": [],
        "delivery_stage": 1
    },
    "blocklist": { "read": false, "write": false, "rate_limits": [] },
    "keys":      { "read": false, "write": false, "rate_limits": [] },
    "devices":   { "read": false, "write": false, "rate_limits": [] }
}
```

**Spam filter client.** Receives every inbound envelope first
(stage 1), does not send, can manage the user's block list based on
classification. Full-access devices implicitly receive at stage 2.

```json
{
    "send":    { "mode": "none", "rate_limits": [] },
    "receive": { "mode": "unrestricted", "rate_limits": [], "delivery_stage": 1 },
    "blocklist": {
        "read": true,
        "write": true,
        "rate_limits": [
            { "period_seconds": 3600,  "amount_allowed": 200 },
            { "period_seconds": 86400, "amount_allowed": 1000 }
        ]
    },
    "keys":    { "read": false, "write": false, "rate_limits": [] },
    "devices": { "read": false, "write": false, "rate_limits": [] }
}
```

**Vacation autoresponder.** Receives envelopes to generate replies,
sends only to the original senders (the `allow` list is updated
dynamically by the primary device as correspondents appear).
Autoresponder receives alongside full-access devices (same stage):

```json
{
    "send": {
        "mode": "restricted",
        "allow": [ { "type": "user", "address": "correspondent@example.com" } ],
        "rate_limits": [
            { "period_seconds": 3600,  "amount_allowed": 60 },
            { "period_seconds": 86400, "amount_allowed": 500 }
        ]
    },
    "receive":   { "mode": "unrestricted", "rate_limits": [], "delivery_stage": 1 },
    "blocklist": { "read": false, "write": false, "rate_limits": [] },
    "keys":      { "read": false, "write": false, "rate_limits": [] },
    "devices":   { "read": false, "write": false, "rate_limits": [] }
}
```

**Archive exporter with denylist.** Receives from everyone except
sensitive correspondents, never sends, reads only.

```json
{
    "send": { "mode": "none", "rate_limits": [] },
    "receive": {
        "mode": "denylist",
        "deny": [
            { "type": "user", "address": "therapist@clinic.example" },
            { "type": "domain", "domain": "legal.example" }
        ],
        "rate_limits": [
            { "period_seconds": 3600, "amount_allowed": 5000 }
        ],
        "delivery_stage": 1
    },
    "blocklist": { "read": false, "write": false, "rate_limits": [] },
    "keys":      { "read": false, "write": false, "rate_limits": [] },
    "devices":   { "read": false, "write": false, "rate_limits": [] }
}
```

**Device audit tool.** Read-only delegate that lists the account's
registered devices and their scoped certificates for operator
tooling. Does not send, receive, or modify anything.

```json
{
    "send":    { "mode": "none", "rate_limits": [] },
    "receive": { "mode": "none", "rate_limits": [], "delivery_stage": 1 },
    "blocklist": { "read": false, "write": false, "rate_limits": [] },
    "keys":      { "read": true,  "write": false, "rate_limits": [] },
    "devices":   {
        "read": true,
        "write": false,
        "rate_limits": [
            { "period_seconds": 60, "amount_allowed": 30 }
        ]
    }
}
```

These examples are not exhaustive. Other plausible roles include
read-only mobile viewers (receive unrestricted, send restricted to
the user's own address for status updates), and per-correspondent
proxies with receive restricted to a single sender. Implementers
select the minimum scope sufficient for the role.

### 10.4 Key Usage Transparency

To detect unauthorized key use, all key operations SHOULD be logged locally
on each registered device. Usage records include the key ID, device ID,
timestamp, and purpose. Clients SHOULD surface anomalous key usage (such as
a key being used from an unrecognized device) to the user as an alert.

---

## 11. Trust History and Transfer

Per DESIGN.md section 5.3, a domain's trust history is cryptographically bound
to its private key. If a domain changes ownership, the trust history MAY be
transferred through a handshake requiring both parties' private keys: the
seller signs a transfer record, and the buyer accepts it with their own key. The
transfer event is published and visible to the network.

Loss of the domain private key means loss of the associated trust history.
There is no recovery path. Trust cannot be forged, reassigned without both
parties' participation, or reconstructed from backup by an unauthorized party.

### 11.1 User-Level Migration

User-level migration (a user moving from `alice@old.example` to
`alice@new.example`) is specified in `MIGRATION.md` as a RECOMMENDED
optional core module. Migration binds the old and new identity keys
and, in cooperative mode, the old and new domain keys. Trust carry-over
across migration is a per-domain policy decision and is bound to the
identity keys in the migration record, not to address strings.

---

## 12. Security Considerations

### 12.1 Post-Quantum Readiness

All key discovery mechanisms MUST support post-quantum algorithms. During the
transition period, hybrid classical/post-quantum key pairs SHOULD be published
alongside classical-only keys to maintain backward compatibility. Algorithm
negotiation occurs during the handshake.

### 12.2 Key Substitution Attacks

A malicious server could publish attacker-controlled keys for its users,
intercepting messages intended for them. Mitigations:

- Domain signatures over user keys bind the key to the publishing domain
- Self-signatures bind the encryption key to the user's identity key
- Out-of-band verification provides the strongest assurance
- Web of trust signatures from third parties provide additional corroboration

### 12.3 Revocation Freshness

Cached keys that have been revoked remain dangerous until the cache is
invalidated. Implementations SHOULD use conservative TTLs for cached keys,
particularly for encryption keys. On any delivery failure, the key cache SHOULD
be invalidated and keys re-fetched before retry.

### 12.4 Forward Secrecy

Forward secrecy properties at the key layer are defined in `SESSION.md`.
Session keys are derived from ephemeral key material and erased after session
expiry, ensuring that compromise of any long-term key (domain, identity, or
encryption) cannot retroactively decrypt past sessions. See `SESSION.md`
sections 1.1 and 5.3 for the boundary between session keys and long-term keys.

---

## 13. Relationship to Other Specifications

| Specification | Relationship |
|---|---|
| `DESIGN.md` | Governing principles. Key transfer mechanism implements section 5.3. Privacy constraint on fetching implements section 2.6. |
| `HANDSHAKE.md` | Session keys are defined there. Identity keys are used in handshake identity proofs. |
| `ENVELOPE.md` | Encryption keys are used in `seal.brief_recipients` and `seal.enclosure_recipients` key wrapping. Domain keys are used in `seal.signature` and in `seal.brief_recipients` to grant the recipient server access to `K_brief`. |
| `CLIENT.md` | Client key request protocol (`SEMP_KEYS` over session channel) defined in section 5.4. The home server proxies key fetches on behalf of clients per section 6.3. |
| `DISCOVERY.md` | Key server discovery uses the same well-known URI infrastructure. Anonymous fetch constraint is consistent with discovery section 1.2. |

---

*This document is an Internet-Draft. It is subject to revision prior to
finalization as a stable specification.*