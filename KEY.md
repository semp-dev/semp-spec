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
        "mode": "pow",
        "pow_difficulty": 22,
        "invite_required": false
    },
    "signature": { }
}
```

| Field             | Type      | Required | Description                                                                  |
|-------------------|-----------|----------|------------------------------------------------------------------------------|
| `mode`            | `string`  | Yes      | One of: `open`, `pow`, `invite_only`. See section 3.2.1.                     |
| `pow_difficulty`  | `integer` | When `mode == pow` | Leading zero bits required for the first-contact challenge. MUST be in the range 0 to 28 inclusive, subject to the difficulty cap in `HANDSHAKE.md` section 2.2a.2. |
| `invite_required` | `boolean` | When `mode == invite_only` | When `true`, the recipient accepts envelopes only from senders presenting a valid invite token. Invite token issuance and binding are out of scope for this revision. |

#### 3.2.1 Modes

| Mode          | Behavior                                                                                                              |
|---------------|------------------------------------------------------------------------------------------------------------------------|
| `open`        | No first-contact friction. All envelopes proceed through the standard delivery pipeline.                              |
| `pow`         | First-contact envelopes from unknown sender domains MUST carry a valid `seal.first_contact_token` per `HANDSHAKE.md` section 2.2a.4. |
| `invite_only` | Envelopes from unknown sender domains MUST carry a valid invite token. Invite tokens are out of scope for this revision. |

A sender's home server fetching the recipient's key record MUST cache the
`first_contact_policy` alongside the key record and MUST honor it when
composing envelopes to that recipient.

The recipient's home server MUST enforce the published policy regardless
of what the sender's server caches. The published policy is advisory to
senders; it is normative to the recipient server.

#### 3.2.2 Indistinguishability

A recipient server MUST publish the same `first_contact_policy` for all
addresses on its domain that have published any policy at all, OR MUST
publish no policy and apply a per-recipient policy internally. A
per-address policy publication that varies by address would constitute
an existence oracle. See `DESIGN.md` section 2.7.

When a recipient has no published key record, the home server SHOULD
behave as if the recipient's policy were `pow` with the operator's
default difficulty, in order to prevent enumeration via missing-key
inference.

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

### 9.3 Key Backup

SEMP supports multiple backup strategies. Operators and users choose based on
their threat model:

| Strategy             | Description                                                        |
|----------------------|--------------------------------------------------------------------|
| Secret sharing       | Key material split using Shamir's Secret Sharing across M-of-N trusted parties. |
| Threshold encryption | Recovery requires cooperation of M-of-N trusted devices or contacts. |
| Server-assisted      | Private key encrypted under a recovery key and stored on the home server. |
| Paper backup         | Key material encoded as a QR code or word sequence for offline storage. |

Loss of all backup copies means permanent loss of the trust history associated
with the key. SEMP does not provide a recovery path that bypasses key
possession.

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

### 10.3 Key Usage Transparency

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