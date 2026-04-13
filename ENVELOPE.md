# SEMP Envelope Specification

**Sealed Envelope Messaging Protocol**  
Status: Internet-Draft  
Version: 0.1.0  
Related: `DESIGN.md`, `HANDSHAKE.md`, `KEY.md`

---

## Abstract

The SEMP envelope is the core message unit of the protocol. It is modeled
directly on physical correspondence: a sealed envelope that conceals its
contents from everyone except the intended recipient, while exposing only what
is necessary for routing. This document defines the structure, field semantics,
encryption model, and extensibility rules for SEMP envelopes.

---

## 1. Overview

A SEMP envelope consists of four components:

```
envelope
  ├── postmark     outer public header, visible to routing servers
  ├── seal         cryptographic integrity proof, verifiable by any server
  ├── brief        inner private header, encrypted, recipient only
  └── enclosure    message body and attachments, encrypted, recipient only
```

The **postmark** and **seal** are the outside of the envelope. Any server
handling the message in transit can read the postmark and verify the seal. They
cannot read anything else.

The **brief** and **enclosure** are the inside of the envelope. They are
encrypted before transmission. The brief is decryptable by the recipient
server (for delivery and policy enforcement) and by the recipient client.
The enclosure is decryptable only by the recipient client. No routing server
can read the enclosure.

This two-layer structure protects message metadata (sender identity,
recipient identity, subject, timestamp) from exposure to intermediaries.

---

## 2. Envelope Structure

### 2.1 Top-Level Schema

```json
{
    "type": "SEMP_ENVELOPE",
    "version": "1.0.0",
    "postmark": { },
    "seal": { },
    "brief": "<base64-encoded-encrypted-bytes>",
    "enclosure": "<base64-encoded-encrypted-bytes>"
}
```

The `brief` and `enclosure` fields are opaque encrypted blobs at the transport
layer. Their internal structure is defined in sections 4 and 5 respectively, and
is only meaningful after decryption by the recipient.

### 2.2 Top-Level Fields

| Field       | Type     | Required | Description                                              |
|-------------|----------|----------|----------------------------------------------------------|
| `type`      | `string` | Yes      | MUST be `"SEMP_ENVELOPE"`                                |
| `version`   | `string` | Yes      | Protocol version in semver format                        |
| `postmark`  | `object` | Yes      | Outer public routing header                              |
| `seal`      | `object` | Yes      | Cryptographic integrity proof                            |
| `brief`     | `string` | Yes      | Encrypted inner header (base64)                          |
| `enclosure` | `string` | Yes      | Encrypted message body and attachments (base64)          |

---

## 3. Postmark

The postmark contains the minimum information necessary to route and deliver the
envelope. It MUST NOT contain sender or recipient addresses in full. It MUST NOT
contain a subject, timestamp, or any field that could be used to infer the
nature or content of the correspondence.

A routing server reads the postmark and no other component.

### 3.1 Postmark Schema

```json
{
    "postmark": {
        "id": "01J4K7P2XVEM3Q8YNZHBRC5T06",
        "session_id": "session-ulid-from-established-handshake",
        "from_domain": "example.com",
        "to_domain": "otherdomain.com",
        "expires": "2025-06-08T13:05:00Z",
        "hop_count": 0,
        "extensions": {}
    }
}

`hop_count` is optional. When present it starts at `0` and is incremented by
each relay. When absent, relay servers that support hop tracking MAY add it.
Relay servers that do not support it MUST ignore its absence and MUST NOT
reject the envelope on that basis.
```

When `hop_count` is omitted, relay servers that support it MAY add it. Relay
servers that do not support it MUST ignore its absence.

```json
{
    "postmark": {
        "id": "01J4K7P2XVEM3Q8YNZHBRC5T06",
        "from_domain": "example.com",
        "to_domain": "otherdomain.com",
        "expires": "2025-06-08T13:05:00Z",
        "extensions": {}
    }
}
```

### 3.2 Postmark Fields

| Field         | Type      | Required | Description                                                  |
|---------------|-----------|----------|--------------------------------------------------------------|
| `id`          | `string`  | Yes      | Opaque message identifier, ULID or UUID. See note below.     |
| `session_id`  | `string`  | Yes      | Session identifier from the established handshake. Envelopes without a valid `session_id` MUST be rejected. |
| `from_domain` | `string`  | Yes      | Sender's domain only. No local part, no display name.        |
| `to_domain`   | `string`  | Yes      | Recipient's domain only. No local part, no display name.     |
| `expires`     | `string`  | Yes      | ISO 8601 UTC expiry timestamp. Servers MUST reject expired envelopes. |
| `hop_count`   | `integer` | No       | Number of relay hops. Starts at `0` when present. See section 3.4. |
| `extensions`  | `object`  | No       | Postmark-layer extensions. MUST NOT contain private metadata. |

### 3.3 Notes on the Message ID

The `id` field is an opaque routing identifier. It is not a persistent global
message ID; it is scoped to the delivery transaction. Its purpose is deduplication
and loop detection at the routing layer, not conversation threading. Threading
and conversation identifiers belong in the `brief`.

Implementations SHOULD use ULIDs for `id` due to their time-ordered and
URL-safe properties. UUIDs are also acceptable.

### 3.4 Hop Count

`hop_count` is an optional transit field. Relay servers that support hop
tracking SHOULD increment it before forwarding. Relay servers that do not
support hop tracking MUST forward the field unchanged if present, and MAY
forward the envelope without adding the field if absent.

When present, servers MAY reject envelopes whose `hop_count` exceeds a
configured maximum (RECOMMENDED ceiling: 25) as a loop prevention measure.
Servers MUST NOT reject envelopes solely because `hop_count` is absent.

Because `hop_count` is mutable in transit, it is explicitly excluded from
the seal signature scope. See section 4.3.

---

## 4. Seal

The seal provides two independent cryptographic proofs over the same canonical
envelope bytes:

- **`seal.signature`**:  signed with the sender's domain private key. Verifiable
  by any server using the sender's published domain key, without any prior
  session. This is the routing-layer integrity proof. It proves the envelope
  was produced by the stated sender domain and has not been tampered with in
  transit.

- **`seal.session_mac`**:  a MAC computed using the session key derived during
  the handshake. Verifiable only by the receiving server, which holds the
  session key. This is the delivery-layer session enforcement proof. It proves
  the envelope was produced by a party that completed a valid handshake with
  the receiving server, not merely by someone who knows the domain key.

Together, these two proofs make the envelope and the handshake session
cryptographically inseparable at delivery. A forged envelope that passes domain
key verification but was not produced within a valid session will fail the
session MAC check. A routing server that did not participate in the handshake
can still verify the domain signature for routing integrity.

A server that receives an envelope with an invalid or missing `seal.signature`
MUST reject it immediately. A receiving server that additionally finds an
invalid `seal.session_mac` MUST reject the envelope with `reason_code:
"session_mac_invalid"`.

### 4.1 Seal Schema

```json
{
    "seal": {
        "algorithm": "pq-kyber768-x25519",
        "key_id": "sender-domain-key-fingerprint",
        "signature": "base64-encoded-domain-key-signature",
        "session_mac": "base64-encoded-session-key-mac",
        "brief_recipients": {
            "recipient-server-domain-key-fingerprint": "base64-K_brief-encrypted-under-server-domain-key",
            "recipient-client-key-fingerprint":        "base64-K_brief-encrypted-under-client-key"
        },
        "enclosure_recipients": {
            "recipient-client-key-fingerprint": "base64-K_enclosure-encrypted-under-client-key"
        },
        "extensions": {}
    }
}
```

### 4.2 Seal Fields

| Field                  | Type     | Required | Description                                                        |
|------------------------|----------|----------|--------------------------------------------------------------------|
| `algorithm`            | `string` | Yes      | Algorithm used for signing and key encapsulation.                  |
| `key_id`               | `string` | Yes      | Fingerprint of the sender domain key used to produce `seal.signature`. |
| `signature`            | `string` | Yes      | Domain key signature over canonical envelope bytes. See section 4.3. |
| `session_mac`          | `string` | Yes      | Session key MAC over canonical envelope bytes. See section 4.3.    |
| `brief_recipients`     | `object` | Yes      | Map of key fingerprints to encrypted copies of `K_brief`. Includes both the recipient server's domain key and the recipient client's encryption key. See section 4.4. |
| `enclosure_recipients` | `object` | Yes      | Map of key fingerprints to encrypted copies of `K_enclosure`. Includes only the recipient client's encryption key. See section 4.4. |
| `extensions`           | `object` | No       | Seal-layer extensions.                                             |

### 4.3 Signature Scope and Canonicalization

Both `seal.signature` and `seal.session_mac` are computed over the same
canonical serialization of the envelope, defined as the UTF-8 JSON encoding
of the envelope with:

- Keys sorted lexicographically at every level
- No insignificant whitespace
- `seal.signature` set to an empty string `""` during both computations
- `seal.session_mac` set to an empty string `""` during both computations
- `postmark.hop_count` omitted entirely, whether or not present in transit

Setting both fields to empty string during computation means neither proof
depends on the value of the other. Both cover identical input bytes. The
canonical form is computed once and passed to both verification routines.

The exclusion of `hop_count` is intentional because it is a mutable transit field.
All other postmark fields are immutable and covered by both proofs.

This canonical form MUST be reproduced identically by any implementation.
Deviations in key ordering, whitespace, or field exclusion handling will
produce verification failures.

#### Two-Layer Verification Responsibilities

| Layer    | Verifies          | Uses              | Performed by          |
|----------|-------------------|-------------------|-----------------------|
| Routing  | `seal.signature`  | Sender domain key | Any routing server    |
| Delivery | `seal.session_mac`| Session key `K_env_mac` | Receiving server only |

Routing servers MUST verify `seal.signature`. They cannot verify
`seal.session_mac` as they do not hold the session key. Receiving servers
MUST verify both.

### 4.4 Recipient Key Wrapping

The envelope uses two symmetric keys with different access scopes:

- **`K_brief`**:  encrypts the `brief`. Wrapped under both the recipient server's
  domain key and the recipient client's encryption key. The server can decrypt
  the brief to perform delivery and policy enforcement. The client can also
  decrypt it to access message metadata.
- **`K_enclosure`**:  encrypts the `enclosure`. Wrapped only under the recipient
  client's encryption key. The server cannot read the enclosure under any
  circumstances.

The `brief_recipients` map therefore contains two entries per recipient: one
encrypted under the recipient server's published domain key (keyed by domain key
fingerprint), and one encrypted under the recipient client's encryption key
(keyed by client key fingerprint). The `enclosure_recipients` map contains only
the client key entry.

The sender MUST fetch the recipient server's domain key at send time, in addition
to the recipient client's encryption key. Domain keys are already published via
DNS/DANE and the well-known URI per `KEY.md` section 2; this fetch does not
require new infrastructure.

Recipient client identities are not present in either map as plaintext. A client
identifies its entry by attempting decryption with each of its active private
keys. The server identifies its entry by its own domain key fingerprint, which is
not secret (the domain key is publicly published). The server's identity is
already visible in the postmark and handshake; concealing it from the seal map
would provide no additional privacy.

The computational cost of client-side key identification is bounded by the number
of active keys a recipient maintains, which SHOULD be small (typically one to
three keys per user). For large group messages, the cost scales linearly with
recipient count at the sender side only.

### 4.5 Symmetric Key Scope

Two symmetric keys are generated fresh for each envelope:

- **`K_brief`** encrypts the `brief` only. It MUST NOT be reused across envelopes.
- **`K_enclosure`** encrypts the `enclosure` only. It MUST NOT be reused across envelopes.

Neither key is derived from the other. They are independent random values.

---

## 5. Brief

The brief is the inner private header of the envelope. It contains the
correspondence metadata that in SMTP would be exposed in plaintext: sender and
recipient addresses, timestamps, and threading information. It answers who
and when. It does not contain the subject or message content, which belong
in the enclosure, as semantic content rather than routing metadata.

The brief is encrypted with `K_brief`, which is wrapped in `seal.brief_recipients`
under both the recipient server's domain key and the recipient client's encryption
key. The recipient server can decrypt the brief to perform delivery and
user-level policy enforcement. The brief is not readable by any other server
handling the envelope in transit.

### 5.1 Brief Schema (Decrypted)

```json
{
    "message_id": "globally-unique-message-identifier",
    "from": "sender@example.com",
    "to": ["recipient1@example.com", "recipient2@example.com"],
    "cc": ["observer@example.com"],
    "bcc": ["hidden@example.com"],
    "reply_to": "optional-reply-address@example.com",
    "sent_at": "2025-06-08T12:05:00Z",
    "thread_id": "thread-identifier-or-null",
    "group_id": "group-identifier-or-null",
    "in_reply_to": "message-id-of-parent-or-null",
    "extensions": {}
}
```

### 5.2 Brief Fields

| Field        | Type            | Required | Description                                                              |
|--------------|-----------------|----------|--------------------------------------------------------------------------|
| `message_id` | `string`        | Yes      | Globally unique message identifier. Used for threading and deduplication.|
| `from`       | `string`        | Yes      | Full sender address.                                                     |
| `to`         | `string[]`      | Yes      | Primary recipient addresses.                                             |
| `cc`         | `string[]`      | No       | Carbon copy recipient addresses.                                         |
| `bcc`        | `string[]`      | No       | Blind carbon copy. See section 5.3.                                      |
| `reply_to`   | `string`        | No       | Address replies should be directed to, if different from `from`.         |
| `sent_at`    | `string`        | Yes      | ISO 8601 UTC timestamp of message creation at the sender.                |
| `thread_id`  | `string\|null`  | No       | Conversation thread identifier.                                          |
| `group_id`   | `string\|null`  | No       | Group or mailing list identifier.                                        |
| `in_reply_to`| `string\|null`  | No       | `message_id` of the message being replied to.                            |
| `extensions` | `object`        | No       | Brief-layer extensions for private metadata.                             |

### 5.3 BCC Handling

BCC recipients MUST NOT be visible to non-BCC recipients. SEMP enforces this
through per-recipient envelope copies generated by the sending client rather
than server-side stripping.

When a sender includes BCC recipients, the sending client generates a distinct
envelope copy for each BCC recipient. Each BCC copy contains only that
recipient's address in the `bcc` field. The `bcc` field is absent entirely from
the envelope copies delivered to `to` and `cc` recipients.

This approach eliminates the requirement to trust any server to strip BCC
correctly. The information is never present in envelopes that should not
contain it, and the sender's server never sees the full BCC recipient list.

### 5.4 Message ID vs Postmark ID

The `brief.message_id` is the persistent global identifier for the message. It
is stable across retries, forwards, and delivery attempts. It is used for
threading, deduplication at the recipient level, and reply correlation.

The `postmark.id` is a per-transaction routing identifier. It MAY change across
delivery attempts. It is used for hop-level deduplication and loop detection
only.

---

## 6. Enclosure

The enclosure contains the message body and attachments. It is encrypted with
`K_enclosure`, which is wrapped only under the recipient client's encryption
key in `seal.enclosure_recipients`. It is not readable by the recipient server
or by any other server handling the envelope in transit.

### 6.1 Enclosure Schema (Decrypted)

```json
{
    "subject": "Optional subject line",
    "content_type": "multipart/alternative",
    "body": {
        "text/plain": "base64-encoded-encrypted-plaintext-body",
        "text/html": "base64-encoded-encrypted-html-body",
        "text/markdown": "base64-encoded-encrypted-markdown-body"
    },
    "attachments": [
        {
            "id": "attachment-ulid",
            "filename": "report.pdf",
            "mime_type": "application/pdf",
            "size": 204800,
            "hash": "sha256:abc123...",
            "content": "base64-encoded-encrypted-attachment-content"
        }
    ],
    "extensions": {}
}
```

### 6.2 Enclosure Fields

| Field          | Type      | Required | Description                                                         |
|----------------|-----------|----------|---------------------------------------------------------------------|
| `subject`      | `string`  | No       | Subject of the correspondence. Belongs here because it is semantic content, not routing metadata. |
| `content_type` | `string`  | Yes      | MIME type of the body. Use `multipart/alternative` for multiple formats. |
| `body`         | `object`  | Yes      | Map of MIME type to encrypted body content (base64).                |
| `attachments`  | `array`   | No       | List of attached files.                                             |
| `extensions`   | `object`  | No       | Enclosure-layer extensions for content metadata.                    |

### 6.3 Attachment Fields

| Field       | Type      | Required | Description                                              |
|-------------|-----------|----------|----------------------------------------------------------|
| `id`        | `string`  | Yes      | Unique attachment identifier within this envelope.       |
| `filename`  | `string`  | Yes      | Original filename.                                       |
| `mime_type` | `string`  | Yes      | MIME type of the attachment.                             |
| `size`      | `integer` | Yes      | Size in bytes of the unencrypted attachment content.     |
| `hash`      | `string`  | Yes      | Hash of the unencrypted content for integrity verification. Format: `algorithm:hex`. |
| `content`   | `string`  | Yes      | Encrypted attachment content (base64).                   |

### 6.4 Multipart Body

When `content_type` is `multipart/alternative`, the `body` object MAY contain
multiple representations of the same content keyed by MIME type. Receiving
clients SHOULD select the most capable format they support. Senders SHOULD
always include a `text/plain` representation as a baseline.

```json
"content_type": "multipart/alternative",
"body": {
    "text/plain": "base64-encrypted-plain",
    "text/html": "base64-encrypted-html",
    "text/markdown": "base64-encrypted-markdown"
}
```

When `content_type` is a single MIME type, the `body` object MUST contain
exactly one key matching that type.

---

## 7. Encryption Model

### 7.1 Encryption Flow

Sending an envelope follows this sequence:

1. Compose the plaintext `brief` and `enclosure` as JSON objects.
2. Generate two fresh independent random symmetric keys: `K_brief` and `K_enclosure`.
3. Encrypt the `brief` JSON bytes under `K_brief`. Store result in `envelope.brief`.
4. Encrypt the `enclosure` JSON bytes under `K_enclosure`. Store result in
   `envelope.enclosure`.
5. Fetch the recipient client's current public encryption key and the recipient
   server's published domain key. The client obtains these from its home server
   via `SEMP_KEYS` with `step: request` per `CLIENT.md` section 5.4.
6. Encrypt `K_brief` under the recipient server's domain key. Store in
   `seal.brief_recipients` keyed by the server's domain key fingerprint.
7. Encrypt `K_brief` under the recipient client's encryption key. Store in
   `seal.brief_recipients` keyed by the client's key fingerprint.
8. Encrypt `K_enclosure` under the recipient client's encryption key. Store in
   `seal.enclosure_recipients` keyed by the client's key fingerprint.
9. Compose the `postmark`, including `postmark.session_id`.

Steps 1 through 9 are performed by the sending client. The client then
transmits the assembled envelope to its home server, which performs the
remaining steps. The client does not hold the domain private key or the
session key material required for seal computation.

10. Compute the canonical envelope bytes (both `seal.signature` and
    `seal.session_mac` set to `""`, `postmark.hop_count` omitted).
11. Sign the canonical bytes with the sender's domain private key. Store in
    `seal.signature`.
12. Compute a MAC over the canonical bytes using `K_env_mac` from the active
    session. Store in `seal.session_mac`.

### 7.2 Decryption Flow

Receiving an envelope follows this sequence:

1. Verify `seal.signature` against the sender domain's published public key.
   Reject immediately with `reason_code: "seal_invalid"` if invalid.
2. Check `postmark.expires`. Reject with `reason_code: "envelope_expired"` if
   in the past.
3. Verify `postmark.session_id` references an active, non-expired,
   non-invalidated session. Reject with the appropriate reason code if not.
4. Verify `seal.session_mac` using `K_env_mac` from the session identified by
   `postmark.session_id`. Reject with `reason_code: "session_mac_invalid"` if
   the MAC does not verify.
5. Decrypt the server's entry in `seal.brief_recipients` using the server's
   domain private key, yielding `K_brief`.
6. Decrypt `envelope.brief` using `K_brief`. Parse the resulting JSON.
7. Apply domain/server-level and user-level delivery policy using the decrypted
   brief. Reject or silence the envelope if policy requires it.
8. Deliver the envelope to the recipient client. The client decrypts its entry
   in `seal.brief_recipients` using its own private key to obtain `K_brief`,
   and decrypts its entry in `seal.enclosure_recipients` to obtain `K_enclosure`.
9. Client decrypts `envelope.brief` using `K_brief` and `envelope.enclosure`
   using `K_enclosure`. Parse both.
10. Client verifies attachment hashes against decrypted attachment content.

Steps 1 through 4 MUST all pass before any further processing. Each failure
MUST produce an immediate, explicit rejection with the appropriate reason code.
Step 1 may be performed by any routing server. Steps 2 through 7 are performed
by the receiving server only. Steps 8 through 10 are performed by the client.

If step 5 fails, the server cannot decrypt the brief and MUST return an explicit
rejection to the sending server indicating delivery failure.

### 7.3 Algorithm Suites

SEMP defines algorithm suites as indivisible bundles. Each suite specifies the
complete set of cryptographic primitives used for a session and its envelopes.
Implementations negotiate suites, not individual primitives.

#### 7.3.1 Suite Definitions

| Suite identifier               | Key agreement          | Symmetric cipher      | MAC          | KDF           | Signing       |
|--------------------------------|------------------------|-----------------------|--------------|---------------|---------------|
| `x25519-chacha20-poly1305`     | X25519                 | ChaCha20-Poly1305     | HMAC-SHA-256 | HKDF-SHA-512  | Ed25519       |
| `pq-kyber768-x25519`          | Kyber768 + X25519      | ChaCha20-Poly1305     | HMAC-SHA-256 | HKDF-SHA-512  | Ed25519       |

Each column specifies:

- **Key agreement**:  the ephemeral key exchange used during the handshake to
  produce the shared secret. Hybrid suites concatenate both outputs
  (`K_kyber || K_x25519`) as defined in `SESSION.md` section 4.1.
- **Symmetric cipher**:  encrypts the `brief`, `enclosure`, and handshake
  messages after key derivation.
- **MAC**:  the algorithm used for `seal.session_mac` and handshake message
  MACs (`K_mac_c2s`, `K_mac_s2c`, `K_env_mac`).
- **KDF**:  the key derivation function used to derive session keys from the
  shared secret, as defined in `SESSION.md` section 2.1.
- **Signing**:  the algorithm used for `seal.signature`, domain key signatures,
  and identity proofs.

#### 7.3.2 Suite Requirements

Implementations MUST support:

- `x25519-chacha20-poly1305`: baseline suite, required for interoperability.
- `pq-kyber768-x25519`: hybrid post-quantum suite. RECOMMENDED.

Implementations MAY define and negotiate additional suites. Additional suites
MUST specify all five components. The negotiated suite MUST be recorded in
`seal.algorithm`.

Implementations MUST NOT negotiate suites below the minimum baseline. A server
that cannot support any mutually acceptable suite MUST reject the connection
explicitly.

#### 7.3.3 Suite Extensibility

Future suites MAY substitute any component (a different KDF, a different MAC,
a different symmetric cipher) as long as the suite is defined as a complete
bundle. Suite identifiers MUST be distinct strings that unambiguously identify
all five components. The protocol does not support mixing components from
different suites within a single session.

#### 7.3.4 Fixed Protocol Primitives

Two operations are not governed by the negotiated suite because they occur
before or outside of suite negotiation:

- **Confirmation hash**:  `SHA-256(canonical(message_1) || canonical(message_2))`.
  This is computed before any suite is agreed and covers the message that
  contains the suite negotiation. It is a fixed protocol primitive.
- **Challenge hash**:  SHA-256 as specified in `HANDSHAKE.md` section 2.2a.
  The proof of work challenge occurs before session establishment and is
  independent of the session suite.

---

## 8. Extensibility

Each layer of the envelope has its own `extensions` object. This allows new
capabilities to be introduced at the appropriate visibility level:

- **`postmark.extensions`**:  routing-layer extensions, visible to all servers
  in transit. MUST NOT contain private metadata. Examples: priority hints,
  delivery class indicators.
- **`seal.extensions`**:  integrity-layer extensions, visible to all servers.
  Examples: additional signature schemes, notarization tokens.
- **`brief.extensions`**:  private metadata extensions, visible to recipients
  only. Examples: labels, priority flags, custom headers.
- **`enclosure.extensions`**:  content-layer extensions, visible to recipients
  only. Examples: content negotiation hints, rendering instructions.

### 8.1 Extension Rules

- Extension keys MUST be namespaced to prevent collision:
  `"vendor.example.com/feature-name"`.
- Core implementations MUST ignore unknown extension keys rather than rejecting
  the envelope.
- Extensions MUST NOT redefine or shadow reserved field names at their layer.
- Extensions placed in `postmark.extensions` or `seal.extensions` are visible
  to all routing servers and MUST be treated as public metadata.

---

## 9. Server Responsibilities

### 9.1 Acceptance Requirements

A server receiving an envelope MUST:

1. Verify `seal.signature` before any other processing.
2. Reject envelopes with invalid seals immediately and explicitly.
3. Reject envelopes where `postmark.expires` is in the past.
4. Verify `postmark.session_id` references an active, non-expired,
   non-invalidated session. Reject if absent or invalid. See section 9.3.

A server MUST NOT:

- Accept and silently discard an envelope.
- Forward an envelope with an invalid seal.
- Modify any signed field of the envelope.

A server MAY:

- Increment `postmark.hop_count` if present, or add it starting at `1` if absent.
- Reject envelopes where `postmark.hop_count` exceeds a locally configured maximum.

### 9.2 Rejection

All rejections MUST be explicit. The rejecting server MUST return a structured
rejection response to the sending server containing:

- A reason code
- A human-readable description
- The `postmark.id` of the rejected envelope

A server that is unable to deliver or declines to deliver an envelope MUST return an explicit
rejection.

### 9.3 Envelope Rejection Reason Codes

The following reason codes apply to envelope rejection. They are a subset of
the reason codes defined in `HANDSHAKE.md` section 4.1, applied
at the envelope layer:

| Reason code         | Meaning                                                                  |
|---------------------|--------------------------------------------------------------------------|
| `blocked`           | The sender or their domain is blocked.                                   |
| `handshake_invalid` | The session referenced by `postmark.session_id` has been invalidated.   |
| `handshake_expired` | The session TTL has elapsed. Sender server should re-handshake and retry.|
| `no_session`        | `postmark.session_id` is absent or does not reference a known session.   |
| `seal_invalid`          | `seal.signature` domain key verification failed.                         |
| `session_mac_invalid`   | `seal.session_mac` session key MAC verification failed.                  |
| `envelope_expired`      | `postmark.expires` is in the past.                                       |

The sender server MUST handle `handshake_invalid`, `handshake_expired`, and
`no_session` as recoverable conditions by establishing a new session and
resending the envelope. `blocked` and `auth_failed` are non-recoverable and
MUST be surfaced to the sending user rather than retried automatically.

---

## 10. Security Considerations

### 10.1 Metadata Protection

The postmark contains only domain-level routing information.
Full sender and recipient addresses, timestamps, and threading metadata are
inside the encrypted `brief`. The subject and message content are inside the
encrypted `enclosure`.

Observers of network traffic are able to determine that a message was sent from one domain to
another. They MUST NOT be able to determine who sent it, who received it, what it was about,
or when within the expiry window it was sent.

### 10.2 Replay Prevention

The `postmark.expires` field limits the window during which a captured envelope
could be replayed. Servers MUST reject expired envelopes. The expiry value
SHOULD be set conservatively: long enough to account for legitimate delivery
delays, short enough to limit the replay window. A default of one hour is
RECOMMENDED.

The `postmark.id` provides hop-level deduplication. Servers MAY cache recently
seen `postmark.id` values and reject duplicates within the expiry window.

### 10.3 Tampering Detection

The envelope has two complementary tamper detection mechanisms covering the
same canonical bytes.

`seal.signature` is verifiable by any server using the sender's published
domain key. Any modification to any immutable field, including routing metadata
in the postmark, invalidates it. Routing servers verify this before forwarding.

`seal.session_mac` is verifiable only by the receiving server using the session
key. It proves the envelope was produced within a valid established session, not
merely by someone who possesses the domain key. A stolen or forged domain key
cannot produce a valid session MAC without also completing a real handshake.

The sole exclusion from both proofs is `postmark.hop_count`, which relay
servers may legitimately increment. All other fields are immutable after the
sender computes the seal.

### 10.4 Forward Secrecy

Forward secrecy properties of the envelope model are defined in `SESSION.md`.
Session keys are ephemeral and erased after session expiry, ensuring that
compromise of long-term domain or identity keys cannot retroactively decrypt
past envelopes. See `SESSION.md` sections 1.1 and 2 for the full specification.

### 10.5 Differential Brief/Enclosure Encryption

SEMP uses distinct symmetric keys for the brief and enclosure, with different
access grants at the server layer. The brief is decryptable by the recipient
server (via its domain key entry in `seal.brief_recipients`) and by the
recipient client. The enclosure is decryptable only by the recipient client.

A compromised or malicious recipient server can therefore read delivery
metadata (the full sender address, recipient addresses, timestamps, and thread
identifiers in the brief) but cannot read the message subject, body, or
attachments, which are protected in the enclosure under `K_enclosure`.

The residual exposure is that the recipient server learns the full correspondent
graph through the brief. This tradeoff exists because the alternative, hiding
the sender address from the server, conflicts with server-enforceable
user-level blocking. See section 10.6.

### 10.6 Blocking Enforcement and the Correspondent Graph

User-level blocking (blocking a specific sender address, as distinct from
blocking an entire domain) requires the recipient server to know the full sender
address at delivery time, so it can check the address against the recipient's
block list before delivering to the client. This check occurs after the server
decrypts the brief, which contains `brief.from`.

The consequence is that the recipient server learns the full sender address for
every envelope it delivers, not just the domain, but the individual
correspondent. Over time this constitutes a complete correspondent graph visible
to the server operator.

Server-enforceable user-level blocking is retained at the cost of a
server-visible correspondent graph. The alternative, moving block enforcement
entirely to the client, would require the server to deliver envelopes it cannot
screen, passing blocked traffic through to the client for client-side discard.

### 10.7 Recipient Anonymity

The `seal.brief_recipients` and `seal.enclosure_recipients` maps use key
fingerprints rather than addresses as keys. This prevents either map from
serving as a plaintext recipient list. However, a recipient's key fingerprint
may itself be linkable to their identity if their public key is widely
published. The recipient server's domain key fingerprint is public,
consistent with the server's visibility in the postmark and handshake. Implementations with strong recipient
anonymity requirements for client keys SHOULD consult the key management
specification for guidance on key publication strategies.

---

## 11. Privacy Considerations

The postmark exposes sender and recipient domains to routing servers. This is an
irreducible minimum for federated delivery: a server must know where to send
a message. Domain-level metadata reveals that two organizations are
corresponding, but not who within them or about what.

The `postmark.expires` timestamp reveals an upper bound on when the message was
sent. Implementations MAY reduce precision (rounding to the nearest hour, for
example) to limit timing correlation attacks, at the cost of replay window
expansion.

---

## 12. Relationship to Other Specifications

| Specification | Relationship |
|---|---|
| `DESIGN.md` | Governing principles. This specification implements section 4. |
| `HANDSHAKE.md` | Handshake establishes the session within which envelopes are exchanged. |
| `KEY.md` | Defines key discovery used in `seal.brief_recipients` and `seal.enclosure_recipients` key wrapping. |
| `DISCOVERY.md` | Protocol discovery determines whether SEMP delivery proceeds. Legacy routing is handled by the client, not the server. |
| `DELIVERY.md` | Blocking decisions are applied before envelope acceptance. |

---

*This document is an Internet-Draft. It is subject to revision prior to
finalization as a stable specification.*