# SEMP Envelope Specification

**Sealed Envelope Messaging Protocol**  
Status: Internet-Draft  
Version: 0.2.0-draft  
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
        "first_contact_token": null,
        "extensions": {}
    }
}
```

### 4.2 Seal Fields

| Field                  | Type            | Required | Description                                                        |
|------------------------|-----------------|----------|--------------------------------------------------------------------|
| `algorithm`            | `string`        | Yes      | Algorithm used for signing and key encapsulation.                  |
| `key_id`               | `string`        | Yes      | Fingerprint of the sender domain key used to produce `seal.signature`. |
| `signature`            | `string`        | Yes      | Domain key signature over canonical envelope bytes. See section 4.3. |
| `session_mac`          | `string`        | Yes      | Session key MAC over canonical envelope bytes. See section 4.3.    |
| `brief_recipients`     | `object`        | Yes      | Map of key fingerprints to encrypted copies of `K_brief`. Includes both the recipient server's domain key and the recipient client's encryption key. See section 4.4. |
| `enclosure_recipients` | `object`        | Yes      | Map of key fingerprints to encrypted copies of `K_enclosure`. Includes only the recipient client's encryption key. See section 4.4. |
| `first_contact_token`  | `object\|null`  | Yes      | Proof-of-work token presented in response to a first-contact challenge. `null` when not required or not yet issued. See `DELIVERY.md` section 6.4 and `HANDSHAKE.md` section 2.2a.4. |
| `extensions`           | `object`        | No       | Seal-layer extensions.                                             |

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

#### Signature Domain Separation

All Ed25519 signatures in SEMP MUST prepend a context-specific prefix to the
signed message before signing. This prevents cross-context signature confusion
where a signature valid in one context could be misinterpreted in another.

| Context | Prefix |
|---------|--------|
| Envelope seal signature | `SEMP-ENVELOPE:` |
| Handshake message signature | `SEMP-HANDSHAKE:` |
| Identity proof signature | `SEMP-IDENTITY:` |
| Key response signature | `SEMP-KEYS:` |
| Discovery response signature | `SEMP-DISCOVERY:` |
| Revocation signature | `SEMP-REVOCATION:` |

The signed input is always `prefix || canonical_bytes`. Verification MUST
reconstruct the same prefixed input before calling Ed25519 Verify.
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

Key wrapping uses the negotiated suite's KEM for per-recipient encapsulation.
For the baseline suite (`x25519-chacha20-poly1305`), wrapping uses X25519
ephemeral key agreement. For the post-quantum suite (`pq-kyber768-x25519`),
wrapping uses the Kyber768+X25519 hybrid KEM. This ensures that post-quantum
protection extends to envelope confidentiality at rest, not only to session key
exchange. Recipient encryption keys MUST be generated using the same suite's KEM
as the wrapping operation.

The symmetric key ciphertext is bound to the recipient via the recipient's
public key as AEAD additional authenticated data.

The `brief` and `enclosure` AEAD encryption MUST pass `postmark.id` as additional
authenticated data. This binds the ciphertext to the specific envelope and
prevents transplanting encrypted payloads between envelopes.

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
    "forwarded_from": null,
    "extensions": {},
    "sender_signature": {
        "algorithm": "ed25519",
        "key_id": "sender-identity-key-fingerprint",
        "value": "base64-signature"
    }
}
```

### 6.2 Enclosure Fields

| Field              | Type            | Required | Description                                                         |
|--------------------|-----------------|----------|---------------------------------------------------------------------|
| `subject`          | `string`        | No       | Subject of the correspondence. Belongs here because it is semantic content, not routing metadata. |
| `content_type`     | `string`        | Yes      | MIME type of the body. Use `multipart/alternative` for multiple formats. |
| `body`             | `object`        | Yes      | Map of MIME type to encrypted body content (base64).                |
| `attachments`      | `array`         | No       | List of attached files.                                             |
| `forwarded_from`   | `object\|null`  | Yes      | Forwarding evidence block. `null` if the envelope is not a forward. See section 6.6. |
| `extensions`       | `object`        | No       | Enclosure-layer extensions for content metadata.                    |
| `sender_signature` | `object`        | Yes      | Sender identity key signature over the enclosure. See section 6.5.  |

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

### 6.5 Sender Signature

`enclosure.sender_signature` is a signature produced by the sending user's
identity key over the canonical bytes of the enclosure. It binds the
enclosure plaintext to the sender's identity independently of the
`seal.signature` (which binds ciphertext at the sender's domain).

The sender_signature exists so that an enclosure plaintext, once decrypted,
can be cryptographically attributed to its original sender by any party
that subsequently obtains the plaintext. This is the foundation of forward
provenance defined in section 6.6.

#### 6.5.1 Signing Key

The signing key MUST be the sending user's published identity key
(`KEY.md` section 1.1). Device subkeys, ephemeral keys, and session keys
MUST NOT be used. Identity is the property that survives forwarding; per
device attribution is not.

#### 6.5.2 Signature Scope

The sender computes the signature as follows:

1. Set `enclosure.sender_signature.algorithm` to the suite-bound signature
   algorithm.
2. Set `enclosure.sender_signature.key_id` to the fingerprint of the
   identity key.
3. Set `enclosure.sender_signature.value` to the empty string `""`.
4. Compute the canonical JSON serialization of the entire enclosure object
   per section 4.3 canonicalization rules.
5. Sign the canonical bytes with the identity private key.
6. Replace `enclosure.sender_signature.value` with the base64-encoded
   signature.

Every other field of the enclosure (`subject`, `content_type`, `body`,
`attachments`, `forwarded_from`, `extensions`) is covered by the signature.

#### 6.5.3 Signature Verification

A recipient client MUST verify `enclosure.sender_signature` after decrypting
the enclosure and before rendering any content to the user. Verification:

1. Reconstruct the canonical bytes by setting `sender_signature.value` to
   `""` and re-serializing per section 4.3.
2. Fetch the sender's identity key indicated by `sender_signature.key_id`,
   sourced from the sender's published key set (`KEY.md` section 3).
3. Verify the signature against the canonical bytes.

If verification fails, the recipient client MUST NOT display the enclosure
content as authored by the claimed sender. The client SHOULD surface the
verification failure to the user as a security warning. The client MUST
NOT silently render the content.

If `sender_signature.key_id` does not match any currently published or
historically-published-and-now-revoked identity key for the sender, the
client MUST treat verification as failed.

#### 6.5.4 Non-Repudiation Property

The sender signature is a non-repudiable signature over the enclosure
content. A sender who signs an enclosure cannot later credibly deny having
authored it, given the signature plus the plaintext.

This is an intentional property of the design. SEMP prioritizes
verifiable provenance (so that forwarded content can be attributed to its
true author) over plausible deniability. Senders who require deniability
SHOULD use ephemeral channels outside SEMP for such content.

### 6.6 Forwarded Envelopes

When a recipient client forwards a previously received envelope, the new
envelope's enclosure carries a `forwarded_from` block containing the
original enclosure plaintext and accompanying advisory metadata.

A forward composes a fresh envelope addressed to the new recipient, sealed
by the forwarder's domain and signed by the forwarder's identity key.
The new envelope is structurally indistinguishable from any other envelope
to routing servers; the forward is visible only to the new recipient
client after enclosure decryption.

#### 6.6.1 Forwarded Block Schema

```json
{
    "original_enclosure_plaintext": {
        "subject": "...",
        "content_type": "...",
        "body": { "...": "..." },
        "attachments": [],
        "forwarded_from": null,
        "extensions": {},
        "sender_signature": {
            "algorithm": "ed25519",
            "key_id": "original-sender-identity-key-fingerprint",
            "value": "base64-signature"
        }
    },
    "original_seal": { },
    "original_postmark": { },
    "original_sender_address": "alice@example.com",
    "received_at": "2026-04-15T14:30:00Z",
    "forwarder_attestation": {
        "algorithm": "ed25519",
        "key_id": "forwarder-identity-key-fingerprint",
        "value": "base64-signature"
    }
}
```

#### 6.6.2 Forwarded Block Fields

| Field                          | Type     | Required | Description                                                                                       |
|--------------------------------|----------|----------|---------------------------------------------------------------------------------------------------|
| `original_enclosure_plaintext` | `object` | Yes      | The full decrypted enclosure of the original envelope, including its `sender_signature`.          |
| `original_seal`                | `object` | No       | The original envelope's seal, preserved verbatim. Advisory only (see section 6.6.4).              |
| `original_postmark`            | `object` | No       | The original envelope's postmark, preserved verbatim. Advisory only (see section 6.6.4).          |
| `original_sender_address`      | `string` | Yes      | The full sender address from the original envelope's `brief.from`. Bound by `forwarder_attestation`. |
| `received_at`                  | `string` | Yes      | ISO 8601 UTC timestamp at which the forwarder received the original envelope.                     |
| `forwarder_attestation`        | `object` | Yes      | Forwarder's identity key signature over the forwarded block. See section 6.6.3.                   |

The new enclosure's own `subject`, `body`, and `attachments` MAY contain
the forwarder's own commentary on the forwarded content. The original
content lives only in `forwarded_from.original_enclosure_plaintext`. The
forwarder MUST NOT modify `original_enclosure_plaintext` in any way; doing
so would invalidate the original sender's `sender_signature` carried within
it.

#### 6.6.3 Forwarder Attestation

`forwarded_from.forwarder_attestation` is a signature produced by the
forwarder's identity key over the canonical bytes of the
`forwarded_from` object with `forwarder_attestation.value` set to `""`.

The attestation binds:

- The original enclosure plaintext (and through its inner
  `sender_signature`, the original sender's identity).
- The advisory `original_seal` and `original_postmark` if present.
- The claimed `original_sender_address`.
- The `received_at` timestamp.

The forwarder's identity is established by the new envelope's outer
`enclosure.sender_signature` (section 6.5), which the new recipient
verifies first. The attestation key in `forwarder_attestation.key_id`
MUST match the `sender_signature.key_id` of the new enclosure. A new
recipient MUST reject a `forwarded_from` block whose
`forwarder_attestation.key_id` differs from the outer
`sender_signature.key_id`.

#### 6.6.4 Verification by the New Recipient

A recipient client receiving an envelope with non-null
`forwarded_from` MUST perform the following verification, in order, after
the standard decryption flow (section 7.2):

1. Verify the new envelope's `enclosure.sender_signature` per section 6.5.3.
   This authenticates the forwarder.
2. Verify `forwarded_from.forwarder_attestation` against the canonical
   bytes of `forwarded_from` (with `forwarder_attestation.value` set to
   `""`), using the forwarder's identity key. This authenticates the
   forwarding act.
3. Verify
   `forwarded_from.original_enclosure_plaintext.sender_signature` per
   section 6.5.3, using the original sender's identity key as indicated
   by that signature's `key_id` and the
   `forwarded_from.original_sender_address`. This authenticates the
   original content as authored by the original sender.

If steps 1 or 3 fail, the recipient client MUST NOT display the original
content as attributed to the claimed original sender. If step 2 fails,
the recipient client MUST NOT display the forwarded block at all and
SHOULD treat the envelope as if `forwarded_from` were null, surfacing a
security warning.

`original_seal` and `original_postmark` are advisory only. The new
recipient cannot independently verify `original_seal.signature` because
the original ciphertext is not preserved in the forward. Clients MAY use
these fields to display additional context (such as the original
postmark expiry or message ID) but MUST NOT present them as
cryptographically verified evidence.

#### 6.6.5 Multi-Level Forwarding

`original_enclosure_plaintext.forwarded_from` MAY itself be non-null,
representing a forward of a forward. Verification in section 6.6.4
applies recursively: the new recipient verifies each level of the
forwarding chain using the inner `sender_signature` and
`forwarder_attestation` at each level.

A recipient MUST verify the full chain or treat any unverified inner
level as advisory. A client that displays forwarded content from a
chain SHOULD make the chain depth and the identity of each forwarder
visible to the user.

#### 6.6.6 Forwarding and Non-Repudiation

Because `original_enclosure_plaintext.sender_signature` is preserved
verbatim, a forwarded enclosure carries the original sender's
non-repudiable signature to every downstream recipient. Senders who do
not wish their content to be cryptographically attributable when
forwarded SHOULD use ephemeral channels outside SEMP for such content.
SEMP does not provide a sender-side opt-out from forward provenance.

---

## 7. Encryption Model

### 7.1 Encryption Flow

Sending an envelope follows this sequence:

1. Compose the plaintext `brief` and `enclosure` as JSON objects. If the
   envelope is a forward, populate `enclosure.forwarded_from` per section
   6.6, including the forwarder's `forwarder_attestation` signature.
2. Compute `enclosure.sender_signature` over the canonical enclosure bytes
   per section 6.5.2, using the sending user's identity key. The
   resulting signature value is written into `enclosure.sender_signature`.
3. Generate two fresh independent random symmetric keys: `K_brief` and `K_enclosure`.
4. Encrypt the `brief` JSON bytes under `K_brief`. Store result in `envelope.brief`.
5. Encrypt the (now signed) `enclosure` JSON bytes under `K_enclosure`. Store
   result in `envelope.enclosure`.
6. Fetch the recipient client's current public encryption key and the recipient
   server's published domain key. The client obtains these from its home server
   via `SEMP_KEYS` with `step: request` per `CLIENT.md` section 5.4.
7. Encrypt `K_brief` under the recipient server's domain key. Store in
   `seal.brief_recipients` keyed by the server's domain key fingerprint.
8. Encrypt `K_brief` under the recipient client's encryption key. Store in
   `seal.brief_recipients` keyed by the client's key fingerprint.
9. Encrypt `K_enclosure` under the recipient client's encryption key. Store in
   `seal.enclosure_recipients` keyed by the client's key fingerprint.
10. Compose the `postmark`, including `postmark.session_id`.

Steps 1 through 10 are performed by the sending client. The client then
transmits the assembled envelope to its home server, which performs the
remaining steps. The client does not hold the domain private key or the
session key material required for seal computation.

11. Compute the canonical envelope bytes (both `seal.signature` and
    `seal.session_mac` set to `""`, `postmark.hop_count` omitted).
12. Sign the canonical bytes with the sender's domain private key. Store in
    `seal.signature`.
13. Compute a MAC over the canonical bytes using `K_env_mac` from the active
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
10. Client verifies `enclosure.sender_signature` per section 6.5.3 against
    the sender's identity key. The client MUST NOT render enclosure content
    if verification fails.
11. If `enclosure.forwarded_from` is non-null, the client performs the
    forwarded-envelope verification chain per section 6.6.4.
12. Client verifies attachment hashes against decrypted attachment content.

Steps 1 through 4 MUST all pass before any further processing. Each failure
MUST produce an immediate, explicit rejection with the appropriate reason code.
Step 1 may be performed by any routing server. Steps 2 through 7 are performed
by the receiving server only. Steps 8 through 12 are performed by the client.

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

### 7.4 Per-Extension Cryptographic Key Scoping

Some extensions place data in `enclosure.extensions` that is intended for
only a subset of the recipient user's devices. A delegated filter device
(`CLIENT.md` section 2.3) that produces a classification result for the
user's main reading device is the canonical example: the filter device
SHOULD be able to read the inbound envelope's enclosure to perform the
classification, but the classification result it produces SHOULD be
readable only by the main reading device, not by every device that
receives the envelope.

The reference SDK enforcement contract (`EXTENSIONS.md` section 9)
restricts behavior at the implementation layer. Cryptographic key scoping
restricts read access at the protocol layer, independent of any SDK
guarantees. A device that is not given the wrapped key for a particular
extension's enclosure data cannot decrypt that data, regardless of
implementation honesty.

#### 7.4.1 Wire Format

When an extension entry in `enclosure.extensions` requires per-extension
key scoping, the entry's `data` field is itself an encrypted blob and the
seal carries a separate `extension_keys` map keyed by extension identifier:

```json
"seal": {
    "enclosure_recipients": {
        "default": {
            "device-key-id-1": "wrapped-K_enclosure-default",
            "device-key-id-2": "wrapped-K_enclosure-default"
        },
        "extension_keys": {
            "semp.dev/classification-result": {
                "device-key-id-1": "wrapped-K_ext-classification"
            }
        }
    }
}
```

```json
"enclosure": {
    "extensions": {
        "semp.dev/classification-result": {
            "required": true,
            "scoped": true,
            "data": "base64-AEAD-ciphertext-encrypted-under-K_ext"
        }
    }
}
```

The `default` map under `enclosure_recipients` carries the wrapped
`K_enclosure` for entries that do not use per-extension scoping (the
existing behavior). The `extension_keys` map carries one entry per
scoped extension; each entry is a map from device key fingerprint to the
wrapped per-extension key.

A scoped extension entry MUST set `scoped: true` and MUST place its
encrypted payload in the `data` field as a base64-encoded AEAD ciphertext
under the per-extension key. The plaintext under encryption is the
canonical JSON serialization of the extension-specific data object as
defined by the extension's `data_schema`.

#### 7.4.2 Key Derivation

Each per-extension key is generated freshly for each envelope by the
producing party. The key is derived independently from `K_enclosure`:

```
K_ext = HKDF-Expand(
    PRK = random(32 bytes, generated per envelope),
    info = "SEMP-v1-ext-" || extension_identifier,
    L = 32
)
```

The PRK is generated freshly per envelope and is not derived from
`K_enclosure` or any session key. This ensures that compromise of
`K_enclosure` does not yield `K_ext`, and compromise of `K_ext` does not
yield `K_enclosure`. The two key spaces are independent.

The AEAD cipher MUST match the negotiated suite's symmetric cipher
(`ChaCha20-Poly1305` for both currently defined suites). The associated
data MUST include the canonical envelope ID (`postmark.id`) and the
extension identifier to bind the ciphertext to its envelope and to
prevent cross-extension substitution.

#### 7.4.3 Wrapping

The producing party wraps the per-extension key under the public
encryption keys of every device that should be able to read the
extension data. Devices not listed in the `extension_keys` map for a
given extension cannot recover the plaintext.

The wrapping uses the same key encapsulation mechanism as
`enclosure_recipients` (the negotiated suite's KEM, applied per
recipient device key).

#### 7.4.4 Decryption

A receiving device performs the following steps for each scoped
extension entry it encounters:

1. Look up its own device key fingerprint in
   `seal.enclosure_recipients.extension_keys[<identifier>]`.
2. If no entry is present, the device is not authorized to read this
   extension. The device MUST treat the entry as opaque and MUST NOT
   attempt to decrypt the `data` field.
3. If an entry is present, unwrap to recover `K_ext`.
4. Decrypt the `data` field using `K_ext` and the AEAD cipher with the
   declared associated data.
5. Validate the resulting plaintext against the extension's
   `data_schema` per `EXTENSIONS.md` section 8.2.

A device that is not authorized to read a scoped extension MUST NOT
include the extension in any user-visible representation of the
envelope and MUST NOT report decryption failure as an error to the user.
Absence of authorization is normal operation, not failure.

#### 7.4.5 Use With `required` Flag

A scoped extension MAY be marked `required: true`. The required-extension
semantics (`EXTENSIONS.md` section 3.1) apply at the recipient server
layer, since the server can confirm the extension's presence and
identifier without holding the per-extension key. A receiving device that
holds no key for a required scoped extension processes the envelope
normally; the extension is required to be present, not required to be
readable by every device.

#### 7.4.6 Size Accounting

The encrypted `data` blob counts toward the size limit on
`enclosure.extensions` defined in `EXTENSIONS.md` section 4.1. Producing
parties SHOULD account for ciphertext expansion (typically 16 bytes of
AEAD tag plus base64 overhead) when sizing scoped extension payloads.

The `extension_keys` map in the seal counts toward the seal size budget
and adds approximately 64 bytes per device per scoped extension. Heavy
use of per-extension key scoping across many devices increases envelope
size proportionally.

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

| Reason code             | Meaning                                                                  |
|-------------------------|--------------------------------------------------------------------------|
| `blocked`               | The sender or their domain is blocked. MAY be returned only when the recipient's policy permits revealing the block. Otherwise `policy_forbidden` MUST be returned in its place. |
| `handshake_invalid`     | The session referenced by `postmark.session_id` has been invalidated.   |
| `handshake_expired`     | The session TTL has elapsed. Sender server should re-handshake and retry.|
| `no_session`            | `postmark.session_id` is absent or does not reference a known session.   |
| `seal_invalid`          | `seal.signature` domain key verification failed.                         |
| `session_mac_invalid`   | `seal.session_mac` session key MAC verification failed.                  |
| `envelope_expired`      | `postmark.expires` is in the past.                                       |
| `policy_forbidden`      | Delivery refused for policy reasons. The protocol does not distinguish among the underlying causes through this code. The rejection response MAY include a `challenge` body inviting the sender to retry with proof of work. See `DELIVERY.md` section 6.4 and `DESIGN.md` section 2.7. |

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

### 10.8 Forwarding Provenance

`enclosure.sender_signature` (section 6.5) and `enclosure.forwarded_from`
(section 6.6) together provide the forwarding provenance model.

Anti-forgery: a forwarder cannot fabricate a forward that appears to
originate from a third party. The original sender's identity key signature
on the enclosure plaintext travels with the content. A forger would need
the original sender's identity private key to produce a verifiable
`forwarded_from.original_enclosure_plaintext.sender_signature`.

Anti-tampering: a forwarder cannot alter the original content while
preserving its provenance. Any modification to
`original_enclosure_plaintext` invalidates the inner sender signature.

Limits of evidence: the new recipient cannot independently verify the
original envelope's `seal.signature` because the original ciphertext is
not preserved. `original_seal` and `original_postmark` in the forwarded
block are advisory only. The cryptographic provenance is the identity-key
signature on the plaintext, not the domain-key signature on the
ciphertext.

The forwarder is bound by `forwarder_attestation` (section 6.6.3),
which signs the forwarded block including the claimed
`original_sender_address` and `received_at`. A forwarder who falsifies
these fields is making a verifiable, non-repudiable claim under their
own identity key.

Identity-key compromise: an attacker who obtains a user's identity
private key can forge that user's authorship of arbitrary content,
including content carried in forwards composed by others. This risk is
the same as for any signature-based authorship system. Identity key
rotation and revocation per `KEY.md` sections 7 and 8 limit the window
in which a compromised key can be used.

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