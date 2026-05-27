## Abstract

This document specifies the wire format of a Sealed Envelope Messaging
Protocol (SEMP) envelope. An envelope comprises a postmark, a seal, a
brief, and an enclosure. The postmark and seal are visible to routing
servers; the brief and enclosure are encrypted under the recipient's
keys. SEMP envelopes carry two independent integrity proofs over the
same canonical bytes: a domain signature verifiable by any routing
server, and a session MAC verifiable only by the receiving server. The
enclosure additionally carries a sender identity signature that
provides forwarding provenance independent of any domain signature.
This document also registers the media types associated with SEMP
artifacts: `application/semp-envelope`, `application/semp-receipt`,
`application/semp-recovery`, and `application/semp-migration`.

# Introduction

The SEMP envelope is the unit of transmission in the protocol. It is
modeled on physical correspondence and consists of four components:

* a postmark (outer public header, visible to routing servers);
* a seal (cryptographic integrity proof, tamper-evident);
* a brief (inner private header, encrypted, decryptable by the
  recipient server and the recipient client);
* an enclosure (message body and attachments, encrypted, decryptable
  only by the recipient client).

This document specifies the wire format, field semantics,
canonicalization rules, encryption model, signature schemes,
forwarding provenance, server responsibilities, and media-type
registrations associated with SEMP envelopes. The architectural role
of each component is defined in [Architecture](architecture.md);
this document is the normative wire-format companion to that
architecture.

The brief is decryptable by the recipient server because the server
performs delivery and user-level policy enforcement (block-list
checks, first-contact gating, recipient status). The enclosure is
decryptable only by the recipient client. No routing server can read
the enclosure under any circumstances.

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

This document additionally uses terminology from [RFC 4949](https://www.rfc-editor.org/rfc/rfc4949) for
general security-protocol terms.

## Field Presence Convention

Schemas in this document mark each field as Required Yes or
Required No. A field marked Required Yes MUST appear in the
canonical serialization of the containing record. When such a
field's type is declared as `T | null`, the field MUST be
present and its value MAY be `null` to signal explicit absence;
the field still appears in the canonical bytes covered by any
signature or MAC over the record. A field marked Required No
MAY be omitted entirely. When omitted, it does not appear in
the canonical bytes and is not covered by any signature or MAC.
This distinction is significant because `T | null` Required Yes
and `T` Required No produce different canonical inputs to
signature verification.

# Envelope Structure

## Top-Level Schema

A SEMP envelope is a JSON object [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259) with the following
top-level shape:

~~~ json
{
    "type": "SEMP_ENVELOPE",
    "version": "1.0.0",
    "postmark": { },
    "seal": { },
    "brief": "<base64-encoded-encrypted-bytes>",
    "enclosure": "<base64-encoded-encrypted-bytes>",
    "padding": "<base64-alphabet-filler-or-empty>"
}
~~~

The `brief` and `enclosure` fields are opaque encrypted blobs at the
transport layer. Their internal structure is defined in [Brief](#brief) and
[Enclosure](#enclosure) respectively, and is meaningful only after decryption
by the recipient.

## Top-Level Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | MUST be `"SEMP_ENVELOPE"`. |
| `version` | string | Yes | Protocol version in semver format. |
| `postmark` | object | Yes | Outer public routing header. See [Postmark](#postmark). |
| `seal` | object | Yes | Cryptographic integrity proof. See [Seal](#seal). |
| `brief` | string | Yes | Encrypted inner header, base64. See [Brief](#brief). |
| `enclosure` | string | Yes | Encrypted message body and attachments, base64. See [Enclosure](#enclosure). |
| `padding` | string | Yes | Opaque base64-alphabet filler. See [Envelope Padding](#envelope-padding). MAY be the empty string. |

<a id="address-canonicalization"></a>

## Address Canonicalization
Every SEMP address in wire form is the UTF-8 string `local-part "@"
domain`, where `local-part` and `domain` are each normalized to a
single canonical form before signing, hashing, comparison, or
storage. A non-canonical address MUST be rejected as malformed at
the point of ingress.

### Local-Part

The local-part MUST be Unicode-normalized to Normalization Form C
(NFC). Implementations MUST NOT apply compatibility decomposition
(NFKD or NFKC). Case folding is NOT applied; the local-part is
case-sensitive on the wire. Operators that wish to treat
`Alice@example.com` and `alice@example.com` as the same recipient
MUST perform that mapping at the local delivery layer rather than
at the protocol layer.

A local-part MUST NOT contain U+0040 COMMERCIAL AT, U+0000 NUL, any
C0 or C1 control character, or any code point that is unassigned
in the active Unicode version at the time of canonicalization. A
local-part's UTF-8 encoding MUST NOT exceed 64 octets.

### Domain

The domain MUST be encoded in its A-label (Punycode,
ASCII-compatible) form per IDNA2008 ([RFC 5890](https://www.rfc-editor.org/rfc/rfc5890), [RFC 5891](https://www.rfc-editor.org/rfc/rfc5891))
before being placed in any SEMP message. U-label (Unicode) forms
are for user-interface display only and MUST NOT appear on the
wire. A conformant implementation receiving a domain that contains
any code point outside the ASCII range 0x00 to 0x7F MUST reject
the address as malformed.

Domain matching is case-insensitive per DNS convention. An
implementation MUST fold the domain to lower case before
comparison, signing, or hashing. On the wire (in any SEMP message
between SEMP nodes) the domain MUST be lower case. A SEMP node
receiving a mixed-case domain in any protocol field MUST reject
the address as malformed.

A trailing `.` is a DNS presentation form and MUST NOT appear in
SEMP addresses on the wire.

### Composition and Length

After local-part NFC normalization and domain A-label encoding,
the composed address `local-part "@" domain` MUST NOT exceed 254
octets of UTF-8. Clients MUST enforce this bound at envelope
composition time and MUST NOT produce a seal over an envelope
whose brief contains any non-canonical or over-length address. A
server that detects a canonicalization failure after brief
decryption MUST reject the envelope with `reason_code:
"policy_forbidden"`, preserving the address-enumeration
resistance required by [Architecture](architecture.md).

### Equivalence

Two addresses are equivalent if and only if their local-parts are
identical octet-for-octet after NFC normalization AND their
domains are identical octet-for-octet after A-label encoding and
lower-case folding. The protocol MUST NOT assume any other
equivalence. Visually similar characters (Cyrillic U+0430 versus
Latin U+0061, for example) produce distinct addresses under this
rule; confusables defense is the responsibility of user-interface
layers and is outside the scope of this specification.

<a id="envelope-padding"></a>

## Envelope Padding
The `padding` field carries opaque bytes whose sole purpose is to
obscure the wire size of an envelope from any observer of routing
infrastructure. Sending clients MUST populate `padding` so that
the total wire size of the canonical envelope falls on one of the
size buckets defined below. Routing servers and recipient servers
MUST ignore the contents of `padding` during delivery and MUST
count its bytes toward the negotiated `max_envelope_size`
enforcement.

### Size Buckets

The size of the canonical envelope, measured in bytes of UTF-8
encoded JSON (the same canonical form defined in
[Signature Scope and Canonicalization](#signature-scope-and-canonicalization), with `padding`
included), MUST equal a value in the chosen bucket sequence after
padding.

Conformant implementations use the following power-of-two
sequence unless the operator configures an alternative:

~~~
4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288,
1048576, 2097152, 4194304, 8388608, 16777216, max_envelope_size
~~~

The smallest bucket is 4096 bytes. Each subsequent bucket is
twice the previous, up to `max_envelope_size` (the
session-negotiated ceiling, defined in
[Handshake](handshake.md)). A sender MUST pick the smallest
bucket whose value is at least the unpadded envelope size. An
envelope whose unpadded size exceeds `max_envelope_size` MUST be
recomposed; padding is not a remedy for over-limit content.

An operator MAY configure a custom bucket sequence for their
deployment. Any custom sequence MUST be monotonically strictly
increasing, MUST have its first element at or above 4096 bytes,
and MUST have its last element at or below the
session-negotiated `max_envelope_size`. The receiver does not
need to know the sender's bucket sequence.

### Padding Content

`padding` is a string of characters drawn from the base64
alphabet defined in [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) (`A-Z`, `a-z`, `0-9`, `+`, `/`,
and `=`). Its sole purpose is to adjust the envelope's wire
size; the bytes have no internal structure and MUST NOT be
decoded or interpreted by any party.

Senders MUST derive the characters from a cryptographically
secure source. The string is NOT required to be a valid base64
encoding of an integer number of bytes because base64 has a
4-character granularity while buckets require byte-level
alignment.

Senders MUST NOT reuse padding characters across envelopes; each
envelope receives fresh randomness. Zero bytes are PERMITTED but
NOT RECOMMENDED because they can leak the padding boundary under
compression.

### Interaction with the Seal

`padding` is outside the signature scope and is not covered by
`seal.signature` or `seal.session_mac` per
[Signature Scope and Canonicalization](#signature-scope-and-canonicalization). A routing
intermediary that alters `padding` does not tamper with the
authenticated envelope, and a recipient server validates the
seal against the unpadded canonical bytes without dependency on
padding content. Padding is a size-obfuscation mechanism rather
than an integrity mechanism.

### Minimum Floor

The 4096-byte floor means every envelope, including the smallest
plaintext-only messages, occupies at least 4 KiB on the wire. A
minimal SEMP envelope (postmark, seal with one recipient's
wrapped keys, short encrypted brief, short encrypted enclosure)
is typically around 1.5 to 2.5 KiB before padding, so the 4 KiB
floor consolidates all short messages into one indistinguishable
bucket. Operators that require stricter unlinkability MAY
configure a higher floor.

<a id="device-sync-padding"></a>

### Device-Sync Envelopes
Envelopes carrying the `semp.dev/device-sync` extension
marker ([Extensions](extensions.md)) MUST follow the
same padding rules as any other envelope. Device-sync
envelopes travel over the public internet to the user's
home server and MAY pass through the same routing
infrastructure a cross-domain envelope would; a passive
observer could otherwise distinguish device-sync traffic
from correspondent traffic by size pattern alone.

Send-time delay mechanisms that batch device-sync
envelopes more aggressively than user-visible sends apply
to timing, not to size. Device-sync envelopes MAY be
delayed longer than user-visible sends because their
timing is not observable to correspondents, but their
size padding is unchanged.

<a id="postmark"></a>

# Postmark
The postmark contains the minimum information necessary to route
and deliver the envelope. It MUST NOT contain sender or recipient
addresses in full. It MUST NOT contain a subject, a precise
timestamp, or any field that could be used to infer the nature
or content of the correspondence.

A routing server reads the postmark and no other component.

## Postmark Schema

~~~ json
{
    "postmark": {
        "id": "01J4K7P2XVEM3Q8YNZHBRC5T06",
        "session_id": "session-ulid-from-established-handshake",
        "from_domain": "example.com",
        "to_domain": "otherdomain.com",
        "expires": "2026-06-08T13:05:00Z",
        "hop_count": 0,
        "extensions": {}
    }
}
~~~

## Postmark Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | Yes | Opaque message identifier, ULID or UUID. |
| `session_id` | string | Yes | Session identifier from the established handshake. Envelopes without a valid `session_id` MUST be rejected. |
| `from_domain` | string | Yes | Sender's fully-qualified domain. MUST NOT include a local part or display name. |
| `to_domain` | string | Yes | Recipient's fully-qualified domain. MUST NOT include a local part or display name. |
| `expires` | string | Yes | ISO 8601 UTC expiry timestamp. Servers MUST reject expired envelopes. |
| `hop_count` | integer | No | Number of relay hops. Starts at `0` when present. See [Hop Count](#hop-count). |
| `extensions` | object | No | Postmark-layer extensions. MUST NOT contain private metadata. |

## Notes on the Message ID

The `id` field is an opaque routing identifier scoped to the
delivery transaction. Its purpose is deduplication and loop
detection at the routing layer rather than conversation
threading. Threading and conversation identifiers belong in the
brief.

Implementations SHOULD use ULIDs for `id` due to their
time-ordered and URL-safe properties. UUIDs are also acceptable.

<a id="hop-count"></a>

## Hop Count
`hop_count` is an optional transit field. Relay servers that
support hop tracking SHOULD increment it before forwarding.
Relay servers that do not support hop tracking MUST forward the
field unchanged if present, and MAY forward the envelope without
adding the field if absent.

When present, servers MAY reject envelopes whose `hop_count`
exceeds a configured maximum (RECOMMENDED ceiling: 25) as a loop
prevention measure. Servers MUST NOT reject envelopes solely
because `hop_count` is absent.

Because `hop_count` is mutable in transit, it is excluded from
the seal signature scope. See
[Signature Scope and Canonicalization](#signature-scope-and-canonicalization).

<a id="seal"></a>

# Seal
The seal provides two independent cryptographic proofs over the
same canonical envelope bytes:

* `seal.signature`: signed with the sender's domain private key,
  verifiable by any server that holds the sender's published
  domain key without any prior session. This is the
  routing-layer integrity proof.
* `seal.session_mac`: a MAC computed using the session key
  derived during the handshake, verifiable only by the receiving
  server, which holds the session key. This is the
  delivery-layer session enforcement proof.

Together, these two proofs make the envelope and the handshake
session cryptographically inseparable at delivery. A forged
envelope that passes domain key verification but was not produced
within a valid session will fail the session MAC check. A
routing server that did not participate in the handshake can
still verify the domain signature for routing integrity.

A server that receives an envelope with an invalid or missing
`seal.signature` MUST reject it immediately. A receiving server
that additionally finds an invalid `seal.session_mac` MUST reject
the envelope with `reason_code: "session_mac_invalid"`.

## Seal Schema

~~~ json
{
    "seal": {
        "algorithm": "pq-kyber768-x25519",
        "key_id": "sender-domain-key-fingerprint",
        "signature": "base64-encoded-domain-key-signature",
        "session_mac": "base64-encoded-session-key-mac",
        "brief_recipients": {
            "recipient-server-domain-key-fingerprint":
                "base64-K_brief-encrypted-under-server-domain-key",
            "recipient-client-key-fingerprint":
                "base64-K_brief-encrypted-under-client-key"
        },
        "enclosure_recipients": {
            "recipient-client-key-fingerprint":
                "base64-K_enclosure-encrypted-under-client-key"
        },
        "first_contact_token": null,
        "extensions": {}
    }
}
~~~

## Seal Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `algorithm` | string | Yes | Algorithm suite used for signing and key encapsulation. |
| `key_id` | string | Yes | Fingerprint of the sender domain key used to produce `signature`. |
| `signature` | string | Yes | Domain key signature over canonical envelope bytes. |
| `session_mac` | string | Yes | Session key MAC over canonical envelope bytes. |
| `brief_recipients` | object | Yes | Map of key fingerprint to encrypted copy of `K_brief`. Includes both the recipient server's domain key and the recipient client's encryption key. |
| `enclosure_recipients` | object | Yes | Map of key fingerprint to encrypted copy of `K_enclosure`. Includes only the recipient client's encryption key. |
| `first_contact_token` | object \| null | Yes | Proof-of-work token presented in response to a first-contact challenge. `null` when not required or not yet issued. See [Delivery](delivery.md) and [Handshake](handshake.md). |
| `extensions` | object | No | Seal-layer extensions. |

<a id="signature-scope-and-canonicalization"></a>

## Signature Scope and Canonicalization
Both `seal.signature` and `seal.session_mac` are computed over
the same canonical serialization of the envelope, defined as the
UTF-8 JSON encoding of the envelope with:

* keys sorted lexicographically at every level;
* no insignificant whitespace;
* `seal.signature` set to the empty string `""` during both
  computations;
* `seal.session_mac` set to the empty string `""` during both
  computations;
* `postmark.hop_count` omitted entirely, whether or not present
  in transit;
* `padding` omitted entirely, whether or not present in transit.

Setting both signature fields to empty string during computation
means neither proof depends on the value of the other. Both
cover identical input bytes. The canonical form is computed once
and passed to both verification routines.

`hop_count` is excluded because it is a mutable transit field.
`padding` is excluded because its bytes serve only to obscure
wire size: they are ignored during verification and MAY be
altered in transit without affecting envelope authenticity.
All other postmark fields are immutable and covered by both
proofs.

This canonical form MUST be reproduced identically by any
implementation.

<a id="signature-domain-separation"></a>

### Signature Domain Separation
All Ed25519 [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) signatures in SEMP MUST prepend a
context-specific prefix to the signed message before signing.
This prevents cross-context signature confusion where a
signature valid in one context could be misinterpreted in
another.

| Context | Prefix |
|---|---|
| Envelope seal signature | `SEMP-ENVELOPE:` |
| Handshake message signature | `SEMP-HANDSHAKE:` |
| Identity proof signature | `SEMP-IDENTITY:` |
| Key response signature | `SEMP-KEYS:` |
| User key self-signature | `SEMP-KEY-SELF-SIG:` |
| Discovery response signature | `SEMP-DISCOVERY:` |
| Configuration update notification | `SEMP-CONFIGURATION-UPDATE:` |
| Revocation signature | `SEMP-REVOCATION:` |
| Delivery receipt signature | `SEMP-DELIVERY-RECEIPT:` |
| Recovery backup bundle signature | `SEMP-RECOVERY-BUNDLE:` |
| Recovery set manifest signature | `SEMP-RECOVERY-MANIFEST:` |
| Recovery share device signature | `SEMP-RECOVERY-SHARE:` |
| Successor record signatures | `SEMP-SUCCESSOR-RECORD:` |
| Migration record signatures | `SEMP-MIGRATION-RECORD:` |
| Device registration signature | `SEMP-DEVICE-REGISTER:` |
| Device enrollment authorization | `SEMP-DEVICE-AUTHORIZE:` |
| Device revocation signature | `SEMP-DEVICE-REVOCATION:` |
| Device directory signature | `SEMP-DEVICE-DIRECTORY:` |
| Enclosure sender signature | `SEMP-ENCLOSURE-SENDER:` |
| Forwarder attestation signature | `SEMP-FORWARDER-ATTESTATION:` |
| User policy update signature | `SEMP-USER-POLICY:` |
| Account closure request/cancel signature | `SEMP-ACCOUNT-CLOSURE:` |
| Transparency Signed Tree Head signature | `SEMP-TRANSPARENCY-STH:` |
| User status configuration signature | `SEMP-STATUS:` |
| Trust observation signature | `SEMP-TRUST-OBSERVATION:` |
| Trust transfer record signature | `SEMP-TRUST-TRANSFER:` |
| Reputation references document signature | `SEMP-REPUTATION-REFERENCES:` |
| Abuse report signature | `SEMP-ABUSE-REPORT:` |

The signed input is always `prefix || canonical_bytes`.
Verification MUST reconstruct the same prefixed input before
calling Ed25519 Verify. Deviations in key ordering, whitespace,
or field exclusion handling will produce verification failures.

### Two-Layer Verification Responsibilities

| Layer | Verifies | Uses | Performed by |
|---|---|---|---|
| Routing | `seal.signature` | Sender domain key | Any routing server |
| Delivery | `seal.session_mac` | Session key `K_env_mac` | Receiving server only |

Routing servers MUST verify `seal.signature`. They cannot verify
`seal.session_mac` as they do not hold the session key.
Receiving servers MUST verify both.

<a id="anchoring-layer"></a>

### Anchoring Layer per Signature Context
Each context in the [Signature Domain Separation
table](#signature-domain-separation) anchors to one of two keys,
capturing the two-layer trust model described in
[Architecture](architecture.md), "Domain and Author Anchored
Trust".

| Context | Anchored to | What it proves |
|---|---|---|
| `SEMP-ENVELOPE:` | Domain | Envelope was emitted by the claimed sending domain |
| `SEMP-HANDSHAKE:` | Domain | Federation peer is the claimed domain |
| `SEMP-KEYS:` | Domain | Authenticated set of published user keys for the domain |
| `SEMP-DISCOVERY:` | Domain | Discovery response came from the claimed domain |
| `SEMP-CONFIGURATION-UPDATE:` | Domain | Authentic update to the domain's configuration |
| `SEMP-DELIVERY-RECEIPT:` | Domain | Recipient domain acknowledged delivery |
| `SEMP-TRANSPARENCY-STH:` | Domain | Transparency log signed tree head |
| `SEMP-TRUST-OBSERVATION:` | Domain | Domain observed peer behavior |
| `SEMP-TRUST-TRANSFER:` | Domain | Domain ownership / key change with reputation handoff |
| `SEMP-REPUTATION-REFERENCES:` | Domain | Domain published its reputation references |
| `SEMP-ABUSE-REPORT:` | Domain | Domain reported peer abuse |
| `SEMP-REVOCATION:` | Issuing key (domain or user) | Key holder revoked their own key |
| `SEMP-IDENTITY:` | User | User asserts identity inside the enclosure |
| `SEMP-ENCLOSURE-SENDER:` | User | Inner sender attestation; survives forwarding |
| `SEMP-KEY-SELF-SIG:` | User | User binds their encryption and device subkeys |
| `SEMP-FORWARDER-ATTESTATION:` | User | Forwarder identifies themselves |
| `SEMP-USER-POLICY:` | User | User updates their policy |
| `SEMP-STATUS:` | User | User publishes status (available, away, do-not-disturb) |
| `SEMP-SUCCESSOR-RECORD:` | User | User declares successor key |
| `SEMP-MIGRATION-RECORD:` | User | User-initiated account migration |
| `SEMP-ACCOUNT-CLOSURE:` | User | User requests account closure |
| `SEMP-RECOVERY-BUNDLE:` | User | User-controlled recovery payload |
| `SEMP-RECOVERY-MANIFEST:` | User | Recovery-set manifest |
| `SEMP-RECOVERY-SHARE:` | User | Recovery share authorization (signed by an authorized device under the user) |
| `SEMP-DEVICE-REGISTER:` | User | User registers a new device |
| `SEMP-DEVICE-AUTHORIZE:` | User | User authorizes a device enrollment |
| `SEMP-DEVICE-REVOCATION:` | User | User revokes a device |
| `SEMP-DEVICE-DIRECTORY:` | User | User publishes their device list |

Domain-keyed signatures verify under a domain's published domain
key (per [Discovery](discovery.md)). User-keyed signatures
verify under a user's identity key. The domain publishes that
identity key inside its user-key record and signs the record
itself under `SEMP-KEYS:`. A user-keyed signature is therefore
indirectly anchored to a domain via the key publication, but the
content attestation is the user's alone and survives any
re-signing of the user's key record by the domain.

<a id="recipient-key-wrapping"></a>

## Recipient Key Wrapping
The envelope uses two symmetric keys with different access
scopes:

* `K_brief` encrypts the brief. It is wrapped under both the
  recipient server's domain key and the recipient client's
  encryption key. The server can decrypt the brief to perform
  delivery and policy enforcement. The client can also decrypt
  it to access message metadata.
* `K_enclosure` encrypts the enclosure. It is wrapped only under
  the recipient client's encryption key. The server cannot read
  the enclosure under any circumstances.

The `brief_recipients` map therefore contains two entries per
recipient: one encrypted under the recipient server's published
domain key (keyed by domain key fingerprint), and one encrypted
under the recipient client's encryption key (keyed by client key
fingerprint). The `enclosure_recipients` map contains only the
client key entry.

The sender MUST hold a current copy of the recipient server's
domain key when composing the envelope, in addition to the
recipient client's encryption key. The sender MAY use a cached
copy that is within its advertised TTL and has not been
revoked. Cache validity, speculative pre-fetching, and batched
fetching of recipient key material are specified in
[Discovery](discovery.md); this section imposes no
additional fetch-timing requirement beyond the freshness rules
defined there.

Key wrapping uses the negotiated suite's KEM for per-recipient
encapsulation. For the baseline suite
(`x25519-chacha20-poly1305`), wrapping uses X25519 [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)
ephemeral key agreement. For the post-quantum suite
(`pq-kyber768-x25519`), wrapping uses the Kyber768 + X25519
hybrid KEM. Post-quantum protection therefore covers envelope
confidentiality at rest as well as session key exchange.
Recipient encryption keys MUST be generated using the same
suite's KEM as the wrapping operation.

### Wrap Construction

Each entry in `seal.brief_recipients` and
`seal.enclosure_recipients` is the base64 encoding [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648)
of a wrap output computed as follows.

Inputs:

* `recipient_pub`: the recipient's public encryption key. For
  the baseline suite this is a 32-byte X25519 public key. For
  the post-quantum suite this is the concatenation of a Kyber768
  encapsulation key (1184 bytes; ML-KEM-768 per FIPS 203) and a
  32-byte X25519 public key, in that order.
* `K`: the symmetric key being wrapped (`K_brief` or
  `K_enclosure`).

Step 1: KEM encapsulation. For the baseline suite:

~~~
ephemeral_priv  := X25519 keygen
ephemeral_pub   := X25519 derive(ephemeral_priv)
shared_secret   := X25519 ECDH(ephemeral_priv, recipient_pub)
kem_ct          := ephemeral_pub
~~~

For the post-quantum suite:

~~~
(kyber_ct,
 kyber_ss)      := Kyber768.Encapsulate(recipient_pub.kyber)
ephemeral_priv  := X25519 keygen
ephemeral_pub   := X25519 derive(ephemeral_priv)
x25519_ss       := X25519 ECDH(ephemeral_priv, recipient_pub.x25519)
shared_secret   := kyber_ss || x25519_ss
kem_ct          := kyber_ct || ephemeral_pub
~~~

`shared_secret` MUST be zeroed from memory after Step 2.

Step 2: Wrap-key derivation, using HKDF [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) with
SHA-512.

~~~
salt := kem_ct || recipient_pub
PRK  := HKDF-Extract(salt, shared_secret, SHA-512)
info := "SEMP-v1-wrap" (UTF-8, no NUL)
wrap_key := HKDF-Expand(PRK, info, L=32, SHA-512)
~~~

`PRK` and `wrap_key` MUST be zeroed from memory after Step 3.

Step 3: AEAD seal using ChaCha20-Poly1305 [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439).

~~~
nonce   := 12 bytes of 0x00
aead_ct := ChaCha20-Poly1305.Seal(
              key       = wrap_key,
              nonce     = nonce,
              plaintext = K,
              aad       = recipient_pub)
~~~

`aead_ct` is the ChaCha20-Poly1305 ciphertext concatenated with
its 16-byte authentication tag. For a 32-byte symmetric key
`K`, `aead_ct` is 48 bytes.

The zero nonce is unconditionally safe because `wrap_key` is
derived fresh from a unique ephemeral key on every Wrap call: a
(key, nonce) pair is never reused across calls. The recipient
public key is bound as AAD so that an attacker cannot transplant
a wrap entry to a different recipient even if the recipient's
domain or client somehow accepted the same `wrap_key`.

Step 4: Output assembly.

~~~
wrapped_bytes := kem_ct || aead_ct
wrapped       := base64(wrapped_bytes)
~~~

For the baseline suite with a 32-byte K: `|kem_ct| + |aead_ct| =
32 + 48 = 80 bytes`, base64-encoded as 108 characters with two
`=` padding characters.

For the post-quantum suite with a 32-byte K: `|kem_ct| +
|aead_ct| = 1120 + 48 = 1168 bytes`, base64-encoded as 1560
characters with no padding.

### Unwrap Procedure

A recipient with `(recipient_priv, recipient_pub)` reverses the
construction:

1. `wrapped_bytes := base64-decode(wrapped)`.
2. Parse `kem_ct || aead_ct` using the suite-specific kem_ct
   length (32 bytes for baseline, 1120 bytes for the
   post-quantum suite).
3. Recover `shared_secret`:
   * baseline: `shared_secret := X25519 ECDH(recipient_priv,
     kem_ct)`;
   * post-quantum: `shared_secret :=
     Kyber768.Decapsulate(recipient_priv.kyber, kem_ct[0..1088])
     || X25519 ECDH(recipient_priv.x25519, kem_ct[1088..1120])`.
4. Re-derive `wrap_key` with the same HKDF-Extract/Expand
   parameters.
5. `K := ChaCha20-Poly1305.Open(wrap_key, nonce=[0x00 * 12],
   ciphertext=aead_ct, aad=recipient_pub)`. An auth-tag mismatch
   MUST surface as an unwrap error.

A conformant SEMP implementation MUST produce wrap entries
identical to those produced by the reference generator when given
the same `K`, `recipient_pub`, and `ephemeral_priv` inputs (plus
`kyber_encapsulation_randomness` for the post-quantum suite).
Pinned test vectors are listed in the test-vectors companion
artifact. Determinism under pinned inputs is interop-critical:
any deviation in the HKDF inputs, the nonce convention, or the
AEAD AAD prevents recipients from unwrapping `K` and surfaces as
a verification failure indistinguishable from corruption.

The construction shape follows the HPKE design [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180);
SEMP fixes the construction to the parameters above rather than
using HPKE's full negotiation surface.

### Recipient-Count Obfuscation

The size of `seal.brief_recipients` and
`seal.enclosure_recipients` reveals the number of recipients on
an envelope to any party that can inspect the seal: routing
servers see both maps, and the recipient server counts the
entries it cannot decrypt alongside those it can. To prevent
recipient-count enumeration and group-size inference, sending
clients MUST pad both maps with dummy entries so that the number
of entries falls on a power-of-two bucket.

The number of entries in `enclosure_recipients` after padding
MUST equal one of: `1, 2, 4, 8, 16, 32, 64, 128, 256, 512,
1024`. The client MUST pick the smallest bucket whose value is
at least the count of real recipient client keys.

The number of entries in `brief_recipients` after padding MUST
equal `enclosure_bucket + domain_bucket`, where:

* `enclosure_bucket` is the bucket value chosen above (one entry
  per recipient client, real or dummy);
* `domain_bucket` is `max(D, 1)` rounded up to the next power of
  two, where `D` is the count of distinct recipient domains that
  hold real recipient clients on this envelope.

Each dummy entry MUST have a `key_id` indistinguishable from a
real key fingerprint (32 bytes drawn from a cryptographically
secure random source, encoded as hex) and a ciphertext whose
length is identical to a real wrapped-key ciphertext for the
negotiated suite, populated with fresh random bytes.

A recipient attempting to decrypt the seal iterates over the
entries matching its key fingerprint. Dummy entries' fingerprints
do not match any recipient's real keys, so no decryption is
attempted against them. An observer cannot distinguish real from
dummy entries without holding a recipient's private key, and a
recipient cannot determine the count of other real recipients.

A sending client MAY omit dummy entries only when the envelope
is addressed to a single recipient client on a single recipient
domain AND no group address is present in `brief.to` or
`brief.cc` AND the envelope is not a device-sync envelope. In
every other case, padding to the next power-of-two bucket is
REQUIRED.

Dummy entries inflate the envelope's pre-padding size. Senders
compute recipient-count padding first, then compute total-size
padding per [Envelope Padding](#envelope-padding) against the resulting envelope.

## Symmetric Key Scope

Two symmetric keys are generated fresh for each envelope:

* `K_brief` encrypts the brief only. It MUST NOT be reused
  across envelopes.
* `K_enclosure` encrypts the enclosure only. It MUST NOT be
  reused across envelopes.

Neither key is derived from the other. They are independent
random values.

<a id="brief"></a>

# Brief
The brief is the inner private header of the envelope. It
contains the correspondence metadata that in SMTP [RFC 5321](https://www.rfc-editor.org/rfc/rfc5321)
would be exposed in plaintext: sender and recipient addresses,
timestamps, and threading information. It does not contain the
subject or message content, which are semantic content and
belong in the enclosure.

The brief is encrypted with `K_brief`, which is wrapped in
`seal.brief_recipients` under both the recipient server's domain
key and the recipient client's encryption key. The recipient
server can decrypt the brief to perform delivery and user-level
policy enforcement. The brief is not readable by any other
server handling the envelope in transit.

## Brief Schema (Decrypted)

~~~ json
{
    "message_id": "globally-unique-message-identifier",
    "from": "sender@example.com",
    "to": ["recipient1@example.com", "recipient2@example.com"],
    "cc": ["observer@example.com"],
    "bcc": ["hidden@example.com"],
    "reply_to": "optional-reply-address@example.com",
    "sent_at": "2026-06-08T12:05:00Z",
    "thread_id": "thread-identifier-or-null",
    "group_id": "group-identifier-or-null",
    "in_reply_to": "message-id-of-parent-or-null",
    "extensions": {}
}
~~~

## Brief Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `message_id` | string | Yes | Globally unique message identifier. Used for threading and deduplication. |
| `from` | string | Yes | Full sender address. |
| `to` | string[] | Yes | Primary recipient addresses. |
| `cc` | string[] | No | Carbon copy recipient addresses. |
| `bcc` | string[] | No | Blind carbon copy. See [BCC Handling](#bcc-handling). |
| `reply_to` | string | No | Address replies should be directed to, if different from `from`. |
| `sent_at` | string | Yes | ISO 8601 UTC timestamp of message creation at the sender. |
| `thread_id` | string \| null | No | Conversation thread identifier. |
| `group_id` | string \| null | No | Group or mailing list identifier. |
| `in_reply_to` | string \| null | No | `message_id` of the message being replied to. |
| `extensions` | object | No | Brief-layer extensions for private metadata. |

<a id="bcc-handling"></a>

## BCC Handling
BCC recipients MUST NOT be visible to non-BCC recipients. SEMP
enforces this through per-recipient envelope copies generated by
the sending client rather than through server-side stripping.

When a sender includes BCC recipients, the sending client
generates a distinct envelope copy for each BCC recipient. Each
BCC copy contains only that recipient's address in the `bcc`
field. The `bcc` field is absent entirely from the envelope
copies delivered to `to` and `cc` recipients.

This approach eliminates the requirement to trust any server to
strip BCC correctly. The information is never present in
envelopes that should not contain it, and the sender's server
never sees the full BCC recipient list.

## Message ID vs Postmark ID

`brief.message_id` is the persistent global identifier for the
message. It is stable across retries, forwards, and delivery
attempts. It is used for threading, deduplication at the
recipient level, and reply correlation.

`postmark.id` is a per-transaction routing identifier. It MAY
change across delivery attempts. It is used for hop-level
deduplication and loop detection only.

<a id="enclosure"></a>

# Enclosure
The enclosure contains the message body and attachments. It is
encrypted with `K_enclosure`, which is wrapped only under the
recipient client's encryption key in
`seal.enclosure_recipients`. It is not readable by the recipient
server or by any other server handling the envelope in transit.

## Enclosure Schema (Decrypted)

~~~ json
{
    "subject": "Optional subject line",
    "content_type": "multipart/alternative",
    "body": {
        "text/plain": "base64-encoded-encrypted-plaintext-body",
        "text/html": "base64-encoded-encrypted-html-body"
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
~~~

## Enclosure Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `subject` | string | No | Subject of the correspondence. |
| `content_type` | string | Yes | MIME type of the body. Use `multipart/alternative` for multiple formats. |
| `body` | object | Yes | Map of MIME type to encrypted body content (base64). |
| `attachments` | array | No | List of attached files. |
| `forwarded_from` | object \| null | Yes | Forwarding evidence block. `null` if the envelope is not a forward. See [Forwarded Envelopes](#forwarded-envelopes). |
| `extensions` | object | No | Enclosure-layer extensions for content metadata. |
| `sender_signature` | object | Yes | Sender identity key signature over the enclosure. See [Sender Signature](#sender-signature). |

## Attachment Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | Yes | Unique attachment identifier within this envelope. |
| `filename` | string | Yes | Original filename. |
| `mime_type` | string | Yes | MIME type of the attachment. |
| `size` | integer | Yes | Size in bytes of the unencrypted attachment content. |
| `hash` | string | Yes | Hash of the unencrypted content for integrity verification. Format: `algorithm:hex`. |
| `content` | string | Yes | Encrypted attachment content (base64). |

## Multipart Body

When `content_type` is `multipart/alternative`, the `body`
object MAY contain multiple representations of the same content
keyed by MIME type. Receiving clients SHOULD select the most
capable format they support. Senders SHOULD always include a
`text/plain` representation as a baseline.

When `content_type` is a single MIME type, the `body` object
MUST contain exactly one key matching that type.

<a id="sender-signature"></a>

## Sender Signature
`enclosure.sender_signature` is a signature produced by the
sending user's identity key over the canonical bytes of the
enclosure. It binds the enclosure plaintext to the sender's
identity independently of `seal.signature` (which binds
ciphertext at the sender's domain).

The sender signature exists so that an enclosure plaintext, once
decrypted, can be cryptographically attributed to its original
sender by any party that subsequently obtains the plaintext.
This is the foundation of forward provenance defined in
[Forwarded Envelopes](#forwarded-envelopes).

### Signing Key

The signing key MUST be the sending user's published identity
key as defined in [Discovery](discovery.md). Device
subkeys, ephemeral keys, and session keys MUST NOT be used.
Identity is the property that survives forwarding.

### Signature Scope

The sender computes the signature as follows:

1. Set `enclosure.sender_signature.algorithm` to the suite-bound
   signature algorithm.
2. Set `enclosure.sender_signature.key_id` to the fingerprint
   of the identity key.
3. Set `enclosure.sender_signature.value` to the empty string
   `""`.
4. Compute the canonical JSON serialization of the entire
   enclosure object per
   [Signature Scope and Canonicalization](#signature-scope-and-canonicalization) canonicalization
   rules.
5. Prefix the canonical bytes with `SEMP-ENCLOSURE-SENDER:` per
   [Signature Domain Separation](#signature-domain-separation).
6. Sign the prefixed bytes with the identity private key.
7. Replace `enclosure.sender_signature.value` with the
   base64-encoded signature.

Every other field of the enclosure (`subject`, `content_type`,
`body`, `attachments`, `forwarded_from`, `extensions`) is
covered by the signature.

### Signature Verification

A recipient client MUST verify `enclosure.sender_signature`
after decrypting the enclosure and before rendering any content
to the user. Verification:

1. Reconstruct the canonical bytes by setting
   `sender_signature.value` to `""` and re-serializing per
   [Signature Scope and Canonicalization](#signature-scope-and-canonicalization), then prefixing the
   result with `SEMP-ENCLOSURE-SENDER:`.
2. Fetch the sender's identity key indicated by
   `sender_signature.key_id`, sourced from the sender's
   published key set per [Discovery](discovery.md).
3. Verify the signature against the prefixed canonical bytes.

If verification fails, the recipient client MUST NOT display
the enclosure content as authored by the claimed sender. The
client SHOULD surface the verification failure to the user as a
security warning. The client MUST NOT silently render the
content.

If `sender_signature.key_id` does not match any currently
published or historically-published-and-now-revoked identity
key for the sender, the client MUST treat verification as
failed.

### Non-Repudiation Property

The sender signature is a non-repudiable signature over the
enclosure content. A sender who signs an enclosure cannot later
credibly deny having authored it, given the signature plus the
plaintext.

SEMP prioritizes verifiable provenance, so that forwarded
content can be attributed to its true author, over plausible
deniability. Senders who require deniability SHOULD use
ephemeral channels outside SEMP for such content.

<a id="forwarded-envelopes"></a>

## Forwarded Envelopes
When a recipient client forwards a previously received
envelope, the new envelope's enclosure carries a
`forwarded_from` block containing the original enclosure
plaintext and accompanying advisory metadata.

A forward composes a fresh envelope addressed to the new
recipient, sealed by the forwarder's domain and signed by the
forwarder's identity key. The new envelope is structurally
indistinguishable from any other envelope to routing servers;
the forward is visible only to the new recipient client after
enclosure decryption.

### Forwarded Block Schema

~~~ json
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
~~~

### Forwarded Block Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `original_enclosure_plaintext` | object | Yes | The full decrypted enclosure of the original envelope, including its `sender_signature`. |
| `original_seal` | object | No | The original envelope's seal, preserved verbatim. Advisory only. |
| `original_postmark` | object | No | The original envelope's postmark, preserved verbatim. Advisory only. |
| `original_sender_address` | string | Yes | The full sender address from the original envelope's `brief.from`. Bound by `forwarder_attestation`. |
| `received_at` | string | Yes | ISO 8601 UTC timestamp at which the forwarder received the original envelope. |
| `forwarder_attestation` | object | Yes | Forwarder's identity key signature over the forwarded block. |

The new enclosure's own `subject`, `body`, and `attachments`
MAY contain the forwarder's commentary on the forwarded
content. The original content lives only in
`forwarded_from.original_enclosure_plaintext`. The forwarder
MUST NOT modify `original_enclosure_plaintext` in any way;
doing so would invalidate the original sender's signature
carried within it.

### Forwarder Attestation

`forwarded_from.forwarder_attestation` is a signature produced
by the forwarder's identity key over the canonical bytes of the
`forwarded_from` object with `forwarder_attestation.value` set
to `""`, prefixed with `SEMP-FORWARDER-ATTESTATION:` per
[Signature Domain Separation](#signature-domain-separation).

The attestation binds the original enclosure plaintext (and
through its inner `sender_signature`, the original sender's
identity), the advisory `original_seal` and `original_postmark`
if present, the claimed `original_sender_address`, and the
`received_at` timestamp.

The forwarder's identity is established by the new envelope's
outer `enclosure.sender_signature`, which the new recipient
verifies first. The attestation key in
`forwarder_attestation.key_id` MUST match the
`sender_signature.key_id` of the new enclosure. A new recipient
MUST reject a `forwarded_from` block whose
`forwarder_attestation.key_id` differs from the outer
`sender_signature.key_id`.

### Verification by the New Recipient

A recipient client receiving an envelope with a non-null
`forwarded_from` MUST perform the following verification, in
order, after the standard decryption flow
([Decryption Flow](#decryption-flow)):

1. Verify the new envelope's `enclosure.sender_signature`. This
   authenticates the forwarder.
2. Verify `forwarded_from.forwarder_attestation` against the
   canonical bytes of `forwarded_from` (with
   `forwarder_attestation.value` set to `""`), using the
   forwarder's identity key. This authenticates the forwarding
   act.
3. Verify
   `forwarded_from.original_enclosure_plaintext.sender_signature`,
   using the original sender's identity key as indicated by
   that signature's `key_id` and the
   `forwarded_from.original_sender_address`. This
   authenticates the original content as authored by the
   original sender.

If steps 1 or 3 fail, the recipient client MUST NOT display
the original content as attributed to the claimed original
sender. If step 2 fails, the recipient client MUST NOT display
the forwarded block at all and SHOULD treat the envelope as if
`forwarded_from` were null, surfacing a security warning.

`original_seal` and `original_postmark` are advisory only. The
new recipient cannot independently verify
`original_seal.signature` because the original ciphertext is
not preserved in the forward. Clients MAY use these fields to
display additional context but MUST NOT present them as
cryptographically verified evidence.

### Multi-Level Forwarding

`original_enclosure_plaintext.forwarded_from` MAY itself be
non-null, representing a forward of a forward. Verification
applies recursively: the new recipient verifies each level of
the forwarding chain using the inner `sender_signature` and
`forwarder_attestation` at each level.

A recipient MUST verify the full chain or treat any unverified
inner level as advisory. A client that displays forwarded
content from a chain SHOULD make the chain depth and the
identity of each forwarder visible to the user.

# Encryption Model

<a id="encryption-flow"></a>

## Encryption Flow
Sending an envelope follows this sequence:

1. Compose the plaintext brief and enclosure as JSON objects.
   If the envelope is a forward, populate
   `enclosure.forwarded_from` per [Forwarded Envelopes](#forwarded-envelopes),
   including the forwarder's `forwarder_attestation` signature.
2. Compute `enclosure.sender_signature` over the canonical
   enclosure bytes per [Sender Signature](#sender-signature), using the sending
   user's identity key. The resulting signature value is
   written into `enclosure.sender_signature`.
3. Generate two fresh independent random symmetric keys:
   `K_brief` and `K_enclosure`.
4. Encrypt the brief JSON bytes under `K_brief`. Store result
   in `envelope.brief`.
5. Encrypt the (now signed) enclosure JSON bytes under
   `K_enclosure`. Store result in `envelope.enclosure`.
6. Fetch the recipient client's current public encryption key
   and the recipient server's published domain key per
   [Discovery](discovery.md).
7. Encrypt `K_brief` under the recipient server's domain key.
   Store in `seal.brief_recipients` keyed by the server's
   domain key fingerprint.
8. Encrypt `K_brief` under the recipient client's encryption
   key. Store in `seal.brief_recipients` keyed by the client's
   key fingerprint.
9. Encrypt `K_enclosure` under the recipient client's
   encryption key. Store in `seal.enclosure_recipients` keyed
   by the client's key fingerprint.
10. Compose the postmark, including `postmark.session_id`.

Steps 1 through 10 are performed by the sending client. The
client then transmits the assembled envelope to its home
server, which performs the remaining steps. The client does
not hold the domain private key or the session key material
required for seal computation.

11. Compute the canonical envelope bytes (both
    `seal.signature` and `seal.session_mac` set to `""`,
    `postmark.hop_count` omitted).
12. Sign the canonical bytes with the sender's domain private
    key. Store in `seal.signature`.
13. Compute a MAC over the canonical bytes using `K_env_mac`
    from the active session. Store in `seal.session_mac`.

### Brief and Enclosure Encryption Wire Format

For Step 4 (brief encryption) and Step 5 (enclosure
encryption), the plaintext bytes and the resulting ciphertext
envelope-field encoding are pinned as follows.

Plaintext: the AEAD plaintext is the canonical JSON
serialization of the brief or enclosure object per
[Signature Scope and Canonicalization](#signature-scope-and-canonicalization) canonicalization
rules. For the enclosure, the canonical form already includes
`sender_signature` with its computed `value`, because the
signature value was written into the enclosure object in Step
2 of the encryption flow above, before encryption in Step 5.

AAD: the AEAD additional authenticated data is the UTF-8 bytes
of `postmark.id` (no length prefix, no separator).

Nonce: the AEAD nonce is the size required by the negotiated
suite's cipher. For both currently defined suites, this is 12
bytes for ChaCha20-Poly1305. Each AEAD seal call uses a fresh
nonce drawn from a cryptographically secure random source.
Nonces MUST NOT be reused under the same key.

Ciphertext envelope-field encoding:

~~~
ciphertext := AEAD.Seal(
                  key       = K,
                  nonce     = nonce,
                  plaintext = canonical_json,
                  aad       = postmark.id (UTF-8))

// K = K_brief for the brief, K_enclosure for the enclosure
envelope.<field> := base64( nonce || ciphertext )
~~~

`ciphertext` is the AEAD ciphertext concatenated with its
16-byte authentication tag. Receiving implementations parse
`envelope.brief` or `envelope.enclosure` by base64-decoding,
splitting off the leading nonce according to the suite's nonce
size, and passing the remainder as ciphertext to AEAD.Open
with the matching `K`, `nonce`, and AAD (`postmark.id`). On
success the plaintext is the canonical JSON of the brief or
enclosure object.

<a id="decryption-flow"></a>

## Decryption Flow
Receiving an envelope follows this sequence:

1. Verify `seal.signature` against the sender domain's
   published public key. Reject immediately with
   `reason_code: "seal_invalid"` if invalid.
2. Check `postmark.expires`. Reject with `reason_code:
   "envelope_expired"` if in the past.
3. Verify `postmark.session_id` references an active,
   non-expired, non-invalidated session. Reject with the
   appropriate reason code if not.
4. Verify `seal.session_mac` using `K_env_mac` from the
   session identified by `postmark.session_id`. Reject with
   `reason_code: "session_mac_invalid"` if the MAC does not
   verify.
5. Decrypt the server's entry in `seal.brief_recipients`
   using the server's domain private key, yielding `K_brief`.
6. Decrypt `envelope.brief` using `K_brief`. Parse the
   resulting JSON.
7. Apply domain-server-level and user-level delivery policy
   using the decrypted brief. Reject or apply the recipient's
   silent policy as required.
8. Deliver the envelope to the recipient client. The client
   decrypts its entry in `seal.brief_recipients` using its
   own private key to obtain `K_brief`, and decrypts its
   entry in `seal.enclosure_recipients` to obtain
   `K_enclosure`.
9. The client decrypts `envelope.brief` using `K_brief` and
   `envelope.enclosure` using `K_enclosure`. Parse both.
10. The client verifies `enclosure.sender_signature` against
    the sender's identity key. The client MUST NOT render
    enclosure content if verification fails.
11. If `enclosure.forwarded_from` is non-null, the client
    performs the forwarded-envelope verification chain per
    [Forwarded Envelopes](#forwarded-envelopes).
12. The client verifies attachment hashes against decrypted
    attachment content.

Steps 1 through 4 MUST all pass before any further
processing. Each failure MUST produce an immediate, explicit
rejection with the appropriate reason code. Step 1 may be
performed by any routing server. Steps 2 through 7 are
performed by the receiving server only. Steps 8 through 12
are performed by the client.

If Step 5 fails, the server cannot decrypt the brief and MUST
return an explicit rejection to the sending server indicating
delivery failure.

<a id="algorithm-suites"></a>

## Algorithm Suites
SEMP defines algorithm suites as indivisible bundles. Each
suite specifies the complete set of cryptographic primitives
used for a session and its envelopes. Implementations
negotiate suites rather than individual primitives.

### Suite Definitions

`x25519-chacha20-poly1305`:
: Key agreement: X25519. Symmetric cipher: ChaCha20-Poly1305.
  MAC: HMAC-SHA-256. KDF: HKDF-SHA-512. Signing: Ed25519.

`pq-kyber768-x25519`:
: Key agreement: Kyber768 + X25519 (hybrid). Symmetric cipher:
  ChaCha20-Poly1305. MAC: HMAC-SHA-256. KDF: HKDF-SHA-512.
  Signing: Ed25519.

Each column specifies:

* Key agreement: the ephemeral key exchange used during the
  handshake to produce the shared secret. Hybrid suites
  concatenate both outputs (`K_kyber || K_x25519`) as defined
  in [Handshake](handshake.md).
* Symmetric cipher: encrypts the brief, enclosure, and
  handshake messages after key derivation.
* MAC: the algorithm used for `seal.session_mac` and
  handshake message MACs.
* KDF: the key derivation function used to derive session
  keys from the shared secret.
* Signing: the algorithm used for `seal.signature`, domain
  key signatures, and identity proofs.

### Suite Requirements

Implementations MUST support `x25519-chacha20-poly1305` (the
baseline suite) for interoperability. Implementations are
RECOMMENDED to support `pq-kyber768-x25519` (the hybrid
post-quantum suite).

Implementations MAY define and negotiate additional suites.
Additional suites MUST specify all five components. The
negotiated suite MUST be recorded in `seal.algorithm`.

Implementations MUST NOT negotiate suites below the baseline.
A server that cannot support any mutually acceptable suite
MUST reject the connection explicitly.

### Suite Extensibility

Future suites MAY substitute any component as long as the
suite is defined as a complete bundle. Suite identifiers MUST
be distinct strings that unambiguously identify all
components. The protocol does not support mixing components
from different suites within a single session.

### Fixed Protocol Primitives

Two operations are not governed by the negotiated suite
because they occur before or outside of suite negotiation:

* Confirmation hash: `SHA-256(canonical(message_1) ||
  canonical(message_2))`. Computed before any suite is
  agreed and covers the message that contains the suite
  negotiation.
* Challenge hash: SHA-256 as specified in
  [Handshake](handshake.md). The proof-of-work challenge
  occurs before session establishment and is independent of
  the session suite.

<a id="per-extension-key-scoping"></a>

## Per-Extension Cryptographic Key Scoping
Some extensions place data in `enclosure.extensions` that
is intended for only a subset of the recipient user's
devices. A delegated filter device
([Discovery](discovery.md)) that produces a
classification result for the user's main reading device
is the canonical example: the filter device SHOULD be
able to read the inbound envelope's enclosure to perform
the classification, while the classification result it
produces SHOULD be readable only by the main reading
device, not by every device that receives the envelope.

The library extension enforcement contract
([Extensions](extensions.md)) restricts behavior at the
implementation layer. Cryptographic key scoping restricts
read access at the protocol layer, independent of any
library-level guarantees. A device that is not given the
wrapped key for a particular extension's enclosure data
cannot decrypt that data, regardless of implementation
honesty.

### Wire Format

When an extension entry in `enclosure.extensions`
requires per-extension key scoping, the entry's `data`
field is itself an encrypted blob, and the seal carries a
separate `extension_keys` map keyed by extension
identifier:

~~~ json
"seal": {
    "enclosure_recipients": {
        "default": {
            "device-key-id-1":
                "wrapped-K_enclosure-default",
            "device-key-id-2":
                "wrapped-K_enclosure-default"
        },
        "extension_keys": {
            "semp.dev/classification-result": {
                "device-key-id-1":
                    "wrapped-K_ext-classification"
            }
        }
    }
}
~~~

~~~ json
"enclosure": {
    "extensions": {
        "semp.dev/classification-result": {
            "required": true,
            "scoped": true,
            "data":
                "base64-AEAD-ciphertext-under-K_ext"
        }
    }
}
~~~

The `default` map under `enclosure_recipients` carries
the wrapped `K_enclosure` for entries that do not use
per-extension scoping (the simple form already specified
in [Seal](#seal)). The `extension_keys` map carries one entry
per scoped extension. Each entry is a map from device key
fingerprint to the wrapped per-extension key.

A scoped extension entry MUST set `scoped: true` and MUST
place its encrypted payload in the `data` field as a
base64-encoded AEAD ciphertext under the per-extension
key. The plaintext under encryption is the canonical JSON
serialization of the extension-specific data object as
defined by the extension's `data_schema`
([Extensions](extensions.md)).

<a id="per-extension-key-derivation"></a>

### Key Derivation
Each per-extension key is generated freshly for each
envelope by the producing party. The key is derived
independently from `K_enclosure`:

~~~
K_ext = HKDF-Expand(
    PRK = random(32 bytes, generated per envelope),
    info = "SEMP-v1-ext-" || extension_identifier,
    L = 32
)
~~~

The PRK is generated freshly per envelope and is not
derived from `K_enclosure` or any session key. This
ensures that compromise of `K_enclosure` does not yield
`K_ext`, and compromise of `K_ext` does not yield
`K_enclosure`. The two key spaces are independent.

The AEAD cipher MUST match the negotiated suite's
symmetric cipher (ChaCha20-Poly1305 for both currently
defined suites, see [Algorithm Suites](#algorithm-suites)). The associated
data MUST include the canonical envelope ID
(`postmark.id`) and the extension identifier, binding
the ciphertext to its envelope and preventing
cross-extension substitution.

### Wrapping

The producing party wraps the per-extension key under
the public encryption keys of every device that should
be able to read the extension data. Devices not listed
in the `extension_keys` map for a given extension cannot
recover the plaintext.

The wrapping uses the same key encapsulation mechanism
as `enclosure_recipients` (the negotiated suite's KEM,
applied per recipient device key, per
[Recipient Key Wrapping](#recipient-key-wrapping)).

<a id="per-extension-decryption"></a>

### Decryption
A receiving device performs the following steps for
each scoped extension entry it encounters:

1. Look up its own device key fingerprint in
   `seal.enclosure_recipients.extension_keys[<identifier>]`.
2. If no entry is present, the device is not authorized
   to read this extension. The device MUST treat the
   entry as opaque and MUST NOT attempt to decrypt the
   `data` field.
3. If an entry is present, unwrap to recover `K_ext`.
4. Decrypt the `data` field using `K_ext` and the AEAD
   cipher with the declared associated data.
5. Validate the resulting plaintext against the
   extension's `data_schema` per
   [Extensions](extensions.md).

A device that is not authorized to read a scoped
extension MUST NOT include the extension in any
user-visible representation of the envelope, and it MUST
NOT report decryption failure as an error to the user.
Absence of authorization is normal operation rather than
failure.

### Use With Required Flag

A scoped extension MAY be marked `required: true`. The
required-extension semantics
([Extensions](extensions.md)) apply at the recipient
server layer, since the server can confirm the
extension's presence and identifier without holding the
per-extension key. A receiving device that holds no key
for a required scoped extension processes the envelope
normally; the extension is required to be present, not
required to be readable by every device.

### Size Accounting

The encrypted `data` blob counts toward the size limit
on `enclosure.extensions` defined in
[Extensions](extensions.md). Producing parties SHOULD
account for ciphertext expansion (typically 16 bytes of
AEAD tag plus base64 overhead) when sizing scoped
extension payloads.

The `extension_keys` map in the seal counts toward the
seal size budget and adds approximately 64 bytes per
device per scoped extension. Heavy use of per-extension
key scoping across many devices increases envelope size
proportionally.

<a id="extensibility"></a>

# Extensibility
Each layer of the envelope has its own `extensions` object.
This allows new capabilities to be introduced at the
appropriate visibility level:

* `postmark.extensions`: routing-layer extensions, visible to
  all servers in transit. MUST NOT contain private metadata.
* `seal.extensions`: integrity-layer extensions, visible to
  all servers.
* `brief.extensions`: private metadata extensions, visible to
  the recipient server and recipient client.
* `enclosure.extensions`: content-layer extensions, visible
  only to the recipient client.

Extension keys MUST be namespaced to prevent collision (for
example, `vendor.example.com/feature-name`). Core
implementations MUST ignore unknown extension keys rather
than rejecting the envelope. Extensions MUST NOT redefine or
shadow reserved field names at their layer. Extensions placed
in `postmark.extensions` or `seal.extensions` are visible to
all routing servers and MUST be treated as public metadata.

The wire-level extension framework, including registration
and size limits, is specified in
[Extensions](extensions.md). The per-extension key scoping
mechanism for encrypting extension data to a subset of a
recipient user's devices is specified in
[Per-Extension Cryptographic Key Scoping](#per-extension-key-scoping).

# Server Responsibilities

## Acceptance Requirements

A server receiving an envelope MUST:

1. Verify `seal.signature` before any other processing.
2. Reject envelopes with invalid seals immediately and
   explicitly.
3. Reject envelopes where `postmark.expires` is in the past.
4. Verify `postmark.session_id` references an active,
   non-expired, non-invalidated session. Reject if absent or
   invalid.

A server MUST NOT:

* accept and silently discard an envelope as a wire-visible
  default;
* forward an envelope with an invalid seal;
* modify any signed field of the envelope.

A server MAY:

* increment `postmark.hop_count` if present, or add it
  starting at `1` if absent;
* reject envelopes where `postmark.hop_count` exceeds a
  locally configured maximum.

## Rejection

All rejections MUST be explicit. The rejecting server MUST
return a structured rejection response to the sending server
containing a reason code, a human-readable description, and
the `postmark.id` of the rejected envelope.

A server that is unable to deliver or declines to deliver an
envelope MUST return an explicit rejection. A server MUST NOT
silently accept an envelope and then discard it as a
wire-visible default. A server MAY apply silent acceptance only
as a deliberate recipient privacy policy under the rules in
[Delivery](delivery.md).

## Envelope Rejection Reason Codes

The envelope-layer reason codes (returned in structured
rejection responses to envelope delivery attempts) are defined
in the Reason Code Registry of [Delivery](delivery.md).
That registry is the authoritative cross-cutting list, with
per-code recoverability classification and sender-behavior
guidance. Envelope-layer codes include `seal_invalid`,
`session_mac_invalid`, `envelope_expired`,
`envelope_size_exceeded`, `policy_forbidden`, and others.

A rejection MAY include a `challenge` body inviting the sender
to retry with proof of work, per the first-contact challenge
mechanism in [Delivery](delivery.md). When the recipient's
policy does not permit revealing a block, `policy_forbidden`
MUST be returned in place of the more specific `blocked` code.

# Media Types

This section defines the media types associated with SEMP
artifacts and the corresponding file formats. The IANA
registration templates are in [IANA Considerations](#iana-considerations).

## application/semp-envelope

A `application/semp-envelope` resource is a serialized SEMP
envelope as defined in this document. The MIME type applies to
envelopes transmitted over HTTP, HTTP/2, QUIC, and WebSocket
transports as well as envelopes stored as files.

The file extension is `.semp`. A `.semp` file contains
exactly one SEMP envelope serialized as a UTF-8 JSON object.
The file MUST be encoded as UTF-8 without a byte order mark.
The file SHOULD use the canonical serialization defined in
[Signature Scope and Canonicalization](#signature-scope-and-canonicalization) but MAY use
pretty-printed JSON for human inspection. Seal verification
MUST always be performed against the canonical form regardless
of the file's whitespace formatting.

A `.semp` file is a complete, self-contained SEMP envelope.
The postmark and seal are visible in plaintext to anyone with
access to the file. The brief and enclosure are encrypted; the
brief is readable only by the recipient server (via its domain
key) and the recipient client (via its encryption key); the
enclosure is readable only by the recipient client.
Verification of `seal.signature` against the sender's
published domain key confirms that the envelope was produced
by the claimed sender domain and has not been tampered with
since.

`seal.session_mac` cannot be verified from a file alone
because it requires the session key, which is ephemeral and
erased after the session ends per
[Handshake](handshake.md). This is expected. The session
MAC proves the envelope was delivered within a valid session,
a property that is meaningful at delivery time rather than at
rest.

A `.semp` file contains exactly one envelope. Applications
that need to store multiple envelopes MUST use one file per
envelope or use an archive format (`.tar`, `.zip`) containing
multiple `.semp` files.

Applications parsing `.semp` files MUST validate JSON
structure before processing. Malformed JSON, excessively
nested objects, or unexpectedly large fields could be used for
denial-of-service attacks. Applications SHOULD impose
reasonable limits on parsing depth and field sizes consistent
with the envelope size limits defined in this document and in
[Extensions](extensions.md).

Applications MUST NOT cache or store decrypted brief or
enclosure content alongside the `.semp` file. Decrypted
content that is written to disk MUST be in a separate file
under the user's explicit control.

<a id="envelope-content-type"></a>

### Content-Type and Framing Rules
When transmitting envelopes over HTTP-based transports
(HTTP/2 and QUIC), servers MUST use
`application/semp-envelope` as the `Content-Type` header
value:

~~~
Content-Type: application/semp-envelope
~~~

Servers SHOULD include the `charset=utf-8` parameter:

~~~
Content-Type: application/semp-envelope; charset=utf-8
~~~

WebSocket frames carrying SEMP envelopes MUST use text
frames (opcode 0x1), because the envelope content is UTF-8
JSON. Binary frames (opcode 0x2) MUST NOT be used for
envelope payloads.

<a id="envelope-file-open"></a>

### Opening a `.semp` File
When a client application opens a `.semp` file:

1. Parse the JSON and validate that the top-level `type`
   field equals `"SEMP_ENVELOPE"`.
2. Verify `seal.signature` against the sender domain's
   published signing key.
3. Attempt to decrypt `K_brief` from
   `seal.brief_recipients` using each of the user's active
   private encryption keys.
4. If step 3 succeeds, decrypt the `brief` and display
   message metadata.
5. Attempt to decrypt `K_enclosure` from
   `seal.enclosure_recipients` using each of the user's
   active private encryption keys.
6. If step 5 succeeds, decrypt the `enclosure` and display
   message content.
7. If step 3 or step 5 fails, display what is available
   (postmark, seal verification result) and indicate that
   the user is not a recipient of this envelope.

### Verification Without Decryption

Applications that handle `.semp` files SHOULD offer a
verification mode that checks `seal.signature` against the
sender's domain key without attempting decryption. This
allows third parties to verify envelope authenticity and
integrity without access to private key material.

Successful verification of `seal.signature` confirms that
the envelope was produced by the claimed sender domain and
that no field covered by the signature has been altered
since. It does not confirm that the envelope was
successfully delivered, that the intended recipient
received it, or that the content has not been selectively
omitted. An attacker who controls a domain can produce a
valid envelope with arbitrary content under that domain's
signature; seal verification proves provenance, and it
does not prove delivery or truthfulness.

### Exporting Envelopes

SEMP clients SHOULD support exporting received envelopes
as `.semp` files. The exported file is the envelope
exactly as received: postmark, seal, encrypted brief, and
encrypted enclosure. The client MUST NOT export decrypted
content into the `.semp` file. The file preserves the
envelope's security properties at rest.

If the user needs to export decrypted content (for example,
for legal discovery or personal archival), the client
SHOULD export the decrypted content in a separate format
(plaintext, PDF, or similar) with a clear indication that
the exported content is no longer cryptographically
protected.

<a id="envelope-file-interoperability"></a>

### Interoperability
Applications that encounter a `.semp` file with an
unrecognized `version` value SHOULD attempt to parse it as
best effort rather than rejecting it outright. The
top-level envelope structure is stable across versions,
and unknown fields SHOULD be preserved and ignored
consistent with the extensibility rules in
[Extensions](extensions.md).

`.semp` files MUST be UTF-8. Applications MUST reject
files that are not valid UTF-8 and MUST NOT assume or
attempt other encodings.

The maximum size of a `.semp` file is bounded by the
`limits.max_envelope_size` value advertised by the
recipient's home server in its configuration document per
[Discovery](discovery.md). For files created by export,
the maximum size is the size of the original envelope.
Applications SHOULD handle files up to at least 25 MB,
which is consistent with common maximum envelope sizes.

Applications that register to handle `.semp` files SHOULD
register the following:

| Attribute | Value |
|---|---|
| File extension | `.semp` |
| MIME type | `application/semp-envelope` |
| UTI (Apple platforms) | `org.semp.envelope` |
| File type description | `"SEMP Envelope"` |

### File Access Control

A `.semp` file exposes the postmark in plaintext, including
sender and recipient domains. The postmark is less
sensitive than the full brief, and it still reveals that
two domains corresponded. Users who require domain-level
privacy SHOULD store `.semp` files on encrypted storage.

## application/semp-receipt

A `application/semp-receipt` resource is a signed delivery
receipt as defined in [Delivery](delivery.md), serialized
as a UTF-8 JSON object. The file extension is `.semp-receipt`.
One receipt per file.

A `.semp-receipt` file is a portable evidence artifact. The
holder of the file, together with the recipient domain's
published signing key, can verify that the recipient domain
accepted a specific envelope at a specific time. The receipt
exposes the recipient domain, the canonical envelope hash, and
the accepted-at time. It does not expose postmark contents,
brief contents, enclosure contents, or any identifiers beyond
the canonical hash.

## application/semp-recovery

A `application/semp-recovery` resource is a recovery bundle as
defined in [Recovery](recovery.md), serialized as a UTF-8
JSON object. The file extension is `.semp-recovery`.

A recovery bundle contains key material protected by
user-supplied passphrase derivation and, for server-assisted
bundles, by server-held unlock material. Possession of the
file alone is insufficient to recover the identity; the
recovery flow requires additional inputs as specified in
[Recovery](recovery.md).

Users SHOULD store recovery bundles on encrypted media and
SHOULD NOT transmit them over unauthenticated channels.

## application/semp-migration

A `application/semp-migration` resource is a migration record
as defined in [Recovery](recovery.md), serialized as a
UTF-8 JSON object. The file extension is `.semp-migration`.

A `.semp-migration` file is independently verifiable against
the published domain signing keys of the old and new providers
and the identity keys named in the record. Users MAY
distribute the file out of band to correspondents who wish to
verify continuity without performing a live fetch from the new
provider's migration endpoint.

A migration record is a public artifact. Its contents expose
the old and new addresses, the old and new identity key
identifiers, and the timestamps of the migration. Users
requiring migration without public announcement MUST NOT use
this mechanism.

# Security Considerations

For the consolidated adversary model under which this section
is evaluated, see [Architecture](architecture.md).

## Metadata Protection

The postmark contains only domain-level routing information.
Full sender and recipient addresses, timestamps, and threading
metadata are inside the encrypted brief. The subject and
message content are inside the encrypted enclosure.

Observers of network traffic are able to determine that a
message was sent from one domain to another. They cannot
determine who sent it, who received it, what it was about, or
when within the expiry window it was sent.

## Replay Prevention

The `postmark.expires` field limits the window during which a
captured envelope could be replayed. Servers MUST reject
expired envelopes. The expiry value SHOULD be set
conservatively: long enough to account for legitimate delivery
delays, short enough to limit the replay window. A default of
one hour is RECOMMENDED.

The `postmark.id` provides hop-level deduplication. Servers
MAY cache recently seen `postmark.id` values and reject
duplicates within the expiry window.

## Tampering Detection

The envelope has two complementary tamper-detection
mechanisms covering the same canonical bytes.

`seal.signature` is verifiable by any server using the
sender's published domain key. Any modification to any
immutable field, including routing metadata in the postmark,
invalidates it. Routing servers verify this before
forwarding.

`seal.session_mac` is verifiable only by the receiving server
using the session key. It proves the envelope was produced
within a valid established session, in addition to whatever
the domain key proves about origin. A stolen or forged domain
key cannot produce a valid session MAC without also
completing a real handshake.

The sole exclusion from both proofs is `postmark.hop_count`,
which relay servers may legitimately increment.

## Forward Secrecy

Forward secrecy properties of the envelope model are defined
in [Handshake](handshake.md). Session keys are ephemeral
and erased after session expiry, ensuring that compromise of
long-term domain or identity keys cannot retroactively decrypt
past envelopes.

## Differential Brief and Enclosure Encryption

SEMP uses distinct symmetric keys for the brief and enclosure,
with different access grants at the server layer. The brief
is decryptable by the recipient server (via its domain key
entry in `seal.brief_recipients`) and by the recipient
client. The enclosure is decryptable only by the recipient
client.

A compromised or malicious recipient server can therefore
read delivery metadata (the full sender address, recipient
addresses, timestamps, and thread identifiers in the brief)
but cannot read the message subject, body, or attachments,
which are protected in the enclosure under `K_enclosure`.

The residual exposure is that the recipient server learns
the full correspondent graph through the brief. This
trade-off exists because the alternative, hiding the sender
address from the server, conflicts with server-enforceable
user-level blocking.

## Blocking Enforcement and the Correspondent Graph

User-level blocking (blocking a specific sender address, as
distinct from blocking an entire domain) requires the
recipient server to know the full sender address at delivery
time, so it can check the address against the recipient's
block list before delivering to the client. This check
occurs after the server decrypts the brief.

The consequence is that the recipient server learns the full
sender address for every envelope it delivers. Over time
this constitutes a complete correspondent graph visible to
the server operator. Server-enforceable user-level blocking
is retained at the cost of a server-visible correspondent
graph.

## Recipient Anonymity

The `seal.brief_recipients` and `seal.enclosure_recipients`
maps use key fingerprints rather than addresses as keys. This
prevents either map from serving as a plaintext recipient
list. A recipient's key fingerprint may itself be linkable
to their identity if their public key is widely published.
The recipient server's domain key fingerprint is public,
consistent with the server's visibility in the postmark and
handshake. Implementations with strong recipient anonymity
requirements for client keys SHOULD consult
[Discovery](discovery.md) for guidance on key publication
strategies.

## Forwarding Provenance

`enclosure.sender_signature` and `enclosure.forwarded_from`
together provide the forwarding provenance model.

Anti-forgery: a forwarder cannot fabricate a forward that
appears to originate from a third party. The original
sender's identity key signature on the enclosure plaintext
travels with the content. A forger would need the original
sender's identity private key to produce a verifiable
`forwarded_from.original_enclosure_plaintext.sender_signature`.

Anti-tampering: a forwarder cannot alter the original content
while preserving its provenance. Any modification to
`original_enclosure_plaintext` invalidates the inner sender
signature.

Limits of evidence: the new recipient cannot independently
verify the original envelope's `seal.signature` because the
original ciphertext is not preserved. `original_seal` and
`original_postmark` in the forwarded block are advisory only.
The cryptographic provenance is the identity-key signature
on the plaintext.

The forwarder is bound by `forwarder_attestation`, which
signs the forwarded block including the claimed
`original_sender_address` and `received_at`. A forwarder who
falsifies these fields is making a verifiable, non-repudiable
claim under their own identity key.

Identity-key compromise: an attacker who obtains a user's
identity private key can forge that user's authorship of
arbitrary content, including content carried in forwards
composed by others. This risk is the same as for any
signature-based authorship system. Identity key rotation and
revocation per [Discovery](discovery.md) bound the window
in which a compromised key can be used.

# Privacy Considerations

The postmark exposes sender and recipient domains to routing
servers. This is an irreducible minimum for federated
delivery: a server must know where to send a message.
Domain-level metadata reveals that two organizations are
corresponding, without revealing who within them or about
what.

The `postmark.expires` timestamp reveals an upper bound on
when the message was sent. Implementations MAY reduce
precision (rounding to the nearest hour, for example) to
limit timing correlation attacks, at the cost of replay
window expansion.

<a id="test-vectors"></a>

# Test Vectors
The cross-language test vector corpus at `vectors/v1.0.0/` of
the SEMP specification repository pins the byte-level behavior
of the constructions in this document. The following files
exercise the envelope layer:

| File | What it pins |
|---|---|
| `envelope-canonical.json` | Canonical envelope encoding (input to `seal.signature` and `seal.session_mac`). |
| `envelope-buckets.json` | Size and recipient-count bucket selection. |
| `envelope-roundtrip.json` | Full compose flow per §7.1 and verification per §7.2; both algorithm suites; every random input pinned. |
| `seal-roundtrip.json` | Seal wrap construction per §4.4.1; both suites. |
| `sender-signature.json` | Enclosure `sender_signature` per §6.5. |
| `forwarding.json` | Forwarded-envelope three-signature chain per §6.6. |
| `large-attachment.json` | Large-attachment AEAD per the `semp.dev/large-attachment` extension. |
| `negative-envelope-rejection.json` | Must-reject cases for the §7.2 decryption flow. |

<a id="iana-considerations"></a>

# IANA Considerations
This document requests that IANA register four new media
types in the "Media Types" registry per [RFC 6838](https://www.rfc-editor.org/rfc/rfc6838).

## application/semp-envelope

Type name:
: application

Subtype name:
: semp-envelope

Required parameters:
: None

Optional parameters:
: `version`: SEMP protocol version (semver). Defaults to the
  version declared in the envelope's `version` field.

Encoding considerations:
: 8bit. The envelope is a UTF-8 JSON object. Binary content is
  base64-encoded [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) within the JSON structure.

Security considerations:
: See {{security-considerations}} of this document.

Interoperability considerations:
: See [Architecture](architecture.md) for the architectural
  model.

Published specification:
: This document.

Applications that use this media type:
: SEMP servers and clients.

Fragment identifier considerations:
: None.

Additional information:
: File extension(s): `.semp`. UTI (Apple platforms):
  `org.semp.envelope`.

Person and email address to contact for further information:
: Seyit Gokce \<contact@seyitgokce.me\>.

Intended usage:
: COMMON

Restrictions on usage:
: None

Author:
: Seyit Gokce.

Change controller:
: Seyit Gokce.

## application/semp-receipt

Type name:
: application

Subtype name:
: semp-receipt

Required parameters:
: None

Optional parameters:
: `version`: receipt format version (semver).

Encoding considerations:
: 8bit. UTF-8 JSON object. Signature bytes are base64-encoded
  within the JSON structure.

Security considerations:
: See {{security-considerations}} of this document and
  [Delivery](delivery.md).

Interoperability considerations:
: The receipt format is defined in [Delivery](delivery.md).

Published specification:
: This document and [Delivery](delivery.md).

Applications that use this media type:
: SEMP clients and applications that handle delivery evidence
  artifacts.

Fragment identifier considerations:
: None.

Additional information:
: File extension(s): `.semp-receipt`. UTI: `org.semp.receipt`.

Person and email address to contact for further information:
: Seyit Gokce \<contact@seyitgokce.me\>.

Intended usage:
: COMMON

Restrictions on usage:
: None

Author:
: Seyit Gokce.

Change controller:
: Seyit Gokce.

## application/semp-recovery

Type name:
: application

Subtype name:
: semp-recovery

Required parameters:
: None

Optional parameters:
: `version`: recovery bundle format version (semver).

Encoding considerations:
: 8bit. UTF-8 JSON object. Binary fields are base64-encoded
  within the JSON structure.

Security considerations:
: See [Recovery](recovery.md).

Interoperability considerations:
: The bundle format is defined in [Recovery](recovery.md).

Published specification:
: This document and [Recovery](recovery.md).

Applications that use this media type:
: SEMP clients and applications that handle recovery artifacts.

Fragment identifier considerations:
: None.

Additional information:
: File extension(s): `.semp-recovery`. UTI: `org.semp.recovery`.

Person and email address to contact for further information:
: Seyit Gokce \<contact@seyitgokce.me\>.

Intended usage:
: COMMON

Restrictions on usage:
: None

Author:
: Seyit Gokce.

Change controller:
: Seyit Gokce.

## application/semp-migration

Type name:
: application

Subtype name:
: semp-migration

Required parameters:
: None

Optional parameters:
: `version`: migration record format version (semver).

Encoding considerations:
: 8bit. UTF-8 JSON object. Signature bytes are base64-encoded
  within the JSON structure.

Security considerations:
: See [Recovery](recovery.md).

Interoperability considerations:
: The record format is defined in [Recovery](recovery.md).

Published specification:
: This document and [Recovery](recovery.md).

Applications that use this media type:
: SEMP clients and applications that handle migration evidence.

Fragment identifier considerations:
: None.

Additional information:
: File extension(s): `.semp-migration`. UTI: `org.semp.migration`.

Person and email address to contact for further information:
: Seyit Gokce \<contact@seyitgokce.me\>.

Intended usage:
: COMMON

Restrictions on usage:
: None

Author:
: Seyit Gokce.

Change controller:
: Seyit Gokce.

# Acknowledgments

The author thanks the contributors to the SEMP specification
for review, design discussion, and prior-art analysis.

