## Abstract

This document specifies the Sealed Envelope Messaging Protocol
(SEMP) handshake, session lifecycle, and transport bindings. The
handshake establishes a secure, authenticated session between two
parties before any envelopes are exchanged. It provides mutual
authentication, capability negotiation, and a shared session
context. SEMP supports a client-to-server handshake variant and a
server-to-server federation handshake variant, both following a
four-message structure with an optional challenge interstitial.
Sessions provide forward secrecy and post-quantum confidentiality
through a hybrid Kyber768 plus X25519 key agreement, with
ephemeral keys erased after derivation. SEMP defines transport
bindings for WebSocket [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455), HTTP/2 [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113), and QUIC
[RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001); HTTP/2 is the mandatory baseline.

# Introduction

The SEMP handshake occurs after the TLS connection is established
and before any envelope exchange. A successful handshake produces
mutual authentication, agreed cryptographic parameters, and a
session context that both parties reference for the duration of
the exchange.

Handshakes in SEMP are transaction-level rather than
connection-level. They are performed per logical messaging
transaction or batch of related messages, enabling per-transaction
access control and blocking without requiring persistent
connections.

SEMP defines two handshake variants:

* a client handshake, in which a user's client connects to its
  home server;
* a federation handshake, in which two servers establish a
  cross-domain session.

This document specifies both variants, the optional challenge
interstitial, the session key derivation procedure, the
in-session rekey protocol, the resumption mechanism, the session
lifecycle (forward secrecy, key erasure, concurrent-session
bounds, ticket lifetime), the post-quantum hybrid key agreement,
and the transport bindings that carry SEMP traffic.

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

This document additionally uses terminology from [RFC 4949](https://www.rfc-editor.org/rfc/rfc4949) for
general security-protocol terms.

# Connection Model and Privacy Constraint

## Connection Topology

SEMP enforces a strict connection topology: a sender client
connects only to its own home server. A client never connects
directly to a remote domain's server. Cross-domain message
delivery is always server-to-server through a federation session
between the sender's home server and the recipient's home server.
A server that receives a client handshake from an address outside
its own domain SHOULD treat the connection as suspicious and MAY
reject it.

How a server signals to a client that messages are waiting
(polling, persistent transport, or platform notification
services) is outside the scope of this specification.

## Identity Privacy

A core requirement of the client handshake is that client
identity MUST NOT appear in plaintext on the wire at any point.
The init message carries an
ephemeral key and capabilities only. Client identity is revealed
only after a shared secret is established, encrypted under that
secret, and therefore invisible to passive observers.

A passive observer sees that a connection was made to a server,
but cannot determine who made it or who they intend to reach.

The federation handshake does not impose this constraint: server
domains are public by nature, and the init message in the
federation variant carries the initiating domain in plaintext.

# Packet Discrimination

SEMP defines two message types at the session layer:
`SEMP_HANDSHAKE` for session establishment, and `SEMP_REKEY` for
in-session key rotation.

## SEMP_HANDSHAKE

Every handshake packet has the shape:

~~~ json
{
    "type": "SEMP_HANDSHAKE",
    "step": "<step>",
    "party": "<party>",
    "...": "..."
}
~~~

The full discriminator matrix:

| `step` | `party` | Sent by | Meaning |
|---|---|---|---|
| `init` | `client` | Client | Client opens handshake with home server. |
| `init` | `server` | Server A | Server A opens federation with Server B. |
| `response` | `server` | Server | Server responds to either init type. |
| `challenge` | `server` | Server | Server requires a challenge before proceeding. |
| `challenge_response` | `client` | Client | Client submits challenge solution. |
| `challenge_response` | `server` | Server A | Server A submits challenge solution (federation). |
| `confirm` | `client` | Client | Client confirms after key exchange. |
| `confirm` | `server` | Server A | Server A confirms federation after key exchange. |
| `accepted` | `server` | Server | Server accepts the session. |
| `rejected` | `server` | Server | Server rejects the session explicitly. |
| `resume` | `client` | Client | Client presents a resumption ticket (see [Resumption](#resumption)). |
| `resume` | `server` | Server A | Server A presents a resumption ticket (federation). |

`response`, `accepted`, and `rejected` always come from the
server, since the party being connected to controls the final
outcome.

## SEMP_REKEY

Once a session is established, either party may initiate a
rekeying exchange to rotate session keys without a full
re-authentication. Rekey packets use a separate message type to
distinguish them unambiguously from handshake traffic:

~~~ json
{
    "type": "SEMP_REKEY",
    "step": "<step>",
    "...": "..."
}
~~~

| `step` | Sent by | Meaning |
|---|---|---|
| `init` | Either | Initiates a rekeying exchange on an active session. |
| `accepted` | Responder | Accepts the rekey; carries responder ephemeral key. |
| `rejected` | Responder | Declines the rekey; session continues under old keys. |

`SEMP_REKEY` packets are encrypted and MACed under the current
session keys. Receipt of a valid `SEMP_REKEY` message therefore
implies the sender holds the active session keys, so no separate
identity proof is required.

<a id="client-handshake"></a>

# Client Handshake
## Sequence

The four-message client-to-server handshake exchanges:

1. Client to server: `step=init`, `party=client`. Carries
   ephemeral key and capabilities; carries no identity.
2. Optional challenge interstitial. Server sends `step=challenge`
   when a challenge is required (see [Challenge Interstitial](#challenge)). Client
   replies with `step=challenge_response`.
3. Server to client: `step=response`, `party=server`. Carries
   server ephemeral key, negotiated parameters, and signed server
   identity proof.
4. Both parties derive the shared session secret per
   [Shared Secret Derivation](#shared-secret-derivation).
5. Client to server: `step=confirm`, `party=client`. Carries the
   client identity and authentication, encrypted under the
   shared session secret.
6. Server to client: `step=accepted` or `step=rejected`,
   `party=server`. The session is established or refused.

The challenge round trip is conditional. When no challenge is
required, the handshake proceeds directly from message 1 to
message 2 of the response. The four-message structure is
preserved in both cases; the challenge is an optional
interstitial.

## Message 1: init / client

The init message is anonymous. It carries the client's ephemeral
public key and capabilities. Nothing in this message identifies
the client.

~~~ json
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
            "semp.dev/large-attachment"
        ]
    },
    "extensions": {}
}
~~~

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | MUST be `"SEMP_HANDSHAKE"`. |
| `version` | string | Yes | SEMP protocol version (semver). |
| `nonce` | string | Yes | Cryptographically random base64-encoded value, minimum 32 bytes. |
| `transport` | string | Yes | Transport in use; one of the identifiers defined in [Transport Bindings](#transport-bindings) or an extended binding identifier. |
| `client_ephemeral_key` | object | Yes | Ephemeral public key for this session only. MUST NOT be reused. |
| `capabilities` | object | Yes | Supported cryptographic algorithms and extension identifiers advertised for this session. |
| `extensions` | object | No | Handshake-layer extension entries. |

The init message is NOT signed. Signing would require a key
identifier, which would link this message to a client identity.
Integrity of the init is established through the confirmation
hash in message 3.

<a id="challenge"></a>

## Challenge Interstitial
When the server determines a challenge is required (based on
domain reputation, registration age, or operator policy as
specified in [Delivery](delivery.md)), it MUST respond with
a `challenge` message instead of proceeding directly to the
`response` step. No session resources are allocated and no
ephemeral key material is generated until the challenge is
verified.

The challenge mechanism is type-agnostic. The `challenge_type`
field identifies which kind of challenge the server is issuing,
and the `parameters` object carries the type-specific data
needed by the client to compute a solution.

### Challenge Schema

~~~ json
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
    "expires": "2026-06-10T20:35:00Z",
    "server_signature": "signature-over-entire-message"
}
~~~

The initiator MUST verify `server_signature` before computing a
solution. A `challenge` message with an invalid signature MUST
be treated as a rejection and the handshake MUST be aborted.
This obligation applies to both client initiators performing
client-to-server handshakes and federation peers performing
server-to-server handshakes.

An initiator that does not recognize the `challenge_type` MUST
abort the handshake.

### Proof-of-Work Challenge Type

The `proof_of_work` challenge type requires the client to find a
nonce that produces a hash with a specified number of leading
zero bits. It is the baseline challenge type and MUST be
supported by all implementations.

Parameters:

| Field | Type | Required | Description |
|---|---|---|---|
| `algorithm` | string | Yes | Hash algorithm. MUST be `sha256`. |
| `prefix` | string | Yes | Base64-encoded random bytes. Minimum 16 bytes of entropy. |
| `difficulty` | integer | Yes | Leading zero bits required in the solution hash. MUST be in the range 0 to 28 inclusive. |

A conformant server MUST NOT issue a `proof_of_work` challenge
with `difficulty` greater than 28. A conformant handshake
initiator MUST abort the handshake with `reason_code:
"challenge_invalid"` if it receives a `proof_of_work` challenge
with `difficulty` greater than 28, and MUST NOT attempt to solve
a challenge that exceeds the cap. The cap prevents a malicious
or compromised server from issuing prohibitively expensive
challenges against either clients (exhausting device resources
or draining batteries) or federation peers (consuming CPU on
shared infrastructure).

The `expires` timestamp MUST be far enough in the future to
allow a legitimate initiator on constrained hardware or a
high-latency network to compute a solution. A conformant server
MUST NOT issue a `proof_of_work` challenge whose `expires` value
is less than the floor corresponding to its `difficulty`:

| Difficulty range | Minimum `expires` relative to issuance |
|---|---|
| 0 to 20 | 30 seconds |
| 21 to 24 | 60 seconds |
| 25 to 28 | 120 seconds |

A conformant initiator MUST abort the handshake with
`reason_code: "challenge_invalid"` if it receives a
`proof_of_work` challenge whose `expires` value, measured against
the initiator's clock at receipt, is shorter than the floor for
its difficulty.

### Challenge Response

The client submits its solution to the challenge:

~~~ json
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
~~~

For `proof_of_work` challenges, the client finds a nonce such
that:

~~~
SHA-256(prefix || ":" || challenge_id || ":" || nonce)
~~~

produces a hash with at least `difficulty` leading zero bits.

The server MUST verify the solution before proceeding:

1. Confirm `challenge_id` matches an issued, unexpired challenge.
2. Recompute the SHA-256 over the full preimage above.
3. Confirm the result matches the submitted `hash`.
4. Confirm the hash has at least `difficulty` leading zero bits.

If verification passes, the handshake continues to message 2. If
verification fails or the challenge has expired, the server MUST
respond with `step=rejected` and `reason_code:
"challenge_failed"`. Each challenge MUST be single-use: the
server MUST reject a duplicate `challenge_id` submission even if
the solution is valid.

A valid challenge solution permits the handshake to proceed. It
does not grant trust or bypass any subsequent identity
verification steps.

### First-Contact Proof of Work

A `proof_of_work` challenge MAY be issued by a recipient server
in response to an envelope submission, in addition to in-handshake
issuance, when the recipient's first-contact policy announces
`mode: "challenge"` with `challenge_type: "proof_of_work"`. The
challenge format is identical to the in-handshake form and is
delivered as a field of a `policy_forbidden` rejection response.

The challenge is bound to a (sender_domain, recipient_address,
postmark_id) tuple by including those values in the `prefix`
derivation:

~~~
prefix = base64( random_bytes(16) || H(
    "SEMP-FIRST-CONTACT-V1:" || sender_domain || 0x00 ||
    recipient_address || 0x00 || postmark_id
) )
~~~

`H` is SHA-256, `||` denotes byte concatenation, and `0x00` is a
single NUL octet. The leading ASCII tag provides domain
separation from any other SHA-256 use in this protocol. The NUL
separators between the three input fields prevent
boundary-shift collisions.

The recipient server MUST NOT vary `difficulty` based on whether
the recipient address exists, in conformance with the
address-enumeration resistance requirement in
[Architecture](architecture.md).

The solved token is carried in `seal.first_contact_token` of the
resubmitted envelope. The full token schema and verification
procedure are specified in [Delivery](delivery.md).

### Initiator Aborts

When the initiator rejects a server-issued challenge, the
initiator MUST send a `rejected` handshake message to the
issuing server before closing the transport. The abort message
carries a `reason_code` so the issuer learns the specific rule
it violated.

A client-initiator abort is NOT signed. Signing would require a
`key_id` identifying the client's identity key, defeating the
anonymous-init property. A federation-initiator abort IS signed
with the initiator's domain key, matching the signed abort
produced by federation responders. Federation peer identities
are public by nature, so signing imposes no anonymity cost.

After sending the abort, the initiator MUST close the transport
and MUST NOT retry under the same conditions.

## Message 2: response / server

The server responds with its own ephemeral key and the
negotiated session parameters.

~~~ json
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
            "semp.dev/large-attachment"
        ],
        "max_envelope_size": 26214400
    },
    "server_signature": "signature-over-entire-message",
    "extensions": {}
}
~~~

The `negotiated` object MUST include `max_envelope_size`, which
declares the maximum envelope size in bytes that this server
will accept. Clients MUST NOT submit envelopes exceeding this
value. In federation handshakes, the negotiated
`max_envelope_size` is the minimum of both servers' advertised
limits.

The server MUST sign message 2 with its long-term domain key.
The client verifies this signature using the server's published
domain key before proceeding to message 3. If verification
fails, the client MUST abort.

<a id="shared-secret-derivation"></a>

## Shared Secret Derivation
After message 2, both parties derive the shared session secret
using HKDF [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869):

* Input keying material: shared secret from ephemeral key
  agreement (the negotiated suite's KEM output).
* Salt: `client_nonce || server_nonce` (concatenation).
* Info context: `"SEMP-v1-session"`.
* Hash function: determined by the negotiated suite. Both
  currently defined suites
  (`x25519-chacha20-poly1305` and
  `pq-kyber768-x25519`) use HKDF-SHA-512, per the suite
  definitions in [Envelope](envelope.md). Future suites
  MUST explicitly name their HKDF hash function as part of
  the suite definition.

Six keys are derived from this material via HKDF-Expand using
distinct labels per key:

| Key | Length | Purpose | Label |
|---|---|---|---|
| `K_enc_c2s` | 32 | Encrypts client to server handshake messages. | `SEMP-v1-session-enc-c2s` |
| `K_enc_s2c` | 32 | Encrypts server to client handshake messages. | `SEMP-v1-session-enc-s2c` |
| `K_mac_c2s` | 32 | MACs client to server handshake messages. | `SEMP-v1-session-mac-c2s` |
| `K_mac_s2c` | 32 | MACs server to client handshake messages. | `SEMP-v1-session-mac-s2c` |
| `K_env_mac` | 32 | MACs all envelopes sent within this session. | `SEMP-v1-session-env-mac` |
| `K_resumption` | 32 | Pre-shared key used to resume this session after disconnect. | `SEMP-v1-session-resumption` |

All six expansions use the same HKDF PRK (the single
HKDF-Extract output over the ephemeral shared secret and nonce
salt). The six Expand calls are independent.

Separate directional keys prevent cross-channel attacks where a
message sent in one direction could be replayed in the other.
`K_env_mac` is distinct from the handshake MAC keys and is used
exclusively for authenticating envelopes sent within this
session, as specified in [Envelope](envelope.md).

`K_resumption` is treated differently from the other five keys:
it is NOT used to encrypt or MAC messages within this session.
Instead, the server retains `K_resumption` (directly or
indirectly via a resumption ticket) so it can be combined with
fresh ephemeral material to derive the key schedule of a later
resumed session.

A server that does not support resumption MAY skip derivation of
`K_resumption` and MUST NOT issue resumption tickets.

## Message 3: confirm / client

The confirm message carries the client's identity and
authentication, encrypted under the shared session secret. A
passive observer sees only an opaque encrypted blob alongside
the confirmation hash.

~~~ json
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
~~~

The `identity_proof` field is an encrypted JSON object
containing:

~~~ json
{
    "client_id": "client-ulid",
    "client_identity": "user@example.com",
    "client_long_term_key_id": "long-term-key-fingerprint",
    "identity_signature": "base64-identity-signature",
    "auth": {
        "method": "identity_key",
        "params": {}
    }
}
~~~

This block is encrypted under `K_enc_c2s` and is opaque to any
party that does not hold the session secret.

The `confirmation_hash` is computed as:

~~~
SHA-256(canonical(message_1) || canonical(message_2))
~~~

Where `canonical()` uses the same canonicalization as envelope
seal signatures (lexicographically sorted keys, no insignificant
whitespace). This binds the confirmation to the specific
exchange that preceded it, preventing message-substitution
attacks.

## Authentication Methods

SEMP treats all authentication methods as equally first-class.
The `auth` object in the identity proof block specifies the
method and carries its parameters. Servers declare which methods
they accept during discovery.

`identity_key`:
: Authentication is provided entirely by `identity_signature`
  in the identity proof block. No additional parameters
  required.

`token`:
: A JWT or opaque token issued by the server or a trusted
  identity provider. Token validation semantics are
  server-defined.

`password`:
: Challenge-response password authentication. The server MAY
  issue a challenge in message 2 via `extensions` when password
  auth is expected. The response is computed over the challenge
  using the agreed password hash scheme.

`mfa`:
: Combines a primary method with an additional factor. Factor
  types (such as TOTP) are extensible.

Additional authentication methods MAY be defined in extensions
using the standard namespacing convention.

## Message 4: accepted or rejected

The server's final message confirms the session is open, or
rejects it explicitly with a reason.

~~~ json
{
    "type": "SEMP_HANDSHAKE",
    "step": "accepted",
    "party": "server",
    "version": "1.0.0",
    "session_id": "echoed-session-id",
    "session_ttl": 300,
    "permissions": ["send", "receive", "create_group"],
    "resumption_ticket": {
        "value": "base64-opaque-ticket-bytes",
        "expires_at": "2026-04-26T12:00:00Z"
    },
    "server_signature": "signature-over-entire-message",
    "extensions": {}
}
~~~

On rejection:

~~~ json
{
    "type": "SEMP_HANDSHAKE",
    "step": "rejected",
    "party": "server",
    "version": "1.0.0",
    "session_id": "echoed-session-id",
    "reason_code": "auth_failed",
    "reason": "Identity signature could not be verified.",
    "server_signature": "signature-over-entire-message",
    "extensions": {}
}
~~~

| Field | Type | Required | Description |
|---|---|---|---|
| `session_id` | string | Yes | Echo of session identifier. |
| `session_ttl` | integer | Yes | Session lifetime in seconds from `established_at`. The client computes `expires_at` and schedules proactive rekeying from this value. A client that receives an `accepted` message without this field MUST assume 300 seconds and SHOULD log a warning. |
| `permissions` | array | No | Granted permissions. Present in `accepted` step only. |
| `resumption_ticket` | object | No | Server-issued resumption ticket. Present in `accepted` step when the server supports resumption. |
| `reason_code` | string | No | Machine-readable reason. Present in `rejected` step only. See [Reason Codes](#reason-codes). |
| `reason` | string | No | Human-readable description. Present in `rejected` step only. |
| `server_signature` | string | Yes | Signature over the entire message. |

If the server cannot complete the handshake for any reason, it
MUST send a `rejected` response rather than closing the
connection without explanation.

<a id="federation-handshake"></a>

# Federation Handshake
The server-to-server handshake follows the same four-message
structure as the client-to-server handshake. The differences
are:

* both parties authenticate as domains rather than as
  individual users;
* domain ownership is proved cryptographically through one of
  the verification methods in [Domain Verification Methods](#domain-verification-methods);
* federation policies are negotiated during the handshake;
* sessions are typically longer-lived.

## Message 1: init / server

Unlike the client init, the server init includes domain identity
in plaintext. Server-to-server connections are domain-to-domain
by nature.

~~~ json
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
            "semp.dev/large-attachment"
        ],
        "max_envelope_size": 52428800,
        "max_batch_size": 1000
    },
    "server_signature": "signature-over-entire-message",
    "extensions": {}
}
~~~

The `peer_configuration_revision` field carries the initiator's
cached revision of the responding peer's configuration document
per [Discovery](discovery.md). The responder compares the
received value against its own current configuration revision
and, if the initiator's value is stale, SHOULD emit a
configuration update message over the established session at
first opportunity.

SEMP defines a single federation mode. The protocol does not
encode named federation types such as "full" or "relay" at the
handshake layer. Every federation session grants the same
baseline. Operators express per-peer restrictions through local
policy rather than through a wire-level federation-type field.

## Domain Key Bootstrap

Before a federation handshake can proceed, both sides need each
other's domain signing public key to verify handshake message
signatures. The bootstrap follows this order:

1. Check the local cache for the peer's domain key. If present
   and not expired, use it.
2. Resolve the peer's SEMP service record via DNS to find the
   peer's server hostname per [Discovery](discovery.md).
3. Fetch the peer's well-known configuration document, read
   `endpoints.domain_keys`, and fetch the domain keys from that
   URL. The HTTPS certificate chain serves as the trust anchor.
4. Store the fetched domain key in the local cache for future
   handshakes.

The bootstrap is performed lazily: the initiating server fetches
the peer's domain key the first time it needs to federate with
that domain. Subsequent handshakes (including rekeys) use the
cached key.

<a id="domain-verification-methods"></a>

## Domain Verification Methods
Server-to-server handshakes require domain ownership
verification. SEMP supports multiple methods, ordered by
operator preference.

DNS TXT record:
: A record at `_semp-verify.<domain>` carries a signed
  verification token. The format is
  `v=semp1;id=<server_id>;s=<signature>`.

Certificate verification:
: Domain ownership is established via the TLS certificate
  presented during the underlying mTLS connection. The
  certificate Common Name or Subject Alternative Name MUST
  match `server_domain`.

Configuration verify endpoint:
: The initiating server advertises a `verify` endpoint in its
  configuration document. The verification token is derived
  from the server's identity proof signature and appended to
  the advertised base URL. The responding server fetches the
  resulting URL to confirm domain control.

Servers MAY support multiple verification methods. The method
used is declared in `domain_proof.method` and MUST be verifiable
by the receiving server before message 2 is sent.

## Messages 2 to 4

The federation `response`, `confirm`, and `accepted`/`rejected`
messages parallel the client variant with the following
differences:

* `response` carries `server_id`, `server_domain`,
  `server_configuration_revision`, and a
  `domain_verification_result` block alongside the negotiated
  parameters.
* `response` carries a `federation_policy` object describing
  message retention and other operator-declared terms.
* `confirm` (party=server) carries a `federation_acceptance`
  object whose `policy_acknowledged` field MUST be `true` if
  the initiating server accepts the federation policy terms.
  Unacceptable policy MUST trigger an explicit
  `accepted: false` rather than a silent close.
* `accepted` and `rejected` follow the same shape as the client
  variant.

## Race Resolution

If two federation servers simultaneously initiate handshakes to
each other (a race during startup or failover), both MUST detect
the collision via `session_id` comparison in the confirm step.
The session whose `session_id` sorts lower lexicographically
MUST be abandoned; the other proceeds to `accepted`. This is
deterministic and requires no external coordination.

<a id="resumption"></a>

# Resumption
A client that holds a valid, unexpired resumption ticket from a
prior handshake MAY resume rather than performing a full
four-message handshake. Resumption uses a two-message exchange
that binds a fresh ephemeral key agreement to the resumption
secret recovered from the ticket. The authenticated identity,
permissions, and session TTL policy from the original handshake
carry forward; the key material is fresh.

## Preconditions

A client MAY resume if and only if:

1. The server's last `accepted` response issued a
   `resumption_ticket`.
2. The ticket's `expires_at` is in the future per the clock
   tolerance of the implementation.
3. The ticket has not been presented before (single-use).
4. The client's cached configuration for the server has not
   been invalidated.

If any precondition fails, the client MUST perform a full
handshake.

## Resume Step Schema

Client sends:

~~~ json
{
    "type": "SEMP_HANDSHAKE",
    "step": "resume",
    "party": "client",
    "version": "1.0.0",
    "nonce": "base64-random-32-bytes",
    "resumption_ticket": "base64-opaque-ticket-bytes",
    "client_ephemeral_key": {
        "algorithm": "pq-kyber768-x25519",
        "key": "base64-encoded-ephemeral-public-key",
        "key_id": "ephemeral-key-fingerprint"
    },
    "transport": "ws",
    "extensions": {}
}
~~~

Server responds with `step: "accepted"` or `step: "rejected"`.
On acceptance the response carries a fresh `session_id`, a
fresh `server_ephemeral_key`, a `server_nonce`, and a new
`resumption_ticket` that replaces the consumed one.

## Key Derivation for Resumption

Session keys for the resumed session are derived per
[Shared Secret Derivation](#shared-secret-derivation) with one modification: the
HKDF-Extract input keying material is the concatenation of the
ephemeral shared secret and the resumption secret recovered
from the ticket:

~~~
IKM_resume := ephemeral_shared_secret || K_resumption
PRK        := HKDF-Extract(salt = client_nonce || server_nonce,
                           IKM = IKM_resume)
~~~

The five per-direction keys (`K_enc_c2s`, `K_enc_s2c`,
`K_mac_c2s`, `K_mac_s2c`, `K_env_mac`) and the next resumption
secret (`K_resumption_next`) are derived by HKDF-Expand from
this PRK using the same labels as the full-handshake key
schedule.

The fresh ephemeral key agreement is what preserves forward
secrecy for the resumed session. An attacker who obtains the
ticket alone cannot derive session keys without also breaking
the ephemeral assumption.

## Ticket Lifecycle

Resumption tickets are single-use. On successful acceptance, the
server MUST invalidate the presented ticket and issue a fresh
ticket in the `accepted` response, bound to the new session's
key schedule.

Ticket `expires_at` MUST NOT exceed 7 days from the time of
issuance. A server that receives a `resume` message bearing a
ticket past its `expires_at` MUST reject with `reason_code:
"resumption_failed"`.

Servers MAY implement tickets in one of two ways:

Stateful ticket table:
: The ticket value is a random identifier. The server
  maintains a table mapping the identifier to
  `{authenticated_identity, K_resumption, expires_at,
  additional context}`. On acceptance, the server removes
  the consumed ticket from the table.

Stateless self-contained ticket:
: The ticket value is an AEAD encryption of the same record
  under a server-held ticket-encryption key. The server holds
  no per-client state. To enforce single-use, the server MUST
  maintain a consumed-ticket cache: on acceptance, the
  server records a unique identifier for the consumed ticket
  (for example, the AEAD ciphertext hash) and retains it
  until past the ticket's `expires_at`. A `resume` request
  bearing a ticket whose identifier is present in the
  consumed-ticket cache MUST be rejected with `reason_code:
  "resumption_failed"`.

The wire format treats the ticket as opaque; clients cannot
distinguish the two implementations.

The ticket-encryption key used for stateless tickets is a
long-term server secret. The operator SHOULD rotate this key
at least quarterly to bound the exposure window of a leaked
ticket-encryption key. During rotation, the server MUST
retain the prior key for an overlap window of at least the
maximum ticket TTL (7 days) so that tickets issued under the
prior key continue to decrypt. After the overlap window, the
prior key MUST be erased.

A server MAY decline to issue tickets (operator policy,
resource constraints, forward-secrecy-strict mode). In that
case, the `accepted` message omits `resumption_ticket`.

## Rejection and Fallback

A server unable to resume a presented ticket MUST return
`step: "rejected"` with one of:

* `reason_code: "resumption_failed"` for resumption-specific
  failure (ticket unknown, expired, corrupt, or already
  consumed);
* a standard invalidation reason code when the underlying
  identity is no longer valid (`revoked`, `blocked`, or
  `certificate_expired`).

On `resumption_failed` the client MUST perform a full handshake
and MUST NOT retry resumption with the same ticket.

## No 0-RTT Data

The `resume` message MUST NOT carry envelope submissions or
other session-bound application data. The client MUST wait for
`accepted` before sending any payload that depends on the
resumed session keys. Servers that receive application data in
a `resume` message MUST reject with `reason_code:
"resumption_failed"`. This rules out the replay exposure
associated with 0-RTT data in other protocols.

## Federation Resumption

Federation handshakes support resumption on the same terms. The
`resume` message uses `party: "server"` and carries the domain
identity fields (`server_id`, `server_domain`,
`peer_configuration_revision`) in addition to the
resumption-specific fields. Domain-ownership proof is NOT
repeated on resumption: the ticket, issued after the original
full handshake verified domain ownership, stands in for it.

# Session Lifecycle

## Forward Secrecy

SEMP sessions provide forward secrecy: a future compromise of
any long-term key (domain key, identity key, or encryption
key) cannot be used to decrypt envelopes exchanged in past
sessions. Each session's confidentiality rests entirely on its
ephemeral key material.

An adversary who records encrypted SEMP traffic and later
obtains a server's long-term domain key learns:

* that sessions occurred between the two domains (visible from
  the TLS connection and postmark);
* the timing and approximate volume of those sessions.

The adversary does not learn:

* the contents of any brief or enclosure from past sessions;
* the session keys used in any past session;
* the identity of any client who participated in a past
  session, because identity is encrypted under the session
  secret in the handshake.

This guarantee holds as long as the ephemeral private keys used
in the handshake have been erased.

## Ephemeral Key Erasure

The ephemeral private key MUST be erased immediately after the
shared secret is computed. "Erased" means overwritten with
zeros (or platform-equivalent secure erasure) and freed from
memory. The ephemeral private key MUST NOT be:

* written to disk, swap, or any persistent storage;
* logged, cached, or retained for debugging;
* held in memory beyond the point where the shared secret is
  derived.

Implementations MUST treat the ephemeral private key as a
single-use value. If the shared secret computation fails, the
ephemeral private key is still erased; the handshake is
aborted and a new ephemeral key pair is generated for any
retry.

## Active Session State

While a session is active, the server holds the following state
in memory: `session_id`, the five session keys (`K_env_mac`,
`K_enc_c2s`, `K_enc_s2c`, `K_mac_c2s`, `K_mac_s2c`),
`established_at`, `expires_at`, `client_identity` (client
sessions only), and `peer_domain` (federation sessions only).

This state MUST be held only in memory. It MUST NOT be written
to disk, replicated to secondary storage, or included in
backups. A server restart invalidates all active sessions; the
sender's server is responsible for re-establishing sessions
after interruption.

<a id="session-expiry-and-key-erasure"></a>

## Session Expiry and Key Erasure
When a session expires (its TTL elapses) or is explicitly
invalidated:

1. The session state MUST be erased from memory using secure
   zeroing before the memory is freed.
2. The `session_id` MUST be retained in an expiry log for
   replay prevention. Only the ID is retained, not any key
   material.
3. No key material from the expired session is transferred to
   any new session.

A session that has expired MUST NOT remain in a state where
its keys could be read from memory by an attacker with runtime
memory access.

## Concurrent Session Limits

A server MUST permit at most one active session per
authenticated client identity at a time. If a client initiates
a new handshake while an existing session for the same
`client_identity` is active and unexpired, the server MUST:

* Immediately erase the older session's key material per
  [Session Expiry and Key Erasure](#session-expiry-and-key-erasure).
* Retain the older `session_id` in the expiry log for replay
  prevention.
* Complete the new handshake normally.

The server MUST NOT push an invalidation message on the
superseded session at the moment of supersession. The client is
itself the party that initiated the new handshake; the client
always knows which session is current without server
notification. Any continued use of the old session after
supersession indicates a client defect or a second process
under the same `client_identity` that raced the first. In
either case, the server's response of `handshake_invalid` or
`no_session` on the next envelope is sufficient to redirect the
stale submitter to the current session. The old session's key
material is erased at supersession and no further authenticated
message can be produced on it.

For server-to-server federation sessions, a server MUST permit
at most one active session per peer domain at a time, subject
to the same invalidation rule.

### Federation Race Resolution

If two federation servers simultaneously initiate handshakes
to each other (a startup or failover race), both peers MUST
detect the collision via `session_id` comparison in the
confirm step. The session whose `session_id` sorts lower
lexicographically MUST be abandoned, and the other proceeds
to `accepted`. This resolution is deterministic and requires
no external coordination.

To prevent resource exhaustion, servers MUST enforce a bound on
total concurrent active sessions. Recommended defaults: 10000
client sessions and 1000 federation sessions per server. When
the active session count reaches the configured limit, the
server MUST reject new handshake `init` messages with
`reason_code: "server_at_capacity"`.

## Client-Side Session State

The client holds a corresponding session context for the
duration of the session: `session_id`, `K_enc_c2s`, `K_mac_c2s`,
`K_env_mac`, `established_at`, `server_ttl`, and a locally
computed `expires_at = established_at + server_ttl`.

The client does not retain `K_enc_s2c` or `K_mac_s2c` after the
handshake concludes, as those keys are used exclusively for
server-to-client messages. They MAY be held during the
handshake exchange and MUST be erased once the session is
established.

Client session state MUST be held only in process memory. It
MUST NOT be written to disk, included in crash reports,
synchronized to cloud backup services, or retained across
application restarts. On platforms that support secure zeroing,
the client MUST erase key material before freeing memory; on
platforms without secure zeroing, the client MUST overwrite the
key bytes with random data before deallocation.

### Backgrounding and Device Lock

On mobile and desktop platforms, the operating system may
suspend or checkpoint the application when it is backgrounded
or the device is locked. Client implementations MUST handle
these transitions distinctly.

On backgrounding:
: The client SHOULD erase session key material and treat the
  session as ended. The session TTL is short enough that a
  session will typically have expired by the time the
  application is foregrounded again. On resumption, the
  client MUST initiate a fresh handshake rather than
  attempting to resume the prior session.

On device lock:
: The client MUST erase session key material when the device
  transitions to a locked state, consistent with the
  platform's secure enclave or keychain erasure semantics.
  Session state MUST NOT be held in storage that persists
  across a lock event.

Bounded background tasks:
: Implementations MAY keep the session alive through a brief
  backgrounding when the platform provides a reliable
  background execution window with a known time bound. In
  that case, key material MUST be held in locked,
  non-swappable memory for the duration, and MUST be erased
  when the background window ends, regardless of whether the
  session TTL has elapsed.

The client MUST treat the following as definitive evidence that
a session has expired or been invalidated, regardless of its
local `expires_at`:

* receipt of `handshake_expired`, `handshake_invalid`, or
  `no_session` in response to an envelope submission;
* receipt of a `SEMP_HANDSHAKE rejected` message with any of
  the above reason codes during a rekey attempt.

On any of these signals, the client MUST erase the current
session state, initiate a fresh handshake, and retry the
envelope under the new session.

<a id="rekeying"></a>

# Session Rekeying
Sessions approaching their TTL may be extended without full
re-authentication through a rekeying exchange.

## When to Rekey

Implementations SHOULD initiate rekeying when a session has
consumed 80% of its TTL. The initiating party (client for
client sessions, either server for federation sessions) is
responsible for timing the rekey.

Rekeying MUST NOT be initiated after the session has expired.
An expired session requires a full new handshake.

## Rekey Exchange

Rekeying uses a two-message exchange (`SEMP_REKEY`) over the
existing authenticated session channel. Both messages are
encrypted and MACed using the current session keys.

Init message (sent by initiator):

~~~ json
{
    "type": "SEMP_REKEY",
    "step": "init",
    "version": "1.0.0",
    "session_id": "current-session-id",
    "new_ephemeral_key": {
        "algorithm": "pq-kyber768-x25519",
        "key": "base64-encoded-new-ephemeral-public-key",
        "key_id": "new-ephemeral-key-fingerprint"
    },
    "rekey_nonce": "base64-random-32-bytes"
}
~~~

The encryption proves the initiating party holds the current
session keys; no additional signature is required.

Accepted message (sent by responder):

~~~ json
{
    "type": "SEMP_REKEY",
    "step": "accepted",
    "version": "1.0.0",
    "session_id": "current-session-id",
    "new_session_id": "server-generated-new-ulid",
    "new_ephemeral_key": {
        "algorithm": "pq-kyber768-x25519",
        "key": "base64-encoded-responder-ephemeral-public-key",
        "key_id": "responder-ephemeral-key-fingerprint"
    },
    "rekey_nonce": "echoed-rekey-nonce",
    "responder_nonce": "base64-random-32-bytes"
}
~~~

On rejection, `step` is `"rejected"` and the message carries
`reason_code` and `reason` fields. Reason codes for rekeying:

| Reason code | Meaning |
|---|---|
| `session_expired` | The session expired before the rekey completed. |
| `rekey_unsupported` | The remote party does not support in-session rekeying. |
| `rate_limited` | Too many rekey attempts within the session lifetime. |

## New Key Derivation

After the two-message exchange, both parties compute a new
shared secret via ephemeral key agreement. The new session
keys are derived using HKDF with:

* Input keying material: new shared secret from the rekeying
  ephemeral key agreement.
* Salt: `rekey_nonce || responder_nonce`.
* Info context: `"SEMP-v1-rekey"` (distinct from the initial
  session info context to prevent cross-context key
  confusion).

The same five key labels are used as in the initial derivation,
applied to the new HKDF PRK.

## Key Transition

Once the new keys are derived:

1. The new session is identified by `new_session_id`. The old
   `session_id` is retired.
2. Both parties MUST erase the old session keys using secure
   zeroing before switching to the new keys.
3. The rekeying ephemeral private keys MUST be erased
   immediately after the new shared secret is computed.
4. Envelopes in flight that reference the old `session_id`
   MUST be processed under the old keys if received before the
   transition deadline. Both parties SHOULD allow a brief
   transition window (RECOMMENDED: 5 seconds) during which
   both session IDs are accepted.

A rekeyed session inherits the original session's
`established_at` for purposes of authentication audit logging.
The new `expires_at` is `rekey_accepted_at + original_TTL`.

## Rekeying Limits

A session MUST NOT be rekeyed more than once per minute.
Implementations MUST enforce a maximum of 10 rekey events per
session lifetime, regardless of TTL. If the maximum is reached,
the session is not extended further and a full new handshake
is required.

# Post-Quantum Forward Secrecy

SEMP's preferred algorithm suite is `pq-kyber768-x25519`, a
hybrid combining Kyber768 (a lattice-based key encapsulation
mechanism) with X25519 (classical elliptic-curve
Diffie-Hellman).

The hybrid performs two parallel key agreements and combines
their outputs:

1. Kyber768 encapsulation: the initiating party encapsulates a
   secret under the responder's Kyber768 ephemeral public key,
   producing a Kyber shared secret `K_kyber` and a ciphertext.
2. X25519 scalar multiplication: both parties perform X25519
   using their respective ephemeral key pairs, producing
   `K_x25519`.

The combined input keying material for HKDF is:

~~~
IKM := K_kyber || K_x25519
~~~

Concatenation order is fixed. Implementations MUST NOT vary the
order, as it would produce incompatible session secrets.

The hybrid provides forward secrecy against both classical and
quantum adversaries. If one component is broken, the other
still protects the session secret. This addresses the
"harvest now, decrypt later" threat model: an adversary who
records traffic today and gains quantum capability in the
future cannot retroactively decrypt sessions protected by
Kyber768 ephemeral keys that have already been erased.

Servers MUST prefer the strongest mutually supported suite and
MUST NOT downgrade to a suite that lacks post-quantum
components if both parties support one. Downgrade attempts are
detectable via the confirmation hash.

<a id="session-invalidation-and-blocking"></a>

# Session Invalidation and Blocking
Session invalidation in SEMP is a local server concern. There
is no published invalidation message, no gossip, and no
network-level invalidation protocol. When a server invalidates
a session, whether due to a block, a security event, or
expiry, it updates its local state and enforces the consequence
on subsequent interactions.

<a id="blocking-behavior"></a>

## Blocking Behavior
A server MUST check block lists before processing a handshake
`init` message. This check occurs before any session resources
are allocated.

The matching block entry carries a policy field defined in
[Delivery](delivery.md). The server's action on the
blocked sender's `init` and on subsequent envelopes received
on an existing session depends on that policy.

When the block policy is `rejected`:
: The blocked sender's `init` MUST be rejected with `step:
  "rejected"` and `reason_code: "blocked"`. A blocked
  sender's envelope received on an existing session MUST be
  rejected with `reason_code: "blocked"`. Where operator
  policy requires indistinguishability from other policy
  refusals, `reason_code: "policy_forbidden"` MUST be
  returned in place of `blocked`, per the rules in
  [Envelope](envelope.md) and
  [Architecture](architecture.md).

When the block policy is `silent`:
: The server MUST NOT send any response to the `init`
  message and MUST discard envelopes received on an existing
  session without reply. The recipient does not transmit any
  wire value labelled `silent`; the sending server
  synthesizes the `silent` classification locally after its
  timeout window elapses without a response, per
  [Delivery](delivery.md). Silent policy is a
  legitimate recipient privacy and abuse-protection
  mechanism, applicable to anti-harassment cases,
  denial-of-service mitigation, and any other situation
  where revealing a refusal would itself be harmful.
  Operators MUST NOT apply `silent` as the default policy
  for all blocks. A server operating a silent block MUST
  maintain consistent timing per the rules in
  [Delivery](delivery.md) so that silence is
  indistinguishable from unrelated network failure.

When a block is applied after a session is already
established, the server invalidates the session locally. The
server MUST NOT send an invalidation message to the blocked
party regardless of block policy. Subsequent envelopes and
handshake attempts from the blocked party are handled
according to the block entry's policy: explicit rejection
with `reason_code: "blocked"` (or `policy_forbidden` under
indistinguishability policy), or silent discard per the rules
above.

## Non-Block Invalidation

When a session is invalidated for a reason other than a block
(for example, a key revocation event or a security policy
change), subsequent envelopes referencing that session MUST be
rejected with `reason_code: "handshake_invalid"`. The sending
server MUST treat this as a signal to establish a new session
and resend the envelope.

## Envelope-Session Binding

Every envelope MUST reference a valid session via
`postmark.session_id`. An envelope without a `session_id` MUST
be rejected with `reason_code: "no_session"`.

The receiving server verifies that the `session_id` in the
postmark corresponds to an active, non-expired,
non-invalidated session before processing the envelope
further. This check occurs after seal verification and after
the `postmark.expires` check, and before any content is
processed.

<a id="reason-codes"></a>

# Reason Codes
All rejections MUST carry a machine-readable reason code. The
authoritative cross-cutting registry of every reason code in
the SEMP protocol, organized by layer and with per-code
recoverability and sender-behavior columns, is the Reason Code
Registry in [Delivery](delivery.md). The handshake-layer
codes (rejection of `SEMP_HANDSHAKE` messages with
`step: "rejected"`) and the rekeying-layer codes (rejection of
in-session rekey attempts) are defined there.

Additional reason codes MAY be defined in extensions using the
standard namespacing convention.

# Sender Server Retry Responsibility

The sender server is responsible for retry logic. Envelope
rejections that indicate a recoverable session state MUST
trigger automatic retry:

| Received reason code | Sender server action |
|---|---|
| `handshake_expired` | Establish a new session, resend the envelope. |
| `handshake_invalid` | Establish a new session, resend the envelope. |
| `no_session` | Establish a session, resend the envelope. |
| `blocked` | Do not retry. Surface the failure to the sending user. |
| `rate_limited` | Retry after exponential backoff. |
| `challenge_failed` | Restart the handshake from message 1 to obtain a fresh challenge. Do not surface to the sending user unless retries are exhausted. |
| `server_at_capacity` | Retry after exponential backoff. Do not surface to the sending user unless retries are exhausted. |
| `auth_failed` | Do not retry automatically. Surface to the sending user. |

The sender server MUST NOT retry indefinitely. A maximum retry
count and backoff ceiling SHOULD be configured per operator
policy.

<a id="transport-bindings"></a>

# Transport Bindings
SEMP is transport-agnostic. It defines application-layer
semantics without prescribing a specific wire transport. This
section defines the minimum requirements a transport must
satisfy and specifies bindings for the core transports.

SEMP does not require a dedicated port. All core transports
operate over standard HTTPS infrastructure on port 443.

<a id="minimum-transport-requirements"></a>

## Minimum Transport Requirements
Any transport used to carry SEMP messages MUST satisfy:

Confidentiality:
: The transport MUST encrypt all data in transit. TLS 1.3 is
  RECOMMENDED. TLS 1.2 with forward-secret cipher suites is
  the minimum acceptable floor. Transports that do not
  provide confidentiality of all data in transit MUST NOT
  be used to carry SEMP messages.

Server authentication:
: The transport MUST allow the connecting party to verify the
  remote server's domain identity, satisfied by TLS
  certificate verification.

Reliable, ordered delivery:
: Every SEMP message MUST arrive at the recipient and MUST
  arrive in the order it was sent. The handshake is a strict
  state machine. A receiver that observes an out-of-order or
  missing message during the handshake MUST abort the
  handshake.

Bidirectional messaging:
: Both parties MUST be able to send messages after the
  connection is established.

Message framing:
: The transport MUST provide message framing to delimit
  individual SEMP messages. SEMP sends discrete JSON
  objects. If the underlying transport provides a byte
  stream without framing (for example, raw TCP), the
  transport binding MUST define a framing scheme. Framing
  requirements for custom transport bindings appear in
  [Custom Transport Binding Requirements](#custom-transport-binding-requirements).

Binary-safe variable-length payloads:
: The transport MUST support messages up to the server's
  advertised `max_envelope_size`. SEMP payloads contain
  base64-encoded binary data for keys, nonces, signatures,
  and encrypted content. The transport MUST NOT alter,
  truncate, or re-encode payload content. Transports with
  fixed or low message size limits MAY be used if they
  define a chunking mechanism in their transport binding;
  the chunking mechanism MUST reassemble the complete SEMP
  message before delivering it to the SEMP layer.

Connection lifecycle signaling:
: The transport MUST provide clean connection open and close
  semantics, allowing both parties to distinguish an
  intentional disconnect from a network failure.

## Transport Profiles

SEMP traffic falls into two communication patterns:

Synchronous profile:
: Handshake (four-message exchange with optional challenge),
  discovery, key exchange, and rekeying. Synchronous profile
  operations require low latency and strict message ordering.

Asynchronous profile:
: Envelope submission, envelope relay, and delivery event
  notifications. Asynchronous operations are tolerant of
  higher latency.

A transport that satisfies the synchronous profile necessarily
satisfies the asynchronous profile. Implementations using a
transport that satisfies only the asynchronous profile MUST
use a separate transport for synchronous operations.

## Core Transport Bindings

SEMP defines bindings for three transports. Implementations
MUST support HTTP/2 as the baseline transport for
interoperability. Implementations SHOULD additionally support
WebSocket and QUIC.

### WebSocket

| Property | Value |
|---|---|
| Transport identifier | `ws` |
| Endpoint URL scheme | `wss://` |
| Default port | 443 |
| TLS requirement | Required (WSS only; WS is prohibited) |
| Framing | Native WebSocket frames |
| Specification | [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455) |

The client initiates a WebSocket connection to the endpoint URL
advertised in the server's discovery response or well-known URI
configuration. The HTTP Upgrade request MUST include the
subprotocol identifier `semp.v1`. The server MUST confirm the
subprotocol in its Upgrade response.

Each SEMP message is sent as a single WebSocket text frame
containing the UTF-8-encoded JSON message. Binary frames MUST
NOT be used for SEMP messages. Implementations MUST NOT split a
single SEMP message across multiple WebSocket messages.

WebSocket close frames provide clean shutdown signaling. When a
server rejects a handshake or an envelope, it MUST send the
rejection response before initiating a WebSocket close. A close
frame without a preceding rejection message MUST be treated as
a network-level failure.

Implementations SHOULD use WebSocket ping/pong frames for
keepalive during long-lived sessions. The recommended ping
interval is 30 seconds.

### HTTP/2

| Property | Value |
|---|---|
| Transport identifier | `h2` |
| Endpoint URL scheme | `https://` |
| Default port | 443 |
| TLS requirement | Required (HTTPS only) |
| Framing | HTTP/2 stream framing |
| Specification | [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113) |

The HTTP/2 binding uses a single base URL with path-based
routing for different protocol operations. HTTP method
selection follows REST conventions: read-only lookups use
`GET`, state-changing operations use `POST`, and long-lived
server-initiated streams use `GET` for Server-Sent Events.

| Operation | Method | Path |
|---|---|---|
| Discovery lookup | `GET` | `/v1/discovery/{address}` |
| Key request | `GET` | `/v1/keys/{address}` |
| Handshake | `POST` | `/v1/handshake` |
| Envelope submit | `POST` | `/v1/envelope` |
| Session stream | `GET` | `/v1/session/{id}` |

`{address}` in the GET paths is the percent-encoded SEMP
address (user@domain) or domain. Query parameters MAY be
used to narrow the request (for example, `?key_types=identity,device`
on the key request). A lookup that requires a signed request
body MAY be submitted as a `POST` to the same path; servers
MUST accept both methods for the lookup operations.

Request and response bodies for `POST` operations are
`application/json; charset=utf-8`. Discovery, key exchange,
and envelope submission use standard HTTP/2 request-response
semantics.

HTTP status codes indicate transport-level outcomes only. A 200
response with a SEMP rejection in the body is normal operation.
The transport-status codes, and their non-normative correspondence
to SEMP reason codes, are defined in the Transport-Layer Status
Codes section of [Delivery](delivery.md).

The four-message handshake maps to sequential HTTP/2 POST
requests. The server includes a `Semp-Session-Id` header in
the response to message 1. Subsequent handshake requests for
the same session MUST include this header so the server can
correlate them.

For established sessions requiring server-initiated messages
(delivery event notifications, rekeying), the client opens a
long-lived POST to `/v1/session/{id}`. The server sends SEMP
messages as Server-Sent Events within the response body.

### QUIC

| Property | Value |
|---|---|
| Transport identifier | `quic` |
| Endpoint URL scheme | `https://` |
| Default port | 443 |
| TLS requirement | Built-in (TLS 1.3 is integral to QUIC) |
| Framing | QUIC stream framing |
| Specification | [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) with TLS profile [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) |

The QUIC binding follows the same endpoint structure and
message encoding as the HTTP/2 binding, carried over HTTP/3.
All path routing, status code semantics, and session stream
mechanisms are identical.

QUIC provides benefits beyond HTTP/2: no head-of-line blocking
across streams, connection migration across network changes,
reduced connection establishment latency, and built-in TLS 1.3.

QUIC operates over UDP, which may be blocked by some network
middleboxes. Implementations MUST fall back to HTTP/2 or
WebSocket when QUIC is unreachable.

When `quic` is advertised in the `c` capability list of a
domain's discovery TXT record, the QUIC endpoint host and
port are the same as the `_semp._tcp` SRV target (or the
host:port resolved from the well-known URI). The client
SHOULD attempt UDP on that host:port for QUIC. Operators
that require a distinct UDP target MAY additionally publish
an `_semp._udp` SRV record. When both `_semp._tcp` and
`_semp._udp` SRV records are published, clients selecting
QUIC MUST prefer the `_semp._udp` target.

## Optional Transport Bindings

Beyond the three core transports, SEMP MAY operate over
additional transports where the minimum requirements above
are satisfied. Optional bindings are non-core: conformant
servers and clients are not required to support them, and
interoperability between independent operators MUST rely on
the core bindings.

### gRPC

| Property | Value |
|---|---|
| Transport identifier | `grpc` |
| Default port | 443 |
| Profile | Synchronous and asynchronous |
| TLS requirement | Required |
| Specification | gRPC over HTTP/2 |

gRPC is an OPTIONAL transport binding for operators with
existing gRPC infrastructure. A gRPC binding for SEMP MUST
wrap each SEMP message as an `application/json` payload, MUST
satisfy all custom-transport binding requirements
([Custom Transport Binding Requirements](#custom-transport-binding-requirements)), and MUST
advertise at least one core transport (HTTP/2, WebSocket, or
QUIC) alongside `grpc` in the discovery configuration so
that peers without gRPC support can still federate.
Operators MUST NOT assume federation peers support gRPC.

The specific gRPC service definition and RPC method surface
are implementation-defined. What is normative is that the
wrapped SEMP JSON messages, their ordering semantics, and
their session-lifecycle obligations are identical to those
carried over the core transports. Implementations MAY define
a protobuf-native encoding of SEMP messages as a future
optimization, but the JSON encoding MUST be supported as the
interoperability baseline.

<a id="custom-transport-binding-requirements"></a>

## Custom Transport Binding Requirements
Operators MAY define transport bindings beyond those
specified in the core and optional sections above. A custom
transport binding MUST satisfy all of the following.

### Minimum Requirements

The transport MUST satisfy all seven requirements in
[Minimum Transport Requirements](#minimum-transport-requirements). If any requirement is
not natively provided by the transport, the binding MUST
specify how it is achieved.

### Transport Identifier

The binding MUST define a unique transport identifier string
for use in discovery records and handshake `init` messages.
Identifiers for custom bindings MUST use the SEMP extension
namespacing convention (for example,
`vendor.example.com/transport-name`). The identifiers `ws`,
`h2`, `quic`, and `grpc` are reserved for the core and
optional bindings.

### Framing

If the transport does not provide native message framing,
the binding MUST define a framing scheme. The RECOMMENDED
framing scheme for stream-oriented transports is
length-prefix framing:

~~~
[4 bytes: message length, network byte order][message bytes]
~~~

The message length is the byte length of the UTF-8-encoded
JSON message. The maximum message length is governed by the
server's advertised `max_envelope_size`.

### Profile Declaration

The binding MUST declare which transport profiles
(synchronous, asynchronous, or both) the transport
satisfies. If only the asynchronous profile is satisfied,
the binding MUST state the companion channel requirement.

### Message Encoding

All SEMP messages MUST be encoded as UTF-8 JSON regardless
of transport. A custom binding MAY define an additional
binary encoding (such as Protocol Buffers or CBOR) as an
optimization, but the JSON encoding MUST be supported as the
interoperability baseline.

### Endpoint and Discovery Integration

The binding MUST define how the transport is advertised in
discovery (DNS TXT `c` parameter and well-known URI
`endpoints` object) and how endpoint URLs are structured.

### Connection Lifecycle Mapping

The binding MUST document how transport-level lifecycle
events map to SEMP session events. Specifically:

* How a clean disconnect is signaled.
* How a network failure is detected.
* How transport-level timeouts interact with the SEMP
  handshake timeout.

## Transport Negotiation and Fallback

Servers advertise supported transports via DNS TXT records
(under the `c` parameter, listing transport identifiers in
preference order) and via the `endpoints` object in the
well-known URI configuration document. The connecting party
selects a transport using the following priority:

1. The connecting party's own preference, constrained to
   transports the remote server advertises.
2. If multiple transports are mutually supported, the
   connecting party SHOULD prefer the remote server's
   preference order.
3. If no mutually supported transport exists, the connection
   cannot proceed.

When the selected transport is unreachable, the connecting
party SHOULD attempt alternative transports before treating the
connection as failed. The recommended fallback order is:
QUIC, then WebSocket, then HTTP/2. Because HTTP/2 is the
mandatory baseline transport, a connecting party MAY always
attempt HTTP/2 even when the peer's discovery records do not
explicitly advertise it.

Fallback attempts MUST be sequential rather than concurrent.
Concurrent connection attempts to the same server on multiple
transports waste resources on both sides and may trigger rate
limiting.

Transport fallback MUST be transparent to the SEMP layer. A
handshake initiated over WebSocket and a handshake initiated
over HTTP/2 produce identical SEMP sessions. Only the
`transport` field in the handshake init records the choice.

## Tor Routing

SEMP operates over Tor without protocol modification. When
the recipient domain is a `.onion` address, DNS discovery is
inapplicable and implementations MUST skip DNS lookup and
fetch the well-known URI directly over Tor.

HTTP/2 is the RECOMMENDED transport for `.onion` endpoints
because of Tor's connection-reliability characteristics.
Persistent connections such as WebSocket are prone to
circuit-rotation disruptions and are not recommended for
Tor-routed traffic. The handshake timeout accommodates Tor's
higher latency without adjustment.

Tor-specific discovery, address form, and operator contracts
for Tor-only versus dual-reachable deployments are defined in
[Discovery](discovery.md). Tor-routed key fetching for
`.onion` recipients is also defined there.

## TLS and Transport Independence

The SEMP session layer and the transport layer are
independent. A TLS session provides transport encryption. A
SEMP session provides application-layer forward secrecy,
identity binding, and session key material. The two layers
address distinct concerns and MUST be treated independently
by implementations.

TLS session resumption MUST NOT resume a SEMP session. Each
SEMP session requires a fresh handshake regardless of TLS
state.

If the transport connection drops and is re-established, the
SEMP session does not automatically resume. The implementation
MUST check whether the SEMP session's `expires_at` has passed.
If the session is still valid, no re-handshake is required. If
the session has expired, the implementation MUST initiate a
fresh handshake.

A single transport connection MAY carry multiple SEMP sessions
when the transport supports multiplexing (HTTP/2 streams, QUIC
streams). Each session is identified by `session_id`, not by
transport-level identifiers.

# Security Considerations

For the consolidated adversary model under which this section
is evaluated, see [Architecture](architecture.md).

## Identity Confidentiality

Client identity is never transmitted in plaintext during the
client handshake. The init message carries no identifying
information. The identity proof is encrypted under the session
secret established by ephemeral key exchange. Passive observers
cannot determine who initiated a session.

The residual leak is that a connection to a specific server was
made. This is documented in [Architecture](architecture.md) as
an irreducible minimum for federated messaging.

## Replay Prevention

Each handshake uses a fresh client nonce and server nonce. The
confirmation hash in message 3 binds the identity proof to the
specific exchange that preceded it. A captured message 3 from
one session MUST NOT be accepted for replay in a different
session.

The nonce MUST be cryptographically random, minimum 32 bytes.
Implementations MUST reject handshakes with nonces they have
seen within the session TTL window.

Session IDs MUST be retained in an expiry log after the session
ends, for a duration equal to the maximum allowed
`postmark.expires` window. A receiving server that sees a
`postmark.session_id` referencing a retired session MUST reject
the envelope with `reason_code: "handshake_invalid"`.

## Downgrade Prevention

Capability negotiation is covered by the confirmation hash. A
man-in-the-middle that modifies the capabilities in message 1
to downgrade the negotiated algorithm will cause the
confirmation hash in message 3 to fail verification, aborting
the handshake.

## Algorithm Selection

Servers MUST prefer the strongest mutually supported algorithm.
If a client offers both `pq-kyber768-x25519` and
`x25519-chacha20-poly1305`, the server MUST select the
post-quantum hybrid unless it cannot support it. Selecting a
weaker algorithm when a stronger one is available is a policy
violation.

## Memory Safety

Session key material exists only in memory. Implementations
MUST use memory-safe data structures that cannot be read by
other processes on the same host, are zeroed before
deallocation, are not swapped to disk, and are not included in
crash dumps or core files.

Where the platform supports it, implementations MUST call
`mlock` (POSIX) or `VirtualLock` (Windows) on memory regions
holding session keys immediately after allocation. If the call
fails (due to privilege restrictions or `ulimit` constraints),
the implementation MUST log a startup warning identifying
which key types are unprotected and MUST NOT silently continue
as if the lock succeeded.

Crash dump exclusion MUST be enforced at the process level
where the OS provides a mechanism (for example,
`prctl(PR_SET_DUMPABLE, 0)` on Linux,
`SetProcessMitigationPolicy` on Windows). If no such mechanism
is available, the implementation MUST document the limitation
in its operator-facing documentation alongside the memory
locking limitation.

On platforms without memory locking primitives, the
implementation MUST surface the following in its documentation
and, where applicable, in its operator-facing configuration
output:

* Which key types are held in unlocked memory.
* The consequence: a host-level attacker with access to swap
  or a crash dump may recover session keys from terminated
  sessions.
* The mitigations available to operators: encrypted swap,
  disabled core dumps, and reduced session TTLs to narrow the
  exposure window.

## Key Isolation

Session keys MUST NOT be derived from, or used to derive,
long-term key material. Keys are derived from the ephemeral
exchange, used for the duration of the session, and erased.
`K_env_mac` MUST NOT be used as input to any key derivation
beyond its defined MAC purpose.

## Compromise of Long-Term Keys

Compromise of a server's long-term domain key after the fact
allows an attacker to impersonate the domain in future
sessions, forge `seal.signature` on new envelopes, spoof new
handshakes, and read `K_brief` from future envelopes. It does
not allow the attacker to decrypt envelopes from past
sessions, recover past session keys, or verify past
`seal.session_mac` values. Past session keys were derived
entirely from ephemeral material that no longer exists.

## Side Channels

Implementations SHOULD use constant-time operations for all
key comparisons and MAC verifications. Timing side channels
on `K_env_mac` verification could allow an attacker to probe
for valid session IDs. Standard HMAC implementations in
well-audited cryptographic libraries are generally
constant-time; custom implementations require explicit
review.

## Handshake Timeout

Implementations MUST enforce a timeout on handshake
completion. If a handshake is not completed within the
timeout, the connection MUST be closed. A timeout of 30
seconds is RECOMMENDED. Incomplete handshakes MUST NOT
consume session resources beyond what is needed to enforce
the timeout.

## Transport as Defense in Depth

TLS at the transport layer and SEMP's application-layer
encryption provide defense in depth. An attacker who
compromises the TLS layer gains access to SEMP handshake
ciphertext and postmark metadata, but not to brief or
enclosure content, which are encrypted under SEMP session
keys.

Operators MUST NOT treat transport-layer encryption as
sufficient and skip SEMP application-layer encryption. The
two layers protect against different threat models: TLS
protects against network-level eavesdropping, SEMP protects
against compromised infrastructure.

# Privacy Considerations

The client-to-server handshake exposes the following to a
passive observer: that a connection was made to a SEMP server
at a specific domain, the protocol version and transport type,
and the set of extensions the client supports. It does not
expose who made the connection, who they intend to send to, or
any message content.

A distinctive capability set in message 1 could fingerprint a
specific client implementation. Clients SHOULD advertise all
capabilities they support rather than a minimal subset, to
reduce fingerprinting surface.

Running SEMP over standard HTTPS on port 443 makes SEMP
traffic resistant to protocol-specific blocking. An observer
sees HTTPS connections to a web server, indistinguishable from
any other HTTPS traffic without deep packet inspection.

<a id="test-vectors"></a>

# Test Vectors
The cross-language test vector corpus at `vectors/v1.0.0/` of
the SEMP specification repository pins the byte-level behavior
of the constructions in this document. The following files
exercise the handshake, session, and transport layers:

| File | What it pins |
|---|---|
| `hkdf.json` | HKDF-SHA-512 derivation of the five session keys from the shared secret, salt, and per-key info labels. |
| `session-mac.json` | HMAC-SHA-256 envelope session MAC over canonical envelope bytes. |
| `confirmation-hash.json` | SHA-256 over canonical(init) ‖ canonical(response). |
| `handshake-messages.json` | Canonical bytes and `SEMP-HANDSHAKE:` Ed25519 signature path for the four-step handshake plus a rejection. |
| `handshake-messages-pq.json` | PQ-suite (`pq-kyber768-x25519`) handshake variants with hybrid ephemerals. |
| `session-resumption.json` | Resumption exchange and key derivation mixing `K_resumption` with a fresh ephemeral. |
| `session-lifecycle.json` | Session state transitions, concurrency limits, rekey limits. |
| `clock-tolerance.json` | Future-dated and `expires_at` boundary cases at 0, 5, and 15 minutes. |
| `pow.json` | Proof-of-work challenge solution verification. |
| `first-contact-token.json` | First-contact tokens binding a solved PoW to a `postmark.id`. |

# IANA Considerations

This document has no IANA actions. Reason codes are registered
in [Delivery](delivery.md). Algorithm suite identifiers
are namespaced under SEMP and do not require external
registration. Transport identifiers (`ws`, `h2`, `quic`) are
internal to this specification.

# Acknowledgments

The author thanks the contributors to the SEMP specification
for review, design discussion, and prior-art analysis.

