## Abstract

This document specifies the Sealed Envelope Messaging Protocol
(SEMP) discovery procedure, the well-known URI configuration
document, the publication and verification of domain and user
public keys, the key request and response messages, key rotation
and revocation, and the scoped device certificate mechanism that
authorizes delegated devices to act within a restricted permission
scope. Discovery is performed by the sender's home server rather
than by the client. Domain keys are published via DANE
[RFC 6698](https://www.rfc-editor.org/rfc/rfc6698) and a configuration endpoint; user keys are published
through the configuration endpoint of the user's home server.

# Introduction

Before delivering an envelope to a recipient domain, the sender's
home server must determine whether the domain supports SEMP, which
server handles SEMP for that domain, and what capabilities the
server offers. SEMP answers these questions through DNS-based
discovery as the primary method and a well-known URI as fallback.
Once the server is located, public keys are fetched: domain keys
for routing-layer signature verification, and user keys for
recipient envelope encryption.

This document specifies the discovery flow, the configuration
document format, the publication and verification of all SEMP
public keys, the key request and response protocol, key rotation
and revocation procedures, and the scoped device certificate
mechanism that authorizes delegated devices.

The architectural role of discovery and keys is defined in
[Architecture](architecture.md). The envelope format that
references these keys is in [Envelope](envelope.md). The
handshake that consumes the keys for federation establishment is
in [Handshake](handshake.md).

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

This document additionally uses terminology from [RFC 4949](https://www.rfc-editor.org/rfc/rfc4949) for
general security-protocol terms.

# Discovery Responsibility and Privacy

## Discovery Is a Server Responsibility

Per the connection model defined in [Handshake](handshake.md),
clients connect only to their own home server. Cross-domain
delivery is server-to-server. Discovery is therefore always
performed by the sender's server on behalf of the sending user. A
client never performs cross-domain discovery directly.

## Privacy Constraint

Discovery requests MUST be anonymous by default. A lookup request
MUST NOT identify the requester or the sender whose message
prompted the lookup. The lookup reveals only that someone on the
querying server intends to send to someone on the target domain,
but not who, and not about what.

Authenticated discovery is available as an optional extension.
Servers MAY rate-limit anonymous discovery requests. See
[Authenticated Discovery](#authenticated-discovery).

# DNS-Based Discovery

DNS is the primary discovery method. It requires no active
connection to the target domain and benefits from DNS caching
infrastructure [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035).

## SRV Records

SEMP servers are advertised via DNS SRV records [RFC 2782](https://www.rfc-editor.org/rfc/rfc2782)
under `_semp._tcp.<domain>`:

~~~
_semp._tcp.example.com.  3600  IN  SRV  10  10  443  semp.example.com.
~~~

Standard SRV semantics apply: lower priority values are
preferred, weight controls load distribution among servers of
equal priority.

The `_semp._tcp` SRV target also serves as the host and port
for QUIC (UDP-based) transport when `quic` is advertised in
the TXT capability list ([TXT Capability Record](#txt-capability-record)). Clients
selecting QUIC SHOULD attempt UDP on the SRV target's
host:port. Operators that require a distinct UDP target MAY
additionally publish an `_semp._udp` SRV record:

~~~
_semp._udp.example.com.  3600  IN  SRV  10  10  443  semp.example.com.
~~~

When both `_semp._tcp` and `_semp._udp` records are published,
clients selecting QUIC MUST prefer the `_semp._udp` target.

<a id="txt-capability-record"></a>

## TXT Capability Record
A companion TXT record advertises the server's SEMP capabilities
(shown wrapped for readability; the on-the-wire record is a single
TXT string):

~~~
_semp._tcp.example.com.  3600  IN  TXT
    "v=semp1;"
    "s=pq-kyber768-x25519,x25519-chacha20-poly1305;"
    "c=h2,ws,quic;"
    "mes=26214400"
~~~

`v`:
: SEMP protocol version. MUST be present. Current value: `semp1`.

`s`:
: Supported cryptographic suites, comma-separated, in preference order. `x25519-chacha20-poly1305` (baseline) MUST be present. `pq-kyber768-x25519` (post-quantum hybrid) is RECOMMENDED.

`c`:
: Supported transports, comma-separated. Values: `h2`, `ws`, `quic`. `h2` MUST be present.

`mes`:
: Maximum accepted envelope size in bytes. Senders MUST NOT transmit envelopes exceeding this value.

Implementations MUST treat unknown parameters as ignored rather
than as errors.

## Multiple Servers Per Domain

A domain may operate multiple SEMP servers for load balancing,
geographic distribution, or high availability via multiple SRV
records. Servers at the same priority share traffic according to
their weights. Higher-priority-value servers receive traffic only
if all lower-priority-value servers are unreachable.

## User Partitioning

For large domains distributing users across multiple servers,
SEMP supports user partitioning via an additional TXT record:

~~~
_semp-partition.example.com.  3600  IN  TXT
    "v=semp1;"
    "strategy=hash;"
    "servers=8;"
    "algorithm=sha256"
~~~

`hash`:
: `hash(username) mod N` determines the server index. Leaks Existence: No.

`alpha`:
: Alphabetical ranges mapped to specific servers. Leaks Existence: No.

`lookup`:
: A partition server must be queried for the mapping. Leaks Existence: Yes, unless authenticated..

The `hash` strategy is RECOMMENDED. It is deterministically
computable by any party from the address alone and leaks no
information beyond what the address itself already carries.

The `lookup` strategy requires a partition server to resolve each
address to a specific delivery server. A server that answers
lookup queries reveals, by construction, whether a given address
exists on the domain. Operators SHOULD NOT use the `lookup`
strategy. Operators that MUST use it MUST require authenticated
discovery (see [Authenticated Discovery](#authenticated-discovery)) for every lookup
query and MUST return a generic negative response for addresses
that do not exist, indistinguishable in structure, size, and
timing from responses for existing addresses.

# Tor-Reachable Deployments

DNS-based discovery is inapplicable to domains that terminate in
the `.onion` pseudo-TLD; the Tor network has no DNS SRV
infrastructure and clearnet DNS MUST NOT be consulted for an
onion name.

## Address Form

A `.onion` SEMP address has the form `user@<onion-name>.onion`,
where `<onion-name>` is a 56-character version-3 onion service
identifier. Version-2 onion addresses (16 characters) MUST NOT be
used; they are cryptographically deprecated. A server receiving
an envelope whose `postmark.to_domain` is a 16-character onion
label MUST reject it.

## Discovery Flow for Onion Addresses

For a destination domain ending in `.onion`, a sending server
MUST:

1. Skip DNS lookups entirely. Any DNS query for a `.onion` name
   is a protocol violation and MUST NOT be emitted.
2. Open a Tor circuit to `<onion-name>.onion:443`. Standard
   three-hop circuits are required; single-hop circuits MUST NOT
   be used.
3. Fetch
   `https://<onion-name>.onion/.well-known/semp/configuration`
   over the Tor circuit using HTTP/2.
4. Verify the configuration document's domain signature against
   the domain key published in the document itself. DANE
   cross-checks are inapplicable; onion services have no
   DNS-based key attestation.
5. Proceed with the federation handshake over the same or a
   fresh Tor circuit.

A sending server that cannot reach Tor (no local Tor daemon,
blocked Tor egress, offline node) MUST NOT fall back to clearnet
discovery for a `.onion` recipient. It MUST surface the delivery
as `server_unavailable` to the sending user.

## Operator Contract for Tor-Only Deployments

An operator that hosts a SEMP domain exclusively over Tor MUST
NOT publish DNS SRV, TXT, or well-known URI records under any
clearnet name that references this domain's backend, MUST NOT
run the domain's backend under a clearnet DNS name that resolves
to a clearnet-reachable IP, MUST NOT publish domain or user keys
at any clearnet endpoint for this domain, and MUST configure the
onion service with the standard three-hop topology.

A Tor-only deployment that violates any of the above forfeits
the anonymity properties documented in
[Architecture](architecture.md).

# Well-Known URI Discovery

When DNS records are absent or unreachable, the sender's server
falls back to fetching the well-known configuration URI [RFC 8615](https://www.rfc-editor.org/rfc/rfc8615).
The bootstrapping path is fixed:

~~~
https://<hostname>/.well-known/semp/configuration
~~~

The hostname is determined by DNS SRV resolution or, when no SRV
records exist, the email domain itself. This path MUST be served
over HTTPS. Servers MUST NOT serve it over plain HTTP. The HTTPS
certificate chain is the trust anchor for the response contents.

## Configuration Document

The response is a JSON configuration document:

~~~ json
{
    "type": "SEMP_CONFIGURATION",
    "version": "1.0.0",
    "domain": "example.com",
    "revision": 17,
    "ttl_seconds": 3600,
    "endpoints": {
        "client": {
            "h2": "https://semp.example.com/v1/h2",
            "ws": "wss://semp.example.com/v1/ws"
        },
        "federation": {
            "h2": "https://semp.example.com/v1/h2/federate",
            "ws": "wss://semp.example.com/v1/federate"
        },
        "register": "https://semp.example.com/v1/register",
        "device_register":
            "https://semp.example.com/v1/device/register",
        "blocklist": "https://semp.example.com/v1/blocklist",
        "keys": "https://semp.example.com/v1/keys/",
        "domain_keys":
            "https://semp.example.com/v1/domain-keys",
        "reputation": "https://semp.example.com/v1/reputation/"
    },
    "suites": [
        "pq-kyber768-x25519",
        "x25519-chacha20-poly1305"
    ],
    "limits": {
        "max_envelope_size": 26214400
    },
    "extensions": []
}
~~~

`type` (string, required):
: MUST be `"SEMP_CONFIGURATION"`.

`version` (string, required):
: SEMP protocol version (semver).

`domain` (string, required):
: The email domain this server operates for.

`revision` (integer, required):
: Monotonically non-decreasing revision number.

`ttl_seconds` (integer, required):
: Operator-advised cache lifetime in seconds.

`endpoints` (object, required):
: All discoverable endpoints.

`suites` (array, required):
: Cryptographic suite identifiers in preference order.

`limits` (object, required):
: Operational limits.

`extensions` (array, optional):
: Supported extensions per [Extensions](extensions.md).

`reciprocity` (object, optional):
: Trust-gossip reciprocity policy disclosure. Required when the server enforces reciprocity. See [Reciprocity Policy](#reciprocity-policy).

Implementations MUST ignore unknown fields rather than failing.

## Endpoints

The `endpoints` object contains all URLs a client or federation
peer needs. Transport endpoints (which carry SEMP sessions) are
grouped by role; API endpoints (which are plain HTTPS) are flat.

`client` (required):
: Transport endpoints for client sessions. Map of transport identifier (`h2`, `ws`, `quic`) to URL. `h2` MUST be present.

`federation` (required):
: Transport endpoints for federation sessions. Same structure as `client`. `h2` MUST be present.

`register` (required):
: URL for client key registration.

`device_register` (optional):
: URL for delegated device registration.

`blocklist` (optional):
: URL for block list management.

`keys` (required):
: Base URL for user key publication.

`domain_keys` (required):
: URL for domain signing and encryption key publication.

`reputation` (optional):
: Base URL for trust gossip observations.

`verify` (optional):
: Base URL for federation domain-ownership verification tokens.

`backup` (optional):
: Base URL for server-assisted account recovery backups.

`migration` (optional):
: Base URL for provider migration records.

`transparency_log` (optional):
: Base URL for the domain's key transparency log.

All URL values are implementation-chosen. The protocol does not
mandate URL path structure.

<a id="reciprocity-policy"></a>

## Reciprocity Policy
A server that fetches trust gossip from peers SHOULD also publish
its own observations under its `reputation` endpoint per
[Delivery](delivery.md). A peer MAY refuse to serve trust
gossip to a server that does not publish. A peer that enforces
reciprocity MUST disclose its policy in the `reciprocity` object
of its configuration document so that prospective consumers can
determine eligibility before fetching.

~~~ json
"reciprocity": {
    "mode": "strict",
    "minimum_publish_volume": 100,
    "evaluation_window_days": 30
}
~~~

`mode` (string, required):
: `"strict"`, `"lenient"`, or `"none"`. See mode semantics below.

`minimum_publish_volume` (integer, optional):
: Publication count a peer MUST reach in the evaluation window to satisfy `strict`. Absence means any non-empty publication satisfies.

`evaluation_window_days` (integer, optional):
: Sliding window in days for `minimum_publish_volume`. Absence means the operator default (RECOMMENDED 30 days).

Mode semantics:

`strict`:
: Peers MUST publish observations to receive gossip from this
  server.

`lenient`:
: Non-publishing peers receive de-weighted observations or
  partial access at this server's discretion.

`none`:
: This server applies no reciprocity policy.

A consuming server SHOULD read the disclosed policy before
issuing trust gossip fetches against a peer that has set `mode`
to `"strict"`. The exact field shape MAY evolve in future
revisions, and consumers MUST ignore unknown fields within the
`reciprocity` object.

Absence of the `reciprocity` field indicates the server has not
declared a reciprocity policy. A consumer SHOULD treat absence as
equivalent to `mode: "none"`.

## Configuration Is the Sole Endpoint Registry

The configuration document is the single source of truth for
every endpoint exposed by a SEMP server. The path
`/.well-known/semp/configuration` is the only fixed URL in the
protocol.

* A SEMP server MUST NOT expose a protocol endpoint that is not
  advertised in its configuration document.
* A SEMP client or federation peer MUST NOT probe well-known or
  guessed paths for functionality that is not advertised. The
  absence of a field in `endpoints` is definitive: the
  capability is not offered.
* A SEMP server MAY place any advertised endpoint at any URL it
  chooses, including under `/.well-known/`, on a different
  hostname, on a different port, or behind a reverse proxy.

<a id="configuration-versioning"></a>

## Configuration Versioning
The configuration document's `revision` field is a monotonically
non-decreasing integer. Operators MUST increment `revision` on
any byte-level change to the configuration document. Operators
MUST NOT decrement `revision`, MUST NOT reuse a previously
published `revision` value for a different document, and MUST
NOT reset `revision` when rotating other state.

A peer holding cached revision N that subsequently fetches
revision M where M < N MUST treat the fetch as suspicious. The
peer MUST NOT replace its cached copy on such a fetch. The peer
SHOULD log the anomaly and MAY retry via a different transport.

The `ttl_seconds` field is the operator's advised cache lifetime
for the document. Cached peers MUST re-fetch the configuration
when the cache age exceeds `ttl_seconds`. Peers MAY re-fetch
earlier. `ttl_seconds` MUST be at least 60 and MAY be at most
604800 (one week). The RECOMMENDED default is 3600.

`ttl_seconds` is independent of HTTP `Cache-Control` headers. A
conformant peer MUST respect `ttl_seconds` regardless of HTTP
cache hints.

A peer caching the configuration of a domain MUST re-fetch when
any of the following occurs, regardless of remaining TTL:

* the cache age exceeds `ttl_seconds`;
* the peer receives a `SEMP_CONFIGURATION_UPDATE` message on an
  active federation session for the domain (see
  [SEMP_CONFIGURATION_UPDATE Message](#configuration-update-message));
* the peer receives a federation handshake init whose
  `peer_configuration_revision` differs from the cached
  revision;
* an operation against the domain fails with a capability- or
  endpoint-mismatch error attributable to stale configuration.

If a re-fetch fails, the peer MUST NOT use the cached
configuration for new operations beyond the grace window
defined by `ttl_seconds`. Operations in flight at the time of
failure MAY complete under the cached configuration.

<a id="configuration-update-message"></a>

## SEMP_CONFIGURATION_UPDATE Message
A SEMP server MAY notify its active federation peers when its
configuration has changed:

~~~ json
{
    "type": "SEMP_CONFIGURATION_UPDATE",
    "version": "1.0.0",
    "domain": "example.com",
    "revision": 18,
    "timestamp": "2026-04-19T12:00:00Z",
    "signature": {
        "algorithm": "ed25519",
        "key_id": "domain-signing-key-fingerprint",
        "value": "base64-signature"
    }
}
~~~

The signature is computed over the canonical bytes of the
message with `signature.value` set to `""`, prefixed with
`SEMP-CONFIGURATION-UPDATE:` per the signature domain
separation table in [Envelope](envelope.md).

Peers MUST verify the signature against the cached domain key.
If verification fails, the peer MUST discard the message. On
receipt of a verified message whose `revision` is strictly
greater than the peer's cached revision, the peer MUST re-fetch
the configuration document before using any cached endpoint or
capability. A message whose `revision` is less than or equal to
the cached revision MUST be discarded silently.

The notification is a hint, not a guarantee. Peers MUST NOT
depend on receiving it.

# Domain Key Publication

## DANE TLSA Records (Primary)

Domain keys are published via DANE TLSA records [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698),
making them verifiable through the DNS infrastructure
independently of any SEMP-specific lookup:

~~~
_semp-key._tcp.example.com.  IN  TLSA
    3 0 1  <hash-of-domain-signing-key>
~~~

The TLSA record parameters are: `3` (certificate usage:
domain-issued), `0` (selector: full key), `1` (matching type:
SHA-256 hash).

DNSSEC is RECOMMENDED for domains publishing SEMP key records.
Without DNSSEC, the DNS record is unauthenticated and
susceptible to spoofing.

## Configuration Endpoint (Fallback)

When DNS/DANE is unavailable or unverifiable, the domain key is
discoverable through the `domain_keys` endpoint advertised in
the server's configuration document:

~~~ json
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
~~~

Each key object contains `algorithm`, `public_key`
(base64-encoded), and `key_id` (SHA-256 fingerprint of the raw
public key bytes, hex-encoded).

The HTTPS certificate chain serves as the trust anchor: if the
TLS certificate is valid for the hostname, the domain keys it
publishes are trusted. Relying parties SHOULD cross-check
against DNS/DANE records where DNSSEC is available.

# User Key Publication

User public keys are published at the user's home server through
the `keys` endpoint advertised in the server's configuration
document. The full fetch URL for a given user is the base URL
with the user's address appended:

~~~
GET <endpoints.keys><user@example.com>
~~~

The endpoint MUST be served over HTTPS.

## Key Response Format

~~~ json
{
    "type": "SEMP_KEYS",
    "step": "response",
    "version": "1.0.0",
    "id": "echoed-request-id",
    "timestamp": "2026-06-10T19:56:34Z",
    "keys": [
        {
            "address": "user@example.com",
            "key_type": "identity",
            "algorithm": "ed25519",
            "public_key": "base64-encoded-public-key",
            "key_id": "key-fingerprint",
            "created": "2026-01-15T08:30:00Z",
            "expires": "2027-01-15T08:30:00Z",
            "signatures": [
                {
                    "signer": "example.com",
                    "key_id": "domain-key-fingerprint",
                    "value": "base64-domain-signature",
                    "timestamp": "2026-01-15T08:30:05Z"
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
~~~

The response is signed by the serving domain's key. Recipients
MUST verify this signature using the domain's published domain
key before trusting the user keys.

Domains supporting key transparency augment each key in the
response with an inclusion proof and a current signed tree head,
enabling recipients to verify that the returned key is present
in the domain's public key log. See [Recovery](recovery.md).

## Key Record Fields

`address` (string, required):
: The address this key belongs to.

`key_type` (string, required):
: One of: `identity`, `encryption`, `device`, `domain`.

`algorithm` (string, required):
: Cryptographic algorithm identifier.

`public_key` (string, required):
: Base64-encoded public key material.

`key_id` (string, required):
: Key fingerprint. SHA-256 of the public key bytes, hex-encoded.

`created` (string, required):
: ISO 8601 UTC creation timestamp.

`expires` (string, required):
: ISO 8601 UTC expiry timestamp.

`signatures` (array, optional):
: Web-of-trust signatures.

<a id="first-contact-policy"></a>

## First-Contact Policy
The `SEMP_KEYS` response MAY include a `first_contact_policy`
block per key record subject. The policy advises senders that
have no prior correspondence with the subject what additional
friction the recipient's home server will apply. Publication of
the policy is opt-in; absent publication, senders MUST assume
`mode: "open"`.

~~~ json
{
    "first_contact_policy": {
        "mode": "challenge",
        "challenge_type": "proof_of_work",
        "parameters": {
            "algorithm": "sha256",
            "difficulty": 22
        }
    }
}
~~~

| Mode | Behavior |
|---|---|
| `open` | No first-contact friction. All envelopes proceed through the standard delivery pipeline. |
| `challenge` | First-contact envelopes from unknown sender domains MUST satisfy the challenge identified by `challenge_type`. Satisfaction evidence is carried in `seal.first_contact_token` per [Handshake](handshake.md). |

Defined challenge types:

| Type | Status | Defined in | Parameters |
|---|---|---|---|
| `proof_of_work` | Core | [Handshake](handshake.md) | `algorithm` (string), `difficulty` (integer). |

A sender's home server encountering a `challenge_type` it does
not recognize MUST treat the policy as non-satisfiable by that
sender and MUST surface the envelope as undeliverable. A
recipient server MUST NOT announce a `challenge_type` it is not
prepared to verify.

A sender's home server fetching the recipient's key record MUST
cache the `first_contact_policy` alongside the key record and
MUST honor it when composing envelopes to that recipient. The
recipient's home server MUST enforce the published policy
regardless of what the sender's server caches.

A recipient server MUST publish the same `first_contact_policy`
for all addresses on its domain that have published any policy
at all, OR MUST publish no policy and apply per-recipient
policy internally. Per-address policy publication that varies
by address would constitute an existence oracle. When a
recipient has no published key record, the home server SHOULD
behave as if the recipient's policy were `mode: "challenge"`
with `challenge_type: "proof_of_work"` at the operator's
default difficulty, in order to prevent enumeration via
missing-key inference.

# Key Request and Response

## Key Request

Key requests are anonymous by default. There is no `requester`
field. The querying server is identified only by the TLS
connection at the domain level.

~~~ json
{
    "type": "SEMP_KEYS",
    "step": "request",
    "version": "1.0.0",
    "id": "request-ulid",
    "timestamp": "2026-06-10T19:49:15Z",
    "addresses": [
        "user1@example.com",
        "user2@example.com"
    ],
    "key_types": ["identity", "encryption"],
    "extensions": {}
}
~~~

`type` (string, required):
: MUST be `"SEMP_KEYS"`.

`step` (string, required):
: MUST be `"request"`.

`version` (string, required):
: SEMP protocol version (semver).

`id` (string, required):
: Unique request identifier. ULID RECOMMENDED.

`timestamp` (string, required):
: ISO 8601 UTC timestamp.

`addresses` (array, required):
: Addresses whose keys are requested. MAY include noise addresses.

`key_types` (array, optional):
: Key types requested. If absent, all current keys are returned.

`extensions` (object, optional):
: Optional authenticated request envelope.

For batch requests, the request is a `POST` to the
`endpoints.keys` base URL with no address suffix. A server that
supports batch fetch MUST accept a `POST` at
`<endpoints.keys>`. A server that does not support batch fetch
MUST respond with HTTP 405.

Servers MAY rate-limit anonymous key requests. Servers MUST NOT
require authenticated requests as a condition of publishing
public keys; public keys are by definition public.

# Key Verification

## Domain Signature

Every user key response is signed by the serving domain. This
is the baseline verification: the domain vouches that the keys
it publishes for its users are the keys those users registered.
Relying parties MUST verify the domain signature before
trusting any key material.

The domain signature is computed over the canonical bytes of
the key response with `signature.value` set to `""`, prefixed
with `SEMP-KEYS:` per the signature domain separation table in
[Envelope](envelope.md).

## Self-Signature

Encryption keys SHOULD be self-signed by the user's identity
key. Relying parties SHOULD verify self-signatures where
present.

The self-signature is computed over the canonical bytes of the
key record with the relevant self-signature slot set to `""`,
prefixed with `SEMP-KEY-SELF-SIG:`.

## Web of Trust

Additional trust signals MAY be attached to a key as
third-party signatures. Web of trust signatures are
informational. Relying parties MAY use them to increase
confidence in a key. They MUST NOT be the sole basis for
trusting a key; domain and self-signatures are required first.

## Out-of-Band Verification

For high-trust relationships, users SHOULD verify key
fingerprints out of band: safety numbers displayed in the
client UI, QR-code scanning between devices or users, or
out-of-band verification phrases read aloud. Out-of-band
verification is the strongest assurance available.

## Domain Verification via DANE

Domain keys SHOULD be cross-checked against DANE TLSA records
where DNSSEC is available. A domain key retrieved from the
well-known URI that matches the DANE record has the highest
available assurance level. A mismatch MUST be treated as a
potential compromise.

# Key Fetching Mechanisms

Fetching a public key before sending reveals communication
intent: an observer can infer that the querying server intends
to send a message to the target. SEMP mitigates this through
multiple fetching mechanisms with different privacy trade-offs.

| Mechanism | Privacy | Latency | Infrastructure cost |
|---|---|---|---|
| Speculative batch crawling | High | Low (cached) | High |
| Third-party key relay | Medium | Medium | Medium |
| Direct well-known fetch | Low | Low | Low |

Speculative batch crawling:
: The server proactively fetches and caches keys from domains
  it interacts with on a schedule, independent of any pending
  message. The fetch is decoupled from the send intent.

Third-party key relay:
: The fetch is proxied through a trusted intermediary. The
  target domain sees the relay's identity rather than the
  querying server's. The relay learns the querying server and
  the target but not the purpose.

Direct well-known fetch:
: Keys are fetched on demand from the target domain's
  well-known URI immediately before sending. Low
  infrastructure cost. The timing correlation between fetch
  and send is observable.

Operators configure which mechanisms are enabled and their
fallback order. The protocol does not mandate a default order.

Clients do not fetch keys from remote domains directly. When a
client needs recipient keys for envelope composition, it sends a
`SEMP_KEYS` message with `step: request` to its home server,
which fulfills the request using whatever fetching mechanism its
operator has configured.

## Tor-Reachable Recipients

When the recipient domain is a `.onion` address, all
key-fetching traffic MUST be carried over Tor. A sending server
MUST perform the direct well-known fetch over a Tor circuit to
the onion service and MUST NOT resolve or connect to any
clearnet endpoint associated with the onion domain for the
purpose of key retrieval.

A sending server MAY use third-party key relays for `.onion`
recipients only if the relay itself fetches via Tor. A relay
that fetches over clearnet when proxying an onion target
defeats recipient anonymity.

A sending server lacking Tor egress MUST NOT attempt clearnet
fallback for a `.onion` recipient.

# Key Rotation

## Rotation Schedule

SEMP recommends the following rotation intervals:

| Key type | Recommended rotation interval |
|---|---|
| `domain` | 12 to 24 months |
| `identity` | 12 to 24 months |
| `encryption` | 6 to 12 months |
| `device` | On device change or compromise |
| `session` | Per handshake (automatic) |

These are recommendations. Operators and users MAY rotate more
frequently.

## Rotation Process

1. Generate the new key pair.
2. Publish the new public key at the appropriate endpoint
   (DNS/DANE for domain keys, well-known URI for user keys).
3. Issue a revocation record for the old key citing
   `superseded`, with `replacement_key_id` pointing to the new
   key.
4. Continue accepting messages encrypted under the old key for
   a transition period to avoid delivery failures during cache
   propagation. The transition period SHOULD match the maximum
   expected cache TTL.
5. After the transition period, the old private key MAY be
   securely erased.

<a id="key-revocation"></a>

# Key Revocation
## Revocation Record

~~~ json
{
    "type": "SEMP_KEY_REVOCATION",
    "version": "1.0.0",
    "revoked_keys": [
        {
            "key_id": "key-fingerprint",
            "address": "user@example.com",
            "reason": "key_compromise",
            "revoked_at": "2026-06-10T19:49:15Z",
            "replacement_key_id": "new-key-fingerprint"
        }
    ],
    "signature": {
        "algorithm": "ed25519",
        "key_id": "identity-or-domain-key-fingerprint",
        "value": "base64-signature"
    }
}
~~~

The revocation `signature` is computed over the canonical bytes
of the revocation record with `signature.value` set to `""`,
prefixed with `SEMP-REVOCATION:`.

## Revocation Reasons

| Reason | Meaning |
|---|---|
| `key_compromise` | Key has been or is suspected of being compromised. |
| `superseded` | Key has been replaced by a newer key. |
| `cessation_of_operation` | The user or domain no longer uses this key. |
| `temporary_hold` | Temporary suspension pending investigation. |

## Revocation Publication

Revocation is pull-based. Servers have no obligation to push
revocation notices to other parties. The obligation is to
publish: a revocation record MUST be made discoverable at the
same endpoint where the key was originally published, and MUST
be returned in key responses for the revoked key's identifier.

When a sender fetches keys and receives a revocation record, it
MUST NOT use the revoked key. If a `replacement_key_id` is
present, the sender SHOULD fetch the replacement key and use it
instead.

Servers MUST retain revocation records indefinitely. A revoked
key that disappears from the published record cannot be
distinguished from a key that never existed, which opens
substitution attack vectors.

# Multi-Device Support

Every SEMP account MAY hold more than one device. Devices are
categorized by authority:

Full-access devices:
: Share the user's identity private key and encryption private
  key history. A full-access device can compose, receive,
  manage block lists and keys, authorize new devices, and
  revoke existing devices. The first device enrolled for an
  account is a full-access device by default.

Delegated devices:
: Hold their own device key pair and a scoped certificate
  issued by a full-access device. A delegated device operates
  within the restricted permission scope of its certificate
  and does not hold the user's identity private key.

Each device also holds its own `device` key pair for
authentication to the home server and for signing
device-scoped artifacts (registration, revocation, directory
records, delegated certificates, Shamir share records, and
device-sync messages).

## Device Registration

A device is registered by submitting a signed `SEMP_DEVICE`
record to the account's home server:

~~~ json
{
    "type": "SEMP_DEVICE",
    "step": "register",
    "version": "1.0.0",
    "user_id": "alice@example.com",
    "device_id": "01JDEVICE00000000000000NEW0",
    "device_name": "Alice's Laptop",
    "device_type": "computer",
    "device_public_key": "base64-ed25519-device-public-key",
    "device_identity_pubkey_algorithm": "ed25519",
    "enrolled_at": "2026-04-23T10:00:00Z",
    "role": "full_access",
    "certificate_id": null,
    "authorization": {
        "method": "qr_scan",
        "authorizing_device_id": "01JDEVICE00000000000000OLD0",
        "authorizing_signature": {
            "algorithm": "ed25519",
            "key_id": "authorizing-device-key-fingerprint",
            "value": "base64-signature"
        }
    },
    "signature": {
        "algorithm": "ed25519",
        "key_id": "user-identity-key-fingerprint",
        "value": "base64-signature"
    }
}
~~~

The home server MUST verify the outer `signature` against the
user's current identity public key, the
`authorization.authorizing_signature` against the authorizing
device's device public key (and that the authorizing device is
currently registered as `full_access`), that `device_id` is not
already present, that `role` and `certificate_id` are
consistent, that the `authorization.method` is one the server
supports, and (for `delegated` role) that a valid scoped
certificate for the named `certificate_id` is present and
unexpired.

The outer `signature` is computed over the canonical bytes of
the record with `signature.value` set to `""`, prefixed with
`SEMP-DEVICE-REGISTER:`.

## Enrollment Flow

A conformant implementation MUST support both `qr_scan` and
`numeric_code` authorization methods.

`qr_scan`:
: NEW (the new device) displays a QR code containing its
  device public key and a fresh 32-byte nonce. EXISTING (an
  existing full-access device) scans the QR code.

`numeric_code`:
: NEW displays a 6-digit code derived from the first 20 bits
  of `SHA-256(device_public_key || nonce)`. The user reads the
  code into EXISTING; EXISTING recomputes the same hash after
  receiving the underlying public key over a local pairing
  channel.

The nonce MUST be freshly generated on every enrollment
attempt and MUST NOT be reused.

For full-access enrollment, EXISTING transmits to NEW, over
the local pairing channel, a sealed bundle containing the
finalized registration record, the user's identity private
key (wrapped under NEW's device public key), the user's
encryption private key history, and a snapshot of the
account's block list.

NEW MUST verify that the wrapped identity public key matches
the user's currently published identity key. If not, NEW MUST
abort with `identity_mismatch` and notify the user of a
probable man-in-the-middle attempt.

EXISTING MUST treat the enrollment as valid only if the outer
`signature` is produced within 5 minutes of `enroll_nonce`
generation. The home server MUST reject registration records
whose `enrolled_at` is more than 15 minutes before the
submission time.

For delegated enrollment, the wrapping step is omitted; NEW
receives only the certificate and continues with the scope
authorized by that certificate.

Users MUST be instructed that any device they authorize via
full-access enrollment will receive the account's identity
private key.

<a id="scoped-device-certificates"></a>

## Scoped Device Certificates
A scoped device certificate authorizes a delegated device to
act on behalf of a user within a restricted permission scope.
Delegated devices include mailing list clients, spam filter
clients, vacation autoresponders, read-only viewers, and any
other program that holds its own device key and requires less
than full-account authority.

The certificate is issued by a full-access device of the
account (the primary device). It binds the delegated device's
public key to a permission scope and a validity window. The
home server enforces the scope at envelope submission and at
inbound delivery.

### Certificate Schema

~~~ json
{
    "type": "SEMP_DEVICE_CERTIFICATE",
    "version": "1.0.0",
    "device_id": "01JDELEGATE0000000000000000",
    "device_public_key": "base64-delegated-device-public-key",
    "account": "user@example.com",
    "issued_by": "01JPRIMARY00000000000000000",
    "issued_at": "2026-06-15T10:00:00Z",
    "expires_at": "2026-12-15T10:00:00Z",
    "scope": {
        "send": {
            "mode": "restricted",
            "allow": [
                { "type": "user",
                  "address": "subscriber1@example.com" },
                { "type": "domain", "domain": "company.example" }
            ],
            "rate_limits": [
                { "period_seconds": 3600, "amount_allowed": 200 },
                { "period_seconds": 86400, "amount_allowed": 2000 }
            ]
        },
        "receive": {
            "mode": "none",
            "rate_limits": [],
            "delivery_stage": 1
        },
        "blocklist": {
            "read": false, "write": false, "rate_limits": []
        },
        "keys": {
            "read": false, "write": false, "rate_limits": []
        },
        "devices": {
            "read": false, "write": false, "rate_limits": []
        }
    },
    "signature": {
        "algorithm": "ed25519",
        "key_id": "primary-device-key-fingerprint",
        "value": "base64-signature"
    }
}
~~~

The certificate MUST be signed by the device key of a
full-access device (the issuer). The signature is computed
over the canonical UTF-8 JSON encoding of the certificate with
`signature.value` set to `""`, prefixed with the appropriate
domain separation tag.

### Scope Object

The scope object has five fields, one per authorizable action
class. `send` and `receive` use the matcher shape;
`blocklist`, `keys`, and `devices` use the resource shape.
Every scope field is REQUIRED, including its `rate_limits`
array (which MAY be empty).

The matcher shape:

| `mode` | Meaning |
|---|---|
| `unrestricted` | All peers permitted. `allow` and `deny` MUST be absent or empty. |
| `restricted` | Only peers matching `allow` are permitted. `allow` MUST be present and non-empty. `deny` MUST be absent. |
| `denylist` | All peers permitted except those matching `deny`. `deny` MUST be present and non-empty. `allow` MUST be absent. |
| `none` | No peers permitted. `allow` and `deny` MUST be absent or empty. |

Entries in `allow` and `deny` use entity types `user`,
`domain`, and `server`. The combined size of `allow` and `deny`
in a single matcher MUST NOT exceed 10000 entries.

For `send`, a peer is the recipient address of an outbound
envelope; enforcement happens at submission. For `receive`, a
peer is the sender address of an inbound envelope after the
home server has decrypted the brief and can read `brief.from`.

`delivery_stage` is present only on the `receive` matcher and
MUST be omitted from `send`. It is a positive integer (`>= 1`)
declaring this device's position in the staged-delivery
ordering. Lower stages receive inbound envelopes first and
decide via delivery-disposition messages whether the envelope
advances. Full-access devices have no certificate and are
treated as implicitly positioned at
`max(delegated_stages_with_mode_not_none) + 1`.

The resource shape:

`read` (boolean):
: Whether the device may list or inspect this resource.

`write` (boolean):
: Whether the device may modify this resource.

`rate_limits` (array):
: Rate-limit tiers applied to any operation on this resource. MAY be empty.

Operations gated by each field:

| Resource | `read` grants | `write` grants |
|---|---|---|
| `blocklist` | List block entries. | Add, modify, remove block entries. |
| `keys` | Read key rotation history and per-device key metadata. | Publish a new user key, rotate, or revoke. |
| `devices` | List registered devices. | Register new delegated devices, revoke devices. |

### Rate Limits

Each rate-limit tier:

~~~ json
{ "period_seconds": 3600, "amount_allowed": 100 }
~~~

`period_seconds` (integer, required):
: Length of the rolling window in seconds. MUST be >= 1.

`amount_allowed` (integer, required):
: Maximum operations permitted within any rolling window of `period_seconds`. MUST be >= 0.

Multiple tiers in the same array are evaluated independently;
an operation is permitted only if it would not exceed any
tier's cap. An empty array means no protocol-imposed cap. A
tier with `amount_allowed: 0` prohibits the operation. A
certificate MUST NOT contain a tier with `period_seconds < 1`,
`amount_allowed < 0`, or more than 16 tiers in a single
`rate_limits` array.

### Scope Enforcement

The home server enforces the scope at every relevant
operation:

* On every outbound envelope submission from the delegated
  device, the server evaluates `scope.send` against each
  recipient. Non-permitted recipients MUST cause rejection
  with `reason_code: "scope_exceeded"`.
* On every inbound envelope, the server evaluates
  `scope.receive` against `brief.from`. Non-permitted senders
  MUST NOT result in delivery to this device's session, and
  the server MUST NOT wrap `K_brief` or `K_enclosure` to this
  device's keys for that envelope.
* On every operation addressing `blocklist`, `keys`, or
  `devices`, the server first dispatches on operation class
  (read or write). If the corresponding permission is
  `false`, the server MUST reject with `reason_code:
  "scope_exceeded"`.
* On every operation that passes the matcher or boolean
  check, the server evaluates the scope field's
  `rate_limits` array. If any tier would be exceeded, the
  server MUST reject with `reason_code: "rate_limited"` and
  MUST NOT record the operation against the counters.

Scope enforcement uses the current certificate at the time of
each operation, not the certificate that was active when the
session was established.

### Lifetime

The `expires_at` value MUST satisfy:

~~~
issued_at < expires_at <= issued_at + 365 days
~~~

The RECOMMENDED lifetime is 180 days from issuance.

A certificate whose `expires_at` has passed MUST be treated by
the home server as invalid. Submissions from the delegated
device MUST be rejected with `reason_code:
"certificate_expired"`. The delegated device's existing
session MUST be terminated on expiry.

<a id="certificate-update"></a>

### Certificate Update
A full-access device MAY issue a new certificate for an
existing delegated `device_id` to change scope or extend
`expires_at`. The home server stores the new certificate and
enforces its scope on the next operation after acceptance.

An active session held by the delegated device MUST NOT be
invalidated by certificate update alone. The session
continues, and the updated scope applies to the next
operation within it. This permits instantaneous scope changes
without requiring the delegated device to reconnect.

The home server MUST preserve the delegated device's existing
session through certificate update. Rotating or revoking the
delegated device key (rather than the certificate)
invalidates the session per [Certificate Revocation](#certificate-revocation).

<a id="certificate-revocation"></a>

### Certificate Revocation
A scoped certificate MAY be revoked either by revoking the
delegated device key itself or by publishing a certificate
revocation record:

~~~ json
{
    "type": "SEMP_DEVICE_CERTIFICATE_REVOCATION",
    "version": "1.0.0",
    "account": "user@example.com",
    "device_id": "01JDELEGATE0000000000000000",
    "revoked_at": "2026-08-01T12:00:00Z",
    "reason": "delegated_role_ended",
    "issued_by": "01JPRIMARY00000000000000000",
    "signature": {
        "algorithm": "ed25519",
        "key_id": "primary-device-key-fingerprint",
        "value": "base64-signature"
    }
}
~~~

Defined revocation reasons:

| Reason | Meaning |
|---|---|
| `delegated_role_ended` | The delegation is no longer needed. |
| `suspected_compromise` | The delegated device or its operator is believed compromised. |
| `scope_change` | Scope is being changed; paired with issuance of a new certificate. |
| `policy` | Revoked for account policy reasons. |

On acceptance of a revocation record, the home server MUST
terminate the delegated device's active session immediately,
reject any subsequent handshake from `device_id` with
`reason_code: "revoked"`, stop delivering inbound envelopes
to `device_id`, and publish the revocation record alongside
the user's key history.

A revocation record MUST be signed by a full-access device of
the account.

### Nested Delegation Prohibited

A delegated device MUST NOT issue a `SEMP_DEVICE_CERTIFICATE`.
Only a full-access device of the account may issue
certificates. `scope.devices.write: true` on a delegated
device authorizes it to submit device registrations to the
home server, but the certificate of any resulting device MUST
still be signed by a full-access device.

<a id="device-revocation"></a>

## Device Revocation
A device is removed from the account's effective set by
publishing a signed `SEMP_DEVICE_REVOCATION` record.
Revocation terminates the device's ability to authenticate
to the home server, issue scoped certificates, authorize new
enrollments, or act on the account in any capacity.
Revocation is monotonic: once published, a revocation record
MUST be retained indefinitely (the same retention rule as
key revocation, [Key Revocation](#key-revocation)).

### Revocation Record Schema

~~~ json
{
    "type": "SEMP_DEVICE_REVOCATION",
    "version": "1.0.0",
    "user_id": "alice@example.com",
    "device_id": "01JDEVICE00000000000000REV0",
    "reason": "key_compromise",
    "revoked_at": "2026-04-23T10:00:00Z",
    "revoked_by_device_id": "01JDEVICE00000000000000OTH0",
    "replacement_device_id": null,
    "signature": {
        "algorithm": "ed25519",
        "key_id": "user-identity-key-fingerprint",
        "value": "base64-signature"
    }
}
~~~

`type` (string, required):
: MUST be `"SEMP_DEVICE_REVOCATION"`.

`version` (string, required):
: Record format version (semver).

`user_id` (string, required):
: The account's SEMP address, canonicalized per [Envelope](envelope.md).

`device_id` (string, required):
: Identifier of the device being revoked. MUST correspond to a device currently in the directory ([Device Directory](#device-directory)).

`reason` (string, required):
: Revocation reason. See [Revocation Reasons](#device-revocation-reasons).

`revoked_at` (string, required):
: ISO 8601 UTC revocation timestamp.

`revoked_by_device_id` (string, required):
: `device_id` of the device that signed the revocation. Authority rules in [Revocation Authority](#revocation-authority).

`replacement_device_id` (`string \, null`):
: Yes

`signature` (object, required):
: Signature by the user's identity private key, over canonical bytes with `signature.value` set to `""`, prefixed with `SEMP-DEVICE-REVOCATION:`.

<a id="device-revocation-reasons"></a>

### Revocation Reasons
| Reason | Meaning |
|---|---|
| `key_compromise` | The device's key material is known or suspected to be under adversary control. Triggers identity-key rotation per [Mandatory Identity-Key Rotation on Compromise](#cascade-rotation). |
| `lost` | The device is physically lost or unreachable but no evidence of active compromise. The device certificate is revoked, and the identity key is not automatically rotated. |
| `retired` | The user is decommissioning the device voluntarily (upgrade, resale, disposal). |
| `superseded` | The device is being replaced by a specific new device. `replacement_device_id` names the replacement. |

Additional reasons MAY be defined by extensions using the
namespace convention.

<a id="revocation-authority"></a>

### Revocation Authority
Any full-access device MAY revoke any other device of the
account, including itself (self-revoke), and MAY revoke
delegated devices unconditionally. A delegated device MUST
NOT revoke any device other than itself. If a delegated
device is not granted `devices.write` scope, its self-revoke
submission MUST be rejected with `reason_code:
"scope_exceeded"`.

A compromised device that the user believes is still under
adversary control SHOULD be revoked from another device
rather than self-revoked, since the adversary could submit a
contradictory record from the compromised device. The home
server MUST accept the first submitted revocation with a
valid signature; later records for the same `device_id` MUST
be ignored. The user is responsible for publishing the
revocation before the adversary can. The home server's
single-accept enforcement protects the user from the
adversary reversing a published revocation.

<a id="device-revocation-publication"></a>

### Publication and Propagation
Revocation records are published at the account's home
server via the same mechanism as key revocations
([Key Revocation](#key-revocation)). The home server MUST:

* Publish the revocation record at the user's key endpoint.
* Increment the device directory revision
  ([Device Directory](#device-directory)) to remove the revoked device from
  the active set.
* Invalidate any active sessions associated with the
  revoked `device_id` per [Handshake](handshake.md).
* Reject any incoming authentication that presents the
  revoked device's device key.

Third-party domains that cache the user's device directory
MUST invalidate their cache on learning of a revocation.

<a id="cascade-rotation"></a>

### Mandatory Identity-Key Rotation on Compromise
A revocation with `reason: "key_compromise"` REQUIRES that
the account's identity key and encryption key be rotated
immediately. Because the revoked device held the shared
identity private key, the adversary holds it as well, and
continued use of the same identity key would leave the
adversary able to forge envelopes and authorize new devices.

The full rotation procedure is:

1. The revoking device generates a new identity key pair
   and a new encryption key pair.
2. The revoking device publishes the revocation record per
   [Publication and Propagation](#device-revocation-publication) and, in the same
   operation, publishes a successor record per
   [Recovery](recovery.md) linking the prior identity
   key to the new one.
3. The revoking device publishes the new identity and
   encryption public keys via the account's key endpoint.
4. The revoking device publishes a revocation record for
   the prior identity key per [Key Revocation](#key-revocation), signed by
   the prior identity key (which the revoking device still
   holds).
5. Remaining full-access devices receive the new identity
   and encryption private keys over the device-sync channel
   and MUST rotate their local state accordingly.

If the revoking device is itself the only remaining
full-access device, steps 1 through 4 still apply. There
are no remaining devices to receive the new key material
via sync, and subsequent enrollments transfer the new key
material.

Revocations with any other reason (`lost`, `retired`,
`superseded`) do not trigger identity-key rotation by
default. The user MAY nonetheless initiate rotation at any
time through the successor-record flow in
[Recovery](recovery.md).

A conformant implementation MUST refuse to complete a
`key_compromise` revocation without simultaneously
completing the identity-key rotation. A partial revocation
(device certificate revoked, identity key not rotated)
leaves the account vulnerable and is a specification
violation.

<a id="device-directory"></a>

## Device Directory
The home server publishes a `SEMP_DEVICE_DIRECTORY` record
listing all currently registered devices for an account.
The directory is the authoritative source for which devices
currently represent a user. Correspondents, the account's
own devices, and recovery manifests
([Recovery](recovery.md)) reference the directory when
validating device-scoped signatures.

### Directory Record Schema

~~~ json
{
    "type": "SEMP_DEVICE_DIRECTORY",
    "version": "1.0.0",
    "user_id": "alice@example.com",
    "revision": 17,
    "issued_at": "2026-04-23T10:00:00Z",
    "devices": [
        {
            "device_id": "01JDEVICE00000000000000PRM0",
            "device_public_key":
                "base64-ed25519-device-public-key",
            "device_identity_pubkey_algorithm": "ed25519",
            "role": "full_access",
            "certificate_id": null,
            "enrolled_at": "2025-12-01T08:00:00Z",
            "device_name": "Alice's Laptop",
            "device_type": "computer"
        },
        {
            "device_id": "01JDEVICE00000000000000PHN0",
            "device_public_key":
                "base64-ed25519-device-public-key",
            "device_identity_pubkey_algorithm": "ed25519",
            "role": "full_access",
            "certificate_id": null,
            "enrolled_at": "2026-01-15T12:30:00Z",
            "device_name": "Alice's Phone",
            "device_type": "phone"
        },
        {
            "device_id": "01JDEVICE00000000000000BOT0",
            "device_public_key":
                "base64-ed25519-device-public-key",
            "device_identity_pubkey_algorithm": "ed25519",
            "role": "delegated",
            "certificate_id": "01JCERT000000000000000SPAM",
            "enrolled_at": "2026-03-01T09:00:00Z",
            "device_name": "Spam Filter",
            "device_type": "server"
        }
    ],
    "signature": {
        "algorithm": "ed25519",
        "key_id": "user-identity-key-fingerprint",
        "value": "base64-signature"
    }
}
~~~

`type` (string, required):
: MUST be `"SEMP_DEVICE_DIRECTORY"`.

`version` (string, required):
: Record format version (semver).

`user_id` (string, required):
: The account's SEMP address, canonicalized.

`revision` (integer, required):
: Monotonically increasing revision number. Consumers MUST reject a fetched directory whose `revision` is less than a previously cached one for the same `user_id`.

`issued_at` (string, required):
: ISO 8601 UTC issuance timestamp.

`devices` (array, required):
: One entry per active device. Order within the array is not semantic, and consumers MUST sort by `device_id` before comparison.

`devices[i].device_id` (string, required):
: Stable device identifier.

`devices[i].device_public_key` (string, required):
: Base64-encoded device identity public key.

`devices[i].device_identity_pubkey_algorithm`:
: (string, required) Signature algorithm identifier.

`devices[i].role` (string, required):
: One of `full_access`, `delegated`.

`devices[i].certificate_id` (`string \, null`):
: Yes

`devices[i].enrolled_at` (string, required):
: ISO 8601 UTC enrollment timestamp.

`devices[i].device_name` (string, required):
: User-facing name.

`devices[i].device_type` (string, required):
: Device category label.

`signature` (object, required):
: Signature by the user's identity private key over the canonical record bytes with `signature.value` set to `""`, prefixed with `SEMP-DEVICE-DIRECTORY:`.

### Publication

The home server MUST expose the device directory at the
account's key endpoint as part of the response for
`key_types` that includes `"device"` in the `SEMP_KEYS`
request. The home server MUST serve the most recent
directory revision, and stale directories beyond the
advertised TTL MUST NOT be returned.

The directory is versioned. Every enrollment and revocation
causes the home server to publish a new directory revision.
The monotonically increasing `revision` field allows
consumers to detect rollback attempts. A home server that
serves a directory with `revision` less than a previously
observed one for the same `user_id` is presumed to be
attempting equivocation, and consumers MUST treat the
attempt with the same suspicion rules as a key-substitution
attempt ([Recovery](recovery.md)).

### Consumer Verification

A consumer of the device directory (another user's home
server, a correspondent's client, the recovery manifest
validator) MUST verify:

* `signature` against the user's identity public key
  published at the same key endpoint.
* `revision` is greater than or equal to any previously
  cached revision for this `user_id`.
* Every `devices[i].device_id` is unique within the array.
* For entries with `role: "delegated"`, the scoped
  certificate identified by `certificate_id` is published
  and unexpired.

A consumer MUST treat a device not present in the directory
as unauthorized. A signature produced by a device key not
present in the current directory, for any device-scoped
artifact (scoped certificate, recovery share,
delivery-disposition marker, device-sync message), MUST be
rejected.

# Protocol Lookup

For cases where DNS and well-known URI are insufficient (such
as determining per-user capability or resolving a specific
address on a partitioned domain), SEMP defines an explicit
protocol lookup exchange.

## Lookup Request

~~~ json
{
    "type": "SEMP_DISCOVERY",
    "step": "request",
    "version": "1.0.0",
    "id": "request-ulid",
    "timestamp": "2026-06-10T19:39:03Z",
    "addresses": [
        "user1@example.com",
        "user2@example.com"
    ],
    "extensions": {}
}
~~~

The request is anonymous. There is no `requester` field. The
querying server is identified only by the TLS connection from
which the request originates.

Servers MAY include noise addresses in the `addresses` array to
reduce the inferability of which specific address prompted the
lookup.

## Lookup Response

~~~ json
{
    "type": "SEMP_DISCOVERY",
    "step": "response",
    "version": "1.0.0",
    "id": "echoed-request-ulid",
    "timestamp": "2026-06-10T19:39:04Z",
    "results": [
        {
            "address": "user1@example.com",
            "status": "semp",
            "transports": ["ws", "h2", "quic"],
            "extensions": ["semp.dev/large-attachment"],
            "server": "semp.example.com",
            "ttl": 3600
        },
        {
            "address": "user2@example.com",
            "status": "legacy",
            "transports": ["smtp"],
            "server": "mail.example.com",
            "ttl": 86400
        },
        {
            "address": "user3@unknown.example",
            "status": "not_found",
            "ttl": 3600
        }
    ],
    "signature": {
        "algorithm": "ed25519",
        "key_id": "server-domain-key-fingerprint",
        "value": "base64-signature-over-response"
    },
    "extensions": {}
}
~~~

| Status | Meaning |
|---|---|
| `semp` | The recipient domain supports SEMP. Handshake and envelope delivery may proceed. |
| `legacy` | The recipient domain does not support SEMP but has MX records. Client SMTP fallback is possible. |
| `not_found` | The recipient domain supports neither SEMP nor SMTP. The domain cannot receive mail by any known method. |

The response MUST be signed by the responding server's domain
key. The querying server MUST verify this signature before
caching or acting on the results.

<a id="statuses-domain-level"></a>

## Statuses Are Domain-Level
The status values describe the recipient domain's capability,
not the existence of an individual address. Per-address
existence MUST NOT be inferred from the response.

A conformant server responding to `SEMP_DISCOVERY` MUST:

* return the same `status`, `transports`, and `extensions`
  values for every address on the same recipient domain,
  regardless of whether the address corresponds to a
  registered user; an address that does not exist on a
  SEMP-supporting domain MUST still receive `status: "semp"`;
* return identical `ttl` values for every address on the same
  recipient domain, to prevent timing-based enumeration;
* return a `server` field that is either domain-level or
  derivable by the requester without server-side knowledge
  (for example, a hash-partitioned server index computable
  from the address);
* not include `recipient_status`, mailbox existence flags,
  account activity timestamps, or any other per-user signal
  in the result object.

This rule prevents discovery from becoming an
address-harvesting endpoint.

# Discovery Flow

## Standard Flow

1. DNS SRV/TXT lookup for `_semp._tcp.<domain>`.
2. If DNS yields no SEMP records, fetch the well-known URI for
   the configuration document.
3. If the well-known URI also yields no SEMP support, query
   DNS MX for the domain. MX present means outcome `legacy`;
   no MX means outcome `not_found`.
4. If SEMP found at any earlier step and per-user resolution is
   needed, send a `SEMP_DISCOVERY` request and wait for the
   signed response.
5. Cache results per TTL.
6. Proceed with SEMP delivery, or return `legacy_required`
   or `recipient_not_found` to the client.

## Cached Flow

When the cache contains a fresh entry for the recipient domain,
the sender's server proceeds directly with the handshake and
delivery without re-running discovery.

## Same-Domain Multi-Server Flow

When a sender and recipient share a domain but are on different
partition servers, delivery routes internally. The sending
partition server forwards the envelope to the receiving
partition server using the `SEMP_INTERNAL_ROUTE` mechanism. The
receiving partition server MUST execute the full delivery
pipeline (seal verification, session validation, brief
decryption, user policy checks, block-list enforcement) before
returning an acknowledgment.

Block list enforcement occurs on the receiving partition server
(the server that holds the recipient's block list), not on the
sending partition server. The sending partition server MUST NOT
access, query, or cache the recipient's block list.

Internal server connections MUST be secured with mutual TLS.

## SRV Target and Configuration Host Resolution

When DNS SRV resolves a domain to a target hostname, the
configuration document is fetched from the SRV target rather
than from the email domain:

~~~
GET https://<srv-target>/.well-known/semp/configuration
~~~

All subsequent operations use the URLs advertised in the
configuration document. When SRV lookup fails or returns no
records, the email domain is used as the hostname.

## Federation Endpoint Resolution

When a server needs to open a federation session to a peer
domain, it resolves the federation endpoint exclusively from
the peer's configuration document. Servers MUST NOT derive
federation endpoints by path manipulation or by guessing.

## Automatic Peer Discovery

Servers MUST NOT require pre-configured peer lists for
federation. Any two SEMP servers with correctly configured DNS
SRV/TXT records and a published configuration document can
federate without prior arrangement.

# Caching

## Caching Rules

Discovery results MUST be cached per the TTL returned in the
response or DNS record.

| Result type | Default TTL when none provided | TTL source |
|---|---|---|
| `semp` | 1 hour | DNS TTL or lookup response. |
| `legacy` | 24 hours | DNS TTL or lookup response. |
| `not_found` | 1 hour | DNS TTL or lookup response. |
| Configuration document | 1 hour | `ttl_seconds` field in the document. |

Implementations MUST respect TTL values, MUST respect
`ttl_seconds` from cached configuration documents, MUST
invalidate cache entries on delivery failure and re-discover
before retry, MUST re-fetch configuration per the mandatory
triggers, and MUST NOT serve stale entries beyond their TTL.

Implementations SHOULD perform discovery speculatively for
frequently contacted domains, independent of pending sends, to
decouple lookup timing from communication intent. They SHOULD
also encrypt cached discovery results at rest.

<a id="authenticated-discovery"></a>

## Authenticated Discovery
Authenticated discovery allows a querying server to
cryptographically identify itself to the target server at the
application layer. The querying server signs each request with
its domain signing key; the target verifies the signature
against the querying server's published domain key.

Authentication is a rate-limiting, audit, and reputation tool
rather than an access control gate. With the exception of
partition lookup queries, servers MUST NOT require
authenticated discovery as a condition of SEMP
interoperability. An anonymous request from an unknown domain
MUST still receive a valid response, subject to rate limits.

Authenticated discovery is declared via a reserved extension in
the `extensions` field of the request:

~~~ json
"extensions": {
    "semp.dev/auth": {
        "method": "domain_key",
        "key_id": "querying-server-domain-key-fingerprint",
        "signature": "base64-signature-over-canonical-request"
    }
}
~~~

The signature MUST cover the canonical JSON form of the
request with the `signature` field excluded. A target server
that receives an authenticated request MUST extract the
`key_id`, resolve the querying server's domain to its
configuration document, fetch the domain keys, locate the key
matching `key_id`, and verify the signature.

An authenticated request whose signature fails verification
MUST be treated as if it were anonymous for the purpose of
rate limiting and policy.

A conformant server SHOULD apply different rate limits based on
authentication status:

| Requester class | Recommended limit |
|---|---|
| Anonymous | 10 lookup addresses per minute per source network prefix. |
| Authenticated, zero reputation | 100 lookup addresses per minute per requester domain. |
| Authenticated, established reputation | Operator-policy-driven, typically 10000 addresses per minute. |
| Authenticated, hostile or throttled reputation | Below the anonymous tier, or rejected. |

Authentication identifies the querying server domain rather
than the user on whose behalf the query is made. A conformant
server MUST NOT interpret authenticated discovery as an
identification of an individual user.

# Legacy Integration

## Discovery Outcome Resolution

When SEMP discovery fails for a recipient domain (no SEMP SRV
records and the well-known URI returns 404 or non-SEMP
content), the sender's server MUST NOT immediately treat the
recipient as unreachable. It MUST perform a secondary SMTP
capability check before resolving the final discovery outcome.

| Outcome | Condition | Submission status |
|---|---|---|
| `semp` | SEMP records found. | Proceed with SEMP delivery. |
| `legacy` | No SEMP records. MX records exist. | `legacy_required`. |
| `not_found` | No SEMP records. No MX records. | `recipient_not_found`. |

The SMTP capability check is a DNS-only operation. The sender's
server MUST NOT attempt an SMTP connection to the recipient
domain during discovery. The MX record is sufficient
confirmation that SMTP delivery is possible.

A `legacy` outcome means the domain has MX records and can
receive SMTP mail. It does not confirm that the specific
recipient address exists on that domain. Per-address validation
is not possible without opening an SMTP connection and issuing
a RCPT TO command, which this specification does not do during
discovery.

## Caching Legacy and Not-Found Results

Legacy and not-found outcomes MUST be cached separately:

| Outcome | Default TTL when none provided |
|---|---|
| `legacy` | 24 hours. |
| `not_found` | 1 hour. |

Servers SHOULD re-check `not_found` domains more aggressively
than `legacy` domains, as a `not_found` result may resolve
quickly if the operator is in the process of setting up their
mail infrastructure.

# Security Considerations

For the consolidated adversary model under which this section
is evaluated, see [Architecture](architecture.md).

## Response Authenticity

Lookup responses MUST be signed by the responding server's
domain key. The querying server MUST verify this signature
before caching or acting on results. An unsigned or
unverifiable response MUST be discarded.

DNS responses are not signed at the application layer. DNSSEC
is RECOMMENDED for domains that publish SEMP SRV and TXT
records to prevent spoofing at the DNS layer.

## Spoofing Prevention

A malicious DNS response or tampered well-known URI could
redirect delivery to a rogue server. Mitigations: DNSSEC for
DNS record integrity; HTTPS with valid certificates for
well-known URI; signed lookup responses verified against the
domain's published key; cross-checking. If DNS and well-known
URI disagree, the discrepancy SHOULD be flagged and MAY trigger
a re-query before delivery proceeds.

## Address Harvesting

The discovery endpoint is a potential address-harvesting
surface. The protocol-level defenses are:

* The status values defined in [Statuses Are Domain-Level](#statuses-domain-level)
  describe the recipient domain's capability, not per-user
  existence. A conformant server MUST return identical
  responses for every address on the same domain regardless
  of whether the address corresponds to a registered user.
* The `lookup` partition strategy resolves addresses to
  specific delivery servers and necessarily reveals address
  existence. A partition server MUST require authenticated
  discovery for every lookup query and MUST return a generic
  response that is indistinguishable for valid and invalid
  addresses to anonymous queries.
* Anonymous discovery MUST be rate-limited. Authenticated
  discovery MUST be attributable to a requester domain and
  MAY feed into reputation observations
  ([Delivery](delivery.md)).

Servers SHOULD hash plaintext addresses before writing them to
access logs, audit logs, telemetry pipelines, or any other
operational data that is not the protocol state itself.

## Intent Leaking

Discovery reveals that the querying domain intends to send to
the target domain. Mitigations: speculative batch caching
decouples lookup timing from send intent; noise addresses in
lookup requests reduce per-address inferability.

## Domain Key Compromise

Compromise of a domain signing key allows an attacker to
forge configuration documents, key responses, and discovery
responses for the affected domain. Domain operators SHOULD
rotate signing keys per the rotation schedule defined earlier
in this document and MUST publish revocation records on
suspected compromise.

DANE TLSA records combined with DNSSEC provide an out-of-band
verification path for domain keys. A relying party that
cross-checks against DANE detects substitution attacks on the
configuration endpoint.

## DNS Privacy

The DNS SRV/TXT lookup reveals the querying server's IP to
the DNS resolver. Implementations MAY use DNS-over-HTTPS
[RFC 8484](https://www.rfc-editor.org/rfc/rfc8484) or DNS-over-TLS [RFC 7858](https://www.rfc-editor.org/rfc/rfc7858) to reduce this
exposure.

# Privacy Considerations

The lookup request reveals the querying server's domain to the
target domain. It does not reveal the sender's identity or the
specific recipient within the domain when noise addresses are
used.

The DNS lookup reveals the querying server's IP to the DNS
resolver. Speculative caching is the most effective privacy
mitigation at the discovery layer; by fetching and refreshing
capability records on a schedule independent of pending
messages, the timing correlation between a lookup and a
subsequent message is broken.

<a id="test-vectors"></a>

# Test Vectors
The cross-language test vector corpus at `vectors/v1.0.0/` of
the SEMP specification repository pins the byte-level behavior
of the constructions in this document. The following files
exercise discovery, key publication, and device records:

| File | What it pins |
|---|---|
| `discovery.json` | Discovery response parsing, DNS TXT capability records, SRV record selection (including `_semp._udp` for QUIC), HTTP/2 path templates, key-fetch status enum, reciprocity policy shape, migration-key-fetch redirect. |
| `discovery-signed.json` | `SEMP_DISCOVERY` response signature path. |
| `configuration-update.json` | `SEMP_CONFIGURATION_UPDATE` signature path with the `SEMP-CONFIGURATION-UPDATE:` prefix. |
| `key-revocation.json` | Sender-side handling of revoked keys with optional replacement. |
| `device-certificates.json` | Scoped device certificate validation, scope enforcement, rate limits, resource enforcement, lifecycle, staged delivery. |

# IANA Considerations

This document makes the registrations below.

## Well-Known URI Registrations

IANA is requested to register two entries in the "Well-Known
URIs" registry established by [RFC 8615](https://www.rfc-editor.org/rfc/rfc8615).

The first entry:

URI suffix:
: semp

Change controller:
: IETF

Specification document:
: This document

Status:
: permanent

Related information:
: This document defines the sub-paths `configuration`,
  `domain-keys`, `keys/{address}`, and `reputation/{subject}`
  under the `semp` suffix.

The second entry:

URI suffix:
: semp-extensions

Change controller:
: IETF

Specification document:
: [Extensions](extensions.md)

Status:
: permanent

Related information:
: Extension definition documents are published under this
  suffix, as described in [Extensions](extensions.md).

## Service Name Registration

IANA is requested to register the following entry in the
"Service Name and Transport Protocol Port Number Registry"
established by [RFC 6335](https://www.rfc-editor.org/rfc/rfc6335). No port number is requested. SEMP
endpoints are located through SRV records, and the port is
carried in the SRV target.

Service Name:
: semp

Transport Protocols:
: TCP, UDP

Assignee:
: IESG

Contact:
: IETF Chair

Description:
: Sealed Envelope Messaging Protocol

Reference:
: This document

The `_semp._tcp` SRV record locates servers reachable over the
TCP-based transports (WebSocket and HTTP/2). The optional
`_semp._udp` SRV record locates a QUIC endpoint.

# Acknowledgments

The author thanks the contributors to the SEMP specification
for review, design discussion, and prior-art analysis.

