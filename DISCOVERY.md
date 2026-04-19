# SEMP Discovery Specification

**Sealed Envelope Messaging Protocol**  
Status: Internet-Draft  
Version: 0.2.0-draft  
Related: `DESIGN.md`, `HANDSHAKE.md`, `KEY.md`, `ENVELOPE.md`

---

## Abstract

The SEMP discovery specification defines how a sending server determines whether
a recipient domain supports SEMP, which server to connect to, and what
capabilities that server offers. Discovery is performed by the sender's server,
not by the client. It is the prerequisite to every cross-domain message delivery.

---

## 1. Overview

Before delivering an envelope to a recipient domain, the sender's server must
answer three questions:

1. Does this domain support SEMP at all?
2. Which server handles SEMP for this domain?
3. What capabilities does that server support?

SEMP answers these questions through two complementary methods: DNS-based
discovery as the primary method, and a well-known URI as fallback. Results are
cached to avoid redundant lookups. Discovery is performed entirely by the
sender's server. Clients are not involved.

### 1.1 Discovery Is a Server Responsibility

Per the connection model defined in `HANDSHAKE.md` section 1.2,
clients only connect to their own home server. Cross-domain delivery is
server-to-server. Discovery is therefore always performed by the sender's server
on behalf of the sending user. A client never performs cross-domain discovery
directly.

### 1.2 Privacy Constraint

Discovery requests MUST be anonymous by default. A lookup request MUST NOT
identify the requester or the sender whose message prompted the lookup. The
lookup reveals only that someone on the querying server intends to send to
someone on the target domain, but not who, and not about what.

Authenticated discovery is available as an optional extension. Servers MAY
rate-limit anonymous discovery requests. See section 6.2.

---

## 2. DNS-Based Discovery

DNS is the primary discovery method. It requires no active connection to the
target domain and benefits from DNS caching infrastructure.

### 2.1 SRV Records

SEMP servers are advertised via DNS SRV records under `_semp._tcp.<domain>`:

```
_semp._tcp.example.com.  3600  IN  SRV  10  10  443  semp.example.com.
```

Standard SRV semantics apply: lower priority values are preferred, weight
controls load distribution among servers of equal priority.

### 2.2 TXT Capability Record

A companion TXT record advertises the server's SEMP capabilities:

```
_semp._tcp.example.com.  3600  IN  TXT  "v=semp1;s=pq-kyber768-x25519,x25519-chacha20-poly1305;c=h2,ws,quic;mes=26214400"
```

| Parameter | Description                                                        |
|-----------|--------------------------------------------------------------------|
| `v`       | SEMP protocol version. MUST be present. Current value: `semp1`.   |
| `s`       | Supported cryptographic suites, comma-separated, in preference order. Suite identifiers are defined in `ENVELOPE.md` section 7. `x25519-chacha20-poly1305` (baseline) MUST be present. `pq-kyber768-x25519` (post-quantum hybrid) is RECOMMENDED. |
| `c`       | Supported transports, comma-separated. Values: `h2`, `ws`, `quic`. `h2` MUST be present (mandatory baseline transport per `TRANSPORT.md` section 4). |
| `mes`     | Maximum accepted envelope size in bytes. Senders MUST NOT transmit envelopes exceeding this value. |

Implementations MUST treat unknown parameters as ignored rather than as errors,
consistent with the extensibility principle.

### 2.3 Multiple Servers Per Domain

A domain may operate multiple SEMP servers for load balancing, geographic
distribution, or high availability via multiple SRV records:

```
_semp._tcp.example.com.  3600  IN  SRV  10  50  443  semp-east.example.com.
_semp._tcp.example.com.  3600  IN  SRV  10  50  443  semp-west.example.com.
_semp._tcp.example.com.  3600  IN  SRV  20  100 443  semp-backup.example.com.
```

Servers at priority 10 share traffic according to their weights (50/50 here).
The priority 20 server receives traffic only if all priority 10 servers are
unreachable.

### 2.4 User Partitioning

For large domains distributing users across multiple servers, SEMP supports
user partitioning via an additional TXT record:

```
_semp-partition.example.com.  3600  IN  TXT  "v=semp1;strategy=hash;servers=8;algorithm=sha256"
```

| Strategy | Description                                         | Leaks Existence |
|----------|-----------------------------------------------------|-----------------|
| `hash`   | `hash(username) mod N` determines the server index. | No              |
| `alpha`  | Alphabetical ranges mapped to specific servers.     | No              |
| `lookup` | A partition server must be queried for the mapping. | Yes, unless authenticated. |

The `hash` strategy is RECOMMENDED. It is deterministically computable by
any party from the address alone, so it leaks no information beyond what
the address itself already carries.

The `alpha` strategy is PERMITTED and leaks only the alphabetical bucket
of the recipient, which is a weak signal roughly equivalent to the first
letter of the username.

The `lookup` strategy requires a partition server to resolve each address
to a specific delivery server. A server that answers lookup queries
reveals, by construction, whether a given address exists on the domain.
This is an address harvesting surface. Operators SHOULD NOT use the
`lookup` strategy. Operators that MUST use it (for deployments where
neither hash nor alpha partitioning is operationally feasible) MUST
follow the authenticated-lookup requirement in section 2.4.4.

#### 2.4.1 Hash Partitioning

The sending server computes:

```
server_index = SHA-256(username@domain) mod number_of_servers
```

And maps the index to a server via additional SRV records published under
`_semp-partition-<index>.example.com`.

#### 2.4.2 Alpha Partitioning

```
_semp-partition-a-f.example.com.  3600  IN  SRV  10  10  443  semp-1.example.com.
_semp-partition-g-m.example.com.  3600  IN  SRV  10  10  443  semp-2.example.com.
_semp-partition-n-s.example.com.  3600  IN  SRV  10  10  443  semp-3.example.com.
_semp-partition-t-z.example.com.  3600  IN  SRV  10  10  443  semp-4.example.com.
```

#### 2.4.3 Lookup Partitioning

When `strategy=lookup`, the sending server first queries a designated partition
server to resolve which delivery server handles the target user. The partition
server address is published as a separate SRV record:

```
_semp-partition-lookup.example.com.  3600  IN  SRV  10  10  443  partition.example.com.
```

#### 2.4.4 Authenticated Lookup Requirement

A partition server that implements the `lookup` strategy MUST require
authenticated discovery per section 6.2 for every query. Anonymous lookup
queries MUST be rejected with a generic response that is indistinguishable
for valid and invalid addresses.

A conformant partition server MUST:

- Verify the `semp.dev/auth` signature on every lookup request before
  returning per-address routing information.
- Apply per-requester rate limits with per-domain reputation budgeting
  per section 6.2.
- Log every authenticated query with the requester domain, query
  timestamp, and address count for audit purposes.
- Return a generic negative response for addresses that do not exist,
  indistinguishable in structure, size, and timing from responses for
  existing addresses.

A partition server MUST NOT return per-address routing information to
anonymous requests. Operators that wish to serve anonymous requests
MUST use `hash` or `alpha` partitioning instead.

The lookup query is additionally subject to the anonymity constraints in
section 1.2: the querying server MUST NOT reveal the sender's identity
(the specific user on whose behalf the query is issued) in the partition
lookup request, even when authenticating at the domain level.

---

## 3. Well-Known URI Discovery

When DNS records are absent or unreachable, the sender's server falls back to
fetching the well-known configuration URI. The bootstrapping path is fixed:

```
https://<hostname>/.well-known/semp/configuration
```

The hostname is determined by DNS SRV resolution (section 5.5) or, when no SRV
records exist, the email domain itself. This path MUST be served over HTTPS.
Servers MUST NOT serve it over plain HTTP. The HTTPS certificate chain is the
trust anchor for the response contents.

The response is a JSON configuration document that describes the server's
capabilities, transport endpoints, API endpoints, and supported extensions.
All URL values inside the document are implementation-chosen.

```json
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
        "device_register": "https://semp.example.com/v1/device/register",
        "blocklist": "https://semp.example.com/v1/blocklist",
        "keys": "https://semp.example.com/v1/keys/",
        "domain_keys": "https://semp.example.com/v1/domain-keys",
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
```

### 3.1 Configuration Document Fields

| Field         | Type      | Required | Description                                                                  |
|---------------|-----------|----------|------------------------------------------------------------------------------|
| `type`        | `string`  | Yes      | MUST be `"SEMP_CONFIGURATION"`.                                              |
| `version`     | `string`  | Yes      | SEMP protocol version supported (semver).                                    |
| `domain`      | `string`  | Yes      | The email domain this server operates for.                                   |
| `revision`    | `integer` | Yes      | Monotonically non-decreasing revision number. See section 3.5.               |
| `ttl_seconds` | `integer` | Yes      | Operator-advised cache lifetime for this document in seconds. See section 3.5.|
| `endpoints`   | `object`  | Yes      | All discoverable endpoints. See section 3.1.1.                               |
| `suites`      | `array`   | Yes      | Cryptographic suite identifiers in preference order. See section 3.1.2.      |
| `limits`      | `object`  | Yes      | Operational limits. See section 3.1.3.                                       |
| `extensions`  | `array`   | No       | Supported extensions. See section 3.1.4.                                     |

Implementations MUST ignore unknown fields rather than failing, consistent with
the extensibility principle.

#### 3.1.1 Endpoints

The `endpoints` object contains all URLs a client or federation peer needs.
Transport endpoints (which carry SEMP sessions) are grouped by role; API
endpoints (which are plain HTTPS) are flat.

| Field              | Type     | Required | Description                                  |
|--------------------|----------|----------|----------------------------------------------|
| `client`           | `object` | Yes      | Transport endpoints for client sessions. Map of transport identifier (`h2`, `ws`, `quic`) to URL. `h2` MUST be present. |
| `federation`       | `object` | Yes      | Transport endpoints for federation sessions. Same structure as `client`. `h2` MUST be present. |
| `register`         | `string` | Yes      | URL for client key registration (`POST`). See `CLIENT.md` section 2.2.1. |
| `device_register`  | `string` | No       | URL for delegated device registration (`POST`). See `KEY.md` section 10. |
| `blocklist`        | `string` | No       | URL for block list management (`GET`/`POST`/`DELETE`). See `DELIVERY.md` section 5. |
| `keys`             | `string` | Yes      | Base URL for user key publication. Append the user address to retrieve keys. Response format in section 3.4. |
| `domain_keys`      | `string` | Yes      | URL for domain signing and encryption key publication. Response format in section 3.3. |
| `reputation`       | `string` | No       | Base URL for this server's published trust gossip observations. Append the subject domain to retrieve observations. Absence indicates the server does not publish gossip. See `REPUTATION.md` section 5. |
| `reputation_references` | `string` | No  | URL for the domain's self-published reputation references document, listing third-party observers that have published observations about this domain. Absence indicates the domain does not self-publish references. See `REPUTATION.md` section 5.6. |
| `verify`           | `string` | No       | Base URL for domain-ownership verification tokens used during federation handshakes. Append the verification token to retrieve the ownership proof. Absence indicates the server does not support well-known URI verification and relies on certificate or DNS TXT verification instead. See `HANDSHAKE.md` section 5.3. |
| `reputation_transfer` | `string` | No    | Base URL for trust-transfer records published when a domain changes ownership. Append `out` or `in` to retrieve the outgoing or incoming transfer record. Absence indicates the domain does not publish transfer records. See `REPUTATION.md` section 11. |
| `backup`           | `string` | No       | Base URL for server-assisted account recovery backups. Append the URL-encoded user address to address a specific account. Accepts `POST` (upload), `GET` (download), and `DELETE`. Absence indicates the server does not host recovery backups. See `RECOVERY.md` section 4.1. |
| `migration`        | `string` | No       | Base URL for provider migration records. Accepts `POST` (submit a cross-signed record), `GET <record_id>` (fetch a specific record), and `GET ?address=<user@domain>` (list records for a user). Absence indicates the server does not participate in cooperative migration. See `MIGRATION.md` section 3.4. |
| `transparency_log` | `string` | No       | Base URL for the domain's key transparency log. Serves STHs, inclusion proofs, consistency proofs, and leaf ranges. Absence indicates the domain does not support key transparency. See `TRANSPARENCY.md` section 2.4. |
| `attachment_storage` | `string` | No     | Base URL for operator-hosted blob storage used by the `semp.dev/large-attachment` wire extension. Absence indicates the operator does not host blob storage for its users. See `ATTACHMENTS.md` section 4.3. |

All URL values are implementation-chosen. The protocol does not mandate URL path
structure. The transport identifiers in `client` and `federation` are defined in
`TRANSPORT.md` section 4: `h2`, `ws`, `quic`.

#### 3.1.2 Suites

The `suites` array lists the cryptographic suite identifiers the server supports,
in preference order (most preferred first). Suite identifiers are defined in
`ENVELOPE.md` section 7.

The array MUST contain at least `x25519-chacha20-poly1305` (the baseline suite
required for interoperability). `pq-kyber768-x25519` (post-quantum hybrid) is
RECOMMENDED.

#### 3.1.3 Limits

The `limits` object declares operational constraints.

| Field              | Type      | Required | Description                                    |
|--------------------|-----------|----------|------------------------------------------------|
| `max_envelope_size`| `integer` | Yes      | Maximum accepted envelope size in bytes. Senders MUST NOT transmit envelopes exceeding this value. |

Future protocol versions MAY introduce additional limit fields.

#### 3.1.4 Extensions

The `extensions` array lists protocol extensions the server supports. Each
entry declares the extension identifier and whether the connecting party MUST
support it to interoperate.

```json
"extensions": [
    {
        "id": "semp.dev/large-attachment",
        "required": false
    },
    {
        "id": "vendor.example.com/example-extension",
        "required": true
    }
]
```

| Field      | Type      | Required | Description                                     |
|------------|-----------|----------|-------------------------------------------------|
| `id`       | `string`  | Yes      | Extension identifier per `EXTENSIONS.md`.       |
| `required` | `boolean` | Yes      | If `true`, a connecting party that does not recognize this extension MUST NOT proceed with the connection. If `false`, the extension is informational and MAY be ignored. |

An empty array indicates no extensions are advertised.

### 3.2 What Is and Is Not Mandated

The configuration document separates what the protocol fixes from what
implementations choose.

Fixed by the protocol:

- The bootstrapping path `/.well-known/semp/configuration` is fixed and MUST NOT
  vary across implementations.
- The document MUST be served over HTTPS.
- The `endpoints.client` and `endpoints.federation` objects MUST each contain at
  least an `h2` entry (the mandatory baseline transport per `TRANSPORT.md`
  section 4).
- The `endpoints.register`, `endpoints.keys`, and `endpoints.domain_keys` fields
  MUST be present.
- The `suites` array MUST contain at least `x25519-chacha20-poly1305`.
- The `limits.max_envelope_size` field MUST be present.

Chosen by the implementation:

- All URL values (paths, subdomains, port numbers) are implementation-chosen.
  The protocol does not mandate URL path structure.
- The hostname may differ from the email domain (see section 5.5).
- Which additional transports, suites, and extensions to support beyond the
  mandatory baselines is operator-chosen.

This split exists so that the bootstrapping flow is deterministic (every SEMP
client knows exactly where to find the configuration), while the operational
deployment remains flexible (operators choose their own URL layout, subdomain
structure, and capability support).

#### 3.2.1 Configuration Is the Sole Endpoint Registry

The configuration document is the single source of truth for every endpoint
exposed by a SEMP server. The path `/.well-known/semp/configuration` is the
only fixed URL in the protocol. Every other endpoint, including transport
endpoints, registration, key publication, block list management, reputation
publication, and any endpoint added by future protocol revisions or
extensions, is whatever URL the configuration document advertises.

The following normative rules apply:

- A SEMP server MUST NOT expose a protocol endpoint that is not advertised
  in its configuration document. Endpoints that exist only by convention
  or only at well-known paths are not discoverable and MUST NOT be assumed
  by peers.
- A SEMP client or federation peer MUST NOT probe well-known or guessed
  paths for functionality that is not advertised in the target server's
  configuration document. The absence of a field in `endpoints` is
  definitive: the capability is not offered, regardless of what path
  conventions other implementations may follow.
- A SEMP server MAY place any advertised endpoint at any URL it chooses,
  including under `/.well-known/`, on a different hostname, on a different
  port, or behind a reverse proxy. Peers locate the URL through the
  configuration document, not through a path convention.

This invariant eliminates ambiguity about optional capabilities, allows
operators to route specific endpoints through dedicated infrastructure,
and ensures that the absence of a capability is always an explicit
signal rather than a probing failure.

### 3.3 Domain Key Publication

SEMP servers MUST publish their domain signing and encryption keys at the
URL advertised as `endpoints.domain_keys` in their configuration document
(section 3.1.1). The endpoint MUST be served over HTTPS. The response is a
JSON document:

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

| Field            | Type     | Required | Description                                      |
|------------------|----------|----------|--------------------------------------------------|
| `type`           | `string` | Yes      | MUST be `"SEMP_DOMAIN_KEYS"`                     |
| `version`        | `string` | Yes      | SEMP protocol version (semver)                   |
| `domain`         | `string` | Yes      | The email domain this server operates for         |
| `signing_key`    | `object` | Yes      | The domain's Ed25519 signing public key           |
| `encryption_key` | `object` | Yes      | The domain's encryption public key                |

Each key object contains `algorithm`, `public_key` (base64-encoded), and `key_id`
(SHA-256 fingerprint of the raw public key bytes, hex-encoded).

Federation peers fetch this endpoint to obtain the domain signing key needed
to verify handshake signatures. The HTTPS certificate chain serves as the trust
anchor: if the TLS certificate is valid for the hostname, the domain keys it
publishes are trusted.

### 3.4 User Key Publication

SEMP servers MUST publish registered user keys under the base URL advertised
as `endpoints.keys` in their configuration document (section 3.1.1). The full
fetch URL for a given user is the base URL with the user's address appended:

```
<endpoints.keys><address>
```

The endpoint MUST be served over HTTPS. The response is a JSON document
containing the user's identity and encryption public keys. See `KEY.md`
section 3 for the response format and verification requirements.

### 3.5 Configuration Versioning and Updates

A SEMP configuration document changes over time: endpoints move,
cryptographic suites are added or deprecated, limits are adjusted,
extensions are added or withdrawn. Peers and clients that cache the
configuration need a reliable way to detect change, know when to
re-fetch, and recognize out-of-order or rolled-back revisions.

#### 3.5.1 Revision Field

The configuration document's `revision` field is a monotonically
non-decreasing integer. Operators MUST increment `revision` on any
byte-level change to the configuration document they publish.
Operators MUST NOT decrement `revision`, MUST NOT reuse a previously
published `revision` value for a different document, and MUST NOT
reset `revision` when rotating other state (such as domain keys).

Rationale: a strict monotonic counter gives cached peers an
unambiguous comparison. A peer holding cached revision N that
subsequently fetches revision M where M < N MUST treat the fetch as
suspicious (attacker serving stale or forged config, operator
misconfiguration, transport corruption). The peer MUST NOT replace
its cached copy on such a fetch. The peer SHOULD log the anomaly and
MAY retry via a different transport (DNS, alternate IP) before
accepting any update.

If an operator needs to republish the same configuration content, the
operator MUST still increment `revision`. Republishing identical
bytes with the same revision is permitted but discouraged because it
makes change detection ambiguous.

#### 3.5.2 TTL Field

The `ttl_seconds` field is the operator's advised cache lifetime for
the document. Cached peers MUST re-fetch the configuration when the
cache age exceeds `ttl_seconds`. Peers MAY re-fetch earlier.

`ttl_seconds` MUST be at least 60 and MAY be at most 604800 (one
week). The RECOMMENDED default is 3600 (one hour). Operators
anticipating frequent changes SHOULD use shorter TTLs; operators
with stable deployments MAY use longer TTLs up to the maximum.

`ttl_seconds` is independent of HTTP `Cache-Control` headers. A
conformant peer MUST respect `ttl_seconds` regardless of HTTP cache
hints. Operators MAY set HTTP cache headers consistently with
`ttl_seconds` for transport-layer correctness, but the application
MUST NOT defer to HTTP hints when they conflict with `ttl_seconds`.

#### 3.5.3 Mandatory Re-Fetch Triggers

A peer caching the configuration of a domain MUST re-fetch when any
of the following occurs, regardless of remaining TTL:

- The cache age exceeds `ttl_seconds` (section 3.5.2).
- The peer receives a `SEMP_CONFIGURATION_UPDATE` message on an
  active federation session for the domain (section 3.5.4).
- The peer receives a federation handshake init whose
  `peer_configuration_revision` differs from the cached revision
  (`HANDSHAKE.md` section 5.2).
- An operation the peer performs against the domain fails with a
  capability- or endpoint-mismatch error attributable to stale
  configuration (for example, `extension_unsupported` for a feature
  the peer's cached configuration shows as supported). The peer
  SHOULD re-fetch and retry once.

Re-fetch MUST follow the full discovery flow (DNS SRV resolution
first, well-known URI fallback) so that endpoint relocations are
discovered correctly.

#### 3.5.4 SEMP_CONFIGURATION_UPDATE Message

A SEMP server MAY notify its active federation peers when its
configuration has changed by sending a `SEMP_CONFIGURATION_UPDATE`
message over each live federation session:

```json
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
```

| Field         | Type      | Required | Description                                                                 |
|---------------|-----------|----------|-----------------------------------------------------------------------------|
| `type`        | `string`  | Yes      | MUST be `"SEMP_CONFIGURATION_UPDATE"`.                                      |
| `version`     | `string`  | Yes      | SEMP protocol version (semver).                                             |
| `domain`      | `string`  | Yes      | The domain whose configuration has changed.                                 |
| `revision`    | `integer` | Yes      | The new configuration revision the peer should expect on next fetch.        |
| `timestamp`   | `string`  | Yes      | ISO 8601 UTC timestamp of the notification.                                 |
| `signature`   | `object`  | Yes      | Domain-key signature over the canonical bytes of the message with `signature.value` set to `""`. |

The signature MUST be produced by the domain's currently published
signing key. Peers MUST verify the signature against the cached
domain key; if verification fails, the peer MUST discard the message
and MUST NOT re-fetch on its basis.

On receipt of a verified `SEMP_CONFIGURATION_UPDATE` whose `revision`
is strictly greater than the peer's cached revision, the peer MUST
re-fetch the configuration document before using any cached endpoint
or capability. A message whose `revision` equals or is less than the
peer's cached revision MUST be discarded silently.

The notification is a hint, not a guarantee. Peers MUST NOT depend
on receiving it; the mandatory re-fetch triggers in section 3.5.3
still apply. An operator who fails to send notifications remains
correct so long as they respect `ttl_seconds`; notifications are
purely a latency optimization.

#### 3.5.5 Handshake Revision Piggyback

Federation handshake init messages carry a
`peer_configuration_revision` field per `HANDSHAKE.md` section 5.2.
Each side's cached revision of the other side's configuration is
included. On handshake processing, each side compares the received
value to its own current revision. A mismatch (peer's expectation is
stale) triggers an out-of-band re-fetch by the mismatched side
before accepting the session for envelope delivery.

#### 3.5.6 Change Classification

All byte-level changes to the configuration increment `revision`.
The spec does not distinguish cosmetic changes from
operationally-significant ones; operators who alter whitespace or
comment-like extension metadata MUST still bump the counter. A
simpler rule is easier to implement correctly than a spec that asks
operators to classify their own changes.

Peers MAY compare fetched configurations field-by-field and choose
to defer cache replacement when the changes are immaterial to the
peer's use, but the protocol-level revision still advances.

#### 3.5.7 Fail-Closed on Fetch Failure

If a re-fetch triggered by any rule in section 3.5.3 fails
(network error, HTTP 5xx, signature mismatch on domain key lookup,
malformed document), the peer MUST NOT use the cached configuration
for new operations beyond the grace window defined by
`ttl_seconds`. Operations in-flight at the time of failure MAY
complete under the cached configuration; new operations MUST be
deferred until a successful re-fetch.

This fail-closed behavior prevents a peer from operating on
demonstrably stale configuration when the operator has signaled a
change.

---

## 4. Protocol Lookup

For cases where DNS and well-known URI are insufficient (such as determining
per-user capability or resolving a specific address on a partitioned domain),
SEMP defines an explicit protocol lookup exchange.

### 4.1 Lookup Request

```json
{
    "type": "SEMP_DISCOVERY",
    "step": "request",
    "version": "1.0.0",
    "id": "request-ulid",
    "timestamp": "2025-06-10T19:39:03Z",
    "addresses": [
        "user1@example.com",
        "user2@example.com"
    ],
    "extensions": {}
}
```

The request is anonymous. There is no `requester` field. The querying server
is identified only by the TLS connection from which the request originates,
which reveals the querying domain but not any individual user.

Servers MAY include noise addresses in the `addresses` array to reduce the
inferability of which specific address prompted the lookup. Implementations
SHOULD batch multiple pending lookups into a single request where possible.

### 4.2 Lookup Request Fields

| Field       | Type     | Required | Description                                                             |
|-------------|----------|----------|-------------------------------------------------------------------------|
| `type`      | `string` | Yes      | MUST be `"SEMP_DISCOVERY"`                                              |
| `step`      | `string` | Yes      | MUST be `"request"`                                                     |
| `version`   | `string` | Yes      | SEMP protocol version (semver)                                          |
| `id`        | `string` | Yes      | Unique request identifier. ULID RECOMMENDED.                            |
| `timestamp` | `string` | Yes      | ISO 8601 UTC timestamp.                                                 |
| `addresses` | `array`  | Yes      | One or more addresses to look up. MAY include noise addresses.          |
| `extensions`| `object` | No       | Extensions. Authenticated discovery MAY be declared here. See section 6.2. |

### 4.3 Lookup Response

```json
{
    "type": "SEMP_DISCOVERY",
    "step": "response",
    "version": "1.0.0",
    "id": "echoed-request-ulid",
    "timestamp": "2025-06-10T19:39:04Z",
    "results": [
        {
            "address": "user1@example.com",
            "status": "semp",
            "transports": ["ws", "h2", "quic"],
            "extensions": [
                "semp.dev/device-sync",
                "semp.dev/large-attachment"
            ],
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
```

### 4.4 Lookup Response Fields

| Field       | Type     | Required | Description                                                    |
|-------------|----------|----------|----------------------------------------------------------------|
| `type`      | `string` | Yes      | MUST be `"SEMP_DISCOVERY"`                                     |
| `step`      | `string` | Yes      | MUST be `"response"`                                           |
| `version`   | `string` | Yes      | SEMP protocol version (semver)                                 |
| `id`        | `string` | Yes      | Echo of the request `id`.                                      |
| `timestamp` | `string` | Yes      | ISO 8601 UTC timestamp.                                        |
| `results`   | `array`  | Yes      | One result object per queried address.                         |
| `signature` | `object` | Yes      | Signature over the response using the responding server's domain key. |
| `extensions`| `object` | No       | Response extensions.                                           |

### 4.5 Result Object Fields

| Field        | Type      | Required | Description                                                                 |
|--------------|-----------|----------|-----------------------------------------------------------------------------|
| `address`    | `string`  | Yes      | The queried address.                                                        |
| `status`     | `string`  | Yes      | One of the status values defined in section 4.6.                            |
| `transports` | `array`   | No       | Supported transports. Present when `status` is `semp` or `legacy`.          |
| `extensions` | `array`   | No       | Supported extension identifiers per `EXTENSIONS.md` section 6. Present only when `status` is `semp`. |
| `server`     | `string`  | No       | Hostname of the server handling this address. Present when `status` is `semp` or `legacy`. |
| `ttl`        | `integer` | Yes      | Seconds the result may be cached.                                           |

### 4.6 Result Status Values

| Status          | Meaning                                                                           |
|-----------------|-----------------------------------------------------------------------------------|
| `semp`          | The recipient domain supports SEMP. Handshake and envelope delivery may proceed.  |
| `legacy`        | The recipient domain does not support SEMP but has MX records. Client SMTP fallback is possible. |
| `not_found`     | The recipient domain supports neither SEMP nor SMTP. The domain cannot receive mail by any known method. |

These three statuses map directly to the submission response values in
`CLIENT.md` section 6.3: `semp` → proceed with SEMP delivery; `legacy` →
return `legacy_required` to client; `not_found` → return `recipient_not_found`
to client.

#### 4.6.1 Statuses Are Domain-Level

The status values defined in this section describe the **recipient domain's
capability**, not the existence of an individual address. Per-address
existence MUST NOT be inferred from the response.

A conformant server responding to `SEMP_DISCOVERY` MUST:

- Return the same `status`, `transports`, and `extensions` values for every
  address on the same recipient domain, regardless of whether the address
  corresponds to a registered user. An address that does not exist on a
  SEMP-supporting domain MUST still receive `status: "semp"`.
- Return identical `ttl` values for every address on the same recipient
  domain, to prevent timing-based enumeration across valid and invalid
  addresses.
- Return a `server` field that is either domain-level (the same hostname
  for every address on the domain) or derivable by the requester without
  server-side knowledge (for example, a hash-partitioned server index
  computable from the address per section 2.4). Per-user server
  assignments that require server-side lookup MUST NOT appear in
  responses to anonymous requests; see section 2.4 and section 6.2 for
  the authenticated-discovery requirement.
- Not include `recipient_status`, mailbox existence flags, account
  activity timestamps, or any other per-user signal in the result
  object. The result object fields defined in section 4.5 are exhaustive
  for anonymous discovery.

The only address-dependent field in a response MAY be the `address` field
itself, which echoes the queried address. Implementations MUST NOT use
the response to distinguish "this user exists" from "this user does not
exist."

This rule exists to prevent discovery from becoming an address harvesting
endpoint. Additional discussion appears in section 8.3.

The response MUST be signed by the responding server's domain key. The querying
server MUST verify this signature before caching or acting on the results.

---

## 5. Discovery Flow

### 5.1 Standard Flow

```
Sender's Server                                    Recipient's Domain
       |                                                   |
       |--- DNS SRV/TXT lookup for _semp._tcp.example.com->|
       |<-- DNS response -----------------------------------|
       |                                                   |
       |   (if DNS lookup yields no SEMP records)          |
       |--- HTTPS GET /.well-known/semp/configuration ---->|
       |<-- Capability document or 404 --------------------|
       |                                                   |
       |   (if well-known URI also yields no SEMP support) |
       |--- DNS MX lookup for example.com ---------------->|
       |<-- MX records or NXDOMAIN ------------------------|
       |                                                   |
       |   MX present  → outcome: legacy                   |
       |   No MX       → outcome: not_found                |
       |                                                   |
       |   (if SEMP found at any earlier step)             |
       |   (if per-user resolution needed)                 |
       |--- SEMP_DISCOVERY request ------------------------>|
       |<-- SEMP_DISCOVERY response ------------------------|
       |                                                   |
       |   (cache results per TTL)                         |
       |                                                   |
       |--- Proceed with SEMP delivery, or                 |
       |    return legacy_required / recipient_not_found -->|
       |    to client                                       |
```

### 5.2 Cached Flow

```
Sender's Server
       |
       |--- Check discovery cache (hit, within TTL)
       |
       |--- Proceed directly with handshake and delivery
```

### 5.3 Mixed Recipient Flow

When an envelope is addressed to recipients on multiple domains, discovery
is performed per domain. Results may differ across the three outcomes:

- `semp` domains: envelope delivered via SEMP
- `legacy` domains: `legacy_required` returned to client; client handles SMTP fallback per `CLIENT.md` section 6.4
- `not_found` domains: `recipient_not_found` returned to client; delivery is not possible

When a message has recipients across multiple outcomes, the server MUST return
per-recipient results in the submission response per `CLIENT.md` section 6.1.
The client MUST surface the per-recipient outcome to the user and MUST NOT
suppress partial failure or partial degradation information.

### 5.4 Same-Domain Multi-Server Flow

When a sender and recipient share a domain but are on different partition
servers, delivery routes internally:

```
Sender's Server A
       |
       |--- User directory lookup for recipient
       |--- Determine: recipient is on Server B
       |
       |--- Internal routing to Server B
       |--- Server B runs delivery pipeline (DELIVERY.md §3)
       |--- Server B returns acknowledgment to Server A
       |--- Server A surfaces result to client
```

Internal routing uses the `SEMP_INTERNAL_ROUTE` mechanism. The envelope is
not re-exposed externally. Internal server connections MUST be secured with
mutual TLS.

```json
{
    "type": "SEMP_INTERNAL_ROUTE",
    "to": "user@example.com",
    "internal_route": ["semp-east.example.com"],
    "timestamp": "2025-06-10T20:35:18Z",
    "envelope": {}
}
```

#### 5.4.1 Internal Route Acknowledgment

The receiving partition server MUST return an acknowledgment to the sending
partition server for every internally routed envelope. The acknowledgment types
are identical to those defined in `DELIVERY.md` section 1: `delivered`,
`rejected`, or `silent`. The same semantics, obligations, and privacy
considerations apply. Internal routing does not exempt an envelope from delivery
policy enforcement.

The receiving partition server MUST execute the full delivery pipeline defined
in `DELIVERY.md` section 3 before returning an acknowledgment. This includes
seal verification, session validation, domain and server policy checks, `brief`
decryption, and user policy checks. Block list enforcement occurs on the
receiving partition server (the server that holds the recipient's block list)
-- not on the sending partition server.

The internal route response carries the same structure as a cross-domain
delivery acknowledgment:

```json
{
    "type": "SEMP_INTERNAL_ROUTE",
    "step": "acknowledgment",
    "version": "1.0.0",
    "envelope_id": "postmark-ulid",
    "to": "user@example.com",
    "status": "rejected",
    "reason_code": "blocked",
    "reason": "Delivery refused by recipient policy.",
    "timestamp": "2025-06-10T20:35:19Z"
}
```

| Field         | Type           | Required | Description                                                             |
|---------------|----------------|----------|-------------------------------------------------------------------------|
| `type`        | `string`       | Yes      | MUST be `"SEMP_INTERNAL_ROUTE"`                                         |
| `step`        | `string`       | Yes      | MUST be `"acknowledgment"`                                              |
| `version`     | `string`       | Yes      | SEMP protocol version (semver).                                         |
| `envelope_id` | `string`       | Yes      | The `postmark.id` of the routed envelope.                               |
| `to`          | `string`       | Yes      | The recipient address this acknowledgment applies to.                   |
| `status`      | `string`       | Yes      | One of: `delivered`, `rejected`, `silent`.                              |
| `reason_code` | `string\|null` | No       | Machine-readable reason. Present when `status` is `rejected`.           |
| `reason`      | `string\|null` | No       | Human-readable description. Present when `reason_code` is present.      |
| `timestamp`   | `string`       | Yes      | ISO 8601 UTC timestamp.                                                 |

The sending partition server MUST forward the acknowledgment to the client
in the submission response per `CLIENT.md` section 6.1. The sending partition
server MUST NOT override or suppress the receiving server's acknowledgment.

When the receiving partition server operates in `silent` mode for a given
sender, it MUST maintain the same consistent timing requirements defined in
`DELIVERY.md` section 8.2. The sending partition server MUST enforce a timeout
on internally routed deliveries and treat expiry as `silent`, consistent with
`DELIVERY.md` section 1.5. A timeout of 30 seconds is RECOMMENDED.

#### 5.4.2 Block List Isolation

The recipient's block list is held by the receiving partition server. The
sending partition server MUST NOT access, query, or cache the recipient's block
list. Block list confidentiality requirements from `DELIVERY.md` section 8.1
apply across partition boundaries within the same domain.

### 5.5 SRV Target and Configuration Host Resolution

When DNS SRV resolves a domain to a target hostname (e.g. `_semp._tcp.example.com`
resolves to `semp.example.com`), the configuration document is fetched from the
SRV target, not from the email domain:

```
GET https://<srv-target>/.well-known/semp/configuration
```

All subsequent operations (domain key fetch, user key fetch, reputation fetch,
federation handshake, and any other endpoint) use the URLs advertised in the
configuration document. Those URLs are implementation-chosen and need not
share the hostname or path of the configuration document.

Using the SRV target for the configuration fetch is necessary because the
email domain (e.g. `example.com`) may not host the SEMP server directly.
The SRV record is the authoritative mapping from the email domain to the
configuration host.

When SRV lookup fails or returns no records, the email domain is used as the
hostname (the well-known URI fallback path in section 3).

### 5.6 Federation Endpoint Resolution

When a server needs to open a federation session to a peer domain, it
resolves the federation endpoint exclusively from the peer's configuration
document. The procedure is:

1. If a static endpoint is configured for the peer by operator policy, use
   it directly.
2. Otherwise, resolve the peer's configuration document per section 3 and
   read `endpoints.federation.<transport>` for the transport selected
   during negotiation. The `h2` entry MUST be present in every conformant
   configuration and serves as the baseline fallback when the preferred
   transport is unavailable.

Servers MUST NOT derive federation endpoints by path manipulation or by
guessing based on other advertised URLs. The absence of a configuration
document means the peer is not a conformant SEMP server and federation is
not possible.

### 5.7 Automatic Peer Discovery

Servers MUST NOT require pre-configured peer lists for federation. When a
server receives an envelope addressed to a recipient on an unknown domain,
it MUST attempt discovery for that domain using the standard flow (section 5.1).
If the domain is discovered to support SEMP, the server MUST proceed with
federation handshake and envelope forwarding.

This means any two SEMP servers with correctly configured DNS SRV/TXT records
and a published configuration document can federate without prior
arrangement. The domain signing key needed for the federation handshake is
fetched from the peer's `endpoints.domain_keys` URL and cached locally.

---

## 6. Caching

### 6.1 Caching Rules

Discovery results MUST be cached per the TTL returned in the response or DNS
record. Caching reduces lookup overhead and, by decoupling fetches from
individual send events, reduces intent leakage.

| Result type           | Default TTL when none provided | TTL source                                |
|-----------------------|-------------------------------|-------------------------------------------|
| `semp`                | 1 hour                        | DNS TTL or lookup response                |
| `legacy`              | 24 hours                      | DNS TTL or lookup response                |
| `not_found`           | 1 hour                        | DNS TTL or lookup response                |
| Configuration document| 1 hour                        | `ttl_seconds` field in the document (§3.5)|

Implementations MUST:
- Respect TTL values from DNS and lookup responses.
- Respect `ttl_seconds` from cached configuration documents per section 3.5.2.
- Invalidate cache entries on delivery failure and re-discover before retry.
- Re-fetch configuration per the mandatory triggers in section 3.5.3.
- Not serve stale entries beyond their TTL.

Implementations SHOULD:
- Perform discovery speculatively for frequently contacted domains, independent
  of pending sends, to decouple lookup timing from communication intent.
- Encrypt cached discovery results at rest.

### 6.2 Authenticated Discovery

#### 6.2.1 Purpose

Authenticated discovery allows a querying server to cryptographically
identify itself to the target server at the application layer. The
querying server signs each request with its domain signing key; the
target verifies the signature against the querying server's published
domain key.

Authentication is a rate-limiting, audit, and reputation tool. It is not
an access control gate. With the exception of partition lookup queries
(section 2.4.4), servers MUST NOT require authenticated discovery as a
condition of SEMP interoperability. An anonymous request from an unknown
domain MUST still receive a valid response, subject to the rate limits
defined in section 6.2.4.

#### 6.2.2 Request Signature Format

Authenticated discovery is declared via a reserved extension in the
`extensions` field of the `SEMP_DISCOVERY` request:

```json
"extensions": {
    "semp.dev/auth": {
        "method": "domain_key",
        "key_id": "querying-server-domain-key-fingerprint",
        "signature": "base64-signature-over-canonical-request"
    }
}
```

| Field       | Type     | Required | Description                                                              |
|-------------|----------|----------|--------------------------------------------------------------------------|
| `method`    | `string` | Yes      | Authentication method. MUST be `"domain_key"` for this version.          |
| `key_id`    | `string` | Yes      | SHA-256 fingerprint of the querying server's domain signing key.         |
| `signature` | `string` | Yes      | Base64-encoded signature over the canonical form of the request.         |

The signature MUST cover the canonical JSON form of the request with the
`signature` field excluded from the canonical form. The canonical form is
computed per `ENVELOPE.md` section 4.3 (JCS-style canonicalization,
sorted keys, no insignificant whitespace).

#### 6.2.3 Verification

A target server that receives an authenticated request MUST:

1. Extract the `key_id` from `extensions["semp.dev/auth"]`.
2. Resolve the querying server's domain (from the TLS connection or from
   a domain supplied in the signature header, as operator policy
   permits) to its configuration document.
3. Fetch the domain keys from `endpoints.domain_keys` and locate the key
   matching `key_id`.
4. Recompute the canonical form of the request with the `signature`
   field excluded.
5. Verify the signature against the resolved public key.
6. Reject the request if the signature is invalid, the key is unknown,
   the domain key is revoked, or the `timestamp` is outside the clock
   tolerance defined in `CONFORMANCE.md` section 9.3.1.

An authenticated request whose signature fails verification MUST be
treated as if it were anonymous for the purpose of rate limiting and
policy, and the verification failure MUST be logged. Target servers
SHOULD NOT return signature-specific error codes; failed authentication
reduces to "you are treated as anonymous" rather than producing a
distinguishable error, so that authentication is never a side channel
for probing the target's policy.

#### 6.2.4 Rate Limiting Tiers

A conformant server SHOULD apply different rate limits based on the
requester's authentication status and reputation:

| Requester class                                             | Recommended limit                                        |
|-------------------------------------------------------------|----------------------------------------------------------|
| Anonymous (no signature)                                    | Strict. RECOMMENDED ceiling: 10 lookup addresses per minute per source network prefix. |
| Authenticated, zero reputation                              | Moderate. RECOMMENDED ceiling: 100 lookup addresses per minute per requester domain. |
| Authenticated, established reputation                       | Operator-policy-driven. RECOMMENDED ceiling: 10,000 lookup addresses per minute per requester domain. |
| Authenticated, `hostile` or throttled reputation            | Below the anonymous tier, or rejected with `rate_limited`. |

Rate limits MUST be enforced per requester identity (domain for
authenticated requests, network prefix for anonymous requests). A server
that cannot accurately distinguish requesters (for example, behind a
NAT) MUST apply the most restrictive applicable tier.

Anonymous rate limit exhaustion MUST result in a response with
`reason_code: "rate_limited"` or an equivalent soft-fail, not a silent
drop. Silent drops defeat the explicit-rejection principle
(`DESIGN.md` section 2.3).

#### 6.2.5 Reputation Integration

A target server MAY record authenticated discovery patterns per
requester domain and publish observations under `protocol_abuse`
(`REPUTATION.md` section 3.4) when a requester exhibits harvesting
behavior. Patterns that justify an observation include:

- Sustained query volume across a window broader than the requester's
  plausible correspondence footprint.
- High ratio of unique queried addresses to successful subsequent
  envelope deliveries.
- Queries that systematically probe common username patterns against
  the target's address space.

Authenticated discovery makes these patterns attributable. Anonymous
discovery, even at its strict rate limit, cannot be attributed beyond
the network layer and cannot feed into reputation observations about
specific peer domains.

#### 6.2.6 Authorization Scope

Authentication identifies the querying **server domain**, not the user
on whose behalf the query is made. A conformant server MUST NOT
interpret authenticated discovery as an identification of an individual
user. Queries remain anonymous at the user level even when
authenticated at the server level, consistent with the privacy
constraints in section 1.2.

---

## 7. Legacy Integration

### 7.1 Discovery Outcome Resolution

When SEMP discovery fails for a recipient domain (no `_semp._tcp` SRV records
found and the well-known URI returns a 404 or non-SEMP document), the sender's
server MUST NOT immediately treat the recipient as unreachable. It MUST perform
a secondary SMTP capability check before resolving the final discovery outcome.

The three possible outcomes are:

| Outcome     | Condition                                                          | Submission status returned to client |
|-------------|--------------------------------------------------------------------|------------------------------------|
| `semp`      | SEMP records found.                                                | Proceed with SEMP delivery.        |
| `legacy`    | No SEMP records. MX records exist for the domain.                  | `legacy_required`                  |
| `not_found` | No SEMP records. No MX records. Domain cannot receive mail.        | `recipient_not_found`              |

### 7.2 SMTP Capability Check

When SEMP discovery yields no result, the sender's server MUST query DNS for
MX records on the recipient domain:

```
dig MX example.com
```

If one or more MX records are present, the domain is capable of receiving SMTP
mail. The discovery outcome is `legacy` and the server returns `legacy_required`
to the client per `CLIENT.md` section 6.3.

If no MX records are present, the domain cannot receive mail by any known
method. The discovery outcome is `not_found` and the server returns
`recipient_not_found` to the client.

The SMTP capability check is a DNS-only operation. The sender's server MUST NOT
attempt an SMTP connection to the recipient domain during discovery. The MX
record is sufficient confirmation that SMTP delivery is possible.

**Domain-level confirmation only.** A `legacy` outcome means the domain has
MX records and can receive SMTP mail. It does not confirm that the specific
recipient address exists on that domain. Per-address validation is not possible
without opening an SMTP connection and issuing a RCPT TO command, which this
spec does not do during discovery. The client will discover invalid addresses
the same way any SMTP sender does: a 550 rejection or a bounce during the
actual send attempt. This is expected behavior and consistent with how SMTP
operates today.

### 7.3 Caching Legacy and Not-Found Results

Legacy and not-found outcomes MUST be cached separately, as their TTLs reflect
different conditions:

| Outcome     | Default TTL when none provided | Rationale                                          |
|-------------|--------------------------------|----------------------------------------------------|
| `legacy`    | 24 hours                       | MX records are stable. Re-checking frequently adds no value. |
| `not_found` | 1 hour                         | The domain may publish records at any time. Check more often. |

Servers SHOULD re-check `not_found` domains more aggressively than `legacy`
domains, as a `not_found` result may resolve quickly if the operator is in the
process of setting up their mail infrastructure.

### 7.4 SEMP Capability Declaration

A domain declares SEMP support by publishing DNS records or a well-known URI.
The absence of these records is not itself a signal about SMTP capability --
it means only that SEMP is not supported. Legacy capability is determined
independently via MX record lookup per section 7.2.

---

## 8. Security Considerations

### 8.1 Response Authenticity

Lookup responses MUST be signed by the responding server's domain key. The
querying server MUST verify this signature before caching or acting on results.
An unsigned or unverifiable response MUST be discarded.

DNS responses are not signed at the application layer. DNSSEC is RECOMMENDED
for domains that publish SEMP SRV and TXT records to prevent spoofing at the
DNS layer.

### 8.2 Spoofing Prevention

A malicious DNS response or tampered well-known URI could redirect delivery to
a rogue server. Mitigations:

- DNSSEC for DNS record integrity
- HTTPS with valid certificates for well-known URI
- Signed lookup responses verified against the domain's published key
- Cross-checking: if DNS and well-known URI disagree, the discrepancy SHOULD
  be flagged and MAY trigger a re-query before delivery proceeds

### 8.3 Address Harvesting

The discovery endpoint is a potential address harvesting surface. An abuser
submits candidate addresses and observes which ones receive differential
responses to enumerate the recipient domain's user base.

Hashing addresses at the wire layer does not prevent harvesting. The
practical email address space is dictionary-attackable (names and common
patterns cover most real addresses), and any response the target server
can compute from plaintext addresses it can equally compute from hashed
addresses. Hashing only reduces collateral exposure in operational logs,
which is a separate concern addressed in section 8.3.4.

The protocol-level defenses against harvesting are layered:

#### 8.3.1 Domain-Level Statuses Are Mandatory

The status values defined in section 4.6 describe the recipient domain's
capability, not per-user existence. A conformant server MUST return
identical responses for every address on the same domain regardless of
whether the address corresponds to a registered user. This is the
primary mechanical defense: if responses cannot differentiate existing
from non-existing addresses, harvesting via the standard discovery
endpoint is not possible.

#### 8.3.2 Partition Lookup Requires Authentication

The `lookup` partition strategy (section 2.4) resolves addresses to
specific delivery servers and necessarily reveals address existence. A
partition server MUST require authenticated discovery (section 6.2) for
every lookup query and MUST return a generic response that is
indistinguishable for valid and invalid addresses to anonymous queries.
Authenticated queries are attributable to a specific requester domain,
which enables reputation-based defenses against harvesting.

Operators are strongly encouraged to use `hash` or `alpha` partitioning
instead, both of which are deterministically computable by the requester
without server-side lookup and therefore leak no information.

#### 8.3.3 Rate Limiting and Reputation

Anonymous discovery MUST be rate-limited per section 6.2.4. Authenticated
discovery MUST be attributable to a requester domain and MUST feed into
reputation observations per section 6.2.5. A requester that exhibits
sustained harvesting patterns becomes subject to `protocol_abuse`
observation records (`REPUTATION.md` section 3.4), which peers observe
and can act on.

Attribution is the practical constraint on harvesters. An abuser
unwilling to burn a domain's reputation cannot sustain harvesting under
authenticated discovery; an abuser willing to burn domains must do so
one at a time, raising the per-harvested-address cost substantially
above what anonymous probing offers.

#### 8.3.4 Operational Log Hygiene

Servers SHOULD hash plaintext addresses before writing them to access
logs, audit logs, telemetry pipelines, or any other operational data
that is not the protocol state itself. The hashing is for operational
privacy, not enumeration resistance: it keeps personal data out of
surfaces that are not always reviewed for disclosure risk (CDN logs,
request traces, debugging captures, snapshot backups). The
recommendation does not change the wire protocol.

#### 8.3.5 What This Does Not Prevent

The defenses above raise the cost of harvesting substantially but do not
eliminate it. A motivated attacker with a wordlist, willing to
authenticate and accept reputational cost, can still enumerate addresses
on a lookup-partitioned domain. Operators who require stronger
guarantees than the protocol provides should use hash or alpha
partitioning (eliminating the lookup surface entirely) or deploy
additional defenses at the operational layer (token-gated access,
invitation-only user visibility, or similar application-level
mechanisms).

### 8.4 Intent Leaking

Discovery reveals that the querying domain intends to send to the target domain.
Mitigations:

- Speculative batch caching decouples lookup timing from send intent
- Noise addresses in lookup requests reduce per-address inferability
- Proxy discovery through a trusted intermediary

---

## 9. Privacy Considerations

The lookup request reveals the querying server's domain to the target domain.
It does not reveal the sender's identity or the specific recipient within the
domain when noise addresses are used.

The DNS SRV/TXT lookup reveals the querying server's IP to the DNS resolver.
Implementations MAY use DNS-over-HTTPS or DNS-over-TLS to reduce this exposure.

Speculative caching is the most effective privacy mitigation at the discovery
layer. By fetching and refreshing capability records on a schedule independent
of pending messages, the timing correlation between a lookup and a subsequent
message is broken.

---

## 10. Relationship to Other Specifications

| Specification | Relationship |
|---|---|
| `DESIGN.md` | Governing principles. Anonymous-by-default constraint implements section 2.6. |
| `HANDSHAKE.md` | Discovery precedes the handshake. Discovered server address and capabilities inform the handshake init. |
| `ENVELOPE.md` | Discovery determines whether SEMP delivery proceeds. |
| `KEY.md` | Key discovery uses the same well-known URI infrastructure defined here. |
| `CLIENT.md` | Discovery outcomes map directly to submission response statuses: `semp` → deliver; `legacy` → `legacy_required`; `not_found` → `recipient_not_found`. |

---

*This document is an Internet-Draft. It is subject to revision prior to
finalization as a stable specification.*