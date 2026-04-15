# SEMP Discovery Specification

**Sealed Envelope Messaging Protocol**  
Status: Internet-Draft  
Version: 0.1.0  
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

| Strategy | Description                                         |
|----------|-----------------------------------------------------|
| `alpha`  | Alphabetical ranges mapped to specific servers.     |
| `hash`   | `hash(username) mod N` determines the server index. |
| `lookup` | A partition server must be queried for the mapping. |

#### Alpha Partitioning

```
_semp-partition-a-f.example.com.  3600  IN  SRV  10  10  443  semp-1.example.com.
_semp-partition-g-m.example.com.  3600  IN  SRV  10  10  443  semp-2.example.com.
_semp-partition-n-s.example.com.  3600  IN  SRV  10  10  443  semp-3.example.com.
_semp-partition-t-z.example.com.  3600  IN  SRV  10  10  443  semp-4.example.com.
```

#### Hash Partitioning

The sending server computes:

```
server_index = SHA-256(username@domain) mod number_of_servers
```

And maps the index to a server via additional SRV records published under
`_semp-partition-<index>.example.com`.

#### Lookup Partitioning

When `strategy=lookup`, the sending server first queries a designated partition
server to resolve which delivery server handles the target user. The partition
server address is published as a separate SRV record:

```
_semp-partition-lookup.example.com.  3600  IN  SRV  10  10  443  partition.example.com.
```

The lookup query is subject to the same anonymity constraints as protocol
discovery: the querying server MUST NOT reveal the sender's identity in the
partition lookup request.

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

| Field        | Type     | Required | Description                                        |
|--------------|----------|----------|----------------------------------------------------|
| `type`       | `string` | Yes      | MUST be `"SEMP_CONFIGURATION"`.                    |
| `version`    | `string` | Yes      | SEMP protocol version supported (semver).          |
| `domain`     | `string` | Yes      | The email domain this server operates for.         |
| `endpoints`  | `object` | Yes      | All discoverable endpoints. See section 3.1.1.     |
| `suites`     | `array`  | Yes      | Cryptographic suite identifiers in preference order. See section 3.1.2. |
| `limits`     | `object` | Yes      | Operational limits. See section 3.1.3.             |
| `extensions` | `array`  | No       | Supported extensions. See section 3.1.4.           |

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
| `blocklist`        | `string` | No       | URL for block list management (`GET`/`POST`/`DELETE`). See `DELIVERY.md` section 4. |
| `keys`             | `string` | Yes      | Base URL for user key publication. Append the user address to retrieve keys. Response format in section 3.4. |
| `domain_keys`      | `string` | Yes      | URL for domain signing and encryption key publication. Response format in section 3.3. |
| `reputation`       | `string` | No       | Base URL for this server's published trust gossip observations. Append the subject domain to retrieve observations. Absence indicates the server does not publish gossip. See `REPUTATION.md` section 5. |
| `reputation_references` | `string` | No  | URL for the domain's self-published reputation references document, listing third-party observers that have published observations about this domain. Absence indicates the domain does not self-publish references. See `REPUTATION.md` section 5.6. |

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
        "id": "semp.dev/read-receipts",
        "required": false
    },
    {
        "id": "example.com/custom-routing",
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
            "features": ["groups", "threads", "reactions"],
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
| `features`   | `array`   | No       | Supported SEMP features. Present only when `status` is `semp`.              |
| `server`     | `string`  | No       | Hostname of the server handling this address. Present when `status` is `semp` or `legacy`. |
| `ttl`        | `integer` | Yes      | Seconds the result may be cached.                                           |

### 4.6 Result Status Values

| Status          | Meaning                                                                           |
|-----------------|-----------------------------------------------------------------------------------|
| `semp`          | Address supports SEMP. Handshake and envelope delivery may proceed.               |
| `legacy`        | No SEMP support found. MX records confirm SMTP is available. Client SMTP fallback is possible. |
| `not_found`     | No SEMP support found and no MX records found. The domain cannot receive mail by any known method. Per-address existence is not checked. |

These three statuses map directly to the submission response values in
`CLIENT.md` section 6.3: `semp` → proceed with SEMP delivery; `legacy` →
return `legacy_required` to client; `not_found` → return `recipient_not_found`
to client.

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
       |--- Server B runs delivery pipeline (DELIVERY.md §2)
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
in `DELIVERY.md` section 2 before returning an acknowledgment. This includes
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
`DELIVERY.md` section 7.2. The sending partition server MUST enforce a timeout
on internally routed deliveries and treat expiry as `silent`, consistent with
`DELIVERY.md` section 1.5. A timeout of 30 seconds is RECOMMENDED.

#### 5.4.2 Block List Isolation

The recipient's block list is held by the receiving partition server. The
sending partition server MUST NOT access, query, or cache the recipient's block
list. Block list confidentiality requirements from `DELIVERY.md` section 7.1
apply across partition boundaries within the same domain.

### 5.5 SRV Target and Well-Known Host Resolution

When DNS SRV resolves a domain to a target hostname (e.g. `_semp._tcp.example.com`
resolves to `semp.example.com`), subsequent HTTPS operations against that domain
MUST use the SRV target hostname, not the email domain:

- Domain key fetch: `https://semp.example.com/.well-known/semp/domain-keys`
- Configuration: `https://semp.example.com/.well-known/semp/configuration`
- User key publication: `https://semp.example.com/.well-known/semp/keys/<address>`

This is necessary because the email domain (e.g. `example.com`) may not host the
SEMP server directly. The SRV record is the authoritative mapping from the email
domain to the server hostname. The well-known endpoints are served by the SEMP
server, not by whatever else runs on the bare domain.

When SRV lookup fails or returns no records, the email domain is used as the
hostname (the well-known URI fallback path in section 3).

### 5.6 Federation Endpoint Derivation

When a server needs to open a federation session to a peer domain, it derives
the federation endpoint as follows:

1. If a static endpoint is configured for the peer, use it directly.
2. If a well-known configuration document is available (from section 3),
   extract the endpoint URL for the preferred transport and replace `/v1/ws`
   or `/v1` with `/v1/federate`.
3. If only DNS SRV is available (no well-known document), construct the
   endpoint from the SRV target using the mandatory HTTP/2 baseline:
   `https://<srv-target>/v1/federate`. Because HTTP/2 is the mandatory
   baseline transport (`TRANSPORT.md` section 4), every conformant server
   MUST accept federation connections over HTTP/2 even when no transport
   is explicitly advertised.

The federation endpoint path `/v1/federate` is the standard path for
server-to-server connections. Implementations MAY use a different path
if advertised in the well-known configuration.

### 5.7 Automatic Peer Discovery

Servers MUST NOT require pre-configured peer lists for federation. When a
server receives an envelope addressed to a recipient on an unknown domain,
it MUST attempt discovery for that domain using the standard flow (section 5.1).
If the domain is discovered to support SEMP, the server MUST proceed with
federation handshake and envelope forwarding.

This means any two SEMP servers with correctly configured DNS SRV/TXT records
can federate without prior arrangement. The domain signing key needed for the
federation handshake is fetched from the peer's well-known endpoint
(`/.well-known/semp/domain-keys`) and cached locally.

---

## 6. Caching

### 6.1 Caching Rules

Discovery results MUST be cached per the TTL returned in the response or DNS
record. Caching reduces lookup overhead and, by decoupling fetches from
individual send events, reduces intent leakage.

| Result type   | Default TTL when none provided |
|---------------|-------------------------------|
| `semp`        | 1 hour                        |
| `legacy`      | 24 hours                      |
| `not_found`   | 1 hour                        |

Implementations MUST:
- Respect TTL values from DNS and lookup responses
- Invalidate cache entries on delivery failure and re-discover before retry
- Not serve stale entries beyond their TTL

Implementations SHOULD:
- Perform discovery speculatively for frequently contacted domains, independent
  of pending sends, to decouple lookup timing from communication intent
- Encrypt cached discovery results at rest

### 6.2 Authenticated Discovery

When a server requires authenticated lookup requests (for example, to enforce
stricter rate limits on known partners versus anonymous queries), authentication
MAY be declared in `extensions`:

```json
"extensions": {
    "semp.dev/auth": {
        "method": "domain_key",
        "key_id": "querying-server-key-fingerprint",
        "signature": "base64-signature-over-request-id-and-timestamp"
    }
}
```

Servers MUST NOT require authenticated discovery as a condition of SEMP
interoperability. Authentication in discovery is a rate-limiting and policy
tool, not an access control gate. An unauthenticated request from an unknown
domain MUST still receive a valid response, subject to rate limiting.

Servers MAY apply stricter rate limits to unauthenticated requests.

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

Unauthenticated lookup requests could be used to enumerate valid addresses on
a domain. Mitigations:

- Rate limiting on unauthenticated requests
- Servers MAY return identical TTLs for valid and invalid addresses to prevent
  timing-based enumeration
- Servers MAY return a generic negative result for addresses that do not exist,
  without distinguishing between "unknown user" and "user exists but not SEMP"

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