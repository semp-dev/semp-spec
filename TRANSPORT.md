# SEMP Transport Specification

**Sealed Envelope Messaging Protocol**  
Status: Internet-Draft  
Version: 0.2.0-draft  
Related: `DESIGN.md`, `DISCOVERY.md`, `HANDSHAKE.md`, `SESSION.md`,
`CONFORMANCE.md`

---

## Abstract

SEMP is a transport-agnostic protocol. It defines application-layer semantics
(envelopes, handshakes, sessions, keys, discovery) without prescribing a
specific wire transport. This document defines the minimum requirements a
transport must satisfy to carry SEMP traffic, establishes two transport
profiles for different communication patterns, specifies bindings for the
core transports, and provides a framework for defining bindings for additional
transports.

SEMP does not require a dedicated port. All core transports operate over
standard HTTPS infrastructure on port 443.

---

## 1. Design Rationale

Modern transports (WebSocket, HTTP/2, QUIC) provide connection management,
multiplexing, encryption, and flow control sufficient for structured
application messaging. SEMP treats these as infrastructure and operates
exclusively at the application layer.

This separation provides three practical advantages:

1. **No port allocation required.** SEMP runs over port 443 alongside existing
   HTTPS infrastructure. No firewall rules to negotiate, no IANA port
   assignment to obtain, no special infrastructure to provision.

2. **Infrastructure reuse.** A SEMP server can run behind the same load
   balancer, use the same TLS certificates, and share the same operational
   tooling as a web application or API.

3. **Deployment flexibility.** Different operators can select transports that
   match their infrastructure. A privacy-focused provider uses WebSocket
   because it blends with normal web traffic. An enterprise uses gRPC because
   they already have gRPC infrastructure. An operator running over an
   unreliable link uses QUIC to absorb packet loss without head-of-line
   blocking. The envelope is the same in every case.

---

## 2. Minimum Transport Requirements

Any transport used to carry SEMP messages MUST satisfy all seven requirements
defined in this section. These requirements are derived from the protocol's
operational needs: the handshake is a strict state machine requiring ordered
bidirectional exchange, envelope delivery requires reliable transmission with
explicit acknowledgment, and all SEMP traffic operates over encrypted channels
with verified domain identity.

### 2.1 Confidentiality

The transport MUST encrypt all data in transit. TLS 1.3 is RECOMMENDED.
TLS 1.2 with forward-secret cipher suites is the minimum acceptable floor.

SEMP's application-layer encryption protects envelope content (the `brief` and
`enclosure`), but handshake messages, postmark metadata, discovery exchanges,
and key requests are all protected at the transport layer. Unencrypted
transports are prohibited.

### 2.2 Server Authentication

The transport MUST allow the connecting party to verify the remote server's
domain identity. This requirement is satisfied by TLS certificate verification where
the certificate's Common Name or Subject Alternative Name matches the
server's domain.

For federation (server-to-server) connections, mutual TLS (mTLS) MAY be used
to provide bidirectional domain verification at the transport layer, in
addition to the application-layer domain verification defined in
`HANDSHAKE.md` section 5.3.

Client-to-server connections do not require mTLS. Client identity is
established through the SEMP handshake, not at the transport layer.

### 2.3 Reliable, Ordered Delivery

Every SEMP message sent over the transport MUST arrive at the recipient, and
MUST arrive in the order it was sent. The SEMP handshake is a strict
state machine; messages 1 through 4 must be processed in sequence.
Out-of-order or dropped messages break the protocol.

If the transport cannot guarantee delivery, the transport binding MUST
implement application-level acknowledgment and retransmission to provide this
guarantee to the SEMP layer.

### 2.4 Bidirectional Messaging

Both parties MUST be able to send messages after the connection is
established. The handshake is a four-message exchange alternating between
client and server. Envelope delivery requires the receiving server to return
acceptance or rejection responses. Discovery and key exchange are
request-response patterns.

A transport that only supports unidirectional or strictly request-response
communication (such as plain HTTP/1.1 without streaming) does not satisfy
this requirement without adaptation.

### 2.5 Message Framing

The transport MUST provide message framing, a mechanism to delimit individual
SEMP messages within the connection. SEMP sends discrete JSON objects, not a
continuous byte stream. Each message must be identifiable as a complete unit
for parsing.

If the underlying transport provides a byte stream without framing (such as
raw TCP), the transport binding MUST define a framing scheme. See section 7
for framing requirements in custom transport bindings.

### 2.6 Binary-Safe Variable-Length Payloads

The transport MUST support messages up to the server's advertised
`max_envelope_size` (default 25 MB per `DISCOVERY.md` section 3.1). SEMP
payloads contain base64-encoded binary data for keys, nonces, signatures, and
encrypted content. The transport MUST NOT alter, truncate, or re-encode
payload content.

Transports with fixed or low message size limits MAY be used if they define
a chunking mechanism in their transport binding. The chunking mechanism MUST
reassemble the complete SEMP message before delivering it to the SEMP layer.

### 2.7 Connection Lifecycle Signaling

The transport MUST provide clean connection open and close semantics. Both
parties MUST be able to distinguish between:

- An intentional disconnect (the remote party closed the connection)
- A network failure (the connection was lost without a close signal)

This distinction is required for correct session management. An intentional
close following a `rejected` handshake message is normal operation. A network
failure during a handshake is a transient condition that warrants retry. The
SEMP layer cannot make this distinction without transport-level lifecycle
signaling.

---

## 3. Transport Profiles

SEMP traffic falls into two communication patterns with different transport
requirements. A transport MAY satisfy one or both profiles.

### 3.1 Synchronous Profile

The synchronous profile covers protocol exchanges that follow a strict
request-response or multi-message sequential pattern:

- **Handshake**:  Four-message exchange with optional challenge interstitial.
- **Discovery**:  Request-response lookup.
- **Key exchange**:  Request-response key fetch.
- **Rekeying**:  Two-message exchange within an established session.

Synchronous profile operations require low latency and strict message ordering.
The transport MUST support bidirectional messaging with round-trip response
times suitable for interactive session establishment. A transport where message
delivery latency is measured in seconds rather than milliseconds is unsuitable
for this profile.

### 3.2 Asynchronous Profile

The asynchronous profile covers envelope delivery and delivery acknowledgment:

- **Envelope submission**:  Client submits an envelope; server returns a
  per-recipient result.
- **Envelope relay**:  Server-to-server envelope delivery with acceptance or
  rejection response.
- **Delivery event notifications**:  Server notifies client of delivery outcome
  for `queued` envelopes.

Asynchronous profile operations are tolerant of higher latency. The response
is expected but not immediate. A transport that introduces seconds of latency
is acceptable for envelope delivery, though not ideal.

### 3.3 Profile Satisfaction

A transport that satisfies the synchronous profile necessarily satisfies the
asynchronous profile. The reverse is not true.

Implementations that use a transport satisfying only the asynchronous profile
MUST use a separate transport for synchronous operations. The transport used
for each operation MUST be declared in the handshake init message and
advertised during discovery.

The three core transports defined in section 4 all satisfy both profiles.

---

## 4. Core Transport Bindings

SEMP defines bindings for three transports. Implementations MUST support
HTTP/2 as the baseline transport for interoperability. Implementations SHOULD
additionally support WebSocket and QUIC. All three are chosen because they are
widely deployed, run over standard HTTPS infrastructure, and satisfy both
transport profiles natively.

### 4.1 WebSocket (ws)

| Property              | Value                                          |
|-----------------------|------------------------------------------------|
| Transport identifier  | `ws`                                           |
| Endpoint URL scheme   | `wss://`                                       |
| Default port          | 443                                            |
| Profile               | Synchronous and asynchronous                   |
| TLS requirement       | Required (WSS only; WS is prohibited)          |
| Framing               | Native WebSocket frames                        |
| Bidirectional         | Native                                         |
| Specification         | RFC 6455                                       |

#### 4.1.1 Connection Establishment

The client initiates a WebSocket connection to the endpoint URL advertised in
the server's discovery response or well-known URI configuration. The HTTP
Upgrade request MUST include the subprotocol identifier `semp.v1`:

```
Sec-WebSocket-Protocol: semp.v1
```

The server MUST confirm the subprotocol in its Upgrade response. If the server
does not confirm `semp.v1`, the client MUST close the connection.

#### 4.1.2 Message Encoding

Each SEMP message is sent as a single WebSocket text frame containing the
UTF-8-encoded JSON message. Binary frames MUST NOT be used for SEMP messages.

Implementations MUST NOT split a single SEMP message across multiple WebSocket
messages. WebSocket fragmentation at the frame level is permitted; the
WebSocket layer reassembles fragments into a complete message before delivery
to the SEMP layer.

#### 4.1.3 Connection Lifecycle

WebSocket close frames provide clean shutdown signaling. When a server rejects
a handshake or an envelope, it MUST send the rejection response before
initiating a WebSocket close. A close frame without a preceding rejection
message MUST be treated as a network-level failure, not as a silent rejection.

Implementations SHOULD use WebSocket ping/pong frames for keepalive during
long-lived sessions. The recommended ping interval is 30 seconds.

#### 4.1.4 Considerations

WebSocket is RECOMMENDED as an additional transport alongside the mandatory
HTTP/2 baseline. It blends with normal web traffic on port 443, making it
resistant to protocol-specific blocking. It has mature library support across
all major programming languages. Its persistent connection model maps naturally
to
SEMP's session lifecycle.

### 4.2 HTTP/2 (h2)

| Property              | Value                                          |
|-----------------------|------------------------------------------------|
| Transport identifier  | `h2`                                           |
| Endpoint URL scheme   | `https://`                                     |
| Default port          | 443                                            |
| Profile               | Synchronous and asynchronous                   |
| TLS requirement       | Required (HTTPS only)                          |
| Framing               | HTTP/2 stream framing                          |
| Bidirectional         | Via streams                                    |
| Specification         | RFC 9113                                       |

#### 4.2.1 Endpoint Structure

The SEMP HTTP/2 binding uses a single base URL with path-based routing for
different protocol operations:

| Operation        | Method | Path                     |
|------------------|--------|--------------------------|
| Discovery lookup | POST   | `/v1/discovery`          |
| Key request      | POST   | `/v1/keys`               |
| Handshake        | POST   | `/v1/handshake`          |
| Envelope submit  | POST   | `/v1/envelope`           |
| Session stream   | POST   | `/v1/session/{id}`       |

All request and response bodies are `application/json; charset=utf-8`.

#### 4.2.2 Request-Response Operations

Discovery, key exchange, and envelope submission use standard HTTP/2
request-response semantics. The client sends a POST request containing the
SEMP message as the request body. The server returns the SEMP response as the
response body.

HTTP status codes indicate transport-level outcomes only:

| HTTP status | Meaning                                                       |
|-------------|---------------------------------------------------------------|
| 200         | SEMP message processed. SEMP-level outcome is in the body.    |
| 400         | Malformed SEMP message. Could not parse.                      |
| 413         | Payload exceeds `max_envelope_size`.                           |
| 429         | Transport-level rate limit. Distinct from SEMP `rate_limited`.|
| 503         | Server temporarily unavailable.                               |

A 200 response with a SEMP rejection in the body is normal operation. HTTP
status codes and SEMP reason codes are independent layers.

#### 4.2.3 Handshake as Multi-Request Exchange

The four-message handshake maps to sequential HTTP/2 POST requests. Each
handshake message is a separate request-response round trip:

1. Client POSTs `init` → Server responds with `response` (or `challenge`)
2. Client POSTs `challenge_response` (if required) → Server responds with `response`
3. Client POSTs `confirm` → Server responds with `accepted` or `rejected`

The server includes a `Semp-Session-Id` header in the response to message 1.
Subsequent handshake requests for the same session MUST include this header so
the server can correlate them.

#### 4.2.4 Session Stream

For established sessions requiring server-initiated messages (delivery event
notifications, rekeying), the client opens a long-lived POST to
`/v1/session/{id}`. The server sends SEMP messages as server-push events
using SSE (Server-Sent Events) encoding within the response body:

```
data: {"type":"SEMP_DELIVERY_EVENT","status":"delivered",...}

data: {"type":"SEMP_REKEY","step":"init",...}

```

Each `data:` line contains a complete SEMP JSON message. Blank lines delimit
events per the SSE specification.

The client sends messages for this session by issuing additional POST requests
to `v1/session/{id}`.

#### 4.2.5 Considerations

HTTP/2 is RECOMMENDED for environments with existing HTTP infrastructure and
API gateway patterns. The request-response model maps naturally to discovery
and key exchange. The session stream mechanism for server-initiated messages
is more complex than WebSocket's native bidirectional model but avoids the
HTTP Upgrade negotiation step that some intermediaries handle poorly.

### 4.3 QUIC (quic)

| Property              | Value                                          |
|-----------------------|------------------------------------------------|
| Transport identifier  | `quic`                                         |
| Endpoint URL scheme   | `https://`                                     |
| Default port          | 443                                            |
| Profile               | Synchronous and asynchronous                   |
| TLS requirement       | Built-in (TLS 1.3 is integral to QUIC)         |
| Framing               | QUIC stream framing                            |
| Bidirectional         | Native bidirectional streams                   |
| Specification         | RFC 9000, RFC 9114 (HTTP/3)                    |

#### 4.3.1 Binding Model

The SEMP QUIC binding follows the same endpoint structure and message encoding
as the HTTP/2 binding (section 4.2), carried over HTTP/3. All path routing,
status code semantics, and session stream mechanisms are identical.

#### 4.3.2 QUIC-Specific Advantages

QUIC provides benefits beyond HTTP/2 for SEMP:

- **No head-of-line blocking.** Packet loss on one QUIC stream does not block
  other streams. Multiple concurrent envelope deliveries proceed independently.
- **Connection migration.** A QUIC connection survives network changes (e.g.,
  Wi-Fi to cellular) without re-handshaking at the transport level. The SEMP
  session continues uninterrupted.
- **Reduced connection establishment latency.** QUIC's 0-RTT and 1-RTT
  connection setup reduces time to first SEMP handshake message.
- **Built-in TLS 1.3.** Encryption is not optional or negotiable. The minimum
  confidentiality requirement is satisfied by definition.

#### 4.3.3 Considerations

QUIC operates over UDP, which may be blocked by some network middleboxes.
Implementations MUST fall back to HTTP/2 or WebSocket when QUIC is unreachable.

---

## 5. Transport Negotiation

Transport selection happens during discovery, before any SEMP handshake
begins.

### 5.1 Advertisement

Servers advertise supported transports in two places:

**DNS TXT record** (per `DISCOVERY.md` section 2.2):

```
_semp._tcp.example.com.  3600  IN  TXT  "v=semp1;pq=ready;c=ws,h2,quic"
```

The `c` parameter lists transport identifiers in the server's preference
order.

**Well-known URI** (per `DISCOVERY.md` section 3):

```json
{
    "endpoints": {
        "ws": "wss://semp.example.com/v1/ws",
        "h2": "https://semp.example.com/v1",
        "quic": "https://semp.example.com/v1"
    }
}
```

Each key in the `endpoints` object is a transport identifier. The value is the
endpoint URL for that transport.

### 5.2 Selection

The connecting party (client or federation peer) selects a transport using the
following priority:

1. The connecting party's own preference, constrained to transports the
   remote server advertises.
2. If multiple transports are mutually supported, the connecting party SHOULD
   prefer the remote server's preference order (from the `c` parameter or
   `endpoints` key order).
3. If no mutually supported transport exists, the connection cannot proceed.

The selected transport is declared in the handshake init message via the
`transport` field (per `HANDSHAKE.md` section 2.2.1).

### 5.3 Recommended Fallback Order

When the selected transport is unreachable (connection refused, timeout, or
blocked by a middlebox), the connecting party SHOULD attempt alternative
transports before treating the connection as failed. The following is the
RECOMMENDED fallback order for the core and extended transports:

| Priority | Transport  | Rationale                                                   |
|----------|------------|-------------------------------------------------------------|
| 1        | QUIC       | Lowest latency (0-RTT/1-RTT), no head-of-line blocking, built-in TLS 1.3, connection migration. |
| 2        | WebSocket  | Persistent bidirectional connection, widely supported, traverses nearly all middleboxes. |
| 3        | HTTP/2     | Mandatory baseline. Request-response model adds round-trip latency to handshakes. |
| 4        | gRPC       | Bidirectional streaming over HTTP/2. Applicable only when both parties have gRPC infrastructure. |

This order reflects a preference for performance first (QUIC), reliability
second (WebSocket), universal availability third (HTTP/2), and
infrastructure-specific optimization last (gRPC).

Because HTTP/2 is the mandatory baseline transport (section 4), a connecting
party MAY always attempt HTTP/2 even when the peer's DNS TXT record or
well-known configuration does not explicitly advertise it. Every conformant
SEMP server MUST accept connections over HTTP/2 regardless of what transports
it advertises. This guarantees that two conformant servers can always
communicate even when transport advertisement is absent or incomplete.

Implementations MAY deviate from the fallback order based on operational
context. For example, an enterprise deployment where all peers are known to
support gRPC may reasonably prefer gRPC over WebSocket. The recommended order
applies when the connecting party has no additional knowledge about the remote
environment.

### 5.4 Fallback Procedure

The fallback procedure is:

1. Attempt connection on the selected transport.
2. If the connection fails within the transport timeout (RECOMMENDED: 10
   seconds), move to the next transport in the fallback order that is both
   mutually supported and not yet attempted.
3. Repeat until a connection succeeds or all mutually supported transports
   have been exhausted.
4. If all transports fail, the connection attempt fails. The sender server
   MUST surface this as a delivery failure, not a silent discard.

Fallback attempts MUST be sequential, not concurrent. Concurrent connection
attempts to the same server on multiple transports waste resources on both
sides and may trigger rate limiting.

### 5.5 Fallback Transparency

Transport fallback MUST be transparent to the SEMP layer. A handshake
initiated over WebSocket and a handshake initiated over HTTP/2 produce
identical SEMP sessions. The SEMP layer does not observe or depend on which
transport was selected. Only the `transport` field in the handshake init
records the choice.

### 5.6 Fallback Caching

When a transport fails and fallback succeeds, implementations SHOULD cache
the successful transport for the target domain with a TTL matching the
discovery cache TTL. Subsequent connections to the same domain SHOULD attempt
the cached transport first, followed by the standard fallback order if the
cached transport also fails.

The cache MUST be invalidated when discovery records for the domain are
refreshed. A domain that previously failed on QUIC may have resolved the
issue; the connecting party should not permanently avoid a transport based
on a single failure.

---

## 6. Optional Transport Bindings

Beyond the three core transports, SEMP MAY operate over additional
transports where the minimum requirements of section 2 are satisfied.
Optional bindings are non-core: conformant servers and clients are not
required to support them, and interoperability between independent
operators MUST rely on the core bindings in section 4.

### 6.1 gRPC (grpc)

| Property              | Value                                          |
|-----------------------|------------------------------------------------|
| Transport identifier  | `grpc`                                         |
| Default port          | 443                                            |
| Profile               | Synchronous and asynchronous                   |
| TLS requirement       | Required                                       |
| Framing               | Protocol Buffers or JSON over HTTP/2            |
| Bidirectional         | Native bidirectional streaming                  |
| Specification         | gRPC over HTTP/2 (grpc.io)                     |

#### 6.1.1 Status

gRPC is an OPTIONAL transport binding. Operators with existing gRPC
infrastructure MAY use it for client sessions and for federation
sessions with peers that also advertise `grpc`. Operators MUST NOT
assume federation peers support gRPC. At least one core transport
(section 4) MUST be advertised alongside `grpc` in the discovery
configuration so that peers without gRPC support can still federate.

#### 6.1.2 Service Definition

The gRPC binding defines a SEMP service with the following RPC methods:

```protobuf
service SEMPService {
    // Request-response operations
    rpc Discover (SEMPMessage) returns (SEMPMessage);
    rpc FetchKeys (SEMPMessage) returns (SEMPMessage);
    rpc SubmitEnvelope (SEMPMessage) returns (SEMPMessage);

    // Multi-message handshake
    rpc Handshake (stream SEMPMessage) returns (stream SEMPMessage);

    // Session stream for server-initiated messages
    rpc Session (stream SEMPMessage) returns (stream SEMPMessage);
}

message SEMPMessage {
    string json_payload = 1;
}
```

The `SEMPMessage` wrapper carries the JSON-encoded SEMP message as a string.
Implementations MAY define a protobuf-native encoding of SEMP messages as a
future optimization, but the JSON encoding MUST be supported for
interoperability.

#### 6.1.3 Handshake Mapping

The handshake uses a bidirectional stream. The client sends `init`, reads
`response` (or `challenge`), sends `challenge_response` or `confirm`, and reads
`accepted` or `rejected`. The stream is closed after the handshake completes.

---

## 7. Custom Transport Binding Requirements

Operators MAY define transport bindings beyond those specified in sections 4
and 6. A custom transport binding MUST satisfy all of the following:

### 7.1 Minimum Requirements

The transport MUST satisfy all seven requirements defined in section 2. If
any requirement is not natively provided by the transport, the binding MUST
specify how it is achieved.

### 7.2 Transport Identifier

The binding MUST define a unique transport identifier string for use in
discovery records and handshake init messages. Identifiers for custom
bindings MUST use the SEMP extension namespacing convention:
`"vendor.example.com/transport-name"`. The identifiers `ws`, `h2`, `quic`,
and `grpc` are reserved for the core and optional bindings in sections 4
and 6.

### 7.3 Framing

If the transport does not provide native message framing, the binding MUST
define a framing scheme. The RECOMMENDED framing scheme for stream-oriented
transports is length-prefix framing:

```
[4 bytes: message length in network byte order][message bytes]
```

The message length is the byte length of the UTF-8-encoded JSON message. The
maximum message length is governed by the server's advertised
`max_envelope_size`.

### 7.4 Profile Declaration

The binding MUST declare which transport profiles (synchronous, asynchronous,
or both) the transport satisfies. If only the asynchronous profile is
satisfied, the binding MUST state the companion channel requirement.

### 7.5 Message Encoding

All SEMP messages MUST be encoded as UTF-8 JSON regardless of transport. A
custom binding MAY define an additional binary encoding (such as Protocol
Buffers or CBOR) as an optimization, but the JSON encoding MUST be supported
as the interoperability baseline.

### 7.6 Endpoint and Discovery Integration

The binding MUST define how the transport is advertised in discovery (DNS TXT
`c` parameter and well-known URI `endpoints` object) and how endpoint URLs are
structured.

### 7.7 Connection Lifecycle Mapping

The binding MUST document how transport-level lifecycle events map to SEMP
session events. Specifically:

- How a clean disconnect is signaled.
- How a network failure is detected.
- How transport-level timeouts interact with the SEMP handshake timeout
  (30 seconds per `HANDSHAKE.md` section 6.6).

---

## 8. Transport and SEMP Session Independence

The SEMP session layer and the transport layer are deliberately independent.
This section documents the boundaries between them.

### 8.1 TLS Sessions Are Not SEMP Sessions

A TLS session provides transport encryption. A SEMP session provides
application-layer forward secrecy, identity binding, and session key material.
These are distinct concerns.

TLS session resumption MUST NOT resume a SEMP session. Each SEMP session
requires a fresh handshake regardless of TLS state. This is consistent with
`SESSION.md` section 5.5.

### 8.2 Transport Reconnection

If the transport connection drops and is re-established (e.g., a WebSocket
reconnects after a network interruption), the SEMP session does not
automatically resume. The implementation MUST:

1. Check whether the SEMP session's `expires_at` has passed.
2. If the session is still valid: resume sending envelopes on the session.
   No re-handshake is required if the session has not expired.
3. If the session has expired: initiate a fresh SEMP handshake.

Transport reconnection does not affect SEMP session validity. Re-establishing
a transport connection does not restore an expired session.

### 8.3 Connection Multiplexing

A single transport connection MAY carry multiple SEMP sessions when the
transport supports multiplexing (HTTP/2 streams, QUIC streams). Each session
is identified by `session_id`, not by transport-level identifiers.

Implementations MUST NOT assume a one-to-one mapping between transport
connections and SEMP sessions. A server MUST accept envelopes on any transport
connection where the `session_id` references a valid, non-expired session.

---

## 9. Security Considerations

### 9.1 Transport as Defense in Depth

TLS at the transport layer and SEMP's application-layer encryption provide
defense in depth. An attacker who compromises the TLS layer (by obtaining a
TLS session key or certificate) gains access to SEMP handshake ciphertext and
postmark metadata, but not to `brief` or `enclosure` content, which are
encrypted under SEMP session keys.

Operators MUST NOT treat transport-layer encryption as sufficient and skip
SEMP application-layer encryption. The two layers protect against different
threat models: TLS protects against network-level eavesdropping, SEMP protects
against compromised infrastructure.

### 9.2 Protocol Fingerprinting

Running SEMP over standard HTTPS on port 443 makes SEMP traffic resistant to
protocol-specific blocking. An observer sees HTTPS connections to a web
server, indistinguishable from any other HTTPS traffic without deep packet
inspection.

The WebSocket subprotocol header (`semp.v1`) is visible during the HTTP
Upgrade. Operators concerned about protocol identification MAY omit the
subprotocol header at the cost of requiring a fixed SEMP endpoint URL instead
of subprotocol negotiation.

### 9.3 Transport Downgrade

An attacker with control over DNS or network infrastructure could attempt to
remove higher-security transports from discovery responses, forcing a downgrade
to a transport the attacker can exploit. Discovery responses are signed (per
`DISCOVERY.md` section 4.3), which mitigates this attack when the connecting
party verifies the signature.

Implementations SHOULD cache previously observed transport capabilities and
alert the operator if a domain's advertised transports change significantly
(e.g., QUIC support disappears).

### 9.4 Tor

SEMP operates over Tor without protocol modification. When the recipient
domain is a `.onion` address, DNS discovery is inapplicable and implementations
MUST skip DNS lookup and fetch the well-known URI directly over Tor. HTTP/2 is
the RECOMMENDED transport for `.onion` endpoints due to Tor's connection
reliability characteristics; persistent connections such as WebSocket are
prone to circuit rotation disruptions. The handshake timeout of 30 seconds
(per `HANDSHAKE.md` section 6.6) accommodates Tor's higher latency without
adjustment.

---

## 10. Conformance

### 10.1 Server Conformance

A conformant server MUST:

- Support HTTP/2 as the baseline transport for interoperability.
- Advertise supported transports accurately in discovery records.
- Accept SEMP messages on any advertised transport without semantic
  differences; the same SEMP message produces the same outcome regardless
  of transport.
- Satisfy all seven minimum transport requirements on every advertised
  transport.

A conformant server SHOULD additionally support WebSocket and QUIC.

### 10.2 Client Conformance

A conformant client MUST:

- Support HTTP/2 as the baseline transport for interoperability.
- Respect the server's advertised transport capabilities during selection.
- Declare the selected transport in the handshake init message.
- Implement transport fallback when the preferred transport is unreachable.

### 10.3 Extension Transport Conformance

An implementation advertising an extended or custom transport binding MUST:

- Publish the binding specification.
- Satisfy the custom transport binding requirements in section 7.
- Ensure the binding does not weaken the security guarantees of the core
  protocol.

---

## 11. Relationship to Other Specifications

| Specification  | Relationship                                                                       |
|----------------|------------------------------------------------------------------------------------|
| `DESIGN.md`    | Transport agnosticism follows from section 9: SEMP builds on existing transport standards. |
| `DISCOVERY.md` | Transport advertisement via DNS TXT `c` parameter (section 2.2) and well-known URI `endpoints` (section 3). |
| `HANDSHAKE.md` | Transport declared in init `transport` field (section 2.2.1). Handshake timeout (section 6.6) bounds transport-level delays. |
| `SESSION.md`   | TLS independence (section 5.5). Transport reconnection does not resume SEMP sessions. |
| `CONFORMANCE.md` | Transport support requirement (section 9.2).                                      |
| `ERRORS.md`    | Transport-layer status codes and connection failure conditions registered in section 12. |

---

*This document is an Internet-Draft. It is subject to revision prior to
finalization as a stable specification.*