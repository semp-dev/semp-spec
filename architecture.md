## Abstract

The Sealed Envelope Messaging Protocol (SEMP) is a federated messaging
protocol that addresses key structural limitations of SMTP [RFC 5321](https://www.rfc-editor.org/rfc/rfc5321),
including metadata exposure, IP-based reputation as a trust anchor, the
absence of explicit verifiable rejection, the lack of end-to-end message
integrity guarantees, and insufficient extensibility. This document
defines the SEMP architecture, design principles, document series
organization, and consolidated threat model. It serves as the cover
specification for the SEMP document series. Detailed wire formats and
normative behavior live in companion documents.

# Introduction

SMTP [RFC 5321](https://www.rfc-editor.org/rfc/rfc5321) was designed for a trusted network among known
participants. Subsequent extensions, including SPF [RFC 7208](https://www.rfc-editor.org/rfc/rfc7208),
DKIM [RFC 6376](https://www.rfc-editor.org/rfc/rfc6376), DMARC [RFC 7489](https://www.rfc-editor.org/rfc/rfc7489), and STARTTLS [RFC 3207](https://www.rfc-editor.org/rfc/rfc3207),
address individual symptoms but do not resolve the underlying
structural limitations.

Among the structural limitations SEMP addresses at the protocol level:

1. SMTP transmits message metadata (sender, recipient, subject,
   timestamp) in cleartext. Every intermediary that handles a message
   can observe this metadata. Body encryption alone does not protect
   the envelope.

2. SMTP trust is anchored to IP addresses. New mail servers are
   treated as untrusted until they accumulate reputation through
   mechanisms controlled by a small number of large operators with
   opaque criteria.

3. SMTP lacks an explicit rejection mechanism. Servers may accept
   messages they intend to discard, providing false delivery
   confirmation to senders and silently dropping messages intended
   for recipients.

4. SMTP provides no end-to-end integrity guarantee. A message may be
   altered in transit by any intermediary. DKIM [RFC 6376](https://www.rfc-editor.org/rfc/rfc6376) provides
   a partial signature over selected headers and body, but it is
   bound to the sending domain's outbound server rather than to the
   sender's identity. SEMP envelopes carry two independent integrity
   proofs over the same canonical bytes: a domain key signature
   verifiable by any home server, and a session MAC verifiable
   only by the receiving server. Delivery without a valid established
   session is cryptographically impossible.

5. SMTP was not designed for extensibility. Adding new capabilities
   requires either backwards-incompatible changes or optional
   extension headers that implementations may ignore. SEMP includes
   capability negotiation as part of every connection, allowing new
   features to be introduced without breaking existing
   implementations.

This document is the architectural cover for the SEMP document series.
Detailed wire formats and normative behavior are specified in the
companion documents enumerated in [Document Series](#document-series).

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

This document additionally uses terminology from
[RFC 4949](https://www.rfc-editor.org/rfc/rfc4949) for general security-protocol terms.

# Terminology

The following terms have specific meaning within the SEMP
specification.

Envelope:
: The complete SEMP message unit. Comprises a postmark, a seal, a
  brief, and an enclosure.

Postmark:
: The outer public header of an envelope, visible on the wire.
  Carries only the information necessary to route the envelope.

Seal:
: The cryptographic integrity proof covering the envelope. Includes a
  domain signature and a session MAC.

Brief:
: The inner private header of an envelope. Encrypted; visible only to
  the recipient server (for delivery and policy enforcement) and to
  the recipient client.

Enclosure:
: The message body and any attachments. Encrypted under the
  recipient's encryption key; visible only to the recipient client.

Domain operator:
: The entity responsible for operating a SEMP server for a given
  domain.

Trust gossip:
: A hashed, publishable representation of a domain's trust history,
  verifiable by other SEMP servers without exposing underlying data.

Zero reputation:
: The starting state of a domain with no SEMP history.

Home server:
: The SEMP server hosting a user's account. Brokers outbound
  envelopes, accepts inbound envelopes for the user, and stores the
  minimum state required for delivery and policy enforcement.

Recipient server:
: The home server of the recipient, from the sending server's
  perspective. The role is identical to that of a home server; the
  labels "sender" and "recipient" are envelope-relative.

Federation peer:
: Any home server with which another home server is in active or
  cached session.

Routing infrastructure:
: Transport-layer intermediaries (HTTPS proxies, CDNs, load
  balancers, Tor relays) carrying SEMP traffic between any two
  servers.

Third-party domain:
: A domain that fetches public SEMP artifacts (such as domain keys,
  user keys, or successor records) without itself being a sender or
  recipient in the corresponding exchange.

Key relay:
: A cooperative third-party service that fetches user keys on behalf
  of a sender to reduce communication-intent leakage to the target
  domain.

Transparency monitor:
: An independent service watching the key-transparency log for
  split-view attacks.

# Design Principles

These principles govern every technical decision in SEMP. When a
specification is ambiguous, these principles are the tiebreaker.

## Sealed Envelope Model

A SEMP envelope conceals its contents from all parties except the
intended recipient. Envelopes expose only the information necessary
for routing. All other fields (sender identity, recipient identity,
subject, body, attachments) are encrypted before transmission and
visible only to the parties that hold the appropriate keys.

## Domain and Author Anchored Trust

SEMP separates trust into two layers anchored to two distinct
cryptographic keys.

The **domain key** anchors the server-to-server layer. Every
server operating a SEMP domain holds a domain key. The domain
key signs the routing-layer integrity of every envelope the
domain emits (`seal.signature`), authenticates peers during the
federation handshake, signs discovery responses and the
published user-key record, and signs every observation a domain
publishes about its peers (reputation gossip, abuse reports,
trust transfers). Other servers admit, route, and rate-limit a
domain based on signals anchored to its domain key. The
reputation and abuse-handling story operates entirely at this
layer.

The **user key** anchors the user-to-user layer. Every SEMP user
holds an identity key. The user key signs the authorship
attestation inside the enclosure (the `sender_signature` in
[Envelope](envelope.md)), self-signs the user's encryption
and device subkeys, signs successor and migration records that
govern the user's account lifecycle, and signs recovery bundles
and shares. The recipient client and any out-of-session reader
(forwarder targets, archival readers, future verifiers) verifies
the user key directly. The accountability story,
forwarding-survives-rewrite story, and account-recovery story all
operate at this layer.

The two layers compose. A receiving server admits an envelope
based on the sending domain's reputation (domain layer), and a
recipient verifies the envelope's authorship based on the sender
user's identity key (user layer). A trust failure at the domain
layer rejects the envelope before delivery. An authenticity
failure at the user layer flags the envelope to the recipient
even after admission. The two checks are independent and
cumulative.

The full enumeration of which key signs which context appears in
the "Anchoring Layer per Signature Context" table in
[Envelope](envelope.md).

SEMP builds its reputation model on domain identity rather than
IP address history. A new domain starts with zero reputation.
Trust is earned through observed behavior over time. Trust
observations are:

* observable, in that other servers MAY publish what they
  have seen about a domain through the trust gossip mechanism
  in [Delivery](delivery.md);

* cryptographically verifiable, in that signed records anchor
  every observation, transfer, and revocation to a domain
  key;

* transferable across an ownership or key change only through
  a cooperative cryptographic handshake that requires both
  the prior and the new key holder's private keys, per the
  trust-transfer rules in [Delivery](delivery.md).
  Negative observations carry at full weight across a
  transfer; positive observations carry at a discounted
  weight for a cooldown window. The protocol does not permit
  unilateral transfer.

### Transport vs Trust Separation

IP addresses are visible to SEMP implementations at the transport
layer because TCP/IP requires them. This visibility is unavoidable.
However, IP addresses MUST NOT be used as inputs to protocol-layer
trust decisions. The separation is:

* Transport-layer operational defenses MAY be IP-keyed. SYN flood
  protection, per-IP connection caps, TLS handshake rate limiting,
  and network-level DDoS mitigation operate on traffic
  characteristics and are legitimate uses of IP addresses.

* Protocol-layer trust decisions MUST be domain-keyed. Reputation,
  block lists, delivery policy, gossip observations, abuse reports,
  and federation rate limits that feed into trust evaluation all
  anchor to cryptographic domain identity, never to IP.

An implementation that lets IP signals influence protocol-layer
trust decisions is non-conformant. An operator defending against
connection-level abuse at the transport layer is not thereby
corrupting the trust model, provided the IP-keyed decision stays at
the transport layer and never appears in federation-visible state
(block-list propagation, observation records, abuse reports, or
rate-limit responses carrying a SEMP reason code).

The following operational consequences follow from this
separation:

* Multiple unrelated SEMP domains MAY share a single IP (shared
  HTTPS hosting). One bad neighbor MUST NOT contaminate the
  reputation of the others.

* A SEMP domain MAY present many IPs (CDN, multi-region, failover).
  The domain's accumulated reputation MUST persist across IP
  changes.

* A SEMP domain MAY be reached exclusively over Tor via a `.onion`
  address. The source IP of incoming federation traffic is a Tor
  circuit exit, and the receiving server MUST NOT use that IP as a
  trust signal. Tor-only deployments follow the discovery and
  key-fetch rules specified in [Discovery](discovery.md).

* A SEMP domain MAY rotate its hosting infrastructure (change IPs
  entirely) without disturbing its reputation. Conversely, an IP
  previously associated with an abusive SEMP domain MUST NOT
  automatically taint a different SEMP domain now hosted on the
  same IP.

Conformant servers MUST accept federation handshakes regardless of
source IP, subject only to domain-level policy and transport-layer
operational defenses.

<a id="rejection-must-be-explicit"></a>

## Explicit Rejection
When a SEMP server declines to accept a message, it MUST say
so immediately and explicitly, with a reason code. A server
MUST NOT silently accept an envelope and then discard it as a
wire-visible default. A server MAY apply silent acceptance
only as a deliberate recipient privacy policy under the rules
in [Delivery](delivery.md) (anti-harassment, mailbox
quarantine, and similar narrowly-scoped cases). Detailed
acknowledgment semantics are defined in
[Delivery](delivery.md).

## Operator-Defined Policy

SEMP defines what information is available and what signals exist.
Trust scores, reputation thresholds, blocking rules, and federation
allowlists are policy decisions that belong to server operators.

## Extensibility

SEMP is designed to be extended without fragmentation. Capability
negotiation occurs at every connection. New message types,
encryption algorithms, transport protocols, and trust mechanisms
can be introduced without breaking existing implementations.

Where multiple valid solutions exist to a problem, SEMP defines the
interface and supports all solutions as options rather than
mandating one. This applies to key fetching mechanisms, trust
gossip implementations, cryptographic algorithm selection, and
transport protocols. The extension framework is specified in
[Extensions](extensions.md).

## Documented Privacy Leaks

Some operations in SEMP reveal information about communication
intent. Key fetching, protocol discovery, and handshake initiation
can leak the fact that a sender intends to communicate with a
recipient. Where such leaks exist, the specification documents
them explicitly, describes their severity, and provides mechanisms
to mitigate them. The consolidated view of these leaks appears in
[Threat Model](#threat-model).

<a id="address-enumeration-resistance"></a>

## Address Enumeration Resistance
A SEMP server MUST NOT permit a sender to determine, from any
protocol-defined response, whether a particular recipient address
exists on the recipient domain. This applies to discovery
responses, key fetch responses, envelope rejection reason codes,
and rejection response timing. Side-channel leakage at the
implementation level (microsecond-scale timing variation across
distinct code paths, response sizes that vary with internal database
lookups) is a separate concern; implementations SHOULD mitigate it
where practical, but it is not addressed normatively in this
section.

Concretely:

* Per-address existence MUST NOT be encoded in any reason code
  returned to the sender. Non-existent addresses and
  policy-rejected existing addresses MUST receive the same
  `policy_forbidden` rejection.

* Discovery responses are scoped to the domain rather than to
  individual addresses, per [Discovery](discovery.md).

* Key fetch for an unknown address MUST return a response that is
  indistinguishable in shape, size, and timing from a fetch for an
  existing address whose owner has not published keys.

* First-contact challenges, rate limits, and any other gating
  mechanisms MUST be applied identically to existent and
  non-existent recipient addresses, so that the gating itself does
  not constitute an oracle.

Under these requirements the address book of a domain is private at
the protocol layer. A sender's correspondence intent is observable
only at the domain level absent a successful delivery.

# Non-Goals

SEMP explicitly does not attempt to:

Eliminate spam universally:
: SEMP provides better tools for reputation and rejection, but
  determined abuse at scale is a social and economic problem that
  no protocol can solve alone. SEMP raises the cost of abuse.

Replace SMTP overnight:
: SEMP is designed for incremental adoption. Users may maintain
  both SEMP and legacy mail accounts during the transition period.
  SEMP clients SHOULD support legacy mail access alongside SEMP,
  allowing users to manage legacy correspondence without switching
  clients. The SEMP server is SEMP-only; legacy mail handling is a
  client responsibility.

Guarantee anonymity:
: SEMP provides metadata protection significantly stronger than
  SMTP. It does not provide the anonymity guarantees of systems
  such as Tor or mix networks. Operators who require stronger
  anonymity properties may implement additional layers.

Solve the key exchange intent leak completely:
: No federated messaging protocol can eliminate the observable
  fact that server A contacted server B. SEMP provides multiple
  mechanisms to mitigate this leak and documents the residual
  exposure.

Be opinionated about cryptographic algorithms beyond minimum requirements:
: SEMP specifies minimum acceptable algorithms and supports
  negotiation of stronger ones.

# The Envelope Model

SEMP's core message unit is the envelope. Its structure is modeled on
physical correspondence. An envelope comprises four components:

* The postmark: outer public header, visible on the wire.

* The seal: cryptographic integrity proof, tamper-evident.

* The brief: inner private header, encrypted, visible to the recipient
  server and the recipient client.

* The enclosure: message body and attachments, encrypted, visible only
  to the recipient client.

This document defines the architectural role of each component. The
wire format is specified in [Envelope](envelope.md).

## Postmark

The postmark carries the fields a home server needs to forward the
envelope: the source and destination domains, an envelope identifier,
an expiry, and a size-bucket indicator. Full sender and recipient
addresses, the subject, and precise timestamps are excluded from the
postmark and appear, if at all, only in the encrypted brief or
enclosure.

A home server can read the postmark and no other component.

## Seal

The seal provides cryptographic proof that the envelope has not been
tampered with in transit. It covers the entire envelope. A broken or
invalid seal MUST cause the receiving server to reject the message
immediately and explicitly.

## Brief

The brief contains the routing metadata of the correspondence: full
sender and recipient addresses, timestamps, thread identifiers, and
reply information. It is encrypted and decryptable by both the
recipient server (for delivery and policy enforcement) and the
recipient client. It is not visible to any other server handling the
message in transit.

The subject is not in the brief. It is semantic content and belongs
in the enclosure, where it is protected from server exposure.

## Enclosure

The enclosure contains the message body and any attachments. It is
encrypted under the recipient's encryption key. Content type
negotiation occurs within the enclosure. The enclosure is never
visible to routing infrastructure.

<a id="evidence-properties"></a>

## Evidence Properties
SEMP is explicit about what each party can and cannot prove from
the artifacts they hold. An evidence claim is a statement a party
can back with cryptographic verification against published keys,
independent of any server's continued cooperation.

What the protocol establishes, grouped by the party for whom the
claim is verifiable:

Sender:
: Authorship of the plaintext brief and enclosure by the
  sender's identity key, and that the envelope was constructed
  and signed by the sender domain at the time indicated in the
  postmark.

Sender, post-delivery:
: That a specific recipient domain accepted the envelope
  identified by canonical hash at a specific time.

Sender, during the delivery session:
: That the envelope was delivered within a valid federation
  session between specific sender and recipient domains.

Recipient:
: That the envelope was signed by the claimed sender domain and,
  when the inner signature is present, by the claimed sender
  identity.

Third party holding a forwarded enclosure:
: Authorship of the forwarded plaintext by the original sender
  identity, independent of the forwarding path.

Third party holding an envelope file:
: That the envelope was produced by the claimed sender domain
  and has not been altered since.

Any party holding a migration record:
: That the old identity key, the new identity key, and (in
  cooperative mode) both provider domains co-authorized the
  address change.

The following claims are not established by the protocol:

That the recipient user read the envelope:
: Read status is an application concern and is not observable
  on the wire.

That the envelope was delivered to a specific device within the recipient's account:
: Per-device delivery events are private sync state and do not
  produce federation-visible artifacts.

That the envelope was not subsequently deleted by the recipient:
: SEMP does not model retention at the recipient. A receipt
  attests to acceptance with no statement about subsequent
  retention.

That a recipient address does or does not exist on a domain:
: Protocol responses do not disclose address existence (see
  [Address Enumeration Resistance](#address-enumeration-resistance)).

That a given sender or recipient was not also corresponding with other parties:
: Correspondent-graph privacy is a goal. Envelopes do not
  reveal other correspondents.

That two envelopes are part of the same conversation to an outside observer:
: Thread identifiers live in the encrypted brief and are not
  visible to routing infrastructure.

Implementations and higher-level protocols built on SEMP MUST NOT
claim evidence properties beyond those enumerated above. In
particular, a delivery receipt MUST NOT be described to users as
proof of read, proof of response, or proof of any application-layer
action the recipient took.

The wire-level evidence artifacts (seal signature, session MAC,
sender signature, delivery receipt, migration record) are specified
in [Envelope](envelope.md), [Delivery](delivery.md), and
[Recovery](recovery.md).

# Trust and Reputation Model

## Domain-Based Identity

A SEMP identity takes the form `user@domain`. The domain is the unit
of trust at the server-to-server level. The full address is the unit
of trust at the user level.

## Reputation Signals

SEMP defines the following observable reputation signals.

Domain registration age:
: Available via WHOIS, publicly verifiable, resistant to retroactive
  manipulation.

Abuse rate:
: The ratio of reported abuse events to message volume over a
  domain's operating history.

Trust gossip:
: A cryptographically hashed reputation value derived from a
  domain's trust history, publishable and verifiable by other SEMP
  servers without exposing the underlying data.

These signals are inputs to operator-defined policy. The reputation
mechanism is fully specified in [Delivery](delivery.md).

## Trust Transfer

When a domain changes ownership, the trust history associated
with it MAY be transferred from seller to buyer through a
cryptographic handshake requiring both parties' private keys.
The signed transfer record is published at each domain's
`reputation_transfer` endpoint, where other SEMP servers
fetch it as part of normal trust-gossip operation. Observers
apply their own policy regarding whether and how to honor the
inherited reputation. The transfer record schema, retention
window, verification rules, and asymmetric carry-over of
positive versus negative reputation are specified in
[Delivery](delivery.md).

## New Domain Behavior

A domain with no history starts at zero reputation. Servers MAY
apply additional caution to zero-reputation domains as a matter of
operator policy. They MUST NOT reject messages from zero-reputation
domains on that basis alone without explicit operator
configuration.

# Key Management Philosophy

SEMP requires cryptographic key pairs for domains and for
individual users. Private keys are the root of identity. Loss of a
private key results in loss of the associated trust history, which
cannot be recovered. Operators and users SHOULD maintain secure key
backups.

Key fetching (retrieving another party's public key before
communicating) can reveal communication intent to passive
observers. SEMP addresses this by supporting multiple key fetching
mechanisms with documented privacy tradeoffs, ordered by operator
preference.

Speculative batch crawling:
: Servers proactively fetch and cache keys on a schedule,
  decoupling the fetch from the communication intent. High
  privacy, higher infrastructure cost.

Third-party key relay:
: Fetches are proxied through an intermediary, obscuring the
  requester's identity from the target domain. Medium privacy,
  medium cost.

Direct well-known fetch:
: Keys are fetched on demand from the target domain's published
  endpoint. Lower privacy, lower cost.

Operators configure the order and fallback behavior. Detailed
mechanisms are specified in [Discovery](discovery.md).

# Blocking and Rejection

SEMP defines the following blocking requirements.

* Servers MUST check block lists before completing a handshake.

* Blocked senders MUST receive an immediate, explicit rejection
  with a reason code.

* A server MUST NOT silently accept an envelope and then
  discard it as a wire-visible default. Silent acceptance is
  permitted only as a deliberate recipient privacy policy
  (anti-harassment, mailbox quarantine, and similar
  narrowly-scoped cases) under the rules in
  [Delivery](delivery.md).

* Block events MAY be propagated to federation partners as policy
  signals. Partners apply their own policy in response and are not
  required to honor another server's block decisions.

Blocking operates at three levels of granularity: individual
address, domain-wide, and global emergency invalidation. Detailed
mechanisms, reason codes, and propagation rules are specified in
[Delivery](delivery.md).

# Legacy Interoperability

SEMP servers are SEMP-only. They do not speak SMTP, wrap legacy
messages, or deliver to legacy recipients on behalf of senders.
Legacy interoperability is handled at the client layer rather than
at the server layer.

When a sender's SEMP server determines via discovery that a
recipient domain has no SEMP support, it signals this to the
client with a `legacy_required` or `recipient_not_found` response.
The client then decides how to proceed.

* If SMTP credentials are configured for the sender's address, the
  client MAY send directly via SMTP after explicit user
  confirmation.

* Users MUST be informed that SEMP guarantees (sealed metadata,
  end-to-end encryption, explicit rejection) do not apply to
  legacy delivery.

Inbound legacy mail is handled by the client connecting directly
to the user's legacy retrieval provider (typically IMAP or POP3,
occasionally JMAP or a proprietary API) alongside their SEMP
server. The client presents legacy and SEMP messages in a unified
interface with a persistent, unambiguous origin indicator. The
SEMP server is never involved in legacy mail retrieval, and SEMP
does not constrain which legacy retrieval protocol the client
uses.

Legacy credentials (SMTP Submission, IMAP, POP3, or other) are
held by the client only and MUST NOT be transmitted to the SEMP
server.

Outbound SMTP messages MAY carry `SEMP-Capability`, `SEMP-Identity`,
`SEMP-Domain`, and `SEMP-Address` upgrade-signal headers so that a
SEMP-capable recipient client can offer a thread upgrade on reply.
The signal is advisory; recipient clients verify the advertised
identity against SEMP discovery before acting. Thread continuity
across mixed SEMP and legacy correspondence is maintained
client-side via a local Message-ID to brief identifier mapping.

Reason codes used at the discovery and delivery layers, including
`legacy_required` and `recipient_not_found`, are specified in
[Delivery](delivery.md).

# Relationship to Existing Standards

SEMP builds on existing standards where they serve its goals.

DNS:
: Server discovery, capability advertisement, key publication.

TLS:
: Transport security layer beneath SEMP's application-layer
  security.

BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)):
: Normative language throughout all SEMP specifications.

HTTP/2:
: Mandatory baseline transport for interoperability.

WebSocket and QUIC:
: Recommended additional transports, negotiated during discovery.

Internet Message Format ([RFC 5322](https://www.rfc-editor.org/rfc/rfc5322)):
: Reference for legacy interoperability mappings only. SEMP does
  not produce or consume [RFC 5322](https://www.rfc-editor.org/rfc/rfc5322) headers as part of native
  delivery.

SEMP operates as an application-layer protocol on top of DNS, TLS,
and the underlying transport. It replaces SMTP [RFC 5321](https://www.rfc-editor.org/rfc/rfc5321) for
message exchange; it relies on the rest of the stack as-is.

# Comparison with Related Systems

This section summarizes how SEMP relates to other protocols and
products that address overlapping problems. Each subsection is
informational and does not modify any normative requirement of this
document or its companions.

<a id="comparison-smtp"></a>

## SMTP
SMTP [RFC 5321](https://www.rfc-editor.org/rfc/rfc5321) transmits envelope and header metadata in
plaintext, anchors deliverability decisions to IP-based reputation
maintained by a small number of large operators, permits silent
acceptance followed by silent discard, provides no end-to-end
integrity proof tied to the sender's identity, and supports new
capabilities only through extension mechanisms that implementations
may ignore. SEMP encrypts envelope and header metadata, anchors
trust to cryptographic domain identity, requires explicit rejection
with a reason code for any envelope the recipient is willing to
disclose a refusal of, carries dual integrity proofs over the
canonical envelope bytes (a domain signature plus a session MAC)
together with an inner sender identity signature inside the
enclosure, and includes capability negotiation as a property of
every federated session.

SEMP is a new protocol rather than an SMTP revision. Legacy
interoperability with SMTP is a client-layer concern as specified
in {{legacy-interoperability}}.

## Dark Internet Mail Environment (DIME)

The Dark Mail Alliance proposed the Dark Internet Mail Environment
between 2013 and 2017. DIME defined a layered envelope format and
a transport protocol (DMTP) intended to provide metadata protection
over a federated email-shaped delivery model. DIME's Next-Hop,
Envelope, and Content layers correspond roughly to SEMP's postmark,
brief, and enclosure components.

SEMP differs from DIME in three respects. First, DIME retained SMTP
backward compatibility at the server layer through configurable
"Trustful", "Cautious", and "Paranoid" modes; SEMP is SEMP-only at
the server layer, with legacy interop confined to the client.
Second, DIME did not specify a reputation or anti-abuse model;
SEMP defines a domain-keyed reputation system, observation gossip,
and proof-of-work as part of the core specification. Third, DIME
did not reach a stable interoperable specification or sustained
deployment.

## OpenPGP and S/MIME

OpenPGP [RFC 4880](https://www.rfc-editor.org/rfc/rfc4880) and S/MIME [RFC 8551](https://www.rfc-editor.org/rfc/rfc8551) provide message body
encryption layered on top of SMTP. Envelope metadata, headers
(including the subject line in many configurations), and routing
information remain in plaintext on the wire. Key distribution is
performed out of band, through HKP key servers, web key
directories, manual fingerprint exchange, or X.509 certificate
authorities. SEMP protects metadata at the protocol layer by
structuring the envelope itself, and automates key distribution
through SEMP discovery.

OpenPGP and S/MIME remain applicable as enclosure content payloads
for clients that require their semantics. SEMP is independent of
the content payload format.

## Autocrypt and pretty Easy privacy (pEp)

Autocrypt and pEp deploy opportunistic OpenPGP encryption inside
SMTP, automating key discovery through in-band header
advertisement. Their security properties are constrained by the
SMTP substrate: envelope metadata remains visible, IP-keyed
reputation continues to apply, silent-discard semantics are
unchanged, and capability negotiation is limited to what SMTP
extensions allow. SEMP addresses these substrate properties at the
protocol layer.

## Messaging Layer Security (MLS)

MLS [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420) is a group key agreement protocol. It establishes
shared symmetric keys for participants in a group, with
post-compromise security and continuous group-membership
operations. MLS does not define a message envelope, a transport, a
routing model, a reputation system, or a delivery acknowledgment
scheme. SEMP and MLS operate at distinct layers and are
complementary.

The core SEMP cryptographic model uses stateless per-envelope key
wrapping under each recipient's published public key, which
preserves SEMP's asynchronous-recovery and durability semantics.
MLS is anticipated as a future SEMP extension for large-group
messaging, where the cost of per-recipient wrapping becomes a
constraint and where post-compromise security across a group
membership set is desirable.

## The Signal Protocol

The Signal Protocol provides end-to-end encryption with forward
secrecy and post-compromise security for two-party and small-group
messaging. The Signal deployment that uses it is centralized: all
traffic transits servers operated by a single organization, and
accounts are bound to phone numbers; the deployment does not
federate. SEMP achieves comparable cryptographic properties for
envelope confidentiality and session forward secrecy within a
federated architecture that uses domain-form addresses and
domain-keyed trust.

## Closed End-to-End Encrypted Email Products

Products such as ProtonMail and Tuta offer end-to-end encryption
between users of the same product, with opaque link-based
workarounds for messages addressed to recipients on other systems.
These deployments confirm user demand for encrypted email but do
not provide a federated protocol layer; communication with external
providers degrades to SMTP or to a non-protocol fallback. SEMP
provides the protocol layer that would enable independent providers
of encrypted email to interoperate.

<a id="document-series"></a>

# Document Series
SEMP is specified by a series of Internet-Drafts. This document is
the architectural cover and incorporates the consolidated threat
model in [Threat Model](#threat-model). The companion documents are listed below.

[Envelope](envelope.md):
: Envelope wire format (postmark, seal, brief, enclosure),
  sender identity signature, forwarding primitive, address
  canonicalization, envelope padding, encryption flow, algorithm
  suites, per-extension key scoping, media type registrations,
  and the `.semp` file format.

[Handshake](handshake.md):
: Client handshake, federation handshake, session lifecycle,
  forward secrecy, ephemeral key erasure, session rekeying,
  resumption tickets, post-quantum hybrid key agreement,
  transport bindings (WebSocket, HTTP/2, QUIC, gRPC), transport
  negotiation and fallback, and session invalidation.

[Discovery](discovery.md):
: DNS-based discovery (SRV, TXT capability records), well-known
  URI configuration document, configuration versioning and
  update notifications, domain key publication (DANE primary),
  user key publication, key rotation, key revocation, device
  directory, scoped device certificates, key fetching
  mechanisms, and reciprocity policy disclosure.

[Delivery](delivery.md):
: Acknowledgment semantics, signed delivery receipts,
  silent-mode disposition, queueing and retry, persistent silent
  recipient handling, staged delivery, delivery pipeline, block
  list, first-contact, user policy synchronization, recipient
  status, reputation signals, trust gossip publication and
  consumption, abuse reporting, trust transfer, and the
  authoritative reason-code registry.

[Recovery](recovery.md):
: Account recovery (server-assisted encrypted backup and Shamir
  device-split backup), restore flow, provider migration with
  cryptographic continuity, migration notice window, account
  closure with grace period, local-part reassignment rules, key
  transparency (Merkle-tree log per RFC 6962), inclusion and
  consistency proofs, augmented key fetch, and equivocation
  detection via observation gossip.

[Extensions](extensions.md):
: Wire-level extension framework, namespacing, criticality
  signaling, size constraints, extension registry, definition
  documents under `.well-known/semp-extensions/`, conflict
  detection, validation, lifecycle, anti-fragmentation rules,
  library extension enforcement, the `semp.dev/large-attachment`
  extension, and the full conformance requirement set covering
  server, client, federation peer, trust-gossip, algorithm
  suite, retention policy, version negotiation, clock skew
  tolerance, legacy interoperability, and delegation.

[Client](client.md):
: Client obligations: handshake, key registration (first-device
  and subsequent-device enrollment), delegated client
  registration and scope enforcement, envelope composition,
  sent-message availability, recipient key validation, BCC
  handling, forward composition, send-time obfuscation, envelope
  receipt and decryption, legacy-origin messages with
  upgrade-signal detection, message history sync, device sync
  (including the `delivery-disposition` kind), key management,
  `SEMP_KEYS` recipient key request protocol, envelope
  submission protocol, migration notice handling, legacy
  required fallback (MIME composition, upgrade-signaling
  headers, threading continuity), mixed-recipient consent
  gating, delivery state reporting, first-contact inbox, user
  policy synchronization, recipient status configuration, abuse
  reporting, notification content constraints, and security
  considerations.

Test vectors that exercise the wire formats defined in the drafts
above are distributed across the corresponding drafts as
illustrative appendices, and the canonical bytes are published in
the `vectors/v1.0.0/` directory of the SEMP specification
repository.

<a id="threat-model"></a>

# Threat Model
This section consolidates the threat model that SEMP is designed
against. It enumerates the actors involved in message delivery, the
adversary classes SEMP considers, what each adversary can and
cannot learn or influence under the specification as written, and
residual risks that the specification documents but does not
eliminate.

This section does not define new protocol behavior. Normative
requirements are defined in the companion documents and are cited
in context.

## Scope

This subsection describes:

* the actors involved in SEMP message delivery and key
  distribution;

* adversary classes grouped by capability and access;

* what each adversary can observe, modify, or forge under the
  current specification;

* known residual risks and how they are mitigated, accepted, or
  deferred.

It does not define new protocol behavior, operational security
practices for server operators, or legal, regulatory, or
compliance implications.

SEMP does not aim to defend against:

* targeted endpoint compromise (a user whose device is under
  adversary control has already lost confidentiality of the
  messages that device can read);

* side-channel attacks on cryptographic implementations (timing,
  power, and cache attacks are the domain of the underlying
  cryptography library);

* social engineering (a user who knowingly discloses their
  recovery secret has bypassed the protocol);

* compulsion applied to the home server (what a compelled server
  discloses is a legal question; what it technically possesses is
  defined in [Compromised Home Server](#compromised-home-server)).

## Actors and Trust Relationships

The actors involved in a SEMP exchange and key distribution are:

* the user, who owns a SEMP account and one or more devices;

* the client device, holding identity and encryption private keys
  or scoped delegated certificates;

* the home server, hosting the user's account, brokering outbound
  envelopes, accepting inbound envelopes, and storing the minimum
  state required;

* the recipient server, which has the same role as the home
  server, with "sender" and "recipient" labels assigned
  envelope-relative;

* federation peers, defined as any home server with which another
  home server is in active or cached session;

* routing infrastructure, defined as transport-layer intermediaries
  between any two servers;

* third-party domains, fetching public artifacts such as domain
  keys, user keys, or successor records;

* key relays, cooperative third-party services that fetch user
  keys on behalf of senders to reduce existence-oracle leakage;

* transparency monitors, independent services watching the
  key-transparency log for split-view attacks.

SEMP assumes the following trust relationships, expressed as "A
trusts B with respect to property P".

* A user trusts their client devices with the identity private
  key, the encryption private key history, and the plaintext of
  received envelopes. This is unavoidable because the client is
  the endpoint.

* A user trusts their home server with the user's correspondent
  graph, the user's block list, and the minimum envelope metadata
  required for delivery and policy enforcement.

* A user does NOT trust their home server with envelope enclosure
  plaintexts, recovery secrets, or the user's identity private
  key.

* A sending server trusts a recipient server to honor its
  published policies (first-contact, rate-limit, block semantics)
  but does not trust it with enclosure plaintext.

* A recipient server trusts the sending server's domain signature
  as proof of envelope origin, subject to revocation and
  transparency signals.

* All parties distrust routing infrastructure except for its
  delivery of ciphertext.

The user-server trust boundary is wider than the user-device
boundary because the server enforces user-level policy
(block list, first-contact gating, status configuration) and
brokers routing on the user's behalf. SEMP's privacy posture
is to minimize what the server learns rather than to
eliminate it. The recipient server observes the correspondent
graph as a structural consequence of user-level blocking
enforcement.

## Adversary Models

### Passive Network Observer

An adversary with the ability to observe network traffic between
two or more parties but no ability to modify, inject, or delay
messages.

Can observe:
: TCP and TLS connection metadata (source and destination IP,
  connection timing, byte counts); the approximate size and timing
  of SEMP exchanges; postmark-level source and destination domains
  during federation handshakes.

Cannot observe:
: Envelope plaintext. The brief and enclosure are encrypted
  under per-envelope symmetric keys. The seal exposes
  routing-essential metadata (algorithm identifier, sender
  domain key fingerprint, signature, MAC) in plaintext, but
  the per-recipient wrapped-key maps inside the seal are
  encrypted blobs that an observer cannot unwrap without the
  intended recipient's private key. Handshake confirm
  contents are encrypted after the key exchange. Session MAC
  values are meaningless without the session MAC key.

Residual leakage:
: Envelope sizes expose approximate content category, bounded to
  power-of-two buckets. Connection timing correlates to send and
  receive events. IP-level observation can deanonymize `.onion`
  deployments that also expose clearnet endpoints; see
  [Onion-Only Deployment Leakage via Clearnet Artifacts](#onion-deployment-leakage).

### Active Network Attacker

An adversary with the ability to modify, inject, delay, or drop
messages between parties, but without access to any party's
long-term key material.

The attacker can:

* deny service by dropping packets;

* delay envelopes to force retry behavior;

* attempt to downgrade cipher suite negotiation at the TLS layer;

* attempt to substitute public key records served by a home
  server the attacker can reach;

* replay prior session or envelope messages.

The attacker cannot:

* produce a valid handshake confirm without the session keys;

* produce a valid seal signature without the sender's domain
  signing key;

* produce a valid session MAC without the session MAC key;

* decrypt past envelopes absent compromise of the ephemeral key
  exchange material.

Defeats and mitigations:

* Replay: postmark expiry bounds envelope lifetime; session
  identifiers and session MACs bind envelopes to a specific
  session; first-contact tokens are single-use bound to envelope
  identifier.

* Downgrade: handshake confirm hash covers the negotiated cipher
  suite and configuration.

* Key substitution: transparency-log inclusion proofs and
  split-view detection via gossip.

The detailed wire-level mechanisms are specified in
[Handshake](handshake.md), [Envelope](envelope.md), and
[Recovery](recovery.md).

<a id="compromised-home-server"></a>

### Compromised Home Server
The home server of a user is under adversary control, whether by
compromise, compulsion, or malicious operation.

Observes about the user:
: Full correspondent graph of the user's inbound and outbound
  envelopes. Brief plaintexts after decryption using the server's
  domain key entry in the seal's brief recipients. Delivery
  timing and acknowledgment outcomes. The user's block list.
  Stored delivery receipts for the retention window. Device
  registration events and device identity public keys.

Does not observe:
: Enclosure plaintext. Enclosure keys are wrapped to the user's
  encryption key rather than to the server's domain key. The
  user's identity or encryption private keys. The user's recovery
  secret. The recovery bundle's payload.

Can do:

* delay or drop envelopes, either targeted or in bulk;

* decline to serve the user's key records or the backup bundle;

* fabricate envelopes addressed to the user (the user's client
  detects these because the envelope either lacks a sender
  signature or carries one that does not verify against the
  claimed sender's published identity key);

* publish a fraudulent successor record (detected by transparency
  monitors and by the recovery-key binding specified in
  [Recovery](recovery.md));

* issue a new user identity key (detected by transparency
  monitors; users may migrate to a new provider).

Cannot do:

* forge envelopes appearing to originate from the user to third
  parties (the sender's signature is computed by the client over
  the envelope seal, and the server holds no client signing
  material);

* decrypt envelopes sealed to the user (the encryption private
  key is client-held);

* unilaterally restore a user's account (recovery depends on a
  user-held secret or user-held share quorum).

### Compromised Recipient Server

The recipient's home server is under adversary control, from the
sender's perspective.

Observes:
: Full envelope ingress, including seal, brief ciphertext, brief
  plaintext after domain-key decryption, enclosure ciphertext.
  The sender's domain identity from the postmark. Delivery and
  rejection outcomes.

Does not observe:
: Enclosure plaintext, because enclosure keys are sealed to the
  user's encryption-key entries in the seal's enclosure
  recipients rather than to the server's domain-key entries.

Can do:
: Same envelope-fabrication and delay attacks as in
  [Compromised Home Server](#compromised-home-server), scoped to envelopes addressed to
  that domain. Can publish fraudulent recipient user keys subject
  to transparency detection.

Cannot do:
: Read enclosure content. Forge senders outside its own domain.

First-contact enforcement depends on the recipient server. The
proof-of-work or challenge gate (defined in
[Delivery](delivery.md)) is an admission control applied
after brief decryption and before delivery to the client. The
envelope's enclosure encryption does not depend on the challenge
solution. A recipient server that fails to enforce the policy,
through a bug, an alternate ingestion path, or operator action,
delivers the envelope to the client as though the gate had
passed.

This failure stays within the recipient server's trust boundary.
The gate protects the server's own users from unsolicited first
contact, so a server that declines to run it harms only those
users, who already depend on it for brief handling, block-list
enforcement, and delivery acknowledgment. It is not a
confidentiality boundary. Enclosure secrecy comes from the
per-recipient encryption and holds regardless of first-contact
enforcement.

A future extension MAY bind the challenge solution into the
enclosure key derivation, making a first-contact envelope
cryptographically unreadable without the solution. This document
does not define that binding. It would put the challenge solution
on the wire and complicate the server's brief-only handling path,
and the property it adds is largely subsumed by the
recipient-server trust model above.

### Colluding Servers

Two or more home servers cooperate to combine the information each
individually observes.

Joint observation:
: Sender domain to recipient domain pairings across all envelopes
  each collaborator handles. Sender and recipient user identities
  for envelopes where both endpoints are inside the collaborator
  set. Timing, size, and retry patterns.

Joint inference:
: Correspondent graph restricted to users on the collaborator
  domains. Approximate social graph from delivery timing and
  reply patterns.

Residual privacy:
: Users whose correspondents are split across collaborators and
  non-collaborators retain partial unlinkability. Enclosure
  plaintext remains protected; the collaborators gain no
  decryption capability beyond what each individually has.

### Compromised Key Relay

A cooperative third-party service used to fetch user public keys
is under adversary control.

Observes:
: Which users' keys are being fetched, by whom, and at what rate.

Cannot do:
: Substitute a user's key record, because the record carries the
  user's self-signature and the home server's domain signature. A
  relay returning a fraudulent record is detected at signature
  verification by the sender client.

Residual leakage:
: The relay observes communication-intent metadata (sender
  intends to write to user X). From the sender's privacy
  perspective, a compromised relay is therefore equivalent to
  having used a direct fetch to the recipient's home server; the
  relay's value is only realized if it remains honest.

<a id="compromised-endpoint"></a>

### Compromised Endpoint
A user's device is under adversary control.

Observes:
: All envelopes the device can decrypt, which is the full inbox
  and outbox for devices holding the user's identity and
  encryption private keys; a scoped subset for devices holding
  scoped delegated certificates.

Can do:
: Act as the user toward the home server until the compromise is
  detected and the device is revoked. Transmit the user's
  private keys to the adversary. Sign a new Shamir recovery
  manifest enrolling adversary-controlled devices.

Mitigations:

* Scoped delegated certificates limit the blast radius of
  compromising a device that holds only a delegated certificate.

* Device revocation with reason `key_compromise` triggers
  mandatory identity-key rotation and a successor record to
  correspondents. The revoked device cannot forge envelopes
  under the rotated identity key.

* The device directory is monotonically versioned and
  identity-signed; correspondents and delegated consumers reject
  device-scoped signatures from devices not listed in the
  current directory.

* Key transparency surfaces unauthorized key rotations.

SEMP does not claim recovery from endpoint compromise without user
intervention. Endpoint compromise is the dominant residual risk
and is acknowledged as such. The mandatory-rotation rule ensures
that detection-plus-revocation is sufficient to end the
adversary's ability to act as the user, limited only by how
quickly the user detects and revokes. Detailed mechanisms are in
[Discovery](discovery.md) and [Recovery](recovery.md).

### Key Compromise Scenarios

Loss of control of a long-term key has different consequences
depending on which key is lost.

Domain signing key:
: An attacker holding it signs envelopes as any user in the
  domain and impersonates the domain to peers. Detection:
  transparency-log monitors observe unexpected signing
  activity; peers observe revocation records; the domain is
  rotated.

User identity key:
: An attacker issues envelopes as the user, rotates the user's
  encryption keys, or signs a fraudulent successor record.
  Detection: transparency-log entries for unexpected key
  rotations; correspondents observe sudden address or
  behavior change.

User encryption key:
: An attacker decrypts envelopes previously sealed to that key
  until revocation propagates. Detection: none inline.
  Revocation records published; correspondents invalidate
  caches.

Device identity key:
: An attacker acts as that specific device until revoked. For
  primary devices, this approaches identity-key compromise.
  Detection: primary device revokes via the device-revocation
  mechanism.

Session long-term material:
: SEMP uses ephemeral session keys for every session. No
  session long-term key exists beyond those already listed.

Resumption ticket:
: An attacker who also observes the subsequent ephemeral key
  exchange derives the resumed session's keys. Detection:
  tickets are short-lived (7-day maximum).

Recovery secret:
: An attacker decrypts the user's backup bundle and recovers
  the user's prior identity and encryption private keys.
  Detection: none inline. Bundle rotation and
  transparency-monitored successor-record behavior bound
  exposure.

Shamir share (below threshold):
: Nothing useful. Shamir's Secret Sharing is
  information-theoretic below threshold.

Shamir shares (threshold or more):
: An attacker reconstructs the bundle key and, with bundle
  ciphertext, recovers the user's backup payload. Detection:
  none inline.

Forward secrecy of past session keys holds against every
key-compromise row above except for the resumption-ticket plus
ephemeral-key-exchange-observation combination.

## Information Visibility by Party

The following table states what each party to an envelope exchange
observes under the specification as written.

| Party | Postmark domains | Brief ciphertext | Brief plaintext | Enclosure ciphertext | Enclosure plaintext |
|---|---|---|---|---|---|
| Sender client | Yes | Yes | Yes | Yes | Yes |
| Sender home server | Yes | Yes | Yes | Yes | No |
| Routing infrastructure | Yes | Yes (opaque) | No | Yes (opaque) | No |
| Recipient home server | Yes | Yes | Yes | Yes | No |
| Recipient client | Yes | Yes | Yes | Yes | Yes |
| Passive network observer | Yes (domains) | Yes (opaque) | No | Yes (opaque) | No |

"Yes (opaque)" means the bytes are visible but are ciphertext under
keys the observer does not hold. The recipient server learns the
sender and recipient addresses from the brief plaintext; passive
network observers see only domain-level information.

## What SEMP Defends Against

This subsection summarizes the protections that SEMP provides.
Detailed rationale is in the cited companion documents.

* Metadata disclosure to routing infrastructure. The sealed
  envelope model exposes only routing-essential domains.

* Forged envelopes. The seal carries a domain signature
  (verifiable by any party) and a session MAC (verifiable by the
  recipient server). An end-to-end sender signature inside the
  enclosure is verified by the recipient client.

* Silent acceptance with discard as a wire-visible default.
  Explicit reject-with-reason is mandatory for well-formed
  envelopes. Silent acceptance, where the recipient server
  accepts the envelope on the wire and then discards it
  without notifying the sender, MAY be applied only as a
  deliberate recipient privacy policy (anti-harassment,
  mailbox quarantine, and similar narrowly-scoped cases) and
  is subject to timing rules that keep it indistinguishable
  from unrelated network failure.

* Downgrade attacks on session establishment. The handshake
  confirm hash covers the negotiated parameters.

* Retroactive decryption of past sessions. Ephemeral key
  exchange on every session, with hybrid post-quantum
  confidentiality against harvest-now-decrypt-later adversaries.

* Existence oracles. Indistinguishable rejection for non-existent
  addresses. Optional speculative key caching and relay fetch.

* Key substitution. Transparency-log inclusion proofs and
  gossip-based split-view detection.

* Recovery under operator distrust. The server is a custodian of
  encrypted material only; it cannot initiate, gate, or observe
  recovery.

* Cross-envelope first-contact token replay. Tokens are
  single-use and bound to the envelope identifier.

* Unauthorized Shamir share injection at restore. The recovery
  set manifest binds each share to a specific device identity
  key.

* Envelope-size traffic analysis at bucket resolution. Wire size
  is padded to the nearest power-of-two bucket. Content-category
  inference is bounded to the bucket; the exact size is not
  exposed.

* Recipient-count and group-size disclosure via seal structure.
  Recipient maps are padded to power-of-two entry counts with
  indistinguishable dummy entries. Group size is revealed only at
  bucket resolution.

* Correspondent-graph inference via reputation gossip counts.
  Observation metrics are published as power-of-two buckets rather
  than exact counts. Intersection attacks are bounded to bucket
  width.

## What SEMP Does Not Defend Against

These are acknowledged residual risks. Each is addressed in the
cited companion document.

### Endpoint Compromise

A compromised user device has access to everything that device
can decrypt. Scoped delegated certificates limit blast radius but
do not prevent compromise. See [Compromised Endpoint](#compromised-endpoint) and
[Discovery](discovery.md).

### Correspondent Graph at the Home Server

The recipient home server observes the full inbound and outbound
correspondent graph of its users. This is a structural
consequence of server-side user policy enforcement (block lists,
first-contact gating) and is acknowledged as a residual risk.
There is no technical mitigation within the current
specification; defense depends on operator selection.

### Traffic Analysis by Envelope Size and Timing

Envelope sizes reveal approximate content category (short text,
image, attached document) only at the bucket resolution defined
in [Envelope](envelope.md). Wire sizes are padded to powers
of two between 1 KB and a per-domain maximum, so every envelope
is indistinguishable in size from every other envelope in the
same bucket.

Send timing correlates to user activity. Clients MAY apply a
send-time obfuscation mechanism that delays submission by an
operator-configurable random interval up to 60 seconds by
default. The mechanism reduces the temporal resolution available
to a passive network observer but is not sufficient to defeat
active adversaries or observers with large-window correlation
capabilities. SEMP does not provide mixnet-class timing
unlinkability.

The send-time delay does not hide correspondent pairs from the
sender's or recipient's home server (either observes every
envelope it routes regardless of when it was submitted). It does
not hide aggregate activity patterns over windows larger than the
delay bound. It does not provide the unlinkability properties of
a mix network. Users with threat models that require those
properties SHOULD use a purpose-built mixnet for the affected
correspondence.

### Social-Graph Inference from Reputation Gossip

Reputation observations published by servers include counts of
senders and envelopes observed from each peer domain. Counts are
published as power-of-two buckets rather than as exact values.
Third parties observing multiple gossip records cannot intersect
them below the bucket width, which reduces but does not eliminate
domain-pair correspondent-graph inference. The residual signal
is intentional: it preserves reputation utility while bounding
leakage. Detail is in [Delivery](delivery.md).

### Migration-Record Linkability

Migration records are published in plaintext at both the old and
new provider, mapping old addresses to new ones for any
observer. A user re-identifying themselves across providers
cannot do so anonymously under the current migration flow.
Detail is in [Recovery](recovery.md).

### Compelled Disclosure by the Home Server

A home server that is compelled to disclose data can provide the
correspondent graph, stored delivery receipts, and the user's
block list. It cannot provide envelope enclosure plaintexts,
encryption private keys, or recovery secrets, because it does
not hold them. What a compelled server is required to disclose
is a legal question outside the scope of this specification.

<a id="onion-deployment-leakage"></a>

### Onion-Only Deployment Leakage via Clearnet Artifacts
A `.onion` deployment's anonymity posture is defined by an
operator contract specified in [Discovery](discovery.md).
Tor-only deployments MUST NOT publish DNS SRV, TXT, or well-known
URI records under any clearnet name that references the same
backend; MUST NOT publish domain or user keys at any clearnet
endpoint; and MUST use standard three-hop onion services rather
than single-hop variants. Key fetches for `.onion` recipients are
restricted to Tor circuits; a sender without Tor egress MUST NOT
attempt clearnet fallback.

Residual risk. A Tor-only deployment that violates the operator
contract (by accident or misconfiguration) can still be
deanonymized by correlating the offending clearnet access with
the onion service. The specification names the contract and the
consequences of violating it; it cannot technically prevent a
misconfigured deployment.

### Fan-Out Patterns from Large Recipient Sets

A sender delivering an envelope to a large recipient set exposes
the size of that set only at the bucket resolution defined in
[Envelope](envelope.md). Recipient maps are padded to
power-of-two entry counts with dummy entries indistinguishable
from real wrapped keys. A group message to 50 real recipients
appears identical in structure to a group message to 64 real
recipients. Residual leakage is the bucket index itself.

## Residual Risks and Open Problems

All acknowledged residual risks are scoped and mitigated to the
extent that this specification addresses them.

* Envelope size is padded to power-of-two buckets; see
  [Envelope](envelope.md).

* Recipient-count leakage is padded to power-of-two entry counts;
  see [Envelope](envelope.md).

* Reputation-count leakage is bucketed; see
  [Delivery](delivery.md).

* Timing correlation is mitigated at the client layer via an
  OPTIONAL send-time delay mechanism. Mixnet-class unlinkability
  is out of scope.

* Onion-only leakage is scoped to operator-contract violations;
  see [Discovery](discovery.md).

* Endpoint compromise is bounded by mandatory identity-key
  rotation on `key_compromise` device revocation; see
  [Discovery](discovery.md).

Future revisions of these specifications MAY narrow these risks
further if implementation experience identifies new mitigations.
The specifications do not claim protections beyond those named
here.

# Security Considerations

This document is the architectural cover for the SEMP series. It
does not, by itself, define wire-level cryptographic mechanisms;
each companion document carries its own Security Considerations
section that pertains to the layer it specifies.

The consolidated threat model in [Threat Model](#threat-model) aggregates the
adversary classes, residual risks, and information-visibility
posture across the series. Implementers SHOULD treat
[Threat Model](#threat-model) as the cross-document reference when assessing
whether SEMP's guarantees match a given operating environment.

The following architectural invariants are normative on
implementations and operators across the entire series.

* The IP address visible at the transport layer MUST NOT be used
  as input to a protocol-layer trust decision. See
  {{transport-vs-trust-separation}}.

* Per-address existence MUST NOT be observable through any
  protocol-defined response. See
  [Address Enumeration Resistance](#address-enumeration-resistance).

* A server MUST NOT silently accept an envelope and then
  discard it as a wire-visible default. See
  [Explicit Rejection](#rejection-must-be-explicit).

* A SEMP server MUST NOT speak SMTP. Legacy interoperability is a
  client-layer responsibility. See {{legacy-interoperability}}.

* Implementations MUST NOT claim evidence properties beyond those
  enumerated in [Evidence Properties](#evidence-properties).

Violation of any of the above by an implementation makes that
implementation non-conformant.

<a id="protocol-constants"></a>

# Protocol Constants
This section is a cross-cutting navigational index of the
constant values pinned across the SEMP series. It is not a
normative source; each value's normative definition lives in
the draft cited in the "Defined in" column. Implementations
MUST follow the cited section.

## Size Caps

| Constant | Value | Source |
|---|---|---|
| `postmark.extensions` max bytes | 4096 (4 KiB) | [Extensions](extensions.md) |
| `brief.extensions` max bytes | 16384 (16 KiB) | [Extensions](extensions.md) |
| `enclosure.extensions` max bytes | implementation-defined; bounded by `max_envelope_size` | [Extensions](extensions.md) |
| Trust-gossip observation record max bytes | 16384 (16 KiB) in canonical UTF-8 JSON | [Delivery](delivery.md) |
| Trust-gossip evidence fetch RECOMMENDED max | 1048576 (1 MiB) | [Delivery](delivery.md) |
| Envelope size buckets | powers of two from 4096 to `max_envelope_size` | [Envelope](envelope.md) |
| Local-part max octets | 64 | [Envelope](envelope.md) |
| Address max octets (composed) | 254 | [Envelope](envelope.md) |
| Matcher entry max count | 10000 | [Discovery](discovery.md) |

## Time Bounds

| Constant | Value | Source |
|---|---|---|
| Migration `notice_window_until` minimum | 30 days | [Recovery](recovery.md) |
| Migration `notice_window_until` RECOMMENDED | 180 days | [Recovery](recovery.md) |
| Migration `notice_window_until` maximum | 730 days | [Recovery](recovery.md) |
| Account closure grace period minimum | 604800 s (7 days) | [Recovery](recovery.md) |
| Resumption ticket `expires_at` maximum | 7 days from issuance | [Handshake](handshake.md) |
| Federation session TTL default | 3600 s (1 hour) | [Handshake](handshake.md) |
| Client session TTL default | 300 s (5 minutes) | [Handshake](handshake.md) |
| Persistent silent observation window minimum | 24 hours | [Delivery](delivery.md) |
| Persistent silent shortened deadline RECOMMENDED | 4 hours | [Delivery](delivery.md) |
| Persistent silent counter idle expiry RECOMMENDED | 30 days | [Delivery](delivery.md) |
| Reputation evaluation window RECOMMENDED | 30 days | [Delivery](delivery.md) |
| Recovery bundle retention minimum | 30 days (superseded bundles) | [Recovery](recovery.md) |
| STH freshness bound | 1 hour | [Recovery](recovery.md) |
| Delivery receipt retention maximum | 30 days | [Delivery](delivery.md) |
| Transparency record retention minimum | 2 years | [Recovery](recovery.md) |
| Connection timeout RECOMMENDED | 10 seconds | [Handshake](handshake.md) |
| Clock skew tolerance default per hop | 5 minutes | [Handshake](handshake.md) |
| Discovery TXT TTL minimum | 60 seconds | [Discovery](discovery.md) |
| Discovery TXT TTL maximum | 7 days | [Discovery](discovery.md) |

## Numeric Thresholds

| Constant | Value | Defined in |
|---|---|---|
| Trust-gossip publication eligibility minimum envelopes | 16 | [Delivery](delivery.md) §Publication Eligibility |
| Persistent silent consecutive-silent threshold | 5 | [Delivery](delivery.md) §Persistent Silent Recipients |
| Proof-of-work difficulty cap | 28 bits | [Delivery](delivery.md) §Proof of Work |
| PoW expiry floor at difficulty ≤ 20 | 30 seconds | [Delivery](delivery.md) §Proof of Work |
| PoW expiry floor at difficulty 21..24 | 60 seconds | [Delivery](delivery.md) §Proof of Work |
| PoW expiry floor at difficulty 25..28 | 120 seconds | [Delivery](delivery.md) §Proof of Work |
| Extension cap per protocol version | 20 | [Extensions](extensions.md) §Anti-Fragmentation |

## Magic Strings

### Well-known URL paths

| Path | Purpose | Defined in |
|---|---|---|
| `/.well-known/semp/configuration` | Domain SEMP configuration document | [Discovery](discovery.md) §Discovery Configuration |
| `/.well-known/semp/domain-keys` | Domain signing and encryption public keys | [Discovery](discovery.md) §Key Publication |
| `/.well-known/semp/keys/{address}` | Per-address user key publication | [Discovery](discovery.md) §Key Publication |
| `/.well-known/semp/reputation/{subject}` | Trust-gossip observation publication | [Delivery](delivery.md) §Trust Gossip |
| `/.well-known/semp-extensions/{name}.json` | Extension definition document (canonical form per RFC 8615) | [Extensions](extensions.md) §Definition Documents |

### HTTP/2 path templates

| Path | Method | Defined in |
|---|---|---|
| `/v1/discovery/{address}` | `GET` (also accepts `POST` for callers requiring a signed body) | [Handshake](handshake.md) §HTTP/2 |
| `/v1/keys/{address}` | `GET` (also accepts `POST`) | [Handshake](handshake.md) §HTTP/2 |
| `/v1/handshake` | `POST` | [Handshake](handshake.md) §HTTP/2 |
| `/v1/envelope` | `POST` | [Handshake](handshake.md) §HTTP/2 |
| `/v1/session/{id}` | `GET` (Server-Sent Events for the long-lived session stream) | [Handshake](handshake.md) §HTTP/2 |

### DNS records

| Name | Purpose | Defined in |
|---|---|---|
| `_semp._tcp.{domain}` SRV | Server endpoint discovery (TCP-based transports) | [Discovery](discovery.md) §SRV Records |
| `_semp._udp.{domain}` SRV | Optional QUIC endpoint override (UDP) | [Discovery](discovery.md) §SRV Records |
| `_semp._tcp.{domain}` TXT | Protocol version and capability advertisement (`v=semp1;...`) | [Discovery](discovery.md) §TXT Records |

### Extension identifiers (core, `semp.dev/` namespace)

| Identifier | Purpose | Defined in |
|---|---|---|
| `semp.dev/device-sync` | Device-sync envelope marker | [Client](client.md) §Device Sync Marker |
| `semp.dev/large-attachment` | Out-of-band attachment storage descriptor | [Extensions](extensions.md) §large-attachment |

### Upgrade-signal SMTP headers (legacy interop)

| Header | Defined in |
|---|---|
| `SEMP-Capability` | [Client](client.md) §Upgrade-Signaling Headers |
| `SEMP-Identity` | [Client](client.md) §Upgrade-Signaling Headers |
| `SEMP-Domain` | [Client](client.md) §Upgrade-Signaling Headers |
| `SEMP-Address` | [Client](client.md) §Upgrade-Signaling Headers |

### Signature domain-separation prefixes

Every Ed25519 signature in the SEMP protocol is computed over
canonical bytes prefixed with a domain-separation tag. The
prefixes registered across the series are:

| Prefix | Used by | Defined in |
|---|---|---|
| `SEMP-ENVELOPE:` | seal signature | [Envelope](envelope.md) §Signature Domain Separation |
| `SEMP-HANDSHAKE:` | handshake server / federation message signatures | [Handshake](handshake.md) |
| `SEMP-IDENTITY:` | inner identity-proof signature | [Handshake](handshake.md) §Identity Proof |
| `SEMP-KEYS:` | SEMP_KEYS response signatures | [Discovery](discovery.md) |
| `SEMP-CONFIGURATION-UPDATE:` | SEMP_CONFIGURATION_UPDATE | [Discovery](discovery.md) |
| `SEMP-DELIVERY-RECEIPT:` | signed delivery receipt | [Delivery](delivery.md) |
| `SEMP-USER-POLICY:` | signed user-policy message | [Delivery](delivery.md) |
| `SEMP-STATUS:` | signed SEMP_STATUS record | [Delivery](delivery.md) |
| `SEMP-TRUST-OBSERVATION:` | signed observation record | [Delivery](delivery.md) |
| `SEMP-TRUST-TRANSFER:` | signed trust-transfer record | [Delivery](delivery.md) |
| `SEMP-REPUTATION-REFERENCES:` | signed references document | [Delivery](delivery.md) |
| `SEMP-ABUSE-REPORT:` | signed abuse-report record | [Delivery](delivery.md) |
| `SEMP-FORWARDER-ATTESTATION:` | forwarder attestation | [Envelope](envelope.md) §Forwarding Provenance |
| `SEMP-RECOVERY-BUNDLE:` | SEMP_RECOVERY_BUNDLE | [Recovery](recovery.md) |
| `SEMP-RECOVERY-MANIFEST:` | SEMP_RECOVERY_SET_MANIFEST | [Recovery](recovery.md) |
| `SEMP-RECOVERY-SHARE:` | SEMP_RECOVERY_SHARE | [Recovery](recovery.md) |
| `SEMP-SUCCESSOR-RECORD:` | SEMP_SUCCESSOR | [Recovery](recovery.md) |
| `SEMP-MIGRATION-RECORD:` | SEMP_MIGRATION | [Recovery](recovery.md) |
| `SEMP-ACCOUNT-CLOSURE:` | SEMP_ACCOUNT_CLOSURE | [Recovery](recovery.md) |
| `SEMP-TRANSPARENCY-STH:` | transparency Signed Tree Head | [Recovery](recovery.md) |
| `SEMP-DEVICE-REGISTER:` | device registration | [Discovery](discovery.md) |
| `SEMP-DEVICE-AUTHORIZE:` | device authorization | [Discovery](discovery.md) |
| `SEMP-DEVICE-DIRECTORY:` | device directory record | [Discovery](discovery.md) |
| `SEMP-DEVICE-REVOCATION:` | device revocation record | [Discovery](discovery.md) |
| `SEMP-REVOCATION:` | domain / user key revocation | [Discovery](discovery.md) |
| `SEMP-KEY-SELF-SIG:` | key self-signature | [Discovery](discovery.md) |

## Vocabulary Enums

| Enum | Values | Defined in |
|---|---|---|
| Algorithm suites | `x25519-chacha20-poly1305`, `pq-kyber768-x25519` | [Handshake](handshake.md) §Cryptographic Suites |
| Handshake reason codes | `blocked`, `auth_failed`, `policy_forbidden`, `handshake_expired`, `handshake_invalid`, `no_session`, `rate_limited`, `challenge`, `challenge_failed`, `challenge_invalid`, `server_at_capacity`, `version_unsupported`, `resumption_failed`, `revoked` | [Delivery](delivery.md) §Handshake Reason Codes |
| Envelope reason codes | `blocked`, `seal_invalid`, `session_mac_invalid`, `envelope_expired`, `envelope_size_exceeded`, `policy_forbidden`, `auth_failed`, `handshake_invalid`, `handshake_expired`, `no_session`, `server_unavailable`, `extension_unsupported`, `extension_size_exceeded`, `scope_exceeded`, `scope_invalid`, `certificate_expired`, `quota_exceeded` | [Delivery](delivery.md) §Envelope Reason Codes |
| Rekeying reason codes | `session_expired`, `rekey_unsupported`, `rate_limited` | [Delivery](delivery.md) §Rekeying Reason Codes |
| User-policy reason codes | `policy_kind_unsupported`, `policy_op_invalid`, `policy_version_stale`, `policy_collision` | [Delivery](delivery.md) §User Policy Reason Codes |
| Cancellation refused reason codes | `not_found`, `scope_exceeded`, `unauthorized` | [Client](client.md) §Refused Cancellation |
| Trust-transfer reasons | `key_rotation`, `sold`, `merged`, `corporate_reorganization`, `inherited`, `other` | [Delivery](delivery.md) §Transfer Reasons |
| Submission status | `delivered`, `rejected`, `silent`, `legacy_required`, `recipient_not_found`, `error` | [Delivery](delivery.md) §Submission Status Values |
| SEMP_KEYS result status | `found`, `not_found`, `legacy_required`, `recipient_not_found`, `error` | [Client](client.md) §Recipient Key Request Protocol |
| Recipient status state | `available`, `away`, `do_not_disturb` | [Delivery](delivery.md) §Recipient Status |
| Status visibility mode | `nobody`, `users`, `everyone` | [Delivery](delivery.md) §Recipient Status |
| Abuse categories | `spam`, `harassment`, `phishing`, `malware`, `protocol_abuse`, `impersonation`, `observation_record_abuse`, `other` | [Delivery](delivery.md) §Abuse Reporting |
| Extension validation failure | `data_schema_mismatch`, `placement_violation`, `criticality_unsupported`, `size_exceeded`, `version_unsupported`, `definition_signature_invalid`, `unknown_extension` | [Extensions](extensions.md) §Validation Failures |
| Migration mode | `cooperative`, `unilateral` | [Recovery](recovery.md) §Migration Modes |
| Reciprocity policy mode | `none`, `lenient`, `strict` | [Discovery](discovery.md) §Reciprocity Policy |
| Domain key revocation reasons | `key_compromise`, `superseded`, `cessation_of_operation`, `temporary_hold` | [Discovery](discovery.md) §Revocation Reasons |
| Device revocation reasons | `key_compromise`, `lost`, `retired`, `superseded` | [Discovery](discovery.md) §Device Revocation Reasons |

# IANA Considerations

This document has no IANA actions. Registries defined by SEMP are
specified in the relevant companion documents:
[Envelope](envelope.md) (media types),
[Delivery](delivery.md) (error and reason codes), and
[Extensions](extensions.md) (extension namespace).

# Acknowledgments

The author thanks the contributors to the SEMP specification for
review, design discussion, and prior-art analysis.

