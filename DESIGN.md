# SEMP Design Philosophy and Principles

**Sealed Envelope Messaging Protocol**  
Status: Internet-Draft  
Version: 0.2.0-draft  
Date: 2025-06

---

## Abstract

SEMP (Sealed Envelope Messaging Protocol) is a federated messaging protocol
that addresses five structural limitations of SMTP: metadata exposure,
IP-based reputation as a trust anchor, the absence of explicit verifiable
rejection, the lack of end-to-end message integrity guarantees, and
insufficient extensibility. SEMP is designed for incremental deployment
alongside existing email infrastructure.

---

## 1. Introduction

SMTP [RFC 5321] was designed for a trusted network among known participants.
Subsequent extensions (SPF [RFC 7208], DKIM [RFC 6376], DMARC [RFC 7489],
STARTTLS [RFC 3207]) address individual symptoms but do not resolve the
underlying structural limitations.

SEMP addresses the following five limitations at the protocol level:

1. SMTP transmits message metadata (sender, recipient, subject, timestamp)
   in cleartext. Every intermediary that handles a message can observe this
   metadata. Body encryption (PGP, S/MIME) does not protect the envelope.

2. SMTP trust is anchored to IP addresses. New mail servers are treated as
   untrusted until they accumulate reputation through mechanisms controlled
   by a small number of large operators with opaque criteria.

3. SMTP lacks an explicit rejection mechanism. Servers may accept messages
   they intend to discard, providing false delivery confirmation to senders
   and silently dropping messages intended for recipients.

4. SMTP provides no end-to-end integrity guarantee. A message may be altered
   in transit by any intermediary. DKIM provides a partial signature over
   selected headers and body, but it is bound to the sending domain's
   outbound server, not to the sender's identity. SEMP envelopes carry two
   independent integrity proofs over the same canonical bytes: a domain key
   signature verifiable by any routing server, and a session MAC verifiable
   only by the receiving server. Delivery without a valid established session
   is cryptographically impossible.

5. SMTP was not designed for extensibility. Adding new capabilities requires
   either backwards-incompatible changes or optional extension headers that
   implementations may ignore. SEMP includes capability negotiation as part
   of every connection, allowing new features to be introduced without
   breaking existing implementations.

---

## 2. Design Principles

These principles govern every technical decision in SEMP. When a specification
is ambiguous, these principles are the tiebreaker.

### 2.1 The Envelope Must Be Sealed

A SEMP envelope conceals its contents from all parties except the intended
recipient. Envelopes expose only the information necessary for routing.
All other fields (sender identity, recipient identity, subject, body,
attachments) are encrypted before transmission and visible only to the
parties that hold the appropriate keys.

### 2.2 Trust Is Anchored to Domains

SEMP builds its reputation and trust model on domain identity rather than
IP address history. A new domain starts with zero reputation. Trust is earned
through observed behavior over time and is observable, transferable, and
cryptographically verifiable.

#### 2.2.1 Transport vs Trust Separation

IP addresses are visible to SEMP implementations at the transport layer
because TCP/IP requires them. This visibility is unavoidable. However,
IP addresses MUST NOT be used as inputs to protocol-layer trust
decisions. The separation is:

- **Transport-layer operational defenses** MAY be IP-keyed. SYN flood
  protection, per-IP connection caps, TLS handshake rate limiting, and
  network-level DDoS mitigation operate on traffic characteristics and
  are legitimate uses of IP addresses.
- **Protocol-layer trust decisions** MUST be domain-keyed. Reputation,
  block lists, delivery policy, gossip observations, abuse reports, and
  federation rate limits that feed into trust evaluation all anchor to
  cryptographic domain identity, never to IP.

An implementation that lets IP signals influence protocol-layer trust
decisions is non-conformant. An operator defending against connection-
level abuse at the transport layer is not thereby corrupting the trust
model, provided the IP-keyed decision stays at the transport layer and
never appears in federation-visible state (block list propagation,
observation records, abuse reports, rate-limit responses carrying a
SEMP reason code).

This separation has operational consequences that the protocol embraces
deliberately:

- Multiple unrelated SEMP domains MAY share a single IP (shared HTTPS
  hosting). One bad neighbor MUST NOT contaminate the reputation of the
  others.
- A SEMP domain MAY present many IPs (CDN, multi-region, failover). The
  domain's accumulated reputation MUST persist across IP changes.
- A SEMP domain MAY be reached exclusively over Tor via a `.onion`
  address. The source IP of incoming federation traffic is a Tor
  circuit exit, and the receiving server MUST NOT use that IP as a
  trust signal. Tor-only deployments follow the discovery and
  key-fetch rules defined in `DISCOVERY.md` section 2.5 and
  `KEY.md` section 6.4.
- A SEMP domain MAY rotate its hosting infrastructure (change IPs
  entirely) without disturbing its reputation. Conversely, an IP
  previously associated with an abusive SEMP domain MUST NOT
  automatically taint a different SEMP domain now hosted on the same IP.

Conformant servers MUST accept federation handshakes regardless of
source IP, subject only to domain-level policy and transport-layer
operational defenses.

### 2.3 Rejection Must Be Explicit

When a SEMP server declines to accept a message, it MUST say so immediately and
explicitly, with a reason code. Silent acceptance followed by silent discard is
prohibited.

### 2.4 Policy Is the Operator's Responsibility

SEMP defines what information is available and what signals exist. Trust scores,
reputation thresholds, blocking rules, and federation allowlists are policy
decisions that belong to server operators.

### 2.5 Extensibility Is Required

SEMP is designed to be extended without fragmentation.
Capability negotiation occurs at every connection. New message types, encryption
algorithms, transport protocols, and trust mechanisms can be introduced without
breaking existing implementations.

Where multiple valid solutions exist to a problem, SEMP defines the interface
and supports all solutions as options rather than mandating one. This applies to
key fetching mechanisms, trust gossip implementations, cryptographic algorithm
selection, and transport protocols.

### 2.6 Privacy Leaks Are Documented

Some operations in SEMP reveal information about communication intent. Key
fetching, protocol discovery, and handshake initiation can leak the fact that a
sender intends to communicate with a recipient.

Where such leaks exist, the specification documents them explicitly, describes
their severity, and provides mechanisms to mitigate them.

### 2.7 Per-Address Existence Is Not Observable

A SEMP server MUST NOT permit a sender to determine, from any
protocol-defined response, whether a particular recipient address exists
on the recipient domain. This applies to discovery responses, key fetch
responses, envelope rejection reason codes, and rejection response
timing.

Concretely:

- Per-address existence MUST NOT be encoded in any reason code returned
  to the sender. Non-existent addresses and policy-rejected existing
  addresses MUST receive the same `policy_forbidden` rejection.
- Discovery responses are domain-scoped, not address-scoped, per
  `DISCOVERY.md` section 1 and section 7.
- Key fetch for an unknown address MUST return a response that is
  indistinguishable in shape, size, and timing from a fetch for an
  existing address whose owner has not published keys.
- First-contact challenges, rate limits, and any other gating
  mechanisms MUST be applied identically to existent and non-existent
  recipient addresses, so that the gating itself does not constitute
  an oracle.

The address book of a domain is private. A sender's correspondence
intent is observable only at the domain level absent a successful
delivery.

---

## 3. Non-Goals

SEMP explicitly does not attempt to:

- **Eliminate spam universally.** SEMP provides better tools for reputation and
  rejection, but determined abuse at scale is a social and economic problem that
  no protocol can solve alone. SEMP raises the cost of abuse.

- **Replace SMTP overnight.** SEMP is designed for incremental adoption. Users
  may maintain both SEMP and SMTP accounts during the transition period. SEMP
  clients SHOULD support SMTP/IMAP access alongside SEMP, allowing users to
  manage legacy correspondence without switching clients. The server is
  SEMP-only; legacy mail handling is a client responsibility.

- **Guarantee anonymity.** SEMP provides metadata protection significantly
  stronger than SMTP. It does not provide the anonymity guarantees of systems
  like Tor or Mix networks. Operators who require stronger anonymity properties
  may implement additional layers; SEMP does not prohibit this.

- **Solve the key exchange intent leak completely.** No federated messaging
  protocol can eliminate the observable fact that server A contacted server B.
  SEMP provides multiple mechanisms to mitigate this leak and documents the
  residual exposure.

- **Be opinionated about cryptographic algorithms beyond minimum requirements.**
  SEMP specifies minimum acceptable algorithms and supports negotiation of
  stronger ones.

---

## 4. The Envelope Model

SEMP's core message unit is the **envelope**. Its structure is modeled on
physical correspondence:

```
envelope
  ├── postmark     outer public header, visible to routing servers
  ├── seal         cryptographic integrity proof, tamper evident
  ├── brief        inner private header, encrypted, recipient only
  └── enclosure    message body and attachments, encrypted, recipient only
```

### 4.1 Postmark

The postmark contains only what is necessary for a server to route and deliver
the message. It does not contain sender or recipient addresses in full. It does
not contain a subject. It does not contain a timestamp that could be used to
correlate communication patterns with precision.

A routing server can read the postmark and no other component.

### 4.2 Seal

The seal provides cryptographic proof that the envelope has not been tampered
with in transit. It covers the entire envelope. A broken or invalid seal MUST
cause the receiving server to reject the message immediately and explicitly.

### 4.3 Brief

The brief contains the routing metadata of the correspondence: full sender and
recipient addresses, timestamps, thread identifiers, and reply information. It
is encrypted and decryptable by both the recipient server (for delivery and
policy enforcement) and the recipient client. It is not visible to any other
server handling the message in transit.

The subject is not in the brief. It is semantic content and belongs in the
enclosure, where it is protected from server exposure.

### 4.4 Enclosure

The enclosure contains the message body and any attachments. It is encrypted
under the recipient's key. Content type negotiation occurs within the enclosure.
The enclosure is never visible to routing infrastructure.

### 4.5 Evidence Properties

SEMP is explicit about what each party can and cannot prove from the
artifacts they hold. An evidence claim is a statement a party can back with
cryptographic verification against published keys, independent of any
server's continued cooperation.

The following table enumerates what the protocol establishes.

| Party                                                       | What the artifacts prove                                                                                                                                                         | Relevant artifact                                                                 |
|-------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------|
| Sender                                                      | Authorship of the plaintext brief and enclosure by the sender's identity key.                                                                                                    | Inner signature over the enclosure plaintext (`ENVELOPE.md` section 6.5).         |
| Sender                                                      | That the envelope was constructed and signed by the sender domain at the time indicated in the postmark.                                                                         | `seal.signature` over the canonical envelope (`ENVELOPE.md` section 4.3).         |
| Sender, post-delivery                                       | That a specific recipient domain accepted the envelope identified by canonical hash at a specific time.                                                                          | Signed delivery receipt (`DELIVERY.md` section 1.1.1).                            |
| Sender, during the delivery session                         | That the envelope was delivered within a valid federation session between specific sender and recipient domains.                                                                 | `seal.session_mac` (`ENVELOPE.md` section 4.4).                                   |
| Recipient                                                   | That the envelope was signed by the claimed sender domain and, if the inner signature is present, by the claimed sender identity.                                                | `seal.signature` plus inner signature.                                            |
| Third party holding a forwarded enclosure                   | Authorship of the forwarded plaintext by the original sender identity, independent of the forwarding path.                                                                       | Inner signature preserved across forwarding (`ENVELOPE.md` section 6.6.4).        |
| Third party holding a `.semp` envelope file                 | That the envelope was produced by the claimed sender domain and has not been altered since.                                                                                      | `seal.signature` (`MIME.md` section 3.1).                                         |
| Any party holding a migration record                        | That the old identity key, the new identity key, and (in cooperative mode) both provider domains co-authorized the address change.                                               | Migration record signatures (`MIGRATION.md` section 3).                           |

The following claims the protocol deliberately does not establish.

| Claim                                                                                       | Why not                                                                                                                                   |
|---------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| That the recipient user read the envelope.                                                  | Read status is an application concern and intentionally unobservable on the wire. See `DELIVERY.md` section 1.                            |
| That the envelope was delivered to a specific device within the recipient's account.        | Per-device delivery events are private sync state (`CLIENT.md` section 4.5) and do not produce federation-visible artifacts.              |
| That the envelope was not subsequently deleted by the recipient.                            | SEMP does not model retention at the recipient. A receipt attests to acceptance, not persistence.                                         |
| That a recipient address does or does not exist on a domain.                                | Per-address existence is not observable by design. See section 2.7.                                                                       |
| That a given sender or recipient was not also corresponding with other parties.             | Correspondent-graph privacy is a goal. Envelopes do not reveal other correspondents.                                                      |
| That two envelopes are part of the same conversation to an outside observer.                | Thread identifiers live in the encrypted brief and are not visible to routing infrastructure.                                             |

Implementations and higher-level protocols built on SEMP MUST NOT claim
evidence properties beyond those enumerated above. In particular, a receipt
MUST NOT be described to users as proof of read, proof of response, or proof
of any application-layer action the recipient took.

---

## 5. Trust and Reputation Model

### 5.1 Domain-Based Identity

A SEMP identity takes the form `user@domain`. The domain is the unit of trust
at the server-to-server level. The full address is the unit of trust at the
user level.

### 5.2 Reputation Signals

SEMP defines the following observable reputation signals:

- **Domain registration age**:  available via WHOIS, publicly verifiable,
  resistant to retroactive manipulation.
- **Abuse rate**:  the ratio of reported abuse events to message volume over a
  domain's operating history.
- **Trust gossip**:  a cryptographically hashed reputation value derived from a
  domain's trust history, publishable and verifiable by other SEMP servers
  without exposing the underlying data.

These signals are inputs to operator-defined policy.

### 5.3 Trust Transfer

When a domain changes ownership, the trust history associated with it MAY be
transferred from seller to buyer through a cryptographic handshake requiring
both parties' private keys. The transfer event is published to the network.
Other SEMP servers observe the transfer and apply their own policy regarding
whether and how to honor the inherited reputation.

### 5.4 New Domain Behavior

A domain with no history starts at zero reputation. Servers MAY apply additional
caution to zero-reputation domains as a matter of operator policy. They MUST NOT
reject messages from zero-reputation domains on that basis alone without explicit
operator configuration.

---

## 6. Key Management Philosophy

SEMP requires cryptographic key pairs for domains and for individual users.
Private keys are the root of identity. Loss of a private key results in loss
of the associated trust history, which cannot be recovered. Operators and users
SHOULD maintain secure key backups.

Key fetching (retrieving another party's public key before communicating)
can reveal communication intent to passive observers. SEMP addresses this by
supporting multiple key fetching mechanisms with documented privacy tradeoffs,
ordered by operator preference:

- **Speculative batch crawling**:  servers proactively fetch and cache keys on
  a schedule, decoupling the fetch from the communication intent. High privacy,
  higher infrastructure cost.
- **Third-party key relay**:  fetches are proxied through an intermediary,
  obscuring the requester's identity from the target domain. Medium privacy,
  medium cost.
- **Direct well-known fetch**:  keys are fetched on demand from the target
  domain's published endpoint. Lower privacy, lower cost.

Operators configure the order and fallback behavior.

---

## 7. Blocking and Rejection

SEMP defines the following blocking requirements:

- Servers MUST check block lists before completing a handshake.
- Blocked senders MUST receive an immediate, explicit rejection with a reason
  code.
- Silent acceptance of messages intended for discard is prohibited.
- Block events MAY be propagated to federation partners as policy signals.
  Partners apply their own policy in response and are not required to honor
  another server's block decisions.

Blocking operates at three levels of granularity: individual address,
domain-wide, and global emergency invalidation.

---

## 8. Legacy Interoperability

SEMP servers are SEMP-only. They do not speak SMTP, wrap legacy messages, or
deliver to legacy recipients on behalf of senders. Legacy interoperability is
handled at the client layer, not the server layer.

When a sender's SEMP server determines via discovery that a recipient domain
has no SEMP support, it signals this to the client with a `legacy_required`
or `recipient_not_found` response per `CLIENT.md` section 6.3. The client
then decides how to proceed:

- If SMTP credentials are configured for the sender's address, the client MAY
  send directly via SMTP after explicit user confirmation.
- Users MUST be informed that SEMP guarantees (sealed metadata, end-to-end
  encryption, explicit rejection) do not apply to legacy delivery.

Inbound legacy mail is handled by the client connecting directly to the user's
IMAP server alongside their SEMP server. The client presents legacy and SEMP
messages in a unified interface with a persistent, unambiguous origin indicator.
The SEMP server is never involved in legacy mail retrieval.

SMTP credentials are held by the client only and MUST NOT be transmitted to the
SEMP server.

---

## 9. Relationship to Existing Standards

SEMP builds on existing standards where they serve its goals:

- **DNS**:  server discovery, capability advertisement, key publication.
- **TLS**:  transport security layer beneath SEMP's application-layer security.
- **RFC 2119**:  normative language throughout all SEMP specifications.
- **HTTP/2**:  mandatory baseline transport for interoperability.
- **WebSocket / QUIC**:  recommended additional transports, negotiated during
  discovery.

SEMP operates as an application-layer protocol on top of DNS, TLS, and the
underlying transport. It replaces SMTP for message exchange; it relies on the
rest of the stack as-is.

---

## 10. Document Structure

| Document | Description |
The specification is organized into three architectural tiers plus
supporting material.

**Core Specification.** Normative for every SEMP implementation.

| Document | Description |
|---|---|
| `DESIGN.md` | This document. Philosophy, principles, non-goals, and document index. |
| `ENVELOPE.md` | Envelope structure: postmark, seal, brief, enclosure. Sender identity signature and forwarding primitive. |
| `HANDSHAKE.md` | Session establishment, federation handshake, resumption, and session reason codes. |
| `SESSION.md` | Forward secrecy, session key lifecycle, rekeying, and resumption tickets. |
| `DISCOVERY.md` | Server discovery, configuration document, versioning and update notifications. |
| `KEY.md` | Key management: publication, rotation, revocation, and scoped device certificates. |
| `DELIVERY.md` | Acknowledgment types, queuing and retry, staged delivery, block list, and first-contact enforcement. |
| `CLIENT.md` | Client obligations: composition, receipt, device sync, legacy interop. |
| `REPUTATION.md` | Trust signals, abuse reporting, gossip observations, and trust transfer. |
| `TRANSPORT.md` | Transport requirements and bindings. |
| `EXTENSIONS.md` | Wire-level extension framework, registry, lifecycle, and anti-fragmentation governance. |
| `ERRORS.md` | Error code registry and status values. |
| `MIME.md` | MIME compatibility and mapping rules. |
| `CONFORMANCE.md` | Conformance requirements for every role. |
| `VECTORS.md` | Test vectors. |

**Optional Core Modules.** Recommended but optional. An implementation that claims a module's functionality must conform to that module.

| Document | Description |
|---|---|
| `RECOVERY.md` | Account recovery: server-assisted encrypted backup and Shamir device-split backup, restore flow, successor records. |
| `MIGRATION.md` | Provider migration across domains with key continuity, forwarding, and local-part reassignment rules. |
| `CLOSURE.md` | Account closure with grace period, key revocation under existing mechanisms, retention window, and local-part reassignment rules. |
| `TRANSPARENCY.md` | Key transparency: append-only Merkle-tree log of key events, inclusion proofs on key fetch, equivocation detection via observation gossip. |

**Wire-Level Extensions.** Defined extensions registered under `semp.dev/`, living inside existing message structures per `EXTENSIONS.md`.

| Document | Description |
|---|---|
| `ATTACHMENTS.md` | `semp.dev/large-attachment`: external-storage attachments with HKDF-derived per-attachment keys. |

**Non-Normative.**

| Document | Description |
|---|---|
| `THREAT.md` | Consolidated threat model: actors, adversary classes, information visibility, residual risks. Companion to the security and privacy sections of the core documents. |
| `FAQ.md` | Frequently asked questions. |

---

## 11. Terminology

**MUST**:  An absolute requirement of the specification.  
**MUST NOT**:  An absolute prohibition.  
**SHOULD**:  Recommended. Deviation requires documented justification.  
**SHOULD NOT**:  Not recommended.  
**MAY**:  Optional but permitted.

**Envelope**:  The complete SEMP message unit.  
**Postmark**:  The outer public header, visible to routing servers.  
**Seal**:  The cryptographic integrity proof covering the envelope.  
**Brief**:  The inner private header, encrypted, visible only to the recipient.  
**Enclosure**:  The message body and attachments, encrypted, visible only to the recipient.  
**Domain operator**:  The entity responsible for a SEMP server for a given domain.  
**Trust gossip**:  A hashed, publishable representation of a domain's trust history.  
**Zero reputation**:  The starting state of a domain with no SEMP history.

---

*This document is an Internet-Draft. It is subject to revision prior to
finalization as a stable specification.*
