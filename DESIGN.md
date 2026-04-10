# SEMP Design Philosophy and Principles

**Sealed Envelope Messaging Protocol**  
Status: Internet-Draft  
Version: 0.1.0  
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
- **WebSocket / HTTP/2 / QUIC**:  supported transports, negotiated during
  discovery.

SEMP operates as an application-layer protocol on top of DNS, TLS, and the
underlying transport. It replaces SMTP for message exchange; it relies on the
rest of the stack as-is.

---

## 10. Document Structure

| Document | Description |
|---|---|
| `DESIGN.md` | This document. Philosophy, principles, and non-goals. |
| `ENVELOPE.md` | The envelope model and field specifications. |
| `HANDSHAKE.md` | The handshake protocol for session establishment. |
| `DISCOVERY.md` | Protocol and server discovery mechanisms. |
| `KEY.md` | Key management, discovery, rotation, and revocation. |
| `REPUTATION.md` | Trust signals, gossip protocol, and transfer. |
| `DELIVERY.md` | Blocking, rejection, and invalidation protocol. |
| `CLIENT.md` | Client protocol obligations, envelope submission, and legacy interoperability. |
| `SESSION.md` | Forward secrecy, session key lifecycle, and rekeying. |
| `TRANSPORT.md` | Transport requirements, bindings, and negotiation. |
| `ERRORS.md` | Error codes registry and status values. |
| `EXTENSIONS.md` | Extension framework, registry, lifecycle, and anti-fragmentation governance. |

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
