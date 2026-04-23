# SEMP Design Rationale and Frequently Asked Questions

**Sealed Envelope Messaging Protocol**  
Status: Companion Document  
Version: 0.2.0-draft  
Related: All SEMP specifications

---

## Abstract

This document serves two purposes. Part I answers anticipated questions about
SEMP's feature coverage, particularly from reviewers familiar with SMTP and its
ecosystem. Part II documents the design decisions and tradeoffs that shaped the
protocol, including alternatives that were considered and rejected.

This is a non-normative companion document. It does not define protocol behavior.
It explains why the protocol behaves the way it does.

---

# Part I: Frequently Asked Questions

## 1. Feature Coverage

### 1.1 Where is mailing list support?

SMTP mailing lists are a server-side expansion mechanism: the list server
receives one message, rewrites the headers, and re-sends it to every subscriber.
This model is fundamentally incompatible with end-to-end encryption because the
list server must read and rewrite the message. It also conflicts with SMTP's own
authentication mechanisms: mailing list re-sending breaks DKIM signatures,
confuses SPF alignment, and has required years of workarounds (ARC, From
rewriting) that remain incomplete.

In SEMP, mailing list semantics are handled through two mechanisms:

**Group addressing.** A sender addresses a message to a group using the
`group_id` field in the brief. The sending client resolves group membership
and generates per-recipient envelopes, each properly encrypted to the individual
recipient. There is no intermediary that reads or rewrites the message.

**Delegated clients.** A user registers a mailing list service as a delegated
client with a scoped device certificate (`KEY.md` section 10.3) that restricts
the service to sending only to the subscriber list. The service composes and
encrypts envelopes as the user's account because it is an authorized client of
that account. The seal is valid because the envelope originates from the user's
domain through a legitimate session.

This eliminates DKIM breakage (there is no intermediary modifying signed
content), confines blast radius if the service is compromised (the scope limits
which addresses the service can reach), and makes moderated lists straightforward
(the moderator is a participant who reviews submissions and forwards approved
ones through their own delegated client).

For large groups where per-recipient envelope generation becomes a performance
concern, the MLS extension described in `ENVELOPE.md` section 4.4 provides
logarithmic-cost group key management as a future optimization.

### 1.2 How do autoresponders work?

SEMP replaces the need for autoresponder messages with recipient status
(`DELIVERY.md` section 1.6). When the acknowledgment type is `delivered`, the
recipient server attaches a status field (`available`, `away`, or
`do_not_disturb`) along with an optional freetext message and an expiry
timestamp. The sender learns "recipient is away until July 1" from the
acknowledgment the server was already generating, without a separate message
round trip.

This eliminates autoresponder pathologies: no loop risk (status is a field on
an acknowledgment, not a message), no mailing list pollution (the acknowledgment
goes only to the sender's server), and no address confirmation to unwanted
senders (the acknowledgment already exists regardless of status). Status
visibility is opt-in with per-user, per-domain, and per-server granularity.

For use cases that require richer automated responses (such as a service that
composes context-aware replies), a client process running on a dedicated device
can be registered as a delegated client with receive and restricted send
permissions. This is an explicit trust delegation, not a default server behavior.

### 1.3 Where is message forwarding?

In SMTP, forwarding is a server-side operation where the server re-routes a
message to a different address. In SEMP, the server cannot do this because it
cannot read the enclosure to reconstruct the envelope for a new recipient.

Forwarding is a client operation. The recipient's client composes a new envelope
to the forwarding target, encrypting under the new recipient's keys. The original
enclosure plaintext, including the original sender's identity-key signature
(`enclosure.sender_signature`), is preserved verbatim inside
`enclosure.forwarded_from` of the new envelope. The new recipient verifies the
original sender's signature against the original sender's published identity
key, giving cryptographic provenance regardless of how many times the message
has been forwarded. See `ENVELOPE.md` sections 6.5 and 6.6.

Automatic forwarding is handled through the delegation model. A user registers
a delegated client with receive permission and a restricted send scope limited
to the forwarding target address. The delegated client receives inbound
envelopes, decrypts them, and composes new envelopes to the forwarding target.
The scope guarantees it can only forward to the designated address.

This is more transparent than SMTP forwarding, where the forwarding target often
cannot tell whether a message was forwarded or sent directly, and where
forwarding breaks DKIM signatures.

### 1.4 Where is server-side search?

Server-side full-text search is architecturally incompatible with end-to-end
encryption. This is not a SEMP limitation; it applies to every encrypted
messaging system. The server cannot search content it cannot read.

Clients build local search indexes from decrypted content. This means search
is available on devices that have decrypted and indexed messages, and unavailable
on new devices that have not yet built an index.

The server can search brief metadata (sender address, domain, timestamps,
thread and group identifiers) because it can decrypt the brief. Metadata
search covers "messages from this sender" and "messages in this thread" without
exposing content.

Organizations that require server-side content search can run a delegated client
with receive permissions that decrypts messages and indexes content within their
own infrastructure. The delegation is explicit, scoped, and auditable.

Individual users can do the same: a delegated indexing client with receive
permission and no send permission receives envelopes, decrypts them, builds a
search index, and makes it available to the user's other clients. The index can
reside on the user's home server, a self-hosted service, or a third-party
provider; that is an application decision, not a protocol concern. This gives
users something SMTP never offered: choice over who indexes their mail. In SMTP,
the server indexes everything because it can read everything. In SEMP, indexing
requires explicit delegation that the user controls and can revoke at any time.

A future extension could define a privacy-preserving search mechanism using
techniques like encrypted search indexes, but this is a research problem, not
a protocol gap.

### 1.5 Where is server-side filtering and rules?

The same constraint applies. Sieve scripts and server-side rules work in SMTP
because the server can read message content. In SEMP, the server can filter on
all brief metadata (sender address, domain, timestamps, threading, group
identifiers) but not on subject, body, or attachments.

Content-based filtering requires the client. The delegation mechanism allows a
user to run a client-side filtering service as a scoped delegated client if they
want automated processing.

### 1.6 Where are delivery status notifications (DSN) and read receipts (MDN)?

DSN functionality is core to SEMP. Every delivery attempt produces an explicit
acknowledgment: `delivered`, `rejected`, or `silent`. The sender knows the
outcome immediately with a machine-readable reason code, rather than waiting
for a bounce message that may or may not arrive. `DELIVERY.md` section 2
extends this with sender-side queuing state visible to the submitting client
(attempt counts, next attempt time, effective deadline, terminal state).
This is strictly better than SMTP's DSN mechanism.

Read receipts (MDN) are not defined by SEMP. They are privacy-hostile by
design, because they compel the recipient's device to reveal that the
recipient has seen a message and when, to a sender who has no independent
claim on that information. Most privacy-respecting email clients disable
or strip MDN today. Writing a normative SEMP spec for a feature that
privacy-respecting implementations should decline runs counter to the
protocol's posture. Vendors who genuinely need read confirmation for a
specific application domain MAY define a vendor extension under their own
namespace per `EXTENSIONS.md` section 5.3.

### 1.7 Where is relay and smarthost support?

SEMP delivery is direct: sender's server to recipient's server. There is no
multi-hop relay chain. The sender's home server performs the role that
smarthosts serve in SMTP, without the metadata exposure that multi-hop relaying
creates.

This eliminates an entire category of SMTP complexity: relay authorization,
open relay detection, relay-induced DKIM breakage, and the accumulation of
`Received` headers that expose internal infrastructure to every recipient.

### 1.8 Where are VRFY and EXPN?

SMTP's VRFY (verify address) and EXPN (expand mailing list) commands have been
disabled on most production servers for decades because they are address
enumeration vectors.

SEMP's discovery protocol (`DISCOVERY.md`) handles address verification with
privacy protections that VRFY never had: noise addresses in queries, batched
lookups, and no sender identity in the request. List expansion does not exist
because mailing lists are sender-side operations, not server-side expansions.

### 1.9 Where is STARTTLS? How is opportunistic encryption handled?

There is no opportunistic encryption in SEMP. Encryption is mandatory and
structural, not optional and negotiable. Every envelope is encrypted before it
leaves the sender's client. There is no plaintext fallback within the protocol.

The plaintext fallback path is SMTP, handled at the client layer with explicit
user consent and degradation warnings (`CLIENT.md` section 6.4). A user must
acknowledge that SEMP's security guarantees do not apply before the client
sends via SMTP.

Opportunistic encryption's failure mode, silent plaintext delivery when
negotiation fails, is unacceptable in SEMP's threat model.

### 1.10 Where is aliasing and plus-addressing?

In SMTP, `user+tag@domain` routes to `user@domain` and the tag is available for
filtering. In SEMP, this is a server-side routing decision. The server maps
addresses to recipient keys during key lookup and delivery. A server that wants
to support plus-addressing maps `user+tag@domain` to `user@domain` during
resolution.

The protocol does not constrain address resolution. Any aliasing scheme a server
implements is compatible with SEMP as long as the server can resolve the alias
to a recipient key.

### 1.11 Where is internationalized email address support?

SEMP is UTF-8 native. All JSON fields, including address fields in the brief,
are UTF-8 encoded. Internationalized addresses require no special handling or
extensions. This is a structural advantage over SMTP, which required the
SMTPUTF8 extension (RFC 6531) to support non-ASCII addresses.

### 1.12 What about calendar invites, vCards, and structured content?

Structured content types are carried in the enclosure as typed body parts or
attachments with appropriate `mime_type` values. Calendar invites, vCards, and
any other MIME type are supported through the existing content type system in
`ENVELOPE.md` section 6.

The protocol is content-agnostic. It encrypts and delivers typed payloads
without needing to understand their semantics.

### 1.13 What about message priority?

Priority hints are a candidate extension in `postmark.extensions`, listed in
`EXTENSIONS.md` section 9. The postmark layer is appropriate because priority
affects routing behavior, which servers need to see.

### 1.14 What about the forty years of RFC 5321 edge cases?

SEMP is not a revision of RFC 5321. It is a new protocol that addresses the
same use case. SEMP does not inherit SMTP's edge cases because it does not
inherit SMTP's architecture.

Where SMTP edge cases reflect genuine user needs (mailing lists, delivery
receipts, forwarding), SEMP addresses those needs through mechanisms compatible
with its security model. Where SMTP edge cases reflect architectural accidents
(the eight ways a message can bounce, the ambiguity between `MAIL FROM` and
the `From` header, the existence of `Resent-` headers), SEMP has designed them
out rather than carrying them forward.

Example: SMTP has an entire RFC section (RFC 5321 section 3.6.3 plus RFC 5322
section 3.6.6) dealing with the `Resent-` header block, which exists because
SMTP conflates forwarding, redirecting, and resending into a single mechanism
with different header semantics that most implementations get wrong. In SEMP,
forwarding creates a new envelope with a clear reference to the original. There
is no ambiguity because there is no mechanism to rewrite headers in transit. The
edge case does not exist because the architecture that created it does not exist.

---

## 2. Migration and Deployment

### 2.1 Why should anyone switch from SMTP?

SMTP has five structural limitations that extensions cannot fully address:

1. Metadata (sender, recipient, subject, timestamps) is transmitted in
   cleartext and visible to every intermediary.
2. Trust is anchored to IP addresses, controlled by a small number of large
   operators with opaque criteria.
3. There is no explicit rejection mechanism; servers silently discard messages.
4. There is no end-to-end integrity guarantee, so messages can be altered in
   transit.
5. Extensibility is limited: adding capabilities requires backward-incompatible
   changes or optional extensions that implementations may ignore.

These are architectural limitations, not missing features. No combination of
SPF, DKIM, DMARC, STARTTLS, ARC, or MTA-STS resolves them because the
architecture that creates them remains unchanged.

### 2.2 Is the migration cost high?

The migration cost is lower than deploying a new SMTP server.

A SEMP server runs over standard web transports (WebSocket, HTTP/2, QUIC). There
is no special port to unblock, no IP reputation to warm, no reverse DNS to
configure, no SPF/DKIM/DMARC alignment to debug. Deployment requires a domain
name, a TLS certificate, and DNS records, the same infrastructure any web
application uses.

The address format is unchanged: `user@domain.tld`. Existing contact lists,
business cards, and account recovery flows work without modification. The
client presents SEMP and legacy messages (retrieved via IMAP, POP3, or any
other legacy retrieval mechanism the user's provider supports) in a unified
inbox with a clear origin indicator. Users do not need to choose between
protocols: they use SEMP for correspondents who support it and legacy mail
for everyone else.

### 2.3 Why is SEMP server-only, with no SMTP backward compatibility?

SMTP backward compatibility at the server layer would require the server to
handle plaintext messages, maintain SMTP's relay model, and support its
authentication extensions. This would undermine SEMP's security model at the
architectural level. A server that speaks SMTP can be compelled to process
plaintext metadata, which defeats the purpose of sealed envelopes.

Legacy interoperability is handled at the client layer (`CLIENT.md` sections
4.3 and 6.4, `DESIGN.md` section 8). The client speaks whatever retrieval
protocol the user's legacy provider supports (IMAP, POP3, JMAP, a provider
API) for inbound, and SMTP Submission or the equivalent provider send
protocol for outbound, with explicit user consent and degradation warnings.
The SEMP server is never involved in legacy mail. This separation ensures
that SEMP's security guarantees are not diluted by backward compatibility.

### 2.4 Isn't SEMP just a web service?

No. SEMP is a federated protocol that uses web transports. A web service has a
central operator. A protocol has independent implementations that interoperate.

SMTP runs over TCP, yet no one calls it "merely a TCP service." HTTP/2 runs over
TLS, yet no one calls it "merely a TLS wrapper." SEMP runs over WebSocket, HTTP/2,
and QUIC because those transports are universally available, universally
deployable, and already have mature TLS integration. The transport is a
pluggable layer defined in `TRANSPORT.md`. SEMP could run over raw TCP with
custom framing and every core property (encryption, reputation, explicit
rejection) would be identical.

Using web transports is a deployment advantage: they pass through every
firewall, every NAT, every proxy. They get TLS for free through existing
certificate infrastructure. Choosing a custom transport for protocol purity
would make SEMP harder to deploy for no security benefit.

---

## 3. Security and Privacy

### 3.1 Can the recipient's server read my messages?

The recipient's server can read the brief (sender address, recipient addresses,
timestamps, threading metadata) but cannot read the enclosure (subject, body,
attachments). This is the differential encryption model defined in `ENVELOPE.md`
sections 4.4 and 10.5.

The brief is decryptable by the server to enable server-enforced user-level
blocking. The enclosure is encrypted under the recipient client's key only.
No server (sender's, recipient's, or any intermediary) can read message
content.

### 3.2 Why does the recipient's server see the sender's full address?

Server-enforceable user-level blocking requires the server to know who sent
the message so it can check the sender against the recipient's block list
before delivering to the client. This is documented in `ENVELOPE.md`
section 10.6.

The alternative, hiding the sender address from the server entirely, would
require the server to deliver every envelope to the client, including from
blocked senders, and rely on the client to discard them. This wastes bandwidth,
drains battery on mobile devices, and allows a determined harasser to force the
target's device to do work.

The exposure is bounded: only the recipient's own server (the entity the user
has chosen to trust) sees the correspondent graph. Routing intermediaries see
only domains, not individual addresses. A future protocol revision may adopt
Private Set Intersection (PSI) to allow the server to check block lists without
learning the sender address in plaintext.

### 3.3 Is SEMP post-quantum secure?

SEMP's preferred algorithm suite is `pq-kyber768-x25519`, a hybrid combining
Kyber768 (lattice-based key encapsulation) with X25519 (classical elliptic
curve Diffie-Hellman). If either component is broken, the other still protects
the session secret. This addresses the "harvest now, decrypt later" threat model
where an adversary records encrypted traffic today and attempts decryption with
future quantum capability.

Post-quantum protection applies to both the handshake (session key exchange) and
the envelope (symmetric key wrapping). Implementations MUST prefer the hybrid
suite when both parties support it and MUST NOT downgrade when a stronger suite
is available.

### 3.4 What happens if a server is compromised?

A compromised recipient server can read brief metadata (sender addresses,
timestamps, threading) for current and future envelopes but cannot read
enclosure content (subject, body, attachments). It cannot decrypt past
envelopes because session keys are ephemeral and erased after each session.

A compromised sender server can forge new envelopes (it holds the domain key)
but cannot decrypt past envelopes it relayed. Key revocation and re-keying are
the response to domain key compromise, documented in `KEY.md` section 8.

---

## 4. Protocol Mechanics

### 4.1 Is the handshake too slow?

The handshake is four messages (two round trips) in the normal case. With
proof-of-work, it is six messages (three round trips). On modern web transports
over persistent connections, this takes tens to hundreds of milliseconds --
invisible for email, where users expect delivery in seconds.

For comparison, TLS 1.3 is two round trips. SMTP with STARTTLS, SPF, DKIM,
DMARC, and reputation checks involves more round trips and external DNS lookups
than SEMP's handshake, with none of SEMP's security properties.

Sessions amortize the handshake cost: once established, envelopes flow without
re-handshaking until the session expires. For active federation pairs, the
per-envelope handshake cost approaches zero.

### 4.2 Why not extend sessions automatically based on good behavior?

This was considered and rejected. Session TTLs are fixed per session and
determined by server policy at handshake time. The full rationale is documented
in `SESSION.md` section 3.6. In summary:

- Forward secrecy degrades with session lifetime. Every envelope in a session
  shares derived key material. Longer sessions mean larger compromise windows.
- Abuse detection is retrospective. Non-abusive delivery at the protocol layer
  does not mean non-abusive content, which is determined by the recipient after
  reading.
- The same benefit is achievable through simpler mechanisms: reputation-informed
  TTLs (trusted domains get longer sessions) and in-session rekeying (fresh keys
  without full re-handshake).

### 4.3 Why fixed proof-of-work instead of CAPTCHA or rate limiting alone?

Proof-of-work imposes a per-envelope computational cost that is negligible for
low-volume senders and prohibitive for bulk senders. It does not require human
interaction (unlike CAPTCHA, which is inappropriate for server-to-server
communication) and is not bypassable through distributed sending (unlike rate
limiting alone, which can be evaded with many IP addresses, though IP
addresses are not a factor in SEMP).

PoW is one tool in a layered defense: rate limiting caps throughput, domain age
gating delays new domains, proof-of-work adds per-message cost, and the
reputation system tracks behavior over time. No single mechanism is sufficient;
the combination makes sustained abuse uneconomical.

---

# Part II: Design Decisions and Rationale

## 5. Architectural Decisions

### 5.1 Why a new protocol instead of extending SMTP?

SMTP's metadata exposure is structural. The envelope metadata (sender,
recipient, subject, routing path) must be in plaintext for SMTP's relay
model to function. No extension can encrypt this metadata without replacing the
relay model, and replacing the relay model is replacing the protocol.

Body encryption (PGP, S/MIME) has been available for decades and has not
achieved widespread adoption because it solves only the content problem while
leaving the metadata problem, the reputation problem, the silent discard
problem, and the extensibility problem untouched. SEMP addresses all five
problems as a unified design because they are interconnected: metadata
protection requires a new envelope model, which requires a new transport model,
which requires a new trust model.

### 5.2 Why domain-based reputation instead of IP-based?

IP-based reputation is controlled by a small number of large operators with
opaque criteria. A new mail server operator cannot participate in email on equal
terms because their IP has no reputation, and building reputation requires
implicit permission from the incumbents. This has turned a federated protocol
into a de facto oligopoly.

Domain-based reputation is verifiable, transferable, and transparent. A domain's
reputation is built from cryptographically signed observation records published
by independent observers. Any operator can evaluate any domain's reputation
independently. There is no central authority that controls participation.

### 5.3 Why explicit rejection instead of allowing silent discard?

Silent discard in SMTP is the source of one of email's most frustrating
failure modes: the sender believes a message was delivered when it was silently
dropped. The recipient never knows the message existed. Neither party can
diagnose the problem.

SEMP requires explicit rejection with reason codes for all delivery failures.
The one exception is the `silent` acknowledgment type, which is permitted for
deliberate privacy or anti-harassment reasons (e.g., a blocked sender should not
learn they are blocked). Even `silent` is a documented, intentional behavior --
not an accidental failure mode.

### 5.4 Why is the subject in the enclosure instead of the brief?

The subject is semantic content, not routing metadata. A server does not need
the subject to deliver a message. Placing it in the brief would expose it to
the recipient's server, which can read the brief for policy enforcement.

In SMTP, the subject is a header visible to every intermediary. In SEMP, it is
protected under the same encryption as the message body. This is a deliberate
privacy improvement with no functional cost, since the server's delivery decision
does not depend on subject content.

### 5.5 Why stateless per-envelope key wrapping instead of MLS?

SEMP's per-envelope key wrapping generates fresh symmetric keys for each
envelope and wraps them under each recipient's public key. This model is
stateless: a recipient can decrypt any envelope with just their private key, no
shared state with the sender required.

This property is essential for email semantics. Messages may be stored for
years, accessed from new devices, or recovered from backups long after
transmission. A stateful key agreement protocol like MLS requires participants
to maintain evolving epoch state across messages, which conflicts with stateless
decryption.

MLS is designated as a future extension for large-group messaging (`ENVELOPE.md`
section 4.4), where the O(N) cost of per-recipient key wrapping becomes a
performance constraint and where continuous post-compromise security across the
group is desirable. The core protocol does not depend on MLS because email's
durability and asynchrony requirements differ from the synchronized-state model
MLS assumes.

### 5.6 Why is legacy interop at the client layer, not the server?

A server that speaks both SEMP and SMTP cannot provide SEMP's security
guarantees for SMTP traffic. Mixing the two at the server layer creates a
confused security model where some messages are sealed and some are not, with
the distinction invisible to users.

By placing legacy interop at the client layer, the security boundary is clear:
SEMP envelopes go through the SEMP server with full security properties. Legacy
messages go through the client's own legacy retrieval and send paths (IMAP,
POP3, SMTP Submission, or any provider-specific equivalent) directly, with
explicit user-visible indicators that SEMP guarantees do not apply. The SEMP
server never handles plaintext email, which means its security properties are
unconditional.

### 5.7 Why per-layer extensions instead of a flat extension mechanism?

SEMP's envelope has four layers with different visibility: postmark (all
servers), seal (all servers), brief (recipient server and client), and enclosure
(recipient client only). A flat extension mechanism would force all extensions
to the same visibility level, which either exposes private metadata to routing
servers or hides routing hints from them.

Per-layer extensions allow each extension to be placed at the appropriate
visibility level. A priority hint belongs in `postmark.extensions` where routing
servers can see it. A large-attachment reference belongs in `enclosure.extensions`
where only the recipient client sees it (`ATTACHMENTS.md`). A delivery-disposition
signal belongs in `brief.extensions` where the home server can read and act on it
(`CLIENT.md` §4.5.7). This layered placement is a direct consequence of the
encryption model and would not be possible without it.

### 5.8 Why bake delegation scopes into device certificates?

Delegation permissions could be stored as a separate database on the server,
independent of the device key. This was rejected because it creates two
independent revocation paths (key revocation and permission revocation) that
can fall out of sync. A compromised device could have its permissions revoked
while its key remains valid, or vice versa.

By embedding the scope in a certificate signed by the primary device and bound
to the delegated device's key, revocation is atomic: revoking the key revokes
the permissions. There is no window where the key is revoked but permissions
linger, or permissions are changed but the old key still works. The key is
the authorization.

### 5.9 Why a thick core instead of a minimal core with extensions?

XMPP demonstrated the consequences of a minimal core: the base protocol defined
streaming XML and presence, but nearly everything users needed (file transfer,
group chat, receipts, end-to-end encryption) was pushed to extensions (XEPs).
Two "XMPP-compliant" implementations could support non-overlapping extension
sets and be unable to do anything useful together beyond plain text messaging.

SEMP's core includes encryption, metadata protection, blocking, reputation,
delivery semantics, key management, and session security. Two conformant SEMP
implementations can exchange sealed envelopes with full security properties
without negotiating a single extension. Extensions exist for genuinely optional
features where reasonable deployments may differ in their needs. The extension
lifecycle (`EXTENSIONS.md` sections 6 and 7) ensures that successful extensions
are promoted into the core over time, preventing the permanent fragmentation
that XMPP experienced.

---

## 6. Comparison with Prior Art

### 6.1 SEMP vs. SMTP

SMTP transmits metadata in plaintext, anchors trust to IP addresses, allows
silent discard, provides no end-to-end integrity, and resists extension. SEMP
encrypts metadata, anchors trust to domains with verifiable reputation, requires
explicit rejection, provides dual-layer integrity proofs, and includes a
structured extension framework. The comparison is detailed in `DESIGN.md`
section 1.

### 6.2 SEMP vs. DIME (Dark Mail Alliance)

DIME (2013-2017) had similar goals: layered encryption with different access
scopes per layer, metadata protection, and a new transport protocol (DMTP).
The architectural parallels are significant. DIME's Next-Hop / Envelope /
Content layers map to SEMP's postmark / brief / enclosure structure.

SEMP differs from DIME in three ways. First, DIME maintained SMTP backward
compatibility at the server layer with "Trustful/Cautious/Paranoid" modes,
creating a muddled security story. SEMP is SEMP-only at the server, with legacy
interop at the client. Second, DIME had no reputation or spam prevention system.
SEMP's trust gossip, proof-of-work, and domain-based reputation are novel in
this design space. Third, DIME did not reach a usable implementation or sustain
a community. The lesson from DIME is that a protocol needs running code and
sustained development, not just a specification and credentialed founders.

### 6.3 SEMP vs. PGP / S/MIME

PGP and S/MIME encrypt message bodies but leave all metadata in plaintext. They
bolt encryption onto SMTP without changing the transport. Key management is
manual and notoriously painful. SEMP protects metadata structurally by designing
the envelope format and transport together, and automates key management through
server-mediated key discovery.

### 6.4 SEMP vs. Autocrypt / pEp

Autocrypt and pEp make encryption opportunistic and automatic within SMTP. They
accept SMTP as the transport and cannot solve the metadata problem, the
reputation problem, or the silent discard problem because those are server
behaviors outside their control. SEMP is a more comprehensive project that
replaces the transport rather than patching over it.

### 6.5 SEMP vs. MLS (RFC 9420)

MLS is a group key agreement protocol, not a messaging system. It solves
efficient asynchronous group key establishment but does not define message
formats, routing, delivery semantics, reputation, or blocking. SEMP could use
MLS for group key management as a future extension. They operate at different
layers and are complementary, not competing.

### 6.6 SEMP vs. Signal Protocol

Signal's protocol provides end-to-end encryption with forward secrecy and
post-compromise security for two-party and small-group messaging. It is
centralized (all traffic flows through Signal's servers), tied to phone numbers,
and does not support federation. SEMP provides similar cryptographic properties
in a federated architecture with email-style addressing and domain-based trust.

### 6.7 SEMP vs. ProtonMail / Tuta

ProtonMail and Tuta are products, not protocols. They encrypt at rest on their
servers and offer end-to-end encryption between their own users, but
communication with external providers is either unencrypted SMTP or a workaround
(click a link to read the encrypted message). They have proven market demand for
encrypted email but have not solved the federation problem. SEMP is the protocol
layer that would enable them to interoperate securely.

---

*This document is a non-normative companion to the SEMP specification suite.
It is subject to revision as the protocol evolves.*
