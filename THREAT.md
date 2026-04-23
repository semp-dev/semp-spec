# SEMP Threat Model

**Sealed Envelope Messaging Protocol**  
Status: Internet-Draft  
Version: 0.2.0-draft  
Related: `DESIGN.md`, `ENVELOPE.md`, `HANDSHAKE.md`, `SESSION.md`, `KEY.md`, `DELIVERY.md`, `REPUTATION.md`, `RECOVERY.md`, `TRANSPARENCY.md`, `MIGRATION.md`, `CLOSURE.md`

---

## Abstract

This document consolidates the threat model that the Sealed Envelope
Messaging Protocol (SEMP) is designed against. It enumerates the actors
involved in message delivery, the adversary classes SEMP considers, what
each adversary can and cannot learn or influence under the specification
as written, and residual risks that the specification acknowledges rather
than eliminates. It is a companion to the architecture in `DESIGN.md` and
the per-component security sections across the core specification.

This document is informational. It does not define protocol behavior.
Normative requirements referenced here are defined in the documents cited
in each section.

---

## 1. Overview

### 1.1 Purpose

SEMP makes security and privacy claims in several documents, but those
claims assume a particular threat model that is not consolidated
elsewhere. This document fills that gap so that implementers, operators,
and users can assess whether SEMP's guarantees match their own operating
environment.

### 1.2 Scope

This document describes:

- The actors involved in SEMP message delivery and key distribution.
- Adversary classes grouped by capability and access.
- What each adversary can observe, modify, or forge under the current
  specification.
- Known residual risks and how they are mitigated, accepted, or deferred.

It does not define:

- New protocol behavior. All MUST, SHOULD, and MAY requirements
  referenced here are defined elsewhere and cited in context.
- Operational security practices for server operators. Those are at most
  RECOMMENDED and left to deployment judgment.
- Legal, regulatory, or compliance implications.

### 1.3 Non-Goals

SEMP does not aim to defend against:

- Targeted endpoint compromise. A user whose device is under adversary
  control has already lost confidentiality of the messages that device
  can read.
- Side-channel attacks on cryptographic implementations. Timing, power,
  and cache attacks are the domain of the underlying cryptography
  library.
- Social engineering. A user who knowingly discloses their recovery
  secret has bypassed the protocol.
- Compulsion applied to the home server. What a compelled server
  discloses is a legal question; what it technically possesses is
  defined in section 3.3.

---

## 2. Actors and Trust Relationships

### 2.1 Actors

| Actor                   | Role                                                                                                                                                     |
|-------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| User                    | The human or group owning an SEMP account and one or more devices.                                                                                        |
| Client device           | Software on a user's device, holding identity and encryption private keys or scoped delegated certificates per `KEY.md` section 10.                      |
| Home server             | The server hosting the user's account, brokering outbound envelopes, accepting inbound envelopes, and storing minimum necessary state.                    |
| Recipient server        | The home server of the recipient, from the sending server's perspective. Identical role to the home server; "recipient" and "sender" are envelope-relative. |
| Federation peer         | Any home server that another home server is in active or cached session with.                                                                             |
| Routing infrastructure  | Transport-layer intermediaries (HTTPS proxies, CDNs, load balancers, Tor relays) between any two servers.                                                 |
| Third-party domain      | Any domain beyond sender and recipient that fetches public artifacts such as domain keys, user keys, or successor records.                                |
| Key relay               | A cooperative third-party service that fetches user keys on behalf of a sender to reduce existence-oracle leakage (`KEY.md` section 6.1).                 |
| Transparency monitor    | An independent service watching the key-transparency log for split-view attacks (`TRANSPARENCY.md`).                                                      |

### 2.2 Trust Relationships

SEMP assumes the following trust, expressed as "A trusts B with respect
to property P":

- A user trusts their client devices with the identity private key, the
  encryption private key history, and the plaintext of received
  envelopes. This is unavoidable because the client is the endpoint.
- A user trusts their home server with the user's correspondent graph
  (`ENVELOPE.md` section 10.6), the user's block list, and the minimum
  envelope metadata required for delivery and policy enforcement.
- A user does NOT trust their home server with envelope enclosure
  plaintexts, recovery secrets, or the user's identity private key.
- A sending server trusts a recipient server to honor its published
  policies (first-contact, rate-limit, block semantics) but does not
  trust it with enclosure plaintext.
- A recipient server trusts the sending server's domain signature as
  proof of envelope origin, subject to revocation and transparency
  signals.
- All parties distrust routing infrastructure except for its delivery
  of ciphertext.

The user-server trust boundary is deliberately wider than the
user-device boundary. SEMP tolerates this because the protocol's
privacy posture is to minimize what the server learns, not to
eliminate it. `ENVELOPE.md` section 10.6 is explicit that the recipient
server observes the correspondent graph as a structural consequence of
user-level blocking enforcement.

---

## 3. Adversary Models

### 3.1 Passive Network Observer

An adversary with the ability to observe network traffic between two or
more parties but no ability to modify, inject, or delay messages.

**Can observe:** TCP and TLS connection metadata (source and destination
IP, connection timing, byte counts); the approximate size and timing of
SEMP exchanges; postmark-level source and destination domains during
federation handshakes.

**Cannot observe:** Envelope plaintext. The seal, brief, and enclosure
are encrypted. Handshake confirm contents are encrypted after the key
exchange. Session MAC values are meaningless without the session MAC
key.

**Residual leakage:** Envelope sizes expose approximate content
category (`ENVELOPE.md` section 11). Connection timing correlates to
send and receive events. IP-level observation can deanonymize `.onion`
deployments that also expose clearnet endpoints; see section 6.7.

### 3.2 Active Network Attacker

An adversary with the ability to modify, inject, delay, or drop
messages between parties, but without access to any party's long-term
key material.

**Can do:**

- Deny service by dropping packets.
- Delay envelopes to force retry behavior (`DELIVERY.md` section 2.3).
- Attempt to downgrade cipher suite negotiation at the TLS layer.
- Attempt to substitute public key records served by a home server the
  attacker can reach.
- Replay prior session or envelope messages.

**Cannot do:**

- Produce a valid handshake confirm without the session keys
  (`HANDSHAKE.md` section 2.4).
- Produce a valid seal signature without the sender's domain signing
  key.
- Produce a valid session MAC without the session MAC key.
- Decrypt past envelopes absent compromise of the ephemeral key
  exchange material.

**Defeats and mitigations:**

- Replay: `postmark.expires` bounds envelope lifetime; `session_id` and
  `session_mac` bind envelopes to a specific session; first-contact
  tokens are single-use bound to `postmark.id` (`HANDSHAKE.md`
  section 2.2a.3).
- Downgrade: handshake confirm hash covers the negotiated cipher suite
  and configuration (`HANDSHAKE.md` section 6.3).
- Key substitution: transparency-log inclusion proofs and split-view
  detection via gossip (`TRANSPARENCY.md`).

### 3.3 Compromised Home Server

The home server of a user is under adversary control, whether by
compromise, compulsion, or malicious operation.

**Observes about the user:** Full correspondent graph of the user's
inbound and outbound envelopes. Brief plaintexts after decryption using
the server's domain key entry in `seal.brief_recipients`. Delivery
timing and acknowledgment outcomes. The user's block list. Stored
delivery receipts for the retention window. Device registration events
and device identity public keys.

**Does not observe:** Enclosure plaintext. Enclosure keys are wrapped to
the user's encryption key, not the server's domain key. The user's
identity or encryption private keys. The user's recovery secret. The
recovery bundle's payload.

**Can do:**

- Delay or drop envelopes, either targeted or in bulk.
- Decline to serve the user's key records or the backup bundle.
- Fabricate envelopes addressed to the user. The user's client detects
  these because the envelope either lacks a `sender_signature` or
  carries one that does not verify against the claimed sender's
  published identity key (`ENVELOPE.md` section 6.5).
- Publish a fraudulent successor record. Detected by transparency
  monitors and by the `recovery_verify_pk` binding in `RECOVERY.md`
  section 8.8.
- Issue a new user identity key. Detected by transparency monitors;
  users may migrate per `MIGRATION.md`.

**Cannot do:**

- Forge envelopes appearing to originate from the user to third
  parties. The sender's signature is computed by the client over the
  envelope seal and the server holds no client signing material.
- Decrypt envelopes sealed to the user. The encryption private key is
  client-held.
- Unilaterally restore a user's account. Recovery depends on a
  user-held secret or user-held share quorum (`RECOVERY.md` section 8.3).

### 3.4 Compromised Recipient Server

The recipient's home server is under adversary control, from the
sender's perspective.

**Observes:** Full envelope ingress, including seal, brief ciphertext,
brief plaintext after domain-key decryption, enclosure ciphertext. The
sender's domain identity from `postmark.source`. Delivery and rejection
outcomes.

**Does not observe:** Enclosure plaintext, because enclosure keys are
sealed to the user's encryption-key entries in
`seal.enclosure_recipients`, not to the server's domain-key entries.

**Can do:** Same envelope-fabrication and delay attacks as in section
3.3, scoped to envelopes addressed to that domain. Can publish
fraudulent recipient user keys subject to transparency detection.

**Cannot do:** Read enclosure content. Forge senders outside its own
domain.

### 3.5 Colluding Servers

Two or more home servers cooperate to combine the information each
individually observes.

**Joint observation:** Sender domain to recipient domain pairings
across all envelopes each collaborator handles. Sender and recipient
user identities for envelopes where both endpoints are inside the
collaborator set. Timing, size, and retry patterns.

**Joint inference:** Correspondent graph restricted to users on the
collaborator domains. Approximate social graph from delivery timing and
reply patterns.

**Residual privacy:** Users whose correspondents are split across
collaborators and non-collaborators retain partial unlinkability.
Enclosure plaintext remains protected; the collaborators gain no
decryption capability beyond what each individually has.

### 3.6 Compromised Key Relay

A cooperative third-party service used to fetch user public keys
(`KEY.md` section 6.1) is under adversary control.

**Observes:** Which users' keys are being fetched, by whom, and at what
rate.

**Cannot do:** Substitute a user's key record, because the record
carries the user's self-signature and the home server's domain
signature. A relay returning a fraudulent record is detected at
signature verification by the sender client.

**Residual leakage:** The relay observes communication-intent metadata
(sender intends to write to user X). From the sender's privacy
perspective, a compromised relay is therefore equivalent to having
used a direct fetch to the recipient's home server; the relay's value
is only realized if it remains honest.

### 3.7 Compromised Endpoint

A user's device is under adversary control.

**Observes:** All envelopes the device can decrypt, which is the full
inbox and outbox for devices holding the user's identity and
encryption private keys; a scoped subset for devices holding scoped
delegated certificates (`KEY.md` section 10).

**Can do:** Act as the user toward the home server until the
compromise is detected and the device is revoked. Transmit the user's
private keys to the adversary. Sign a new Shamir recovery manifest
enrolling adversary-controlled devices (`RECOVERY.md` section 8.7).

**Mitigations:**

- Scoped delegated certificates limit the blast radius of compromising
  a device that has only a delegated certificate (`KEY.md`
  section 10.3).
- Device revocation via `SEMP_DEVICE_REVOCATION` with
  `reason: "key_compromise"` triggers mandatory identity-key rotation
  and a successor record to correspondents (`KEY.md` section 10.5.5).
  The revoked device cannot forge envelopes under the rotated identity
  key.
- The device directory (`KEY.md` section 10.6) is monotonically
  versioned and identity-signed; correspondents and delegated
  consumers reject device-scoped signatures from devices not listed in
  the current directory.
- Key transparency surfaces unauthorized key rotations.

SEMP does not claim recovery from endpoint compromise without user
intervention. Endpoint compromise is the dominant residual risk and is
acknowledged as such. The mandatory-rotation rule ensures that
detection-plus-revocation is sufficient to end the adversary's
ability to act as the user, limited only by how quickly the user
detects and revokes.

### 3.8 Key Compromise Scenarios

Loss of control of a long-term key has different consequences depending
on which key is lost.

| Key                               | If compromised, the attacker can                                                                                                | Detection                                                                                                                             |
|-----------------------------------|---------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------|
| Domain signing key                | Sign envelopes as from any user in that domain; impersonate the domain to peers.                                                | Transparency log monitors observe unexpected signing activity. Peers observe revocation records. Domain is rotated per `KEY.md` section 7. |
| User identity key                 | Issue envelopes as the user; rotate the user's encryption keys; sign a fraudulent successor record.                              | Transparency log entries for unexpected key rotations. Correspondents observe sudden address or behavior change.                      |
| User encryption key               | Decrypt envelopes previously sealed to that key until revocation propagates.                                                    | No inline detection. Revocation records published; correspondents invalidate caches.                                                 |
| Device identity key               | Act as that specific device until revoked. For primary devices, this is close to identity-key compromise.                        | Primary device revokes per `KEY.md` section 10.                                                                                       |
| Session long-term material        | SEMP uses ephemeral session keys for every session. There is no session long-term key beyond those already listed.               | N/A.                                                                                                                                  |
| Resumption ticket                 | If also able to observe the subsequent ephemeral DH, derive the resumed session's keys.                                          | Tickets are short-lived (7-day maximum, `SESSION.md` section 2.7).                                                                    |
| Recovery secret                   | Decrypt the user's backup bundle and recover the user's prior identity and encryption private keys.                              | No inline detection. Bundle rotation and transparency-monitored successor-record behavior bound exposure.                              |
| Shamir share (below threshold)    | Nothing useful. Shamir's Secret Sharing is information-theoretic below threshold.                                               | N/A.                                                                                                                                  |
| Shamir shares (threshold or more) | Reconstruct `K_bundle` and, with bundle ciphertext, recover the user's backup payload.                                           | No inline detection. `RECOVERY.md` section 8.6 discusses threshold selection.                                                          |

Forward secrecy of past session keys holds against every key-compromise
row above except for the resumption-ticket plus ephemeral-DH-observation
combination. `SESSION.md` section 2.8 is explicit about this.

---

## 4. Information Visibility by Party

The following summary states what each party to an envelope exchange
observes under the specification as written. Exceptions and edge cases
live in the cited documents.

| Party                    | Postmark domains | Brief ciphertext | Brief plaintext | Enclosure ciphertext | Enclosure plaintext | Sender address | Recipient address | Delivery outcome      |
|--------------------------|------------------|------------------|-----------------|----------------------|---------------------|----------------|-------------------|-----------------------|
| Sender client            | Yes              | Yes              | Yes             | Yes                  | Yes                 | Yes            | Yes               | Yes                   |
| Sender home server       | Yes              | Yes              | Yes             | Yes                  | No                  | Yes            | Yes               | Yes                   |
| Routing infrastructure   | Yes              | Yes (opaque)     | No              | Yes (opaque)         | No                  | No             | No                | No                    |
| Recipient home server    | Yes              | Yes              | Yes             | Yes                  | No                  | Yes            | Yes               | Yes                   |
| Recipient client         | Yes              | Yes              | Yes             | Yes                  | Yes                 | Yes            | Yes               | Yes                   |
| Passive network observer | Yes (domains)    | Yes (opaque)     | No              | Yes (opaque)         | No                  | No             | No                | Inferred from timing  |

"Yes (opaque)" means the bytes are visible but are ciphertext under keys
the observer does not hold.

---

## 5. What SEMP Defends Against

Summarized here for quick reference; full rationale is in the cited
sections.

- **Metadata disclosure to routing infrastructure.** Sealed envelope
  model (`ENVELOPE.md`, `DESIGN.md` section 4). Postmark exposes only
  routing-essential domains.
- **Forged envelopes.** Seal carries a domain signature (verifiable by
  any party) and a session MAC (verifiable by the recipient server)
  (`ENVELOPE.md` section 4.3). End-to-end sender signature inside the
  enclosure is verified by the recipient client (`ENVELOPE.md`
  section 6.5).
- **Silent rejection as default.** Explicit reject-with-reason is
  mandatory for well-formed envelopes; silent is reserved for
  anti-harassment (`DELIVERY.md` sections 1.3, 8.2, `HANDSHAKE.md`
  section 4.2).
- **Downgrade attacks on session establishment.** Confirm hash covers
  negotiated parameters (`HANDSHAKE.md` section 6.3).
- **Retroactive decryption of past sessions.** Ephemeral key exchange
  on every session; hybrid Kyber768+X25519 against
  harvest-now-decrypt-later (`SESSION.md` section 4).
- **Existence oracles.** Indistinguishable rejection for non-existent
  addresses (`DESIGN.md` section 2.7, `DELIVERY.md` section 6.4.3);
  optional speculative key caching and relay fetch (`KEY.md` section
  6.1).
- **Key substitution.** Transparency-log inclusion proofs and
  gossip-based split-view detection (`TRANSPARENCY.md`).
- **Recovery under operator distrust.** Server is a custodian of
  encrypted material only; it cannot initiate, gate, or observe
  recovery (`RECOVERY.md` section 8.3).
- **Cross-envelope first-contact token replay.** Tokens are single-use
  and bound to `postmark.id` (`HANDSHAKE.md` section 2.2a.3).
- **Unauthorized Shamir share injection at restore.** Recovery set
  manifest binds each share to a specific device identity key
  (`RECOVERY.md` sections 5.2, 8.7).
- **Envelope-size traffic analysis at bucket resolution.** Wire size is
  padded to the nearest power-of-two bucket between 1 KB and
  `max_envelope_size` (`ENVELOPE.md` section 2.4). Content-category
  inference is bounded to the bucket, not the exact size.
- **Recipient-count and group-size disclosure via seal structure.**
  Recipient maps are padded to power-of-two entry counts with
  indistinguishable dummy entries (`ENVELOPE.md` section 4.4.1). Group
  size is revealed only at bucket resolution.
- **Correspondent-graph inference via reputation gossip counts.**
  Observation metrics are published as power-of-two buckets, not exact
  counts (`REPUTATION.md` section 4.5.1). Intersection attacks are
  bounded to bucket width.

---

## 6. What SEMP Does Not Defend Against

These are acknowledged residual risks. Each is addressed in the cited
section.

### 6.1 Endpoint Compromise

A compromised user device has access to everything that device can
decrypt. Scoped delegated certificates (`KEY.md` section 10) limit
blast radius but do not prevent compromise.

### 6.2 Correspondent Graph at the Home Server

The recipient home server observes the full inbound and outbound
correspondent graph of its users. This is a structural consequence of
server-side user policy enforcement (block lists, first-contact gating)
and is acknowledged in `ENVELOPE.md` section 10.6. There is no
technical mitigation within the current specification; defense depends
on operator selection.

### 6.3 Traffic Analysis by Envelope Size and Timing

Envelope sizes reveal approximate content category (short text, image,
attached document) only at the bucket resolution defined in
`ENVELOPE.md` section 2.4. Wire sizes are padded to powers of two
between 1 KB and `max_envelope_size`, so every envelope is
indistinguishable in size from every other envelope in the same
bucket. Send timing correlates to user activity. The specification
does not mandate cover traffic. Operators requiring timing
unlinkability SHOULD batch outbound sends or introduce randomized
delays; these remain operator-layer techniques.

### 6.4 Social-Graph Inference from Reputation Gossip

Reputation observations published by servers include counts of senders
and envelopes observed from each peer domain (`REPUTATION.md`
section 4.2). Counts are published as power-of-two buckets per
`REPUTATION.md` section 4.5.1, not as exact values. Third parties
observing multiple gossip records cannot intersect them below the
bucket width, which reduces but does not eliminate domain-pair
correspondent-graph inference. The residual signal is intentional: it
preserves reputation utility while bounding leakage.

### 6.5 Migration-Record Linkability

Migration records are published in plaintext at both the old and new
provider, mapping old addresses to new ones for any observer
(`MIGRATION.md` section 10.1). A user re-identifying themselves across
providers cannot do so anonymously under the current migration flow.

### 6.6 Compelled Disclosure by the Home Server

A home server that is compelled to disclose data can provide the
correspondent graph, stored delivery receipts, and the user's block
list. It cannot provide envelope enclosure plaintexts, encryption
private keys, or recovery secrets, because it does not hold them. What
a compelled server is required to disclose is a legal question outside
the scope of this specification.

### 6.7 Onion-Only Deployment Leakage via Clearnet Artifacts

A `.onion` deployment's anonymity posture is defined by the operator
contract in `DISCOVERY.md` section 2.5.3. Tor-only deployments MUST
NOT publish DNS SRV, TXT, or well-known URI records under any
clearnet name that references the same backend; MUST NOT publish
domain or user keys at any clearnet endpoint; and MUST use standard
three-hop onion services rather than single-hop variants. Key
fetches for `.onion` recipients are restricted to Tor circuits per
`KEY.md` section 6.4; a sender without Tor egress MUST NOT attempt
clearnet fallback.

Residual risk. A Tor-only deployment that violates the operator
contract (by accident or misconfiguration) can still be deanonymized
by correlating the offending clearnet access with the onion service.
The specification names the contract and the consequences of
violating it; it cannot technically prevent a misconfigured
deployment. Operators requiring strong Tor isolation are the sole
party capable of enforcing the contract; THREAT.md readers
evaluating a specific deployment must confirm the contract is
honored for that deployment.

### 6.8 Fan-Out Patterns from Large Recipient Sets

A sender delivering an envelope to a large recipient set exposes the
size of that set only at the bucket resolution defined in
`ENVELOPE.md` section 4.4.1. Recipient maps are padded to power-of-two
entry counts with dummy entries indistinguishable from real wrapped
keys. A group message to 50 real recipients appears identical in
structure to a group message to 64 real recipients. Residual leakage
is the bucket index itself: an envelope with 64 entries is
distinguishable from one with 4.

---

## 7. Residual Risks and Open Problems

The following are known gaps that future revisions of the specification
are expected to address. Implementers and operators SHOULD treat them as
caveats on the security claims.

- **SMTP fallback wire format.** Implementer's choice, no interop
  specification. Open question: normative SMTP mapping.
- **Cover traffic and timing unlinkability.** Envelope and recipient
  size padding are specified (sections 2.4 and 4.4.1 of
  `ENVELOPE.md`), but timing correlation between send and receive
  events remains an open problem. Operator-layer batching or delayed
  sending is out of scope.

---

## 8. Relationship to Other Specifications

| Specification    | Relationship                                                                                                                                           |
|------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| `DESIGN.md`      | Governing principles. Section 2 articulates the design commitments; this document consolidates the adversary-facing view of those commitments.        |
| `ENVELOPE.md`    | Sections 10 and 11 detail envelope-layer security and privacy; this document aggregates across layers and names the compromised-server view.           |
| `HANDSHAKE.md`   | Section 6 covers handshake-layer guarantees; this document places them in the broader adversary model.                                                 |
| `SESSION.md`     | Sections 2.7, 2.8, and 4 cover session-key lifecycle and forward secrecy; this document summarizes forward secrecy under each key-compromise scenario. |
| `KEY.md`         | Section 12 covers key-distribution and revocation risks; section 6.1 covers existence-oracle hardening.                                                |
| `DELIVERY.md`    | Section 8 covers block-list and first-contact privacy; this document unifies those with the compromised-server view.                                   |
| `REPUTATION.md`  | Section 10 covers gossip leakage; this document names it as residual risk 6.4.                                                                         |
| `RECOVERY.md`    | Sections 8 and 9 cover recovery-specific threats; this document summarizes recovery-secret and Shamir-share compromise.                                |
| `TRANSPARENCY.md`| The key-transparency log is the detection mechanism for key-substitution adversaries in section 3.8 and the compromised-home-server view in section 3.3.|
| `MIGRATION.md`   | Section 10 covers migration-specific privacy; this document names record linkability as residual risk 6.5.                                             |
| `CLOSURE.md`     | Section 9 covers closure-specific privacy; residual timestamps may be visible in transparency-log entries for key revocations.                         |

---

*This document is an Internet-Draft. It is subject to revision prior to
finalization as a stable specification.*
