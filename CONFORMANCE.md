# SEMP Conformance Specification

**Sealed Envelope Messaging Protocol**
Status: Internet-Draft
Version: 0.1.0
Related: `DESIGN.md`, `ENVELOPE.md`, `HANDSHAKE.md`, `DISCOVERY.md`, `KEY.md`,
`REPUTATION.md`, `DELIVERY.md`, `CLIENT.md`, `SESSION.md`

---

## Abstract

This document defines the conformance requirements for SEMP implementations.
It consolidates the normative obligations scattered across the SEMP
specification suite into a single reference, organized by implementation role.
An implementation that satisfies all applicable requirements in this document
is conformant. An implementation that violates any MUST or MUST NOT requirement
is non-conformant.

This document does not introduce new protocol behavior. Every requirement here
is derived from and traceable to the specification that defines it. The
authoritative source for protocol semantics is always the originating
specification.

---

## 1. Terminology

Normative language follows RFC 2119, as established in `DESIGN.md` section 11:

**MUST**:  An absolute requirement of the specification.
**MUST NOT**:  An absolute prohibition.
**SHOULD**:  Recommended. Deviation requires documented justification.
**SHOULD NOT**:  Not recommended.
**MAY**:  Optional but permitted.

---

## 2. Implementation Roles

SEMP defines three implementation roles. A single software product may
implement one or more roles.

| Role              | Description                                                        |
|-------------------|--------------------------------------------------------------------|
| **SEMP Server**   | Operates on behalf of a domain. Handles handshakes, envelope routing, delivery policy, key publication, and discovery responses. |
| **SEMP Client**   | Operates on behalf of a user. Handles envelope composition, encryption, decryption, key management, and home server communication. |
| **Routing Server**| Intermediate server that forwards envelopes between domains. Verifies routing-layer integrity but does not decrypt content. |

A routing server is a subset of the server role. Any server that relays
envelopes in transit acts as a routing server for those envelopes.

---

## 3. Conformance Levels

### 3.1 Baseline Conformance

An implementation achieves baseline conformance by satisfying all MUST and
MUST NOT requirements applicable to its role. Baseline conformance is the
minimum for interoperability.

### 3.2 Recommended Conformance

An implementation achieves recommended conformance by satisfying all MUST,
MUST NOT, SHOULD, and SHOULD NOT requirements applicable to its role.
Recommended conformance represents the expected behavior of a
production-quality implementation.

### 3.3 Feature Conformance

Individual features (such as trust gossip publication, proof-of-work
challenges, or legacy interoperability) may be implemented independently.
An implementation that claims support for a feature MUST satisfy all
requirements associated with that feature. Partial feature implementation is
non-conformant for that feature.

---

## 4. Server Conformance Requirements

### 4.1 Envelope Processing

A conformant server MUST:

- Verify `seal.signature` against the sender domain's published key before
  any other envelope processing. (`ENVELOPE.md` §9.1)
- Reject envelopes with invalid seals immediately and explicitly.
  (`ENVELOPE.md` §9.1)
- Reject envelopes where `postmark.expires` is in the past.
  (`ENVELOPE.md` §9.1)
- Verify `postmark.session_id` references an active, non-expired,
  non-invalidated session, and reject if absent or invalid.
  (`ENVELOPE.md` §9.1)
- Verify `seal.session_mac` using `K_env_mac` from the referenced session
  and reject if invalid. (`ENVELOPE.md` §7.2, §9.1)
- Return a structured rejection response containing a reason code,
  human-readable description, and the `postmark.id` of the rejected envelope
  for all rejections. (`ENVELOPE.md` §9.2)
- Reproduce the canonical envelope serialization identically: UTF-8 JSON with
  lexicographically sorted keys, no insignificant whitespace, both
  `seal.signature` and `seal.session_mac` set to empty string, and
  `postmark.hop_count` omitted. (`ENVELOPE.md` §4.3)
- Use the defined envelope rejection reason codes. (`ENVELOPE.md` §9.3)

A conformant server MUST NOT:

- Accept and silently discard an envelope. (`ENVELOPE.md` §9.1,
  `DESIGN.md` §2.3)
- Forward an envelope with an invalid seal. (`ENVELOPE.md` §9.1)
- Modify any signed field of the envelope. (`ENVELOPE.md` §9.1)

A conformant server MAY:

- Increment `postmark.hop_count` if present, or add it starting at 1 if
  absent. (`ENVELOPE.md` §9.1)
- Reject envelopes where `postmark.hop_count` exceeds a locally configured
  maximum. (`ENVELOPE.md` §9.1)
- Cache recently seen `postmark.id` values and reject duplicates within the
  expiry window. (`ENVELOPE.md` §10.2)

### 4.2 Handshake Protocol

A conformant server MUST:

- Complete the four-message handshake sequence as defined: init, response,
  confirm, accepted/rejected. (`HANDSHAKE.md` §2.1)
- Generate a unique session identifier (ULID recommended) for each session.
  (`HANDSHAKE.md` §2.3)
- Sign message 2 (response) with its long-term domain key.
  (`HANDSHAKE.md` §2.3)
- Sign message 4 (accepted/rejected) with its domain key.
  (`HANDSHAKE.md` §5.6)
- Echo the client's nonce in message 2. (`HANDSHAKE.md` §2.3)
- Prefer the strongest mutually supported algorithm during negotiation. If
  a client offers both `pq-kyber768-x25519` and `x25519-chacha20-poly1305`,
  the server MUST select the post-quantum hybrid unless it cannot support it.
  (`HANDSHAKE.md` §6.4)
- Reject handshakes with nonces it has seen within the session TTL window.
  (`HANDSHAKE.md` §6.2)
- Enforce a handshake timeout. If the handshake is not completed within the
  timeout, the connection MUST be closed. 30 seconds is recommended.
  (`HANDSHAKE.md` §6.6)
- Send a `rejected` response rather than closing the connection without
  explanation when the handshake cannot be completed. (`HANDSHAKE.md` §5.6)
- Include a machine-readable reason code with all rejections.
  (`HANDSHAKE.md` §4.1)
- Check block lists before completing a handshake. (`DESIGN.md` §7)
- Provide blocked senders with an immediate, explicit rejection with a
  reason code. (`DESIGN.md` §7)

A conformant server MUST NOT:

- Allocate session resources for incomplete handshakes beyond what is needed
  to enforce the timeout. (`HANDSHAKE.md` §6.6)

### 4.3 Session Management

A conformant server MUST:

- Hold session state only in memory; never write session keys to disk,
  replicate to secondary storage, or include them in backups.
  (`SESSION.md` §2.3)
- Erase all session key material using secure zeroing when a session expires
  or is invalidated. (`SESSION.md` §2.4)
- Retain expired `session_id` values in an expiry log for replay prevention
  for a duration equal to the maximum `postmark.expires` window (default:
  one hour). (`SESSION.md` §5.2)
- Reject envelopes referencing retired sessions with `reason_code:
  "handshake_invalid"`. (`SESSION.md` §5.2)
- Permit at most one active session per authenticated client identity.
  Invalidate the older session before completing a new handshake for the
  same identity. (`SESSION.md` §2.5.1)
- Permit at most one active session per peer domain for federation sessions,
  with the same invalidation rule. (`SESSION.md` §2.5.2)
- Enforce a bound on total concurrent active sessions (recommended defaults:
  10,000 client sessions, 1,000 federation sessions per server). Reject new
  handshakes with `reason_code: "server_at_capacity"` when the limit is
  reached. (`SESSION.md` §2.5.3)
- Respect published TTL values from DNS records. (`HANDSHAKE.md` §3.1)
- Reject messages sent on expired sessions with an explicit reason code.
  (`HANDSHAKE.md` §3.2)
- Use `mlock` (POSIX) or `VirtualLock` (Windows) on memory regions holding
  session keys where the platform supports it. If the call fails, log a
  startup warning and identify which key types are unprotected.
  (`SESSION.md` §5.1)
- Exclude session key memory from crash dumps where the OS provides a
  mechanism. (`SESSION.md` §5.1)

A conformant server MUST NOT:

- Derive session keys from, or use them to derive, long-term key material.
  (`SESSION.md` §5.3)
- Use `K_env_mac` as input to any key derivation beyond its defined MAC
  purpose. (`SESSION.md` §5.3)
- Silently continue as if memory locking succeeded when `mlock` or equivalent
  fails. (`SESSION.md` §5.1)

### 4.4 Discovery

A conformant server MUST:

- Perform discovery for recipient domains before cross-domain delivery.
  (`DISCOVERY.md` §1)
- Serve its configuration document at `/.well-known/semp/configuration`
  over HTTPS. This is the only fixed URL in the protocol.
  (`DISCOVERY.md` §3, §3.2.1)
- Advertise every protocol endpoint it exposes, without exception, through
  the `endpoints` object of its configuration document. A server MUST NOT
  expose a protocol endpoint that is not advertised in its configuration
  document. (`DISCOVERY.md` §3.2.1)
- Keep discovery requests anonymous by default: a lookup request MUST NOT
  identify the requester or the specific sender. (`DISCOVERY.md` §1.2)
- Follow the discovery flow: DNS SRV/TXT first, well-known URI as fallback,
  then MX record check for legacy capability. (`DISCOVERY.md` §5.1)
- Perform an MX record lookup when SEMP discovery fails, to determine
  whether the domain supports SMTP. (`DISCOVERY.md` §7.1)
- Not attempt an SMTP connection during discovery, since the MX record is
  sufficient confirmation. (`DISCOVERY.md` §7.2)
- Cache discovery results per the TTL returned in the response or DNS record.
  (`DISCOVERY.md` §6.1)
- Respect TTL values from DNS and lookup responses. (`DISCOVERY.md` §6.1)
- Invalidate cache entries on delivery failure and re-discover before retry.
  (`DISCOVERY.md` §6.1)
- Not serve stale entries beyond their TTL. (`DISCOVERY.md` §6.1)
- Verify the signature on lookup responses before caching or acting on
  results. Discard unsigned or unverifiable responses.
  (`DISCOVERY.md` §4.6, §8.1)
- Resolve every peer protocol endpoint exclusively from the peer's
  configuration document. A server MUST NOT probe well-known or guessed
  paths for peer endpoints. Absence of a field in `endpoints` is
  definitive: the peer does not offer that capability.
  (`DISCOVERY.md` §3.2.1)
- Return per-recipient results in the submission response when a message has
  recipients across multiple discovery outcomes. (`DISCOVERY.md` §5.3)
- Ignore unknown fields in capability documents rather than failing.
  (`DISCOVERY.md` §3.1)
- Treat unknown TXT record parameters as ignored rather than errors.
  (`DISCOVERY.md` §2.2)
- Return a valid response to unauthenticated discovery requests from unknown
  domains, subject to rate limiting. (`DISCOVERY.md` §6.2)
- Return identical `status`, `transports`, `extensions`, and `ttl` values
  for every address on the same recipient domain, regardless of whether
  the address corresponds to a registered user. Per-address existence
  MUST NOT be inferable from the response. (`DISCOVERY.md` §4.6.1)
- Not include per-user signals (mailbox existence, activity timestamps,
  recipient status) in discovery result objects. The result object fields
  defined in `DISCOVERY.md` §4.5 are exhaustive for anonymous discovery.
  (`DISCOVERY.md` §4.6.1)
- Rate-limit discovery requests by requester class: anonymous requests by
  source network prefix, authenticated requests by requester domain, with
  reputation-adjusted per-domain ceilings. (`DISCOVERY.md` §6.2.4)

A conformant server implementing the `lookup` partition strategy MUST:

- Require authenticated discovery for every lookup query and reject
  anonymous lookups with a response indistinguishable for valid and
  invalid addresses. (`DISCOVERY.md` §2.4.4)
- Verify the `semp.dev/auth` signature on every lookup request before
  returning per-address routing information.
  (`DISCOVERY.md` §2.4.4, §6.2.3)
- Log every authenticated lookup query with requester domain, timestamp,
  and address count. (`DISCOVERY.md` §2.4.4)
- Return a generic negative response for addresses that do not exist,
  indistinguishable in structure, size, and timing from responses for
  existing addresses. (`DISCOVERY.md` §2.4.4)

A conformant server implementing authenticated discovery MUST:

- Verify `semp.dev/auth` signatures against the requester's published
  domain key before applying authenticated-tier policy.
  (`DISCOVERY.md` §6.2.3)
- Treat requests with invalid signatures as anonymous rather than
  returning a distinguishable error response. (`DISCOVERY.md` §6.2.3)
- Not interpret authenticated discovery as identification of an
  individual user. The authentication identifies the server domain
  only. (`DISCOVERY.md` §6.2.6)

A conformant server MUST NOT:

- Require authenticated discovery as a condition of SEMP interoperability,
  except for partition lookup queries per `DISCOVERY.md` §2.4.4.
  (`DISCOVERY.md` §6.2)
- Use the `lookup` partition strategy without implementing the
  authenticated-lookup requirement in `DISCOVERY.md` §2.4.4.

A conformant server SHOULD:

- Prefer `hash` or `alpha` partitioning over `lookup` partitioning to
  eliminate the address harvesting surface. (`DISCOVERY.md` §2.4)
- Hash plaintext addresses before writing them to access logs, audit
  logs, telemetry pipelines, or other operational data not part of the
  protocol state itself. (`DISCOVERY.md` §8.3.4)
- Publish `protocol_abuse` observation records against requester domains
  that exhibit sustained address-harvesting patterns via authenticated
  discovery. (`DISCOVERY.md` §6.2.5, `REPUTATION.md` §3.4)

### 4.5 Key Management (Server)

A conformant server MUST:

- Publish domain keys via DNS/DANE TLSA records as the primary mechanism, with
  well-known URI as fallback. (`KEY.md` §2.1, §2.3)
- Support post-quantum algorithms in all key discovery mechanisms.
  (`KEY.md` §12.1)
- Retain revocation records indefinitely. (`KEY.md` §8.3)
- Return revocation records when a revoked key is requested.
  (`KEY.md` §8.4)
- Reject device registrations without a valid authorization proof from an
  existing trusted device. (`CLIENT.md` §2.2)

### 4.6 Delivery and Blocking

A conformant server MUST:

- Track the acknowledgment type of every delivery attempt and surface it to
  the sending user accurately. (`DELIVERY.md` §1.4)
- Not misrepresent acknowledgment types. If a `rejected` response is received,
  the user MUST be told delivery failed. (`DELIVERY.md` §1.4)
- Enforce a timeout on delivery attempts (30 seconds recommended for initial
  attempts). (`DELIVERY.md` §1.5)
- Follow the fixed delivery pipeline sequence for envelope processing.
  (`DELIVERY.md` §3)
- Maintain a sender-side queue for submitted envelopes, persist queued
  envelopes across restart, and not mutate `seal` or `postmark` between
  attempts. (`DELIVERY.md` §2.1)
- Classify per-attempt outcomes as terminal or non-terminal and retry only
  recoverable non-terminal outcomes. (`DELIVERY.md` §2.2)
- Retry non-terminal outcomes according to the exponential backoff bounds,
  jitter requirement, and minimum attempt count defined in the retry
  schedule. (`DELIVERY.md` §2.3)
- Compute an effective delivery deadline as the earlier of `postmark.expires`
  and `queued_at + server_max_retry_horizon`, and not retry past it.
  (`DELIVERY.md` §2.4)
- Transition an envelope to the terminal state `expired` when the effective
  deadline is reached without a terminal acknowledgment. (`DELIVERY.md` §2.4)
- Maintain a queue state record per queued envelope and retain the terminal
  record for at least 24 hours after termination. (`DELIVERY.md` §2.5)
- Not generate synthetic bounce envelopes and not transmit any message
  across federation in response to a terminal delivery failure.
  (`DELIVERY.md` §2.6)
- Store queued envelopes encrypted at rest and not decrypt the enclosure at
  any point in the queue lifecycle. (`DELIVERY.md` §2.8)
- Accept client-initiated cancellation requests for queued envelopes, halt
  retry scheduling, transition affected queue state records to `canceled`,
  and emit the corresponding delivery event. (`DELIVERY.md` §2.7)
- Enforce delegated-client authority on cancellation: a delegated client
  MAY cancel only envelopes it submitted itself. (`DELIVERY.md` §2.7.2)
- Not propagate cancellation across federation and not attempt to retract an
  envelope already delivered to the recipient server. (`DELIVERY.md` §2.7.3)
- Treat cancellation as idempotent and not override a prior terminal state.
  (`DELIVERY.md` §2.7.2, §2.7.4)
- Enforce delivery policy on cryptographically verified identifiers.
  (`DELIVERY.md` §9.1)
- Verify signatures on block list sync messages before storing or
  propagating. Reject unsigned or unverifiable sync messages.
  (`DELIVERY.md` §7.2, §9.2)
- Store block lists encrypted at rest; the server MUST NOT be able to read
  block list contents in plaintext. (`DELIVERY.md` §7.3)
- Not disclose block list contents to any party other than the owning user's
  authenticated devices. (`DELIVERY.md` §8.1)
- Explicitly reject envelopes with invalid seals even when operating in
  silent mode. (`DELIVERY.md` §1.3)
- Maintain consistent timing in silent mode, because timing variations that
  correlate with delivery policy would leak information.
  (`DELIVERY.md` §8.2)
- Send a delivery event notification to the client when the outcome of a
  queued envelope is known. (`CLIENT.md` §6.5)
- Reject block list entries whose `entity.type` is `ip`, whose entity
  fields contain an IP-address-shaped value, or that identify a network
  range, CIDR block, autonomous system number, or geographic region
  derived from IP. Block lists are protocol-layer trust artifacts and
  MUST be keyed by user, domain, or server identity.
  (`DELIVERY.md` §5.3.1, `DESIGN.md` §2.2.1)
- Not propagate transport-layer operational defenses (firewall rules,
  connection rate limits, DoS mitigation entries) as SEMP block list
  entries or as federation-visible policy signals.
  (`DELIVERY.md` §5.3.1, `DESIGN.md` §2.2.1)
- Enforce the recipient's published first-contact policy on every
  envelope addressed to a recipient on the server's domain.
  (`DELIVERY.md` §6.4, `KEY.md` §3.2)
- Issue first-contact `proof_of_work` challenges of identical
  difficulty for non-existent and existent recipient addresses, on
  identical code paths, with indistinguishable response shape, size,
  and timing. (`DELIVERY.md` §6.4.3, `DESIGN.md` §2.7)
- Not return any reason code that distinguishes per-address existence
  from policy rejection. Use `policy_forbidden` for both.
  (`ENVELOPE.md` §9.3, `DESIGN.md` §2.7)
- Apply per-sender-domain rate limits on submissions to
  non-known-correspondent recipients and switch to `silent`
  acknowledgment when the threshold is exceeded.
  (`DELIVERY.md` §6.5)
- Count submissions to non-existent and existent recipient addresses
  identically for rate-limit purposes. (`DELIVERY.md` §6.5.1)

A conformant server MAY:

- Return a generic reason code rather than `blocked` if revealing the
  specific reason would itself be harmful. (`DELIVERY.md` §8.2)
- Propagate block events to federation partners as policy signals. Partners
  are not required to honor another server's block decisions.
  (`DESIGN.md` §7)

### 4.6.1 Internal Route Delivery

A conformant server that receives an envelope via `SEMP_INTERNAL_ROUTE` MUST:

- Execute the full delivery pipeline defined in `DELIVERY.md` §3 before
  returning an acknowledgment. (`DELIVERY.md` §6.3, `DISCOVERY.md` §5.4.1)
- Return an acknowledgment using one of the three standard acknowledgment
  types: `delivered`, `rejected`, or `silent`. (`DISCOVERY.md` §5.4.1)
- Enforce the recipient's block list. Block enforcement is the responsibility
  of the partition server that holds the recipient's block list.
  (`DELIVERY.md` §6.3, `DISCOVERY.md` §5.4.2)
- Maintain consistent timing in silent mode, identical to cross-domain
  delivery. (`DELIVERY.md` §8.2)

A conformant server that sends an envelope via `SEMP_INTERNAL_ROUTE` MUST:

- Forward the receiving server's acknowledgment to the client in the
  submission response without override or suppression.
  (`DISCOVERY.md` §5.4.1)
- Enforce a timeout on internally routed deliveries and treat expiry as
  `silent`. (`DELIVERY.md` §1.5, `DISCOVERY.md` §5.4.1)

A conformant server MUST NOT:

- Access, query, or cache the block list of a recipient on another partition
  server. (`DISCOVERY.md` §5.4.2, `DELIVERY.md` §8.1)

### 4.7 Reputation

A conformant server MUST:

- Not reject messages from zero-reputation domains solely because they are
  unknown, without explicit operator configuration. (`REPUTATION.md` §8.1,
  `DESIGN.md` §5.4)
- Key every reputation ledger entry and every published observation record
  by domain identity, never by IP address, network range, or other
  transport-layer artifact. (`DESIGN.md` §2.2.1, `REPUTATION.md` §1.3)
- Preserve a domain's accumulated reputation across source-IP changes.
  A domain that migrates hosting, adopts a CDN, or becomes Tor-only MUST
  NOT lose its reputation history. (`REPUTATION.md` §1.3)
- Start unrelated SEMP domains that share a single hosting IP at
  independent zero reputation. One domain's behavior MUST NOT taint
  another domain on the same IP. (`REPUTATION.md` §1.3)
- Accept federation handshakes regardless of source IP, including from
  Tor exit nodes and other anonymizing transports, subject only to
  domain-level policy and transport-layer operational defenses.
  (`DESIGN.md` §2.2.1, `REPUTATION.md` §1.3)
- Not let IP-keyed signals, transport-layer observations, or network-level
  reputation data influence protocol-layer trust decisions (delivery
  policy, block list propagation, gossip observations, abuse reports, or
  federation-visible rate-limit responses). Transport-layer operational
  defenses (DoS protection, connection rate limits) MAY be IP-keyed but
  MUST stay at the transport layer. (`DESIGN.md` §2.2.1)
- Verify observation signatures before using them. Discard observations
  signed by unknown or untrusted keys. (`REPUTATION.md` §9.1)
- Not fabricate or inflate observation metrics. (`REPUTATION.md` §4.5)
- Verify challenge solutions before proceeding with handshakes: confirm
  `challenge_id` matches an issued, unexpired challenge, recompute the hash,
  and confirm the required leading zero bits. (`REPUTATION.md` §8.3.4)
- Treat each challenge as single use and reject duplicate submissions.
  (`REPUTATION.md` §8.3.4)
- Not treat challenge completion as evidence of legitimacy.
  (`REPUTATION.md` §8.3.5)
- Not issue a `proof_of_work` challenge with `difficulty` greater than 28,
  regardless of sender reputation or operator policy. (`HANDSHAKE.md`
  §2.2a.2, `REPUTATION.md` §8.3.2)
- Not issue a `proof_of_work` challenge whose `expires` value is below the
  minimum expiry floor for its difficulty (30 seconds at difficulty 0 to
  20, 60 seconds at 21 to 24, 120 seconds at 25 to 28). (`HANDSHAKE.md`
  §2.2a.2)
- Not disclose decrypted envelope content in abuse evidence without the
  explicit, signed authorization of the affected user.
  (`REPUTATION.md` §3.7)

A conformant server SHOULD:

- Query WHOIS data as part of policy evaluation for previously unobserved
  domains. (`REPUTATION.md` §2.1)
- Apply automatic rate limiting to domains with insufficient registration
  age. Recommended minimum threshold: 30 days. (`REPUTATION.md` §2.1)
- Apply baseline scrutiny to zero-reputation domains: rate limiting, domain
  age gating, and proof-of-work challenges in increasing order of friction.
  (`REPUTATION.md` §8.1)

### 4.8 Federation Handshake

A conformant server participating in federation MUST:

- Include `server_domain` and `server_identity_proof` in the federation init
  message. (`HANDSHAKE.md` §5.2)
- Verify domain ownership through one of the supported verification methods
  (DNS TXT, certificate, well-known URI) before completing the handshake.
  (`HANDSHAKE.md` §5.3)
- When two federation servers simultaneously initiate handshakes to each
  other, resolve the collision deterministically: the session whose
  `session_id` sorts lower lexicographically is abandoned.
  (`SESSION.md` §2.5.2)
- When performing a server-to-server handshake as the initiator, abort with
  reason code `challenge_invalid` on receipt of a `proof_of_work`
  challenge whose `difficulty` exceeds 28, and not attempt to solve the
  challenge. The initiating server MUST treat the remote server as
  misbehaving and MUST NOT retry under the same conditions.
  (`HANDSHAKE.md` §2.2a.2)
- When performing a server-to-server handshake as the initiator, abort
  with reason code `challenge_invalid` on receipt of a `proof_of_work`
  challenge whose `expires` value is below the minimum expiry floor for
  its difficulty. (`HANDSHAKE.md` §2.2a.2)

A conformant federation server SHOULD:

- Record `challenge_invalid` aborts as a metric and retain the signed
  `challenge` message as evidence. (`ERRORS.md` §2)
- Publish `protocol_abuse` observation records against remote domains that
  exhibit the sustained challenge issuance pattern described in
  `REPUTATION.md` section 8.3.6, subject to the evidence and threshold
  requirements defined there.

### 4.9 Extensibility

A conformant server MUST:

- Ignore unknown extension keys with `required: false` rather than rejecting
  the envelope. (`ENVELOPE.md` §8.1, `EXTENSIONS.md` §3.2)
- Reject envelopes containing an unknown extension with `required: true` with
  reason code `extension_unsupported`. The rejection MUST include the
  unrecognized extension key. (`EXTENSIONS.md` §3.1)
- Reject envelopes where any `extensions` object exceeds the size limit for
  its layer: 4 KB for `postmark.extensions` and `seal.extensions`, 16 KB for
  `brief.extensions`, 64 KB for `enclosure.extensions`. The rejection reason
  code is `extension_size_exceeded`. (`EXTENSIONS.md` §4.1, §4.2)
- Enforce extension size limits before performing signature verification to
  prevent resource exhaustion. (`EXTENSIONS.md` §13.2)
- Resolve every recognized extension's identifier to its canonical
  definition document URL per `EXTENSIONS.md` §6.1, fetch and cache the
  document, and verify the document's signature against the namespace
  owner's domain key before treating the definition as authoritative.
  (`EXTENSIONS.md` §6.8, §6.9)
- Perform runtime validation on every received extension entry: `data`
  field MUST conform to the extension's `data_schema`, the entry MUST
  appear in a layer listed in `placement.allowed_layers`, the producing
  party MUST match `authority.produced_by`, all `dependencies` MUST be
  present or advertised, and no entry from `conflicts_with` MUST be
  present. (`EXTENSIONS.md` §8.2)
- Reject any envelope failing runtime extension validation with
  `extension_unsupported` and SHOULD include the `validation_failure`
  diagnostic. (`EXTENSIONS.md` §8.3)

Extensions MUST:

- Use namespaced keys to prevent collision:
  `"vendor.example.com/feature-name"`. (`ENVELOPE.md` §8.1, `EXTENSIONS.md` §2.3)
- Not redefine or shadow reserved field names at their layer.
  (`ENVELOPE.md` §8.1)
- Include a `required` boolean and a `data` object in every extension entry.
  (`EXTENSIONS.md` §2.2)
- Resolve to a definition document at the URL derived from the identifier,
  signed by the namespace owner's domain key. Vendor extensions without a
  conformant definition document MUST NOT participate in the standard
  extension ecosystem. (`EXTENSIONS.md` §6)

### 4.9.1 Reference SDK Enforcement

A SEMP implementation that claims **reference SDK conformance** MUST:

- Mediate every extension access to envelope state through host-provided
  accessor functions and check each access against the calling extension's
  declared `permissions.reads` and `permissions.writes`. Direct memory
  access to envelope structures MUST NOT be exposed.
  (`EXTENSIONS.md` §9.2)
- Invoke registered extensions only at hooks declared in their definition
  document. Extensions MUST NOT run at undeclared hook points.
  (`EXTENSIONS.md` §9.2)
- Log denied access attempts and treat repeated denials from a single
  extension as evidence of misbehavior reportable as `protocol_abuse`.
  (`EXTENSIONS.md` §9.2, `REPUTATION.md` §3.4)
- Verify extension definition document signatures at extension load time,
  including for bundled definitions shipped with the SDK.
  (`EXTENSIONS.md` §6.8, §6.9)

Reference SDK conformance is RECOMMENDED for all conformant
implementations and is strongly RECOMMENDED for any implementation
loading `semp.dev/*` extensions that handle sensitive data.

### 4.9.2 Per-Extension Key Scoping

A conformant server that processes envelopes carrying scoped extension
entries (`scoped: true`) MUST:

- Forward the seal's `enclosure_recipients.extension_keys` map intact
  during delivery without modification. (`ENVELOPE.md` §7.4.1)
- Account for scoped extension ciphertext sizes against the
  `enclosure.extensions` size limit. (`ENVELOPE.md` §7.4.6)

A conformant client MUST:

- Treat absent per-extension keys as a normal authorization signal, not
  as decryption failure, and MUST NOT surface absence to the user as an
  error. (`ENVELOPE.md` §7.4.4)
- Bind per-extension AEAD ciphertexts with associated data including
  `postmark.id` and the extension identifier, to prevent cross-extension
  substitution. (`ENVELOPE.md` §7.4.2)
- Generate per-extension keys freshly per envelope, independently of
  `K_enclosure`. (`ENVELOPE.md` §7.4.2)

### 4.10 Scoped Device Certificate Enforcement

A conformant server MUST:

- Verify the signature chain on scoped device certificates: the certificate
  MUST be signed by a device key that is authorized for the account.
  (`KEY.md` §10.3.1)
- Enforce the permission scope from the current certificate on every envelope
  submission from a delegated device. The server MUST check the current
  certificate at submission time, not the certificate that was active when
  the session was established. (`CLIENT.md` §2.4)
- Reject envelope submissions where any recipient is outside the delegated
  device's `scope.send.allow` list (when `mode` is `restricted`) with reason
  code `scope_exceeded`. (`CLIENT.md` §2.4, `KEY.md` §10.3.4)
- Reject envelope submissions from devices with `scope.send.mode` set to
  `none`. (`KEY.md` §10.3.4)
- Not deliver inbound envelopes to devices with `scope.receive` set to
  `false`. (`CLIENT.md` §2.4)
- Accept certificate updates from the primary device without invalidating
  the delegated device's active session. (`KEY.md` §10.3.6)
- Terminate sessions and reject further handshakes when a device key is
  revoked. (`KEY.md` §10.3.7)
- Reject scoped certificates with more than 10,000 entries in the `allow`
  list. (`KEY.md` §10.3.4)

### 4.11 Recipient Status

A conformant server MUST:

- Not include `recipient_status` in delivery acknowledgments unless the
  recipient has explicitly enabled it. The default is no status disclosure.
  (`DELIVERY.md` §1.6.4)
- Evaluate status visibility rules against the sender's identity (from
  `brief.from`) and include status only when the sender matches a visibility
  rule. (`DELIVERY.md` §1.6.4)
- Not disclose status to senders who do not match any visibility rule. A
  non-matching sender MUST receive an acknowledgment with no
  `recipient_status` field. (`DELIVERY.md` §8.4)
- Not reject or delay envelopes based on recipient status. Status is
  informational only. (`DELIVERY.md` §1.6.3)

### 4.12 Device Sync

A conformant server MUST:

- Accept self-addressed envelopes whose `brief.from` and `brief.to` resolve
  to the same user address. The server MUST NOT reject an envelope solely
  because the sender and recipient addresses are equal. (`CLIENT.md` §4.5.1)
- Apply the ordinary delivery pipeline to envelopes carrying the
  `semp.dev/device-sync` marker in `brief.extensions`, including seal
  verification and per-device fan-out. (`CLIENT.md` §4.5.4)
- Exclude sync envelopes from reputation signals, abuse accounting, and
  trust gossip records. (`CLIENT.md` §4.5.4, `REPUTATION.md` §3)
- Omit sync envelopes from delivery event notifications sent to external
  correspondents. (`CLIENT.md` §4.5.4)
- Not read or act on the contents of `enclosure.extensions` on a sync
  envelope. (`CLIENT.md` §4.5.4)

---

## 5. Client Conformance Requirements

### 5.1 Connection Model

A conformant client MUST:

- Connect only to its own home server. A client MUST NOT connect directly to
  a remote domain's server. (`HANDSHAKE.md` §1.2, `CLIENT.md` §1.1)
- Not perform cross-domain discovery directly. (`DISCOVERY.md` §1.1)

### 5.2 Cryptographic Obligations

A conformant client MUST perform the following operations locally and MUST NOT
delegate them to the home server (`CLIENT.md` §1.3):

- Generation of the user's identity and encryption key pairs.
- Encryption of outbound `brief` and `enclosure` content.
- Decryption of inbound `brief` and `enclosure` content.
- Generation of per-envelope symmetric keys (`K_brief`, `K_enclosure`).
- Wrapping of symmetric keys under recipient public keys.
- Signing of identity proofs during the handshake.

### 5.3 Handshake Obligations

A conformant client MUST:

- Send an anonymous init message containing no identifying information.
  (`CLIENT.md` §2.1)
- Encrypt the identity proof in the confirm message under the session secret.
  The identity proof MUST NOT appear in plaintext on the wire.
  (`CLIENT.md` §2.1)
- Compute `identity_signature` over `session_id || confirmation_hash` using
  the client's long-term identity key. (`CLIENT.md` §2.1)
- Verify the server's `server_signature` on message 2 before transmitting
  the identity proof. Abort if verification fails. (`CLIENT.md` §2.1)
- Verify the `server_signature` on message 4 before treating the session as
  established. (`CLIENT.md` §2.1)
- Record session state on receipt of the `accepted` message, including
  `session_ttl` and the locally computed `expires_at`.
  (`CLIENT.md` §2.1, `SESSION.md` §2.6.1)
- Verify `server_signature` on `challenge` messages before computing a
  solution. Abort on invalid signatures. (`HANDSHAKE.md` §2.2a)
- Abort the handshake with reason code `challenge_invalid` on receipt of a
  `proof_of_work` challenge whose `difficulty` exceeds 28, and not attempt
  to solve the challenge. This requirement applies equally to federation
  peers performing server-to-server handshakes. (`HANDSHAKE.md` §2.2a.2,
  §5)
- Abort the handshake with reason code `challenge_invalid` on receipt of a
  `proof_of_work` challenge whose `expires` value, measured against the
  initiator's clock at receipt, is below the minimum expiry floor for its
  difficulty. (`HANDSHAKE.md` §2.2a.2)

A conformant client SHOULD:

- Surface `challenge_invalid` aborts to the user as a security warning
  rather than a generic connection failure, identifying the remote domain
  as potentially misbehaving or compromised. (`ERRORS.md` §2)
- Retain the signed `challenge` message that caused a `challenge_invalid`
  abort for potential inclusion in a `protocol_abuse` report.
  (`REPUTATION.md` §8.3.6)

### 5.4 Envelope Composition

A conformant client MUST:

- Follow the composition sequence defined in `CLIENT.md` §3.1: compose
  plaintext, sign the enclosure, generate fresh `K_brief` and `K_enclosure`,
  encrypt, wrap keys under recipient public keys, compose the postmark.
- Compute `enclosure.sender_signature` over the canonical enclosure bytes
  using the sending user's identity key, before encrypting the enclosure.
  (`CLIENT.md` §3.1, `ENVELOPE.md` §6.5)
- Use the sending user's identity key (not a device, ephemeral, or session
  key) for `enclosure.sender_signature`. (`ENVELOPE.md` §6.5.1)
- Generate `K_brief` and `K_enclosure` freshly for each envelope. MUST NOT
  reuse. (`CLIENT.md` §3.1)
- Check the revocation status of every recipient key received.
  (`CLIENT.md` §3.1)
- Support `x25519-chacha20-poly1305` (baseline) and `pq-kyber768-x25519`
  (recommended). (`ENVELOPE.md` §7.3)
- Not negotiate algorithms below the minimum baseline. (`ENVELOPE.md` §7.3)

For forward composition, a conformant client MUST:

- Preserve the original received enclosure plaintext verbatim, including
  its `sender_signature`, in `enclosure.forwarded_from.original_enclosure_plaintext`.
  MUST NOT modify any field of the original enclosure plaintext.
  (`CLIENT.md` §3.7, `ENVELOPE.md` §6.6)
- Sign `forwarded_from` with `forwarder_attestation` using the forwarding
  user's identity key, with `forwarder_attestation.key_id` matching the
  outer `enclosure.sender_signature.key_id`.
  (`ENVELOPE.md` §6.6.3)
- Place forwarder commentary only in the new enclosure's own `subject`,
  `body`, and `attachments` fields, not by modifying the original enclosure
  plaintext. (`CLIENT.md` §3.7)
- Not collapse, truncate, or reorder a multi-level forwarding chain.
  (`CLIENT.md` §3.7, `ENVELOPE.md` §6.6.5)

For envelope receipt, a conformant client MUST:

- Verify `enclosure.sender_signature` against the sender's identity key
  before rendering enclosure content. MUST NOT render content if
  verification fails. (`CLIENT.md` §4.1, `ENVELOPE.md` §6.5.3)
- Surface a security warning when sender signature verification fails.
  (`ENVELOPE.md` §6.5.3)
- When `enclosure.forwarded_from` is non-null, perform the verification
  chain in `ENVELOPE.md` §6.6.4: outer sender signature, forwarder
  attestation, then the original sender's signature on
  `original_enclosure_plaintext`. MUST NOT display original content as
  attributed to the claimed original sender if any verification fails.
  (`CLIENT.md` §4.1, `ENVELOPE.md` §6.6.4)
- Not present `original_seal` or `original_postmark` from a forwarded
  block as cryptographically verified evidence. These fields are advisory
  only. (`ENVELOPE.md` §6.6.4)
- For multi-level forwards, verify each level of the forwarding chain
  recursively. (`ENVELOPE.md` §6.6.5)

### 5.5 Session State Management

A conformant client MUST:

- Hold session state only in process memory. MUST NOT write it to disk,
  caches, databases, log files, crash reports, analytics payloads, or cloud
  backups. (`SESSION.md` §2.6.2)
- Erase session key material using secure zeroing on application termination.
  (`SESSION.md` §2.6.2)
- Erase session key material when the device transitions to a locked state.
  (`SESSION.md` §2.6.3)
- Initiate a fresh handshake on resumption from backgrounding rather than
  attempting to resume the prior session. (`SESSION.md` §2.6.3)
- Treat `handshake_expired`, `handshake_invalid`, and `no_session` responses
  as definitive evidence that a session has expired, regardless of the local
  `expires_at`. (`SESSION.md` §2.6.4)
- Not assume a session is valid beyond `expires_at`. If `expires_at` has
  passed without a completed rekey, treat the session as expired and begin a
  fresh handshake. (`SESSION.md` §2.6.4)

A conformant client SHOULD:

- Erase session key material on backgrounding and treat the session as ended.
  (`SESSION.md` §2.6.3)
- Proactively initiate rekeying at 80% of `server_ttl`.
  (`SESSION.md` §2.6.4)

### 5.6 Delivery State Reporting

A conformant client MUST:

- Accurately reflect the submission status received from the home server
  for all submission states (`delivered`, `rejected`, `silent`,
  `legacy_required`, `recipient_not_found`, `queued`) and all event-only
  terminal states (`expired`, `canceled`). (`CLIENT.md` §7.1)
- Distinguish all states listed above in the user interface.
  (`CLIENT.md` §7.1)
- Not display a delivery-confirmed indicator until a `delivered` status has
  been received. (`CLIENT.md` §7.1)
- Not display a `canceled` indicator for a recipient until a
  `cancel_response` entry or a delivery event reports `state: canceled` for
  that recipient. (`CLIENT.md` §6.6.3)
- Not misrepresent a `delivered` envelope as `canceled` when an in-flight
  attempt completed before cancellation could be applied.
  (`CLIENT.md` §6.6.3, `DELIVERY.md` §1.4)
- Not send cancellation requests for envelopes the client did not itself
  submit, where the client is a delegated client. (`CLIENT.md` §6.6.3)
- Surface which recipients received a multi-recipient message and which did
  not. Partial failure MUST NOT be suppressed or aggregated.
  (`CLIENT.md` §7.3)
- Present envelopes from senders that are not yet known correspondents in a
  separate first-contact area distinct from the primary inbox.
  (`CLIENT.md` §7.2)
- Treat a user reply to a first-contact envelope as implicit approval of
  the sender, performing the approval actions before transmitting the
  reply. (`CLIENT.md` §7.2.2)
- Not auto-approve first-contact senders based on heuristics. Approval
  MUST be the result of an explicit user action. (`CLIENT.md` §7.2.3)

### 5.7 Legacy Interoperability

A conformant client MUST:

- Surface the encryption degradation to the user before proceeding with SMTP
  fallback when `legacy_required` is received. (`CLIENT.md` §6.4)
- Require explicit user confirmation before sending via SMTP.
  (`CLIENT.md` §6.4)
- Not transmit SMTP credentials to the home server. (`CLIENT.md` §10.5)
- Not automatically send via SMTP without user awareness.
  (`CLIENT.md` §6.4)

### 5.8 Key Management (Client)

A conformant client MUST:

- Generate device, identity, and encryption key pairs locally.
  (`CLIENT.md` §2.2)
- Not transmit the identity private key over any network interface.
  (`CLIENT.md` §2.2, §10.1)
- Not log private key material. (`CLIENT.md` §10.1)
- Store private keys encrypted at rest, gated behind user authentication.
  (`KEY.md` §9.1)
- Sign block list sync messages with the originating device's key before
  transmission. (`CLIENT.md` §8.1)
- Obtain the user's explicit signed authorization before including decrypted
  `brief` or `enclosure` content in abuse reports. (`CLIENT.md` §8.2)
- Not automatically include decrypted content in any abuse report.
  (`CLIENT.md` §8.2)

### 5.9 Delegation

A conformant primary client that issues scoped device certificates MUST:

- Sign the certificate with its own device key. (`KEY.md` §10.3.1)
- Include all required scope fields: `send`, `receive`, `manage_keys`,
  `manage_blocks`, `manage_devices`. (`KEY.md` §10.3.3)
- Submit the certificate to the home server via the standard device
  registration flow. (`CLIENT.md` §2.3)

A conformant delegated client MUST:

- Accept `scope_exceeded` rejections gracefully and not retry submissions
  rejected for scope reasons without operator intervention.
  (`CLIENT.md` §2.5)
- Not attempt operations outside its certificate scope (registering devices,
  modifying block lists, managing keys) if the scope does not permit them.
  (`CLIENT.md` §2.5)

### 5.10 Message History Sync

A conformant client performing server-assisted message history sync MUST:

- Not transmit symmetric keys (`K_brief`, `K_enclosure`) to the server in
  plaintext during the sync process. The server receives only opaque wrapped
  key blobs. (`CLIENT.md` §4.4.2)
- Authenticate the sync: the new device MUST be registered through the
  standard device registration flow before sync begins.
  (`CLIENT.md` §4.4.2)
- Not initiate re-wrapping without explicit authorization from the existing
  device. (`CLIENT.md` §4.4.2)

### 5.11 Device Sync

A conformant client MUST:

- Recognize the `semp.dev/device-sync` marker in `brief.extensions` and
  treat any envelope carrying it as device sync traffic rather than
  correspondence. (`CLIENT.md` §4.5.2)
- Not surface a sync envelope as correspondence in a mailbox view or any
  equivalent user interface element intended for the user's incoming mail.
  (`CLIENT.md` §4.5.2)
- Place sync payloads in `enclosure.extensions` under a namespaced
  identifier specific to the sync kind. A client MUST NOT place sync
  payloads in the brief or in public-layer extensions. (`CLIENT.md` §4.5.3)
- Wrap `seal.enclosure_recipients` entries only for the target devices of
  the sync message. A client MUST NOT wrap the enclosure key for devices
  that are not intended recipients of the sync message. (`CLIENT.md` §4.5.1)

A conformant client MAY support individual sync extensions (new device
onboarding, historical mail rewrap, read-state synchronization, draft
synchronization, classification results, and similar). Lack of support for
a specific sync extension MUST NOT cause the device sync marker itself to
be rejected. (`CLIENT.md` §4.5.7)

### 5.12 Account Recovery

Account recovery is a RECOMMENDED optional core module specified in `RECOVERY.md`.
A client claiming recovery support MUST comply with `RECOVERY.md` section 10.1.

A server claiming recovery support MUST comply with `RECOVERY.md` section
10.2, and in particular:

- Advertise the `backup` endpoint in its discovery configuration.
  (`RECOVERY.md` §1.2, `DISCOVERY.md` §3.1.1)
- Verify bundle `signature` against the user's current identity key on
  upload. (`RECOVERY.md` §4.2)
- Serve bundle downloads without requiring an authenticated session and
  apply per-user and per-IP rate limits. (`RECOVERY.md` §4.3)
- Retain superseded bundles for at least 30 days. (`RECOVERY.md` §4.4)
- Expose `recovery_verify_pk` in the user's historical key record.
  (`RECOVERY.md` §7.5)
- Not decrypt or examine `encrypted_payload`. (`RECOVERY.md` §4.2, §8.3)
- Not possess, broker, or gate recovery secrets. (`RECOVERY.md` §1.1, §8.3)

A third-party domain choosing to honor successor records MUST verify all
three signatures (`recovery_signature`, `new_key_signature`,
`domain_signature`) and the timing constraint. (`RECOVERY.md` §7.5)
A third-party domain choosing not to honor successor records MUST treat
the new identity key as a fresh identity. (`RECOVERY.md` §7.6)

### 5.13 Provider Migration

Provider migration is a RECOMMENDED optional core module specified in
`MIGRATION.md`. A client claiming migration support MUST comply with
`MIGRATION.md` section 11.1. A server claiming cooperative migration
support MUST comply with section 11.2; a new provider MUST comply with
section 11.3; a third-party domain applying carry-over MUST comply with
section 11.4.

In particular:

- A cooperative old provider MUST NOT reassign a migrated local-part
  during the forwarding window. (`MIGRATION.md` §6.1)
- After the forwarding window ends and until the local-part is
  reassigned, a cooperative old provider MUST return `policy_forbidden`
  with a `migration_notice` body for envelopes addressed to the
  migrated address. (`MIGRATION.md` §5.3, `DELIVERY.md` §6.6)
- A cooperative old provider MUST revoke the old identity key with
  reason `"migrated_to"` on migration-record publication.
  (`MIGRATION.md` §8, `KEY.md` §8)
- Third-party domains applying known-correspondent, reputation, or
  block-list carry-over MUST bind the carry-over to the identity keys
  in the migration record, not to address strings. A sender envelope
  whose identity key does not match the migrated identity MUST NOT
  receive carried-over standing. (`MIGRATION.md` §6.3, §7)
- Third-party domains MUST NOT leak migration state through observable
  behavior that distinguishes migrated, reassigned, and never-used
  addresses. (`MIGRATION.md` §9.3, `DESIGN.md` §2.7)
- A client receiving an envelope with a changed identity key for a
  previously-known correspondent MUST apply key-change detection and
  MUST require explicit user confirmation before trusting the new
  key, regardless of whether the change is due to migration or
  reassignment. (`CLIENT.md` §3.3, `MIGRATION.md` §11.1)

### 5.14 Content Security

A conformant client MUST:

- Not transmit plaintext `enclosure` content to the home server for any
  purpose, including search indexing, notification previews, or draft
  storage. (`CLIENT.md` §10.2)
- Block remote resource loading from `enclosure` HTML content by default.
  Require explicit user permission before loading remote content.
  (`CLIENT.md` §10.3)
- Prevent execution of scripts or active content embedded in `enclosure`
  message bodies. (`CLIENT.md` §10.4)
- Not include `enclosure`-derived content in push notification payloads.
  (`CLIENT.md` §9)

---

## 6. Algorithm Suite Requirements

### 6.1 Mandatory Suites

All implementations (server and client) MUST support:

- `x25519-chacha20-poly1305`: baseline suite, required for interoperability.
  (`ENVELOPE.md` §7.3)
- `pq-kyber768-x25519`: hybrid post-quantum suite. RECOMMENDED.
  (`ENVELOPE.md` §7.3)

Each suite is an indivisible bundle specifying the key agreement, symmetric
cipher, MAC, KDF, and signing algorithm. Implementations negotiate suites,
not individual primitives. See `ENVELOPE.md` §7.3.1 for full suite
definitions.

### 6.2 Key Derivation

Implementations performing handshakes MUST:

- Use the KDF specified by the negotiated suite for session key derivation.
  Both currently defined suites specify HKDF-SHA-512 (RFC 5869).
  (`SESSION.md` §2.1, `ENVELOPE.md` §7.3.1)
- Use `client_nonce || server_nonce` as salt and `"SEMP-v1-session"` as
  info context. (`SESSION.md` §2.1)
- Derive five session keys with distinct HKDF Expand labels.
  (`SESSION.md` §2.1)
- Use the fixed concatenation order `K_kyber || K_x25519` for the hybrid
  input keying material. (`SESSION.md` §4.1)

### 6.3 Ephemeral Key Handling

Implementations MUST:

- Erase the ephemeral private key immediately after the shared secret is
  computed; overwrite with zeros or platform-equivalent secure erasure.
  (`SESSION.md` §2.2)
- Not write ephemeral private keys to disk, swap, or any persistent storage.
  (`SESSION.md` §2.2)
- Not log, cache, or retain ephemeral private keys for debugging.
  (`SESSION.md` §2.2)
- Treat ephemeral private keys as single-use values. If shared secret
  computation fails, erase the ephemeral private key and generate a new one
  for any retry. (`SESSION.md` §2.2)
- Not reuse client ephemeral keys across sessions. (`HANDSHAKE.md` §2.2)

### 6.4 Nonce Requirements

- Nonces MUST be cryptographically random, minimum 32 bytes.
  (`HANDSHAKE.md` §6.2)

### 6.5 Suite Negotiation

- Servers MUST NOT downgrade to a suite that lacks post-quantum components
  if both parties support one. (`SESSION.md` §4.3)
- Implementations MUST NOT negotiate suites below the minimum baseline.
  (`ENVELOPE.md` §7.3.2)
- A server that cannot support any mutually acceptable suite MUST reject
  the connection explicitly. (`ENVELOPE.md` §7.3.2)
- The negotiated suite MUST be recorded in `seal.algorithm`.
  (`ENVELOPE.md` §7.3.2)
- Implementations MUST NOT mix components from different suites within a
  single session. (`ENVELOPE.md` §7.3.3)

### 6.6 Fixed Protocol Primitives

The following primitives are fixed and not governed by the negotiated suite:

- **Confirmation hash**:  SHA-256. Computed before suite negotiation
  completes. (`HANDSHAKE.md` §2.5.3, `ENVELOPE.md` §7.3.4)
- **Challenge hash**:  SHA-256. Used by the proof of work challenge type.
  Occurs before session establishment. (`HANDSHAKE.md` §2.2a, `ENVELOPE.md` §7.3.4)

---

## 7. Security Requirements

### 7.1 Forward Secrecy

Implementations MUST ensure that compromise of any long-term key (domain,
identity, or encryption) cannot retroactively decrypt past sessions. This
is achieved through the ephemeral key exchange and key erasure requirements
defined in `SESSION.md` §1.1, §2.2, and §2.4.

### 7.2 Replay Prevention

- Servers MUST reject handshakes with previously seen nonces within the
  session TTL window. (`HANDSHAKE.md` §6.2)
- Servers MUST reject expired envelopes. (`ENVELOPE.md` §10.2)
- Servers MUST reject envelopes referencing retired sessions.
  (`SESSION.md` §5.2)

### 7.3 Constant-Time Operations

Implementations SHOULD use constant-time operations for all key comparisons
and MAC verifications to prevent timing side channels. (`SESSION.md` §5.6)

### 7.4 TLS Independence

TLS session resumption MUST NOT affect SEMP session validity. Each SEMP
session requires a fresh handshake regardless of TLS resumption state.
(`SESSION.md` §5.5)

---

## 8. Privacy Requirements

### 8.1 Identity Confidentiality

- Client identity MUST NOT appear in plaintext on the wire at any point.
  (`HANDSHAKE.md` §1.1, §6.1)
- The init message MUST be anonymous. (`HANDSHAKE.md` §2.2)
- Identity proofs MUST be encrypted under the session secret.
  (`HANDSHAKE.md` §6.1)

### 8.2 Metadata Protection

- The postmark MUST contain only domain-level routing information. Full
  sender and recipient addresses, timestamps, and threading metadata belong
  in the encrypted `brief`. (`ENVELOPE.md` §10.1)
- The subject MUST be in the `enclosure`, not the `brief`.
  (`DESIGN.md` §4.3)
- Push notification payloads MUST NOT include content derived from the
  `enclosure`. (`CLIENT.md` §9)
- Discovery requests MUST be anonymous by default. (`DISCOVERY.md` §1.2)

### 8.3 Block List Privacy

- Block lists are private. Servers MUST NOT disclose block list contents to
  any party other than the owning user's authenticated devices.
  (`DELIVERY.md` §8.1)
- Block lists MUST be stored encrypted at rest. (`DELIVERY.md` §7.3)
- Implementations MUST NOT expose block list size or contents through any
  observable interface. (`DELIVERY.md` §8.3)

### 8.4 Abuse Reporter Privacy

- The `reporter` field in abuse reports MUST NOT be included in published
  observation records or evidence. (`REPUTATION.md` §9.6)
- Decrypted envelope content MUST NOT be disclosed in abuse evidence without
  the explicit, signed authorization of the affected user.
  (`REPUTATION.md` §3.7)

---

## 9. Interoperability Requirements

### 9.1 Version Negotiation

- All handshake messages MUST include the `version` field.
  (`HANDSHAKE.md` §2.2)
- All SEMP message types MUST include a `version` field (semver).
- Implementations MUST ignore unknown fields rather than failing.
  (`DISCOVERY.md` §3.1, `ENVELOPE.md` §8.1)

### 9.2 Transport Support

Implementations MUST support HTTP/2 as the baseline transport for
interoperability as defined in `TRANSPORT.md` section 4. Implementations SHOULD
additionally support WebSocket and QUIC. Transport is negotiated during
discovery and declared in the handshake init. Minimum transport requirements,
transport profiles, fallback order, and extended transport bindings are defined
in `TRANSPORT.md`.
(`TRANSPORT.md` §2, §4, §5, `HANDSHAKE.md` §2.2, `DISCOVERY.md` §2.2)

### 9.3 Clock Synchronization

Implementations SHOULD reject messages with timestamps more than five minutes
from the current time. NTP or equivalent time synchronization is RECOMMENDED.
(`HANDSHAKE.md` §6.5)

### 9.4 Encoding

- All JSON MUST be UTF-8 encoded.
- Canonical serialization for seal computation requires lexicographically
  sorted keys and no insignificant whitespace. (`ENVELOPE.md` §4.3)
- Binary data (keys, nonces, signatures) MUST be base64-encoded in JSON
  fields unless otherwise specified. Hash values are hex-encoded where
  specified.

---

## 10. Conformance Checklist

The following table summarizes the major conformance areas by role. Each
area references the section of this document containing the detailed
requirements.

| Area                      | Server | Client | Section |
|---------------------------|--------|--------|---------|
| Envelope processing       | MUST   | --      | §4.1    |
| Handshake protocol        | MUST   | MUST   | §4.2, §5.3 |
| Session management        | MUST   | MUST   | §4.3, §5.5 |
| Discovery                 | MUST   | --      | §4.4    |
| Key management            | MUST   | MUST   | §4.5, §5.8 |
| Delivery and blocking     | MUST   | --      | §4.6    |
| Delivery state reporting  | --      | MUST   | §5.6    |
| Reputation                | SHOULD | --      | §4.7    |
| Legacy interoperability   | --      | SHOULD | §5.7    |
| Envelope composition      | --      | MUST   | §5.4    |
| Content security          | --      | MUST   | §5.12   |
| Device sync               | MUST   | MUST   | §4.12, §5.11 |
| Algorithm suites          | MUST   | MUST   | §6      |
| Forward secrecy           | MUST   | MUST   | §7.1    |
| Identity confidentiality  | MUST   | MUST   | §8.1    |
| Metadata protection       | MUST   | MUST   | §8.2    |
| Extensibility             | MUST   | MUST   | §4.9    |
| Scoped device certificates| MUST   | MUST   | §4.10, §5.9 |
| Recipient status          | MUST   | --      | §4.11   |
| Message history sync      | --      | MUST   | §5.10   |
| Transport                 | MUST   | MUST   | §9.2, `TRANSPORT.md` §10 |

---

## 11. Relationship to Other Specifications

| Specification  | Relationship                                                          |
|----------------|-----------------------------------------------------------------------|
| `DESIGN.md`    | Governing principles. All conformance requirements trace back to the design principles, particularly §2.1 (sealed envelope), §2.3 (explicit rejection), and §2.5 (extensibility). |
| `ENVELOPE.md`  | Envelope processing, seal verification, and canonicalization requirements originate here. |
| `HANDSHAKE.md` | Handshake protocol, capability negotiation, and session establishment requirements originate here. |
| `DISCOVERY.md` | Discovery flow, caching, and legacy fallback requirements originate here. |
| `KEY.md`       | Key publication, rotation, revocation, and storage requirements originate here. |
| `REPUTATION.md`| Trust gossip, abuse reporting, handshake challenges, and zero-reputation behavior requirements originate here. |
| `DELIVERY.md`  | Blocking, acknowledgment types, and delivery pipeline requirements originate here. |
| `CLIENT.md`    | Client-specific obligations for encryption, delivery state, and legacy interoperability originate here. |
| `SESSION.md`   | Forward secrecy, session key lifecycle, rekeying, and memory safety requirements originate here. |
| `TRANSPORT.md` | Transport requirements, core and extended bindings, negotiation, and fallback order originate here. |
| `ERRORS.md`    | Authoritative registry of all error codes, reason codes, and status values across the protocol. |
| `EXTENSIONS.md`| Extension framework, criticality signaling, size constraints, and anti-fragmentation governance. |
| `MIME.md`      | Media type registration and `.semp` file format. |

---

*This document is an Internet-Draft. It is subject to revision prior to
finalization as a stable specification.*