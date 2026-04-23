# SEMP Conformance Specification

**Sealed Envelope Messaging Protocol**
Status: Internet-Draft
Version: 0.2.0-draft
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
  `seal.signature` and `seal.session_mac` set to empty string, and both
  `postmark.hop_count` and `padding` omitted. (`ENVELOPE.md` §4.3)
- Use the defined envelope rejection reason codes. (`ENVELOPE.md` §9.3)
- Count the bytes of the top-level `padding` field toward
  `max_envelope_size` enforcement. A server MUST reject with
  `envelope_size_exceeded` if the received envelope, including padding,
  exceeds the session-negotiated `max_envelope_size`. (`ENVELOPE.md` §2.4)

A conformant server MUST NOT:

- Accept and silently discard an envelope. (`ENVELOPE.md` §9.1,
  `DESIGN.md` §2.3)
- Forward an envelope with an invalid seal. (`ENVELOPE.md` §9.1)
- Modify any signed field of the envelope. (`ENVELOPE.md` §9.1)
- Read, interpret, or validate the contents of the top-level `padding`
  field. (`ENVELOPE.md` §2.4)
- Strip or rewrite `padding` while forwarding an envelope between
  partition servers or during internal routing; padding bytes travel
  with the envelope through to the recipient server. (`ENVELOPE.md`
  §2.4)

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

A conformant server that supports session resumption MUST:

- Derive `K_resumption` from the handshake key schedule per
  `SESSION.md` §2.1 and retain it in a ticket that binds to the
  authenticated identity. (`SESSION.md` §2.1, §2.7)
- Issue resumption tickets with `expires_at` no later than 7 days from
  issuance. (`HANDSHAKE.md` §2.8.4, `SESSION.md` §2.7)
- Treat tickets as single-use: invalidate on successful resumption
  and issue a fresh ticket in the `accepted` response.
  (`HANDSHAKE.md` §2.8.4)
- Derive resumed session keys from the concatenation of the fresh
  ephemeral DH output and the resumption secret, with fresh nonces.
  (`HANDSHAKE.md` §2.8.3)
- Reject `resume` messages bearing tickets that are unknown, expired,
  corrupt, or already consumed with `reason_code: "resumption_failed"`.
  (`HANDSHAKE.md` §2.8.5)
- Reject application data included in a `resume` message with
  `reason_code: "resumption_failed"`. No 0-RTT data is permitted.
  (`HANDSHAKE.md` §2.8.6)
- Rotate the ticket-encryption key for stateless tickets at least
  quarterly. On rotation or key compromise, outstanding tickets MUST
  become unusable and return `resumption_failed`.
  (`SESSION.md` §2.7)

A server that does not support resumption MUST NOT issue resumption
tickets. (`SESSION.md` §2.7)

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
- Skip DNS lookups entirely for recipient domains ending in `.onion` and
  fetch the well-known URI over a Tor circuit to the onion service per
  `DISCOVERY.md` §2.5.2. MUST NOT emit a DNS query for a `.onion` name
  under any circumstances.
- Reject `.onion` addresses whose onion label is not a 56-character
  version-3 identifier (`DISCOVERY.md` §2.5.1).
- When Tor egress is unavailable, surface the delivery as
  `server_unavailable` rather than attempting clearnet fallback for a
  `.onion` recipient (`DISCOVERY.md` §2.5.2, `KEY.md` §6.4).
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
- Include a monotonically non-decreasing `revision` and a `ttl_seconds`
  field in every published configuration document. Increment `revision`
  on any byte-level change and never decrement or reuse a prior value.
  (`DISCOVERY.md` §3.5.1, §3.5.2)
- Re-fetch a cached peer configuration when `ttl_seconds` elapses,
  when a verified `SEMP_CONFIGURATION_UPDATE` with a greater revision
  arrives on a federation session, when a federation handshake surfaces
  a revision mismatch, or when an operation fails with a capability
  error attributable to stale configuration.
  (`DISCOVERY.md` §3.5.3)
- Not accept a fetched configuration whose `revision` is less than the
  revision already cached for that domain; treat such a response as
  suspicious. (`DISCOVERY.md` §3.5.1)
- Sign `SEMP_CONFIGURATION_UPDATE` notifications with the domain
  signing key. Verify the signature before acting on a received
  notification. (`DISCOVERY.md` §3.5.4)
- Defer new operations against a peer whose configuration re-fetch has
  failed until a successful re-fetch completes, for the duration of
  the grace window defined by `ttl_seconds`. (`DISCOVERY.md` §3.5.7)
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
- Fetch keys for `.onion` recipients over Tor only, per `KEY.md` §6.4.
  MUST NOT resolve or connect to any clearnet endpoint associated with a
  `.onion` domain for key retrieval.
- When operating as the home server of a `.onion`-hosted Tor-only
  deployment, publish domain and user keys exclusively at the onion
  well-known URI and MUST NOT publish keys at any clearnet endpoint
  (`DISCOVERY.md` §2.5.3).
- Reject device registrations without a valid authorization proof from an
  existing full-access device. (`KEY.md` §10.1, §10.2)
- Verify `SEMP_DEVICE` registration records: identity-key signature under
  the `SEMP-DEVICE-REGISTER:` prefix; authorizing-device signature under the
  `SEMP-DEVICE-AUTHORIZE:` prefix; `device_id` uniqueness in the current
  directory; `role` and `certificate_id` consistency; authorizing device
  currently registered as `full_access`. (`KEY.md` §10.1)
- Reject `endpoints.register` submissions for accounts that already have a
  device directory entry; subsequent devices MUST enroll via `KEY.md`
  §10.2. (`CLIENT.md` §2.2.b)
- On accepting a registration, append the new device to the device
  directory and publish a new monotonic revision per `KEY.md` §10.6.
- Verify `SEMP_DEVICE_REVOCATION` records: identity-key signature under
  the `SEMP-DEVICE-REVOCATION:` prefix; `revoked_by_device_id` currently
  registered with sufficient authority per `KEY.md` §10.5.3; first-accept
  policy for same `device_id`. On acceptance, invalidate sessions for the
  revoked device per `SESSION.md` §2.5 and publish a new device directory
  revision. (`KEY.md` §10.5)
- Retain device revocation records indefinitely, same rule as key
  revocations. (`KEY.md` §10.5, §8.3)
- When a revocation carries `reason: "key_compromise"`, refuse to
  publish the revocation unless accompanied by a successor record
  (`RECOVERY.md` §7) and a rotated identity-key publication in the same
  submission. A `key_compromise` revocation published without the
  rotation cascade is a specification violation and MUST be rejected
  with `reason_code: "policy_forbidden"`. (`KEY.md` §10.5.5)
- Serve the current `SEMP_DEVICE_DIRECTORY` at the account's key
  endpoint in response to `SEMP_KEYS` requests whose `key_types`
  includes `"device"`. MUST return the most recent revision; stale
  directories beyond the advertised TTL MUST NOT be served.
  (`KEY.md` §10.6.2)
- Never serve a device directory whose `revision` is less than a
  revision previously served for the same `user_id`. (`KEY.md` §10.6.2)

### 4.6 Delivery and Blocking

A conformant server MUST:

- Track the acknowledgment type of every delivery attempt and surface it to
  the sending user accurately. (`DELIVERY.md` §1.4)
- Not misrepresent acknowledgment types. If a `rejected` response is received,
  the user MUST be told delivery failed. (`DELIVERY.md` §1.4)
- Produce a signed delivery receipt on every `delivered` acknowledgment,
  covering the canonical envelope hash, the recipient domain, and the
  accepted-at time, signed under the `SEMP-DELIVERY-RECEIPT:` domain
  separation prefix. (`DELIVERY.md` §1.1.1, `ENVELOPE.md` §4.3)
- Verify the receipt's signature against the recipient domain's published
  signing key before treating an acknowledgment as terminal `delivered`.
  Treat a `delivered` acknowledgment without a verifiable receipt as a
  transport failure and retry it. (`DELIVERY.md` §1.1.1.6)
- Deliver the received receipt to the sending client via the delivery
  event notification in `CLIENT.md` §6.5. Hold the receipt only until at
  least one authenticated client device of the sending user has
  acknowledged the delivery event, then drop the server-side copy. Not
  retain a long-term server-side receipts archive. Multi-device
  propagation uses the encrypted device-sync mechanism in `CLIENT.md`
  §4.5. (`DELIVERY.md` §1.1.1.6)
- Not issue a delivery receipt for an envelope not accepted for delivery.
  (`DELIVERY.md` §1.1.1.5)
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
- Verify signatures on user policy sync messages before storing or
  propagating. Reject unsigned or unverifiable sync messages.
  (`DELIVERY.md` §7.2, §9.2)
- Store user policy state encrypted at rest; the server MUST NOT be able to read
  policy contents in plaintext. (`DELIVERY.md` §7.5)
- Not disclose user policy contents to any party other than the owning user's
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
- Publish count-valued observation metrics as power-of-two buckets per
  `REPUTATION.md` §4.5.1. Servers MUST NOT publish exact counts.
- Verify challenge solutions before proceeding with handshakes: confirm
  `challenge_id` matches an issued, unexpired challenge, recompute the hash,
  and confirm the required leading zero bits. (`HANDSHAKE.md` §2.2a.2)
- Treat each challenge as single use and reject duplicate submissions.
  (`HANDSHAKE.md` §2.2a.2)
- Not treat challenge completion as evidence of legitimacy.
  (`REPUTATION.md` §8.3.2)
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
  `REPUTATION.md` section 8.3.3, subject to the evidence and threshold
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
- Not deliver inbound envelopes to a delegated device whose
  `scope.receive` matcher rejects the sender address in `brief.from`.
  (`CLIENT.md` §2.4, `KEY.md` §10.3.4)
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

### 4.13 Retention Policy

A conformant server MUST apply per-artifact retention rules so that
operator data holdings are bounded to what the protocol requires for
correct operation. The rules below are the normative minimums and
maximums; operators MAY apply shorter retention where permitted and
MUST NOT exceed the maximums.

#### 4.13.1 Delivery Receipts

Delivery receipts at the sending server: SHOULD be dropped after the
sending client has acknowledged receipt of the delivery event
(`CLIENT.md` §6.5). MUST NOT be retained beyond 30 days after the
envelope's `postmark.expires` timestamp. (`DELIVERY.md` §1.1.1.6)

Delivery receipts at the recipient server: SHOULD NOT be retained
beyond what is needed to produce the acknowledgment response; the
recipient server is a conduit, not a custodian, for delivery outcomes.

#### 4.13.2 Abuse Evidence

Sealed abuse evidence (`REPUTATION.md` §3): MUST be retained at the
reporting server for at least 90 days, to support observation
publication and peer review. MAY be retained longer under operator
policy, subject to applicable privacy obligations. Evidence MUST be
deleted on request by the reporter.

#### 4.13.3 Session Tickets and Session State

Session tickets: MUST NOT have a lifetime exceeding 7 days from
issuance (`SESSION.md` §2.7). A server MUST delete ticket-encryption
key material for tickets issued under a rotated key at least
quarterly.

Active session state: held in memory only, MUST NOT be persisted
beyond the session's `expires_at` (`SESSION.md` §2.4).

Expired `session_id` log for replay prevention: MUST be retained for
at least one session TTL window (`SESSION.md` §5.2), MUST NOT exceed
30 days.

#### 4.13.4 Revocation Records

MUST be retained indefinitely (`KEY.md` §8.3). Revocation records
prevent key-substitution attacks and cannot be safely deleted.

#### 4.13.5 Backup Bundles (Server-Assisted Recovery)

Current bundle: retained as long as the account is active.

Superseded bundles: MUST be retained for at least 30 days after
supersession to support restore under an older recovery secret
(`RECOVERY.md` §4.4). MAY be retained longer under operator policy.

After account closure: retention follows `CLOSURE.md` §5.1 retention
window rules.

#### 4.13.6 Block Lists

User block lists are user-owned state. MUST be retained for as long
as the account is active. MUST be deleted at account finalization
unless the user has explicitly requested carry-over to a migrated
account per `MIGRATION.md` §7.4.

#### 4.13.7 Correspondent Graph Derivatives

Any data that encodes who corresponded with whom beyond the minimum
required for delivery (for example, search indexes, per-conversation
metadata caches, archived delivery-receipt summaries) is a
correspondent-graph derivative under `ENVELOPE.md` §10.6. Operators
SHOULD NOT create such derivatives; where operational requirements
(monitoring, abuse investigation) demand them, they MUST be retained
no longer than the minimum needed for that requirement and MUST be
surfaced in the operator's privacy documentation.

#### 4.13.8 Queued Envelopes

Envelopes in the sender-side delivery queue: persisted until a
terminal outcome per `DELIVERY.md` §2.1. MUST be deleted from the
queue at the earlier of: reaching a terminal outcome, or
`postmark.expires` plus one retention window. The retention window
for expired-but-queued envelopes SHOULD NOT exceed 24 hours to
accommodate operator diagnostics.

#### 4.13.9 First-Contact Challenge State

The `(challenge_id, prefix, postmark_id)` triple for issued
first-contact challenges MUST be retained at least until the
challenge's `expires` timestamp, to support single-use enforcement
(`HANDSHAKE.md` §2.2a.4). MAY be retained up to 24 hours past
`expires` for diagnostics. Consumed challenge IDs SHOULD be retained
for at least the challenge's original lifetime to prevent replay.

#### 4.13.10 Logs and Diagnostics

Server operational logs (access logs, error logs, rate-limit counters)
are out of scope for this specification. Operators MUST NOT log
decrypted `brief` or `enclosure` content under any circumstances and
MUST NOT log private key material, recovery secrets, or session
keys.

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
  (`REPUTATION.md` §8.3.3)

A conformant client that supports session resumption MUST:

- Store a received `resumption_ticket` alongside session state, treat
  its `value` as opaque, and use it on at most one subsequent reconnect.
  (`HANDSHAKE.md` §2.8, `SESSION.md` §2.7)
- Reject a resumption attempt locally if the ticket's `expires_at` is
  in the past per `CONFORMANCE.md` §9.3.1. Fall back to a full
  handshake. (`HANDSHAKE.md` §2.8.1)
- Not include envelope submissions or other session-bound application
  data in a `resume` message. (`HANDSHAKE.md` §2.8.6)
- On `reason_code: "resumption_failed"`, discard the consumed ticket
  and perform a full handshake. MUST NOT retry resumption with the
  same ticket. (`HANDSHAKE.md` §2.8.5)
- Derive resumed session keys from the concatenation of the ephemeral
  shared secret and the resumption secret, with the fresh nonces.
  (`HANDSHAKE.md` §2.8.3)
- Erase the old resumption ticket from memory and persistent storage
  immediately after a successful resume (the server has issued a
  fresh ticket). (`SESSION.md` §2.7)

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
- Pad the envelope's wire size to the smallest power-of-two bucket between
  1024 bytes and `max_envelope_size` per `ENVELOPE.md` §2.4. Populate the
  top-level `padding` field with fresh random bytes.
- Pad `seal.enclosure_recipients` to the smallest power-of-two entry count
  via dummy entries per `ENVELOPE.md` §4.4.1, and pad
  `seal.brief_recipients` consistently. Dummy entry fingerprints and
  ciphertext bytes MUST be drawn from a cryptographically secure random
  source and MUST be indistinguishable from real entries. The single-domain,
  non-group one-recipient exception MAY be applied per §4.4.1.

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
- Verify the signed delivery receipt accompanying a `delivered` event against
  the recipient domain's published signing key before treating the envelope
  as confirmed delivered. Treat a `delivered` event without a verifiable
  receipt as indeterminate and surface the anomaly. (`CLIENT.md` §6.5.1,
  `DELIVERY.md` §1.1.1)
- Retain verified receipts in local storage keyed by `envelope_id` and offer
  an export action that writes a receipt as a `.semp-receipt` file per
  `MIME.md` §6. (`CLIENT.md` §6.5.1)
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
  fallback when `legacy_required` is received. (`CLIENT.md` §6.4.1)
- Require explicit user confirmation before sending via SMTP.
  (`CLIENT.md` §6.4.1)
- Not transmit legacy mail credentials of any kind (SMTP Submission,
  IMAP, POP3, JMAP, or provider API) to the home server.
  (`CLIENT.md` §10.5)
- Not automatically send via SMTP without user awareness.
  (`CLIENT.md` §6.4.1)
- Produce MIME messages for SMTP fallback per `CLIENT.md` §6.4.2,
  with all listed headers at minimum. MUST NOT include postmark, seal,
  or encrypted brief/enclosure artifacts in the MIME message. MUST NOT
  emit `Bcc` headers; blind recipients are carried only via SMTP
  `RCPT TO`.
- Record a fresh RFC 5322 `Message-ID` for every SMTP send in the
  local legacy-threading map (`CLIENT.md` §6.4.4).
- Use the A-label form of IDN domains in SMTP envelope addresses
  (`CLIENT.md` §6.4.2).

A conformant client SHOULD:

- Include the SEMP upgrade-signal headers (`SEMP-Capability`,
  `SEMP-Identity`, `SEMP-Domain`, `SEMP-Address`) on outbound SMTP
  messages, unless the user has opted out for the sending identity.
  (`CLIENT.md` §6.4.3)
- Inspect upgrade-signal headers on inbound legacy messages and cache
  verified SEMP-capability hints after completing the four-step
  verification in `CLIENT.md` §4.3.1. MUST NOT treat the signal as
  authoritative without verification.
- Default to SEMP routing on replies to senders whose SEMP-capability
  is in the verified cache (`CLIENT.md` §4.3.2), while surfacing the
  routing choice to the user.

For mixed-recipient composes (some SEMP-reachable, some
`legacy_required`), a conformant client MUST:

- Split the send into a SEMP envelope for the SEMP-reachable group
  and an SMTP message for the legacy group (`CLIENT.md` §6.4.5).
- Surface the split to the user with the degradation warning attached
  to the SMTP group, and require explicit confirmation before
  transmission.
- Record both outbound artifacts under the same `thread_key` in the
  local threading map.
- Not silently downgrade SEMP-reachable recipients to SMTP.
- Not combine encrypted and plaintext renditions of the same content
  into a single MIME message.

For legacy-origin inbound messages, a conformant client MUST:

- Distinguish legacy messages from SEMP messages with a persistent,
  unambiguous origin indicator visible without additional user
  interaction. The indicator MUST distinguish at least three states:
  SEMP, legacy, and legacy-with-verified-SEMP-capable-sender.
  (`CLIENT.md` §4.3, §4.3.3)
- Not present legacy and SEMP messages in a unified inbox without
  such an indicator. (`CLIENT.md` §4.3)

### 5.8 Key Management (Client)

A conformant client MUST:

- Generate device, identity, and encryption key pairs locally.
  (`CLIENT.md` §2.2)
- Not transmit the identity private key over any network interface.
  (`CLIENT.md` §2.2, §10.1)
- Not log private key material. (`CLIENT.md` §10.1)
- Store private keys encrypted at rest, gated behind user authentication.
  (`KEY.md` §9.1)
- Sign user policy sync messages with the originating device's key before
  transmission. (`CLIENT.md` §8.1)
- Obtain the user's explicit signed authorization before including decrypted
  `brief` or `enclosure` content in abuse reports. (`CLIENT.md` §8.2)
- Not automatically include decrypted content in any abuse report.
  (`CLIENT.md` §8.2)

### 5.9 Delegation

A conformant primary client that issues scoped device certificates MUST:

- Sign the certificate with its own device key. (`KEY.md` §10.3.1)
- Include all five scope fields (`send`, `receive`, `blocklist`,
  `keys`, `devices`), each with its uniform object shape including a
  `rate_limits` array (possibly empty).
  (`KEY.md` §10.3.3)
- Use matcher mode `unrestricted`, `restricted`, `denylist`, or `none`
  for `send` and `receive`, with `allow` or `deny` populated as the
  mode requires. (`KEY.md` §10.3.3.1)
- Not mix `allow` and `deny` in a single matcher.
  (`KEY.md` §10.3.3.1)
- Use separate `read` and `write` boolean flags on `blocklist`,
  `keys`, and `devices`. (`KEY.md` §10.3.3.2)
- Populate `rate_limits` as an array of zero or more tiers, each with
  integer `period_seconds >= 1` and integer `amount_allowed >= 0`,
  with no more than 16 tiers per array. (`KEY.md` §10.3.3.3)
- Include `delivery_stage: integer >= 1` on the `receive` matcher
  and omit it from `send`. (`KEY.md` §10.3.3.1)
- Set `expires_at` within the range `issued_at < expires_at <= issued_at + 365 days`.
  (`KEY.md` §10.3.8)
- Submit the certificate to the home server via the standard device
  registration flow. (`CLIENT.md` §2.3)
- Issue revocation records using the `SEMP_DEVICE_CERTIFICATE_REVOCATION`
  schema with a defined reason code when terminating a delegation.
  (`KEY.md` §10.3.7)

A conformant delegated client MUST:

- Accept `scope_exceeded` rejections gracefully and not retry submissions
  rejected for scope reasons without operator intervention.
  (`CLIENT.md` §2.5)
- Not attempt operations outside its certificate scope (registering devices,
  modifying block lists, managing keys) if the scope does not permit them.
  (`CLIENT.md` §2.5)
- Not issue `SEMP_DEVICE_CERTIFICATE` records under any scope. Nested
  delegation is prohibited. (`KEY.md` §10.3.9)

A conformant home server MUST:

- Reject certificate registrations whose signature does not verify, whose
  issuer is not a registered full-access device of the account, or whose
  issuer is revoked. (`KEY.md` §10.3.5)
- Reject certificates with malformed or oversized scope (combined
  `allow` and `deny` exceeding 10,000 entries in any single matcher,
  or more than 16 rate-limit tiers in a single `rate_limits` array,
  or `period_seconds < 1` or `amount_allowed < 0` in any tier) with
  `reason_code: "scope_invalid"`.
  (`KEY.md` §10.3.3.1, §10.3.3.3, `ERRORS.md`)
- Reject certificates that mix `allow` and `deny` within a single
  matcher with `reason_code: "scope_invalid"`. (`KEY.md` §10.3.3.1)
- Reject certificates that omit `rate_limits` on any scope field with
  `reason_code: "scope_invalid"`. (`KEY.md` §10.3.3)
- Reject certificates whose `expires_at` exceeds `issued_at + 365 days`
  with `reason_code: "scope_invalid"`. (`KEY.md` §10.3.8)
- Apply the current certificate on every operation, not the certificate
  active at session establishment. (`KEY.md` §10.3.4)
- Evaluate the `receive` matcher against `brief.from` before delivering
  an inbound envelope to the delegated device's session, and not wrap
  session material to this device for envelopes the matcher rejects.
  (`KEY.md` §10.3.4)
- Honor the `scope.receive.delivery_stage` of each delegated device
  when fanning out inbound envelopes to the account, delivering in
  stage order and holding higher-stage devices in a staged-delivery
  queue pending disposition per `DELIVERY.md` §3.2.
- Treat full-access devices as implicitly positioned at
  `max(delegated_stages) + 1` for staged delivery. (`KEY.md` §10.3.3.1,
  `DELIVERY.md` §3.2.1)
- Aggregate dispositions received at a stage with the suppress-wins
  rule and fail-open to the next stage on timeout.
  (`DELIVERY.md` §3.2.3, §3.2.4)
- Re-evaluate staged-delivery partitions when a certificate is
  updated or revoked while an envelope is held. (`DELIVERY.md` §3.2.6)
- Recognize `kind: "delivery-disposition"` on brief-layer
  `semp.dev/device-sync` markers, verify the submitting session
  against the claimed `device_id`, and apply the disposition to the
  matching held envelope. Discard dispositions whose `source_envelope_id`
  does not match any held envelope for the account at the submitting
  device's stage or earlier. (`CLIENT.md` §4.5.7)
- For operations on `blocklist`, `keys`, or `devices`, dispatch on
  read vs write, reject with `reason_code: "scope_exceeded"` when the
  corresponding flag is `false`, and reject nested delegation attempts
  (an `issued_by` pointing at a delegated device) with
  `reason_code: "scope_invalid"`. (`KEY.md` §10.3.3.2, §10.3.4, §10.3.9)
- Evaluate every tier in every scope field's `rate_limits` array on
  each operation that passes the matcher or read/write check, reject
  with `reason_code: "rate_limited"` when any tier would be exceeded,
  and not record the operation against the counters.
  (`KEY.md` §10.3.3.3, §10.3.4)
- Expose current per-tier rate-limit counters to the owning account's
  authenticated clients. (`KEY.md` §10.3.3.3)
- Preserve the delegated device's active session across certificate
  update. Session invalidation is triggered only by device-key rotation
  or explicit revocation. (`KEY.md` §10.3.6)
- Terminate the delegated device's session immediately on acceptance of
  a revocation record and reject subsequent handshakes with
  `reason_code: "revoked"`. (`KEY.md` §10.3.7.3)
- Reject operations from a delegated device whose certificate has
  expired with `reason_code: "certificate_expired"`.
  (`KEY.md` §10.3.8, `ERRORS.md`)

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
be rejected. (`CLIENT.md` §4.5.8)

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

### 5.14 Account Closure

Account closure is a RECOMMENDED optional core module specified in
`CLOSURE.md`. A client claiming closure support MUST comply with
`CLOSURE.md` section 10.1. A server claiming closure support MUST
comply with section 10.2, in particular:

- Verify closure requests against a current full-access device key
  and reject requests signed by delegated devices with
  `reason_code: "scope_invalid"`. (`CLOSURE.md` §2.3, §10.2)
- Enforce `grace_period_seconds` bounds: min 7 days, max 90 days.
  (`CLOSURE.md` §3.1)
- Finalize at `requested_at + grace_period_seconds` and not before.
  (`CLOSURE.md` §4.1)
- Revoke keys with reason `superseded` on finalization, not a
  closure-specific reason. (`CLOSURE.md` §4.2, §9.1)
- Delete the recovery bundle at finalization. (`CLOSURE.md` §4.2, §7)
- Not publish a closure record, closure reason code, or
  closure-specific discovery artifact. (`CLOSURE.md` §4.3)
- Respond to ingress for a closed account during the retention
  window with `policy_forbidden` or `silent`, identical to the
  response given to non-existent addresses.
  (`CLOSURE.md` §5.1, `DELIVERY.md` §6.4)
- Not reassign the local-part before the retention window ends
  (RECOMMENDED 365 days, MINIMUM 180 days). Treat reassignment as
  a fresh registration with no inherited trust.
  (`CLOSURE.md` §6)

A conformant client MUST NOT describe a post-closure delivery
failure as account closure in the user interface, since the protocol
does not publish closure as an observable event.
(`CLOSURE.md` §10.1)

### 5.15 Large Attachments

The `semp.dev/large-attachment` wire extension is specified in
`ATTACHMENTS.md`. A client claiming support MUST comply with
`ATTACHMENTS.md` section 10.1, and in particular:

- Derive `K_attachment` from `K_enclosure` via HKDF-Expand with
  `info = "semp-attachment:" || attachment_id`. (`ATTACHMENTS.md` §3.1)
- Bind item metadata as AEAD additional-data on encryption and
  decryption. (`ATTACHMENTS.md` §3.2)
- Verify `ciphertext_hash` against fetched bytes before attempting
  AEAD decryption. (`ATTACHMENTS.md` §6, §7.2)
- Distinguish fetch failure, hash mismatch, decryption failure, and
  retention-elapsed states in the user-facing error surface.
  (`ATTACHMENTS.md` §7)
- Not use plain HTTP URLs for attachment storage. (`ATTACHMENTS.md` §4.1)
- Surface retention shortfall to the user before send when the chosen
  storage cannot meet the retention minimum.
  (`ATTACHMENTS.md` §4.2)

A server operator who hosts blob storage MUST advertise the
`attachment_storage` endpoint in discovery and MUST NOT decrypt, scan,
or inspect ciphertext content. (`ATTACHMENTS.md` §4.3, §10.2)

### 5.16 Key Transparency

Key transparency is a RECOMMENDED optional core module specified in
`TRANSPARENCY.md`. A server claiming support MUST comply with
`TRANSPARENCY.md` section 9.1, in particular:

- Maintain an append-only Merkle-tree log of every user identity and
  encryption key event. (`TRANSPARENCY.md` §2)
- Publish a fresh signed tree head at least hourly, signed by the
  domain signing key. (`TRANSPARENCY.md` §2.3)
- Serve the `transparency_log` endpoint with inclusion proofs,
  consistency proofs, STHs, and leaf ranges.
  (`TRANSPARENCY.md` §2.4, `DISCOVERY.md` §3.1.1)
- Augment every `SEMP_KEYS` response with per-key `transparency`
  containing an inclusion proof and a current STH.
  (`TRANSPARENCY.md` §4.1)
- Never remove or modify a leaf and never sign two STHs with the
  same `log_size` and different `root_hash`. (`TRANSPARENCY.md` §9.1)
- Continue serving the log for at least 2 years after withdrawing
  transparency support. (`TRANSPARENCY.md` §2.5)

A client that accepts keys from transparency-supporting domains MUST:

- Verify the STH signature and freshness (within 1 hour per
  `CONFORMANCE.md` §9.3.1) before accepting any key.
  (`TRANSPARENCY.md` §4.2, §4.3)
- Verify the inclusion proof against the STH and confirm the proven
  leaf matches the returned key. (`TRANSPARENCY.md` §4.2)
- Refuse to use a key whose transparency verification fails, and
  surface the failure to the user as a security warning.
  (`TRANSPARENCY.md` §4.2, §9.2)
- Verify every STH signature in consumed `key_transparency`
  observations. For `verification` observations, re-verify the
  contained consistency proof. For `equivocation` observations,
  verify that both STHs are signed by the subject domain and have
  the same `log_size` with different `root_hash`.
  (`TRANSPARENCY.md` §5.3, §9.2)
- Treat a verified `equivocation` observation, or a client-observed
  inconsistency between its own key-fetch STH and gossiped STHs,
  as strong evidence that the subject domain is misbehaving.
  (`TRANSPARENCY.md` §5.3)

### 5.17 Content Security

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

#### 9.1.1 Version Format

SEMP protocol versions follow semantic versioning: `MAJOR.MINOR.PATCH`.
The current version is `1.0.0`. Every SEMP message type MUST carry a
`version` field in this format.

- **MAJOR** is incremented on any wire-incompatible change: a new
  message structure, a removed field, a changed field semantics, a
  new mandatory-to-implement cryptographic primitive, or any other
  change that prevents an older implementation from correctly
  processing the new message.
- **MINOR** is incremented on backward-compatible additions: new
  optional fields, new message types whose absence is acceptable,
  new optional extensions added to the registry, clarifications that
  tighten previously ambiguous behavior without changing conforming
  implementations.
- **PATCH** is incremented for editorial clarifications and typo
  fixes only. A PATCH bump MUST NOT change any conforming
  implementation's behavior.

#### 9.1.2 Supported Version Declaration

Every implementation MUST declare the MAJOR version it speaks in:

- Its DNS TXT record (`v=semp1` for MAJOR 1 per `DISCOVERY.md` §2.2).
- Its configuration document (`version` field per `DISCOVERY.md`
  §3.1).
- Every handshake message it sends (`version` field per
  `HANDSHAKE.md` §2.2).

An implementation MAY declare support for more than one MAJOR by
publishing one configuration document per supported MAJOR under
distinct DNS TXT records.

#### 9.1.3 Cross-Major Interoperability

Different MAJOR versions are not wire-interoperable. Implementations
encountering a peer whose declared MAJOR does not match any MAJOR they
support MUST:

- At discovery: treat the domain as non-SEMP for this MAJOR and fall
  back per `CLIENT.md` section 6.4 or abandon the delivery per
  operator policy.
- At handshake: reject the `init` with
  `reason_code: "version_unsupported"`. The rejecting side MAY
  include the list of MAJOR versions it does support in the response
  `reason` string (advisory, not machine-parseable).

An implementation MUST NOT attempt to negotiate down to a lower MAJOR
than it supports. Cross-MAJOR federation is achieved by operators who
run gateways deliberately, outside the scope of this specification.

#### 9.1.4 Within-Major Interoperability

Implementations on the same MAJOR MUST interoperate regardless of
MINOR or PATCH differences. Specifically:

- Unknown fields MUST be ignored, not rejected (`DISCOVERY.md` §3.1,
  `ENVELOPE.md` §8.1).
- Unknown optional message types MUST be rejected with
  `extension_unsupported` if the sender marked them critical, and
  silently dropped otherwise.
- New extensions introduced in a later MINOR are advertised per
  `EXTENSIONS.md` and negotiated at handshake capability exchange.

#### 9.1.5 Deprecation and Sunset

MINOR versions are not deprecated: older MINOR implementations
continue to interoperate indefinitely within the same MAJOR, subject
to the normal extension-advertisement negotiation. Individual
extensions MAY be deprecated per `EXTENSIONS.md` section 7.

A MAJOR version is sunset when a successor MAJOR has been
widely deployed. The specification revision that introduces MAJOR N+1
SHOULD state the recommended end-of-support date for MAJOR N, giving
operators at least 24 months to migrate. The protocol does not
mandate a specific end-of-support date; that decision is deferred to
the spec revision that defines the successor.

#### 9.1.6 Legacy Requirements

- All handshake messages MUST include the `version` field
  (`HANDSHAKE.md` §2.2).
- All SEMP message types MUST include a `version` field (semver).
- Implementations MUST ignore unknown fields rather than failing
  (`DISCOVERY.md` §3.1, `ENVELOPE.md` §8.1).

### 9.2 Transport Support

Implementations MUST support HTTP/2 as the baseline transport for
interoperability as defined in `TRANSPORT.md` section 4. Implementations SHOULD
additionally support WebSocket and QUIC. Transport is negotiated during
discovery and declared in the handshake init. Minimum transport requirements,
transport profiles, fallback order, and extended transport bindings are defined
in `TRANSPORT.md`.
(`TRANSPORT.md` §2, §4, §5, `HANDSHAKE.md` §2.2, `DISCOVERY.md` §2.2)

### 9.3 Clock Synchronization

SEMP relies on timestamp-bearing fields throughout the protocol:
`postmark.expires`, handshake challenge `expires`, session `expires_at`,
block list and status sync `timestamp`, queue state records, backup
bundle `created_at`, migration `migrated_at`, forwarder attestations,
and delegated certificate lifetimes. Every implementation MUST enforce
a consistent clock tolerance for every such field.

#### 9.3.1 Tolerance

Let `now` be the implementation's current wall-clock UTC time and let
`T` be a timestamp value being validated.

**Future-dated timestamps** (`T > now`, meaning the record claims to
have been produced after the current time):

- Implementations MUST reject the record if `T - now > 15 minutes`.
- Implementations SHOULD reject the record if `T - now > 5 minutes`.
- Records with `T - now` in the range 0 to 5 minutes MUST be accepted.

**Expired timestamps** (`expires_at` fields, where validity ends at
`T`):

- Implementations MUST reject as expired when `now > T + 15 minutes`.
- Implementations SHOULD reject as expired at `now > T`.
- Implementations MAY apply up to 5 minutes of grace
  (`T < now <= T + 5 minutes`) for a more forgiving profile.

Senders MUST NOT rely on grace windows. Senders MUST set `expires_at`
values with at least 15 minutes of headroom beyond the worst-case
expected delivery delay for the record, so that receivers applying
zero grace continue to accept on-time records.

#### 9.3.2 Time Source

Implementations MUST maintain clocks within the tolerance bounds in
section 9.3.1. Network Time Protocol (RFC 5905), Precision Time
Protocol (IEEE 1588), or a provider-supplied equivalent is RECOMMENDED.

SEMP does not mandate a specific time-synchronization mechanism.
Implementations that drift beyond the tolerance will produce visible
rejection errors, which is the operational signal to fix the clock.
No separate conformance check on the mechanism is required.

#### 9.3.3 Clock Authority

When a record carries a timestamp produced by a specific party:

- **Sender-produced timestamps** (for example, `postmark.expires` set
  by the sending client, enclosure-layer timestamps set by the sender
  client): the sender's clock is authoritative at the moment of
  composition. The receiver validates against its own clock applying
  the tolerance in section 9.3.1.
- **Server-produced timestamps** (for example, handshake challenge
  `expires`, session `expires_at`, delivery acknowledgment
  `timestamp`, queue state `last_attempt_at`, `next_attempt_at`,
  `deadline`): the server's clock is authoritative at the moment of
  production. Peers validating these timestamps apply the same
  tolerance.

When two parties disagree on a timestamp, the producing party's clock
prevails provided the receiver accepts under section 9.3.1. A record
whose producer-claimed timestamp falls outside the receiver's
tolerance MUST be rejected even if other cryptographic checks pass.

#### 9.3.4 Monotonic Clock for Internal TTL

Servers SHOULD track internal session TTLs (handshake session lifetime,
queue retry scheduling, rate-limit throttling windows) against a
monotonic clock rather than the wall clock. This avoids spurious
expiry or prolongation when the wall clock is adjusted by NTP.

Cross-party timestamps (timestamps written into records exchanged with
other parties or other servers) MUST continue to use wall clock
values in UTC per ISO 8601, since monotonic clock values are not
comparable across processes.

#### 9.3.5 Fail-Closed on Undetectable Clock State

If an implementation cannot determine its own clock state with
confidence (for example, NTP is unreachable at boot and no other
time source is available, or the hardware clock is detected as
stopped or faulty), it MUST NOT process operations that require
timestamp validation. Specifically:

- A server MUST NOT accept new handshakes.
- A server MUST NOT accept envelope submissions.
- A server MUST NOT issue acknowledgments with timestamp fields.
- A server SHOULD surface the clock-state error to operators through
  its operational alerting channel.

Silent proceeding on an unknown clock state expands replay windows,
makes expiry checks vacuous, and is incompatible with the fail-closed
posture required elsewhere in this specification.

A client that cannot determine its own clock state SHOULD surface the
error to the user rather than compose envelopes with uncertain
timestamps. Clients MAY proceed in a degraded mode that refuses to
set `postmark.expires` shorter than operator defaults.

#### 9.3.6 Scope

The tolerance rules in this section apply uniformly to every
timestamp validation in the protocol, including but not limited to:

- `postmark.expires` in `ENVELOPE.md`.
- `expires` in handshake challenges (`HANDSHAKE.md` section 2.2a).
- `expires_at` in session records (`SESSION.md` section 2).
- `timestamp` in user policy sync messages (`DELIVERY.md` section 7).
- Queue state timestamps (`DELIVERY.md` section 2.5).
- `created_at` and `expires` in user and domain key records
  (`KEY.md`).
- `issued_at` and `expires_at` in scoped device certificates
  (`KEY.md` section 10.3).
- `created_at` and `supersedes` relations in recovery bundles
  (`RECOVERY.md`).
- `migrated_at` and `forwarding_window_until` in migration records
  (`MIGRATION.md`).
- `received_at` in forwarder attestations (`ENVELOPE.md` section 6.6).

Any specification introducing a new timestamp field inherits the
tolerance rules defined here unless the new specification explicitly
tightens or loosens them with a documented rationale.

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