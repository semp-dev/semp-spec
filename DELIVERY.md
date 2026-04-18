# SEMP Delivery Specification

**Sealed Envelope Messaging Protocol**  
Status: Internet-Draft  
Version: 0.1.0  
Related: `DESIGN.md`, `HANDSHAKE.md`, `ENVELOPE.md`

---

## Abstract

The SEMP delivery specification defines the three acknowledgment types a
recipient server may return for any envelope delivery attempt, the obligations
of the sending server in tracking and surfacing delivery outcomes, queuing and
retry behavior for non-terminal outcomes, the block list structure and
enforcement, and multi-device block list synchronization.

---

## 1. Acknowledgment Types

Every envelope delivery attempt produces exactly one of three acknowledgment
types. These are protocol-level outcomes, observable on the wire between
servers.

| Acknowledgment | Description                                                                 |
|----------------|-----------------------------------------------------------------------------|
| `delivered`    | The recipient server accepted the envelope and has committed to making it available to the recipient client.|
| `rejected`     | The recipient server explicitly refused the envelope with a reason code.    |
| `silent`       | The recipient server did not respond within the sender's timeout window.    |

These are the only outcomes the protocol models. What the recipient server or
client does internally with an accepted envelope (deliver to inbox, filter to
a folder, suppress notifications, hold for review) is an application concern.
The protocol does not observe or regulate internal inbox management.

### 1.1 Delivered

The recipient server returns an explicit acceptance. The envelope has been
received and will be delivered to the recipient client. The sending server
marks the delivery as confirmed and informs the sending user.

A server MUST NOT return `delivered` for an envelope it does not intend to
deliver to the recipient. Returning a false acknowledgment of delivery is
prohibited.

### 1.2 Rejected

The recipient server returns an explicit rejection with a reason code. The
sending server marks the delivery as failed, records the reason, and informs
the sending user. The sending server MUST determine from the reason code whether
the failure is recoverable before deciding whether to retry.

Rejected is the RECOMMENDED default acknowledgment for any envelope the server
will not deliver. Explicit rejection is consistent with DESIGN.md principle
2.3. It allows sending servers to handle failures correctly and inform their
users accurately.

### 1.3 Silent

The recipient server does not respond. After a timeout window the sending server
marks the delivery as unacknowledged and informs the sending user.

Silent is a permitted acknowledgment type for deliberate operator or user
policy reasons, typically privacy or anti-harassment situations where revealing
that a delivery was refused would itself be harmful. It is not the recommended
default.

Silence and network failure are indistinguishable to the sending server. A
sender cannot determine whether silence means blocking, the recipient is
offline, or the message was lost in transit.

A server operating in silent mode MUST still explicitly reject envelopes with
invalid seals. Silent mode applies only to envelopes that pass all verification
checks. An invalid envelope MUST always be rejected explicitly regardless of
delivery policy.

### 1.4 Sending Server Obligations

The sending server MUST track the acknowledgment type of every delivery attempt
and surface it to the sending user. The three states map directly:

| Acknowledgment | What the sending user sees                                      |
|----------------|-----------------------------------------------------------------|
| `delivered`    | Delivery confirmed.                                             |
| `rejected`     | Delivery rejected. Reason available.                            |
| `silent`       | Delivery unacknowledged. No response received within timeout.   |

The sending server MUST NOT misrepresent the acknowledgment type to its user.
If a `rejected` response is received, the user MUST be told delivery failed,
not that it succeeded or is pending.

### 1.5 Timeout

The sending server MUST enforce a timeout on each individual delivery attempt.
After the timeout elapses with no response, the attempt is classified as
`silent`. A timeout of 30 seconds is RECOMMENDED for an individual attempt.
Retry scheduling and overall deadlines are defined in section 2.

### 1.6 Recipient Status

When the acknowledgment type is `delivered`, the recipient server MAY include
a `recipient_status` object in the acknowledgment response. This provides the
sender with information about the recipient's current availability without
requiring a separate message exchange.

#### 1.6.1 Recipient Status Schema

```json
{
    "acknowledgment": "delivered",
    "recipient_status": {
        "state": "away",
        "message": "On leave until July. Responses will be delayed.",
        "until": "2025-07-01T00:00:00Z"
    }
}
```

#### 1.6.2 Recipient Status Fields

| Field     | Type           | Required | Description                                              |
|-----------|----------------|----------|----------------------------------------------------------|
| `state`   | `string`       | Yes      | One of: `available`, `away`, `do_not_disturb`.           |
| `message` | `string\|null` | No       | Freetext status message set by the recipient. Maximum 256 UTF-8 bytes. |
| `until`   | `string\|null` | No       | ISO 8601 UTC timestamp indicating when the state is expected to change. |

#### 1.6.3 State Values

| State             | Meaning                                                                    |
|-------------------|----------------------------------------------------------------------------|
| `available`       | Recipient is active. No special status. Servers SHOULD omit `recipient_status` entirely rather than sending `available` with no message. |
| `away`            | Recipient is temporarily unavailable. Delivery proceeds normally but the sender is informed of reduced responsiveness. |
| `do_not_disturb`  | Recipient has requested minimal interruption. Delivery proceeds normally. The sender's client MAY suppress follow-up notifications or adjust display accordingly. |

All three states result in normal delivery. Status does not affect whether
an envelope is accepted; it is informational only. A server MUST NOT reject
or delay envelopes based on recipient status.

#### 1.6.4 Status Visibility Rules

Recipient status is opt-in. Servers MUST NOT include `recipient_status` in
acknowledgments unless the recipient has explicitly enabled it. The default
is no status disclosure.

Recipients control who sees their status through visibility rules. The server
evaluates visibility rules against the sender's identity after decrypting
`brief.from`.

| Visibility       | Description                                                              |
|-------------------|--------------------------------------------------------------------------|
| `everyone`        | Status is included in acknowledgments to all senders.                    |
| `domains`         | Status is included only for senders from specified domains.              |
| `servers`         | Status is included only for senders whose envelopes were routed through specified servers. |
| `users`           | Status is included only for specified sender addresses.                  |
| `nobody`          | Status is never included. Equivalent to disabling the feature. This is the default. |

When multiple visibility rules are configured, they are evaluated as a union:
if any rule matches the sender, the status is included.

#### 1.6.5 Status Configuration Schema

```json
{
    "type": "SEMP_STATUS",
    "version": "1.0.0",
    "user_id": "recipient@example.com",
    "state": "away",
    "message": "On leave until July. Responses will be delayed.",
    "until": "2025-07-01T00:00:00Z",
    "visibility": {
        "mode": "users",
        "allow": [
            { "type": "domain", "domain": "work.example.com" },
            { "type": "user", "address": "friend@personal.example" }
        ]
    },
    "updated_at": "2025-06-15T10:00:00Z",
    "device_id": "originating-device-ulid"
}
```

Status updates are transmitted from the client to the home server as signed
messages, following the same authentication model as block list sync messages
(section 7). The server stores the current status and applies visibility rules
at delivery time.

#### 1.6.6 Relationship to Autoresponders

Recipient status replaces the need for autoresponder messages in most use cases.
Traditional email autoresponders (out-of-office replies) are full message round
trips that exist solely to convey availability information. SEMP achieves the
same result by attaching a status field to the delivery acknowledgment the
server was already generating.

This eliminates the pathologies of autoresponders: no loop risk (status is a
field on an acknowledgment, not a message), no mailing list pollution (the
acknowledgment is sent only to the sender's server), and no address
confirmation to unwanted senders (the acknowledgment already exists regardless
of status).

For use cases that require a richer automated response, a client process
running on a dedicated device can hold the user's keys and respond to incoming
envelopes directly. This is an explicit trust delegation by the user, not a
default server behavior.

---

## 2. Queuing, Retry, and Expiry

Section 1 defines the result of a single delivery attempt. This section
defines sender-side behavior when a single attempt does not yield a terminal
outcome: how the sending server queues the envelope, when and how it retries,
when it gives up, and how the sending client observes progress.

### 2.1 Sender-Side Queue

The sending server MUST maintain a delivery queue for envelopes submitted by
its own clients. An envelope enters the queue upon successful submission and
leaves the queue when it reaches a terminal outcome: `delivered`, `rejected`,
or `expired` (section 2.4).

A queued envelope is the sending server's responsibility until a terminal
outcome is reached. The sending server MUST persist queued envelopes such that
a restart does not drop them. The sending server MUST NOT mutate the envelope's
`seal` or `postmark` between attempts. In particular, `postmark.expires` MUST
NOT be rewritten to extend delivery.

### 2.2 When to Retry

The sending server MUST classify each per-attempt outcome as terminal or
non-terminal before scheduling further action.

| Per-attempt outcome                  | Classification | Next action              |
|--------------------------------------|----------------|--------------------------|
| `delivered`                          | Terminal       | Remove from queue.       |
| `rejected`, non-recoverable reason   | Terminal       | Remove from queue.       |
| `rejected`, recoverable reason       | Non-terminal   | Schedule retry (2.3).    |
| `silent`                             | Non-terminal   | Schedule retry (2.3).    |
| Transport failure before any ack     | Non-terminal   | Schedule retry (2.3).    |

Recoverability is determined from the reason code returned with a `rejected`
acknowledgment. The following reason codes from `ENVELOPE.md` section 9.3
and `HANDSHAKE.md` section 4.1 are treated as recoverable for retry purposes:

- `handshake_invalid`
- `handshake_expired`
- `no_session`
- `server_unavailable`
- `rate_limited`
- `quota_exceeded`

All other reason codes, including `blocked`, `seal_invalid`,
`session_mac_invalid`, `envelope_expired`, and `policy_forbidden`, MUST be
treated as non-recoverable. The sending server MUST NOT retry envelopes that
have received a non-recoverable rejection.

The protocol does not define a per-address existence reason code (such as
`no_such_user`). A non-existent recipient address MUST be answered with the
same generic `policy_forbidden` rejection as any other policy refusal, in
conformance with the existence indistinguishability requirement defined in
`DESIGN.md` section 2.7 and enforced in section 6.4 of this document.

A `silent` outcome MUST be treated as non-terminal and subject to the retry
schedule. The sending server cannot distinguish silence caused by transient
transport failure from silence caused by a deliberate recipient policy
(section 1.3), and MUST NOT assume one over the other.

An unrecognized reason code MUST be treated as non-recoverable. An
implementation that receives a code it does not classify MUST NOT silently
retry.

### 2.3 Retry Schedule

For non-terminal outcomes, the sending server MUST schedule a subsequent
attempt subject to the following bounds:

- The sending server MUST make at least five retry attempts before declaring
  terminal failure by deadline, provided the effective deadline (section 2.4)
  permits.
- The sending server MUST use an exponential backoff with a minimum initial
  delay of 60 seconds and a minimum multiplier of 2 between consecutive
  intervals.
- The sending server MUST cap individual inter-attempt intervals at 6 hours.
- The sending server MUST apply jitter of at least plus or minus 10 percent to
  each scheduled interval.

The following schedule is RECOMMENDED as a default, subject to jitter:
1 minute, 5 minutes, 15 minutes, 1 hour, 4 hours, then every 4 hours until the
effective deadline.

Operators MAY use a different schedule provided the bounds above are met.

A retry attempt MUST NOT reuse a federation session that has been invalidated
or has passed its TTL. If the cached federation session is no longer valid,
the sending server MUST perform a fresh handshake before the retry attempt, as
defined in `HANDSHAKE.md` and `SESSION.md`.

On receipt of a `rejected` acknowledgment with reason code `handshake_invalid`,
`handshake_expired`, or `no_session`, the sending server MUST invalidate its
cached federation session with the recipient's server before the next attempt.

### 2.4 Effective Delivery Deadline

Every queued envelope has an effective delivery deadline. The effective
deadline is the earlier of:

- `postmark.expires`, as set by the sending client (`ENVELOPE.md` section 3).
- `queued_at + server_max_retry_horizon`, where `server_max_retry_horizon` is
  an operator-configured value.

The `server_max_retry_horizon` SHOULD default to 72 hours and MUST NOT exceed
7 days. The sending server MUST NOT retry an envelope past its effective
deadline.

When the effective deadline is reached with no terminal outcome, the sending
server MUST transition the envelope to the terminal state `expired` and remove
it from the queue. `expired` is a sender-side terminal state only; it is never
returned by a recipient server as an acknowledgment type. The `envelope_expired`
reason code defined in `ENVELOPE.md` section 9.3 is distinct: it is a recipient
server's rejection of an envelope whose `postmark.expires` is in the past.

The sending client MAY set `postmark.expires` shorter than the server's
horizon for time-sensitive envelopes. The sending client MUST NOT rely on the
server to extend delivery beyond `postmark.expires`.

### 2.5 Sending Client Visibility

While an envelope is queued, the sending server MUST maintain a queue state
record for it. The record reflects aggregate progress and is authoritative for
what the sending client displays to the user.

```json
{
    "envelope_id": "postmark-ulid",
    "recipient": "user@example.com",
    "state": "queued",
    "attempts": 3,
    "last_attempt_at": "2026-04-18T12:00:00Z",
    "last_outcome": "silent",
    "last_reason_code": null,
    "next_attempt_at": "2026-04-18T13:00:00Z",
    "deadline": "2026-04-21T10:00:00Z"
}
```

| Field              | Type           | Required | Description                                                      |
|--------------------|----------------|----------|------------------------------------------------------------------|
| `envelope_id`      | `string`       | Yes      | The `postmark.id` of the queued envelope.                        |
| `recipient`        | `string`       | Yes      | The recipient address this record applies to.                    |
| `state`            | `string`       | Yes      | One of: `queued`, `delivered`, `rejected`, `expired`, `canceled`.|
| `attempts`         | `integer`      | Yes      | Count of delivery attempts made so far.                          |
| `last_attempt_at`  | `string\|null` | Yes      | Timestamp of most recent attempt, or `null` if none.             |
| `last_outcome`     | `string\|null` | Yes      | Per-attempt acknowledgment of most recent attempt, or `null`.    |
| `last_reason_code` | `string\|null` | Yes      | Reason code from the most recent `rejected` attempt, or `null`.  |
| `next_attempt_at`  | `string\|null` | Yes      | Timestamp of the next scheduled attempt, or `null` if terminal.  |
| `deadline`         | `string`       | Yes      | Effective delivery deadline per section 2.4.                     |

The sending server MUST update the queue state record at each attempt. The
sending server MUST NOT emit a per-attempt push notification to the client for
every attempt. On transition to a terminal state, the sending server MUST emit
a delivery event notification as defined in `CLIENT.md` section 6.5.

The sending server MUST retain the terminal queue state record for at least
24 hours after termination, so that a client reconnecting after transient
offline periods can observe the terminal outcome.

Clients MAY poll the queue state record for pending envelopes. The transport
and endpoint for this query are defined in `CLIENT.md`.

### 2.6 Terminal Outcomes and Failure Notification

When an envelope reaches a terminal outcome, the sending server MUST record
the outcome in the queue state (section 2.5). The terminal states are:

| Terminal state | Source                                                                 |
|----------------|------------------------------------------------------------------------|
| `delivered`    | Explicit `delivered` acknowledgment from the recipient server.         |
| `rejected`     | Explicit `rejected` acknowledgment from the recipient server.          |
| `expired`      | Effective delivery deadline reached without a terminal acknowledgment. |
| `canceled`     | Client-initiated cancellation accepted before a terminal acknowledgment (section 2.7). |

The sending client is the authoritative audience for terminal failure. The
sending server MUST surface `last_outcome` and `last_reason_code` to the
sending client for `rejected` and `expired` terminal states. The sending
server MUST NOT fabricate a reason code it did not receive from the recipient
server.

The sending server MUST NOT generate a synthetic bounce envelope addressed to
the sending user or to any third party, and MUST NOT transmit any message
across federation in response to a terminal delivery failure. Failure
notification remains within the sender's home server and its authenticated
clients.

Synthetic bounces addressed to a claimed sender are a documented source of
backscatter abuse in prior message protocols and are incompatible with SEMP's
seal-based provenance model. An envelope received by a recipient server that
claims to be a bounce carries no seal proving it originated from a genuine
prior send by that recipient.

### 2.7 Client-Initiated Cancellation

A sending client MAY request cancellation of a queued envelope before it
reaches a terminal state. Cancellation halts retry scheduling and transitions
the queue state record (section 2.5) to the terminal state `canceled`.

Cancellation is the only sender-initiated mechanism for removing a queued
envelope from the queue before its effective deadline. It does not recall an
envelope that has already been delivered to a recipient server.

#### 2.7.1 Cancellation Request

The sending client issues a cancellation request to its home server. The
message schema and transport binding are defined in `CLIENT.md` section 6.6.
A cancellation request identifies the target envelope by `envelope_id` and
either a specific `recipient` (per-recipient cancel) or no recipient
(whole-envelope cancel, applying to every queue state record still in a
non-terminal state for that `envelope_id`).

#### 2.7.2 Server Handling

On receipt of a cancellation request, the sending server MUST:

1. Verify that the request is authenticated on a session belonging to the
   sending user account of the target envelope. Cancellation requests from
   other accounts MUST be rejected.
2. Verify that the requesting client has authority over the target envelope.
   A full-access device MAY cancel any envelope submitted by any client of
   the same account. A delegated client MAY cancel only envelopes it
   submitted itself, as enforced by device identifier on the original
   submission. Delegated-client scope enforcement follows `CLIENT.md`
   section 2.4.
3. For each affected queue state record, attempt to transition to
   `canceled`:
   - If the record is already in a terminal state, the cancellation MUST be
     treated as a no-op for that record. The server MUST NOT override a
     prior terminal state. In particular, an envelope whose record is
     already `delivered` MUST NOT be reported as `canceled`.
   - If the record is in state `queued` and no attempt is in flight, the
     server MUST set state to `canceled`, clear `next_attempt_at`, and emit
     the delivery event defined in `CLIENT.md` section 6.5 with
     `status: canceled`.
   - If an attempt is in flight, the server MUST allow the in-flight
     attempt to run to completion and apply its result (step 3 recurses on
     the updated record).

The sending server MUST respond to the cancellation request with a
per-record summary indicating the resulting terminal state for each
affected recipient. The response schema is defined in `CLIENT.md`
section 6.6.

#### 2.7.3 Cross-Federation Behavior

A cancellation request MUST NOT be propagated across federation. The sending
server MUST NOT transmit any message to the recipient server in response to
a cancellation, and MUST NOT attempt to retract an envelope that has already
been delivered to the recipient server. Cancellation is a sender-side
queue operation only.

#### 2.7.4 Idempotence

Cancellation MUST be idempotent. A second cancellation request for the same
`envelope_id` and `recipient` MUST return the current terminal state
without changing it. Repeated cancellation requests MUST NOT produce
repeated delivery event notifications.

### 2.8 Privacy and Security Considerations

The sending server learns that a recipient has been unreachable or unresponsive
across repeated attempts. This observation MUST NOT be published as a
reputation signal (`REPUTATION.md`) except through the channels defined
there for acknowledgment observations.

A queued envelope sits at rest on the sending server for up to the effective
deadline. The sending server MUST store queued envelopes encrypted at rest
with a key not accessible to ordinary server processes, consistent with the
block list storage requirement (section 7.3). The enclosure remains sealed to
the recipient and MUST NOT be decrypted by the sending server at any point in
the queue lifecycle.

Retry timing itself is observable to the recipient server and to any on-path
observer. The jitter requirement in section 2.3 exists to avoid
fingerprinting of sending server implementations and to prevent correlated
retry storms from causing self-inflicted denial of service.

The queue state record (section 2.5) is visible to the sending client and
therefore to the sending user. It MUST NOT be exposed to any other party,
including the recipient server, via any SEMP-defined interface.

---

## 3. Delivery Pipeline

Envelopes pass through a fixed sequence of checks before a delivery decision
is made. Each step may produce a `rejected` acknowledgment. The first failure
terminates processing.

```
Envelope received
  │
  ├─ Verify seal.signature          → rejected: seal_invalid
  ├─ Check postmark.expires         → rejected: envelope_expired
  ├─ Check postmark.session_id      → rejected: handshake_invalid / no_session
  ├─ Verify seal.session_mac        → rejected: session_mac_invalid
  ├─ Check domain/server policy     → rejected or silent
  ├─ Decrypt K_brief from seal.brief_recipients using server domain key
  ├─ Decrypt brief using K_brief
  ├─ Check user policy              → rejected or silent
  ├─ Check first-contact policy     → rejected: policy_forbidden (section 6.4)
  ├─ Check rate limit               → silent (section 6.5)
  └─ Deliver to client              → delivered
```

Domain and server-level policy checks occur before `brief` decryption because
domain identity is available from the postmark. User-level policy checks require
`brief` decryption to obtain the full sender address. Both checks are performed
before delivery.

The recipient server decrypts the brief using `K_brief` obtained from
`seal.brief_recipients` via its own domain private key. The server must be
able to read `brief.from` to enforce user-level blocks on behalf of its users.
The privacy implication (that the server learns the full correspondent
graph) is documented in `ENVELOPE.md` section 10.6. The enclosure remains
inaccessible to the server at all times.

### 3.1 Cross-Domain Delivery Prerequisites

When an envelope is addressed to a recipient on a different domain, the sender's
server MUST establish a federation session before forwarding. The prerequisite
flow is:

1. The sender's server performs the discovery flow defined in `DISCOVERY.md`
   section 5.1 to determine the peer's server address. This happens
   automatically for any domain, without requiring pre-configured peer lists
   (see `DISCOVERY.md` section 5.7).

2. The sender's server obtains the peer's domain signing key from the
   peer's configuration document, at the URL advertised as
   `endpoints.domain_keys` (see `HANDSHAKE.md` section 5.3, `DISCOVERY.md`
   section 3.3). The key is cached for subsequent handshakes.

3. The sender's server opens a federation session with the peer via the
   four-message federation handshake defined in `HANDSHAKE.md` section 5. The
   session is cached and reused for subsequent deliveries to the same domain.

4. The sender's server re-signs the envelope's `seal.session_mac` under the
   federation session's `K_env_mac`, then forwards it to the peer. The original
   `seal.signature` (the sender domain's proof of provenance) is preserved. The
   peer's server runs the full delivery pipeline (section 3) on the received
   envelope.

Federation sessions support automatic in-session rekeying at 80% of the
session TTL per `SESSION.md` section 3.1, keeping long-lived federation hops
alive without repeated handshakes.

---

## 4. Sender Policy and Blocking

The acknowledgment type a server returns for a given sender is determined by
its delivery policy for that sender. One common policy mechanism is a block
list. A block list maps sender entities to acknowledgment types.

The block list is one implementation of delivery policy. Servers MAY implement
other policy mechanisms (rate limiting, reputation thresholds, federation
rules) that also determine acknowledgment type. The protocol does not mandate
the policy mechanism, only the acknowledgment type that results from it.

---

## 5. Block List

### 5.1 Block Entry Schema

```json
{
    "id": "block-entry-ulid",
    "entity": {
        "type": "user",
        "address": "blocked@example.com"
    },
    "acknowledgment": "rejected",
    "reason": "harassment",
    "scope": "all",
    "created_at": "2025-06-10T20:17:10Z",
    "expires_at": null,
    "created_by_device_id": "device-ulid",
    "extensions": {}
}
```

### 5.2 Block Entry Fields

| Field                  | Type           | Required | Description                                                        |
|------------------------|----------------|----------|--------------------------------------------------------------------|
| `id`                   | `string`       | Yes      | Unique identifier for this entry. ULID RECOMMENDED.                |
| `entity`               | `object`       | Yes      | The entity whose delivery is being controlled. See section 5.3.    |
| `acknowledgment`       | `string`       | Yes      | Acknowledgment type to return. One of: `rejected`, `silent`.       |
| `reason`               | `string`       | No       | User or operator defined reason label. Never transmitted externally.|
| `scope`                | `string`       | Yes      | One of: `all`, `direct`, `group`. See section 5.4.                 |
| `created_at`           | `string`       | Yes      | ISO 8601 UTC creation timestamp.                                   |
| `expires_at`           | `string\|null` | No       | ISO 8601 UTC expiry. `null` for permanent entries.                 |
| `created_by_device_id` | `string`       | Yes      | Device that created this entry.                                    |
| `extensions`           | `object`       | No       | Application-defined metadata. Never transmitted externally.        |

Note: `delivered` is not a valid value for `acknowledgment` in a block entry.
A block entry exists to restrict delivery; an entry that results in `delivered`
has no effect and SHOULD NOT be created.

### 5.3 Entity Types

| `entity.type` | Description                    | Match behavior                              |
|---------------|--------------------------------|---------------------------------------------|
| `user`        | A specific user address.       | Matches `address` exactly.                  |
| `domain`      | An entire sender domain.       | Matches any address `@domain`.              |
| `server`      | A SEMP server by hostname.     | Matches any envelope routed through it.     |

```json
{ "type": "user",   "address": "sender@example.com" }
{ "type": "domain", "domain": "example.com" }
{ "type": "server", "hostname": "semp.example.com" }
```

Entity matching MUST use cryptographically verified identifiers: domain names
from the verified postmark, key fingerprints from verified handshake identity.
Display names and unverified metadata MUST NOT be used for matching.

#### 5.3.1 Prohibited Entity Types

The following entity types are PROHIBITED at the protocol layer, in
conformance with the transport-vs-trust separation in `DESIGN.md`
section 2.2.1:

- **IP addresses** (IPv4 or IPv6): a block entry with
  `type: "ip"` or with an IP-address-shaped value in any `entity.*`
  field MUST be rejected as malformed. Block lists are protocol-layer
  trust artifacts; IP addresses are transport-layer artifacts.
- **Network ranges** (CIDR blocks, autonomous system numbers, geographic
  regions derived from IP): similarly prohibited.
- **TLS certificate fingerprints of intermediate infrastructure** (load
  balancers, reverse proxies): the certificate that authenticates the
  SEMP server's domain is the appropriate trust anchor, not the
  certificate of an intermediary.

Operators that wish to apply transport-layer operational defenses
(SYN flood protection, connection rate limits, network-level DoS
mitigation) MAY do so at the firewall or network stack, but those
defenses MUST NOT be expressed as SEMP block list entries, MUST NOT be
propagated across federation, and MUST NOT influence reputation
observations published per `REPUTATION.md` section 5.1.

### 5.4 Delivery Scope

| `scope`  | Applies to                                                                 |
|----------|----------------------------------------------------------------------------|
| `all`    | All envelopes from the entity.                                             |
| `direct` | Direct messages only. Group messages from the entity are not affected.     |
| `group`  | Group messages only. Direct messages from the entity are not affected.     |

---

## 6. Enforcement Points

### 6.1 Pre-Handshake

Before completing a handshake, the server checks whether the initiating party
matches a domain-level or server-level block entry. Individual user identity
is not available at this stage because it is encrypted in the handshake confirm step.

If a match is found:

- `acknowledgment: "rejected"`: reject the handshake at `step: "rejected"`
  with `reason_code: "blocked"`. No session is established.
- `acknowledgment: "silent"`: do not complete the handshake. No response
  is sent after the init message.

### 6.2 Post-Handshake Envelope Enforcement

After a session is established, block entries are checked at envelope receipt
following the delivery pipeline in section 3. Domain and server entries are
checked before `brief` decryption. User entries are checked after.

If a match is found, the server applies the acknowledgment type from the block
entry, returning an explicit rejection or going silent.

### 6.3 Internal Route Enforcement

When an envelope arrives via `SEMP_INTERNAL_ROUTE` from another partition
server within the same domain (`DISCOVERY.md` section 5.4), the receiving
partition server MUST execute the full delivery pipeline defined in section 3
and return an acknowledgment. The three acknowledgment types defined in
section 1 (`delivered`, `rejected`, `silent`) apply without modification.
Internal routing is not a bypass.

The receiving partition server enforces block list entries because it holds the
recipient's block list. The sending partition server cannot perform this check
and MUST NOT attempt to access or infer the recipient's block list.

All privacy constraints from section 8 apply across partition boundaries. A
`silent` acknowledgment on an internal route MUST maintain consistent timing
per section 8.2. The sending partition server MUST NOT disclose to the sending
client whether an envelope was blocked versus undeliverable for other reasons,
beyond what the acknowledgment type and reason code convey.

### 6.4 First-Contact Enforcement

A recipient server MUST enforce the first-contact policy published per
`KEY.md` section 3.2 for envelopes addressed to recipients on its domain.
Enforcement occurs after `brief` decryption (section 3) so that the
sender address is available, and before envelope delivery to the
recipient client.

#### 6.4.1 Known Correspondent Definition

A sender `S` is a known correspondent of recipient `R` if any of the
following conditions hold:

1. `R` has previously sent at least one envelope to `S` (outbound history).
2. `R` has previously replied to an envelope from `S` (where the reply
   set `brief.in_reply_to` to a `message_id` of an envelope from `S`).
3. `R` has explicitly added `S` to their accepted-senders list through
   a client action.

The recipient server MAY observe condition 1 from `brief.from` of
outbound envelopes and condition 2 from `brief.in_reply_to` correlated
with the originating envelope's stored metadata. Condition 3 requires a
client-initiated update transmitted as a signed message in the same
manner as block list sync messages (section 7.1).

The recipient server MUST treat a sender as known correspondent at the
domain granularity (`brief.from`'s domain) by default. Operators MAY
configure narrower granularity (per-address known correspondents) at
the cost of more frequent first-contact gating.

#### 6.4.2 Enforcement Procedure

For each delivered envelope, the recipient server:

1. Determines whether the sender is a known correspondent of the
   recipient per section 6.4.1.
2. If the sender is a known correspondent, proceeds to standard delivery.
3. If the sender is not a known correspondent and the recipient's
   policy is `mode: open`, proceeds to standard delivery.
4. If the sender is not a known correspondent and the recipient's
   policy is `mode: pow`:
   - If `seal.first_contact_token` is present and verifies per
     `HANDSHAKE.md` section 2.2a.4, proceeds to standard delivery.
   - Otherwise, rejects with `reason_code: "policy_forbidden"` and
     includes a fresh `proof_of_work` challenge in the rejection
     response, formatted per `HANDSHAKE.md` section 2.2a.3.
5. If the recipient's policy is `mode: invite_only`:
   - If a valid invite token is presented, proceeds to standard
     delivery. Invite token format is out of scope for this revision.
   - Otherwise, rejects with `reason_code: "policy_forbidden"` and
     does not include a challenge body (no challenge can satisfy the
     policy).

#### 6.4.3 Indistinguishable Rejection

The rejection response for steps 4 and 5 MUST be identical in shape,
size, and timing for non-existent recipient addresses and for existing
addresses whose policy is being enforced. A recipient server MUST issue
a `proof_of_work` challenge for envelopes addressed to non-existent
addresses on its domain when the operator's default policy is `pow`,
even though no token will ever be accepted, in order to maintain
indistinguishability per `DESIGN.md` section 2.7.

The recipient server MUST NOT reduce the number of `proof_of_work`
challenge issuance computations for non-existent addresses or use
faster code paths for them. Implementations MUST issue indistinguishable
responses on indistinguishable code paths.

#### 6.4.4 Once-Approved Senders

A sender that has successfully delivered at least one envelope under
first-contact PoW MUST be treated as a known correspondent for purposes
of subsequent envelopes from the same sender domain to the same
recipient address, until the recipient explicitly revokes that status.
Subsequent envelopes from the same sender within the binding window
MAY also reuse the same first_contact_token per `HANDSHAKE.md`
section 2.2a.3.

### 6.5 Sender Rate Limiting

A recipient server MUST apply per-sender-domain rate limits on envelope
submissions to non-known-correspondent recipients on its domain.

#### 6.5.1 Threshold and Action

When a sender domain exceeds the rate threshold (operator-configured;
RECOMMENDED default 100 unknown-correspondent envelope submissions per
hour), the recipient server MUST switch all subsequent rejections to
that sender domain to `silent` acknowledgment per section 1.3, for the
duration of the throttling window. Throttling windows SHOULD be at
least 1 hour and SHOULD NOT exceed 24 hours.

The threshold MUST count submissions to non-existent and existent
recipient addresses identically. A counter that distinguished them
would be an existence oracle.

#### 6.5.2 Pre-Threshold Behavior

Below the threshold, the recipient server returns `policy_forbidden`
rejections with challenge bodies per section 6.4.3. The throttling
mechanism is layered atop, not in place of, first-contact enforcement.

---

## 7. Multi-Device Synchronization

A user's block list must be consistent across all their registered devices.
Changes made on one device are propagated through the user's home server.

### 7.1 Sync Message Schema

```json
{
    "type": "SEMP_BLOCK",
    "step": "update",
    "version": "1.0.0",
    "user_id": "user@example.com",
    "device_id": "originating-device-ulid",
    "list_version": 42,
    "timestamp": "2025-06-10T20:17:10Z",
    "operations": [
        {
            "op": "add",
            "entry": {}
        },
        {
            "op": "remove",
            "entry_id": "block-entry-ulid"
        },
        {
            "op": "modify",
            "entry_id": "block-entry-ulid",
            "entry": {}
        }
    ],
    "signature": {
        "algorithm": "ed25519",
        "key_id": "device-key-fingerprint",
        "value": "base64-signature-over-operations"
    }
}
```

### 7.2 Sync Rules

- Updates MUST be signed by the originating device's key.
- The home server MUST verify the signature before storing or propagating.
- `list_version` is a monotonically increasing counter per user. Updates with
  a lower version than the current known version MUST be rejected as stale.
- Conflicts (two devices modifying the same entry concurrently) are resolved
  by higher `list_version`. Equal versions resolve by later `timestamp`.
- The home server propagates accepted updates to all other registered devices
  on next connection.

### 7.3 Storage Requirements

Block lists MUST be stored encrypted at rest. The server MUST NOT be able to
read block list contents in plaintext. This protects the user in the event of
a server compromise.

---

## 8. Privacy Considerations

### 8.1 Block List Confidentiality

A user's block list is private. It reveals sensitive information: harassment
situations, personal conflicts, security concerns. Servers MUST NOT disclose
block list contents to any party other than the owning user's authenticated
devices.

### 8.2 Acknowledgment Type and Block Detection

With `rejected` acknowledgment, the sender learns delivery was refused and
receives a reason code. Whether the sender learns they are specifically
blocked, as opposed to rejected for another reason, depends on the reason
code returned. Servers MAY return a generic reason code rather than `blocked`
if revealing the specific reason would itself be harmful.

With `silent` acknowledgment, the sender cannot determine whether silence
means a delivery policy decision, the recipient is offline, or network failure.
Implementations MUST maintain consistent timing in silent mode; timing
variations that correlate with delivery policy would leak information.

### 8.3 Block List as an Attack Surface

Block list size or contents could be inferred through side channels.
Implementations SHOULD use encrypted storage and MUST NOT expose block list
size or contents through any observable interface.

### 8.4 Status Disclosure

Recipient status (section 1.6) reveals availability information to senders.
A malicious sender could use status information to infer the recipient's
behavior patterns (for example, correlating `away` periods with travel
schedules). The visibility rules in section 1.6.4 mitigate this by allowing
recipients to restrict status disclosure to trusted senders. The default
visibility is `nobody`, ensuring no status is disclosed unless the recipient
explicitly opts in.

Servers MUST NOT disclose status to senders who do not match the recipient's
visibility rules. A sender who does not match any visibility rule MUST receive
an acknowledgment with no `recipient_status` field, indistinguishable from
a recipient who has not configured status at all.

---

## 9. Security Considerations

### 9.1 Evasion Resistance

Delivery policy MUST be enforced on cryptographically verified identifiers.
A sender cannot evade a domain-level policy entry by changing their display
name or using a different address format. Domain entries MUST match all
addresses from that domain.

### 9.2 Sync Integrity

Block list sync messages MUST be signed by the originating device. The home
server and receiving devices MUST verify signatures before applying updates.
Unsigned or unverifiable sync messages MUST be rejected.

### 9.3 Rate Limiting

Servers SHOULD rate-limit block list operations per user to prevent abuse,
for example automated mass operations that could be used to manipulate
delivery behavior at scale.

### 9.4 Delegated Client Scope Enforcement

The sender's home server enforces permission scopes on delegated clients at
envelope submission time, before the envelope enters the delivery pipeline.
A delegated client with a restricted scope cannot submit envelopes to recipients
outside its authorized list. This enforcement is defined in `CLIENT.md` section
2.4 and uses scoped device certificates defined in `KEY.md` section 10.3.

Scope enforcement is a sender-side control. The recipient server is not aware
of whether the sending client was a full-access device or a delegated service.
From the recipient's perspective, the envelope originates from the sender's
domain with a valid seal, regardless of which client composed it.

---

## 10. Relationship to Other Specifications

| Specification | Relationship |
|---|---|
| `DESIGN.md` | Explicit rejection principle from section 2.3. Silent acknowledgment is a documented exception per section 2.6. |
| `HANDSHAKE.md` | Pre-handshake enforcement uses `step: "rejected"` with `reason_code: "blocked"`. Reason code system defined in section 4.1. |
| `ENVELOPE.md` | Post-handshake enforcement uses envelope rejection reason codes from section 9.3. Delivery pipeline order from section 7.2. |
| `DISCOVERY.md` | Internal route enforcement for same-domain multi-server delivery defined in section 5.4. Acknowledgment schema in section 5.4.1. |
| `CLIENT.md` | Submission response and queued-state visibility to the client defined in section 6 of that document. |
| `SESSION.md` | Federation session rekey behavior during retry defined in section 3. |

---

*This document is an Internet-Draft. It is subject to revision prior to
finalization as a stable specification.*
