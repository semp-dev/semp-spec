## Abstract

This document specifies the Sealed Envelope Messaging Protocol
(SEMP) delivery semantics, sender-side queueing and retry,
staged delivery across multi-device accounts, the block list and
first-contact mechanisms, the user policy synchronization
protocol, the reputation signals and trust gossip mechanism, the
abuse reporting model, and the authoritative registry of reason
codes used across the SEMP protocol. SEMP requires explicit
acknowledgment of every envelope delivery attempt: a recipient
server returns either a `delivered` or `rejected` wire
acknowledgment, or operates in silent mode (no wire response).
Delivered acknowledgments carry a signed delivery receipt that
serves as portable evidence of acceptance. Reputation is
peer-to-peer and observation-based, keyed by cryptographic
domain identity rather than by IP address.

# Introduction

This document specifies the delivery, reputation, and error-code
layers of the Sealed Envelope Messaging Protocol (SEMP). It
defines:

* the wire-level acknowledgments a recipient server may return
  (`delivered`, `rejected`) and the sender-side classification of
  delivery outcomes (including the timeout-derived `silent`
  classification);
* the signed delivery receipt that accompanies every
  `delivered` acknowledgment;
* the sender-side queueing, retry, and expiry behavior;
* the per-envelope delivery pipeline (seal verification, session
  validation, brief decryption, policy and first-contact checks);
* staged delivery across the recipient account's multiple
  devices;
* the block list and first-contact mechanisms;
* the multi-device user policy synchronization protocol;
* the reputation signals (domain registration age, abuse rate,
  trust gossip), abuse reporting, and trust transfer;
* the authoritative registry of error codes, reason codes, and
  status values used across the SEMP protocol.

The architectural role of delivery and reputation is defined in
[Architecture](architecture.md). The envelope format that
carries delivery semantics is in [Envelope](envelope.md).
The handshake and session that the delivery pipeline operates
within are in [Handshake](handshake.md). Discovery and key
publication are in [Discovery](discovery.md).

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

This document additionally uses terminology from [RFC 4949](https://www.rfc-editor.org/rfc/rfc4949)
for general security-protocol terms.

# Delivery Outcomes

Every envelope delivery attempt resolves to exactly one outcome
at the sending server. The outcome is either communicated by the
recipient server on the wire (an explicit acknowledgment) or
inferred by the sending server from the absence of any wire
response within a timeout window.

## Wire Acknowledgments

The recipient server may return one of two wire
acknowledgments. These are the only protocol-level values
observable on the wire between servers:

| Wire Acknowledgment | Description |
|---|---|
| `delivered` | The recipient server accepted the envelope and has committed to making it available to the recipient client. |
| `rejected` | The recipient server explicitly refused the envelope with a reason code. |

A recipient server that wishes to refuse delivery without
disclosing the refusal MUST withhold any wire response. This
behavior is silent mode, described in [Silent Mode](#silent-mode).

## Sender-Side Classification

After a wire acknowledgment is received, or the timeout window
elapses without one, the sending server records the result under
one of three labels. These labels are sender-side bookkeeping.
Only `delivered` and `rejected` labels correspond to wire values:

| Classification | Source |
|---|---|
| `delivered` | Wire acknowledgment of `delivered` received from the recipient server. |
| `rejected` | Wire acknowledgment of `rejected` received from the recipient server. |
| `silent` | No wire acknowledgment received within the timeout window. |

`silent` is the sender-side label for the absence of a wire
response. The classification has no wire value of its own,
and is instead synthesized by the sending server after the
timeout elapses.

What a recipient server or client does internally with an
accepted envelope (deliver to inbox, filter to a folder,
suppress notifications, hold for review) is an application
concern. The protocol does not observe or regulate internal
inbox management.

## Delivered Acknowledgment

The recipient server returns an explicit acceptance. The
envelope has been received and will be delivered to the
recipient client. The sending server marks the delivery as
confirmed and informs the sending user.

A server MUST NOT return `delivered` for an envelope it does
not intend to deliver to the recipient.

<a id="signed-delivery-receipt"></a>

## Signed Delivery Receipt
Every `delivered` acknowledgment MUST carry a signed delivery
receipt. The receipt is a portable artifact the sending server
retains and the sending user MAY export. It proves that a
specific recipient domain accepted a specific envelope at a
specific time.

Receipts are unconditional. The recipient server MUST issue a
receipt for every `delivered` acknowledgment, regardless of any
sender signal. See [Receipt Non-Repudiation and Operator Liability](#receipt-liability).

### Receipt Schema

~~~ json
{
    "type": "SEMP_DELIVERY_RECEIPT",
    "version": "1.0.0",
    "envelope_hash": {
        "algorithm": "sha-256",
        "value": "base64-digest-of-canonical-envelope-bytes"
    },
    "recipient_domain": "recipient.example",
    "accepted_at": "2026-04-21T10:15:32Z",
    "signature": {
        "algorithm": "ed25519",
        "key_id": "recipient-domain-key-fingerprint",
        "value": "base64-signature"
    }
}
~~~

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | MUST be `"SEMP_DELIVERY_RECEIPT"`. |
| `version` | string | Yes | Receipt format version (semver). |
| `envelope_hash` | object | Yes | Hash of the canonical envelope bytes. |
| `recipient_domain` | string | Yes | The recipient server's domain. |
| `accepted_at` | string | Yes | ISO 8601 UTC timestamp, second precision, of the recipient server's accept decision. |
| `signature` | object | Yes | Recipient domain's signature over the receipt. |

`envelope_hash.value` is the SHA-256 digest of the canonical
envelope bytes as defined in [Envelope](envelope.md).
`envelope_hash.algorithm` MUST be `"sha-256"` for version 1.0.0
receipts.

The signed input is:

~~~
SEMP-DELIVERY-RECEIPT: || canonical_receipt_bytes
~~~

where `canonical_receipt_bytes` is the canonical UTF-8 JSON
encoding of the receipt with `signature.value` set to `""` and
all other fields at their final values.

### Recipient Server Obligations

The recipient server MUST produce and return the receipt inline
in the `delivered` acknowledgment response, in a `receipt`
field alongside the existing acknowledgment body:

~~~ json
{
    "acknowledgment": "delivered",
    "receipt": {
        "type": "SEMP_DELIVERY_RECEIPT",
        "...": "..."
    },
    "recipient_status": { "...": "..." }
}
~~~

The recipient server MUST NOT issue a receipt for an envelope
it has not actually accepted for delivery. The receipt is a
non-repudiable artifact, and its semantics are "this server
committed to making this envelope available to its recipient."
A receipt MUST NOT be issued for any envelope that did not
result in a `delivered` acknowledgment.

The recipient server's clock skew relative to true UTC SHOULD
be bounded to within 60 seconds. Verifiers MUST NOT reject a
receipt solely because `accepted_at` is within 120 seconds of
their own current time in either direction.

### Sending Server Obligations

The sending server MUST verify the receipt's signature against
the recipient domain's published signing key before treating
the acknowledgment as a terminal `delivered` outcome. A
`delivered` acknowledgment that arrives without a verifiable
receipt MUST be treated as a transport failure and retried.

The sending server MUST expose the receipt to the sending
client through the delivery event notification. The client is
the authoritative custodian of receipts.

The sending server MUST hold the receipt only as long as
necessary to deliver it to the sending user's devices. After
acknowledgment by a client, the sending server MAY drop its
copy of the receipt.

### Verification by Third Parties

A party that holds a receipt and the corresponding envelope
can verify end to end by parsing the receipt, fetching the
recipient domain's signing key by `signature.key_id`,
reconstructing `canonical_receipt_bytes`, and verifying
`signature.value` over `SEMP-DELIVERY-RECEIPT: ||
canonical_receipt_bytes`. If the verifier also holds the
envelope, the canonical envelope digest can be computed and
compared against `envelope_hash.value`.

A successful verification proves that the recipient domain
acknowledged receipt of the envelope at `accepted_at`. It does
not prove that the recipient user read the envelope, that the
envelope was delivered to any specific device, or that the
envelope was not subsequently deleted.

## Rejected Acknowledgment

The recipient server returns an explicit rejection with a
reason code. The sending server marks the delivery as failed,
records the reason, and informs the sending user. The sending
server MUST determine from the reason code whether the failure
is recoverable before deciding whether to retry.

Rejected is the RECOMMENDED default acknowledgment for any
envelope the server will not deliver.

<a id="silent-mode"></a>

## Silent Mode
`silent` describes two related concepts:

Silent mode (recipient-side policy):
: A recipient server operates in silent mode for a particular
  sender, domain, or class of envelopes when its policy is to
  withhold any wire acknowledgment for matching envelopes.

Silent classification (sender-side bookkeeping):
: After the timeout window elapses with no wire
  acknowledgment received, the sending server records the
  outcome as `silent` and informs the sending user. This label
  is internal to the sending server and its client.

Silent mode MAY be applied as a recipient policy for
deliberate operator or user reasons. Typical applications are
privacy preservation and anti-harassment situations, where
revealing that a delivery was refused would itself be
harmful. Silent mode is NOT RECOMMENDED as the default
policy.

Silence and network failure are indistinguishable to the
sending server. A sender cannot determine whether silence
means blocking, the recipient is offline, or the message was
lost in transit.

A server operating in silent mode MUST still explicitly reject
envelopes with invalid seals on the wire. Silent mode applies
only to envelopes that pass all verification checks. An
invalid envelope MUST always be rejected explicitly regardless
of delivery policy.

## Sending Server Obligations

The sending server MUST track the classification of every
delivery attempt and surface it to the sending user. The
sending server MUST NOT misrepresent the classification: if a
`rejected` wire acknowledgment was received, the user MUST be
told delivery failed. The sending server MUST NOT relabel a
rejection as pending or successful.

## Delivery Timeout

The sending server MUST enforce a timeout on each individual
delivery attempt. After the timeout elapses with no wire
acknowledgment, the attempt is classified as `silent`. A
timeout of 30 seconds is RECOMMENDED for an individual
attempt. Retry scheduling and overall deadlines are defined in
[Queueing, Retry, and Expiry](#queueing-retry-expiry).

## Recipient Status

When the acknowledgment type is `delivered`, the recipient
server MAY include a `recipient_status` object in the
acknowledgment response. The object carries the recipient's
current availability so the sender does not need a separate
message exchange to learn it.

~~~ json
{
    "acknowledgment": "delivered",
    "recipient_status": {
        "state": "away",
        "message": "On leave until July.",
        "until": "2026-07-01T00:00:00Z"
    }
}
~~~

| Field | Type | Required | Description |
|---|---|---|---|
| `state` | string | Yes | One of: `available`, `away`, `do_not_disturb`. |
| `message` | string \| null | No | Freetext status message. Maximum 256 UTF-8 bytes. |
| `until` | string \| null | No | ISO 8601 UTC timestamp indicating when the state is expected to change. |

All three states result in normal delivery. Status is only
informational, and it does not affect whether an envelope is
accepted. A server MUST NOT reject or delay envelopes based on
recipient status.

Recipient status is opt-in. Servers MUST NOT include
`recipient_status` in acknowledgments unless the recipient has
explicitly enabled it. The default is no status disclosure.

Recipients control who sees their status through visibility
rules:

| Visibility | Description |
|---|---|
| `everyone` | Status is included in acknowledgments to all senders. |
| `domains` | Status is included only for senders from specified domains. |
| `servers` | Status is included only for senders whose envelopes were routed through specified servers. |
| `users` | Status is included only for specified sender addresses. |
| `nobody` | Status is never included. Equivalent to disabling the feature. This is the default. |

When multiple visibility rules are configured, they are
evaluated as a union: if any rule matches the sender, the
status is included. A sender who does not match any
visibility rule MUST receive an acknowledgment with no
`recipient_status` field, indistinguishable from a recipient
who has not configured status at all.

### Status Configuration Schema

Status updates are transmitted from the client to the home
server as signed messages, following the same authentication
model as user policy sync messages
([User Policy Synchronization](#user-policy-synchronization)). The server stores the
current status and applies visibility rules at delivery
time.

~~~ json
{
    "type": "SEMP_STATUS",
    "version": "1.0.0",
    "user_id": "recipient@example.com",
    "state": "away",
    "message": "On leave until July.",
    "until": "2026-07-01T00:00:00Z",
    "visibility": {
        "mode": "users",
        "allow": [
            { "type": "domain", "domain": "work.example.com" },
            { "type": "user", "address": "friend@personal.example" }
        ]
    },
    "updated_at": "2026-06-15T10:00:00Z",
    "device_id": "originating-device-ulid",
    "signature": {
        "algorithm": "ed25519",
        "key_id": "originating-device-key-fingerprint",
        "value": "base64-signature"
    }
}
~~~

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | MUST be `"SEMP_STATUS"`. |
| `version` | string | Yes | Record format version (semver). |
| `user_id` | string | Yes | The recipient's SEMP address. |
| `state` | string | Yes | One of: `available`, `away`, `do_not_disturb`. |
| `message` | string \| null | No | Freetext status message. Maximum 256 UTF-8 bytes. |
| `until` | string \| null | No | ISO 8601 UTC timestamp indicating when the state is expected to change. |
| `visibility` | object | Yes | Visibility rule. The `mode` is one of the values in the visibility table. `allow` is populated only for modes that require a list. |
| `updated_at` | string | Yes | ISO 8601 UTC timestamp. The home server treats a later `updated_at` as superseding an earlier one for the same `user_id`. |
| `device_id` | string | Yes | Identifier of the originating device. |
| `signature` | object | Yes | Signature by the originating device's identity key over canonical bytes with `signature.value` set to `""`, prefixed with `SEMP-STATUS:`. |

The signature MUST be produced by a registered device of the
account. The home server MUST reject a `SEMP_STATUS` update
whose `device_id` is not currently registered for the
account, or whose `signature` does not verify against that
device's published key.

<a id="queueing-retry-expiry"></a>

# Queueing, Retry, and Expiry
## Sender-Side Queue

The sending server MUST maintain a delivery queue for
envelopes submitted by its own clients. An envelope enters the
queue upon successful submission and leaves the queue when it
reaches a terminal outcome: `delivered`, `rejected`, or
`expired`.

A queued envelope is the sending server's responsibility until
a terminal outcome is reached. The sending server MUST persist
queued envelopes such that a restart does not drop them. The
sending server MUST NOT mutate the envelope's `seal` or
`postmark` between attempts. In particular,
`postmark.expires` MUST NOT be rewritten to extend delivery.

## When to Retry

The sending server MUST classify each per-attempt outcome as
terminal or non-terminal before scheduling further action.

| Per-attempt outcome | Classification | Next action |
|---|---|---|
| `delivered` | Terminal | Remove from queue. |
| `rejected`, non-recoverable reason | Terminal | Remove from queue. |
| `rejected`, recoverable reason | Non-terminal | Schedule retry. |
| `silent` | Non-terminal | Schedule retry. |
| Transport failure before any acknowledgment | Non-terminal | Schedule retry. |

Recoverability is determined from the reason code returned
with a `rejected` acknowledgment. The following reason codes
are treated as recoverable for retry purposes:

* `handshake_invalid`
* `handshake_expired`
* `no_session`
* `server_unavailable`
* `rate_limited`
* `quota_exceeded`

All other reason codes, including `blocked`, `seal_invalid`,
`session_mac_invalid`, `envelope_expired`, and
`policy_forbidden`, MUST be treated as non-recoverable. The
sending server MUST NOT retry envelopes that have received a
non-recoverable rejection.

A non-existent recipient address MUST be answered with the
same generic `policy_forbidden` rejection as any other policy
refusal, in conformance with the address-enumeration
resistance requirement.

A `silent` outcome MUST be treated as non-terminal and subject
to the retry schedule.

An unrecognized reason code MUST be treated as
non-recoverable.

## Retry Schedule

For non-terminal outcomes, the sending server MUST schedule a
subsequent attempt subject to the following bounds:

* The sending server MUST make at least five retry attempts
  before declaring terminal failure by deadline, provided the
  effective deadline permits.
* The sending server MUST use an exponential backoff with a
  minimum initial delay of 60 seconds and a minimum
  multiplier of 2 between consecutive intervals.
* The sending server MUST cap individual inter-attempt
  intervals at 6 hours.
* The sending server MUST apply jitter of at least plus or
  minus 10 percent to each scheduled interval.

The bounds compose as follows. The server computes a base
interval by applying the configured multiplier to the previous
base interval, then clamping to the 6-hour cap. The 60-second
minimum applies to the first base interval only. The server
then applies symmetric jitter by selecting a random
multiplier in the range `[1 - j, 1 + j]`, where `j` is at
least `0.1`. Jitter MUST NOT reduce the realized interval
below 50 percent of the first base interval (30 seconds).

The following schedule is RECOMMENDED as a default, before
jitter: 1 minute, 5 minutes, 15 minutes, 1 hour, 4 hours,
then every 4 hours until the effective deadline.

A retry attempt MUST NOT reuse a federation session that has
been invalidated or has passed its TTL. On receipt of a
`rejected` acknowledgment with reason code
`handshake_invalid`, `handshake_expired`, or `no_session`,
the sending server MUST invalidate its cached federation
session with the recipient's server before the next attempt.

## Effective Delivery Deadline

Every queued envelope has an effective delivery deadline. The
effective deadline is the earlier of:

* `postmark.expires`, as set by the sending client;
* `queued_at + server_max_retry_horizon`, where
  `server_max_retry_horizon` is an operator-configured value.

The `server_max_retry_horizon` SHOULD default to 72 hours and
MUST NOT exceed 7 days. The sending server MUST NOT retry an
envelope past its effective deadline.

When the effective deadline is reached with no terminal
outcome, the sending server MUST transition the envelope to
the terminal state `expired` and remove it from the queue.

## Persistent Silent Recipients

The sending server SHOULD maintain a per-recipient counter
of consecutive `silent` outcomes observed for envelopes
addressed to the same recipient address. When the counter
reaches an operator-configured threshold (RECOMMENDED 5
consecutive `silent` outcomes, observed over a window of at
least 24 hours, with no intervening non-`silent`
acknowledgment), the sending server SHOULD shorten the
effective delivery deadline for subsequent envelopes
addressed to the same recipient. The shortened deadline
RECOMMENDED is 4 hours, applied in place of the default
`server_max_retry_horizon`.

This counter is sender-side state and is not part of the
wire protocol. The sending server MUST NOT propagate the
counter to any other party, MUST NOT expose it on the wire,
and MUST NOT publish it as a trust gossip observation
([Trust Gossip](#trust-gossip)). The counter reflects the absence of
wire response from a specific recipient to a specific
sending server, and it does not assert that the recipient
is unreachable to others.

The counter MUST be reset to zero on receipt of any
non-`silent` acknowledgment from the same recipient. The
counter MAY also expire after an operator-configured idle
period (RECOMMENDED 30 days) so that a recipient who later
changes policy receives unbiased retry handling.

## Sending Client Visibility

While an envelope is queued, the sending server MUST maintain
a queue state record:

~~~ json
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
~~~

The sending server MUST update the queue state record at each
attempt. The sending server MUST NOT emit a per-attempt push
notification to the client for every attempt. On transition
to a terminal state, the sending server MUST emit a delivery
event notification.

The sending server MUST retain the terminal queue state
record for at least 24 hours after termination, so that a
client reconnecting after transient offline periods can
observe the terminal outcome.

## Terminal Outcomes and Failure Notification

The terminal states are:

| Terminal state | Source |
|---|---|
| `delivered` | Explicit `delivered` acknowledgment from the recipient server. |
| `rejected` | Explicit `rejected` acknowledgment from the recipient server. |
| `expired` | Effective delivery deadline reached without a terminal acknowledgment. |
| `canceled` | Client-initiated cancellation accepted before a terminal acknowledgment. |

The sending server MUST NOT generate a synthetic bounce
envelope addressed to the sending user or to any third party,
and MUST NOT transmit any message across federation in
response to a terminal delivery failure. Failure notification
remains within the sender's home server and its authenticated
clients. Synthetic bounces are a documented source of
backscatter abuse in prior message protocols and are
incompatible with SEMP's seal-based provenance model.

## Client-Initiated Cancellation

A sending client MAY request cancellation of a queued
envelope before it reaches a terminal state. Cancellation
halts retry scheduling and transitions the queue state record
to the terminal state `canceled`.

A cancellation request MUST NOT be propagated across
federation. The sending server MUST NOT transmit any message
to the recipient server in response to a cancellation, and
MUST NOT attempt to retract an envelope that has already been
delivered to the recipient server.

Cancellation MUST be idempotent. A second cancellation
request for the same `envelope_id` and `recipient` MUST
return the current terminal state without changing it.

# Delivery Pipeline

Envelopes pass through a fixed sequence of checks before a
delivery decision is made. Each step produces an outcome that
either terminates processing or advances the envelope to the
next step.

1. Verify `seal.signature`. Invalid signature: `rejected:
   seal_invalid`.
2. Check `postmark.expires`. Past expiry: `rejected:
   envelope_expired`.
3. Check that `postmark.session_id` references an active,
   non-expired, non-invalidated session. Otherwise:
   `rejected: handshake_invalid` or `no_session`.
4. Verify `seal.session_mac`. Invalid MAC: `rejected:
   session_mac_invalid`.
5. Apply domain and server policy. Policy outcome:
   `rejected` or `silent` per the matched entry.
6. Decrypt `K_brief` from `seal.brief_recipients` using the
   server domain key.
7. Decrypt the brief using `K_brief`.
8. Apply user policy (block list). Policy outcome:
   `rejected` or `silent` per the matched entry.
9. Apply first-contact policy. Sender not a known
   correspondent and lacking a verifying first-contact
   token: `rejected: policy_forbidden`.
10. Apply rate limit. Threshold exceeded: `silent`.
11. Deliver to client. Outcome: `delivered`.

Domain and server-level policy checks occur before brief
decryption because domain identity is available from the
postmark. User-level policy checks require brief decryption to
obtain the full sender address.

## Cross-Domain Delivery Prerequisites

When an envelope is addressed to a recipient on a different
domain, the sender's server MUST establish a federation
session before forwarding. The prerequisite flow is:

1. The sender's server performs the discovery flow per
   [Discovery](discovery.md) to determine the peer's
   server address.
2. The sender's server obtains the peer's domain signing key
   from the peer's configuration document.
3. The sender's server opens a federation session with the
   peer via the four-message federation handshake.
4. The sender's server re-signs the envelope's
   `seal.session_mac` under the federation session's
   `K_env_mac`, then forwards it to the peer. The original
   `seal.signature` (the sender domain's proof of provenance)
   is preserved.

<a id="staged-delivery"></a>

## Staged Delivery Across Account Devices
When a user's account has delegated devices whose
`scope.receive.delivery_stage` differs from the full-access
devices' implicit stage, the home server MUST deliver inbound
envelopes in stage order rather than in a single fan-out.

For each inbound envelope, the home server partitions the
account's devices whose keys appear in
`seal.enclosure_recipients` by stage:

* For each delegated device, the stage is read from the
  current scoped certificate's
  `scope.receive.delivery_stage`.
* For each full-access device, the stage is the implicit
  value `max(delegated_stages_with_mode_not_none) + 1`. If no
  such delegate exists, full-access devices are at stage 1
  and staging is a no-op.

Devices whose `scope.receive` rejects the envelope are
excluded from the partition entirely.

The home server delivers to the lowest remaining stage and
holds the envelope for higher stages in a staged-delivery
queue keyed by `postmark.id`. After delivering to stage N,
the server waits for delivery-disposition messages from any
device at stage N. The wait terminates when all devices at
stage N have emitted a disposition or the stage timeout
elapses (RECOMMENDED 30 seconds).

When the wait terminates, the server aggregates dispositions:

* If any disposition is `"suppress"`, the held envelope is
  suppressed: all higher-stage entries are removed from the
  queue and the envelope is dropped without further delivery.
* Otherwise, if any disposition is `"advance"`, or if the
  stage timeout elapsed without a `"suppress"` disposition,
  the envelope advances: the server delivers to devices at
  the next stage and repeats.

Aggregation is conservative: `"suppress"` by any stage-N
device wins over `"advance"` by any other stage-N device.

If the stage timeout elapses with no disposition at all, the
server MUST advance the envelope to the next stage. Fail-open
on timeout ensures that an unresponsive filter does not block
delivery indefinitely.

A delivery-disposition message MUST originate from a device
at the same stage as the held envelope's current pending
stage, or from an earlier stage. Dispositions from devices at
a later stage are not on the decision path and MUST be
discarded.

If a delegated device's certificate is updated or revoked
while an envelope is held in the staged queue, the server MUST
re-evaluate the partition for that envelope using the current
certificate state.

# Block List

The wire acknowledgment a server returns for a given sender,
or whether it withholds any wire response (silent mode), is
determined by its delivery policy for that sender. One common
policy mechanism is a block list. A block list maps sender
entities to a policy disposition: explicit rejection on the
wire, or silent withholding.

## Block Entry Schema

~~~ json
{
    "id": "block-entry-ulid",
    "entity": {
        "type": "user",
        "address": "blocked@example.com"
    },
    "acknowledgment": "rejected",
    "reason": "harassment",
    "scope": "all",
    "created_at": "2026-06-10T20:17:10Z",
    "expires_at": null,
    "created_by_device_id": "device-ulid",
    "extensions": {}
}
~~~

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | Yes | Unique identifier for this entry. ULID RECOMMENDED. |
| `entity` | object | Yes | The entity whose delivery is being controlled. |
| `acknowledgment` | string | Yes | Disposition to apply: `rejected` or `silent`. |
| `reason` | string | No | User or operator defined reason label. Never transmitted externally. |
| `scope` | string | Yes | One of: `all`, `direct`, `group`. |
| `created_at` | string | Yes | ISO 8601 UTC creation timestamp. |
| `expires_at` | string \| null | No | ISO 8601 UTC expiry. `null` for permanent entries. |
| `created_by_device_id` | string | Yes | Device that created this entry. |
| `extensions` | object | No | Application-defined metadata. Never transmitted externally. |

`delivered` is not a valid value for `acknowledgment` in a
block entry. A block entry exists to restrict delivery; an
entry that results in `delivered` has no effect.

## Entity Types

| `entity.type` | Description | Match behavior |
|---|---|---|
| `user` | A specific user address. | Matches `address` exactly. |
| `domain` | An entire sender domain. | Matches any address `@domain`. |
| `server` | A SEMP server by hostname. | Matches the peer server at the federation transport layer, before domain identity is established. |

Entity matching MUST use cryptographically verified
identifiers: domain names from the verified postmark, and key
fingerprints from verified handshake identity. Display names
and unverified metadata MUST NOT be used for matching.

A block entry MUST NOT use any of the following entity
types, in conformance with the transport-vs-trust separation
in [Architecture](architecture.md):

* IP addresses (IPv4 or IPv6);
* network ranges (CIDR blocks, autonomous system numbers,
  geographic regions derived from IP);
* TLS certificate fingerprints of intermediate
  infrastructure (load balancers, reverse proxies).

Operators MAY apply transport-layer operational defenses at
the firewall or network stack. Those defenses MUST NOT be
expressed as SEMP block list entries, MUST NOT be propagated
across federation, and MUST NOT influence reputation
observations.

## Delivery Scope

| `scope` | Applies to |
|---|---|
| `all` | All envelopes from the entity. |
| `direct` | Direct messages only. Group messages from the entity are not affected. |
| `group` | Group messages only. Direct messages from the entity are not affected. |

# Enforcement Points

## Pre-Handshake

Before completing a handshake, the server checks whether the
initiating party matches a domain-level or server-level block
entry. Individual user identity is not available at this stage
because it is encrypted in the handshake confirm step.

If a match is found, the server applies the disposition
recorded on the matched block entry:

* If the entry's `acknowledgment` value is `rejected`, the
  server rejects the handshake at `step: "rejected"` with
  `reason_code: "blocked"`, and no session is established.
* If the entry's `acknowledgment` value is `silent`, the
  server drops the init message and sends no wire response.
  The sender's subsequent timeout produces a sender-side
  `silent` classification.

## Post-Handshake Envelope Enforcement

After a session is established, block entries are checked at
envelope receipt following the delivery pipeline above.
Domain and server entries are checked before brief
decryption. User entries are checked after.

If a match is found, the server applies the disposition from
the block entry, returning an explicit `rejected` wire
acknowledgment or withholding any wire response.

<a id="first-contact-enforcement"></a>

## First-Contact Enforcement
A recipient server MUST enforce the first-contact policy
published per [Discovery](discovery.md) for envelopes
addressed to recipients on its domain. Enforcement occurs
after brief decryption so that the sender address is
available, and before envelope delivery to the recipient
client.

A sender `S` is a known correspondent of recipient `R` if any
of the following conditions hold:

1. `R` has previously sent at least one envelope to `S`
   (outbound history).
2. `R` has previously replied to an envelope from `S` (where
   the reply set `brief.in_reply_to` to a `message_id` of an
   envelope from `S`).
3. `R` has explicitly added `S` to their accepted-senders
   list through a client action.

The recipient server MUST treat a sender as known
correspondent at the domain granularity (`brief.from`'s
domain) by default. Operators MAY configure narrower
granularity (per-address known correspondents) at the cost of
more frequent first-contact gating.

For each delivered envelope, the recipient server:

1. Determines whether the sender is a known correspondent.
2. If the sender is a known correspondent, proceeds to
   standard delivery.
3. If the sender is not a known correspondent and the
   recipient's policy is `mode: "open"`, proceeds to standard
   delivery.
4. If the sender is not a known correspondent and the
   recipient's policy is `mode: "challenge"`:
   * If `seal.first_contact_token` is present and verifies
     against the policy's `challenge_type` and `parameters`,
     proceeds to standard delivery.
   * Otherwise, rejects with `reason_code: "policy_forbidden"`
     and includes a fresh challenge of the announced
     `challenge_type` in the rejection response.

The rejection response MUST be identical in shape, size, and
timing for non-existent recipient addresses and for existing
addresses whose policy is being enforced. A recipient server
MUST issue a challenge of the operator's default
`challenge_type` for envelopes addressed to non-existent
addresses on its domain whenever the operator's default policy
is `mode: "challenge"`, even though no token will ever be
accepted, in order to maintain address-enumeration resistance.

A sender that has successfully delivered at least one envelope
under first-contact PoW MUST be treated as a known
correspondent for purposes of subsequent envelopes from the
same sender domain to the same recipient address, until the
recipient explicitly revokes that status.

## Sender Rate Limiting

A recipient server MUST apply per-sender-domain rate limits on
envelope submissions to non-known-correspondent recipients on
its domain.

When a sender domain exceeds the rate threshold
(operator-configured; RECOMMENDED default 100
unknown-correspondent envelope submissions per hour), the
recipient server MUST switch all subsequent rejections to that
sender domain to silent-mode disposition (no wire response),
for the duration of the throttling window. Throttling windows
SHOULD be at least 1 hour and SHOULD NOT exceed 24 hours.

The threshold MUST count submissions to non-existent and
existent recipient addresses identically, since a counter
that distinguished the two cases would constitute an
existence oracle. This rule is part of the
address-enumeration resistance requirement.

## Migration Notice

During the notice window of a cooperative migration (the
period from `migrated_at` to `notice_window_until` per
[Recovery](recovery.md)), the old provider MUST
return a `policy_forbidden` rejection for envelopes
addressed to the migrated address, and MUST include a
`migration_notice` field in the rejection body. After the
notice window ends, the old provider MUST stop returning
the migration notice; envelopes addressed to the migrated
address are handled the same way envelopes addressed to
non-existent addresses are handled, with no
migration-specific body. The rejection body during the
window has the form:

~~~ json
{
    "type": "SEMP_ENVELOPE",
    "step": "rejected",
    "reason_code": "policy_forbidden",
    "reason": "Recipient has migrated.",
    "migration_notice": {
        "new_address": "alice@new.example",
        "migration_record_id": "migration-ulid",
        "migration_record_url":
            "https://new.example/.well-known/semp/migration/<id>"
    }
}
~~~

The sending server MUST surface the `migration_notice` to the
sending client. The sending client MUST NOT redirect
correspondence automatically; the user updates their
correspondent record after verifying the migration record.

<a id="user-policy-synchronization"></a>

# User Policy Synchronization
A user's policy state (block list, accepted-senders list,
first-contact policy, and any future rule kinds) must be
consistent across all their registered devices. Changes made
on one device are propagated through the user's home server.

User policy updates share a single signed-update wire frame,
`SEMP_USER_POLICY`, which carries a heterogeneous list of
operations discriminated by a `kind` field.

## Sync Message Schema

~~~ json
{
    "type": "SEMP_USER_POLICY",
    "step": "update",
    "version": "1.0.0",
    "user_id": "user@example.com",
    "device_id": "originating-device-ulid",
    "policy_version": 42,
    "timestamp": "2026-06-10T20:17:10Z",
    "operations": [
        {
            "op": "add",
            "kind": "block",
            "entry": {}
        },
        {
            "op": "remove",
            "kind": "block",
            "entry_id": "block-entry-ulid"
        },
        {
            "op": "modify",
            "kind": "first_contact",
            "entry": {}
        }
    ],
    "signature": {
        "algorithm": "ed25519",
        "key_id": "device-key-fingerprint",
        "value": "base64-signature-over-operations"
    }
}
~~~

## Sync Rules

* Updates MUST be signed by the originating device's key. The
  signed input is computed over canonical bytes prefixed with
  `SEMP-USER-POLICY:`.
* The home server MUST verify the signature before storing or
  propagating.
* `policy_version` is a monotonically increasing counter per
  user across all rule kinds. Updates with a lower version
  than the current known version MUST be rejected as stale.
* Conflicts (two devices modifying the same entry
  concurrently) are resolved by higher `policy_version`.
  Equal `policy_version` values resolve by later `timestamp`.
  An update whose `policy_version` and `timestamp` both equal
  those of an already-accepted update MUST be rejected with
  `reason_code: "policy_collision"`.
* The home server propagates accepted updates to all other
  registered devices on next connection.
* The `op` vocabulary is a closed set: `add`, `remove`,
  `modify`. New verbs MUST NOT be introduced at the operation
  level. Extensibility is achieved by registering new `kind`
  values.
* The core `kind` values defined in this specification
  ([Defined Rule Kinds](#defined-rule-kinds)) MUST be used unprefixed.
  Additional `kind` values MAY be defined in extensions
  using the standard namespacing convention
  (`vendor.example.com/kind-name`). The home server MUST
  reject operations whose `kind` it does not recognize with
  `reason_code: "policy_kind_unsupported"`. A single
  unrecognized operation MUST NOT cause unrelated operations
  in the same message to be applied, and the message MUST be
  rejected atomically.
* A message MAY carry operations across multiple `kind`
  values. All operations are applied atomically with respect
  to `policy_version` advancement.

<a id="defined-rule-kinds"></a>

## Defined Rule Kinds
This revision defines three rule kinds:

| `kind` | Entry shape |
|---|---|
| `block` | Per-entity list item (block entry schema). |
| `accepted_sender` | Per-entity list item (accepted-sender schema). |
| `first_contact` | Singleton policy object (first-contact policy). |

For list-shaped kinds, each `entry` is identified by a unique
`id` (ULID RECOMMENDED), and `remove` and `modify` operations
reference the entry by `entry_id`.

For singleton-shaped kinds, only `modify` is meaningful;
`add` and `remove` MUST be rejected with `reason_code:
"policy_op_invalid"`.

## Accepted-Sender Entry Schema

An accepted-sender entry allows an entity to bypass
first-contact gating when sending to the owning recipient:

~~~ json
{
    "id": "accepted-sender-ulid",
    "entity": {
        "type": "user",
        "address": "trusted@example.com"
    },
    "created_at": "2026-06-10T20:17:10Z",
    "expires_at": null,
    "created_by_device_id": "device-ulid",
    "extensions": {}
}
~~~

## Storage Requirements

User policy state MUST be stored encrypted at rest. The
encryption applies uniformly to all rule kinds. The home
server MAY hold the encryption key and MAY decrypt policy in
volatile memory while processing inbound envelopes or
applying authenticated user updates, but MUST NOT write
decrypted policy to non-volatile storage, backups, or
disk-backed logs.

The threat model for this requirement is offline storage
compromise: theft of disks or backups, exposure of cold
archives, and forensic recovery from decommissioned
hardware. Encryption at rest does not protect against an
active in-memory compromise of the operating server, which
is outside the scope of this requirement.

# Reputation Signals

SEMP defines three reputation signals as inputs to
operator-defined policy:

Domain registration age:
: Publicly verifiable via WHOIS, resistant to retroactive
  manipulation.

Abuse rate:
: The ratio of reported abuse events to message volume over a
  domain's observed history.

Trust gossip:
: Signed observations that one server publishes about another
  domain's behavior.

## Observed Reputation

A domain does not control its own reputation. A domain's
reputation is the aggregate of observations held by every
server it has interacted with. Every SEMP envelope carries a
`seal.signature` produced by the sender's domain key, and
that signature is non-repudiable, so a server that receives
abusive traffic holds cryptographic proof of the sender's
behavior.

SEMP does not define or endorse any central reputation
authority, aggregation service, or blocklist provider.
Reputation is a peer-to-peer concern.

## Reputation Is Domain-Keyed

Every reputation signal, observation record, gossip fetch,
and abuse report defined in this document is keyed by domain
identity rather than by IP address. IP addresses are
transport-layer artifacts and MUST NOT appear as keys in any
protocol-layer reputation artifact.

A conformant server MUST:

* key every reputation ledger entry and published observation
  by domain;
* preserve a domain's accumulated reputation across changes
  of source IP;
* start unrelated SEMP domains that share a single hosting IP
  at independent zero reputation;
* accept federation from domains reached via Tor exit nodes
  or other anonymizing transports on the same terms as
  domains reached over conventional IP transport.

## Domain Registration Age

Servers SHOULD query WHOIS data as part of their policy
evaluation for any domain they have not previously observed.
This signal is the primary structural defense against
burn-and-rotate abuse.

Servers SHOULD apply automatic rate limiting to domains with
insufficient registration age, regardless of other signals.
The RECOMMENDED minimum threshold is 30 days. Rate limiting
under this rule SHOULD be combined with the proof-of-work
mechanism when available.

A new domain starts at zero reputation. Servers MUST NOT
reject messages from zero-reputation domains on the basis of
age alone without explicit operator configuration. Rate
limiting is not rejection.

<a id="proof-of-work"></a>

## Proof of Work
SEMP defines `proof_of_work` as a challenge type usable by
receiving servers to impose a per-envelope computational
cost on the sender. The cost is negligible for low-volume
senders and prohibitive for bulk senders. The challenge
type, parameter schema, solution submission format, and
verification procedure are defined normatively in
[Handshake](handshake.md). This section specifies the
reputation-facing considerations that apply when a server
chooses to require `proof_of_work`.

PoW is not scoped to zero-reputation or new domains. A
receiving server MAY require PoW from any sender as a matter
of operator policy, including established domains exhibiting
suspicious patterns, domains that have recently crossed an
abuse threshold, or any domain the operator chooses to
subject to additional friction.

<a id="pow-difficulty-calibration"></a>

### Difficulty Calibration
Difficulty is expressed as the number of leading zero bits
required in the SHA-256 hash of the solution. Each
additional bit doubles the expected computation required.

| Difficulty | Expected hashes | Approximate CPU time on contemporary hardware |
|---|---|---|
| 16 | 65,536 | under 1 ms |
| 20 | 1,048,576 | around 10 ms |
| 24 | 16,777,216 | around 150 ms |
| 28 | 268,435,456 | around 2.5 s |

Servers SHOULD use difficulty 20 as the default for
zero-reputation senders. Servers MAY increase difficulty for
senders that have previously submitted invalid solutions,
are within the domain age gate window, or are exhibiting
suspicious patterns regardless of reputation age.
Difficulty above 24 SHOULD be reserved for confirmed
suspicious behavior, as it imposes meaningful latency on
legitimate senders.

Servers MUST NOT issue a `proof_of_work` challenge with
difficulty greater than 28. The cap is defined normatively
in [Handshake](handshake.md) and prevents a malicious or
compromised server from exhausting client or peer resources
through prohibitively expensive challenges. A handshake
initiator that receives a challenge above the cap MUST abort
the handshake with `reason_code: "challenge_invalid"`.
Servers that require stronger gating than difficulty 28
provides MUST use blocking ({{block-list}}) or another
non-challenge mechanism rather than raising the difficulty
further.

Suggested difficulty by condition:

| Condition | Suggested Difficulty |
|---|---|
| Zero reputation, domain age below threshold | 20 |
| Zero reputation, domain age above threshold | 16 |
| Established domain, `suspicious` assessment | 20 to 24 |
| Established domain, `hostile` assessment | 24 to 28 |
| Operator policy (any domain) | Operator-configured, capped at 28 |

### PoW and Reputation

A valid PoW solution does not grant trust. It grants
permission to proceed with the handshake. The sender's
envelope is still subject to normal delivery policy, rate
limiting, and reputation evaluation. Servers MUST NOT treat
PoW completion as evidence of legitimacy. A bulk spammer
with sufficient compute can satisfy PoW, but doing so at
scale is expensive.

<a id="challenge-issuance-observations"></a>

### Challenge-Issuance Observations
A server that issues challenges MUST itself behave
reasonably. The difficulty cap and the minimum expiry table
bound each individual challenge, but the pattern of
challenges a server issues over time is itself a reputation
signal. A server that routinely issues challenges at or near
the cap to peers or clients without corresponding risk
indicators is degrading the performance of the ecosystem and
MAY be the subject of observation records published by
affected parties.

An initiator that aborts a handshake with `reason_code:
"challenge_invalid"` SHOULD record the event, including the
signed `challenge` message, for potential inclusion in an
abuse report. The signed challenge message is
self-authenticating evidence because it carries the issuing
server's domain signature.

A conformant server MAY publish an observation record
against a remote domain when it has observed, across
multiple unrelated handshakes within a single observation
window, both of the following:

1. A sustained share of that domain's issued challenges at
   `difficulty` greater than 24, measured against handshakes
   where the observing server or its users had no reputation
   condition that would justify elevated difficulty.
2. Either a challenge above the difficulty cap of 28, or a
   challenge whose `expires` value was below the minimum
   expiry floor for its difficulty.

The observation record MUST use the `protocol_abuse`
category ([Delivery](delivery.md)) and SHOULD include
one or more signed `challenge` messages as evidence under a
`signed_handshake_challenge` evidence type. The evidence
MUST NOT include any material derived from a session that
the observing server did not itself initiate or receive.

A server that issues challenges MUST be prepared for its
challenge pattern to be observed and reported. Operators
that wish to use aggressive challenge policy for defensible
reasons (a recent abuse surge from a specific network, for
example) SHOULD document the policy publicly so that peer
observations can be interpreted in context.

Servers MUST NOT publish observations based on a single
challenge in isolation. Pattern-based observation requires
multiple unrelated handshakes within the same observation
window.

# Abuse Reporting

Abuse reports flow from users to their home server. The home
server aggregates reports internally and uses them as input
to its own policy decisions and, optionally, as the basis
for trust gossip observations shared with other servers.

Users report to their own home server only. They do not
report directly to the sender's server. This protects the
reporter's identity from the abuser and keeps the reporting
relationship within the existing trust boundary.

## Abuse Report Schema

~~~ json
{
    "type": "SEMP_ABUSE_REPORT",
    "version": "1.0.0",
    "id": "report-ulid",
    "reporter": "user@example.com",
    "reported_domain": "offender.com",
    "reported_address": "spammer@offender.com",
    "category": "spam",
    "timestamp": "2026-06-10T20:30:00Z",
    "evidence": {
        "type": "envelope_metadata",
        "postmark_ids": ["01J4K7P2XVEM3Q8YNZHBRC5T06"],
        "count": 47,
        "window": "2026-06-10T19:00:00Z/2026-06-10T20:00:00Z"
    },
    "description":
        "Unsolicited bulk messages, 47 received in one hour.",
    "extensions": {}
}
~~~

## Abuse Categories

| Category | Description |
|---|---|
| `spam` | Unsolicited bulk messaging. |
| `harassment` | Targeted abusive or threatening content. |
| `phishing` | Impersonation or credential harvesting attempts. |
| `malware` | Messages containing or linking to malicious software. |
| `protocol_abuse` | Malformed envelopes, enumeration, handshake flooding, unreasonable challenge issuance, or similar. |
| `impersonation` | Sender falsely represents their identity or affiliation. |
| `observation_record_abuse` | Trust gossip observations published with adversarial content: oversized records, evidence-hash mismatches, hostile or non-conforming `evidence_uri` content, fabricated metrics, or systematic publication of unverifiable assessments. |
| `other` | Abuse not covered by defined categories. |

Additional categories MAY be defined in extensions using the
standard namespacing convention.

## Evidence Types

Envelope metadata evidence:
: Evidence derived from the postmark and seal (the public
  layer of the envelope). Independently verifiable by any
  party that can fetch the sender's published domain key. No
  decryption is required.

Sealed evidence:
: Full or partial envelope data (postmark, seal, and
  optionally fragments of the decrypted brief or enclosure)
  packaged as verifiable evidence. The seals are intact, so
  the sender's domain signature can be verified. Decrypted
  content is included only when the affected user has
  explicitly authorized disclosure.

A server MUST NOT disclose decrypted envelope content in
abuse evidence without the explicit, signed authorization of
the affected user. Unauthorized disclosure is itself a
violation of the protocol's privacy guarantees.

## Pattern Abuse vs Content Abuse

Pattern abuse:
: Spam, volume attacks, enumeration, protocol abuse. Provable
  entirely from postmarks and seals. No decryption required.
  The cryptographic proof is complete and carries no privacy
  cost.

Content abuse:
: Harassment, phishing, impersonation. Proving the abusive
  nature of the content requires revealing decrypted brief
  or enclosure material. This requires explicit
  authorization from the affected user.

<a id="trust-gossip"></a>

# Trust Gossip
Trust gossip is the mechanism by which servers share
observations about other domains. It is pull-based,
consistent with SEMP's approach to revocation, discovery, and
key fetching.

Editor's Note: This revision incorporates baseline schema
defenses ([Schema Limits and Evidence Binding](#observation-defenses)), a publication
eligibility threshold ([Publication Eligibility](#publication-eligibility)), and a
per-peer reciprocity expectation
([Reciprocity as Policy](#reciprocity-as-policy)). Several design questions
remain open and may produce changes in a future revision:

* Mechanisms for consumers to weight observations by
  observer credibility beyond per-record validation,
  including how to combine conflicting observations from
  peers of unequal credibility without violating SEMP's
  no-transitive-trust principle.
* Anti-Sybil controls beyond domain-key signing and
  minimum-interaction publication thresholds.
* Aggregation layers, including signed transparency logs,
  bloom-filter or sketch-based summaries, and other
  schemes that permit partial contribution and partial
  benefit. These are out of scope for this revision and
  may be defined as a separate extension specification.

The schema described below is sufficient to implement and
test. Future revisions MAY refine the schema and add new
defenses based on operational experience.

## Observation Record Schema

~~~ json
{
    "type": "SEMP_TRUST_OBSERVATION",
    "version": "1.0.0",
    "id": "observation-ulid",
    "observer": "reporting-server.com",
    "subject": "observed-domain.com",
    "kind": "abuse_rate",
    "window": {
        "start": "2026-05-01T00:00:00Z",
        "end": "2026-06-01T00:00:00Z"
    },
    "metrics": {
        "envelopes_received": 16384,
        "envelopes_rejected": 32,
        "abuse_reports": 8,
        "abuse_categories": ["spam", "phishing"],
        "unique_senders_observed": 512,
        "handshakes_completed": 1024,
        "handshakes_rejected": 16
    },
    "assessment": "neutral",
    "evidence_available": true,
    "evidence_uri":
        "https://reporter.example/v1/reputation/evidence/subject",
    "evidence_hash": {
        "algorithm": "sha-256",
        "value": "base64-digest-of-evidence-bytes"
    },
    "timestamp": "2026-06-01T12:00:00Z",
    "expires": "2026-07-01T12:00:00Z",
    "signature": {
        "algorithm": "ed25519",
        "key_id": "observer-domain-key-fingerprint",
        "value": "base64-signature-over-observation"
    },
    "extensions": {}
}
~~~

<a id="observation-defenses"></a>

## Schema Limits and Evidence Binding
An observation record on the wire MUST NOT exceed 16384
bytes (16 KiB) in canonical UTF-8 JSON form. Servers MUST
reject larger records as malformed and MUST NOT propagate
them to other peers.

When `evidence_available` is `true`, the observation MUST
carry an `evidence_hash` field bound into the signed
observation. The hash binds the cited evidence content to
the signed observation. A consumer that fetches
`evidence_uri` MUST compute the digest of the returned
bytes under `evidence_hash.algorithm` and MUST treat any
mismatch as a verification failure equivalent to a
signature failure. When `evidence_available` is `false`,
both `evidence_uri` and `evidence_hash` MUST be absent;
consumers MAY weight such observations lower than
evidence-bearing observations.

A consumer that fetches evidence content MUST treat the
returned bytes as untrusted input. The consumer MUST NOT
recursively fetch URLs or other references found within
the evidence content, MUST cap the fetched response size
to a locally-configured limit (RECOMMENDED 1 MiB), and
MUST parse the content in an isolated context that does
not expose the consumer's primary process state to
adversarial input. A consumer MAY refuse to fetch evidence
from observers below a locally-configured credibility
threshold.

## Observation Windows

Observations cover a defined time window. This prevents stale
assessments from persisting indefinitely. Observation windows
SHOULD be 30 days or less. An expired observation MUST be
treated as absent rather than as evidence of continued
behavior.

<a id="count-bucketing"></a>

## Count Bucketing
All integer-valued count metrics in an observation record
MUST be reported as powers-of-two buckets, not as raw counts.
The published value is the smallest power of two greater than
or equal to the raw count, drawn from the sequence:

~~~
0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048,
4096, 8192, 16384, 32768, 65536, 131072, 262144,
524288, 1048576
~~~

A raw count of `0` is published as `0`. A raw count of `1` is
published as `1`. A raw count in the range `[2, 2]` is
published as `2`. A raw count in the range `[3, 4]` is
published as `4`. The maximum published bucket is `1048576`;
raw counts greater than this threshold MUST be published as
`1048576`.

Bucketing reduces the effective resolution of published
metrics so that third parties observing multiple observation
records cannot intersect them to reconstruct the
correspondent graph at a resolution finer than the bucket
width.

Consumers MUST treat the published value as an upper bound of
the true count within the preceding bucket. An observer that
publishes `envelopes_received: 128` means "at least 65 and at
most 128 envelopes observed in the window".

`abuse_categories` is a deduplicated set of category
identifiers observed at least once during the window. The
published array MUST NOT contain duplicates: each category
appears zero or one times. Receivers MUST treat the array as
a set.

## Assessment Values

| Assessment | Meaning |
|---|---|
| `trusted` | Consistent good behavior observed over the window. Low or zero abuse. |
| `neutral` | Insufficient data or mixed signals. No strong conclusion. |
| `suspicious` | Elevated abuse rate or anomalous patterns. Warrants caution. |
| `hostile` | Sustained, verified abusive behavior. Evidence available. |

## Observation Kinds

| Kind | Subject |
|---|---|
| `abuse_rate` | Volume and severity of abuse reports attributed to the subject domain. |
| `delivery_outcomes` | Delivery success and rejection ratios observed by the publishing server. |
| `key_transparency` | Observations of the subject domain's key transparency log. See [Recovery](recovery.md). |

Additional kinds MAY be defined by future revisions or
extensions. Observation record consumers MUST ignore unknown
kinds rather than rejecting the containing record.

<a id="publication-eligibility"></a>

## Publication Eligibility
A server SHOULD NOT publish an observation about a subject
domain unless the observer has directly observed at least
16 envelopes (or an equivalent number of handshake
attempts) involving the subject during the observation
window. This threshold reduces the publication of
low-confidence assessments and limits the value of
manipulation by Sybil clusters that have not attracted
real traffic.

A server MUST NOT publish observations whose `metrics`
fields are uniformly zero. Such observations carry no
information beyond domain identity and would only serve
to bloat the gossip network.

## Observation Weighting

A consumer aggregating observations from multiple peers
SHOULD weight each observation by its locally-computed
credibility for the publishing observer. Inputs to local
credibility are implementation-defined and include:

* The rate at which the observer's `evidence_hash`
  values have resolved to verifiable evidence with seal
  signatures matching the subject's published key.
* Past alignment of the observer's assessments with the
  consumer's own direct experience of the subject.
* The schema conformance history of the observer's
  records (absence of oversized records, hash mismatches,
  or fabricated metrics).
* Observer domain-stability signals, such as
  registration age and key-rotation cadence.

Consumer credibility is per-consumer, local state. A
consumer MUST NOT publish or share credibility scores
about other observers as part of trust gossip or any
other SEMP wire artifact. Shared credibility scores would
introduce transitive trust between observers, which is
incompatible with the no-transitive-trust principle in
[Architecture](architecture.md). A consumer MAY use any
local algorithm (linear weighting, exponential decay,
Bayesian update, or other) to compute credibility, and
the choice of algorithm is not
interoperability-relevant.

# Trust Gossip Publication and Fetching

A server that publishes trust gossip MUST advertise a
`reputation` endpoint in its configuration document. The
advertised URL is the base URL for published observations:

~~~
GET <endpoints.reputation><subject-domain>
~~~

A server that does not advertise a `reputation` endpoint does
not publish trust gossip. Peers MUST NOT probe for
observations at any other path.

Response format:

~~~ json
{
    "subject": "observed-domain.com",
    "observations": [
        { }
    ]
}
~~~

Each element of `observations` is a complete
`SEMP_TRUST_OBSERVATION` record carrying its own `signature`
field. The response body itself is not separately signed: the
per-record signatures are sufficient. The fetching server
MUST verify every record's signature before use.

Trust gossip is pull-based. Servers are not required to fetch
or publish trust gossip. A server that makes all reputation
decisions based solely on its own direct observations is
fully compliant.

Servers MAY speculatively fetch and cache observations for
domains they interact with frequently, independent of any
pending delivery decision.

<a id="reciprocity-as-policy"></a>

## Reciprocity as Policy
A server that fetches trust gossip from peers SHOULD also
publish its own observations under its `reputation`
endpoint. Reciprocity is a per-peer policy choice: a peer
MAY refuse to serve trust gossip to a server that does not
publish, and a consuming server MAY weight observations
from non-publishing peers lower than observations from
publishing peers. The protocol does not mandate
enforcement of reciprocity, and operators MAY adopt
strict, lenient, or no reciprocity policy.

A peer that enforces reciprocity MUST disclose its policy
in its configuration document so that prospective
consumers can determine eligibility before fetching.

<a id="self-referenced-observations"></a>

## Self-Referenced Observations
A domain MAY publish a curated index of observations that
other domains have published about it. The index is a list
of references, not a claim: each referenced observation
remains independently signed by its observer, and a
consuming server MUST verify those signatures directly.

The index is served at the URL advertised in the
`reputation_references` field of the publishing domain's
configuration document ([Discovery](discovery.md)). A
domain that does not advertise `reputation_references` does
not self-publish references.

### Schema

~~~ json
{
    "type": "SEMP_REPUTATION_REFERENCES",
    "version": "1.0.0",
    "domain": "example.com",
    "references": [
        {
            "observer": "trusted-server-1.com",
            "uri":
                "https://trusted-server-1.com/v1/reputation/example.com",
            "fetched_at": "2026-06-10T12:00:00Z",
            "assessment": "trusted"
        },
        {
            "observer": "large-provider.net",
            "uri":
                "https://large-provider.net/reputation/example.com",
            "fetched_at": "2026-06-10T11:30:00Z",
            "assessment": "trusted"
        }
    ],
    "timestamp": "2026-06-10T20:00:00Z",
    "signature": {
        "algorithm": "ed25519",
        "key_id": "example-domain-key-fingerprint",
        "value": "base64-signature-over-references"
    }
}
~~~

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | MUST be `"SEMP_REPUTATION_REFERENCES"`. |
| `version` | string | Yes | Record format version (semver). |
| `domain` | string | Yes | The domain publishing the references. |
| `references` | array | Yes | Links to third-party observation records. See the Reference Entry Fields table below. |
| `timestamp` | string | Yes | ISO 8601 UTC timestamp of publication. |
| `signature` | object | Yes | Signature over the canonical bytes of the document with `signature.value` set to `""`, prefixed with `SEMP-REPUTATION-REFERENCES:`. |

Reference entry fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `observer` | string | Yes | Domain of the server whose observation is referenced. |
| `uri` | string | Yes | Full URI of the observation record. |
| `fetched_at` | string | Yes | ISO 8601 UTC timestamp of when the publishing domain last verified this URI. |
| `assessment` | string | No | The assessment value from the referenced observation at fetch time. Informational only; consumers MUST re-fetch and verify. |

### Self-Referencing Is Not Self-Reporting

The references document is a convenience index. It tells a
querying server where to look, not what to conclude. The
publishing domain is curating links, not making claims
about itself. Every referenced observation record is
independently signed by the observer that produced it, and
a consuming server MUST verify that signature directly. The
referencing domain cannot forge, modify, or misrepresent
the contents of the linked observation.

A domain will naturally reference its most favorable
observations. This is expected and not a problem. The
consuming server knows the references are curated, since
they are published by the subject domain rather than by a
neutral party. Operators MAY use self-references as a
starting point for reputation discovery while giving them
appropriate weight: useful for finding observers to query,
not authoritative as a reputation signal in themselves.

### Cold-Start Utility

Self-referencing is most valuable during the cold-start
period. When a consuming server encounters a new domain
for the first time and has no observations from its own
trust set, the new domain's references document provides a
set of leads: third-party servers that have published
observations. The consuming server can fetch those
observations, verify the signatures, and decide whether to
trust the observers. This does not shortcut the trust
process; it accelerates the discovery of relevant
observers.

<a id="trust-transfer"></a>

# Trust Transfer
When a domain changes ownership or rotates its domain
key, the trust history associated with the prior domain
key MAY be transferred to the new key through a
cryptographic handshake requiring both parties' private
keys. Trust transfer is permitted only through this
cooperative handshake. Unilateral transfer is not
possible: neither party alone can move trust to a new
key. This implements the cooperative-transfer rule for
trust in [Architecture](architecture.md).

Trust transfer is the mechanism by which SEMP handles
legitimate domain transitions (sales, mergers, key
rotations) without leaking trust to the wrong operator
and without forcing legitimate new operators to start
from zero. Both directions matter: a buyer of a
reputable domain cannot fully inherit its trust, and a
buyer of a disreputable domain cannot launder away its
history.

## Transfer Record Schema

~~~ json
{
    "type": "SEMP_TRUST_TRANSFER",
    "version": "1.0.0",
    "id": "transfer-ulid",
    "domain": "transferred-domain.com",
    "reason": "sold",
    "from": {
        "domain_key_id": "seller-domain-key-fingerprint",
        "signature": "base64-seller-signature-over-transfer",
        "signed_at": "2026-06-10T18:00:00Z"
    },
    "to": {
        "domain_key_id": "buyer-domain-key-fingerprint",
        "signature": "base64-buyer-signature-over-transfer",
        "signed_at": "2026-06-10T18:05:00Z"
    },
    "effective_at": "2026-06-10T18:05:00Z",
    "extensions": {}
}
~~~

## Transfer Record Fields

| Field          | Type     | Required | Description                                                       |
|----------------|----------|----------|-------------------------------------------------------------------|
| `type`         | `string` | Yes      | MUST be `"SEMP_TRUST_TRANSFER"`.                                  |
| `version`      | `string` | Yes      | SEMP protocol version (semver).                                   |
| `id`           | `string` | Yes      | Unique transfer identifier. ULID RECOMMENDED.                     |
| `domain`       | `string` | Yes      | The domain being transferred.                                     |
| `reason`       | `string` | Yes      | One of the enum values in [Transfer Reasons](#transfer-reasons).                   |
| `from`         | `object` | Yes      | Prior key holder's signed attestation.                            |
| `to`           | `object` | Yes      | New key holder's signed acceptance.                               |
| `effective_at` | `string` | Yes      | ISO 8601 UTC timestamp when the transfer takes effect.            |
| `extensions`   | `object` | No       | Transfer-related metadata.                                        |

<a id="transfer-reasons"></a>

## Transfer Reasons
| `reason`                    | Meaning                                                                                                          | Default carry-over class                   |
|-----------------------------|------------------------------------------------------------------------------------------------------------------|--------------------------------------------|
| `key_rotation`              | Same operator, new domain key. No change in control. Operator is rotating per [Discovery](discovery.md).     | Full                                       |
| `sold`                      | Ownership transferred to a new operator via commercial sale.                                                     | Asymmetric (see [Asymmetric Carry-Over](#asymmetric-carry-over)) |
| `merged`                    | Organizational merger: the new operator subsumes the prior operator's infrastructure.                            | Asymmetric (see [Asymmetric Carry-Over](#asymmetric-carry-over)) |
| `corporate_reorganization`  | Same corporate entity, legal restructure (spin-off, reincorporation, name change).                               | Full                                       |
| `inherited`                 | Ownership transferred due to dissolution, bankruptcy, or death of the prior operator.                            | Asymmetric (see [Asymmetric Carry-Over](#asymmetric-carry-over)) |
| `other`                     | Reason outside the enum. Observers MAY treat as `sold` for policy purposes.                                      | Asymmetric (see [Asymmetric Carry-Over](#asymmetric-carry-over)) |

`key_rotation` is the routine case: the operator is
rotating their domain key per the rotation schedule
in [Discovery](discovery.md). The transfer record
binds the prior key's trust history to the new key.
This is distinct from key revocation: a rotation with
transfer preserves continuity; a revocation without
transfer severs it.

Operators whose transfer does not fit the enum SHOULD
use `other` with an optional
`extensions["semp.dev/transfer-reason-note"]`
human-readable note. Observer policy defaults to
treating `other` conservatively.

## Transfer Publication

The transfer record MUST be published through the
`reputation_transfer` endpoint advertised in the
publishing domain's configuration document
([Discovery](discovery.md)). The endpoint is a base
URL, and the outgoing and incoming records are served at
the `out` and `in` sub-paths respectively. Let `<R>`
denote the URL value of the `reputation_transfer` field
in the configuration document. The two records are
retrieved as:

Outgoing record (record describing this domain's
transfer to a new key):

~~~
GET <R>/out
~~~

Incoming record (record describing a transfer from a
prior key to this domain):

~~~
GET <R>/in
~~~

For example, if `<R>` is
`https://example.com/v1/reputation/transfer`, the
outgoing record is fetched from
`https://example.com/v1/reputation/transfer/out`.

For `sold`, `merged`, and `inherited`, the transfer is
cross-domain (or cross-operator on the same domain).
Both the prior and new publishers MUST advertise and
serve their respective record for at least 2 years
after `effective_at`. This retention window is the
minimum period during which an observer newly
encountering the domain is expected to discover the
transition.

For `key_rotation` and `corporate_reorganization`,
both records are published on the same domain under
the respective keys. The same 2-year retention
applies.

A domain that does not advertise
`reputation_transfer` does not publish transfer
records. Absence of a transfer record at the
advertised endpoint MUST NOT be interpreted as
evidence that a transfer did not occur; it is
evidence that no transfer record is available for
observers at that endpoint.

## Transfer Verification

Any server that encounters a transfer record MUST
verify the chain:

1. Verify `from.signature` against the prior domain
   key, fetched from the domain's published key
   history or DNS.
2. Verify `to.signature` against the new domain key.
3. Confirm both signatures cover the same transfer
   `id`, `domain`, and `reason`.
4. Confirm `from.signed_at <= to.signed_at <=
   effective_at`.
5. Confirm `effective_at` is not in the future per
   the clock tolerance defined in
   [Extensions](extensions.md).

If any check fails, the transfer is invalid. Servers
MUST NOT honor an unverifiable transfer and MUST
record no continuity between the two keys.

<a id="asymmetric-carry-over"></a>

## Asymmetric Carry-Over
Transfer records have different default carry-over
behavior depending on `reason` ([Transfer Reasons](#transfer-reasons)).
The following rules are normative defaults; operators
MAY adjust them via policy, subject to the
constraints in [Immutability of Pre-Transfer Observations](#pre-transfer-immutability).

Negative observations always carry at full weight.
Any abuse reports, gossip observations, or policy
signals produced about the prior key during its
active period MUST continue to apply to the domain's
reputation after transfer, at full weight, regardless
of `reason`. Negative history does not decay under
transfer.

Positive observations carry with discount for
asymmetric reasons. For `sold`, `merged`, `inherited`,
and `other`, observers SHOULD discount transferred
positive reputation by at least 50% for the 90-day
cooldown period following `effective_at`. After the
cooldown, observers MAY restore full weight based on
post-transfer observed behavior.

Full carry-over for continuity reasons. For
`key_rotation` and `corporate_reorganization`, both
positive and negative observations carry at full
weight with no cooldown discount. These reasons
assert no change of operator; the transfer is an
administrative act.

The 90-day cooldown is the RECOMMENDED default.
Operators that prefer faster onboarding MAY apply
shorter cooldowns but MUST NOT treat newly
transferred positive reputation as if no transfer had
occurred. Operators that prefer more conservative
onboarding MAY extend the cooldown or refuse to honor
the transfer entirely.

<a id="pre-transfer-immutability"></a>

## Immutability of Pre-Transfer Observations
Observations published before `effective_at` about
the prior key's activity MUST NOT be retracted,
hidden, modified, or otherwise altered as a
consequence of a transfer. A transfer is a continuity
claim; it is not a redaction mechanism.

Publishers of observations MUST continue to serve
their prior observation records after a transfer of
the subject domain through the trust gossip
observation window. Observers fetching observations
about a domain whose key has been transferred MUST
retain pre-transfer observations at their original
timestamps.

A publisher who retracts or amends a prior
observation in response to a transfer MUST treat the
retraction as a new observation with the retraction
timestamp. The original observation is preserved in
the publisher's ledger.

## Observer Fetch Policy

A conformant server that federates with a domain for
the first time, or that encounters a domain key it
does not recognize on an already federated domain,
MUST fetch the `reputation_transfer` records at that
domain proactively and cache them. The cache SHOULD
be refreshed on expiry of the cached entry, and MUST
be re-fetched if the server receives a
`SEMP_TRUST_TRANSFER` reference it does not yet have.

Proactive fetch ensures that observers are aware of a
continuity claim before they make delivery decisions,
rather than discovering it only when they encounter
stale cached reputation.

## Fail-Open on Fetch Failure

If a server cannot fetch a transfer record (network
failure, 404, timeout, signature verification
failure), it MUST treat the domain as if no transfer
occurred. An inability to fetch MUST NOT be
interpreted as evidence that a transfer happened.

This rule prevents network partitions, denial of
service attacks on the publishing endpoint, or
deliberate endpoint suppression from creating phantom
transfers that would otherwise let a new operator
inherit reputation they did not sign for.

## Trust Transfer Security Considerations

Inherited abuse immunity:
: An operator cannot clean up a disreputable domain
  by purchasing and transferring it. Negative
  observations from the prior key carry at full
  weight. The new operator starts with the prior
  domain's negative history intact and must earn
  clean status through observed behavior
  post-transfer.

Reputation laundering across owned domains:
: An operator that controls multiple domains can
  issue transfers between their own keys. The
  protocol cannot distinguish this from a genuine
  third-party sale. Observers MAY weigh transfers
  with suspicion when the prior and new keys share
  infrastructure, registrant, or other correlatable
  signals. This weighting is policy.

Fraudulent transfer claims:
: A transfer record MUST be signed by both the prior
  and new keys. A unilateral transfer is
  cryptographically impossible. If the prior key is
  compromised, an attacker holding it can co-sign a
  transfer to a key they control, but the transfer
  is still publicly visible and subject to observer
  policy. Prompt revocation of a compromised prior
  key per [Discovery](discovery.md) supersedes
  any transfer the attacker might have published.

Observer disagreement:
: Observers are not required to honor any transfer.
  A domain that depends on its trust being honored
  across the network SHOULD prepare for divergent
  observer policies and SHOULD NOT assume universal
  continuity.

## Loss of Private Key

Loss of the domain private key without a transfer
record means permanent loss of the associated trust
history. There is no recovery path. Trust cannot be
forged, reassigned unilaterally, or reconstructed
from backup by an unauthorized party
([Architecture](architecture.md),
[Discovery](discovery.md)).

<a id="reason-codes"></a>

# Reason Code Registry
This document is the authoritative registry of all
machine-readable reason codes used across the SEMP protocol.
Each code is assigned to a layer, classified by
recoverability, and tied to specific sender behavior.

Implementations MUST use codes exactly as registered. Unknown
codes received from a peer MUST be treated as non-recoverable
unless the implementation has explicit knowledge of the
code's semantics through an extension.

Recoverability governs automated retry only. A non-recoverable
code means the sender server MUST NOT retry automatically. A
recoverable code means the sender server SHOULD retry after
taking the corrective action described.

## Handshake Reason Codes

These codes appear in `SEMP_HANDSHAKE` messages with
`step: "rejected"`.

| Code | Recoverable | Sender behavior |
|---|---|---|
| `blocked` | No | Surface to user. Do not retry. |
| `auth_failed` | No | Surface to user. Do not retry. |
| `policy_forbidden` | No | Surface to user. Do not retry. |
| `handshake_expired` | Yes | Re-handshake and retry. |
| `handshake_invalid` | Yes | Re-handshake and retry. |
| `no_session` | Yes | Establish new session and retry. |
| `rate_limited` | Yes | Back off and retry. |
| `challenge` | Yes | Solve the issued challenge and continue handshake. |
| `challenge_failed` | Yes | Request new challenge by restarting the handshake. |
| `challenge_invalid` | No | The challenge exceeds protocol bounds. Surface to user or operator. Do not retry. |
| `server_at_capacity` | Yes | Back off and retry later. |
| `version_unsupported` | No | Surface to user or operator. Do not retry under the same MAJOR. |
| `resumption_failed` | No | Perform a full handshake. MUST NOT retry with the same ticket. |
| `revoked` | No | The peer's published key has been revoked since ticket issuance or the session was established. Re-fetch the peer's keys before any further attempt. |

## Envelope Reason Codes

These codes appear in structured rejection responses to
envelope delivery attempts.

| Code | Recoverable | Sender behavior |
|---|---|---|
| `blocked` | No | Surface to user. Do not retry. |
| `seal_invalid` | No | Indicates a bug. Do not retry the same envelope. |
| `session_mac_invalid` | No | Indicates a bug or session mismatch. Re-handshake before retry. |
| `envelope_expired` | No | Recompose with new expiry if content is still relevant. |
| `envelope_size_exceeded` | No | Recompose with smaller envelope; do not retry the same payload. |
| `policy_forbidden` | No | Delivery refused for policy reasons. Surface to user. |
| `auth_failed` | No | An envelope-layer authentication check failed that is not covered by `seal_invalid` or `session_mac_invalid` (for example, a missing or malformed identity proof on a first-contact envelope). Surface to user. |
| `handshake_invalid` | Yes | Establish new session and resend. |
| `handshake_expired` | Yes | Establish new session and resend. |
| `no_session` | Yes | Establish new session and resend. |
| `server_unavailable` | Yes | Back off and retry. Do NOT switch to a different recipient address. |
| `extension_unsupported` | No | Surface unsupported extension key. Do not retry without renegotiating. |
| `extension_size_exceeded` | No | Reduce extension payload size. Do not retry the same envelope. |
| `scope_exceeded` | No | Submitting device's scoped certificate does not authorize the action. Do not retry without certificate update. |
| `scope_invalid` | No | Submitted certificate is malformed. Issuer must correct and reissue. |
| `certificate_expired` | No | Delegated device's certificate has expired. Primary device must renew. |
| `quota_exceeded` | Yes | Sender quota exceeded; back off and retry later. |

## Rekeying Reason Codes

| Code | Recoverable | Sender behavior |
|---|---|---|
| `session_expired` | No | Session has ended. Begin a fresh handshake. |
| `rekey_unsupported` | No | Remote party does not support in-session rekeying. Let session expire and re-handshake. |
| `rate_limited` | Yes | Too many rekey attempts. Back off within the session lifetime. |

## User Policy Reason Codes

| Code | Recoverable | Sender behavior |
|---|---|---|
| `policy_kind_unsupported` | No | Submitted operation carries an unrecognized `kind`. Do not retry without removing the unsupported operation. |
| `policy_op_invalid` | No | Operation combines a `kind` with a verb not valid for that kind. |
| `policy_version_stale` | Yes | Submitted `policy_version` is not greater than the current. Refresh and resubmit. |
| `policy_collision` | Yes | Submitted update has the same `policy_version` and `timestamp` as an already-accepted update. Refresh, generate a new `policy_version`, and resubmit. |

## Submission Status Values

These values appear in submission response messages from the
home server to the client. They are sender-side
classifications of per-recipient delivery outcomes.

| Status | Terminal | Meaning |
|---|---|---|
| `delivered` | Yes | Envelope accepted (wire `delivered`). |
| `rejected` | Yes | Recipient server explicitly refused (wire `rejected`). |
| `silent` | Yes | No wire acknowledgment received within the timeout. |
| `legacy_required` | Yes | Recipient domain does not support SEMP. SMTP fallback is possible. |
| `recipient_not_found` | Yes | No SEMP support and no MX records. |
| `queued` | No | Server accepted the envelope and will attempt delivery asynchronously. |

## Wire Delivery Acknowledgments

These are the wire-level values a recipient server may return
for an envelope delivery attempt:

| Wire Acknowledgment | Description |
|---|---|
| `delivered` | Recipient server accepted the envelope and will deliver it to the client. |
| `rejected` | Recipient server explicitly refused the envelope with a reason code. |

Silent mode (defined in [Silent Mode](#silent-mode)) produces no wire
response.

## Transport-Layer Status Codes

These codes are returned at the transport layer, below the
SEMP application layer. They appear as HTTP status codes in
the HTTP/2 and QUIC bindings and as equivalent
transport-level error signals in other bindings.

Transport-layer codes are distinct from SEMP reason codes. A
200 HTTP response with a SEMP rejection in the body is
normal operation: the transport succeeded but the
application rejected the message.

| HTTP Status | Transport meaning | Recoverable | Sender behavior |
|---|---|---|---|
| 200 | SEMP message processed. Application outcome is in the response body. | N/A | Parse the SEMP response and act on its reason codes. |
| 400 | Malformed SEMP message. Could not parse. | No | Fix the message. Do not retry the same payload. |
| 413 | Payload exceeds the server's `max_envelope_size`. | No | Reduce payload size or split content. |
| 429 | Transport-level rate limit. | Yes | Back off and retry. Distinct from SEMP `rate_limited`. |
| 503 | Server temporarily unavailable. | Yes | Back off and retry. |

### Transport Connection Failures

The following conditions are not wire codes but
transport-level failure states that implementations MUST
handle. They arise during the transport fallback procedure
defined in [Handshake](handshake.md).

| Condition | Meaning | Recoverable | Sender behavior |
|---|---|---|---|
| `connection_refused` | The remote server rejected the transport connection. | Yes | Attempt the next transport in the fallback order. |
| `connection_timeout` | No response within the transport timeout (RECOMMENDED 10 seconds). | Yes | Attempt the next transport in the fallback order. |
| `tls_handshake_failed` | TLS negotiation failed (certificate mismatch, expired, or untrusted). | No | Do not retry on this transport. Log and surface to operator. |
| `tls_version_rejected` | Remote server does not support TLS 1.2 or higher. | No | Do not connect. The server does not meet minimum requirements. |
| `subprotocol_rejected` | WebSocket server did not confirm the `semp.v1` subprotocol. | No | Attempt the next transport in the fallback order. |
| `transport_exhausted` | All mutually supported transports have been attempted and failed. | No | Surface as a delivery failure. Do not silently discard. |

These conditions are internal to the connecting
implementation. They are not transmitted on the wire and do
not appear in SEMP rejection messages. They govern the
transport fallback logic and determine when to escalate a
failure to the SEMP layer.

## Extension Codes

Additional codes MAY be defined in extensions using the
standard SEMP namespacing convention:
`"vendor.example.com/code-name"`. The namespace is a DNS
name controlled by the extension author, followed by `/`
and a lower-case identifier.

Core codes (those defined without a namespace) occupy the
unprefixed registry. Extension codes MUST use their
namespace in every wire occurrence. An unnamespaced code
that is not registered in this document MUST be rejected as
malformed.

For each extension code, the defining specification MUST
specify: the code's name within its namespace, the layer
at which it is used, whether the code is recoverable, the
sender behavior on receipt, and the conditions under which
a server MAY issue the code.

### Collision Avoidance

Extension codes MUST NOT collide with core codes. Extension
authors MUST choose names that are not listed in the core
registries above, including when the namespace prefix is
stripped, to avoid confusion with core codes in logs and
tooling.

Two extensions MAY define the same code name under
different namespaces; the namespace prefix disambiguates
them. Implementations MUST match on the full namespaced
string (`vendor.example.com/name`) and MUST NOT match on
the unprefixed name alone.

### Deprecation

An extension author that deprecates a code SHOULD continue
to document the code at its namespace URL with a
deprecation notice and a link to the replacement code, if
any. Implementations that have processed the deprecated
code in production SHOULD continue to handle it for at
least one year after the deprecation notice.

### Core Registry Extension

Adding a new code to the unprefixed (core) registry
requires a specification revision. Proposed codes SHOULD be
prototyped under an extension namespace first, and graduate
to the core registry only after interop experience
demonstrates their cross-vendor utility.

## Cross-Layer Code Reuse

Several codes appear at multiple protocol layers with
consistent semantics. When the same code appears at
multiple layers, the meaning is identical. Sender behavior
differs only in the context of the operation being
performed (session establishment versus envelope delivery
versus rekeying).

| Code | Appears in | Consistent meaning |
|---|---|---|
| `blocked` | Handshake, Envelope | Sender or domain is blocked. |
| `handshake_invalid` | Handshake, Envelope | Session has been invalidated. |
| `handshake_expired` | Handshake, Envelope | Session TTL has elapsed. |
| `no_session` | Handshake, Envelope | No valid session referenced. |
| `rate_limited` | Handshake, Rekeying | Rate limit exceeded. |
| `extension_unsupported` | Envelope, Handshake | A required extension is not understood by the recipient. |
| `extension_size_exceeded` | Envelope | An extensions object exceeds the layer size limit. |
| `scope_exceeded` | Envelope (submission) | Delegated device attempted an action outside its certificate scope. |
| `scope_invalid` | Device registration | Scoped device certificate is malformed, over-capped, or has an excessive lifetime. |
| `certificate_expired` | Envelope (submission), Handshake | Delegated device's scoped certificate has passed `expires_at`. |
| `resumption_failed` | Handshake | Resume step failed; client MUST fall back to full handshake. |

## Implementation Notes

All rejections carry both a machine-readable `reason_code`
and a human-readable `reason` string. Implementations MUST
NOT parse the `reason` string programmatically; only
`reason_code` governs behavior.

An implementation that receives a `reason_code` it does not
recognize MUST treat it as non-recoverable, surface the code
and the human-readable `reason` to the user or operator, and
log the unknown code for diagnostic purposes.

All codes are lowercase with underscores. Implementations
MUST perform case-sensitive matching.

# Security Considerations

For the consolidated adversary model under which this
section is evaluated, see [Architecture](architecture.md).

## Evasion Resistance

Delivery policy MUST be enforced on cryptographically
verified identifiers. A sender cannot evade a domain-level
policy entry by changing their display name or using a
different address format. Domain entries MUST match all
addresses from that domain.

## Sync Integrity

User policy sync messages MUST be signed by the originating
device. The home server and receiving devices MUST verify
signatures before applying updates. Unsigned or unverifiable
sync messages MUST be rejected.

<a id="receipt-liability"></a>

## Receipt Non-Repudiation and Operator Liability
A signed delivery receipt is a non-repudiable statement by
the recipient domain that it accepted a specific envelope at
a specific time. The sending user needs a portable artifact,
independent of the sending server's queue state, to prove
that attempted correspondence reached the recipient domain.

The property has consequences for recipient-domain operators:

* A receipt is evidence that the recipient domain processed
  the envelope. The receipt does not expose envelope
  contents (the enclosure remains sealed), but its existence
  is itself a data point.
* A receipt MUST NOT be issued for an envelope the recipient
  server did not in fact accept for delivery. A spurious
  `delivered` acknowledgment, issued to suppress retry
  pressure, produces a cryptographically binding false
  statement.
* Recipient operators MUST issue a receipt for every
  `delivered` acknowledgment, since making receipts optional
  would create an observable difference between
  receipt-issuing and non-issuing deliveries.

## Delegated Client Scope Enforcement

The sender's home server enforces permission scopes on
delegated clients at envelope submission time, before the
envelope enters the delivery pipeline. Scope enforcement is
a sender-side control. The recipient server is not aware of
whether the sending client was a full-access device or a
delegated service.

## Reputation Manipulation Resistance

Reputation observations are signed by the publishing
server's domain key. A receiver MUST verify the signature
before using the observation. Unsigned or unverifiable
observations MUST be discarded.

The signature is the only authenticator. A server's
reputation among its peers depends on the credibility of
those peers, which is itself subject to the same peer
observation mechanism.

## Synthetic Bounce Prohibition

The sending server MUST NOT generate a synthetic bounce
envelope addressed to the sending user or to any third party,
and MUST NOT transmit any message across federation in
response to a terminal delivery failure. Synthetic bounces
addressed to a claimed sender are a documented source of
backscatter abuse in prior message protocols and are
incompatible with SEMP's seal-based provenance model.

# Privacy Considerations

## User Policy Confidentiality

A user's policy state (block list, accepted-senders list,
first-contact mode, and any other rule kinds) is private. It
reveals sensitive information: harassment situations,
personal conflicts, invite-only relationships, security
concerns. Servers MUST NOT disclose policy contents to any
party other than the owning user's authenticated devices.

## Acknowledgment Type and Block Detection

When the recipient returns a `rejected` wire acknowledgment,
the sender learns delivery was refused and receives a reason
code. Whether the sender learns they are specifically
blocked, as opposed to rejected for another reason, depends
on the reason code returned. Servers MAY return a generic
reason code rather than `blocked` if revealing the specific
reason would itself be harmful.

When the recipient applies silent-mode disposition, the
sender's home server classifies the timeout as `silent` and
the sender cannot determine whether silence means a delivery
policy decision, the recipient is offline, or network
failure. Implementations MUST maintain consistent timing in
silent mode; timing variations that correlate with delivery
policy would leak information.

## Status Disclosure

Recipient status reveals availability information to senders.
A malicious sender could use status information to infer the
recipient's behavior patterns. The visibility rules above
mitigate this. The default visibility is `nobody`, ensuring
no status is disclosed unless the recipient explicitly opts
in.

## Reputation Gossip and Correspondent Graph Inference

Reputation observations published by servers include counts
of senders and envelopes observed from each peer domain.
Counts are published as power-of-two buckets per
[Count Bucketing](#count-bucketing). Third parties observing multiple
observation records cannot intersect them below the bucket
width, which reduces but does not eliminate domain-pair
correspondent-graph inference. The residual signal is
intentional: it preserves reputation utility while bounding
leakage.

## Compelled Disclosure

A home server that is compelled to disclose data can provide
the correspondent graph (visible because the server decrypts
briefs for delivery), stored delivery receipts (until pruned
per the retention rule above), and the user's block list. It
cannot provide envelope enclosure plaintexts, encryption
private keys, or recovery secrets, because it does not hold
them.

<a id="test-vectors"></a>

# Test Vectors
The cross-language test vector corpus at `vectors/v1.0.0/` of
the SEMP specification repository pins the byte-level behavior
of the constructions in this document. The following files
exercise delivery, receipts, reputation, and policy:

| File | What it pins |
|---|---|
| `delivery-status.json` | Submission-status-to-UI-state mapping, queued-to-final transitions, discovery-outcome dispatch, multi-recipient mixed outcomes, persistent silent counter behavior. |
| `delivery-receipt.json` | Signed delivery receipt path with the `SEMP-DELIVERY-RECEIPT:` prefix. |
| `rejection-codes.json` | Recoverability classification and sender behavior per reason code. |
| `recipient-status.json` | Status visibility rules; status MUST NOT influence the delivery decision. |
| `status-config.json` | `SEMP_STATUS` configuration record signed with the `SEMP-STATUS:` prefix. |
| `trust-observation.json` | `SEMP_TRUST_OBSERVATION` signature path, `evidence_hash` verification (positive + tampered cases), 16 KiB size cap rejection. |
| `reputation-references.json` | Subject-domain `SEMP_REPUTATION_REFERENCES` document signature path. |
| `publication-eligibility.json` | 16-envelope minimum + all-zero-metrics gate per §Publication Eligibility. |
| `abuse-report.json` | `SEMP_ABUSE_REPORT` carrying the `observation_record_abuse` category. |
| `user-policy.json` | `SEMP_USER_POLICY` signature path, `policy_version` monotonicity. |

# IANA Considerations

This document does not request new IANA registrations.
Reason codes, abuse categories, observation kinds, and
delivery acknowledgment values are governed by the registry
in [Reason Code Registry](#reason-codes). Extensions to those registries are
namespaced under DNS labels controlled by the extension
author and require no IANA action.

The media type `application/semp-receipt` referenced by the
signed delivery receipt is registered in
[Envelope](envelope.md).

# Acknowledgments

The author thanks the contributors to the SEMP specification
for review, design discussion, and prior-art analysis.

