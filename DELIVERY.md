# SEMP Delivery Specification

**Sealed Envelope Messaging Protocol**  
Status: Internet-Draft  
Version: 0.1.0  
Related: `DESIGN.md`, `HANDSHAKE.md`, `ENVELOPE.md`

---

## Abstract

The SEMP delivery specification defines the three acknowledgment types a
recipient server may return for any envelope delivery attempt, the obligations
of the sending server in tracking and surfacing delivery outcomes, the block
list structure and enforcement, and multi-device block list synchronization.

---

## 1. Acknowledgment Types

Every envelope delivery attempt produces exactly one of three acknowledgment
types. These are protocol-level outcomes, observable on the wire between
servers.

| Acknowledgment | Description                                                                 |
|----------------|-----------------------------------------------------------------------------|
| `delivered`    | The recipient server accepted the envelope and will deliver it to the client.|
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

The sending server MUST enforce a timeout on delivery attempts. After the
timeout elapses with no response, the delivery is marked `silent`. A timeout
of 30 seconds is RECOMMENDED for initial delivery attempts. Retry attempts
MAY use longer timeouts with exponential backoff.

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
(section 6). The server stores the current status and applies visibility rules
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

For use cases that require a richer automated response (such as a dedicated
service that composes context-aware replies), a client process running on a
dedicated device can hold the user's keys and respond to incoming envelopes
directly. This is an explicit trust delegation by the user, not a default
server behavior.

---

## 2. Delivery Pipeline

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

### 2.1 Cross-Domain Delivery Prerequisites

When an envelope is addressed to a recipient on a different domain, the sender's
server MUST establish a federation session before forwarding. The prerequisite
flow is:

1. **Discovery** — the sender's server performs the discovery flow defined in
   `DISCOVERY.md` section 5.1 to determine the peer's server address. This
   happens automatically for any domain, without requiring pre-configured peer
   lists (see `DISCOVERY.md` section 5.7).

2. **Domain key fetch** — the sender's server obtains the peer's domain signing
   key from `/.well-known/semp/domain-keys` on the resolved hostname (see
   `HANDSHAKE.md` section 5.3). The key is cached for subsequent handshakes.

3. **Federation handshake** — the sender's server opens a federation session
   with the peer via the four-message federation handshake defined in
   `HANDSHAKE.md` section 5. The session is cached and reused for subsequent
   deliveries to the same domain.

4. **Envelope forwarding** — the sender's server re-signs the envelope's
   `seal.session_mac` under the federation session's `K_env_mac`, then forwards
   it to the peer. The original `seal.signature` (sender domain proof of
   provenance) is preserved. The peer's server runs the full delivery pipeline
   (section 2) on the received envelope.

Federation sessions support automatic in-session rekeying at 80% of the
session TTL per `SESSION.md` section 3.1, keeping long-lived federation hops
alive without repeated handshakes.

---

## 3. Sender Policy and Blocking

The acknowledgment type a server returns for a given sender is determined by
its delivery policy for that sender. One common policy mechanism is a block
list. A block list maps sender entities to acknowledgment types.

The block list is one implementation of delivery policy. Servers MAY implement
other policy mechanisms (rate limiting, reputation thresholds, federation
rules) that also determine acknowledgment type. The protocol does not mandate
the policy mechanism, only the acknowledgment type that results from it.

---

## 4. Block List

### 4.1 Block Entry Schema

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

### 4.2 Block Entry Fields

| Field                  | Type           | Required | Description                                                        |
|------------------------|----------------|----------|--------------------------------------------------------------------|
| `id`                   | `string`       | Yes      | Unique identifier for this entry. ULID RECOMMENDED.                |
| `entity`               | `object`       | Yes      | The entity whose delivery is being controlled. See section 4.3.    |
| `acknowledgment`       | `string`       | Yes      | Acknowledgment type to return. One of: `rejected`, `silent`.       |
| `reason`               | `string`       | No       | User or operator defined reason label. Never transmitted externally.|
| `scope`                | `string`       | Yes      | One of: `all`, `direct`, `group`. See section 4.4.                 |
| `created_at`           | `string`       | Yes      | ISO 8601 UTC creation timestamp.                                   |
| `expires_at`           | `string\|null` | No       | ISO 8601 UTC expiry. `null` for permanent entries.                 |
| `created_by_device_id` | `string`       | Yes      | Device that created this entry.                                    |
| `extensions`           | `object`       | No       | Application-defined metadata. Never transmitted externally.        |

Note: `delivered` is not a valid value for `acknowledgment` in a block entry.
A block entry exists to restrict delivery; an entry that results in `delivered`
has no effect and SHOULD NOT be created.

### 4.3 Entity Types

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

### 4.4 Delivery Scope

| `scope`  | Applies to                                                                 |
|----------|----------------------------------------------------------------------------|
| `all`    | All envelopes from the entity.                                             |
| `direct` | Direct messages only. Group messages from the entity are not affected.     |
| `group`  | Group messages only. Direct messages from the entity are not affected.     |

---

## 5. Enforcement Points

### 5.1 Pre-Handshake

Before completing a handshake, the server checks whether the initiating party
matches a domain-level or server-level block entry. Individual user identity
is not available at this stage because it is encrypted in the handshake confirm step.

If a match is found:

- `acknowledgment: "rejected"`: reject the handshake at `step: "rejected"`
  with `reason_code: "blocked"`. No session is established.
- `acknowledgment: "silent"`: do not complete the handshake. No response
  is sent after the init message.

### 5.2 Post-Handshake Envelope Enforcement

After a session is established, block entries are checked at envelope receipt
following the delivery pipeline in section 2. Domain and server entries are
checked before `brief` decryption. User entries are checked after.

If a match is found, the server applies the acknowledgment type from the block
entry, returning an explicit rejection or going silent.

### 5.3 Internal Route Enforcement

When an envelope arrives via `SEMP_INTERNAL_ROUTE` from another partition
server within the same domain (`DISCOVERY.md` section 5.4), the receiving
partition server MUST execute the full delivery pipeline defined in section 2
and return an acknowledgment. The three acknowledgment types defined in
section 1 (`delivered`, `rejected`, `silent`) apply without modification.
Internal routing is not a bypass.

The receiving partition server enforces block list entries because it holds the
recipient's block list. The sending partition server cannot perform this check
and MUST NOT attempt to access or infer the recipient's block list.

All privacy constraints from section 7 apply across partition boundaries. A
`silent` acknowledgment on an internal route MUST maintain consistent timing
per section 7.2. The sending partition server MUST NOT disclose to the sending
client whether an envelope was blocked versus undeliverable for other reasons,
beyond what the acknowledgment type and reason code convey.

---

## 6. Multi-Device Synchronization

A user's block list must be consistent across all their registered devices.
Changes made on one device are propagated through the user's home server.

### 6.1 Sync Message Schema

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

### 6.2 Sync Rules

- Updates MUST be signed by the originating device's key.
- The home server MUST verify the signature before storing or propagating.
- `list_version` is a monotonically increasing counter per user. Updates with
  a lower version than the current known version MUST be rejected as stale.
- Conflicts (two devices modifying the same entry concurrently) are resolved
  by higher `list_version`. Equal versions resolve by later `timestamp`.
- The home server propagates accepted updates to all other registered devices
  on next connection.

### 6.3 Storage Requirements

Block lists MUST be stored encrypted at rest. The server MUST NOT be able to
read block list contents in plaintext. This protects the user in the event of
a server compromise.

---

## 7. Privacy Considerations

### 7.1 Block List Confidentiality

A user's block list is private. It reveals sensitive information: harassment
situations, personal conflicts, security concerns. Servers MUST NOT disclose
block list contents to any party other than the owning user's authenticated
devices.

### 7.2 Acknowledgment Type and Block Detection

With `rejected` acknowledgment, the sender learns delivery was refused and
receives a reason code. Whether the sender learns they are specifically
blocked, as opposed to rejected for another reason, depends on the reason
code returned. Servers MAY return a generic reason code rather than `blocked`
if revealing the specific reason would itself be harmful.

With `silent` acknowledgment, the sender cannot determine whether silence
means a delivery policy decision, the recipient is offline, or network failure.
Implementations MUST maintain consistent timing in silent mode; timing
variations that correlate with delivery policy would leak information.

### 7.3 Block List as an Attack Surface

Block list size or contents could be inferred through side channels.
Implementations SHOULD use encrypted storage and MUST NOT expose block list
size or contents through any observable interface.

### 7.4 Status Disclosure

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

## 8. Security Considerations

### 8.1 Evasion Resistance

Delivery policy MUST be enforced on cryptographically verified identifiers.
A sender cannot evade a domain-level policy entry by changing their display
name or using a different address format. Domain entries MUST match all
addresses from that domain.

### 8.2 Sync Integrity

Block list sync messages MUST be signed by the originating device. The home
server and receiving devices MUST verify signatures before applying updates.
Unsigned or unverifiable sync messages MUST be rejected.

### 8.3 Rate Limiting

Servers SHOULD rate-limit block list operations per user to prevent abuse,
for example automated mass operations that could be used to manipulate
delivery behavior at scale.

### 8.4 Delegated Client Scope Enforcement

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

## 9. Relationship to Other Specifications

| Specification | Relationship |
|---|---|
| `DESIGN.md` | Explicit rejection principle from section 2.3. Silent acknowledgment is a documented exception per section 2.6. |
| `HANDSHAKE.md` | Pre-handshake enforcement uses `step: "rejected"` with `reason_code: "blocked"`. Reason code system defined in section 4.1. |
| `ENVELOPE.md` | Post-handshake enforcement uses envelope rejection reason codes from section 9.3. Delivery pipeline order from section 7.2. |
| `DISCOVERY.md` | Internal route enforcement for same-domain multi-server delivery defined in section 5.4. Acknowledgment schema in section 5.4.1. |

---

*This document is an Internet-Draft. It is subject to revision prior to
finalization as a stable specification.*