# SEMP Session Specification

**Sealed Envelope Messaging Protocol**  
Status: Internet-Draft  
Version: 0.2.0-draft  
Related: `DESIGN.md`, `HANDSHAKE.md`, `KEY.md`, `ENVELOPE.md`

---

## Abstract

This specification defines the forward secrecy properties of SEMP sessions.
It covers the session key lifecycle from derivation through expiry, the rekeying
protocol for long-lived sessions, and the security guarantees that follow from
ephemeral key exchange. It also defines the constraints under which session keys
are stored, erased, and may not be recovered.

This document resolves the forward secrecy deferral noted in `HANDSHAKE.md`
section 6, `ENVELOPE.md` section 10.4, and `KEY.md` section 12.4.

---

## 1. Overview

SEMP sessions are established via ephemeral Diffie-Hellman key exchange during
the handshake defined in `HANDSHAKE.md`. The session secret and all keys derived
from it are scoped strictly to the session and erased when the session ends or
expires.

This provides **forward secrecy**: a future compromise of any long-term
key (domain key, identity key, or encryption key) cannot be used to decrypt
envelopes exchanged in past sessions. Each session's confidentiality rests
entirely on its ephemeral key material.

### 1.1 What "Forward Secrecy" Means in SEMP

An adversary who records encrypted SEMP traffic and later obtains a server's
long-term domain key learns:

- That sessions occurred between the two domains (visible from the TLS
  connection and postmark).
- The timing and approximate volume of those sessions.

The adversary does **not** learn:

- The contents of any brief or enclosure from past sessions.
- The session keys (`K_enc_c2s`, `K_enc_s2c`, `K_mac_c2s`, `K_mac_s2c`,
  `K_env_mac`) used in any past session.
- The identity of any client who participated in a past session (because
  identity is encrypted under the session secret in the handshake).

This guarantee holds as long as the ephemeral private keys used in the
handshake have been erased, which this specification requires.

### 1.2 Scope of This Specification

This specification covers:

- The session key lifecycle (derivation, use, expiry, erasure).
- The rekeying protocol for sessions approaching their TTL.
- Key erasure requirements for implementations.
- The security boundary between session keys and long-term keys.
- Post-quantum forward secrecy.

This specification does not redefine handshake message formats or the HKDF
derivation procedure. Those are defined in `HANDSHAKE.md` section 2.4. This
document defines what happens to the derived keys after the handshake completes.

---

## 2. Session Key Lifecycle

### 2.1 Derivation

Session keys are derived at the conclusion of the handshake (after message 2,
before message 3). The derivation is defined in `HANDSHAKE.md` section 2.4:

- **Input keying material**: shared secret from ephemeral key agreement
  (Kyber768 + X25519 for the `pq-kyber768-x25519` algorithm suite).
- **Salt**: `client_nonce || server_nonce`.
- **Info context**: `"SEMP-v1-session"`.
- **KDF**: determined by the negotiated algorithm suite. Both currently defined
  suites use HKDF-SHA-512 (RFC 5869). See `ENVELOPE.md` section 7.3.1 for
  suite definitions.

Six keys are derived:

| Key            | Length  | Purpose                                                              |
|----------------|---------|----------------------------------------------------------------------|
| `K_enc_c2s`    | 32 bytes| Encrypts client → server handshake messages.                         |
| `K_enc_s2c`    | 32 bytes| Encrypts server → client handshake messages.                         |
| `K_mac_c2s`    | 32 bytes| MACs client → server handshake messages.                             |
| `K_mac_s2c`    | 32 bytes| MACs server → client handshake messages.                             |
| `K_env_mac`    | 32 bytes| MACs all envelopes sent within this session (`seal.session_mac`).    |
| `K_resumption` | 32 bytes| Pre-shared key used to resume this session after disconnect (`HANDSHAKE.md` §2.8). |

Each key is derived as a distinct HKDF output label expansion. Labels MUST be
distinct per key to prevent cross-key substitution. The recommended labels are:

```
"SEMP-v1-session-enc-c2s"
"SEMP-v1-session-enc-s2c"
"SEMP-v1-session-mac-c2s"
"SEMP-v1-session-mac-s2c"
"SEMP-v1-session-env-mac"
"SEMP-v1-session-resumption"
```

All six expansions use the same HKDF PRK (the single HKDF-Extract output
over the ephemeral shared secret and nonce salt). The six Expand calls are
independent.

`K_resumption` is treated differently from the other five keys: it is
NOT used to encrypt or MAC messages within this session. Instead, the
server retains `K_resumption` (directly or indirectly via a resumption
ticket) so that it can be combined with fresh ephemeral DH material to
derive the key schedule of a later resumed session. See section 2.7
for the ticket lifecycle and section 2.8 for the forward-secrecy
analysis.

A server that does not support resumption MAY skip derivation of
`K_resumption` and MUST NOT issue resumption tickets.

### 2.2 Ephemeral Key Erasure

The ephemeral private key MUST be erased immediately after the shared secret
is computed. "Erased" means overwritten with zeros (or platform-equivalent
secure erasure) and freed from memory. The ephemeral private key MUST NOT be:

- Written to disk, swap, or any persistent storage.
- Logged, cached, or retained for debugging.
- Held in memory beyond the point where the shared secret is derived.

Implementations MUST treat the ephemeral private key as a single-use value.
If the shared secret computation fails, the ephemeral private key is still
erased. The handshake is aborted; a new ephemeral key pair is generated for
any retry.

The ephemeral public key is transmitted in the handshake and is not secret. Its
retention or disclosure after the handshake does not weaken forward secrecy.

### 2.3 Active Session State

While a session is active, the server holds the following state in memory:

| Field             | Description                                                  |
|-------------------|--------------------------------------------------------------|
| `session_id`      | ULID identifying this session.                               |
| `K_env_mac`       | Session MAC key for envelope verification.                   |
| `K_enc_c2s`       | Encryption key (client → server direction).                  |
| `K_enc_s2c`       | Encryption key (server → client direction).                  |
| `K_mac_c2s`       | MAC key (client → server direction).                         |
| `K_mac_s2c`       | MAC key (server → client direction).                         |
| `established_at`  | Timestamp when the session was accepted.                     |
| `expires_at`      | Timestamp when the session expires (established_at + TTL).   |
| `client_identity` | The authenticated client address (client sessions only).     |
| `peer_domain`     | The authenticated peer domain (federation sessions only).    |

This state MUST be held only in memory. It MUST NOT be written to disk,
replicated to secondary storage, or included in backups. A server restart
invalidates all active sessions; the sender's server is responsible for
re-establishing sessions after interruption, per `HANDSHAKE.md` section 4.5.

### 2.4 Session Expiry and Key Erasure

When a session expires (its TTL elapses) or is explicitly invalidated:

1. The session state listed in section 2.3 MUST be erased from memory using
   secure zeroing before the memory is freed.
2. The `session_id` MUST be retained in an expiry log for replay prevention
   (see section 5.2). Only the ID is retained, not any key material.
3. No key material from the expired session is transferred to any new session.

A session that has expired MUST NOT remain in a state where its keys could be
read from memory by an attacker with runtime memory access.

### 2.5 Concurrent Session Limits

Multiple sessions may exist simultaneously between the same pair of parties --
for example, a client that opens a new session before the previous one expires,
or a federation partner under high send volume. This section defines the bounds
under which concurrent sessions are permitted and how servers manage them.

#### 2.5.1 Client Sessions

A server MUST permit at most **one active session per authenticated client
identity** at a time. If a client initiates a new handshake while an existing
session for the same `client_identity` is active and unexpired, the server MUST
invalidate the older session before completing the new handshake.

The server MUST:
- Immediately erase the older session's key material per section 2.4.
- Retain the older `session_id` in the expiry log for replay prevention
  per section 5.2.
- Complete the new handshake normally.

The server MUST NOT maintain two concurrent sessions for the same authenticated
client identity. This eliminates ambiguity about which session keys are
authoritative for envelope MAC verification.

A client that receives `handshake_invalid` or `no_session` on an envelope send
while it believes its session is active SHOULD treat this as evidence that the
server has expired or superseded its session. The client MUST initiate a new
handshake rather than retrying the envelope under the now-invalid session.

The server does not push an invalidation message on the superseded session at
the moment of supersession. The design intent is that the client is itself the
party that initiated the new handshake: the client always knows which session
is current without server notification. Any continued use of the old session
after supersession indicates either a client defect or a second process under
the same `client_identity` that raced the first; in either case the server's
response of `handshake_invalid` or `no_session` is sufficient to redirect the
stale submitter to the current session. Servers MUST NOT push a
`session_superseded` or equivalent message on the old session; the old
session's key material is erased at supersession per section 2.4 and no
further authenticated message can be produced on it.

#### 2.5.2 Federation Sessions

For server-to-server federation sessions, a server MUST permit at most
**one active session per peer domain** at a time, subject to the same
invalidation rule as section 2.5.1: a new inbound federation handshake from a
domain that already holds an active session invalidates the prior session before
the new one is accepted.

Exception: if two federation servers simultaneously initiate handshakes to each
other (a race during startup or failover), both MUST detect the collision via
`session_id` comparison in the confirm step. The session whose `session_id`
sorts lower lexicographically MUST be abandoned; the other proceeds to
`accepted`. This is deterministic and requires no external coordination.

#### 2.5.3 Server-Side Memory Bounds

To prevent resource exhaustion, servers MUST enforce a bound on total concurrent
active sessions:

| Session type        | Recommended maximum                      |
|---------------------|------------------------------------------|
| Client sessions     | Configurable; default 10,000 per server  |
| Federation sessions | Configurable; default 1,000 per server   |

When the active session count reaches the configured limit, the server MUST
reject new handshake `init` messages with `reason_code: "server_at_capacity"`
until sessions expire or are invalidated. The server MUST NOT silently discard
the handshake; rejection must be explicit per the general rejection requirement
in `DESIGN.md` section 7.

Memory consumption per session is bounded by the state defined in section 2.3:
five 32-byte keys plus metadata. An implementation holding 10,000 client
sessions allocates approximately 2.5 MB of key material, exclusive of indexing
structures.

### 2.6 Client-Side Session State

Section 2.3 defines what the server holds. The client holds a corresponding
session context for the duration of the session. This section defines that
state, its storage constraints, and the client's obligations when the session
is lost or expires.

#### 2.6.1 Client Session State Fields

| Field            | Description                                                               |
|------------------|---------------------------------------------------------------------------|
| `session_id`     | ULID identifying this session. Included in every outbound envelope postmark. |
| `K_enc_c2s`      | Encryption key for client→server handshake messages.                      |
| `K_mac_c2s`      | MAC key for client→server handshake messages.                             |
| `K_env_mac`      | Session MAC key for all outbound envelope `seal.session_mac` values.      |
| `established_at` | Timestamp when the session was accepted by the server (step 4 of the handshake). |
| `server_ttl`     | TTL value communicated by the server in the `accepted` message, in seconds. |
| `expires_at`     | Locally computed: `established_at + server_ttl`. The client's best estimate of when the server will reject this session. |

The client does not hold `K_enc_s2c` or `K_mac_s2c` after the handshake
concludes, as those keys are used exclusively for server→client messages.
They MAY be held during the handshake exchange and MUST be erased once the
session is established and no further handshake messages are expected.

#### 2.6.2 Storage Constraints

Client session state MUST be held only in process memory. It MUST NOT be:

- Written to disk, including application caches, databases, or log files.
- Included in crash reports, bug reports, or analytics payloads.
- Synchronized to cloud backup services (iCloud, Google Drive, or equivalent).
- Retained across application restarts.

On application termination, the client MUST erase session key material using
secure zeroing before freeing memory. On platforms where secure zeroing is
unavailable, the client MUST overwrite the key bytes with random data before
deallocation.

#### 2.6.3 Backgrounding and Device Lock

On mobile and desktop platforms, the OS may suspend or checkpoint the
application when it is backgrounded or the device is locked. Client
implementations MUST handle these transitions:

**On backgrounding:** The client SHOULD erase session key material and treat
the session as ended. The session TTL is short enough that a session will
typically have expired by the time the app is foregrounded again. On resumption,
the client MUST initiate a fresh handshake rather than attempting to resume the
prior session.

**On device lock:** The client MUST erase session key material when the device
transitions to a locked state, consistent with the platform's secure enclave or
keychain erasure semantics. Session state MUST NOT be held in storage that
persists across a lock event.

Implementations MAY keep the session alive through a brief backgrounding if the
platform provides a reliable background execution window (e.g. a background task
with a known time bound). In that case, key material MUST be held in locked,
non-swappable memory for the duration, and MUST be erased when the background
window ends, regardless of whether the session TTL has elapsed.

#### 2.6.4 Detecting Session Expiry from the Client Side

The client does not control the server's TTL clock and cannot know with
certainty whether a session remains valid at the server. The client's
`expires_at` field is a local estimate. Divergence can occur due to clock skew,
server restart, or server-side invalidation per section 2.5.1.

The client MUST treat the following as definitive evidence that a session has
expired or been invalidated, regardless of its local `expires_at`:

- Receipt of `handshake_expired` in response to an envelope submission.
- Receipt of `handshake_invalid` or `no_session` in response to an envelope
  submission.
- Receipt of a `SEMP_HANDSHAKE` `rejected` message with any of the above
  reason codes during a rekey attempt.

On any of these signals, the client MUST:

1. Erase the current session state per section 2.6.2.
2. Initiate a fresh handshake.
3. Retry the envelope under the new session, up to the retry limits defined
   in `DELIVERY.md`.

The client SHOULD proactively initiate rekeying at 80% of `server_ttl` per
section 3.1, rather than waiting for a rejection. This minimises delivery
failures caused by session expiry racing with envelope sends.

The client MUST NOT assume a session is still valid beyond `expires_at`. If
`expires_at` has passed and the client has not yet completed a rekey, it MUST
treat the session as expired and begin a fresh handshake before sending any
further envelopes.

### 2.7 Resumption Ticket Lifecycle

A server that supports resumption (`HANDSHAKE.md` section 2.8) issues
a resumption ticket at the end of each accepted handshake and each
accepted resumption. The ticket is an opaque byte string that binds
the session's authenticated identity to the `K_resumption` derived
in section 2.1.

Servers MAY implement tickets in one of two ways:

- **Stateful ticket table.** The ticket value is a random
  identifier. The server maintains a table mapping the identifier to
  `{authenticated_identity, K_resumption, expires_at, additional context}`.
- **Stateless self-contained ticket.** The ticket value is an AEAD
  encryption of `{authenticated_identity, K_resumption, expires_at, additional context}`
  under a server-held ticket-encryption key. The server holds no
  per-client state.

The wire format treats the ticket as opaque; clients cannot
distinguish the two implementations and MUST NOT attempt to.

Tickets are single-use. On successful resumption acceptance the
server MUST invalidate the consumed ticket:

- Stateful: remove the entry from the ticket table.
- Stateless: record the ticket's identifier (or hash) in a
  consumed-ticket cache retained until past its `expires_at`.

A ticket `expires_at` MUST NOT exceed 7 days from issuance.
Stateful servers MUST delete the ticket's table entry no later than
its `expires_at`. Stateless servers rely on the embedded expiry for
rejection at the next presentation, but MUST still honor the cap
when issuing.

The ticket-encryption key used for stateless tickets is a long-term
server secret. The operator SHOULD rotate this key at least
quarterly to bound the exposure window of a leaked ticket-encryption
key. On rotation, outstanding tickets under the old key become
undecryptable and return `resumption_failed`, triggering
client-side full-handshake fallback. Operators MAY retain the
previous key for a short overlap window (RECOMMENDED one ticket
lifetime) to avoid mass fallback during rotation.

A server MAY decline to issue tickets (operator policy, resource
constraints, forward-secrecy-strict mode). In that case, the
`accepted` message omits `resumption_ticket`. A client that does
not receive a ticket MUST NOT attempt resumption against that
server in subsequent reconnects.

### 2.8 Resumption Forward Secrecy

Key derivation for a resumed session (`HANDSHAKE.md` section 2.8.3)
incorporates both the resumption secret from the ticket and a fresh
ephemeral DH output. This yields the following properties:

- An attacker who captures a resumption ticket (for example via
  device theft or a memory leak) but does not break the ephemeral DH
  assumption cannot derive the resumed session's keys.
- An attacker who passively observes the ephemeral DH exchange but
  does not obtain the ticket cannot derive the resumed session's
  keys, because the ticket's resumption secret is required.
- An attacker who obtains BOTH the ticket AND observations of the DH
  exchange derives the resumed session's keys only if the DH
  assumption is also broken. This matches the forward secrecy of a
  full handshake with the additional requirement that the ticket be
  obtained.

The ticket's bounded lifetime (at most 7 days) and single-use
consumption limit the window in which a compromised ticket has
value. An attacker must compromise both the ticket and, concurrently,
the DH exchange of the specific resumption attempt before the ticket
is either consumed by the legitimate client or expires. This is a
strictly smaller attack surface than any protocol without fresh DH
on resumption.

Long-term compromise of a server's ticket-encryption key (stateless
tickets) exposes all outstanding tickets under that key. The
mitigation is rotation per section 2.7; a server operator that
detects key compromise MUST rotate the ticket-encryption key and
invalidate all outstanding tickets issued under it. Clients observe
this as `resumption_failed` and fall back to full handshake.

---

## 3. Session Rekeying

Sessions approaching their TTL may be extended without full re-authentication
through a rekeying exchange. Rekeying generates fresh session keys while
preserving the authenticated session context established by the original
handshake.

### 3.1 When to Rekey

Implementations SHOULD initiate rekeying when a session has consumed 80% of
its TTL. For example, a session with a 300-second TTL SHOULD rekey at 240
seconds. The initiating party (client for client sessions, either server for
federation sessions) is responsible for timing the rekey.

Rekeying MUST NOT be initiated after the session has expired. An expired session
requires a full new handshake.

### 3.2 Rekeying Protocol

Rekeying uses a two-message exchange (`SEMP_REKEY`) over the existing
authenticated session channel. Both messages are encrypted and MACed using the
current session keys.

#### Message 1: rekey-init

Sent by the initiating party:

```json
{
    "type": "SEMP_REKEY",
    "step": "init",
    "version": "1.0.0",
    "session_id": "current-session-id",
    "new_ephemeral_key": {
        "algorithm": "pq-kyber768-x25519",
        "key": "base64-encoded-new-ephemeral-public-key",
        "key_id": "new-ephemeral-key-fingerprint"
    },
    "rekey_nonce": "base64-random-32-bytes"
}
```

This message is encrypted under the current `K_enc_c2s` (client-initiated) or
`K_enc_s2c` (server-initiated) and MACed under the corresponding MAC key. The
encryption proves the initiating party holds the current session keys --
no additional signature is required.

#### Message 2: rekey-accepted or rekey-rejected

Sent by the responding party:

```json
{
    "type": "SEMP_REKEY",
    "step": "accepted",
    "version": "1.0.0",
    "session_id": "current-session-id",
    "new_session_id": "server-generated-new-ulid",
    "new_ephemeral_key": {
        "algorithm": "pq-kyber768-x25519",
        "key": "base64-encoded-responder-ephemeral-public-key",
        "key_id": "responder-ephemeral-key-fingerprint"
    },
    "rekey_nonce": "echoed-rekey-nonce",
    "responder_nonce": "base64-random-32-bytes"
}
```

On rejection, `step` is `"rejected"` and the message carries `reason_code`
and `reason` fields. Reason codes for rekeying:

| Reason code        | Meaning                                                        |
|--------------------|----------------------------------------------------------------|
| `session_expired`  | The session expired before the rekey completed.                |
| `rekey_unsupported`| The remote party does not support in-session rekeying.         |
| `rate_limited`     | Too many rekey attempts within the session lifetime.           |

### 3.3 New Key Derivation

After the two-message exchange, both parties compute a new shared secret via
ephemeral key agreement (the same algorithm suite as the original handshake).
The new session keys are derived using the KDF specified by the negotiated
suite (HKDF-SHA-512 for both currently defined suites):

- **Input keying material**: new shared secret from the rekeying ephemeral
  key agreement.
- **Salt**: `rekey_nonce || responder_nonce`.
- **Info context**: `"SEMP-v1-rekey"` (distinct from the initial session info
  context to prevent cross-context key confusion).

The same five key labels are used as in the initial derivation (section 2.1),
applied to the new HKDF PRK.

### 3.4 Key Transition

Once the new keys are derived:

1. The new session is identified by `new_session_id`. The old `session_id` is
   retired.
2. Both parties MUST erase the old session keys using secure zeroing before
   switching to the new keys.
3. The rekeying ephemeral private keys MUST be erased immediately after the
   new shared secret is computed (same rule as section 2.2).
4. Envelopes in flight that reference the old `session_id` MUST be processed
   under the old keys if received before the transition deadline. Both parties
   SHOULD allow a brief transition window (RECOMMENDED: 5 seconds) during which
   both session IDs are accepted, to accommodate in-flight envelopes. After the
   transition window, the old session is fully retired.

A rekeyed session inherits the original session's `established_at` timestamp
for purposes of authentication audit logging. The new `expires_at` is
`rekey_accepted_at + original_TTL`.

### 3.5 Rekeying Limits

A session MUST NOT be rekeyed more than once per minute. Implementations MUST
enforce a maximum of 10 rekey events per session lifetime, regardless of TTL.
If the maximum is reached, the session is not extended further and a full new
handshake is required.

### 3.6 Design Rationale: Fixed TTLs and Adaptive Extension

An alternative design was considered in which sessions would be automatically
extended based on sustained non-abusive delivery, rewarding good behavior
with reduced handshake overhead. This was rejected for the following reasons:

**Forward secrecy degrades with session lifetime.** Every envelope within a
session shares the same derived key material. The longer a session lives, the
larger the window of exposure if session keys are compromised at runtime. Fixed
TTLs bound this window predictably. Adaptive extension makes the window
data-dependent and harder to reason about.

**Abuse detection is retrospective.** Whether a delivery is abusive cannot be
determined at delivery time. A message passes seal verification, session MAC
checks, and block list evaluation, but whether it constitutes spam,
harassment, or phishing is determined by the recipient's experience after
reading it. Extending a session based on "non-abusive delivery" means extending
it based on "nothing has been reported yet," which is a weaker signal than it
appears. A sophisticated attacker would send clean messages to extend the
session and exploit the extended window.

**Complexity without proportionate benefit.** Adaptive extension requires both
parties to agree on the extension algorithm, track extension state, handle
disagreements, and manage edge cases such as abuse reports arriving after an
extension was granted. This adds protocol complexity for a benefit already
achievable through simpler mechanisms.

**The recommended approach is operator policy and rekeying.** Servers already
control the session TTL through the `session_ttl` field in the `accepted`
message (`HANDSHAKE.md` section 2.7). A server that has a long-standing
federation relationship with a trusted domain can offer a longer TTL based on
reputation signals (12 hours instead of 5 minutes). This is an explicit
operator trust decision, not an algorithmic one. For sessions that need to
persist beyond their TTL, rekeying (sections 3.1 through 3.5) provides fresh
key material at a fraction of the cost of a full handshake, restoring forward
secrecy properties without re-authentication or capability negotiation.

The combination of reputation-informed TTLs and in-session rekeying achieves
the performance benefits of adaptive session extension without degrading the
forward secrecy model or adding protocol complexity.

---

## 4. Post-Quantum Forward Secrecy

SEMP's preferred algorithm suite is `pq-kyber768-x25519`, a hybrid combining
Kyber768 (a lattice-based key encapsulation mechanism) with X25519 (classical
elliptic curve Diffie-Hellman). This section describes how the hybrid produces
the session secret and what its forward secrecy properties are.

### 4.1 Hybrid Key Agreement

The hybrid performs two parallel key agreements and combines their outputs:

1. **Kyber768 encapsulation**: the initiating party encapsulates a secret
   under the responder's Kyber768 ephemeral public key, producing a Kyber
   shared secret `K_kyber` and a ciphertext.
2. **X25519 scalar multiplication**: both parties perform X25519 using their
   respective ephemeral key pairs, producing `K_x25519`.

The combined input keying material for HKDF is:

```
IKM = K_kyber || K_x25519
```

Concatenation order is fixed. Implementations MUST NOT vary the order, as
it would produce incompatible session secrets.

### 4.2 Security Properties

The hybrid provides forward secrecy against both classical and quantum
adversaries:

| Adversary model               | Protected by                          |
|-------------------------------|---------------------------------------|
| Classical adversary today     | X25519 ephemeral key agreement.       |
| Quantum adversary in future   | Kyber768 ephemeral key agreement.     |
| Both simultaneously           | Both; compromise of either alone is   |
|                               | insufficient to recover the secret.   |

The security of the hybrid degrades gracefully: if one component is broken,
the other still protects the session secret. This is the standard "harvest
now, decrypt later" threat model: an adversary who records traffic today and
gains quantum capability in the future cannot retroactively decrypt sessions
protected by Kyber768 ephemeral keys that have already been erased.

### 4.3 Algorithm Agility

Future algorithm suites MAY be defined by protocol revision. Algorithm
negotiation occurs during the handshake capability exchange
(`HANDSHAKE.md` section 2.2). Servers MUST prefer the strongest mutually
supported suite and MUST NOT downgrade to a suite that lacks post-quantum
components if both parties support one. Downgrade attempts are detectable
via the confirmation hash as described in `HANDSHAKE.md` section 6.3.

---

## 5. Security Considerations

For the consolidated adversary model under which this section is
evaluated, see `THREAT.md`.

### 5.1 Memory Safety

Session key material exists only in memory. Implementations MUST use
memory-safe data structures that:

- Cannot be read by other processes on the same host.
- Are zeroed before deallocation.
- Are not swapped to disk (use `mlock` or equivalent where available).
- Are not included in crash dumps or core files.

Where the platform supports it, implementations MUST call `mlock` (POSIX) or
`VirtualLock` (Windows) on memory regions holding session keys immediately
after allocation. If the call fails (due to privilege restrictions or ulimit
constraints), the implementation MUST log a startup warning identifying which
key types are unprotected and MUST NOT silently continue as if the lock
succeeded.

On platforms without memory locking primitives, the implementation MUST
surface the following in its documentation and, where applicable, its
operator-facing configuration output:

- Which key types are held in unlocked memory.
- The consequence: a host-level attacker with access to swap or a crash dump
  may recover session keys from terminated sessions.
- The mitigation available to operators: encrypted swap, disabled core dumps,
  and reduced session TTLs to narrow the exposure window.

Crash dump exclusion MUST be enforced at the process level where the OS
provides a mechanism (e.g. `prctl(PR_SET_DUMPABLE, 0)` on Linux,
`SetProcessMitigationPolicy` on Windows). If no such mechanism is available,
this MUST be documented alongside the memory locking limitation above.

### 5.2 Replay Prevention

Session IDs MUST be retained in an expiry log after the session ends, for a
duration equal to the maximum allowed `postmark.expires` window (one hour by
default, per `ENVELOPE.md` section 10.2). Retained IDs require negligible
storage (only the ULID string and its expiry timestamp).

A receiving server that sees a `postmark.session_id` referencing a retired
session MUST reject the envelope with `reason_code: "handshake_invalid"`.
This prevents an attacker from replaying a captured envelope after the session
has ended.

### 5.3 Key Isolation

Session keys MUST NOT be derived from, or used to derive, long-term key
material. Keys are derived from the ephemeral exchange, used for the duration
of the session, and erased. No session key material persists beyond the
session lifetime.

In particular, `K_env_mac` MUST NOT be used as input to any key derivation
beyond its defined MAC purpose. Any implementation that attempts to "export"
session key material for any purpose violates the forward secrecy guarantee.

### 5.4 Compromise of Long-Term Keys

Compromise of a server's long-term domain key after the fact has the following
effects:

| What the attacker can do                        | What the attacker cannot do                         |
|-------------------------------------------------|-----------------------------------------------------|
| Impersonate the domain in future sessions.      | Decrypt envelopes from past sessions.               |
| Forge `seal.signature` on new envelopes.        | Recover past session keys.                          |
| Spoof new handshakes.                           | Verify past `seal.session_mac` values.              |
| Read `K_brief` from future envelopes.           | Recover past `K_brief` or `K_enclosure`.            |

Past session keys were derived entirely from ephemeral material that no longer
exists. A long-term key compromise does not retroactively expose past sessions.

### 5.5 Relationship to TLS

SEMP sessions run over TLS connections. TLS provides transport encryption
independent of the SEMP session layer. The SEMP session layer provides
application-layer forward secrecy and session binding that are not dependent
on TLS session properties. An attacker who breaks TLS (by compromising a TLS
session key or certificate) gains access to the SEMP handshake and envelope
ciphertext, but not to the cleartext of envelopes, which are further encrypted
at the SEMP envelope layer under `K_brief` and `K_enclosure`.

TLS session resumption MUST NOT affect SEMP session validity. A resumed TLS
session does not resume a SEMP session. Each SEMP session requires a fresh
handshake regardless of TLS resumption state.

### 5.6 Side Channels

Implementations SHOULD use constant-time operations for all key comparisons
and MAC verifications. Timing side channels on `K_env_mac` verification could
allow an attacker to probe for valid session IDs. Standard HMAC implementations
in well-audited cryptographic libraries are generally constant-time; custom
implementations require explicit review.

---

## 6. Relationship to Other Specifications

| Specification  | Relationship                                                              |
|----------------|---------------------------------------------------------------------------|
| `DESIGN.md`    | Governing principles. Forward secrecy addresses the integrity and privacy goals in sections 2 and 4. |
| `HANDSHAKE.md` | Defines handshake message formats and the HKDF derivation procedure (section 2.4) that this specification governs the lifecycle of. Session rekeying uses the authenticated channel established there. The `session_ttl` field added to the `accepted` message (section 2.7) carries the TTL value that clients record per section 2.6.1 of this document. |
| `KEY.md`       | Long-term keys are used in the handshake identity proof. This specification defines the boundary at which session keys are independent from long-term keys (section 5.3). |
| `ENVELOPE.md`  | `K_env_mac` is used in `seal.session_mac` (section 4.3). `K_brief` and `K_enclosure` are envelope-layer keys; their forward secrecy is a consequence of the session key erasure defined here. |
| `CLIENT.md`    | Client-side session state obligations (section 2.6) are cross-referenced from `CLIENT.md` section 2.1. |

---

*This document is an Internet-Draft. It is subject to revision prior to
finalization as a stable specification.*