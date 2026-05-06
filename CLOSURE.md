# SEMP Account Closure

**Sealed Envelope Messaging Protocol**  
Status: Internet-Draft  
Version: 0.2.0-draft  
Related: `KEY.md`, `DELIVERY.md`, `RECOVERY.md`, `MIGRATION.md`, `CLIENT.md`, `CONFORMANCE.md`

---

## Abstract

This specification defines how a SEMP user closes their account and
what happens afterward. Closure is expressed as ordinary key revocation
under the existing key lifecycle mechanism, with cascading cleanup of
account state. The protocol does not publish a distinct closure
artifact: a closed account is cryptographically indistinguishable from
an account whose user revoked their keys and did not publish
replacements.

---

## 1. Overview

### 1.1 Goals and Non-Goals

This extension specifies:

- A user-driven closure request.
- A grace period during which closure can be cancelled.
- Finalization effects at the end of the grace period.
- Ingress handling during the post-closure retention window.
- Local-part reassignment rules, aligned with `MIGRATION.md` section 6.

Out of scope:

- Operator-initiated account termination for policy reasons. Operators
  MAY apply their own account-termination policy outside this
  specification; the protocol does not distinguish the operational
  outcome from user-initiated closure.
- A public closure record or a dedicated discovery endpoint. Closure
  is observable only through the same channels as any other key
  revocation.
- Data retention policy on the home server. Retention is operator
  policy subject to local law.

### 1.2 Conformance Status

This specification is a RECOMMENDED optional core module. A SEMP
server MAY omit support. A server that claims closure support MUST
comply with every requirement in this document.

Optional core modules live alongside the base SEMP specification and
do not use the wire-level extension framework in `EXTENSIONS.md`.

### 1.3 Terminology

| Term                 | Definition                                                                                        |
|----------------------|---------------------------------------------------------------------------------------------------|
| Closure request      | A signed message from a full-access device asking the home server to close the account.          |
| Grace period         | Time between a closure request being accepted and finalization. The user MAY cancel during this window. |
| Finalization         | Irreversible closure: key revocation, certificate revocation, state cleanup.                     |
| Retention window     | Operator-defined period after finalization during which the local-part MUST NOT be reassigned.    |

---

## 2. Closure Request

### 2.1 Schema

```json
{
    "type": "SEMP_ACCOUNT_CLOSURE",
    "step": "request",
    "version": "1.0.0",
    "user_id": "alice@example.com",
    "requested_at": "2026-04-19T12:00:00Z",
    "grace_period_seconds": 2592000,
    "issued_by": "01JPRIMARY00000000000000000",
    "signature": {
        "algorithm": "ed25519",
        "key_id": "primary-device-key-fingerprint",
        "value": "base64-signature"
    }
}
```

### 2.2 Fields

| Field                   | Type      | Required | Description                                                                                 |
|-------------------------|-----------|----------|---------------------------------------------------------------------------------------------|
| `type`                  | `string`  | Yes      | MUST be `"SEMP_ACCOUNT_CLOSURE"`.                                                           |
| `step`                  | `string`  | Yes      | MUST be `"request"` for submission or `"cancel"` for cancellation.                          |
| `version`               | `string`  | Yes      | SEMP protocol version (semver).                                                             |
| `user_id`               | `string`  | Yes      | Full SEMP address of the account to close.                                                  |
| `requested_at`          | `string`  | Yes      | ISO 8601 UTC timestamp of the request.                                                      |
| `grace_period_seconds`  | `integer` | Yes      | User-requested grace period in seconds. Subject to operator bounds per section 3.1.         |
| `issued_by`             | `string`  | Yes      | `device_id` of the issuing full-access device.                                              |
| `signature`             | `object`  | Yes      | Signature over the canonical bytes of the request with `signature.value` set to `""`, prefixed with `SEMP-ACCOUNT-CLOSURE:` per `ENVELOPE.md` section 4.3. |

### 2.3 Authentication

The request MUST be signed by a full-access device key of the account.
A delegated device MUST NOT submit a closure request regardless of its
scope. A request whose `issued_by` refers to a delegated device MUST
be rejected with `reason_code: "scope_invalid"`.

The home server MUST verify that `user_id` matches the authenticated
account and that `issued_by` matches the authenticated device. A
submission mismatch MUST be rejected with `reason_code: "unauthorized"`.

### 2.4 Submission Flow

1. A full-access device composes the request and signs it.
2. The device submits the request to the home server over its
   authenticated client session.
3. The home server verifies signature, issuer authority, and
   `grace_period_seconds` bounds.
4. The home server marks the account as `closure_pending` with the
   computed finalization timestamp, but continues serving the account
   normally until finalization.
5. The home server returns acknowledgment to the submitter.

A second closure request submitted while one is already pending MUST
be rejected with `reason_code: "closure_pending"`. The user cancels
and re-requests if they want different parameters.

---

## 3. Grace Period

### 3.1 Duration Bounds

`grace_period_seconds` MUST be at least 604800 (7 days) and at most
7776000 (90 days). The RECOMMENDED default is 2592000 (30 days).
Operator policy MAY enforce a narrower range within these protocol
bounds but MUST NOT exceed them.

A grace period shorter than 7 days gives the user insufficient time to
discover unauthorized closure attempts. A grace period longer than 90
days ties up the local-part and prolongs user uncertainty.

### 3.2 Cancellation

During the grace period, the account operates normally: keys remain
valid, envelopes are delivered, delegates continue to function.

Cancellation is performed by any full-access device submitting a
`SEMP_ACCOUNT_CLOSURE` message with `step: "cancel"` and the same
`user_id`. Cancellation MUST be signed by a current full-access
device of the account.

Cancellation MAY also be performed by a device restored from the
recovery bundle per `RECOVERY.md`, when the pre-closure user has lost
their full-access devices but retains their recovery secret. In this
case, the restore flow produces a fresh full-access device whose
certificate is dated after `requested_at`; that device's cancellation
is valid.

On acceptance of a cancellation:

1. The home server clears the `closure_pending` marker.
2. The account continues normal operation indefinitely.
3. The home server MUST NOT log or retain the cancelled request
   beyond what is needed for ordinary audit.

### 3.3 User-Visible Behavior

The home server SHOULD surface the `closure_pending` state to every
authenticated client of the account so that the user sees a banner or
equivalent indicator on every device during the grace period. A user
who logs in on an unfamiliar device during an attacker-induced closure
needs the most visible possible cue that something is wrong.

---

## 4. Finalization

### 4.1 Timing

Finalization occurs at `requested_at + grace_period_seconds`. The home
server MUST finalize within a reasonable window after that timestamp
(RECOMMENDED within 1 hour). Finalization MUST NOT occur before the
timestamp under any policy.

### 4.2 Effects

At finalization, the home server MUST perform the following
atomically (from the perspective of subsequent operations):

1. Revoke the account's identity key with reason `superseded` per
   `KEY.md` section 8.
2. Revoke all active encryption keys of the account with reason
   `superseded`.
3. Revoke every scoped device certificate of the account per
   `KEY.md` section 10.3.7, using reason `delegated_role_ended`.
4. Terminate all active sessions belonging to any device of the
   account.
5. Drain the outbound queue: every non-terminal queue state record
   for this account MUST transition to `expired` per
   `DELIVERY.md` section 2.6.
6. Delete the recovery bundle per `RECOVERY.md` section 4.2.
7. Mark any in-flight migration records targeting this account as
   canceled. In-flight migration records originating from this
   account MUST be preserved in their current state; they are
   historical artifacts.
8. Retain the block list for the account according to operator
   policy. The block list MUST NOT be transmitted externally.
9. Cease serving SEMP operations on behalf of the account.

The revocation reason `superseded` is used for all revoked keys and
MUST NOT be replaced with an account-closure-specific reason. This
preserves indistinguishability between a closed account and a user
who has revoked their keys for other reasons.

### 4.3 No Public Closure Artifact

The protocol does not define a public closure record, a closure
discovery endpoint, or a closure-specific reason code visible to other
domains. The cryptographic trace of a closed account is identical to
the trace of a user who revoked their keys and did not publish
replacements. This is by design: account lifecycle events are not the
correspondents' business.

---

## 5. Ingress Handling After Finalization

### 5.1 During the Retention Window

An envelope arriving for the closed account during the retention
window (section 6.1) receives `reason_code: "policy_forbidden"`, the
same response non-existent addresses receive per `DELIVERY.md`
section 6.4. The home server MAY alternatively apply a `silent`
acknowledgment per `DELIVERY.md` section 1.3. Both preserve existence
indistinguishability per `DESIGN.md` section 2.7.

The home server MUST NOT return any reason code or body field that
specifically identifies closure. A sender cannot cryptographically
distinguish closure from any other form of recipient unavailability.

### 5.2 Sender Discovery of Closure

A sender's home server encountering `policy_forbidden` for an account
it had been successfully delivering to before SHOULD re-fetch the
recipient's keys as part of its retry logic. On observing that the
recipient's keys are revoked with no published replacement, the
sender's server terminates the envelope queue entry with the terminal
state `expired` per `DELIVERY.md` section 2.6.

The sending client surfaces the terminal outcome to the user. The
client MAY describe the result in plain language (for example
"Recipient is unreachable" or "Recipient's keys are no longer
published") but MUST NOT assert that the account has been closed
specifically, since the protocol does not publish that information.

### 5.3 After Local-Part Reassignment

After the retention window ends, the operator MAY reassign the
local-part per section 6. Ingress for the reassigned address is
evaluated against the new occupant's policy normally. The closed
account's cryptographic identity has no further effect.

---

## 6. Local-Part Reassignment

### 6.1 Retention Window

The home server MUST NOT reassign the closed local-part to a different
user until the retention window has elapsed. The retention window
begins at finalization and lasts at least 180 days (RECOMMENDED 365
days). Operators MAY retain longer per policy.

### 6.2 Reassignment Semantics

Reassignment is identical to a fresh registration under the normal
account creation flow. The new occupant has a new identity key, new
encryption keys, and no cryptographic relationship to the prior
occupant. Correspondents of the prior occupant MUST treat the new
occupant as a distinct identity per the key-change detection rules in
`CLIENT.md` section 3.3.

This matches the reassignment model in `MIGRATION.md` section 6.3.
Trust, block-list entries, and reputation bound to the prior
occupant's identity key do not transfer to the new occupant.

### 6.3 No Inherited Trust

Third-party domains that encounter the reassigned address with a new
identity key MUST NOT carry over any trust, known-correspondent
status, or reputation signal from the prior occupant. Binding is to
the identity key, not to the address string.

---

## 7. Recovery Implications

Recovery per `RECOVERY.md` interacts with closure as follows:

- **During grace period.** The recovery bundle remains published. A
  user who has lost their full-access devices but retains their
  recovery secret MAY restore and cancel the pending closure, per
  section 3.2.
- **At finalization.** The recovery bundle is deleted. Subsequent
  restore attempts fail because no bundle exists for the account.
  A user who did not cancel during the grace period cannot recover
  the closed account.
- **After reassignment.** A new occupant of the local-part has their
  own recovery bundle (if they publish one). The prior occupant's
  recovery material has no effect on the new occupant's account.

The recovery bundle is sensitive. The home server MUST delete the
bundle at finalization. Operators who retain internal copies for
legal hold MUST isolate such copies from the normal recovery endpoint
and MUST NOT serve them in response to recovery requests after
finalization.

---

## 8. Security Considerations

For the consolidated adversary model under which this section is
evaluated, see `THREAT.md`.

### 8.1 Unauthorized Closure Attempt

An attacker who has compromised a full-access device can submit a
closure request. Defense is the grace period: the legitimate user has
at least 7 days (by the section 3.1 minimum) to notice and cancel.
Cancellation requires a full-access device, and a user who has lost
access to all full-access devices can still cancel using a restored
device from the recovery bundle.

Clients SHOULD surface `closure_pending` state prominently on every
device, across every session, until the grace period ends or closure
is cancelled.

### 8.2 Race Between Closure and In-Flight Operations

Operations pending at the moment of finalization are handled as
follows:

- Queued outbound envelopes: drained to `expired` per section 4.2.
- Inbound envelopes in the delivery pipeline: the pipeline completes
  per its ordinary semantics; those delivered just before finalization
  are the recipient's last received envelopes. Envelopes arriving
  after finalization are rejected per section 5.1.
- In-flight migration: canceled per section 4.2. Migration
  counterparties observe ordinary cancellation through migration's
  existing mechanisms.

### 8.3 Operator Cooperation

Finalization is a server-side state transition. A hostile operator
could refuse to finalize a user's closure request. The user's remedy
is to leave the operator via `MIGRATION.md` and then close the new
account. A hostile operator cannot forge a closure request because
the request is signed by the user's full-access device key, which the
operator does not hold.

Conversely, an operator cannot unilaterally close a user's account
through this mechanism, because a closure request without a valid
user signature MUST be rejected. An operator who wishes to terminate
an account for operational reasons does so outside this specification
and cannot use the closure wire format to produce a user-attributed
closure.

### 8.4 Recovery Bundle After Closure

Deletion of the recovery bundle at finalization is required because
the bundle otherwise outlives the account and preserves a restore
path past the user's intent to close. An operator that retains the
bundle beyond finalization MUST isolate it from the recovery endpoint
so that the closure is enforceable.

---

## 9. Privacy Considerations

### 9.1 No Account Lifecycle Oracle

The specification deliberately avoids publishing closure-specific
artifacts. An observer cannot distinguish a closed account from a
dormant account whose user revoked their keys. This prevents account
lifecycle events (creation, closure, reactivation via reassignment)
from becoming observable to non-correspondents.

### 9.2 Retention Disclosure

Operators MAY publish their data retention practices through channels
external to SEMP (privacy policy, terms of service). The protocol
does not mandate a retention disclosure mechanism. Users sensitive to
retention SHOULD verify operator practices before relying on closure
to delete their content.

### 9.3 Block List Retention

The closed account's block list is private data. Operator retention
MUST respect the account owner's intent to close; retention for
operational audit is permitted but the block list MUST NOT be
transmitted externally, repurposed, or merged with any other user's
block list.

---

## 10. Conformance

### 10.1 Client Conformance

A client claiming closure support MUST:

- Compose `SEMP_ACCOUNT_CLOSURE` requests signed by a full-access
  device key.
- Surface the `closure_pending` state to the user on every device
  that can observe it.
- Offer cancellation through any full-access device.
- Not describe post-closure delivery failures as account closure in
  the user interface. The protocol does not distinguish closure from
  key revocation, and the client MUST NOT assert closure without a
  signal the protocol provides.

### 10.2 Server Conformance

A server claiming closure support MUST:

- Verify the closure request signature against a current full-access
  device of the account before accepting.
- Reject closure requests from delegated devices with
  `reason_code: "scope_invalid"`.
- Enforce `grace_period_seconds` bounds per section 3.1.
- Permit cancellation by any current full-access device of the
  account during the grace period.
- Finalize at `requested_at + grace_period_seconds`, not before,
  performing all effects in section 4.2.
- Revoke keys with reason `superseded`, not with any
  closure-specific reason.
- Not publish a closure record, a closure reason code, or a
  closure-specific discovery artifact.
- Delete the recovery bundle at finalization.
- Reject ingress for the closed account during the retention window
  with `reason_code: "policy_forbidden"` or `silent`, matching the
  response given to non-existent addresses.
- Not reassign the local-part before the retention window ends.
- Treat reassignment as a fresh registration with no inherited trust.

---

## 11. Relationship to Other Specifications

| Specification   | Relationship                                                                                            |
|-----------------|---------------------------------------------------------------------------------------------------------|
| `KEY.md`        | Finalization revokes keys using the existing mechanism in section 8. Revocation reason is `superseded`. |
| `DELIVERY.md`   | Ingress rejection uses `policy_forbidden` per section 6.4. Queue drain uses `expired` per section 2.6.  |
| `RECOVERY.md`   | Recovery bundle is deleted at finalization. Restore during grace period can cancel closure.             |
| `MIGRATION.md`  | Local-part reassignment rules parallel migration. In-flight migration records are canceled.             |
| `CLIENT.md`     | Client obligations mirror device-certificate issuance: full-access signature required.                  |
| `DESIGN.md`     | Honors existence indistinguishability (§2.7). Closed accounts are not distinguishable from dormant ones.|
| `CONFORMANCE.md`| This document's conformance requirements are referenced from `CONFORMANCE.md`.                          |

---

*This document is an Internet-Draft. It is subject to revision prior to
finalization as a stable specification.*
