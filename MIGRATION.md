# SEMP Provider Migration

**Sealed Envelope Messaging Protocol**  
Status: Internet-Draft  
Version: 0.2.0-draft  
Related: `KEY.md`, `RECOVERY.md`, `ENVELOPE.md`, `DELIVERY.md`, `REPUTATION.md`, `DISCOVERY.md`

---

## Abstract

This specification defines how a user migrates their SEMP identity from
one provider to another while preserving correspondent relationships,
reputation, and access to prior correspondence. It specifies the
migration record format, the forwarding protocol during migration, the
local-part reassignment lockout, third-party domain verification rules,
and the distinction between cooperative and unilateral migration modes.

---

## 1. Overview

### 1.1 Problem Statement

A SEMP identity takes the form `user@domain`. Changing provider means
changing domain, which changes the identity. Without a defined
migration primitive, a user moving from `alice@old.example` to
`alice@new.example` arrives at the new address as a stranger to every
correspondent, with no reputation, no known-correspondent status, and
no forwarding from the old address.

This specification defines how a user carries forward:

- Correspondent relationships (known-correspondent status).
- Reputation accrued at the old address.
- The cryptographic proof that the new address is the same person.
- Inbound delivery during a transition window.

It does not define server-side archive transfer between providers. The
user's own client holds the user's archive and decryption keys.

### 1.2 Conformance Status

This specification is a RECOMMENDED optional core module. A SEMP server
MAY omit support. A server that claims migration support MUST comply
with every requirement in this document for the mechanisms it supports.

Optional core modules are full protocol modules that live alongside the
base SEMP specification. They define their own wire types and endpoints
and do not use the wire-level extension framework in `EXTENSIONS.md`.
See `EXTENSIONS.md` section 1 for the distinction.

A server advertises cooperative migration support via the `migration`
endpoint in its discovery configuration (`DISCOVERY.md` section 3.1.1).
Absence of the endpoint indicates the server does not participate in
cooperative migration. Unilateral migration requires no server
participation at the old domain.

### 1.3 Terminology

| Term                | Definition                                                                                 |
|---------------------|--------------------------------------------------------------------------------------------|
| Old address         | The user's SEMP address before migration, of the form `local-part@old.example`.            |
| New address         | The user's SEMP address after migration, of the form `local-part@new.example`.             |
| Old identity key    | The user's identity key active at the old address immediately before migration.            |
| New identity key    | The user's identity key active at the new address immediately after migration.             |
| Migration record    | Signed publication linking the old address and key to the new address and key.             |
| Cooperative migration | Migration in which the old provider participates and co-signs the migration record.      |
| Unilateral migration| Migration in which the old provider does not participate; the user alone drives it.        |
| Forwarding window   | Time period after migration during which the old provider forwards envelopes to the new address. |

---

## 2. Migration Modes

### 2.1 Cooperative Migration

In cooperative migration, the old provider participates. Both providers
and both identity keys sign the migration record. The old provider
operates a forwarding window (section 5) and revokes the old identity
key on publication of the record (section 8).

Cooperative migration produces the strongest trust claim. Third-party
domains that observe both domain signatures can be confident the
migration is not contested by either provider.

### 2.2 Unilateral Migration

In unilateral migration, the old provider does not participate. The
user drives the migration using their own identity key material. The
migration record carries the user's old identity key signature and the
new identity key and new provider signatures, but no old provider
signature.

Unilateral migration produces a weaker trust claim. Third-party domains
observe that whoever held the old identity private key authorized the
move, but cannot observe old-provider concurrence. Hostile provider
takeover attempts are deterred at the cryptographic layer: without the
old identity private key, the old provider cannot produce a competing
migration record under the user's name.

Unilateral migration is REQUIRED to be supported when the user retains
possession of the old identity private key (directly or via
`RECOVERY.md`). A user who has lost all access to the old identity
private key cannot migrate. Their only option is to start fresh at the
new address.

---

## 3. Migration Record

### 3.1 Schema

```json
{
    "type": "SEMP_MIGRATION",
    "version": "1.0.0",
    "record_id": "migration-ulid",
    "old_address": "alice@old.example",
    "new_address": "alice@new.example",
    "old_identity_key_id": "old-identity-key-fingerprint",
    "new_identity_key_id": "new-identity-key-fingerprint",
    "new_identity_public_key": "base64-ed25519-public-key",
    "migrated_at": "2026-04-18T12:00:00Z",
    "forwarding_window_until": "2026-10-15T12:00:00Z",
    "mode": "cooperative",
    "old_identity_signature": {
        "algorithm": "ed25519",
        "key_id": "old-identity-key-fingerprint",
        "value": "base64-signature"
    },
    "new_identity_signature": {
        "algorithm": "ed25519",
        "key_id": "new-identity-key-fingerprint",
        "value": "base64-signature"
    },
    "old_domain_signature": {
        "algorithm": "ed25519",
        "key_id": "old-domain-key-fingerprint",
        "value": "base64-signature"
    },
    "new_domain_signature": {
        "algorithm": "ed25519",
        "key_id": "new-domain-key-fingerprint",
        "value": "base64-signature"
    }
}
```

### 3.2 Fields

| Field                      | Type           | Required | Description                                                                       |
|----------------------------|----------------|----------|-----------------------------------------------------------------------------------|
| `type`                     | `string`       | Yes      | MUST be `"SEMP_MIGRATION"`.                                                       |
| `version`                  | `string`       | Yes      | Record format version (semver).                                                   |
| `record_id`                | `string`       | Yes      | Unique identifier for this record. ULID RECOMMENDED.                              |
| `old_address`              | `string`       | Yes      | Full SEMP address before migration.                                               |
| `new_address`              | `string`       | Yes      | Full SEMP address after migration.                                                |
| `old_identity_key_id`      | `string`       | Yes      | Fingerprint of the identity key active at the old address at time of migration.   |
| `new_identity_key_id`      | `string`       | Yes      | Fingerprint of the identity key active at the new address at time of migration.   |
| `new_identity_public_key`  | `string`       | Yes      | Base64-encoded new identity public key, carried inline so verifiers can bootstrap without a separate key fetch. |
| `migrated_at`              | `string`       | Yes      | ISO 8601 UTC timestamp of migration.                                              |
| `forwarding_window_until`  | `string\|null` | Yes      | ISO 8601 UTC timestamp at which the forwarding window ends. `null` if no forwarding is offered (unilateral mode where old provider is non-cooperative). |
| `mode`                     | `string`       | Yes      | One of: `cooperative`, `unilateral`.                                              |
| `old_identity_signature`   | `object`       | Yes      | Signature produced by the old identity private key.                               |
| `new_identity_signature`   | `object`       | Yes      | Signature produced by the new identity private key.                               |
| `old_domain_signature`     | `object`       | When `mode == cooperative` | Signature produced by the old provider's domain signing key.          |
| `new_domain_signature`     | `object`       | Yes      | Signature produced by the new provider's domain signing key.                      |

### 3.3 Canonical Bytes and Signature Order

Each signature is computed over the canonical UTF-8 JSON encoding of the
record with:

- Keys sorted lexicographically at every level.
- The signing signature's `value` set to `""`.
- All other signatures present at their final values.
- No insignificant whitespace.

Signatures are added in the order: `old_identity_signature`,
`new_identity_signature`, `new_domain_signature`, `old_domain_signature`.
Each signature binds the record fields and all prior signatures. A
verifier MUST verify in the same order.

### 3.4 Publication

The migration record is published at the new provider via the
`migration` endpoint (section 6). The new provider MAY also include
the record in responses to key fetches for the new address, as an
optional `migration_from` field in the `SEMP_KEYS` response.

In cooperative mode, the old provider MUST also publish the record via
its own `migration` endpoint and MAY include a `migration_to` field in
responses to key fetches for the old address.

Once published, a migration record is immutable. A new migration record
MUST NOT replace an existing record; the user must publish a successor
record pointing to the new target address if they migrate again.

---

## 4. Cooperative Migration Flow

### 4.1 Sequence

1. User decides to migrate to `new.example`.
2. User registers `alice@new.example` at the new provider, generating a
   new identity key and encryption key per `CLIENT.md` section 2.2.
3. User composes a migration record (section 3.1) with `mode: "cooperative"`
   and an agreed `forwarding_window_until`.
4. User signs with the old identity private key
   (`old_identity_signature`).
5. User signs with the new identity private key
   (`new_identity_signature`).
6. New provider verifies the two identity signatures, then signs with
   its domain key (`new_domain_signature`).
7. New provider submits the record to the old provider's `migration`
   endpoint.
8. Old provider verifies all three signatures, confirms the old
   identity key is active and matches `old_identity_key_id`, and signs
   with its domain key (`old_domain_signature`).
9. Both providers publish the complete record and begin honoring
   forwarding (section 5).
10. Old provider publishes a revocation record for the old identity
    key with `reason: "migrated_to"` and `replacement: new_address`
    per `KEY.md` section 8.

### 4.2 Old Provider Obligations (Cooperative)

The old provider MUST:

- Verify all signatures on the submitted record before countersigning.
- Publish the signed record at its `migration` endpoint.
- Honor the forwarding window per section 5.
- Refuse to reassign the old local-part per section 6.
- Revoke the old identity key on publication per section 8.

The old provider MUST NOT:

- Modify the record after the user has signed it.
- Co-sign a record whose `old_identity_signature` does not verify
  against the identity key currently published at the old address.
- Countersign a second migration record for the same old address while
  a prior record is in its forwarding window.

---

## 5. Forwarding During Migration

### 5.1 Forwarding Window

In cooperative migration, the old provider forwards envelopes addressed
to the old address to the new address until `forwarding_window_until`.
The RECOMMENDED forwarding window is 180 days. Windows shorter than 30
days MUST NOT be accepted by a conformant old provider. Windows longer
than 730 days (two years) MAY be declined by the old provider.

### 5.2 Forwarding Mechanism

Forwarding uses the forwarding primitive defined in `ENVELOPE.md`
section 6.6. For each envelope received for the old address, the old
provider acts as a forwarder:

1. Delivers the envelope to the user's still-registered client on the
   old provider, if any client is still authenticated there, so the
   client performs the forward as a normal user-initiated forward.
2. If no client is authenticated, the old provider MAY perform a
   delegated forward on behalf of the user. Delegated forwarding
   requires a signed authorization produced by the user's identity key
   at migration time. The authorization SHOULD be carried in the
   migration record as an optional `forwarding_authorization` extension
   field.

In both cases, the forward carries `enclosure.forwarded_from.original_enclosure_plaintext`
with the original sender's inner signature intact. The new recipient at
the new address verifies original-sender provenance per `ENVELOPE.md`
section 6.6.4.

The old provider MUST NOT decrypt the enclosure to perform forwarding.
Forwarding is either performed by a still-active client that holds the
enclosure key, or is performed by re-enveloping the sealed payload under
the new recipient's key using a pre-authorized delegation. The exact
mechanism for the delegated path is defined in a future revision of
this specification.

### 5.3 Post-Window Bounce with Migration Notice

After `forwarding_window_until`, the old provider MUST stop forwarding
and MUST return a `rejected` acknowledgment with
`reason_code: "policy_forbidden"` for envelopes addressed to the old
address. The rejection response MUST include a `migration_notice` field:

```json
{
    "type": "SEMP_ENVELOPE",
    "step": "rejected",
    "reason_code": "policy_forbidden",
    "reason": "Recipient has migrated.",
    "migration_notice": {
        "new_address": "alice@new.example",
        "migration_record_id": "migration-ulid",
        "migration_record_url": "https://new.example/.well-known/semp/migration/<record_id>"
    }
}
```

The sending client MUST surface the migration notice to the user and
MUST NOT automatically redirect correspondence without user
confirmation per `CLIENT.md` section 3.3. The user updates their
correspondent record and resends to the new address.

### 5.4 Unilateral Migration and Forwarding

In unilateral migration, the old provider does not forward. The
migration record's `forwarding_window_until` is `null`. Envelopes to
the old address receive the old provider's default rejection response
without a `migration_notice` body, since the old provider is not a
participant.

The user SHOULD announce the new address via out-of-band channels and
through existing correspondents in-band (by sending an envelope from
the new address carrying the migration record in an extension field).

---

## 6. Local-Part Reassignment

### 6.1 Lockout During Forwarding Window

The old provider MUST NOT reassign the migrated local-part to any other
user while `forwarding_window_until` has not been reached. Any attempt
to register the migrated local-part during the window MUST be rejected
with `reason_code: "policy_forbidden"`.

### 6.2 Post-Window Reassignment

After `forwarding_window_until`, the old provider MAY reassign the
local-part. Reassignment MUST be treated as registration of a new
account with no relationship to the migrated account.

The migration record remains published. The old provider MUST continue
to serve the migration record through its `migration` endpoint as
historical evidence of the prior occupant.

### 6.3 No Inherited Standing

A subsequent occupant of the old local-part has a distinct identity
key. Third-party domains, when they observe an envelope from the old
address with an identity key that differs from the migration record's
`old_identity_key_id`, MUST treat the sender as a new identity without
any inherited known-correspondent status, reputation, block-list entry,
or other trust artifact that was bound to the migrated identity.

A correspondent client receiving an envelope from the old address
after migration MUST apply the standard key-change detection rules in
`CLIENT.md` section 3.3. The client MUST surface the key change to
the user and MUST require explicit confirmation before treating the
sender as a known correspondent.

Third-party domains MUST NOT use a cached known-correspondent flag for
the old address as a bypass for first-contact gating
(`DELIVERY.md` section 6.4) on an envelope whose sender identity key
does not match the migrated identity key.

---

## 7. Third-Party Domain Policy

### 7.1 Verification

A third-party domain verifying a migration record MUST:

1. Fetch the record from the new provider's `migration` endpoint, or
   accept a record delivered inline in a received envelope's
   extensions.
2. Verify `old_identity_signature` against the identity key record
   published for the old address (current or historical) at
   `old_identity_key_id`.
3. Verify `new_identity_signature` against `new_identity_public_key`.
4. Verify `new_domain_signature` against the new provider's current
   domain signing key.
5. For `mode: cooperative`, verify `old_domain_signature` against the
   old provider's current domain signing key.
6. Verify that `migrated_at` is not in the future and not earlier than
   `old_identity_key`'s creation timestamp.

If any verification fails, the domain MUST treat the record as
unverified and MUST NOT apply any carry-over policy based on it.

### 7.2 Known-Correspondent Preservation

A third-party domain that verifies a migration record for a user whose
address is in its users' known-correspondent lists SHOULD update those
lists so that the new address is recognized as known for the same users
who had the old address as known.

The update MUST be conditional on the sender's envelope carrying the
migrated identity key. An envelope from the new address whose sender
identity key does not match `new_identity_key_id` MUST NOT receive
known-correspondent status through this mechanism. An envelope from the
old address whose sender identity key does not match
`old_identity_key_id` MUST NOT receive known-correspondent status for
the post-migration period through this mechanism.

### 7.3 Reputation Carry-over

A third-party domain MAY carry over reputation signals accumulated for
the old address to the new address on verification of a migration
record. Reputation carry-over is a per-domain operator decision.
Domains that do not carry over reputation MUST treat the new address
as a zero-reputation domain member per `DESIGN.md` section 5.4.

Reputation carry-over is bound to the identity-key pair in the
migration record, not to the address strings. A mismatched identity
key on any future envelope invalidates the carried reputation for that
envelope.

### 7.4 Block-List Migration

Block-list entries (`DELIVERY.md` section 5) targeting the old address
SHOULD be migrated by the third-party domain to also target the new
address when a migration record is verified. The migrated block entry
MUST preserve the original `entity` type, `acknowledgment`, `reason`,
and `scope`, and MUST record the migration event in its `extensions`
for audit purposes.

A user MAY explicitly disable block-list migration in their own domain
by operator configuration. This operator choice is local and is not
visible across federation.

---

## 8. Old Identity Key Revocation

In cooperative migration, the old provider MUST publish a revocation
record for the old identity key upon publication of the migration
record. The revocation record uses the standard form defined in
`KEY.md` section 8.1 with:

- `reason`: `"migrated_to"`
- `replacement`: the new address (`"alice@new.example"`)
- `migration_record_id`: the `record_id` of the migration record

In unilateral migration, the user MAY revoke the old identity key if
they retain the private key. If the user cannot or does not revoke, the
old identity key remains valid at the old address until it expires
under its normal lifetime or is revoked by the old provider for other
reasons. In that case, the migration record is the only
protocol-visible signal of the move.

---

## 9. Security Considerations

### 9.1 Hostile Old Provider

An old provider that acts in bad faith (refuses to cooperate, refuses
to forward, refuses to revoke) cannot prevent migration. The user
executes a unilateral migration using their old identity private key.
The old identity private key is the essential credential; provider
cooperation is not.

A hostile old provider retains the ability to refuse forwarding, which
means envelopes from correspondents who have not yet updated their
records are lost. This is a strictly weaker outcome than legacy email,
where a hostile provider controls the entire mailbox. In SEMP, the
lost envelopes are confidentiality-preserved (the old provider cannot
read the enclosure).

### 9.2 Old Identity Key Compromise

If the old identity key is compromised before migration, an attacker
can forge a unilateral migration to an address they control. Defense
is the usual key hygiene: timely rotation and revocation. The
`RECOVERY.md` extension provides a recovery path for users who have
lost keys but not had them stolen.

Cooperative migration provides additional defense: the old provider's
signature is required, so an attacker who compromised only the old
identity key cannot move the user to an attacker-controlled new
provider without the old provider's participation.

### 9.3 Reassignment Oracle

A third-party domain tracking known-correspondent or reputation for an
address MUST NOT leak through its responses whether a given address
was migrated, reassigned, or never used. Observable behavior that
differs between these cases constitutes an existence oracle per
`DESIGN.md` section 2.7.

### 9.4 Migration Record Replay

The migration record binds to specific identity keys and timestamps
and is signed by all parties. A replayed record is detectable: the
timestamps have aged, and the bound keys may have been revoked for
other reasons. Verifiers MUST NOT apply migration policy based on a
record whose bound keys are currently revoked for a reason other than
`"migrated_to"`.

### 9.5 Cascading Migration

A user MAY migrate again from `new.example` to `newer.example` by
publishing a fresh migration record at `newer.example` with
`old_address: alice@new.example`. A third-party domain verifying the
chain `old → new → newer` MUST verify each migration record
independently. Chains longer than 8 hops SHOULD be refused by
verifying domains as likely evidence of abuse.

---

## 10. Privacy Considerations

### 10.1 Record Visibility

Migration records are published artifacts. Any party can observe that
`alice@old.example` migrated to `alice@new.example` at a given time.
This is accepted as the cost of cryptographic continuity.

Users who require migration without public announcement MUST NOT use
this mechanism. They start fresh at the new address and do not carry
forward cryptographic proof of continuity.

### 10.2 Reassignment Exposure

A user who later occupies the old local-part observes historical
migration records at that address through public endpoints. The
records reveal that a prior occupant migrated to a specific new
address. This is an acknowledged disclosure and is inherent to the
design.

### 10.3 Correspondent Graph Exposure

Migration records themselves do not expose the migrating user's
correspondent graph. The carry-over actions (known-correspondent
update, block-list migration) are executed by third-party domains
locally; they do not produce federation-visible artifacts naming
individual correspondents.

---

## 11. Conformance

### 11.1 User Client Conformance

A client claiming migration support MUST:

- Construct migration records per section 3 with correctly ordered
  signatures.
- Surface a migration notice received during envelope rejection per
  section 5.3 to the user.
- Require explicit user confirmation before redirecting correspondence
  to the migrated new address, per `CLIENT.md` section 3.3.
- Apply key-change detection on envelopes from a previously-known
  address whose identity key has changed, treating the new key as a
  new correspondent.
- On a verified migration record for a known correspondent, update the
  correspondent's primary address to the new address, subject to
  explicit user confirmation.

### 11.2 Old Provider Conformance (Cooperative)

An old provider claiming cooperative migration support MUST:

- Advertise the `migration` endpoint in its discovery configuration.
- Verify all identity signatures on submitted records before
  countersigning.
- Refuse to reassign the migrated local-part during the forwarding
  window.
- Serve the migration record indefinitely after publication.
- Revoke the old identity key with reason `"migrated_to"` on
  publication.
- Return `policy_forbidden` with a `migration_notice` body for
  envelopes addressed to the migrated address after the window ends,
  until the local-part is reassigned. After reassignment, envelopes
  to the new occupant follow the standard delivery pipeline.

### 11.3 New Provider Conformance

A new provider claiming migration support MUST:

- Accept user registration normally at the new address.
- Sign and publish the migration record.
- Expose the migration record through its `migration` endpoint.
- Honor carry-over policies for its own users as per section 7.

### 11.4 Third-Party Domain Conformance

A third-party domain that applies migration carry-over MUST verify the
record per section 7.1. A third-party domain that does not apply
carry-over MUST treat the new address as a fresh identity per
`DESIGN.md` section 5.4.

Regardless of carry-over policy, third-party domains MUST:

- Not grant known-correspondent or reputation standing to a sender at
  the old address whose identity key does not match
  `old_identity_key_id` after the forwarding window has ended.
- Not leak migration state through observable behavior that
  distinguishes migrated, reassigned, and never-used addresses.

---

## 12. Relationship to Other Specifications

| Specification   | Relationship                                                                                                       |
|-----------------|--------------------------------------------------------------------------------------------------------------------|
| `DESIGN.md`     | Honors operator-non-trust. Unilateral migration requires no cooperation from the old provider.                     |
| `KEY.md`        | Old identity key revocation uses `KEY.md` section 8 with reason `"migrated_to"`.                                   |
| `ENVELOPE.md`   | Forwarding during the window uses the forwarding primitive in section 6.6.                                         |
| `DELIVERY.md`   | Post-window bounce returns `policy_forbidden` with a `migration_notice` body, extending the rejection schema.      |
| `REPUTATION.md` | Reputation carry-over is an optional per-domain policy; binding is to identity keys, not address strings.          |
| `DISCOVERY.md`  | The `migration` endpoint is advertised in the discovery configuration.                                             |
| `RECOVERY.md`   | A user who has lost their old identity private key cannot migrate. Recovery provides the mechanism to retain the key in the first place. |
| `CLIENT.md`     | Key-change detection and user-confirmation requirements apply uniformly to migration-induced address updates.      |
| `CONFORMANCE.md`| This document's conformance requirements are referenced from `CONFORMANCE.md`.                                     |

---

*This document is an Internet-Draft. It is subject to revision prior to
finalization as a stable specification.*
