## Abstract

This document specifies four optional-core modules of the
Sealed Envelope Messaging Protocol (SEMP): account recovery
via server-assisted encrypted backup and Shamir device-split
backup, provider migration with cryptographic continuity of
identity, account closure with grace period and retention
window, and key transparency via per-domain Merkle-tree log
[RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) with observation-based gossip. Implementations
that claim a module's functionality MUST conform to that
module's normative requirements; absence of a module is
permitted and is advertised through SEMP discovery.

# Introduction

The four modules in this document address user-account
lifecycle events and the verifiability of the SEMP key
publication system. Each module is optional-core: a SEMP
implementation MAY omit support, but an implementation that
claims a module MUST comply with that module's normative
requirements. Module support is advertised through endpoints
in the discovery configuration document defined in
[Discovery](discovery.md).

The modules are:

* Account recovery
  ([Account Recovery](#recovery)): mechanisms by which a user whose active
  private keys have been lost may regain control of their
  account without bypassing the SEMP trust model.
* Provider migration ([Provider Migration](#migration)): how a user moves their
  identity from one provider to another while preserving
  correspondent relationships, reputation, and access to
  prior correspondence.
* Account closure ([Account Closure](#closure)): how a user closes their
  account, expressed as ordinary key revocation under the
  existing key lifecycle mechanism, with cascading state
  cleanup.
* Key transparency ([Key Transparency](#transparency)): an append-only
  Merkle-tree log of key events per supporting domain, with
  inclusion proofs on every key fetch and gossip-based
  equivocation detection.

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

This document additionally uses terminology from [RFC 4949](https://www.rfc-editor.org/rfc/rfc4949)
for general security-protocol terms.

<a id="recovery"></a>

# Account Recovery
This section enables a user to reconstruct their identity
private key and the history of their encryption private keys
after loss of all devices, provided the user retains either a
recovery secret or a threshold number of shares distributed
across still-alive devices.

## Goals and Non-Goals

In scope: backup bundle format, server-assisted recovery,
Shamir device-split recovery, restore procedures, successor
record publication.

Not in scope: recovery without any user-held artifact (no
server can re-issue a user's private keys without violating
the SEMP trust model), social recovery via third-party
contacts, paper backup encoding, and operator-initiated
recovery or operator override of restore. SEMP operators are
custodians of encrypted material only. They MUST NOT
possess, broker, or gate recovery secrets.

A SEMP server advertises recovery support via the `backup`
endpoint in its discovery configuration. Absence of the
endpoint indicates the server does not host server-assisted
backups. Shamir device-split backup is entirely client-side
and requires no server support.

## Backup Bundle

### Bundle Schema

~~~ json
{
    "type": "SEMP_BACKUP_BUNDLE",
    "version": "1.0.0",
    "user_id": "alice@example.com",
    "bundle_id": "bundle-ulid",
    "created_at": "2026-04-18T10:00:00Z",
    "supersedes": "prior-bundle-ulid-or-null",
    "kdf": {
        "algorithm": "argon2id",
        "salt": "base64-16-byte-salt",
        "memory_kb": 262144,
        "iterations": 3,
        "parallelism": 4
    },
    "payload_algorithm": "xchacha20-poly1305",
    "payload_nonce": "base64-24-byte-nonce",
    "encrypted_payload": "base64-ciphertext",
    "recovery_verify_pk": {
        "algorithm": "ed25519",
        "public_key": "base64-32-byte-public-key"
    },
    "signature": {
        "algorithm": "ed25519",
        "key_id": "current-identity-key-fingerprint",
        "value": "base64-signature"
    }
}
~~~

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | MUST be `"SEMP_BACKUP_BUNDLE"`. |
| `version` | string | Yes | Backup format version (semver). |
| `user_id` | string | Yes | Full SEMP address the bundle belongs to. |
| `bundle_id` | string | Yes | Unique identifier for this bundle. ULID RECOMMENDED. |
| `created_at` | string | Yes | ISO 8601 UTC creation timestamp. |
| `supersedes` | string \| null | Yes | `bundle_id` of the prior bundle, or `null` for the first bundle. |
| `kdf` | object | Yes | Key derivation parameters. |
| `payload_algorithm` | string | Yes | AEAD algorithm. MUST be `xchacha20-poly1305`. |
| `payload_nonce` | string | Yes | Base64-encoded 24-byte nonce. |
| `encrypted_payload` | string | Yes | Base64-encoded ciphertext of the payload. |
| `recovery_verify_pk` | object | Yes | Public key used to verify successor records. |
| `signature` | object | Yes | Identity key signature over canonical bundle bytes with `signature.value` set to `""`. |

### Payload Schema

The decrypted payload is a JSON object containing the user's
currently active identity key (with private key material),
every encryption key the user has ever held in creation
order (including superseded and revoked keys), the user's
delivery receipts archive, and opaque client metadata.

The payload MUST include all encryption keys ever issued for
the account so that envelopes sealed under any of them
remain decryptable after recovery.

A user who has configured recovery SHOULD include their
receipts archive in the recovery payload so that a total
device loss does not destroy the evidence of prior
deliveries. Each receipt's signature bytes MUST be preserved
unchanged; receipts are verifiable artifacts, and re-encoding
them in a way that breaks canonical form would invalidate
the signature.

A bundle consumer restoring from recovery MUST verify every
receipt's signature against the recipient domain's current
or historical signing keys before treating any restored
receipt as evidential. A receipt whose signature does not
verify MUST NOT be silently dropped. The client MUST
surface the verification failure to the user, and MAY then
either discard the receipt or retain it with a "suspect"
indicator visible alongside the receipt. Verification
failure after a restore could indicate a receipt whose
issuing domain has rotated keys in a way the verifier
cannot reconcile, and the user is the right party to
decide whether to treat the receipt as evidential.

The payload includes a `metadata` object reserved for
opaque client metadata that the server MUST NOT interpret.
Implementations MAY use this for client-internal state such
as an `accepted_senders_version` counter that lets the
client detect whether the recovered bundle's local-state
view is older than the user's current home-server view.

### Canonical Bytes and Signature

`signature` is computed over the canonical UTF-8 JSON
encoding of the bundle object with keys sorted
lexicographically at every level, `signature.value` set to
`""`, and no insignificant whitespace. The canonical bytes
are prefixed with `SEMP-RECOVERY-BUNDLE:` per the signature
domain separation table in [Envelope](envelope.md).

The signature MUST be produced with the user's currently
active identity private key.

### Key Derivation

The bundle encryption key `K_bundle` is derived from the
recovery secret via Argon2id [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106):

~~~
K_bundle := Argon2id(
    secret  = recovery_secret_bytes,
    salt    = bundle.kdf.salt,
    memory  = bundle.kdf.memory_kb * 1024 bytes,
    time    = bundle.kdf.iterations,
    lanes   = bundle.kdf.parallelism,
    out_len = 32)
~~~

KDF parameters MUST meet the following minima:

| Parameter | Minimum | RECOMMENDED default |
|---|---|---|
| `memory_kb` | 65536 | 262144 |
| `iterations` | 2 | 3 |
| `parallelism` | 1 | 4 |
| `salt` | 16 bytes | 16 bytes |

Clients generating a bundle MUST choose parameters that
complete in at least 500 milliseconds on the client's
hardware, to raise brute-force cost for attackers. Clients
MUST NOT select parameters weaker than the minima above.

`K_bundle` encrypts `payload_nonce` concatenated with the
payload JSON under `xchacha20-poly1305`, with empty
associated data.

## Recovery Secret

The recovery secret is one of:

Passphrase form:
: A user-chosen Unicode string. The client MUST normalize
  the passphrase to Unicode NFKC before KDF. The client
  MUST reject passphrases shorter than 12 UTF-8 bytes.

Recovery code form:
: A client-generated sequence of 24 words drawn from the
  BIP-39 English word list (2048 words, 11 bits per word).
  The client MUST display the code to the user for
  transcription and MUST NOT store it in plaintext
  thereafter.

A client MUST offer the user a choice between forms at
backup time.

For both forms, the input to KDF is UTF-8 encoded bytes:
passphrase NFKC normalized and trimmed of leading and
trailing whitespace; recovery code as concatenated words
separated by single ASCII space (0x20), lowercase.

### Deterministic Recovery Key Pair

From the recovery secret, the client MUST also derive an
Ed25519 signing key pair used for successor records:

~~~
seed := HKDF-Expand(
    PRK  = K_bundle,
    info = "SEMP-RECOVERY-SIGN-KEY-v1",
    L    = 32)
(recovery_sign_sk, recovery_verify_pk) :=
    ed25519_keygen_from_seed(seed)
~~~

The HKDF construction follows [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869). The
`recovery_verify_pk` is published in the bundle and is
signed by the current identity key. The `recovery_sign_sk`
is never stored; it is re-derived from the secret at
restore time.

## Server-Assisted Backup

A server supporting server-assisted backup advertises a
`backup` endpoint in its discovery configuration. The
endpoint supports four operations:

* Upload a new bundle (a write operation).
* Fetch the current bundle for a user (a read operation).
* Fetch all retained bundles for a user, including
  superseded ones (a read operation, parameterized by
  `history=true`).
* Delete all stored bundles for a user (a write operation).

All operations target a user-scoped path derived by
appending the URL-encoded user address to the base URL.

The HTTP/2 transport binding
([Handshake](handshake.md)) maps read operations to
`GET` and write operations to `POST` (with `DELETE` for
delete). The WebSocket, QUIC, and any custom transport
bindings carry the equivalent SEMP messages over their
respective wire formats. The operation semantics
described in the rest of this section are
transport-agnostic; references to `GET` and `POST` below
refer to the HTTP/2 binding as the illustrative case.

### Upload

A client uploads a bundle via `POST` over its current
authenticated session with the home server. The server
MUST:

1. Verify the bundle's `signature` against the user's
   currently active identity key.
2. Verify that `user_id` matches the authenticated user.
3. Verify that `supersedes` matches the current stored
   `bundle_id` for that user, or is `null` if no prior
   bundle exists.
4. Store the bundle.
5. Retain superseded bundles for at least 30 days before
   deletion.

A server MUST NOT decrypt or attempt to decrypt
`encrypted_payload`.

### Download

A client downloads a bundle via `GET`. The server MUST
serve bundle downloads without requiring an authenticated
session bound to the user, since the common case for
download is that the user has no remaining private keys
with which to authenticate.

The server MUST apply rate limits per source IP and per
`user_id` to raise the cost of brute-force attacks against
the KDF. A RECOMMENDED limit is 10 download requests per
user address per hour across all sources. When the limit is
exceeded, the server MUST respond with HTTP 429.

The server MUST NOT expose bundle metadata (such as
`created_at` or `bundle_id`) through any interface that
does not require downloading the bundle itself.

### Versioning and Retention

The server MUST retain the current bundle indefinitely.
Superseded bundles MUST be retained for at least 30 days
after being superseded.

A server MUST NOT delete the current bundle except on a
`DELETE` request authenticated on the user's current
session.

## Shamir Device-Split Backup

A client MAY back up `K_bundle` across the user's
registered devices using Shamir's Secret Sharing over
GF(256) with a threshold `M` and share count `N`, where
`2 <= M <= N <= 16`.

The client MUST derive `K_bundle` from the recovery
secret, apply Shamir's Secret Sharing with parameters
`(M, N)`, construct the recovery set manifest binding each
share to a specific registered device and that device's
identity public key, and transmit to each of the user's
`N` registered devices the device's assigned share record
and a copy of the signed manifest.

A device MUST NOT transmit its share to the server or to
any non-device party.

<a id="recovery-set-manifest"></a>

### Recovery Set Manifest
~~~ json
{
    "type": "SEMP_RECOVERY_SET_MANIFEST",
    "version": "1.0.0",
    "bundle_id": "bundle-ulid",
    "threshold": 3,
    "total_shares": 5,
    "contributors": [
        {
            "share_index": 1,
            "device_id": "device-ulid-1",
            "device_identity_pubkey": {
                "algorithm": "ed25519",
                "public_key": "base64-device-identity-pubkey",
                "key_id": "device-identity-key-fingerprint"
            }
        }
    ],
    "issued_at": "2026-04-18T10:00:00Z",
    "signature": {
        "algorithm": "ed25519",
        "key_id": "user-identity-key-fingerprint",
        "value": "base64-signature"
    }
}
~~~

The manifest binds each Shamir share to a specific device's
identity public key, so that at restore time the restoring
client can verify that each collected share was assigned to
a device the user enrolled in the recovery set at backup
time.

The signature is computed over the canonical bytes of the
manifest with `signature.value` set to `""`, prefixed with
`SEMP-RECOVERY-MANIFEST:`.

The `contributors[i].device_identity_pubkey` values MUST
match the `device_public_key` entries for the same
`device_id` in the account's current device directory
([Discovery](discovery.md)) at manifest issuance.

A restore client reconstructing the recovery set MUST
cross-check each contributor against the directory revision
active at the manifest's `issued_at`. A contributor device
that is not listed in that directory revision, or whose
directory `device_public_key` does not match the manifest's
`device_identity_pubkey`, indicates a stale or forged
manifest and MUST be rejected.

### Share Record

~~~ json
{
    "type": "SEMP_RECOVERY_SHARE",
    "version": "1.0.0",
    "bundle_id": "bundle-ulid",
    "share_index": 3,
    "device_id": "device-ulid-3",
    "threshold": 3,
    "total_shares": 5,
    "share_value": "base64-encoded-share-bytes",
    "issued_at": "2026-04-18T10:00:00Z",
    "device_signature": {
        "algorithm": "ed25519",
        "key_id": "device-identity-key-fingerprint",
        "value": "base64-signature"
    }
}
~~~

The device signature is computed over the canonical bytes
of the share record with `device_signature.value` set to
`""`, prefixed with `SEMP-RECOVERY-SHARE:`. It proves that
the device holding this record controls the identity key
listed for its `share_index` in the manifest.

The receiving device MUST verify, before storing the share,
that the manifest's signature verifies against the user's
current identity key, that its own `device_id` matches the
manifest's contributor entry for the share's `share_index`,
and that `share_value` is nonempty and of the expected
length.

### Reconstruction

To reconstruct `K_bundle`, the user MUST assemble shares
from at least `M` still-alive devices through a local
transfer mechanism (QR-code display, direct local network
transfer over an authenticated channel, or USB export).

Share transfer MUST NOT go through the home server or any
other remote party.

After assembling `M` shares and the manifest, the client
reconstructs `K_bundle` via Lagrange interpolation and
proceeds to the common restore flow.

## Restore Flow

### Server-Assisted Restore

On a fresh device with no prior keys, the user provides
`user_id` and the recovery secret. The client fetches the
current bundle via `GET`, derives `K_bundle` via KDF using
the bundle's stored parameters, decrypts
`encrypted_payload`, verifies that the payload decrypts to
valid JSON matching the schema, and verifies the bundle's
outer `signature` against some historically published
identity key for `user_id`.

A decryption failure MUST be surfaced to the user as a
likely incorrect recovery secret.

### Shamir Restore

On a fresh device with no prior keys, the user identifies
`M` of their still-alive devices. The client collects `M`
share records and one manifest from those devices via
local transfer.

The client fetches the user's historically published
identity keys via the home server's key endpoint or via
the key-transparency log where available. The client
verifies the manifest's signature against one of the
historically published identity keys.

For each collected share record, the client verifies the
share's `bundle_id` matches the manifest's `bundle_id`,
that `share_index` appears in the manifest's
`contributors` array exactly once, that `device_id`
matches the manifest's contributor entry for its
`share_index`, and that `device_signature` verifies
against the `device_identity_pubkey` in the corresponding
contributor entry. A share that fails any of these checks
MUST be discarded.

The client then verifies that all accepted shares agree on
`bundle_id`, `threshold`, and `total_shares`, and that
their `share_index` values are distinct. If any of these
cross-share checks fails, the client MUST treat the set as
inconsistent and MUST NOT proceed with reconstruction.

The client then reconstructs `K_bundle` via Shamir
interpolation over the `M` accepted shares and fetches the
corresponding bundle from the home server via `GET`,
matching on `bundle_id`.

### New Key Generation

After successful decryption, the client MUST NOT reuse the
prior identity key as the account's current identity key.
The client MUST:

1. Generate a fresh identity key pair.
2. Generate a fresh encryption key pair.
3. Publish the new identity key and encryption key.
4. Publish a successor record per
   [Successor Record](#successor-record) linking the prior identity key to
   the new identity key.
5. Sign the prior identity key's revocation record using
   the recovered prior identity key.

The prior encryption key history MUST be retained by the
client for decryption of archived envelopes but MUST NOT
be republished or reused for new envelope encryption.

### Restore-Time Device Registration

The restoring device is a fresh device from the account's
point of view. After the new key generation above, the
device MUST register itself with the home server as a new
device under the account, following the device-registration
flow in [Discovery](discovery.md). The home server
MUST publish a new device directory revision that includes
the restoring device.

The recovered prior identity private key and prior
encryption private key history MUST remain bound to the
restoring device only and MUST NOT be re-published as
account identity keys; their role after restore is to
decrypt archived envelopes and to revoke the prior identity
key one final time, as defined above.

### Failure Modes

Wrong secret:
: Decryption of `encrypted_payload` fails AEAD
  verification. The client MUST surface this as a probable
  wrong recovery secret and MUST allow the user to retry.

Corrupt or tampered bundle:
: The payload decrypts to malformed JSON, or `signature`
  verification fails. The client MUST surface this as a
  bundle integrity failure and MUST NOT proceed to key
  generation. The client SHOULD fetch historical bundles
  via `GET ?history=true` and attempt restore against
  each.

<a id="recovery-conformance"></a>

### Recovery Conformance
A client claiming server-assisted recovery support MUST:

* Generate backup bundles on initial key provisioning and
  on every identity or encryption key rotation.
* Upload bundles to the user's home server via the
  advertised `backup` endpoint.
* Normalize passphrases to NFKC before KDF.
* Refuse passphrases below the minimum entropy threshold
  defined in the security considerations.
* Derive `recovery_sign_sk` and `recovery_verify_pk`
  deterministically per the recovery-secret rules.
* Generate fresh identity and encryption key pairs on
  restore, rather than reusing recovered keys as current
  keys.
* Publish a successor record on every restore.
* Revoke the prior identity key immediately after restore
  using the recovered private key.

A client claiming Shamir device-split recovery support
MUST additionally:

* Distribute shares and the recovery set manifest over the
  multi-device sync channel.
* Construct a fresh recovery set manifest for each split
  and sign it with the user's current identity key.
* On receipt of a share, verify the manifest's signature
  against the user's current identity key and verify that
  the share's bound `device_id` matches the manifest's
  contributor entry before storing.
* Retain a local copy of the manifest alongside the share
  on each enrolled device so that the manifest is
  available for local transfer at restore time without
  server cooperation.
* At restore, verify each collected share against the
  recovery set manifest before counting it toward the
  `M`-of-`N` threshold, and verify the cross-share
  agreement on `bundle_id`, `threshold`, and
  `total_shares`.
* Transfer shares and the manifest during reconstruction
  only through local channels, never through the home
  server.

A server claiming server-assisted recovery support MUST:

* Advertise a `backup` endpoint in its discovery
  configuration.
* Verify bundle `signature` against the user's current
  identity key on upload.
* Verify `supersedes` linkage on upload.
* Serve bundle downloads without requiring an
  authenticated session.
* Apply per-user and per-IP rate limits on downloads.
* Retain superseded bundles for at least 30 days.
* Expose `recovery_verify_pk` in the user's historical key
  record so that third-party domains can verify successor
  records without fetching the bundle itself.
* MUST NOT decrypt or attempt to decrypt
  `encrypted_payload`.
* MUST NOT expose bundle metadata through any interface
  that does not require downloading the bundle itself.

A third-party domain choosing to honor successor records
MUST verify all signatures and the timing constraint
defined in [Successor Record](#successor-record). A third-party domain
choosing not to honor successor records MUST treat the
new identity key as a fresh identity with no carried trust.

<a id="successor-record"></a>

## Successor Record
The successor record authenticates a recovered account's
continuity to third-party domains.

~~~ json
{
    "type": "SEMP_SUCCESSOR",
    "version": "1.0.0",
    "user_id": "alice@example.com",
    "prior_key_id": "old-identity-key-fingerprint",
    "new_key_id": "new-identity-key-fingerprint",
    "new_public_key": "base64-new-identity-public-key",
    "recovered_at": "2026-04-18T12:00:00Z",
    "recovery_signature": {
        "algorithm": "ed25519",
        "key_id": "recovery-verify-pk-fingerprint",
        "value": "base64-signature"
    },
    "new_key_signature": {
        "algorithm": "ed25519",
        "key_id": "new-identity-key-fingerprint",
        "value": "base64-signature"
    },
    "domain_signature": {
        "algorithm": "ed25519",
        "key_id": "domain-signing-key-fingerprint",
        "value": "base64-signature"
    }
}
~~~

The record carries three signatures, each computed over
the canonical bytes of the record with the corresponding
signature's `value` set to `""`, prefixed with
`SEMP-SUCCESSOR-RECORD:`. The three signatures are:

* `recovery_signature`: produced by `recovery_sign_sk`
  derived from the recovery secret. Verifiable using
  `recovery_verify_pk` published in the bundle and signed
  by the prior identity key at bundle upload time.
* `new_key_signature`: produced by the new identity
  private key. Confirms the new key's consent.
* `domain_signature`: produced by the home server's domain
  signing key.

All three signatures MUST be present. Verifiers that
cannot obtain all three MUST treat the successor record as
unverified.

A third-party domain verifying a successor record MUST
fetch the prior user key record and extract the
`recovery_verify_pk` published in the corresponding backup
bundle. The home server MUST expose the
`recovery_verify_pk` as a field in the historical key
record so that third parties can fetch it without fetching
the bundle itself.

If all verifications succeed, the domain MAY honor the
continuity claim. Honoring continuity is a local policy
decision. A domain MUST NOT be required to honor
continuity.

Domains choosing to honor a successor record MAY preserve
the prior key's reputation signal on the new key, preserve
the known-correspondent relationship, and migrate block
list entries from the prior key to the new key.

<a id="migration"></a>

# Provider Migration
This section enables a user to move their SEMP identity
from one provider to another while preserving correspondent
relationships, reputation, and access to prior
correspondence.

A SEMP server advertises cooperative migration support via
the `migration` endpoint in its discovery configuration.
Absence of the endpoint indicates the server does not
participate in cooperative migration. Unilateral migration
requires no server participation at the old domain.

## Migration Modes

Cooperative migration:
: The old provider participates. Both providers and both
  identity keys sign the migration record. The old
  provider operates a migration notice window and revokes
  the old identity key on publication.

Unilateral migration:
: The old provider does not participate. The user drives
  the migration using their old identity key material.
  The migration record carries the user's old identity
  key signature and the new identity key and new provider
  signatures, but no old provider signature. Unilateral
  migration is REQUIRED to be supported when the user
  retains possession of the old identity private key.

## Migration Record

~~~ json
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
    "notice_window_until": "2026-10-15T12:00:00Z",
    "mode": "cooperative",
    "old_identity_signature": { },
    "new_identity_signature": { },
    "old_domain_signature": { },
    "new_domain_signature": { },
    "extensions": {}
}
~~~

| Field | Required | Description |
|---|---|---|
| `record_id` | Yes | Unique identifier for this record. ULID RECOMMENDED. |
| `old_address` | Yes | Full SEMP address before migration. |
| `new_address` | Yes | Full SEMP address after migration. |
| `old_identity_key_id` | Yes | Fingerprint of the identity key active at the old address. |
| `new_identity_key_id` | Yes | Fingerprint of the identity key active at the new address. |
| `new_identity_public_key` | Yes | Base64-encoded new identity public key. |
| `migrated_at` | Yes | ISO 8601 UTC timestamp of migration. |
| `notice_window_until` | Yes | ISO 8601 UTC timestamp at which the migration notice window ends. After this timestamp the old provider stops returning the migration notice on envelopes addressed to the old address. `null` for unilateral mode. |
| `mode` | Yes | One of: `cooperative`, `unilateral`. |
| `old_identity_signature` | Yes | Signature produced by the old identity private key. |
| `new_identity_signature` | Yes | Signature produced by the new identity private key. |
| `old_domain_signature` | When mode is cooperative | Signature produced by the old provider's domain signing key. |
| `new_domain_signature` | Yes | Signature produced by the new provider's domain signing key. |
| `extensions` | No | Optional extension entries per [Extensions](extensions.md). Every signature in the four-signature chain covers `extensions`, so any content captured here is attested by all four signers. Defaults to `{}` when absent. |

### Canonical Bytes and Signature Order

Each signature is computed over the canonical UTF-8 JSON
encoding of the record with keys sorted lexicographically,
the signing signature's `value` set to `""`, all other
signatures present at their final values, and no
insignificant whitespace. The canonical bytes are prefixed
with `SEMP-MIGRATION-RECORD:`.

Signatures are added in the order:
`old_identity_signature`, `new_identity_signature`,
`new_domain_signature`, `old_domain_signature`. Each
signature binds the record fields and all prior
signatures. A verifier MUST verify in the same order.

`migrated_at` MUST be at or after the `created` timestamp
of the `old_identity_key_id` key record and MUST NOT be in
the future relative to the verifier's clock beyond
ordinary clock-skew tolerance. A record whose
`migrated_at` precedes the old identity key's creation
MUST be rejected as malformed.

### Publication

The migration record is published at the new provider via
the `migration` endpoint. The new provider MAY also
include the record in responses to key fetches for the new
address, as an optional `migration_from` field in the
`SEMP_KEYS` response per [Discovery](discovery.md).

In cooperative mode, the old provider MUST also publish
the record via its own `migration` endpoint and MAY include
a `migration_to` field in responses to key fetches for the
old address.

Once published, a migration record is immutable. A new
migration record MUST NOT replace an existing record; the
user MUST publish a successor record pointing to the new
target address if they migrate again.

For envelopes addressed to recipients across mixed legacy
and SEMP infrastructure, a sender that resolves a
`recipient_not_found` for one recipient on a multi-recipient
envelope MUST split the envelope so that the recipients that
do resolve are not delayed by the unresolved one. The split
is local to the sender and produces independent envelopes;
the canonical envelope identifier is recomputed for each.

## Cooperative Migration Flow

This subsection defines the wire-level sequence for the
cooperative mode and the old provider's obligations during
that sequence.

### Sequence

1. The user decides to migrate to `new.example`.
2. The user registers their new address at the new
   provider, generating a new identity key and encryption
   key.
3. The user composes a migration record with `mode:
   "cooperative"` and an agreed `notice_window_until`.
4. The user signs with the old identity private key
   (`old_identity_signature`).
5. The user signs with the new identity private key
   (`new_identity_signature`).
6. The new provider verifies the two identity signatures,
   then signs with its domain key
   (`new_domain_signature`).
7. The new provider submits the record to the old
   provider's `migration` endpoint.
8. The old provider verifies all three signatures, confirms
   the old identity key is active and matches
   `old_identity_key_id`, and signs with its domain key
   (`old_domain_signature`).
9. Both providers publish the complete record and begin
   honoring the migration notice window (see
   [Migration Notice Window](#migration-notice-window)).
10. The old provider publishes a revocation record for the
    old identity key with `reason: "migrated_to"` and
    `replacement: <new_address>` per
    [Discovery](discovery.md).

### Old Provider Obligations

The old provider MUST:

* Verify all signatures on the submitted record before
  countersigning.
* Publish the signed record at its `migration` endpoint.
* Honor the migration notice window per
  [Migration Notice Window](#migration-notice-window).
* Refuse to reassign the old local-part during the
  migration notice window per
  [Local-Part Reassignment](#migration-local-part-reassignment).
* Revoke the old identity key on publication per
  [Old Identity Key Revocation](#old-identity-key-revocation).

The old provider MUST NOT:

* Modify the record after the user has signed it.
* Co-sign a record whose `old_identity_signature` does not
  verify against the identity key currently published at
  the old address.
* Countersign a second migration record for the same old
  address while a prior record is in its migration notice
  window.

<a id="migration-notice-window"></a>

## Migration Notice Window
During the cooperative migration's notice window, the
period from `migrated_at` to `notice_window_until`, the
old provider MUST treat envelopes addressed to the old
address and key fetches for the old address as
opportunities to redirect senders to the new address
rather than as ordinary delivery operations. The old
provider performs no envelope re-enveloping and holds no
authorization to act on the user's keys; the redirect is
purely a discovery-time signal.

The RECOMMENDED notice window is 180 days. Windows
shorter than 30 days MUST NOT be accepted by a conformant
old provider. Windows longer than 730 days (two years)
MAY be declined.

### Envelope Rejection With Migration Notice

For each envelope received for the old address during the
window, the old provider MUST return a `rejected`
acknowledgment with `reason_code: "policy_forbidden"` and
MUST include a `migration_notice` field in the rejection
response, per the rejection schema in
[Delivery](delivery.md). The `migration_notice` body
carries the migration record's `new_address` and the
`record_id` of the migration record so that the sender
can fetch the full record for verification.

After `notice_window_until`, the old provider MUST stop
returning the migration notice. Envelopes addressed to the
old address are handled the same way responses to
non-existent addresses are handled, per the rules in
[Delivery](delivery.md), with no migration-specific
body.

### Key-Fetch Redirect

While the migration record is published at the old
provider, responses to `SEMP_KEYS` requests for the old
address MUST include the `migration_to` field in the key
response, carrying the migration record or a stable
pointer to it. A sender that refetches keys for the old
address discovers the redirect through this field without
needing to attempt envelope submission first.

This rule applies for as long as the old provider
publishes the migration record at its `migration`
endpoint. The minimum retention for the migration record
is 2 years from `migrated_at`. Operators MAY retain longer
per policy.

### Sender Behavior

A sender that receives a `migration_notice` rejection or
that sees `migration_to` on a key fetch MUST treat the
old address as redirected to the new address. The sender
SHOULD:

* update local addressbook entries that name the old
  address so that future sends use the new address;
* verify the migration record per
  {{third-party-domain-policy}} before re-sending;
* re-submit the envelope addressed to the new address.

A sender MUST NOT re-submit the original envelope
unchanged to the new address. The envelope's seal was
bound to the old recipient's keys, and the sender MUST
compose a fresh envelope sealed to the new address's
current keys.

### User-Initiated Forwarding

If the user remains authenticated at the old provider
during the notice window, they MAY manually forward
inbound envelopes from the old address to the new address
using the standard forwarding primitive in
[Envelope](envelope.md). This is ordinary
user-initiated forwarding performed by an authenticated
client of the user; it is not a protocol-level obligation
on the old provider, and the old provider holds no
authorization to perform the forward without the user's
direct action. The old provider MUST NOT decrypt or
re-envelope content on the user's behalf as a server-side
operation.

### Unilateral Mode

In unilateral migration, the old provider does not
participate. `notice_window_until` is `null`. Envelopes
addressed to the old address receive whatever response
the old provider gives to ordinary addresses (typically
delivery on the old account, or `recipient_not_found` if
the account is gone). The new provider publishes the
migration record on its own `migration` endpoint, and
senders discover the redirect only by:

* fetching the new provider's `migration` endpoint
  directly;
* observing the old identity key's revocation record
  with `reason: "migrated_to"` and a `replacement` field
  naming the new address, if the user has revoked the old
  key.

<a id="migration-local-part-reassignment"></a>

## Local-Part Reassignment
The old provider MUST NOT reassign the migrated local-part
to any other user while `notice_window_until` has not
been reached.

After `notice_window_until`, the old provider MAY
reassign the local-part. Reassignment MUST be treated as
registration of a new account with no relationship to the
migrated account.

A subsequent occupant of the old local-part has a distinct
identity key. Third-party domains MUST treat the sender as
a new identity without any inherited known-correspondent
status, reputation, block-list entry, or other trust
artifact that was bound to the migrated identity.

## Third-Party Domain Policy

A third-party domain verifying a migration record MUST:

1. Fetch the record from the new provider's `migration`
   endpoint or accept a record delivered inline.
2. Verify `old_identity_signature` against the identity
   key record published for the old address.
3. Verify `new_identity_signature` against
   `new_identity_public_key`.
4. Verify `new_domain_signature` against the new
   provider's current domain signing key.
5. For `mode: cooperative`, verify
   `old_domain_signature` against the old provider's
   current domain signing key.
6. Verify that `migrated_at` is not in the future and not
   earlier than `old_identity_key`'s creation timestamp.

If any verification fails, the domain MUST treat the
record as unverified and MUST NOT apply any carry-over
policy.

A third-party domain MAY carry over reputation signals,
known-correspondent status, and block-list entries from
the old address to the new address. Carry-over is a local
operator decision. Domains that do not carry over MUST
treat the new address as a zero-reputation domain member.

Carry-over is bound to the identity-key pair in the
migration record, not to the address strings. A
mismatched identity key on any future envelope invalidates
the carried reputation for that envelope.

<a id="block-list-migration"></a>

### Block-List Migration
Block-list entries ([Delivery](delivery.md)) targeting
the old address SHOULD be migrated by the third-party
domain to also target the new address when a migration
record is verified. The migrated block entry MUST preserve
the original `entity` type, `acknowledgment`, `reason`, and
`scope`, and MUST record the migration event in its
`extensions` for audit purposes.

A user MAY explicitly disable block-list migration in their
own domain by operator configuration. This operator choice
is local and is not visible across federation.

<a id="old-identity-key-revocation"></a>

## Old Identity Key Revocation
In cooperative migration, the old provider MUST publish a
revocation record for the old identity key upon
publication of the migration record, with `reason:
"migrated_to"` and `replacement: <new_address>`.

In unilateral migration, the user MAY revoke the old
identity key if they retain the private key.

<a id="closure"></a>

# Account Closure
This section defines how a SEMP user closes their account.
Closure is expressed as ordinary key revocation under the
existing key lifecycle mechanism, with cascading cleanup
of account state. The protocol does not publish a
distinct closure artifact.

## Closure Request

~~~ json
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
~~~

The signature is computed over the canonical bytes of the
request with `signature.value` set to `""`, prefixed with
`SEMP-ACCOUNT-CLOSURE:`.

The request MUST be signed by a full-access device key of
the account. A delegated device MUST NOT submit a closure
request regardless of its scope. A request whose
`issued_by` refers to a delegated device MUST be rejected
with `reason_code: "scope_invalid"`.

The home server MUST verify that `user_id` matches the
authenticated account and that `issued_by` matches the
authenticated device. A submission mismatch MUST be
rejected with `reason_code: "unauthorized"`.

### Submission Flow

1. A full-access device composes the request and signs
   it.
2. The device submits the request to the home server
   over its authenticated client session.
3. The home server verifies signature, issuer authority,
   and `grace_period_seconds` bounds.
4. The home server marks the account as
   `closure_pending` with the computed finalization
   timestamp, but continues serving the account
   normally until finalization.
5. The home server returns acknowledgment to the
   submitter.

A second closure request submitted while one is already
pending MUST be rejected with `reason_code:
"closure_pending"`. The user cancels and re-requests if
they want different parameters.

## Grace Period

`grace_period_seconds` MUST be at least 604800 (7 days)
and at most 7776000 (90 days). The RECOMMENDED default is
2592000 (30 days). Operator policy MAY enforce a narrower
range within these protocol bounds.

A grace period shorter than 7 days gives the user
insufficient time to discover unauthorized closure
attempts. A grace period longer than 90 days ties up the
local-part and prolongs user uncertainty.

During the grace period, the account operates normally:
keys remain valid, envelopes are delivered, delegates
continue to function.

Cancellation is performed by any full-access device
submitting a `SEMP_ACCOUNT_CLOSURE` message with
`step: "cancel"` and the same `user_id`. Cancellation
MUST be signed by a current full-access device of the
account.

Cancellation MAY also be performed by a device restored
from the recovery bundle, when the pre-closure user has
lost their full-access devices but retains their recovery
secret.

The home server SHOULD surface the `closure_pending` state
to every authenticated client of the account.

## Finalization

Finalization occurs at
`requested_at + grace_period_seconds`. The home server
MUST finalize within a reasonable window after that
timestamp (RECOMMENDED within 1 hour). Finalization MUST
NOT occur before the timestamp under any policy.

At finalization, the home server MUST atomically:

1. Revoke the account's identity key with reason
   `superseded`.
2. Revoke all active encryption keys of the account with
   reason `superseded`.
3. Revoke every scoped device certificate with reason
   `delegated_role_ended`.
4. Terminate all active sessions belonging to any device
   of the account.
5. Drain the outbound queue: every non-terminal queue
   state record for this account MUST transition to
   `expired`.
6. Delete the recovery bundle.
7. Mark any in-flight migration records targeting this
   account as canceled.
8. Retain the block list for the account according to
   operator policy.
9. Cease serving SEMP operations on behalf of the
   account.

The revocation reason `superseded` is used for all
revoked keys and MUST NOT be replaced with an
account-closure-specific reason. This preserves
indistinguishability between a closed account and a user
who has revoked their keys for other reasons.

The protocol does not define a public closure record, a
closure discovery endpoint, or a closure-specific reason
code visible to other domains. The cryptographic trace of
a closed account is identical to the trace of a user who
revoked their keys and did not publish replacements.

## Ingress After Finalization

An envelope arriving for the closed account during the
retention window receives `reason_code:
"policy_forbidden"`, the same response non-existent
addresses receive. The home server MAY alternatively apply
silent-mode disposition (no wire response). Both preserve
address-enumeration resistance.

The home server MUST NOT return any reason code or body
field that specifically identifies closure. A sender
cannot cryptographically distinguish closure from any
other form of recipient unavailability.

## Local-Part Reassignment

The home server MUST NOT reassign the closed local-part to
a different user until the retention window has elapsed.
The retention window begins at finalization and lasts at
least 180 days (RECOMMENDED 365 days). Operators MAY
retain longer per policy.

Reassignment is identical to a fresh registration. The new
occupant has a new identity key, new encryption keys, and
no cryptographic relationship to the prior occupant.
Third-party domains MUST treat the new occupant as a
distinct identity, with no carry-over of trust,
known-correspondent status, or reputation.

## Closure Conformance

A client claiming closure support MUST:

* Compose `SEMP_ACCOUNT_CLOSURE` requests signed by a
  full-access device key.
* Surface the `closure_pending` state to the user on every
  device that can observe it.
* Offer cancellation through any full-access device.
* MUST NOT describe post-closure delivery failures as
  account closure in the user interface. The protocol does
  not distinguish closure from key revocation, and the
  client MUST NOT assert closure without a signal the
  protocol provides.

A server claiming closure support MUST:

* Verify the closure request signature against a current
  full-access device of the account before accepting.
* Reject closure requests from delegated devices with
  `reason_code: "scope_invalid"`.
* Reject submission mismatches with `reason_code:
  "unauthorized"`.
* Reject duplicate concurrent requests with `reason_code:
  "closure_pending"`.
* Enforce the `grace_period_seconds` bounds.
* Permit cancellation by any current full-access device of
  the account during the grace period.
* Finalize at `requested_at + grace_period_seconds`, not
  before, performing all finalization effects atomically.
* Revoke keys with reason `superseded`, not with any
  closure-specific reason.
* MUST NOT publish a closure record, a closure reason
  code, or a closure-specific discovery artifact.
* Delete the recovery bundle at finalization.

<a id="transparency"></a>

# Key Transparency
This section defines the key transparency extension. Each
supporting domain publishes an append-only Merkle-tree log
[RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) of every user key event. Clients fetching a
user's key receive an inclusion proof and a signed tree
head. Third-party monitors cross-check the log via the
existing observation gossip mechanism, detecting
equivocation.

A SEMP server claiming key transparency support MUST
advertise the `transparency_log` endpoint in its discovery
configuration.

## Transparency Log

Each domain supporting key transparency maintains a single
append-only Merkle tree following [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962)
construction: binary, complete except at the rightmost
level, SHA-256 over domain-separated leaf and interior
node encodings.

Leaves are ordered by insertion time. Once inserted, a
leaf is permanent; the domain MUST NOT remove or modify a
leaf.

### Log Entries

Each leaf is a canonical JSON encoding of a key event:

~~~ json
{
    "event": "publish",
    "user_id": "alice@example.com",
    "key_id": "key-fingerprint",
    "key_type": "identity",
    "algorithm": "ed25519",
    "public_key": "base64-public-key",
    "created": "2026-04-19T10:00:00Z",
    "expires": "2027-04-19T10:00:00Z",
    "revoked_at": null,
    "revoked_reason": null,
    "supersedes": null,
    "log_timestamp": "2026-04-19T10:00:05Z"
}
~~~

| Field | Type | Description |
|---|---|---|
| `event` | string | One of: `publish`, `rotate`, `revoke`. |
| `user_id` | string | Full SEMP address the key belongs to. |
| `key_id` | string | Key fingerprint. |
| `key_type` | string | `identity` or `encryption`. |
| `algorithm` | string | Algorithm identifier. |
| `public_key` | string | Base64-encoded public key. |
| `created` | string | Key creation timestamp. |
| `expires` | string \| null | Key expiry timestamp, or `null`. |
| `revoked_at` | string \| null | Present only on `revoke` events. |
| `revoked_reason` | string \| null | Present only on `revoke` events. |
| `supersedes` | string \| null | `key_id` of the key being rotated out. |
| `log_timestamp` | string | Server-assigned ISO 8601 UTC timestamp of log insertion. |

The leaf hash is `SHA-256(0x00 || canonical_json_bytes)`
per [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) domain separation.

### Signed Tree Head

The domain publishes a Signed Tree Head (STH)
periodically:

~~~ json
{
    "log_size": 12847,
    "root_hash": "base64-root-hash",
    "timestamp": "2026-04-19T12:00:00Z",
    "signature": {
        "algorithm": "ed25519",
        "key_id": "domain-signing-key-fingerprint",
        "value": "base64-signature"
    }
}
~~~

The signature covers the canonical JSON encoding of the
STH object with `signature.value` set to `""`, prefixed
with `SEMP-TRANSPARENCY-STH:`. The signing key is the
domain's current signing key.

Domains MUST publish a fresh STH at least every hour. A
stale STH (timestamp older than 1 hour by clock tolerance)
is unacceptable to clients and monitors.

### Log Endpoint

The `transparency_log` endpoint serves the log. The
endpoint is a base URL supporting:

| Operation | Description |
|---|---|
| `GET /sth` | Current STH. |
| `GET /sth/<timestamp>` | STH that was current at the given UTC ISO 8601 timestamp. |
| `GET /inclusion?log_size=N&leaf_hash=H` | Inclusion proof for the leaf identified by `leaf_hash` in a tree of size `N`. |
| `GET /consistency?from=N1&to=N2` | Consistency proof that the tree of size `N1` is a prefix of the tree of size `N2`. |
| `GET /entries?start=X&end=Y` | Leaf entries in the range `[X, Y)`. Monitors use this to replay the log locally. |

Responses are JSON. The exact response schema for each
operation follows [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) conventions, encoding
Merkle hashes as base64-URL strings.

### Retention

The log is append-only and retained indefinitely. Removing
entries would invalidate outstanding consistency proofs.
Operators MUST NOT remove or modify leaves.

An operator discontinuing transparency support MUST
continue to serve the existing log for at least 2 years
after withdrawing the `transparency_log` endpoint.

## Proofs

### Inclusion Proofs

An inclusion proof for leaf `L` in a tree of size `N` is
the sequence of sibling hashes along the path from `L` to
the root, per [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962). Verifiers recompute the root
from `L`, the path, and the tree size; the result MUST
equal the STH's `root_hash` for size `N`.

Proof size is `O(log N)`, approximately 30 hashes for a
million-entry log. Response format:

~~~ json
{
    "log_size": 12847,
    "leaf_hash": "base64-leaf-hash",
    "leaf_index": 4217,
    "path": [
        "base64-sibling-hash-1",
        "base64-sibling-hash-2"
    ]
}
~~~

### Consistency Proofs

A consistency proof between an earlier STH of size `N1`
and a later STH of size `N2` (where `N1 < N2`) is the
sequence of hashes that lets a verifier reconstruct the
earlier root from subsets of the later tree, per
[RFC 6962](https://www.rfc-editor.org/rfc/rfc6962).

Response format:

~~~ json
{
    "from_size": 10000,
    "to_size": 12847,
    "path": [
        "base64-hash-1",
        "base64-hash-2"
    ]
}
~~~

A valid consistency proof attests that the log was not
rewritten between size `N1` and size `N2`: the earlier
tree's leaves are preserved exactly as the first `N1`
leaves of the later tree.

## Key Fetch With Transparency

When a key fetch is served from a domain supporting
transparency, the `SEMP_KEYS` response is augmented with
an inclusion proof and a current STH for each returned
key:

~~~ json
{
    "type": "SEMP_KEYS",
    "step": "response",
    "keys": [
        {
            "address": "alice@example.com",
            "key_type": "identity",
            "public_key": "base64",
            "key_id": "key-fingerprint",
            "transparency": {
                "sth": { },
                "inclusion_proof": { }
            }
        }
    ],
    "signature": { }
}
~~~

The `transparency.sth` is the current STH at response
time (signed within the last hour). The
`transparency.inclusion_proof` proves that the most
recent key event for this key is a leaf of the tree
described by the STH.

A domain that supports transparency MUST include the
`transparency` field on every key returned. A domain that
does not support transparency omits the field entirely.

On receiving a key response with a `transparency` field, a
client MUST:

1. Verify the domain signature on the STH against the
   subject domain's current signing key.
2. Verify the STH's `timestamp` is within 1 hour of the
   client's clock.
3. Verify the inclusion proof against the STH's
   `root_hash`.
4. Verify the leaf being proven corresponds to the
   returned key (the leaf's `key_id` and `public_key`
   match).

If any verification fails, the client MUST NOT use the
returned key. The client SHOULD surface a security
warning. The client MAY offer the user the option to
proceed with an explicit acknowledgment, but MUST NOT
proceed silently.

## Equivocation Detection

Monitors publish their observations of other domains'
transparency logs via the observation gossip mechanism in
[Delivery](delivery.md). The observation kind
`key_transparency` is registered for this purpose. The
observation record carries a `type` discriminator and one
or two STH records:

~~~ json
{
    "kind": "key_transparency",
    "type": "snapshot",
    "subject_domain": "example.com",
    "observed_at": "2026-04-19T12:00:00Z",
    "sth_records": [ { } ]
}
~~~

| Type | Meaning |
|---|---|
| `snapshot` | One STH the monitor observed. Carries one record. |
| `verification` | Two STHs (an earlier and a later) that the monitor cross-checked using a consistency proof from the same domain. Carries both. |
| `equivocation` | Two STHs for the same `log_size` with different `root_hash` values that the monitor obtained from the same domain. Carries both. Equivocation MUST be reported as soon as observed. |

<a id="observation-verification"></a>

### Observation Verification
A client consuming `key_transparency` observations MUST:

* Verify the signature on every STH in `sth_records`
  against the subject domain's current or
  recently-rotated signing key.
* For `type: "verification"`, recompute the consistency
  proof against the two STHs' roots and reject the
  observation if verification fails.
* For `type: "equivocation"`, verify that both STHs are
  signed by the subject domain and that they have the
  same `log_size` with different `root_hash`. If either
  property fails, the observation is malformed.

A malformed observation MUST be discarded from local
processing. The consumer MAY publish an
`observation_record_abuse` report against the publisher,
per the abuse-category rules in
[Delivery](delivery.md), in cases of systematic
malformedness (multiple malformed records from the same
publisher within a short window). Publishing a report
against every single malformed record is not required
because consumers face a cost-of-reporting trade-off, but
visible patterns SHOULD be reported.

A verified `equivocation` observation MUST be treated as
strong evidence that the subject domain is misbehaving;
the client SHOULD refuse to accept keys from that domain
until the equivocation is explained or mitigated by
operator action.

A verified `verification` or `snapshot` observation whose
STH contradicts the STH the client received on a key
fetch (same subject domain and similar `log_size`,
different `root_hash`) constitutes client-level
equivocation detection. The client SHOULD treat this
equivalently to a verified `equivocation` observation.

A client receiving an `equivocation` observation about a
subject domain MUST treat that domain as untrusted for the
purposes of new key acceptance until the equivocation is
resolved or until operator policy explicitly overrides.

<a id="revocation-shadowing"></a>

### Revocation Shadowing
Revocation records published per the key-revocation rules
in [Discovery](discovery.md) are accompanied by a
corresponding `revoke` event leaf in the log. A client
fetching a key whose log entry shows revocation MUST
treat the key as revoked, even if the key record itself
is cached from a time before the revocation was published.

<a id="transparency-conformance"></a>

## Transparency Conformance
A server claiming key transparency support MUST:

* Maintain an append-only Merkle-tree log per the
  transparency log section above.
* Append a leaf for every user identity and encryption
  key event (publish, rotate, revoke) before the event
  takes effect for key fetches.
* Publish a fresh STH at least every hour, signed by the
  domain signing key.
* Serve the `transparency_log` endpoint.
* Augment every `SEMP_KEYS` response with per-key
  `transparency` including an inclusion proof and a
  current STH.
* Never remove or modify a leaf.
* Continue serving the log for at least 2 years after
  withdrawing transparency support.
* Advertise the `transparency_log` endpoint in discovery.

A server claiming transparency support MUST NOT:

* Serve an inclusion proof that does not verify against
  the accompanying STH.
* Sign two STHs with the same `log_size` and different
  `root_hash` values under any circumstance. This is
  equivocation and is provably misbehavior.

A client that accepts keys from transparency-supporting
domains MUST:

* Verify the STH signature, freshness, and inclusion
  proof on every key fetch.
* Refuse to use a key whose transparency verification
  fails.
* Refuse to use an STH older than 1 hour.
* Surface verification failures to the user as security
  warnings, not generic connection errors.

A client consuming `key_transparency` observations MUST
verify every STH signature and, for `verification`
observations, re-verify the consistency proof.

# Security Considerations

For the consolidated adversary model under which this
section is evaluated, see
[Architecture](architecture.md).

## Recovery Secret Strength

The security of server-assisted recovery rests entirely on
the strength of the recovery secret and the KDF cost. An
attacker who obtains a bundle can attempt offline brute
force. With the RECOMMENDED KDF parameters (256 MB memory,
3 iterations, 4 lanes) and a 264-bit recovery code, the
attack is not practical on any known hardware.

A short or low-entropy passphrase is a weak recovery
secret. Clients SHOULD refuse to accept passphrases whose
estimated entropy is below 80 bits. Clients MUST NOT
silently accept weak passphrases.

## Bundle Download Exposure

A bundle downloaded by an attacker exposes the ciphertext
and the KDF parameters. The attacker's offline brute-force
cost is the dominant defense.

Clients SHOULD rotate the recovery secret periodically and
on any indication of download by a non-owner party.

## Forward Secrecy of Past Envelopes

Recovery of encryption private keys means that past
envelopes sealed under those keys are decryptable by
whoever holds the recovered bundle. This is intrinsic to
the design goal of restoring history.

## Shamir Share Confidentiality

A single Shamir share reveals no information about
`K_bundle` below the threshold. A device compromise that
leaks one share, for `threshold >= 2`, does not
compromise recovery. Clients MUST set the default
threshold `M` to at least 2 and SHOULD default to
`M = ceil(N / 2) + 1` for `N >= 3`.

## Shamir Share Provenance

The recovery set manifest binds each Shamir share to a
specific device identity public key, and each share
record carries a device signature over that binding.
Together, these defeat an attacker who attempts to inject
a forged share into a restore flow.

The manifest does not defend against an attacker who
compromises the user's current identity private key;
defense against that scenario depends on key-transparency
monitoring.

## Hostile Old Provider in Migration

An old provider that acts in bad faith cannot prevent
migration. The user executes a unilateral migration using
their old identity private key. The old identity private
key is the essential credential; provider cooperation is
not.

## Old Identity Key Compromise

If the old identity key is compromised before migration,
an attacker can forge a unilateral migration to an
address they control. Cooperative migration provides
additional defense: the old provider's signature is
required.

## Migration Record Replay

The migration record binds to specific identity keys and
timestamps and is signed by all parties. A replayed record
is detectable. Verifiers MUST NOT apply migration policy
based on a record whose bound keys are currently revoked
for a reason other than `"migrated_to"`.

## Cascading Migration

A user MAY migrate again. A third-party domain verifying
the chain MUST verify each migration record
independently. Chains longer than 8 hops SHOULD be
refused as likely evidence of abuse.

## Reassignment Oracle

A third-party domain tracking known-correspondent or
reputation for an address MUST NOT leak through its
responses whether a given address was migrated,
reassigned, or never used.

## Closure Indistinguishability

The protocol does not publish closure-specific signals. A
closed account is cryptographically indistinguishable
from an account whose user revoked their keys without
publishing replacements. This indistinguishability is a
deliberate privacy property.

## Transparency Log Equivocation

A domain that signs two STHs for the same `log_size` with
different `root_hash` values has equivocated. Without
monitor diversity, a single compromised monitor could
fail to publish equivocation observations. Operators that
rely on transparency for high-stakes accounts SHOULD rely
on observations from multiple independent monitors.

# Privacy Considerations

## Bundle Metadata

The bundle metadata is visible to anyone able to fetch
the bundle. The server MUST treat the bundle as publicly
fetchable for purposes of access control design.

## Successor and Migration Record Visibility

Successor records and migration records are public
artifacts. Any party can observe that
`alice@example.com` recovered or migrated at time T. This
is accepted as the cost of cryptographic continuity.
Users who require recovery or migration without public
announcement MUST NOT use these mechanisms.

## Reassignment Exposure

A user who later occupies the old local-part observes
historical migration records at that address through
public endpoints. The records reveal that a prior
occupant migrated. This is acknowledged disclosure.

## Transparency Log Metadata

The transparency log discloses key rotation history
publicly. Users who require this metadata to be private
SHOULD use a domain that does not support transparency,
accepting the corresponding loss of equivocation
detection.

<a id="test-vectors"></a>

# Test Vectors
The cross-language test vector corpus at `vectors/v1.0.0/` of
the SEMP specification repository pins the byte-level behavior
of the constructions in this document. The following files
exercise recovery, migration, closure, and transparency:

| File | What it pins |
|---|---|
| `account-recovery.json` | Server-assisted backup bundle: Argon2id KDF, XChaCha20-Poly1305 AEAD, `SEMP-RECOVERY-BUNDLE:` signature. |
| `recovery-shamir.json` | Device-split Shamir backup over GF(256); manifest + share signatures; threshold reconstruction round-trip. |
| `migration.json` | Cooperative migration record with the four-signature chain (old_identity, new_identity, new_domain, old_domain) under `SEMP-MIGRATION-RECORD:`. |
| `migration-notice.json` | In-window `migration_notice` rejection body and the indistinguishable post-window rejection. |
| `account-closure.json` | `SEMP_ACCOUNT_CLOSURE` signature path with the `SEMP-ACCOUNT-CLOSURE:` prefix. |
| `transparency.json` | Domain-signed Signed Tree Heads plus RFC 6962 inclusion and consistency proofs. |

# IANA Considerations

This document does not request new IANA registrations.
The media types `application/semp-recovery` and
`application/semp-migration` referenced in this document
are registered in [Envelope](envelope.md).

The signature domain-separation prefixes
(`SEMP-RECOVERY-BUNDLE:`, `SEMP-RECOVERY-MANIFEST:`,
`SEMP-RECOVERY-SHARE:`, `SEMP-SUCCESSOR-RECORD:`,
`SEMP-MIGRATION-RECORD:`, `SEMP-ACCOUNT-CLOSURE:`,
`SEMP-TRANSPARENCY-STH:`) are registered as part of the
SEMP signature domain separation table in
[Envelope](envelope.md).

# Acknowledgments

The author thanks the contributors to the SEMP
specification for review, design discussion, and
prior-art analysis.

