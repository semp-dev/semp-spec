# SEMP Account Recovery

**Sealed Envelope Messaging Protocol**  
Status: Internet-Draft  
Version: 0.2.0-draft  
Related: `KEY.md`, `CLIENT.md`, `DISCOVERY.md`, `DESIGN.md`, `CONFORMANCE.md`

---

## Abstract

This specification defines the account recovery extension for SEMP. It
specifies two optional mechanisms, server-assisted encrypted backup and
Shamir device-split backup, by which a user whose active private keys have
been lost may regain control of their account without bypassing the SEMP
trust model. It defines the backup bundle format, the recovery secret and
its derivation, the restore procedures, and the successor record by which
a recovered account authenticates its continuity to other domains.

---

## 1. Overview

### 1.1 Goals and Non-Goals

This extension enables a user to reconstruct their identity private key and
the history of their encryption private keys after loss of all devices
holding those keys, provided the user retains either a recovery secret or a
threshold number of shares distributed across still-alive devices.

In scope:

- Normative backup bundle format.
- Two recovery mechanisms: server-assisted and Shamir device-split.
- Restore procedures for both mechanisms.
- Successor record publication for trust continuity.

Not in scope:

- Recovery without any user-held artifact (no server can re-issue a user's
  private keys without violating the SEMP trust model).
- Social recovery via third-party contacts.
- Paper backup encoding (implementations MAY encode the recovery secret as
  a word list or QR code; no specific encoding is normative here).
- Operator-initiated recovery or operator override of restore. SEMP
  operators are custodians of encrypted material only. They MUST NOT
  possess, broker, or gate recovery secrets.

### 1.2 Conformance Status

This specification is a RECOMMENDED optional core module. A SEMP server
or client MAY omit support; a conformant implementation that claims
recovery support MUST comply with every requirement in this document
for the mechanisms it supports.

Optional core modules are full protocol modules that live alongside the
base SEMP specification. They define their own wire types and endpoints
and do not use the wire-level extension framework in `EXTENSIONS.md`.
See `EXTENSIONS.md` section 1 for the distinction.

A SEMP server advertises recovery support via the `backup` endpoint in
its discovery configuration (`DISCOVERY.md` section 3.1.1). Absence of
the endpoint indicates the server does not host server-assisted backups.
Shamir device-split backup is entirely client-side and requires no
server support.

### 1.3 Terminology

| Term                     | Definition                                                                 |
|--------------------------|----------------------------------------------------------------------------|
| Backup bundle            | Signed, encrypted container holding the user's identity private key and encryption key history. |
| Recovery secret          | User-controlled secret used to derive the bundle encryption key and the recovery key pair. |
| Recovery key pair        | Deterministically derived Ed25519 key pair used to sign successor records. |
| Successor record         | Publication that links a recovered account's new identity key to the prior one. |
| Device share             | One of N Shamir shares produced by splitting the bundle encryption key for Shamir device-split backup. |

---

## 2. Backup Bundle Structure

### 2.1 Bundle Schema

```json
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
```

### 2.2 Bundle Fields

| Field                | Type            | Required | Description                                                                        |
|----------------------|-----------------|----------|------------------------------------------------------------------------------------|
| `type`               | `string`        | Yes      | MUST be `"SEMP_BACKUP_BUNDLE"`.                                                    |
| `version`            | `string`        | Yes      | Backup format version (semver).                                                    |
| `user_id`            | `string`        | Yes      | Full SEMP address the bundle belongs to.                                           |
| `bundle_id`          | `string`        | Yes      | Unique identifier for this bundle. ULID RECOMMENDED.                               |
| `created_at`         | `string`        | Yes      | ISO 8601 UTC creation timestamp.                                                   |
| `supersedes`         | `string\|null`  | Yes      | `bundle_id` of the prior bundle, or `null` for the first bundle.                   |
| `kdf`                | `object`        | Yes      | Key derivation parameters. See section 2.5.                                        |
| `payload_algorithm`  | `string`        | Yes      | AEAD algorithm for the payload. MUST be `xchacha20-poly1305`.                      |
| `payload_nonce`      | `string`        | Yes      | Base64-encoded 24-byte nonce for payload encryption.                               |
| `encrypted_payload`  | `string`        | Yes      | Base64-encoded ciphertext of the payload.                                          |
| `recovery_verify_pk` | `object`        | Yes      | Public key used to verify successor records. Derived deterministically per section 3.3. |
| `signature`          | `object`        | Yes      | Identity key signature over the canonical bundle bytes with `signature.value` set to `""`. |

### 2.3 Payload Schema

The decrypted payload is a JSON object:

```json
{
    "identity_key": {
        "algorithm": "ed25519",
        "public_key": "base64",
        "private_key": "base64",
        "created": "2025-01-15T08:30:00Z",
        "expires": "2026-01-15T08:30:00Z"
    },
    "encryption_keys": [
        {
            "algorithm": "pq-kyber768-x25519",
            "key_id": "key-fingerprint",
            "public_key": "base64",
            "private_key": "base64",
            "created": "2025-01-15T08:30:00Z",
            "expires": "2026-01-15T08:30:00Z",
            "superseded_at": null
        }
    ],
    "metadata": {
        "accepted_senders_version": 17
    }
}
```

| Field             | Type     | Required | Description                                                                           |
|-------------------|----------|----------|---------------------------------------------------------------------------------------|
| `identity_key`    | `object` | Yes      | The user's currently active identity key, including private key material.             |
| `encryption_keys` | `array`  | Yes      | Every encryption key the user has ever held, in creation order, including revoked ones. |
| `metadata`        | `object` | No       | Opaque client metadata. The server MUST NOT interpret this object.                    |

The payload MUST include all encryption keys ever issued for the account,
including superseded and revoked keys, so that envelopes sealed under any
of them remain decryptable after recovery.

### 2.4 Canonical Bytes and Signature

`signature` is computed over the canonical UTF-8 JSON encoding of the
bundle object with:

- Keys sorted lexicographically at every level.
- `signature.value` set to `""`.
- No insignificant whitespace.

The signature MUST be produced with the user's currently active identity
private key and MUST verify against the user's published identity public
key at the time of upload. A client MUST NOT upload an unsigned bundle.

### 2.5 Key Derivation

The bundle encryption key `K_bundle` is derived from the recovery secret as
follows:

```
K_bundle = Argon2id(
    secret   = recovery_secret_bytes,
    salt     = bundle.kdf.salt,
    memory   = bundle.kdf.memory_kb * 1024 bytes,
    time     = bundle.kdf.iterations,
    lanes    = bundle.kdf.parallelism,
    out_len  = 32
)
```

The KDF parameters MUST meet the following minima:

| Parameter   | Minimum   | RECOMMENDED default |
|-------------|-----------|---------------------|
| `memory_kb` | 65536     | 262144              |
| `iterations`| 2         | 3                   |
| `parallelism`| 1        | 4                   |
| `salt`      | 16 bytes  | 16 bytes            |

Clients generating a bundle MUST choose parameters that complete in at
least 500 milliseconds on the client's hardware, to raise brute-force
cost for attackers. Clients MUST NOT select parameters weaker than the
minima above.

`K_bundle` encrypts `payload_nonce` concatenated with the payload JSON
under `xchacha20-poly1305`, with an empty associated data field.

---

## 3. Recovery Secret

### 3.1 Secret Forms

The recovery secret is one of:

- **Passphrase form.** A user-chosen Unicode string. The client MUST
  normalize the passphrase to Unicode NFKC before KDF. The client MUST
  reject passphrases shorter than 12 UTF-8 bytes.
- **Recovery code form.** A client-generated sequence of 24 words drawn
  from the BIP-39 English word list (2048 words, 11 bits per word,
  yielding 264 bits of entropy of which 256 encode the secret and 8
  encode a checksum). The client MUST display the code to the user for
  transcription and MUST NOT store it in plaintext thereafter.

A client MUST offer the user a choice between forms at backup time. A
client MAY allow the user to switch forms by generating a fresh bundle.
Switching forms invalidates the prior bundle's KDF output; the prior
bundle MUST be marked superseded via `supersedes`.

### 3.2 Normalization

For both forms, the input to KDF is the UTF-8 encoded bytes:

- Passphrase: NFKC normalized, trimmed of leading and trailing whitespace,
  no further transformation.
- Recovery code: concatenated words separated by single ASCII space (0x20),
  lowercase.

### 3.3 Deterministic Recovery Key Pair

From the recovery secret, the client MUST also derive an Ed25519 signing
key pair used for successor records (section 7):

```
seed = HKDF-Expand(
    PRK  = Argon2id output used as bundle key,
    info = "SEMP-RECOVERY-SIGN-KEY-v1",
    L    = 32
)
(recovery_sign_sk, recovery_verify_pk) = ed25519_keygen_from_seed(seed)
```

The `recovery_verify_pk` is published in the bundle (section 2.1) and is
signed by the current identity key. The `recovery_sign_sk` is never
stored; it is re-derived from the secret at restore time.

---

## 4. Server-Assisted Backup

### 4.1 Storage Endpoint

A server supporting server-assisted backup advertises a `backup` endpoint
in its discovery configuration. The URL accepts:

- `POST`: upload a new bundle.
- `GET`: fetch the current bundle for a user.
- `GET` with `?history=true`: fetch all retained bundles for a user.
- `DELETE`: delete all stored bundles for a user.

All requests target a user-scoped path derived by appending the URL-encoded
user address to the base URL.

### 4.2 Upload

A client uploads a bundle via `POST` with body as defined in section 2.1.
The upload is authenticated on the client's current authenticated session
with the home server. The server MUST:

1. Verify the bundle's `signature` against the user's currently active
   identity key.
2. Verify that `user_id` matches the authenticated user.
3. Verify that `supersedes` matches the current stored `bundle_id` for
   that user, or is `null` if no prior bundle exists.
4. Store the bundle.
5. Retain superseded bundles for at least 30 days before deletion.

A server MUST NOT decrypt or attempt to decrypt `encrypted_payload`. A
server MUST NOT examine the payload's contents through any mechanism.

### 4.3 Download

A client downloads a bundle via `GET`. The server MUST serve bundle
downloads without requiring an authenticated session bound to the user,
since the common case for download is that the user has no remaining
private keys with which to authenticate.

The server MUST apply rate limits per source IP and per `user_id` to
raise the cost of brute-force attacks against the KDF. A RECOMMENDED
limit is 10 download requests per user address per hour across all
sources. When the limit is exceeded, the server MUST respond with HTTP
429.

The server MUST NOT expose bundle metadata (such as `created_at` or
`bundle_id`) through any interface that does not require downloading
the bundle itself. An anonymous existence probe is an oracle and is
prohibited.

### 4.4 Versioning and Retention

The server MUST retain the current bundle indefinitely. Superseded
bundles MUST be retained for at least 30 days after being superseded,
so that a recovering user with an older recovery secret can still
restore. A server MAY retain superseded bundles longer.

A server MUST NOT delete the current bundle except on a `DELETE`
request authenticated on the user's current session.

### 4.5 Bundle Compromise Response

If a user believes their recovery secret has been compromised, the
user rotates by:

1. Authenticating with an existing device that holds the identity key.
2. Generating a new recovery secret.
3. Uploading a new bundle with `supersedes` set to the current
   `bundle_id`.

The server MUST accept the upload, mark the prior bundle as superseded,
and honor retention rules on the prior bundle.

---

## 5. Shamir Device-Split Backup

### 5.1 Splitting

A client MAY back up `K_bundle` across the user's registered devices using
Shamir's Secret Sharing over GF(256) with a threshold `M` and share count
`N`, where `2 <= M <= N <= 16`.

The client MUST:

1. Derive `K_bundle` from the recovery secret per section 2.5.
2. Apply Shamir's Secret Sharing to `K_bundle` with parameters `(M, N)`.
3. Transmit one share to each of the user's `N` registered devices over
   the multi-device sync channel defined in `KEY.md` section 10.2.

Each device stores its share in local secure storage. A device MUST NOT
transmit its share to the server or to any non-device party.

### 5.2 Share Record

Each share is transmitted as:

```json
{
    "type": "SEMP_RECOVERY_SHARE",
    "version": "1.0.0",
    "bundle_id": "bundle-ulid",
    "share_index": 3,
    "threshold": 3,
    "total_shares": 5,
    "share_value": "base64-encoded-share-bytes",
    "issued_at": "2026-04-18T10:00:00Z",
    "signature": {
        "algorithm": "ed25519",
        "key_id": "current-identity-key-fingerprint",
        "value": "base64-signature"
    }
}
```

The receiving device MUST verify the signature against the user's current
identity key before storing the share.

### 5.3 Reconstruction

To reconstruct `K_bundle`, the user MUST assemble shares from at least
`M` still-alive devices. The user's new device (the one performing the
restore) collects shares through a local transfer mechanism: QR code
display on each alive device scanned by the new device, direct local
network transfer over an authenticated channel, or USB export.

Share transfer MUST NOT go through the home server or any other remote
party. The server is not a participant in Shamir-mode restore.

After assembling `M` shares, the client reconstructs `K_bundle` via
Lagrange interpolation and proceeds to the common restore flow
(section 6).

---

## 6. Restore Flow

### 6.1 Server-Assisted Restore

On a fresh device with no prior keys, the user:

1. Provides the `user_id` of the account to restore.
2. Provides the recovery secret in the form used at backup time.
3. The client fetches the current bundle via `GET` to the `backup`
   endpoint advertised by the user's home server's discovery document.
4. The client derives `K_bundle` via KDF (section 2.5) using the
   bundle's stored `kdf` parameters.
5. The client decrypts `encrypted_payload` using `K_bundle`.
6. The client verifies that the payload decrypts to valid JSON matching
   the schema in section 2.3. A decryption failure MUST be surfaced to
   the user as a likely incorrect recovery secret.
7. The client verifies that the bundle's outer `signature` verifies
   against some historically published identity key for `user_id`
   (possibly the key encoded in the payload itself, for self-consistency
   verification).
8. The client proceeds to section 6.3 (new key generation).

### 6.2 Shamir Restore

On a fresh device with no prior keys:

1. The user identifies `M` of their still-alive devices.
2. The client collects `M` `SEMP_RECOVERY_SHARE` records from those
   devices via local transfer (section 5.3).
3. The client verifies each share's signature against some historically
   published identity key for `user_id`.
4. The client verifies that all shares agree on `bundle_id`, `threshold`,
   and `total_shares`.
5. The client reconstructs `K_bundle` via Shamir interpolation.
6. The client fetches the corresponding bundle from the home server via
   `GET`, matching on `bundle_id`.
7. The client decrypts the payload as in section 6.1, steps 5 through 7.
8. The client proceeds to section 6.3.

### 6.3 New Key Generation

After successful decryption, the client holds the user's prior identity
private key and encryption private key history. The client MUST NOT
reuse the prior identity key as the account's current identity key.
Instead:

1. Generate a fresh identity key pair.
2. Generate a fresh encryption key pair.
3. Publish the new identity key and encryption key via the home server's
   key registration endpoint (`CLIENT.md` section 2.2).
4. Publish a successor record per section 7 linking the prior identity
   key to the new identity key.
5. Sign the prior identity key's revocation record per `KEY.md` section
   8.1, using the prior identity key that the user now holds from the
   decrypted payload. This signs out the old key under its own
   authority.

The prior encryption key history MUST be retained by the client for
decryption of archived envelopes but MUST NOT be republished or reused
for new envelope encryption. New envelopes addressed to the user use the
fresh encryption key.

### 6.4 Restore-Time Device Registration

The restoring device is a fresh device from the account's point of view.
After new key generation (section 6.3), the device MUST register itself
with the home server per `KEY.md` section 10.1.

### 6.5 Failure Modes

The restore flow distinguishes two failure classes:

- **Wrong secret.** Decryption of `encrypted_payload` fails AEAD
  verification. The client MUST surface this as a probable wrong
  recovery secret and MUST allow the user to retry, subject to server
  rate limits (section 4.3).
- **Corrupt or tampered bundle.** The payload decrypts to
  malformed JSON, or `signature` verification fails. The client MUST
  surface this as a bundle integrity failure and MUST NOT proceed to
  key generation. The client SHOULD fetch historical bundles via
  `GET ?history=true` and attempt restore against each.

---

## 7. Successor Record

### 7.1 Purpose

The successor record authenticates a recovered account's continuity to
third-party domains. Other domains MAY choose to preserve reputation,
correspondent relationships, and history bindings to the prior identity
key based on successor record verification.

### 7.2 Schema

```json
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
```

### 7.3 Signatures

The record carries three signatures, all over the canonical bytes of
the record with the corresponding signature's `value` set to `""`:

- `recovery_signature`: produced by `recovery_sign_sk` derived from the
  recovery secret per section 3.3. Verifiable using
  `recovery_verify_pk` published in the bundle and signed by the prior
  identity key at bundle upload time.
- `new_key_signature`: produced by the new identity private key.
  Confirms the new key's consent to the successor record.
- `domain_signature`: produced by the home server's domain signing key.
  Confirms the home server's participation.

All three signatures MUST be present. Verifiers that cannot obtain all
three MUST treat the successor record as unverified.

### 7.4 Publication

The home server MUST publish successor records via the same mechanism as
key revocation records (`KEY.md` section 8.3). A conformant home server
MUST include successor records in the user's published key record
history.

### 7.5 Verification by Third-Party Domains

A third-party domain verifying a successor record MUST:

1. Fetch the prior user key record for `user_id` and extract the
   `recovery_verify_pk` that was published in the corresponding backup
   bundle, as signed by the prior identity key. The home server MUST
   expose the `recovery_verify_pk` as a field in the historical key
   record so that third parties can fetch it without fetching the
   bundle itself.
2. Verify `recovery_signature` over the canonical record bytes using
   `recovery_verify_pk`.
3. Verify `new_key_signature` using `new_public_key`.
4. Verify `domain_signature` using the home server's current domain
   signing key.
5. Verify that `recovered_at` is not in the future and not earlier than
   the prior identity key's `created` timestamp.

If all verifications succeed, the domain MAY honor the continuity
claim. Honoring continuity is a local policy decision. A domain MUST
NOT be required by this specification to honor continuity.

### 7.6 Policy Options for Third-Party Domains

Domains choosing to honor a successor record MAY apply any of the
following policies:

- Preserve the prior key's reputation signal on the new key.
- Preserve the "known correspondent" relationship between their users
  and the recovered user.
- Migrate block list entries from the prior key to the new key.

Domains choosing not to honor a successor record MUST treat the new
identity key as a fresh identity with no prior history. This is the
conservative default.

---

## 8. Security Considerations

### 8.1 Recovery Secret Strength

The security of server-assisted recovery rests entirely on the strength
of the recovery secret and the KDF cost. An attacker who obtains a
bundle can attempt offline brute force. With the RECOMMENDED KDF
parameters (256 MB memory, 3 iterations, 4 lanes) and a 264-bit
recovery code, the attack is not practical on any known hardware.

A short or low-entropy passphrase is a weak recovery secret. The
specification RECOMMENDS the recovery code form for users who do not
use a password manager. Clients SHOULD refuse to accept passphrases
whose estimated entropy is below 80 bits, as measured by any reasonable
entropy estimator. Clients MUST NOT silently accept weak passphrases.

### 8.2 Bundle Download Exposure

A bundle downloaded by an attacker exposes the ciphertext and the KDF
parameters. The attacker's offline brute-force cost is the dominant
defense. The specification does NOT rely on download rate limiting as
a primary defense; rate limiting is a secondary friction only.

Clients SHOULD rotate the recovery secret (and therefore the bundle)
periodically and on any indication of download by a non-owner party.
Operators SHOULD log bundle download access events with source IP and
User-Agent for operator review by the account owner through a separate
audit endpoint. This spec does not define that endpoint.

### 8.3 Server Trust Model

The server learns:

- That a bundle exists for a given `user_id`.
- The bundle's `bundle_id`, `created_at`, `supersedes`, KDF parameters,
  `recovery_verify_pk`, and `signature`.
- When bundles are downloaded.

The server does not learn:

- The recovery secret.
- The bundle payload.
- The prior or new identity private keys.
- Whether the recovery secret is the passphrase form or the recovery
  code form.

The server cannot unilaterally initiate or gate a restore. A server
that refuses to serve bundle downloads is a recoverable denial of
service: the user may relocate their account to another domain through
standard provider migration once that mechanism is specified.

### 8.4 Compromised Identity Key During Backup Rotation

A compromised identity key can upload a fresh bundle, replacing the
current one. This does not directly expose the user's payload (the
attacker does not hold the recovery secret), but it can lock the
legitimate user out by rendering their known recovery secret
ineffective.

Defense: retention of superseded bundles (section 4.4). A user
recovering with an older recovery secret can restore from a retained
prior bundle and then rotate. Clients SHOULD surface the list of
available historical bundles to the user during a failed-current-secret
restore flow.

### 8.5 Forward Secrecy of Past Envelopes

Recovery of encryption private keys means that past envelopes sealed
under those keys are decryptable by whoever holds the recovered
bundle. This is intrinsic to the design goal of restoring history.

Users who require forward secrecy for specific content SHOULD use
short expiry windows on envelopes containing such content, combined
with separate ephemeral keys outside the recoverable history. Such
mechanisms are out of scope for this specification.

### 8.6 Shamir Share Confidentiality

A single Shamir share reveals no information about `K_bundle` below
the threshold. A device compromise that leaks one share, for
`threshold >= 2`, does not compromise recovery. A device compromise
that leaks `threshold` or more shares compromises recovery and
downgrades to the server-assisted threat model (attacker needs only
the bundle ciphertext, which is available via `GET`).

Clients MUST set the default threshold `M` to at least 2 and SHOULD
default to `M = ceil(N / 2) + 1` for `N >= 3`.

### 8.7 Key Substitution Resistance

The successor record's `recovery_signature` binds the new identity key
to a signature verifiable by the prior bundle's `recovery_verify_pk`.
An attacker who compromises the home server cannot substitute a
fraudulent successor record without also holding the recovery secret,
because `recovery_verify_pk` is signed by the prior identity key at
bundle upload time and is verifiable by any party that fetched the
prior key record.

---

## 9. Privacy Considerations

### 9.1 Bundle Metadata

The bundle metadata (`user_id`, `bundle_id`, `created_at`, `supersedes`,
`recovery_verify_pk`, `signature`) is visible to anyone able to fetch
the bundle. The server MUST treat the bundle as publicly fetchable for
purposes of access control design. Clients SHOULD NOT include identifying
extensions or non-required fields in the bundle.

### 9.2 Access Correlation

Bundle downloads are observable to the server. Users sensitive to this
exposure SHOULD use Tor or another anonymizing transport when performing
a restore.

### 9.3 Successor Record Visibility

Successor records are public key-record artifacts. Any party can observe
that `alice@example.com` recovered at time T. This is accepted as the
cost of cryptographic continuity.

---

## 10. Conformance

### 10.1 Client Conformance

A client claiming server-assisted recovery support MUST:

- Generate backup bundles per section 2 on initial key provisioning
  and on every identity or encryption key rotation.
- Upload bundles to the user's home server via the advertised `backup`
  endpoint.
- Normalize passphrases to NFKC before KDF.
- Refuse passphrases below the minimum entropy threshold (section 8.1).
- Derive `recovery_sign_sk` and `recovery_verify_pk` deterministically
  per section 3.3.
- Generate fresh identity and encryption key pairs on restore, rather
  than reusing recovered keys as current keys.
- Publish a successor record per section 7 on every restore.
- Revoke the prior identity key immediately after restore using the
  recovered private key.

A client claiming Shamir device-split recovery support MUST additionally:

- Distribute shares over the multi-device sync channel per section 5.1.
- Verify share signatures against the current identity key before
  storing.
- Transfer shares during reconstruction only through local channels,
  never through the home server.

### 10.2 Server Conformance

A server claiming server-assisted recovery support MUST:

- Advertise a `backup` endpoint in its discovery configuration.
- Verify bundle `signature` against the user's current identity key on
  upload.
- Verify `supersedes` linkage on upload.
- Serve bundle downloads without requiring an authenticated session.
- Apply per-user and per-IP rate limits on downloads.
- Retain superseded bundles for at least 30 days.
- Expose `recovery_verify_pk` in the user's historical key record so
  that third-party domains can verify successor records without
  fetching the bundle itself.
- Not decrypt or attempt to decrypt `encrypted_payload`.
- Not expose bundle metadata through any interface that does not
  require downloading the bundle itself.

### 10.3 Third-Party Domain Conformance

A third-party domain choosing to honor successor records MUST verify
all three signatures and the timing constraint per section 7.5. A
third-party domain choosing not to honor successor records MUST treat
the new identity key as a fresh identity per section 7.6.

---

## 11. Relationship to Other Specifications

| Specification    | Relationship                                                                                            |
|------------------|---------------------------------------------------------------------------------------------------------|
| `DESIGN.md`      | Honors operator-non-trust: the server is a custodian only, not a recovery authority.                     |
| `KEY.md`         | Backup payload carries keys defined in `KEY.md` section 1.1. Revocation uses section 8.1.                |
| `CLIENT.md`      | New key publication after restore uses the key registration protocol in section 2.2.                     |
| `DISCOVERY.md`   | The `backup` endpoint is advertised in the discovery configuration (section 3.1.1).                      |
| `CONFORMANCE.md` | This document's conformance requirements are referenced from `CONFORMANCE.md`.                           |
| `EXTENSIONS.md`  | Account recovery is a RECOMMENDED optional core module, not a wire-level extension. It does not appear in any `extensions` field and does not use the `semp.dev/<name>` extension namespace. |

---

*This document is an Internet-Draft. It is subject to revision prior to
finalization as a stable specification.*
