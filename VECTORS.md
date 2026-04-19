# SEMP Test Vectors

**Sealed Envelope Messaging Protocol**
Status: Internet-Draft
Version: 0.1.0
Related: `DESIGN.md`, `ENVELOPE.md`, `HANDSHAKE.md`, `SESSION.md`, `KEY.md`,
`DISCOVERY.md`, `CONFORMANCE.md`

---

## Abstract

This document provides canonical test vectors for SEMP implementations. Each
vector specifies deterministic inputs and expected outputs for a single
protocol operation. An implementation that produces the expected output for
every applicable vector is interoperable at that operation. An implementation
that produces different output has a bug.

These vectors cover only deterministic operations: key derivation, canonical
serialization, MAC computation, challenge verification, and confirmation
hashing. Operations that depend on random input (key generation, nonce
generation, encryption) cannot be tested with static vectors. Those operations
are tested indirectly through round-trip vectors where both encryption and
decryption inputs are provided.

---

## 1. Notation

All byte strings are represented as hexadecimal unless otherwise noted. Base64
values are standard base64 with padding (RFC 4648 §4). JSON strings are UTF-8.

| Notation        | Meaning                                              |
|-----------------|------------------------------------------------------|
| `hex:`          | Hexadecimal-encoded byte string.                     |
| `b64:`          | Standard base64-encoded byte string.                 |
| `utf8:`         | UTF-8 encoded string, shown as literal text.         |
| `||`            | Byte concatenation.                                  |
| `len: N`        | Length in bytes.                                      |

---

## 2. HKDF-SHA-512 Session Key Derivation

Reference: `HANDSHAKE.md` §2.4, `SESSION.md` §2.1, `ENVELOPE.md` §7.3.1.

These vectors verify that an implementation correctly derives the five session
keys from a known shared secret, client nonce, and server nonce. The KDF
(HKDF-SHA-512) and MAC (HMAC-SHA-256) used in these vectors are determined by
the negotiated algorithm suite. Both currently defined suites,
`x25519-chacha20-poly1305` and `pq-kyber768-x25519`, specify HKDF-SHA-512
for key derivation and HMAC-SHA-256 for MAC operations. Future suites may
specify different primitives; test vectors for those suites would be added
when they are defined.

### 2.1 Vector: Baseline Key Derivation

**Inputs:**

Shared secret (IKM): 64 bytes, representing the combined output of a hybrid
key agreement (`K_kyber || K_x25519`). This is a synthetic test value, not the
output of a real Kyber768 or X25519 operation.

```
IKM (hex): 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
            0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
            0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c
            0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c
```

That is, 32 bytes of `0x0b` followed by 32 bytes of `0x0c`.

Client nonce (32 bytes):

```
client_nonce (hex): aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

Server nonce (32 bytes):

```
server_nonce (hex): bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
```

**Derivation procedure:**

1. Compute salt: `client_nonce || server_nonce` (64 bytes).
2. HKDF-Extract(salt, IKM) → PRK.
3. For each key, HKDF-Expand(PRK, info_label, 32) → key.

**Info labels (UTF-8 encoded):**

```
K_enc_c2s:  "SEMP-v1-session-enc-c2s"
K_enc_s2c:  "SEMP-v1-session-enc-s2c"
K_mac_c2s:  "SEMP-v1-session-mac-c2s"
K_mac_s2c:  "SEMP-v1-session-mac-s2c"
K_env_mac:  "SEMP-v1-session-env-mac"
```

**Expected PRK (64 bytes):**

```
PRK (hex): 1ca5eed820a07ef313053ec19352a69c
           6dd00c924139d012ff571faa55f07037
           087ced0021ce2b853c3ee8ffeabea069
           7586d06f989c315cab24859bb3b9ef6e
```

**Expected session keys (32 bytes each):**

```
K_enc_c2s (hex): cf74d91d41de6ac8f838715bc44a31d7
                 e23b8e9b4dd7dab6be6ad4b8d0567af6

K_enc_s2c (hex): bed26f42d9b1762ab5665b429ef51131
                 6e2f9a9be7b4721a310488b3540f90cd

K_mac_c2s (hex): 7f7c8b61c27e91c160dba88063346afb
                 920b99fa2736aa0c54b5d022ff58484e

K_mac_s2c (hex): 7905bf680e3095c0b71b4d331c2a5863
                 16171ab6ad072842b5bea4a0c374723a

K_env_mac (hex): 32925224f762c4f921db929271bfdc5e
                 911b0d877bc30cd4695f9d6530337c02
```

**Verification:** An implementation MUST derive all five keys from the given
IKM, salt, and labels and compare against these expected values. Any mismatch
indicates incorrect HKDF-SHA-512 usage, incorrect label encoding, or incorrect
salt construction.

### 2.2 Vector: Rekey Derivation

Reference: `SESSION.md` §3.3.

Rekeying uses a different info context: `"SEMP-v1-rekey"`. The salt is
`rekey_nonce || responder_nonce`. All other parameters are identical to the
initial derivation.

**Inputs:**

```
IKM (hex):            d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1
                      d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1
                      e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2
                      e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2

rekey_nonce (hex):    cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc

responder_nonce (hex):dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
```

**Derivation procedure:**

1. Compute salt: `rekey_nonce || responder_nonce` (64 bytes).
2. HKDF-Extract(salt, IKM) → PRK.
3. For each key, HKDF-Expand(PRK, info_label, 32) → key, using the same
   five label strings as section 2.1 but applied to the new PRK.

**Note:** The info labels for rekey derivation use the same key-specific labels
as the initial derivation (`"SEMP-v1-session-enc-c2s"`, etc.). The
`"SEMP-v1-rekey"` context string distinguishes the rekey from the initial
derivation through the different salt (rekey nonces vs. session nonces), not
through the per-key expand labels.

Implementations MUST produce identical keys when given the same IKM, salt, and
labels, regardless of whether the derivation occurs during an initial handshake
or a rekey. The PRK will differ because the salt differs.

**Expected PRK (64 bytes):**

```
PRK (hex): 3e62694adf1c3ae0bf998d6c74498ba7
           148406359c374cbd6fa54f14ca2a2561
           260c9bc3944c48204505f4ad8455958a
           616b2c5b9ba0eebe99ee6ad15eac9c23
```

**Expected session keys (32 bytes each):**

```
K_enc_c2s (hex): b3b8093896f5ed916ebe6a55b6a0d3e0
                 dc1bb6bf6e23f58a317f01135c4dead0

K_enc_s2c (hex): c10997d1c541bffa1131ee886a3ab372
                 e4622603f168f6e3bb69caf4bdf93910

K_mac_c2s (hex): 3b723faad0d05e17bb96b82efcec2257
                 a3900bd00b30ae7dc0254b59e3abe153

K_mac_s2c (hex): 1f91269a2493c11eb02a61114b8debe7
                 499a38e2cd0886ae3ee715383bac6ab6

K_env_mac (hex): 187cd04362c27d37f95c6cc4558935398
                 037a13f1c6015e23dbef97ba3aa8db3
```

---

## 3. Envelope Canonicalization

Reference: `ENVELOPE.md` §4.3.

These vectors verify that an implementation produces the correct canonical byte
sequence from a given envelope, which is the input to both `seal.signature` and
`seal.session_mac` computation.

### 3.1 Vector: Minimal Envelope

**Input envelope (as parsed JSON):**

```json
{
    "type": "SEMP_ENVELOPE",
    "version": "1.0.0",
    "postmark": {
        "id": "01J4K7P2XVEM3Q8YNZHBRC5T06",
        "session_id": "01J4K7Q0ABCDEFGHJKLMNPQRST",
        "from_domain": "sender.example",
        "to_domain": "recipient.example",
        "expires": "2025-06-10T21:00:00Z",
        "hop_count": 2,
        "extensions": {}
    },
    "seal": {
        "algorithm": "pq-kyber768-x25519",
        "key_id": "abc123def456",
        "signature": "existing-signature-value",
        "session_mac": "existing-mac-value",
        "brief_recipients": {},
        "enclosure_recipients": {},
        "extensions": {}
    },
    "brief": "ZW5jcnlwdGVkLWJyaWVm",
    "enclosure": "ZW5jcnlwdGVkLWVuY2xvc3VyZQ=="
}
```

**Canonicalization rules applied:**

1. `seal.signature` → set to `""`
2. `seal.session_mac` → set to `""`
3. `postmark.hop_count` → omitted entirely
4. All keys sorted lexicographically at every nesting level
5. No insignificant whitespace
6. UTF-8 encoding

**Expected canonical form (UTF-8 string):**

```
{"brief":"ZW5jcnlwdGVkLWJyaWVm","enclosure":"ZW5jcnlwdGVkLWVuY2xvc3VyZQ==","postmark":{"expires":"2025-06-10T21:00:00Z","extensions":{},"from_domain":"sender.example","id":"01J4K7P2XVEM3Q8YNZHBRC5T06","session_id":"01J4K7Q0ABCDEFGHJKLMNPQRST","to_domain":"recipient.example"},"seal":{"algorithm":"pq-kyber768-x25519","brief_recipients":{},"enclosure_recipients":{},"extensions":{},"key_id":"abc123def456","session_mac":"","signature":""},"type":"SEMP_ENVELOPE","version":"1.0.0"}
```

**Key observations for implementers:**

- `hop_count` is absent from the canonical output even though it was present
  in the input (value `2`).
- `seal.signature` and `seal.session_mac` are present as empty strings, not
  omitted.
- Top-level keys are sorted: `brief`, `enclosure`, `postmark`, `seal`, `type`,
  `version`.
- `postmark` keys are sorted: `expires`, `extensions`, `from_domain`, `id`,
  `session_id`, `to_domain`. Note `hop_count` is missing.
- `seal` keys are sorted: `algorithm`, `brief_recipients`,
  `enclosure_recipients`, `extensions`, `key_id`, `session_mac`, `signature`.
- Empty objects `{}` are preserved, not omitted.

### 3.2 Vector: Envelope with Extensions

**Input envelope:**

```json
{
    "type": "SEMP_ENVELOPE",
    "version": "1.0.0",
    "postmark": {
        "id": "01JTEST00000000000000000000",
        "session_id": "01JTEST11111111111111111111",
        "from_domain": "alpha.example",
        "to_domain": "beta.example",
        "expires": "2025-07-01T12:00:00Z",
        "extensions": {
            "vendor.example.com/priority": "high",
            "another.example.com/class": "transactional"
        }
    },
    "seal": {
        "algorithm": "x25519-chacha20-poly1305",
        "key_id": "key-fingerprint-xyz",
        "signature": "to-be-replaced",
        "session_mac": "to-be-replaced",
        "brief_recipients": {
            "server-key-fp": "wrapped-K_brief-for-server",
            "client-key-fp": "wrapped-K_brief-for-client"
        },
        "enclosure_recipients": {
            "client-key-fp": "wrapped-K_enclosure-for-client"
        },
        "extensions": {}
    },
    "brief": "YnJpZWYtZGF0YQ==",
    "enclosure": "ZW5jbG9zdXJlLWRhdGE="
}
```

**Expected canonical form:**

```
{"brief":"YnJpZWYtZGF0YQ==","enclosure":"ZW5jbG9zdXJlLWRhdGE=","postmark":{"expires":"2025-07-01T12:00:00Z","extensions":{"another.example.com/class":"transactional","vendor.example.com/priority":"high"},"from_domain":"alpha.example","id":"01JTEST00000000000000000000","session_id":"01JTEST11111111111111111111","to_domain":"beta.example"},"seal":{"algorithm":"x25519-chacha20-poly1305","brief_recipients":{"client-key-fp":"wrapped-K_brief-for-client","server-key-fp":"wrapped-K_brief-for-server"},"enclosure_recipients":{"client-key-fp":"wrapped-K_enclosure-for-client"},"extensions":{},"key_id":"key-fingerprint-xyz","session_mac":"","signature":""},"type":"SEMP_ENVELOPE","version":"1.0.0"}
```

**Key observations:**

- Extension keys within `postmark.extensions` are sorted lexicographically:
  `another.example.com/class` before `vendor.example.com/priority`.
- `brief_recipients` keys are sorted: `client-key-fp` before `server-key-fp`.
- No `hop_count` was present in the input, so none appears in the output.
  The canonicalization is the same whether `hop_count` was absent or present.

---

## 4. Proof-of-Work Verification

Reference: `HANDSHAKE.md` §2.2b, `REPUTATION.md` §8.3.

These vectors verify that an implementation correctly validates proof of work
challenge solutions.

### 4.1 Vector: Valid Proof of Work Solution (Difficulty 16)

**Inputs:**

```
prefix (raw bytes, hex): 4a8f2c1d3b5e7a9f0d6c8b4e2a1f3d5c
challenge_id:            01JTEST22222222222222222222
nonce (raw bytes, hex):  000000000000adb7
```

**Preimage construction:**

The preimage is the UTF-8 encoding of:
```
<base64(prefix)> || ":" || <challenge_id> || ":" || <base64(nonce)>
```

Where:
```
base64(prefix):       So8sHTteep8NbItOKh89XA==
challenge_id:         01JTEST22222222222222222222
base64(nonce):        AAAAAAAArbc=
```

Full preimage string:
```
So8sHTteep8NbItOKh89XA==:01JTEST22222222222222222222:AAAAAAAArbc=
```

**Expected hash:**

```
SHA-256(preimage) (hex): 0000cfa08ac13df837194fecda38add1
                         267f3682fc7981cfab886d7c7c00caf4
```

First two bytes are `0x00 0x00` (16 leading zero bits).

**Verification steps:**

1. Confirm `challenge_id` matches an issued, unexpired challenge.
2. Reconstruct the preimage string from the components.
3. Compute SHA-256 over the UTF-8 bytes of the preimage string.
4. Confirm the hash has at least 16 leading zero bits (first two bytes are
   `0x00`).
5. Confirm the submitted hash matches the computed hash.

**Result:** PASS. The hash has exactly 16 leading zero bits, satisfying
difficulty 16.

### 4.2 Vector: Failed Proof of Work Solution (Insufficient Difficulty)

**Inputs:**

Same prefix and challenge_id as section 4.1.

```
nonce (raw bytes, hex): 0000000000000001
```

**Preimage:**
```
So8sHTteep8NbItOKh89XA==:01JTEST22222222222222222222:AAAAAAAAAAE=
```

**Expected hash:**

```
SHA-256(preimage) (hex): 011599577d9ecb9005422686c7635d32
                         eb2b2f7f1c8b3972ff102b497f9ae7c6
```

First byte is `0x01` (only 7 leading zero bits).

**Result:** FAIL. The hash has only 7 leading zero bits, which is fewer
than the required 16. The solution MUST be rejected.

### 4.3 Proof of Work Preimage Construction Reference

The preimage is always constructed as:

```
base64(prefix) + ":" + challenge_id + ":" + base64(nonce)
```

All three components are encoded as UTF-8 strings. The colons are literal
`":"` characters (UTF-8 byte `0x3a`). The SHA-256 hash is computed over the
raw UTF-8 bytes of this string, not over any further encoding of it.

Difficulty `N` requires the first `N` bits of the SHA-256 output to be zero.
For `N = 16`, the first 2 bytes must be `0x0000`. For `N = 20`, the first 2
bytes must be `0x0000` and the high nibble of the third byte must be `0x0`.

---

## 5. Confirmation Hash

Reference: `HANDSHAKE.md` §2.5.3.

The confirmation hash binds the client's identity proof to the specific
handshake exchange.

### 5.1 Vector: Confirmation Hash Computation

**Inputs:**

Message 1 (init) canonical form:

```json
{"capabilities":{"encryption_algorithms":["pq-kyber768-x25519","x25519-chacha20-poly1305"],"extensions":["semp.dev/device-sync","semp.dev/read-receipts"]},"client_ephemeral_key":{"algorithm":"pq-kyber768-x25519","key":"Y2xpZW50LWVwaGVtZXJhbC1rZXk=","key_id":"client-eph-fp"},"extensions":{},"nonce":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqs=","party":"client","step":"init","transport":"ws","type":"SEMP_HANDSHAKE","version":"1.0.0"}
```

Message 2 (response) canonical form:

```json
{"client_nonce":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqs=","extensions":{},"negotiated":{"encryption_algorithm":"pq-kyber768-x25519","extensions":["semp.dev/device-sync","semp.dev/read-receipts"]},"party":"server","server_ephemeral_key":{"algorithm":"pq-kyber768-x25519","key":"c2VydmVyLWVwaGVtZXJhbC1rZXk=","key_id":"server-eph-fp"},"server_identity_proof":{"domain":"example.com","key_id":"server-lt-fp","signature":"c2VydmVyLXNpZw=="},"server_nonce":"u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s=","server_signature":"c2VydmVyLXNpZ25hdHVyZQ==","session_id":"01JTEST33333333333333333333","step":"response","type":"SEMP_HANDSHAKE","version":"1.0.0"}
```

**Procedure:**

```
confirmation_hash = SHA-256( canonical(message_1) || canonical(message_2) )
```

Where `canonical()` produces the UTF-8 bytes of the sorted, minified JSON
(the same canonicalization used for envelope seals). The two byte sequences
are concatenated directly with no separator.

**Expected confirmation_hash:**

```
SHA-256 (hex): 81208e0db84224eef8a6bde1510f119e
               34e4b910d63bcbb01e1e40504e851ab1

Base64:        gSCODbhCJO74pr3hUQ8RnjTkuRDWO8uwHh5AUE6FGrE=
```

The client then signs `session_id || confirmation_hash` with its long-term
identity key.

**Verification:** Given the exact canonical forms above, two implementations
MUST produce the SHA-256 output shown. Any difference indicates a
canonicalization or encoding bug.

---

## 6. Envelope Session MAC

Reference: `ENVELOPE.md` §4.3, `SESSION.md` §2.1.

The `seal.session_mac` is an HMAC computed using `K_env_mac` over the canonical
envelope bytes.

### 6.1 Vector: Session MAC Computation

**Inputs:**

`K_env_mac` from Vector 2.1:

```
K_env_mac (hex): 32925224f762c4f921db929271bfdc5e
                 911b0d877bc30cd4695f9d6530337c02
```

Canonical envelope bytes: the UTF-8 bytes of the canonical form from
section 3.1.

**Procedure:**

```
session_mac = HMAC-SHA-256(K_env_mac, canonical_envelope_bytes)
```

**Expected output:**

```
HMAC-SHA-256 (hex): b59371cec75f07a5b40444ffc46049b1
                    fa9c6673e1072903ff821ab4506c9bfe

Base64:             tZNxzsdfB6W0BET/xGBJsfqcZnPhBykD/4IatFBsm/4=
```

**Verification:** Given the same `K_env_mac` and the same canonical bytes,
two implementations MUST produce the HMAC-SHA-256 output shown. The base64
encoding of this value is stored in `seal.session_mac`. Any difference
indicates incorrect canonicalization, incorrect key usage, or an HMAC
implementation bug.

---

## 7. Discovery Response Validation

Reference: `DISCOVERY.md` §4.3, §4.6, §8.1.

These vectors verify that implementations correctly parse and validate
discovery responses.

### 7.1 Vector: Well-Formed Discovery Response

```json
{
    "type": "SEMP_DISCOVERY",
    "step": "response",
    "version": "1.0.0",
    "id": "01JTEST44444444444444444444",
    "timestamp": "2025-06-10T20:00:00Z",
    "results": [
        {
            "address": "alice@example.com",
            "status": "semp",
            "transports": ["ws", "h2"],
            "extensions": ["semp.dev/device-sync", "semp.dev/read-receipts"],
            "server": "semp.example.com",
            "ttl": 3600
        },
        {
            "address": "bob@legacy.example",
            "status": "legacy",
            "transports": ["smtp"],
            "server": "mail.legacy.example",
            "ttl": 86400
        },
        {
            "address": "charlie@nowhere.invalid",
            "status": "not_found",
            "ttl": 3600
        }
    ],
    "signature": {
        "algorithm": "ed25519",
        "key_id": "server-domain-key-fp",
        "value": "c2lnbmF0dXJlLXZhbHVl"
    },
    "extensions": {}
}
```

**Expected parsing behavior:**

| Address                   | Status      | Action                                              |
|---------------------------|-------------|-----------------------------------------------------|
| `alice@example.com`       | `semp`      | Proceed with SEMP handshake to `semp.example.com`.  |
| `bob@legacy.example`      | `legacy`    | Return `legacy_required` to client.                 |
| `charlie@nowhere.invalid` | `not_found` | Return `recipient_not_found` to client.             |

**Validation requirements:**

1. Verify `signature` against the responding server's published domain key
   before caching or acting on results.
2. Cache each result per its individual `ttl`.
3. Unknown fields in the response or result objects MUST be ignored, not
   rejected.

### 7.2 Vector: DNS TXT Capability Record Parsing

```
_semp._tcp.example.com.  3600  IN  TXT  "v=semp1;pq=ready;c=ws,h2,quic;f=groups,threads,reactions;x=unknown"
```

**Expected parsing:**

| Parameter | Value                            | Required |
|-----------|----------------------------------|----------|
| `v`       | `semp1`                          | Yes      |
| `pq`      | `ready`                          | No       |
| `c`       | `["ws", "h2", "quic"]`          | No       |
| `f`       | `["groups", "threads", "reactions"]` | No  |
| `x`       | (ignored; unknown parameter)      | --        |

The unknown parameter `x` MUST be ignored, not treated as an error.

---

## 8. Rejection Reason Code Validation

Reference: `HANDSHAKE.md` §4.1, `ENVELOPE.md` §9.3.

These vectors verify that implementations correctly categorize rejection
reason codes as recoverable or non-recoverable.

### 8.1 Handshake Rejection Codes

| Reason code         | Recoverable | Expected sender behavior                          |
|---------------------|-------------|---------------------------------------------------|
| `blocked`           | No          | Surface to user. Do not retry.                    |
| `auth_failed`       | No          | Surface to user. Do not retry.                    |
| `policy_violation`  | No          | Surface to user. Do not retry.                    |
| `handshake_expired` | Yes         | Re-handshake and retry.                           |
| `handshake_invalid` | Yes         | Re-handshake and retry.                           |
| `no_session`        | Yes         | Establish new session and retry.                  |
| `rate_limited`      | Yes         | Back off and retry.                               |
| `challenge`         | Yes         | Solve the issued challenge and continue handshake.|
| `challenge_failed`  | Yes         | Request new challenge and retry.                  |
| `server_at_capacity`| Yes         | Back off and retry later.                         |

### 8.2 Envelope Rejection Codes

| Reason code           | Recoverable | Expected sender behavior                        |
|-----------------------|-------------|-------------------------------------------------|
| `blocked`             | No          | Surface to user. Do not retry.                  |
| `seal_invalid`        | No          | Indicates a bug. Do not retry same envelope.    |
| `session_mac_invalid` | No          | Indicates a bug or session mismatch. Re-handshake before retry. |
| `envelope_expired`    | No          | Recompose with new expiry if content still relevant. |
| `handshake_invalid`   | Yes         | Establish new session and resend.               |
| `handshake_expired`   | Yes         | Establish new session and resend.               |
| `no_session`          | Yes         | Establish new session and resend.               |
| `extension_unsupported` | No        | Remove or renegotiate the unsupported extension.|
| `extension_size_exceeded` | No      | Reduce extension payload size.                  |
| `scope_exceeded`      | No          | Update device certificate scope or use a full-access device. |

---

## 9. Session Lifecycle Validation

Reference: `SESSION.md` §2.3, §2.4, §2.5, §3.

These vectors verify correct session state transitions.

### 9.1 Vector: Session State Transitions

```
State: NO_SESSION
  Event: Handshake completes (accepted)
  → State: ACTIVE
  → Store: session_id, five session keys, established_at, expires_at

State: ACTIVE
  Event: Envelope submitted with valid session_id
  → State: ACTIVE (unchanged)
  → Action: Compute seal.session_mac using K_env_mac

State: ACTIVE
  Event: expires_at reached
  → State: EXPIRED
  → Action: Erase all session keys (secure zeroing)
  → Action: Retain session_id in expiry log

State: ACTIVE
  Event: Rekey initiated at 80% of TTL
  → State: REKEYING
  → Action: Generate new ephemeral key pair

State: REKEYING
  Event: Rekey accepted
  → State: ACTIVE (new session keys)
  → Action: Erase old session keys
  → Action: Retire old session_id to expiry log
  → Action: 5-second transition window for in-flight envelopes

State: ACTIVE
  Event: New handshake from same client_identity
  → State: (old session) INVALIDATED
  → Action: Erase old session keys
  → Action: Retire old session_id to expiry log
  → State: (new session) ACTIVE

State: EXPIRED / INVALIDATED
  Event: Envelope received referencing this session_id
  → Action: Reject with reason_code "handshake_invalid"
```

### 9.2 Vector: Concurrent Session Limits

| Scenario                                  | Expected behavior                             |
|-------------------------------------------|-----------------------------------------------|
| Client A opens session, Client A opens another | Old session invalidated, new session accepted |
| Federation peer opens session while one exists  | Old session invalidated, new session accepted |
| Two federation peers initiate simultaneously    | Lower session_id lexicographically is abandoned |
| Active sessions reach server maximum            | New handshakes rejected with `server_at_capacity` |

### 9.3 Vector: Rekey Limits

| Condition                           | Expected behavior                              |
|-------------------------------------|------------------------------------------------|
| Rekey attempted before 80% of TTL   | Permitted (SHOULD wait, not MUST)              |
| Rekey attempted after session expiry | MUST be rejected; full handshake required      |
| 11th rekey in same session           | MUST be rejected; maximum 10 rekeys per session|
| Two rekeys within 60 seconds         | Second MUST be rejected; minimum 1 minute gap  |

---

## 10. Delivery Acknowledgment Mapping

Reference: `DELIVERY.md` §1.4, `CLIENT.md` §7.1.

These vectors verify that implementations correctly map server acknowledgments
to user-facing delivery states.

### 10.1 Vector: Acknowledgment to UI State

| Server acknowledgment | Client UI state                | Additional behavior                        |
|-----------------------|--------------------------------|--------------------------------------------|
| `delivered`           | Confirmed delivery indicator   | --                                          |
| `rejected`            | Failure indicator + reason     | Reason accessible to user                  |
| `silent`              | Unacknowledged (distinct)      | Must be visually distinct from above       |
| `legacy_required`     | Degradation warning            | Await user confirmation before SMTP send   |
| `recipient_not_found` | Undeliverable indicator        | No fallback available                      |
| `queued`              | Pending indicator              | Update when delivery event received        |

### 10.2 Vector: Queued → Final State Transitions

| Initial status | Delivery event status | Client action                              |
|----------------|----------------------|--------------------------------------------|
| `queued`       | `delivered`          | Update to confirmed delivery indicator     |
| `queued`       | `rejected`           | Update to failure indicator + reason       |
| `queued`       | `silent`             | Update to unacknowledged indicator         |

A client MUST NOT display a confirmed delivery indicator for a `queued`
envelope until a `delivered` event is received.

---

## 11. Submission Status Mapping

Reference: `DISCOVERY.md` §7.1, `CLIENT.md` §6.3.

### 11.1 Vector: Discovery Outcome to Submission Status

| Discovery outcome | Submission status returned to client | Client action                       |
|-------------------|--------------------------------------|-------------------------------------|
| `semp`            | (proceed with delivery)              | Envelope delivered via SEMP         |
| `legacy`          | `legacy_required`                    | Surface degradation, await confirm  |
| `not_found`       | `recipient_not_found`                | Surface as undeliverable            |

### 11.2 Vector: Multi-Recipient Mixed Outcomes

Given an envelope addressed to three recipients:

| Recipient              | Discovery outcome | Submission status       |
|------------------------|-------------------|-------------------------|
| `alice@semp.example`   | `semp`            | `delivered`             |
| `bob@legacy.example`   | `legacy`          | `legacy_required`       |
| `carol@gone.invalid`   | `not_found`       | `recipient_not_found`   |

**Expected behavior:**

- The server returns per-recipient results in the submission response.
- The client surfaces each recipient's status individually.
- The client MUST NOT suppress or aggregate partial failure.
- `legacy_required` for Bob MUST be surfaced as a per-recipient degradation
  and MUST await user confirmation before SMTP fallback.

---

## 12. Key Revocation Handling

Reference: `KEY.md` §8.

### 12.1 Vector: Revoked Key Response

When a sender fetches keys and receives:

```json
{
    "address": "user@example.com",
    "key_type": "encryption",
    "key_id": "old-key-fp",
    "revocation": {
        "reason": "key_compromise",
        "revoked_at": "2025-06-10T19:49:15Z",
        "replacement_key_id": "new-key-fp"
    }
}
```

**Expected behavior:**

| Condition                        | Action                                          |
|----------------------------------|-------------------------------------------------|
| Revocation present               | MUST NOT use `old-key-fp`                       |
| `replacement_key_id` present     | SHOULD fetch and use `new-key-fp`               |
| Key was cached locally           | MUST invalidate cached entry and re-fetch       |
| No `replacement_key_id`          | Delivery cannot proceed for this recipient      |

---

## 13. Extension Entry Validation

Reference: `EXTENSIONS.md` §2, §3, §4.

These vectors verify correct parsing and enforcement of extension entries,
criticality signaling, and size limits.

### 13.1 Vector: Extension Entry Structure

**Valid extension entry:**

```json
{
    "extensions": {
        "semp.dev/priority": {
            "required": false,
            "data": {
                "level": "urgent"
            }
        }
    }
}
```

**Expected behavior:** Extension is parsed. Since `required` is `false` and the
extension is unknown to the implementation, it is silently ignored. Envelope
processing continues normally.

### 13.2 Vector: Required Extension, Known

```json
{
    "extensions": {
        "semp.dev/message-expiry": {
            "required": true,
            "data": {
                "delete_after": "2025-07-01T00:00:00Z"
            }
        }
    }
}
```

**Expected behavior (implementation supports `semp.dev/message-expiry`):**
Extension is parsed and processed. Envelope processing continues.

**Expected behavior (implementation does NOT support `semp.dev/message-expiry`):**
Envelope is rejected with reason code `extension_unsupported`. The rejection
MUST include the key `"semp.dev/message-expiry"` so the sender can identify
which extension caused the failure.

### 13.3 Vector: Required Extension, Unknown

```json
{
    "extensions": {
        "vendor.example.com/custom-feature": {
            "required": true,
            "data": {
                "mode": "strict"
            }
        }
    }
}
```

**Expected behavior:** Envelope is rejected with reason code
`extension_unsupported`. The sender is informed that
`"vendor.example.com/custom-feature"` is not supported.

### 13.4 Vector: Extension Size Enforcement

| Layer                  | Size limit | Test payload size | Expected behavior            |
|------------------------|------------|-------------------|------------------------------|
| `postmark.extensions`  | 4 KB       | 3 KB              | Accepted                     |
| `postmark.extensions`  | 4 KB       | 5 KB              | Rejected: `extension_size_exceeded` |
| `seal.extensions`      | 4 KB       | 5 KB              | Rejected: `extension_size_exceeded` |
| `brief.extensions`     | 16 KB      | 10 KB             | Accepted                     |
| `brief.extensions`     | 16 KB      | 20 KB             | Rejected: `extension_size_exceeded` |
| `enclosure.extensions` | 64 KB      | 50 KB             | Accepted                     |
| `enclosure.extensions` | 64 KB      | 70 KB             | Rejected: `extension_size_exceeded` |

Size is measured as the serialized UTF-8 JSON byte length of the `extensions`
object at each layer. Size enforcement MUST occur before signature verification
to prevent resource exhaustion.

### 13.5 Vector: Mixed Required and Optional Extensions

```json
{
    "extensions": {
        "semp.dev/priority": {
            "required": false,
            "data": { "level": "low" }
        },
        "vendor.example.com/unknown-feature": {
            "required": true,
            "data": { "enabled": true }
        }
    }
}
```

**Expected behavior:** Even though `semp.dev/priority` is valid and optional,
the presence of an unknown required extension
(`vendor.example.com/unknown-feature`) causes rejection with
`extension_unsupported`. The optional extension does not rescue the envelope.

### 13.6 Vector: Extension Canonicalization

Extensions are included in the canonical form for seal computation. Extension
keys within each `extensions` object MUST be sorted lexicographically,
consistent with `ENVELOPE.md` §4.3. See section 3.2 of this document for
a canonicalization vector that includes extensions.

---

## 14. Scoped Device Certificate Validation

Reference: `KEY.md` §10.3, `CLIENT.md` §2.3, §2.4.

These vectors verify correct validation and enforcement of scoped device
certificates.

### 14.1 Vector: Valid Scoped Certificate

```json
{
    "type": "SEMP_DEVICE_CERTIFICATE",
    "version": "1.0.0",
    "device_id": "01JDELEGATE0000000000000000",
    "device_public_key": "base64-delegated-device-public-key",
    "account": "user@example.com",
    "issued_by": "01JPRIMARY00000000000000000",
    "issued_at": "2025-06-15T10:00:00Z",
    "expires_at": "2025-12-15T10:00:00Z",
    "scope": {
        "send": {
            "mode": "restricted",
            "allow": [
                { "type": "user", "address": "subscriber1@example.com" },
                { "type": "domain", "domain": "company.example" }
            ],
            "rate_limits": [
                { "period_seconds": 3600,  "amount_allowed": 200 },
                { "period_seconds": 86400, "amount_allowed": 2000 }
            ]
        },
        "receive": { "mode": "none", "rate_limits": [] },
        "blocklist": { "read": false, "write": false, "rate_limits": [] },
        "keys":      { "read": false, "write": false, "rate_limits": [] },
        "devices":   { "read": false, "write": false, "rate_limits": [] }
    },
    "signature": {
        "algorithm": "ed25519",
        "key_id": "primary-device-key-fingerprint",
        "value": "base64-valid-signature"
    }
}
```

**Expected behavior:**

| Check                                  | Expected result                         |
|----------------------------------------|-----------------------------------------|
| Signature valid against primary key    | Pass                                    |
| Primary device authorized for account  | Pass                                    |
| Certificate not expired                | Pass                                    |
| Scope fields present and well-formed   | Pass                                    |
| Certificate registered on server       | Accepted                                |

### 14.2 Vector: Certificate Validation Failures

| Condition                                    | Expected behavior                            |
|----------------------------------------------|----------------------------------------------|
| Signature does not verify against primary key | Reject registration                         |
| `issued_by` device is not registered for account | Reject registration                      |
| `issued_by` device has been revoked          | Reject registration                          |
| `expires_at` is in the past                  | Reject registration                          |
| Combined `allow`+`deny` in a matcher exceeds 10,000 entries | Reject: `scope_invalid`       |
| Matcher contains both `allow` and `deny`     | Reject: `scope_invalid`                      |
| `scope.send.mode` is `restricted` but `allow` is missing | Reject: `scope_invalid`         |
| `scope.send.mode` is `denylist` but `deny` is missing | Reject: `scope_invalid`              |
| Required scope fields missing (including `limits`) | Reject: `scope_invalid`                |
| `expires_at` exceeds `issued_at + 365 days`  | Reject: `scope_invalid`                      |

### 14.3 Vector: Scope Enforcement at Submission

Given a delegated device with the certificate from section 14.1:

| Recipient address             | Matches scope? | Expected behavior                    |
|-------------------------------|---------------|--------------------------------------|
| `subscriber1@example.com`     | Yes (user)    | Submission accepted                  |
| `anyone@company.example`      | Yes (domain)  | Submission accepted                  |
| `other@unrelated.example`     | No            | Rejected: `scope_exceeded`           |
| `subscriber1@example.com` + `other@unrelated.example` | Partial | Rejected: `scope_exceeded` (the non-matching recipient causes rejection) |

### 14.4 Vector: Scope Mode Enforcement

| `scope.send.mode` | Recipient                  | Expected behavior             |
|--------------------|----------------------------|-------------------------------|
| `unrestricted`     | Any address                | Submission accepted           |
| `restricted`       | Address in `allow` list    | Submission accepted           |
| `restricted`       | Address not in `allow`     | Rejected: `scope_exceeded`    |
| `denylist`         | Address in `deny` list     | Rejected: `scope_exceeded`    |
| `denylist`         | Address not in `deny` list | Submission accepted           |
| `none`             | Any address                | Rejected: `scope_exceeded`    |

### 14.4.1 Vector: Receive Matcher Enforcement

Given two delegated devices on the same account:

| Device | `scope.receive`                                                  | Inbound sender             | Expected behavior                        |
|--------|------------------------------------------------------------------|----------------------------|------------------------------------------|
| A      | `{ "mode": "unrestricted" }`                                     | any                        | Delivered to device A                    |
| B      | `{ "mode": "restricted", "allow": [ {"type":"domain","domain":"trusted.example"} ] }` | `alice@trusted.example`    | Delivered to device B                    |
| B      | same as above                                                    | `mallory@other.example`    | Not delivered to device B (device A still receives) |
| C      | `{ "mode": "none" }`                                             | any                        | Not delivered to device C                |

### 14.4.2 Vector: Rate Limit Enforcement

Given a delegated device with `scope.send.rate_limits` containing one
tier `{ "period_seconds": 3600, "amount_allowed": 100 }`:

| Submissions in rolling hour | Expected behavior                                                 |
|-----------------------------|-------------------------------------------------------------------|
| 1 to 100                    | Accepted                                                          |
| 101st                       | Rejected: `rate_limited`. Counters MUST NOT record the rejected attempt. Rolling window advance permits next send. |

Given a delegated device with `scope.send.rate_limits` containing two
tiers `{ "period_seconds": 3600, "amount_allowed": 100 }` and
`{ "period_seconds": 86400, "amount_allowed": 500 }`:

| State                                                          | Expected behavior                    |
|----------------------------------------------------------------|--------------------------------------|
| 100 sends in the last hour, 300 in the last day                | Hourly tier at cap: reject           |
| 50 sends in the last hour, 500 in the last day                 | Daily tier at cap: reject            |
| 50 sends in the last hour, 300 in the last day                 | Accept                               |

Given a delegated device with `scope.blocklist.rate_limits = []`:

| Update count | Expected behavior                                        |
|--------------|----------------------------------------------------------|
| any          | Protocol imposes no cap; operator policy MAY still apply. |

### 14.4.3 Vector: Resource Read/Write Enforcement

Given a delegated device with:

```json
"blocklist": { "read": true, "write": false, "rate_limits": [] },
"keys":      { "read": false, "write": false, "rate_limits": [] },
"devices":   { "read": true, "write": true, "rate_limits": [] }
```

| Operation                                             | Expected behavior                     |
|-------------------------------------------------------|---------------------------------------|
| GET block list                                        | Accepted                              |
| POST block entry                                      | Rejected: `scope_exceeded`            |
| GET key rotation history                              | Rejected: `scope_exceeded`            |
| POST key rotation                                     | Rejected: `scope_exceeded`            |
| GET devices list                                      | Accepted                              |
| POST new delegated device whose `issued_by` is a full-access device | Accepted (with issuer-signature requirement) |
| POST new delegated device whose `issued_by` is this delegated device | Rejected: `scope_invalid` (nested delegation) |

### 14.5 Vector: Certificate Lifecycle Operations

| Operation                                        | Session impact              | Expected behavior                          |
|--------------------------------------------------|-----------------------------|--------------------------------------------|
| Primary client issues new certificate (scope update) | Session continues       | New scope enforced on next submission      |
| Primary client rotates delegated device key      | Session invalidated         | Delegated client must re-handshake         |
| Primary client revokes delegated device key      | Session invalidated         | Delegated client cannot re-handshake       |
| Certificate expires                              | Session continues           | All submissions rejected until new certificate issued |

### 14.6 Vector: Receive Scope

| `scope.receive` | Expected behavior                                              |
|------------------|----------------------------------------------------------------|
| `true`           | Server delivers inbound envelopes to this device               |
| `false`          | Server does not deliver inbound envelopes to this device       |

---

## 15. Recipient Status Validation

Reference: `DELIVERY.md` §1.6.

These vectors verify correct inclusion and omission of recipient status in
delivery acknowledgments.

### 15.1 Vector: Status Visibility Rules

Given recipient has status `away` with message "Back July 1":

| Visibility mode | Sender identity              | Status included? |
|-----------------|------------------------------|------------------|
| `nobody`        | Any sender                   | No               |
| `everyone`      | Any sender                   | Yes              |
| `users`         | Listed user address          | Yes              |
| `users`         | Unlisted user address        | No               |
| `domains`       | Address at listed domain     | Yes              |
| `domains`       | Address at unlisted domain   | No               |
| `servers`       | Routed through listed server | Yes              |
| `servers`       | Not routed through listed server | No           |

When status is not included, the acknowledgment MUST contain no
`recipient_status` field. The absence MUST be indistinguishable from a
recipient who has not configured status at all.

### 15.2 Vector: Status Does Not Affect Delivery

| Recipient state    | Envelope valid? | Expected acknowledgment |
|--------------------|----------------|-------------------------|
| `available`        | Yes            | `delivered`             |
| `away`             | Yes            | `delivered` (with status if visible) |
| `do_not_disturb`   | Yes            | `delivered` (with status if visible) |
| `away`             | No (bad seal)  | `rejected: seal_invalid` |

Status MUST NOT influence the delivery decision. An invalid envelope is
rejected regardless of recipient status.

---

## 16. Implementation Notes

### 16.1 Generating Authoritative Vectors

The HKDF-SHA-512 vectors in section 2 and the HMAC-SHA-256 vectors in
section 6 are fully deterministic given the specified inputs. Implementers
can generate reference outputs using any trusted cryptographic library:

```python
# Python example using the standard library:
import hmac, hashlib

# Inputs
ikm = bytes([0x0b]*32 + [0x0c]*32)
salt = bytes([0xaa]*32) + bytes([0xbb]*32)

# HKDF-Extract (RFC 5869 §2.2)
prk = hmac.new(salt, ikm, hashlib.sha512).digest()

# HKDF-Expand (RFC 5869 §2.3) for one key
def hkdf_expand(prk, info, length):
    t = b""
    okm = b""
    for i in range(1, (length + 63) // 64 + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha512).digest()
        okm += t
    return okm[:length]

key = hkdf_expand(prk, b"SEMP-v1-session-enc-c2s", 32)
# Expected: cf74d91d41de6ac8f838715bc44a31d7...
```

### 16.2 Canonicalization Testing Strategy

Envelope canonicalization is the most common source of interoperability
failures. Implementers SHOULD:

1. Start with the minimal envelope vector (§3.1).
2. Verify byte-for-byte identical output.
3. Progress to the extensions vector (§3.2) to confirm nested key sorting.
4. Generate additional test envelopes with edge cases: Unicode domain names,
   long base64 values, deeply nested extensions, and empty string values.

### 16.3 Test Vector Limitations

These vectors test deterministic operations only. The following operations
require round-trip testing between two independent implementations rather
than static vectors:

- Envelope encryption and decryption (depends on random `K_brief`,
  `K_enclosure`).
- Handshake key exchange (depends on random ephemeral keys).
- Ed25519 / Kyber768 / X25519 key generation.
- Nonce generation.

For these operations, two implementations demonstrate interoperability by
successfully completing a handshake and exchanging an envelope, not by
producing identical intermediate values.

---

## 17. Relationship to Other Specifications

| Specification    | Relationship                                                      |
|------------------|-------------------------------------------------------------------|
| `CONFORMANCE.md` | Defines the requirements these vectors verify. Each vector section references the conformance requirement it tests. |
| `HANDSHAKE.md`   | Handshake message formats, HKDF derivation, confirmation hash, and challenge verification are tested here. |
| `SESSION.md`     | Session key derivation, lifecycle, rekeying, and concurrent session behavior are tested here. |
| `ENVELOPE.md`    | Envelope canonicalization, seal computation, and rejection codes are tested here. |
| `DISCOVERY.md`   | Discovery response parsing and outcome mapping are tested here. |
| `KEY.md`         | Key revocation handling and scoped device certificate validation are tested here. |
| `DELIVERY.md`    | Acknowledgment types, delivery state mapping, and recipient status are tested here. |
| `CLIENT.md`      | Submission status mapping, UI state requirements, scope enforcement, and message history sync constraints are tested here. |
| `EXTENSIONS.md`  | Extension entry structure, criticality signaling, and size limit enforcement are tested here. |
| `ERRORS.md`      | Rejection reason codes including `extension_unsupported`, `extension_size_exceeded`, and `scope_exceeded` are tested here. |

---

*This document is an Internet-Draft. It is subject to revision prior to
finalization as a stable specification.*