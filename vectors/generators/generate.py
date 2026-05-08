#!/usr/bin/env python3
"""Generate SEMP test vector JSON files from primitive crypto.

This script depends ONLY on the Python standard library. It is the
authoritative source for the byte values in vectors/v1.0.0/*.json.
The reference implementation (semp.dev/semp-go) is a CONSUMER of these
vectors, not their source: an implementation passes when its output
matches the JSON; the JSON passes when this script produces it from
public-standard primitives (HKDF/RFC 5869, HMAC-SHA-256/RFC 2104,
SHA-256/FIPS 180-4) plus the SEMP canonicalization rules defined in
ENVELOPE.md §4.3.

Usage:
    python3 generate.py            # write JSON files
    python3 generate.py --verify   # check existing JSON; non-zero on diff
    python3 generate.py --diff     # show diffs without writing

Coverage: Layer 1 + Layer 2 (deterministic operations).
Layer 3+ (seal wrap, envelope compose/open) requires the SEMP
construction logic and is intentionally not generated here yet.
"""

from __future__ import annotations

import argparse
import base64
import copy
import difflib
import hashlib
import hmac
import json
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Cryptographic primitives (RFC 5869 HKDF, RFC 2104 HMAC, FIPS 180-4 SHA)


def hkdf_extract(salt: bytes, ikm: bytes, hash_func=hashlib.sha512) -> bytes:
    """RFC 5869 §2.2: HKDF-Extract(salt, IKM) -> PRK."""
    return hmac.new(salt, ikm, hash_func).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int, hash_func=hashlib.sha512) -> bytes:
    """RFC 5869 §2.3: HKDF-Expand(PRK, info, L) -> OKM."""
    hash_len = hash_func().digest_size
    n = (length + hash_len - 1) // hash_len
    if n > 255:
        raise ValueError("HKDF cannot expand to more than 255*HashLen bytes")
    t = b""
    okm = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hash_func).digest()
        okm += t
    return okm[:length]


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def sha256(msg: bytes) -> bytes:
    return hashlib.sha256(msg).digest()


# ---------------------------------------------------------------------------
# SEMP canonicalization (ENVELOPE.md §4.3)


def canonical_json(obj: Any) -> bytes:
    """Sorted-key minified JSON, UTF-8 encoded. The base canonicalization
    used for any SEMP message that gets signed or MACed."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def canonical_envelope(env: dict) -> bytes:
    """Envelope-specific canonicalization per ENVELOPE.md §4.3:

    1. seal.signature   -> ""
    2. seal.session_mac -> ""
    3. postmark.hop_count omitted entirely
    4. padding omitted entirely
    5. Sort keys at every nesting level (canonical_json)
    """
    e = copy.deepcopy(env)
    if "seal" in e:
        if "signature" in e["seal"]:
            e["seal"]["signature"] = ""
        if "session_mac" in e["seal"]:
            e["seal"]["session_mac"] = ""
    if "postmark" in e:
        e["postmark"].pop("hop_count", None)
    e.pop("padding", None)
    return canonical_json(e)


# ---------------------------------------------------------------------------
# Per-vector generation

INFO_LABELS_UTF8 = {
    "K_enc_c2s": "SEMP-v1-session-enc-c2s",
    "K_enc_s2c": "SEMP-v1-session-enc-s2c",
    "K_mac_c2s": "SEMP-v1-session-mac-c2s",
    "K_mac_s2c": "SEMP-v1-session-mac-s2c",
    "K_env_mac": "SEMP-v1-session-env-mac",
}


def derive_session_keys(salt: bytes, ikm: bytes) -> tuple[bytes, dict[str, bytes]]:
    prk = hkdf_extract(salt, ikm)
    keys = {
        name: hkdf_expand(prk, label.encode("utf-8"), 32)
        for name, label in INFO_LABELS_UTF8.items()
    }
    return prk, keys


# ---- HKDF vectors -----------------------------------------------------------


def build_hkdf_json() -> dict:
    # §2.1 baseline
    ikm_a = bytes([0x0B] * 32 + [0x0C] * 32)
    cn = bytes([0xAA] * 32)
    sn = bytes([0xBB] * 32)
    prk_a, keys_a = derive_session_keys(cn + sn, ikm_a)

    # §2.2 rekey
    ikm_b = bytes([0xD1] * 32 + [0xE2] * 32)
    rn = bytes([0xCC] * 32)
    rdn = bytes([0xDD] * 32)
    prk_b, keys_b = derive_session_keys(rn + rdn, ikm_b)

    return {
        "version": "1.0.0",
        "category": "hkdf",
        "description": (
            "HKDF-SHA-512 derivation of the five session keys from a shared "
            "secret, salt, and per-key info labels. Source of truth: VECTORS.md §2."
        ),
        "spec_reference": "VECTORS.md §2; HANDSHAKE.md §2.4; SESSION.md §2.1; ENVELOPE.md §7.3.1",
        "kdf": "HKDF-SHA-512",
        "vectors": [
            {
                "id": "hkdf-baseline",
                "description": (
                    "Initial-handshake derivation of K_enc_c2s, K_enc_s2c, "
                    "K_mac_c2s, K_mac_s2c, K_env_mac from a synthetic 64-byte "
                    "hybrid IKM and 64-byte (client_nonce || server_nonce) salt."
                ),
                "spec_reference": "VECTORS.md §2.1",
                "inputs": {
                    "ikm_hex": ikm_a.hex(),
                    "client_nonce_hex": cn.hex(),
                    "server_nonce_hex": sn.hex(),
                    "salt_construction": "client_nonce || server_nonce",
                    "info_labels_utf8": dict(INFO_LABELS_UTF8),
                    "key_length_bytes": 32,
                },
                "expected": {
                    "prk_hex": prk_a.hex(),
                    "keys": {f"{k}_hex": v.hex() for k, v in keys_a.items()},
                },
            },
            {
                "id": "hkdf-rekey",
                "description": (
                    "Mid-session rekey derivation. Same five info labels as the "
                    "initial handshake; the salt is (rekey_nonce || responder_nonce) "
                    "instead of session nonces."
                ),
                "spec_reference": "VECTORS.md §2.2; SESSION.md §3.3",
                "inputs": {
                    "ikm_hex": ikm_b.hex(),
                    "rekey_nonce_hex": rn.hex(),
                    "responder_nonce_hex": rdn.hex(),
                    "salt_construction": "rekey_nonce || responder_nonce",
                    "info_labels_utf8": dict(INFO_LABELS_UTF8),
                    "key_length_bytes": 32,
                },
                "expected": {
                    "prk_hex": prk_b.hex(),
                    "keys": {f"{k}_hex": v.hex() for k, v in keys_b.items()},
                },
            },
        ],
    }


# ---- Envelope canonicalization vectors --------------------------------------


def build_envelope_canonical_json() -> dict:
    minimal = {
        "type": "SEMP_ENVELOPE",
        "version": "1.0.0",
        "postmark": {
            "id": "01J4K7P2XVEM3Q8YNZHBRC5T06",
            "session_id": "01J4K7Q0ABCDEFGHJKLMNPQRST",
            "from_domain": "sender.example",
            "to_domain": "recipient.example",
            "expires": "2025-06-10T21:00:00Z",
            "hop_count": 2,
            "extensions": {},
        },
        "seal": {
            "algorithm": "pq-kyber768-x25519",
            "key_id": "abc123def456",
            "signature": "existing-signature-value",
            "session_mac": "existing-mac-value",
            "brief_recipients": {},
            "enclosure_recipients": {},
            "extensions": {},
        },
        "brief": "ZW5jcnlwdGVkLWJyaWVm",
        "enclosure": "ZW5jcnlwdGVkLWVuY2xvc3VyZQ==",
        "padding": "cGFkZGluZy1ieXRlcy1mb3ItMTAyNC1idWNrZXQ=",
    }

    with_ext = {
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
                "another.example.com/class": "transactional",
            },
        },
        "seal": {
            "algorithm": "x25519-chacha20-poly1305",
            "key_id": "key-fingerprint-xyz",
            "signature": "to-be-replaced",
            "session_mac": "to-be-replaced",
            "brief_recipients": {
                "server-key-fp": "wrapped-K_brief-for-server",
                "client-key-fp": "wrapped-K_brief-for-client",
            },
            "enclosure_recipients": {
                "client-key-fp": "wrapped-K_enclosure-for-client",
            },
            "extensions": {},
        },
        "brief": "YnJpZWYtZGF0YQ==",
        "enclosure": "ZW5jbG9zdXJlLWRhdGE=",
    }

    return {
        "version": "1.0.0",
        "category": "envelope-canonical",
        "description": (
            "Canonical envelope encoding (the input to seal.signature and "
            "seal.session_mac). Source of truth: VECTORS.md §3."
        ),
        "spec_reference": "VECTORS.md §3; ENVELOPE.md §4.3",
        "rules_summary": [
            "seal.signature -> set to \"\"",
            "seal.session_mac -> set to \"\"",
            "postmark.hop_count -> omitted",
            "padding -> omitted",
            "All keys sorted lexicographically at every nesting level",
            "No insignificant whitespace",
            "UTF-8 encoding",
        ],
        "vectors": [
            {
                "id": "envelope-canonical-minimal",
                "description": (
                    "Minimal envelope with empty recipient maps and empty extensions. "
                    "Confirms hop_count and padding are stripped, signature/session_mac "
                    "are blanked, and top-level keys sort correctly."
                ),
                "spec_reference": "VECTORS.md §3.1",
                "inputs": {"envelope_json": minimal},
                "expected": {
                    "canonical_utf8": canonical_envelope(minimal).decode("utf-8"),
                },
            },
            {
                "id": "envelope-canonical-with-extensions",
                "description": (
                    "Envelope with two postmark extensions and two brief recipients. "
                    "Confirms nested extension keys sort and recipient-map keys sort."
                ),
                "spec_reference": "VECTORS.md §3.2",
                "inputs": {"envelope_json": with_ext},
                "expected": {
                    "canonical_utf8": canonical_envelope(with_ext).decode("utf-8"),
                },
            },
        ],
    }


# ---- Session-MAC vectors ----------------------------------------------------


def build_session_mac_json(hkdf_baseline_keys: dict[str, bytes], minimal_canonical: bytes) -> dict:
    k_env_mac = hkdf_baseline_keys["K_env_mac"]
    mac = hmac_sha256(k_env_mac, minimal_canonical)
    import base64

    return {
        "version": "1.0.0",
        "category": "session-mac",
        "description": (
            "HMAC-SHA-256 envelope session MAC over canonical envelope bytes. "
            "Source of truth: VECTORS.md §6."
        ),
        "spec_reference": "VECTORS.md §6; ENVELOPE.md §4.3; SESSION.md §2.1",
        "mac": "HMAC-SHA-256",
        "vectors": [
            {
                "id": "session-mac-minimal-envelope",
                "description": (
                    "MAC over the canonical bytes of the §3.1 minimal envelope, "
                    "keyed with the K_env_mac from §2.1."
                ),
                "spec_reference": "VECTORS.md §6.1",
                "inputs": {
                    "key_hex": k_env_mac.hex(),
                    "message_canonical_utf8": minimal_canonical.decode("utf-8"),
                },
                "expected": {
                    "mac_hex": mac.hex(),
                    "mac_b64": base64.b64encode(mac).decode("ascii"),
                },
            }
        ],
    }


# ---- Confirmation hash vectors ----------------------------------------------


CONFIRM_MSG_1 = (
    '{"capabilities":{"encryption_algorithms":["pq-kyber768-x25519",'
    '"x25519-chacha20-poly1305"],"extensions":["semp.dev/device-sync",'
    '"semp.dev/large-attachment"]},"client_ephemeral_key":'
    '{"algorithm":"pq-kyber768-x25519","key":"Y2xpZW50LWVwaGVtZXJhbC1rZXk=",'
    '"key_id":"client-eph-fp"},"extensions":{},"nonce":'
    '"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqs=","party":"client",'
    '"step":"init","transport":"ws","type":"SEMP_HANDSHAKE","version":"1.0.0"}'
)
CONFIRM_MSG_2 = (
    '{"client_nonce":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqs=",'
    '"extensions":{},"negotiated":{"encryption_algorithm":"pq-kyber768-x25519",'
    '"extensions":["semp.dev/device-sync","semp.dev/large-attachment"]},'
    '"party":"server","server_ephemeral_key":{"algorithm":"pq-kyber768-x25519",'
    '"key":"c2VydmVyLWVwaGVtZXJhbC1rZXk=","key_id":"server-eph-fp"},'
    '"server_identity_proof":{"domain":"example.com","key_id":"server-lt-fp",'
    '"signature":"c2VydmVyLXNpZw=="},"server_nonce":'
    '"u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s=","server_signature":'
    '"c2VydmVyLXNpZ25hdHVyZQ==","session_id":"01JTEST33333333333333333333",'
    '"step":"response","type":"SEMP_HANDSHAKE","version":"1.0.0"}'
)


def build_confirmation_hash_json() -> dict:
    import base64

    digest = sha256(CONFIRM_MSG_1.encode("utf-8") + CONFIRM_MSG_2.encode("utf-8"))
    return {
        "version": "1.0.0",
        "category": "confirmation-hash",
        "description": (
            "SHA-256 over (canonical message_1 || canonical message_2) used to "
            "bind the client's identity proof to a specific handshake exchange. "
            "Source of truth: VECTORS.md §5."
        ),
        "spec_reference": "VECTORS.md §5; HANDSHAKE.md §2.5.3",
        "hash": "SHA-256",
        "vectors": [
            {
                "id": "confirmation-hash-pq-kyber-baseline",
                "description": (
                    "Hash over a canonical INIT (party=client) concatenated with a "
                    "canonical RESPONSE (party=server) for the pq-kyber768-x25519 suite."
                ),
                "spec_reference": "VECTORS.md §5.1; HANDSHAKE.md §2.5.3",
                "inputs": {
                    "message_1_canonical_utf8": CONFIRM_MSG_1,
                    "message_2_canonical_utf8": CONFIRM_MSG_2,
                    "concatenation": "canonical(message_1) || canonical(message_2)",
                },
                "expected": {
                    "hash_hex": digest.hex(),
                    "hash_b64": base64.b64encode(digest).decode("ascii"),
                },
            }
        ],
    }


# ---- Envelope bucket vectors ------------------------------------------------


def envelope_size_bucket(size: int) -> int:
    """ENVELOPE.md §2.4.1: next power of 2, minimum 1024.

    Implementations clamp the final value to the operator-configured
    `max_envelope_size` (typically 25 MiB / 26214400 bytes). The clamp
    happens at the deployment boundary, not in this function — the
    raw next-power-of-2 value is the canonical mathematical answer.
    """
    bucket = 1024
    while bucket < size:
        bucket *= 2
    return bucket


def recipient_count_bucket(real_recipients: int, single_domain_not_group: bool) -> int | str:
    """ENVELOPE.md §4.4.2: next power of 2 with floor 2 (or 1 for the
    single-domain non-group case), ceiling 1024."""
    if real_recipients == 1 and single_domain_not_group:
        return 1
    if real_recipients > 1024:
        return "exceeds bucket ceiling; recomposition required"
    bucket = 2
    while bucket < real_recipients:
        bucket *= 2
    return bucket


def build_envelope_buckets_json() -> dict:
    size_inputs = [
        1, 1023, 1024, 1025, 2048, 2049, 4096, 4097,
        16383, 16384, 16385, 1000000, 1048576, 1048577, 16777217,
    ]
    size_samples = []
    for size in size_inputs:
        bucket = envelope_size_bucket(size)
        sample = {"unpadded_size_bytes": size, "bucket_size_bytes": bucket}
        if size > 16777216:
            sample["note"] = (
                "Computed bucket exceeds typical max_envelope_size; "
                "implementations clamp to the operator-configured maximum."
            )
        size_samples.append(sample)

    recipient_cases = [
        (1, True),
        (1, False),
        (2, False),
        (3, False),
        (4, False),
        (5, False),
        (9, False),
        (16, False),
        (17, False),
        (65, False),
        (129, False),
        (1024, False),
        (1025, False),
    ]
    recipient_samples = []
    for real, single in recipient_cases:
        bucket = recipient_count_bucket(real, single)
        sample = {
            "real_recipients": real,
            "single_domain_not_group": single,
            "bucket_count": bucket,
        }
        if real == 1 and single:
            sample["note"] = "single-domain non-group: padding exception applies"
        elif isinstance(bucket, str):
            sample["note"] = "recomposition into multiple envelopes required"
        recipient_samples.append(sample)

    return {
        "version": "1.0.0",
        "category": "envelope-buckets",
        "description": (
            "Envelope size and recipient-count bucket selection. Source of "
            "truth: VECTORS.md §3.3 and §3.4."
        ),
        "spec_reference": "VECTORS.md §3.3, §3.4; ENVELOPE.md §2.4.1, §4.4.2",
        "vectors": [
            {
                "id": "envelope-size-buckets",
                "description": (
                    "Maps unpadded envelope size in bytes to the selected "
                    "power-of-two padding bucket. Rule: next power of two with "
                    "minimum 1024."
                ),
                "spec_reference": "VECTORS.md §3.3; ENVELOPE.md §2.4.1",
                "rule": "bucket = max(1024, smallest power of two >= unpadded_size)",
                "samples": size_samples,
            },
            {
                "id": "recipient-count-buckets",
                "description": (
                    "Maps the real recipient client-key count to the padded "
                    "enclosure_recipients entry count. Rule: next power of two "
                    "with floor 2; floor relaxes to 1 only when there is exactly "
                    "one recipient and that recipient is single-domain (not a "
                    "group send and not multi-domain). Real counts above 1024 "
                    "force recomposition into multiple envelopes."
                ),
                "spec_reference": "VECTORS.md §3.4; ENVELOPE.md §4.4.2",
                "rule": (
                    "bucket = 1 if (real == 1 and single_domain_not_group) "
                    "else min(1024, smallest power of two >= max(2, real)); "
                    "real > 1024 -> recomposition required"
                ),
                "samples": recipient_samples,
            },
        ],
    }


# ---- Proof-of-work vectors --------------------------------------------------


def pow_preimage(prefix: bytes, challenge_id: str, nonce: bytes) -> bytes:
    """HANDSHAKE.md §2.2b preimage construction:
    base64(prefix) || ":" || challenge_id || ":" || base64(nonce), UTF-8."""
    s = (
        base64.b64encode(prefix).decode("ascii")
        + ":" + challenge_id + ":"
        + base64.b64encode(nonce).decode("ascii")
    )
    return s.encode("utf-8")


def leading_zero_bits(h: bytes) -> int:
    bits = 0
    for byte in h:
        if byte == 0:
            bits += 8
            continue
        for i in range(8):
            if (byte >> (7 - i)) & 1:
                return bits + i
        return bits + 8  # unreachable
    return bits


def build_pow_json() -> dict:
    prefix = bytes.fromhex("4a8f2c1d3b5e7a9f0d6c8b4e2a1f3d5c")
    challenge_id = "01JTEST22222222222222222222"

    valid_nonce = bytes.fromhex("000000000000adb7")
    valid_preimage = pow_preimage(prefix, challenge_id, valid_nonce)
    valid_hash = sha256(valid_preimage)
    valid_zb = leading_zero_bits(valid_hash)

    failed_nonce = bytes.fromhex("0000000000000001")
    failed_preimage = pow_preimage(prefix, challenge_id, failed_nonce)
    failed_hash = sha256(failed_preimage)
    failed_zb = leading_zero_bits(failed_hash)

    return {
        "version": "1.0.0",
        "category": "pow",
        "description": (
            "Proof-of-work challenge solution verification. Source of truth: "
            "VECTORS.md §4."
        ),
        "spec_reference": "VECTORS.md §4; HANDSHAKE.md §2.2b; REPUTATION.md §8.3",
        "preimage_construction": (
            "base64(prefix) || ':' || challenge_id || ':' || base64(nonce), "
            "encoded as UTF-8"
        ),
        "hash": "SHA-256",
        "vectors": [
            {
                "id": "pow-difficulty-16-valid",
                "description": (
                    "Valid solution at difficulty 16: the SHA-256 of the "
                    "preimage has at least 16 leading zero bits."
                ),
                "spec_reference": "VECTORS.md §4.1",
                "inputs": {
                    "prefix_hex": prefix.hex(),
                    "prefix_b64": base64.b64encode(prefix).decode("ascii"),
                    "challenge_id": challenge_id,
                    "nonce_hex": valid_nonce.hex(),
                    "nonce_b64": base64.b64encode(valid_nonce).decode("ascii"),
                    "preimage_utf8": valid_preimage.decode("utf-8"),
                    "required_difficulty_bits": 16,
                },
                "expected": {
                    "hash_hex": valid_hash.hex(),
                    "leading_zero_bits": valid_zb,
                    "valid": valid_zb >= 16,
                },
            },
            {
                "id": "pow-difficulty-16-insufficient",
                "description": (
                    "Insufficient solution: same prefix and challenge_id as the "
                    "valid case, but with a nonce that produces only a few "
                    "leading zero bits — the implementation MUST reject."
                ),
                "spec_reference": "VECTORS.md §4.2",
                "inputs": {
                    "prefix_hex": prefix.hex(),
                    "prefix_b64": base64.b64encode(prefix).decode("ascii"),
                    "challenge_id": challenge_id,
                    "nonce_hex": failed_nonce.hex(),
                    "nonce_b64": base64.b64encode(failed_nonce).decode("ascii"),
                    "preimage_utf8": failed_preimage.decode("utf-8"),
                    "required_difficulty_bits": 16,
                },
                "expected": {
                    "hash_hex": failed_hash.hex(),
                    "leading_zero_bits": failed_zb,
                    "valid": failed_zb >= 16,
                },
            },
        ],
    }


# ---- Discovery vectors ------------------------------------------------------


def parse_dns_txt_capability(txt: str) -> dict:
    """DISCOVERY.md §8.1: parse a SEMP TXT capability record.

    Format: semicolon-separated `key=value` pairs. Known keys:
      v   protocol version (required)
      pq  post-quantum readiness (optional)
      c   comma-separated transport ids (optional)
      f   comma-separated optional features (optional)

    Unknown keys MUST be ignored, not rejected.
    """
    out: dict[str, Any] = {}
    ignored: list[str] = []
    for segment in txt.split(";"):
        segment = segment.strip()
        if not segment:
            continue
        if "=" not in segment:
            ignored.append(segment)
            continue
        key, value = segment.split("=", 1)
        if key in ("c", "f"):
            out[key] = [item for item in value.split(",") if item]
        elif key in ("v", "pq"):
            out[key] = value
        else:
            ignored.append(key)
    if ignored:
        out["_ignored_unknown"] = ignored
    return out


def build_discovery_json() -> dict:
    response = {
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
                "extensions": ["semp.dev/device-sync", "semp.dev/large-attachment"],
                "server": "semp.example.com",
                "ttl": 3600,
            },
            {
                "address": "bob@legacy.example",
                "status": "legacy",
                "transports": ["smtp"],
                "server": "mail.legacy.example",
                "ttl": 86400,
            },
            {
                "address": "charlie@nowhere.invalid",
                "status": "not_found",
                "ttl": 3600,
            },
        ],
        "signature": {
            "algorithm": "ed25519",
            "key_id": "server-domain-key-fp",
            "value": "c2lnbmF0dXJlLXZhbHVl",
        },
        "extensions": {},
    }

    expected_actions = {
        "alice@example.com": {
            "status": "semp",
            "action": "proceed_with_handshake",
            "server": "semp.example.com",
            "transports": ["ws", "h2"],
        },
        "bob@legacy.example": {
            "status": "legacy",
            "action": "return_legacy_required",
        },
        "charlie@nowhere.invalid": {
            "status": "not_found",
            "action": "return_recipient_not_found",
        },
    }

    txt_record = "v=semp1;pq=ready;c=ws,h2,quic;f=groups,threads,reactions;x=unknown"
    parsed = parse_dns_txt_capability(txt_record)

    return {
        "version": "1.0.0",
        "category": "discovery",
        "description": (
            "Discovery response parsing and DNS TXT capability-record parsing. "
            "Source of truth: VECTORS.md §7."
        ),
        "spec_reference": "VECTORS.md §7; DISCOVERY.md §4.3, §4.6, §8.1",
        "vectors": [
            {
                "id": "discovery-response-parsing",
                "description": (
                    "A well-formed SEMP_DISCOVERY response carries per-address "
                    "results with statuses semp / legacy / not_found. Each "
                    "result drives a different sender action; unknown fields "
                    "MUST be ignored, and the response signature MUST be "
                    "verified against the responding server's published domain "
                    "key before any result is acted on or cached. Each result "
                    "is cached for its individual ttl."
                ),
                "spec_reference": "VECTORS.md §7.1; DISCOVERY.md §4.3, §4.6",
                "validation_requirements": [
                    "Verify response.signature against the server's published domain key BEFORE caching or acting on results.",
                    "Cache each result per its individual ttl.",
                    "Unknown fields in the response or per-result objects MUST be ignored, not rejected.",
                ],
                "inputs": {
                    "response_json": response,
                },
                "expected": {
                    "per_address_actions": expected_actions,
                },
            },
            {
                "id": "discovery-txt-parsing",
                "description": (
                    "A DNS TXT capability record advertises protocol version "
                    "and optional capability hints under semicolon-separated "
                    "key=value pairs. Unknown keys (here: x=unknown) MUST be "
                    "ignored, not rejected."
                ),
                "spec_reference": "VECTORS.md §7.2; DISCOVERY.md §8.1",
                "rule": (
                    "split on ';' -> for each 'k=v' segment, dispatch by key: "
                    "v/pq -> string, c/f -> comma-split list, anything else -> "
                    "silently ignore."
                ),
                "inputs": {
                    "txt_record_utf8": txt_record,
                },
                "expected": {
                    "parsed": parsed,
                },
            },
        ],
    }


# ---- Rejection-code vectors -------------------------------------------------


def build_rejection_codes_json() -> dict:
    handshake = [
        ("blocked", False, "Surface to user. Do not retry."),
        ("auth_failed", False, "Surface to user. Do not retry."),
        ("policy_forbidden", False, "Surface to user. Do not retry."),
        ("handshake_expired", True, "Re-handshake and retry."),
        ("handshake_invalid", True, "Re-handshake and retry."),
        ("no_session", True, "Establish new session and retry."),
        ("rate_limited", True, "Back off and retry."),
        ("challenge", True, "Solve the issued challenge and continue handshake."),
        ("challenge_failed", True, "Request new challenge and retry."),
        ("challenge_invalid", False, "Surface to user or operator. Do not retry."),
        ("server_at_capacity", True, "Back off and retry later."),
        ("version_unsupported", False, "Surface to user. Peer's MAJOR version unsupported."),
    ]
    envelope = [
        ("blocked", False, "Surface to user. Do not retry."),
        ("seal_invalid", False, "Indicates a bug. Do not retry same envelope."),
        ("session_mac_invalid", False, "Indicates a bug or session mismatch. Re-handshake before retry."),
        ("envelope_expired", False, "Recompose with new expiry if content still relevant."),
        ("envelope_size_exceeded", False, "Recompose with smaller envelope: split recipients or move large content to the large-attachment extension."),
        ("policy_forbidden", False, "Surface to user. Rejection MAY carry a challenge."),
        ("handshake_invalid", True, "Establish new session and resend."),
        ("handshake_expired", True, "Establish new session and resend."),
        ("no_session", True, "Establish new session and resend."),
        ("extension_unsupported", False, "Remove or renegotiate the unsupported extension."),
        ("extension_size_exceeded", False, "Reduce extension payload size."),
        ("scope_exceeded", False, "Update device certificate scope or use a full-access device."),
    ]

    def to_samples(rows):
        return [
            {"reason_code": code, "recoverable": rec, "expected_sender_behavior": text}
            for code, rec, text in rows
        ]

    return {
        "version": "1.0.0",
        "category": "rejection-codes",
        "description": (
            "Recoverability classification and expected sender behavior for "
            "every defined rejection reason code in handshake and envelope "
            "rejections. Source of truth: VECTORS.md §8."
        ),
        "spec_reference": "VECTORS.md §8; HANDSHAKE.md §4.1; ENVELOPE.md §9.3",
        "vectors": [
            {
                "id": "handshake-rejection-codes",
                "description": (
                    "Recoverability and expected sender behavior for codes "
                    "carried in a SEMP_HANDSHAKE rejection."
                ),
                "spec_reference": "VECTORS.md §8.1; HANDSHAKE.md §4.1",
                "samples": to_samples(handshake),
            },
            {
                "id": "envelope-rejection-codes",
                "description": (
                    "Recoverability and expected sender behavior for codes "
                    "carried in a per-recipient envelope SubmissionResult."
                ),
                "spec_reference": "VECTORS.md §8.2; ENVELOPE.md §9.3",
                "samples": to_samples(envelope),
            },
        ],
    }


# ---- Extension-entry vectors ------------------------------------------------


def build_extension_entries_json() -> dict:
    size_table = [
        ("postmark.extensions", 4 * 1024, 3 * 1024, "accept"),
        ("postmark.extensions", 4 * 1024, 5 * 1024, "reject:extension_size_exceeded"),
        ("seal.extensions", 4 * 1024, 5 * 1024, "reject:extension_size_exceeded"),
        ("brief.extensions", 16 * 1024, 10 * 1024, "accept"),
        ("brief.extensions", 16 * 1024, 20 * 1024, "reject:extension_size_exceeded"),
        ("enclosure.extensions", 64 * 1024, 50 * 1024, "accept"),
        ("enclosure.extensions", 64 * 1024, 70 * 1024, "reject:extension_size_exceeded"),
    ]
    size_samples = []
    for layer, limit, size, outcome in size_table:
        sample = {
            "layer": layer,
            "size_limit_bytes": limit,
            "test_payload_bytes": size,
            "expected_outcome": outcome,
        }
        if outcome.startswith("reject:"):
            sample["reason_code"] = outcome.split(":", 1)[1]
            sample["expected_outcome"] = "reject"
        size_samples.append(sample)

    return {
        "version": "1.0.0",
        "category": "extension-entries",
        "description": (
            "Extension entry parsing, criticality enforcement, and size limits. "
            "Source of truth: VECTORS.md §13."
        ),
        "spec_reference": "VECTORS.md §13; EXTENSIONS.md §2, §3, §4",
        "vectors": [
            {
                "id": "extension-optional-unknown",
                "description": (
                    "Optional extension whose key is unknown to the receiver. "
                    "MUST be silently ignored; envelope processing continues."
                ),
                "spec_reference": "VECTORS.md §13.1; EXTENSIONS.md §3",
                "inputs": {
                    "extensions_json": {
                        "semp.dev/priority": {
                            "required": False,
                            "data": {"level": "urgent"},
                        }
                    },
                    "implementation_supports": [],
                },
                "expected": {
                    "action": "accept",
                    "ignored_keys": ["semp.dev/priority"],
                },
            },
            {
                "id": "extension-required-known-supported",
                "description": (
                    "Required extension whose key the receiver supports. "
                    "Extension is parsed and processed."
                ),
                "spec_reference": "VECTORS.md §13.2; EXTENSIONS.md §3",
                "inputs": {
                    "extensions_json": {
                        "vendor.example.com/example-extension": {
                            "required": True,
                            "data": {"example_field": "example_value"},
                        }
                    },
                    "implementation_supports": [
                        "vendor.example.com/example-extension"
                    ],
                },
                "expected": {
                    "action": "accept",
                    "processed_keys": ["vendor.example.com/example-extension"],
                },
            },
            {
                "id": "extension-required-known-unsupported",
                "description": (
                    "Required extension whose key the receiver does NOT support. "
                    "Envelope MUST be rejected with extension_unsupported, and "
                    "the rejection MUST identify the offending key."
                ),
                "spec_reference": "VECTORS.md §13.2; EXTENSIONS.md §3",
                "inputs": {
                    "extensions_json": {
                        "vendor.example.com/example-extension": {
                            "required": True,
                            "data": {"example_field": "example_value"},
                        }
                    },
                    "implementation_supports": [],
                },
                "expected": {
                    "action": "reject",
                    "reason_code": "extension_unsupported",
                    "offending_keys": ["vendor.example.com/example-extension"],
                },
            },
            {
                "id": "extension-required-unknown",
                "description": (
                    "Required extension with a vendor key the receiver does not "
                    "recognize. Envelope rejected with extension_unsupported."
                ),
                "spec_reference": "VECTORS.md §13.3; EXTENSIONS.md §3",
                "inputs": {
                    "extensions_json": {
                        "vendor.example.com/custom-feature": {
                            "required": True,
                            "data": {"mode": "strict"},
                        }
                    },
                    "implementation_supports": [],
                },
                "expected": {
                    "action": "reject",
                    "reason_code": "extension_unsupported",
                    "offending_keys": ["vendor.example.com/custom-feature"],
                },
            },
            {
                "id": "extension-size-limits",
                "description": (
                    "Per-layer size limits on the serialized UTF-8 JSON byte "
                    "length of each extensions object. Size enforcement MUST "
                    "occur before signature verification."
                ),
                "spec_reference": "VECTORS.md §13.4; EXTENSIONS.md §4",
                "samples": size_samples,
            },
            {
                "id": "extension-mixed-required-and-optional",
                "description": (
                    "An optional supported extension does not rescue an envelope "
                    "carrying an unknown required extension. Reject is driven by "
                    "the required-and-unsupported entry."
                ),
                "spec_reference": "VECTORS.md §13.5; EXTENSIONS.md §3",
                "inputs": {
                    "extensions_json": {
                        "semp.dev/priority": {
                            "required": False,
                            "data": {"level": "low"},
                        },
                        "vendor.example.com/unknown-feature": {
                            "required": True,
                            "data": {"enabled": True},
                        },
                    },
                    "implementation_supports": ["semp.dev/priority"],
                },
                "expected": {
                    "action": "reject",
                    "reason_code": "extension_unsupported",
                    "offending_keys": ["vendor.example.com/unknown-feature"],
                    "ignored_keys": ["semp.dev/priority"],
                },
            },
        ],
    }


# ---- Session lifecycle vectors ----------------------------------------------


def build_session_lifecycle_json() -> dict:
    transitions = [
        {
            "from_state": "NO_SESSION",
            "event": "handshake completes (accepted)",
            "to_state": "ACTIVE",
            "actions": [
                "store session_id, five session keys, established_at, expires_at",
            ],
        },
        {
            "from_state": "ACTIVE",
            "event": "envelope submitted with valid session_id",
            "to_state": "ACTIVE",
            "actions": ["compute seal.session_mac using K_env_mac"],
        },
        {
            "from_state": "ACTIVE",
            "event": "expires_at reached",
            "to_state": "EXPIRED",
            "actions": [
                "erase all session keys (secure zeroing)",
                "retain session_id in expiry log",
            ],
        },
        {
            "from_state": "ACTIVE",
            "event": "rekey initiated at 80% of TTL",
            "to_state": "REKEYING",
            "actions": ["generate new ephemeral key pair"],
        },
        {
            "from_state": "REKEYING",
            "event": "rekey accepted",
            "to_state": "ACTIVE",
            "actions": [
                "install new session keys",
                "erase old session keys",
                "retire old session_id to expiry log",
                "5-second transition window for in-flight envelopes",
            ],
        },
        {
            "from_state": "ACTIVE",
            "event": "new handshake from same client_identity",
            "to_state": "INVALIDATED -> ACTIVE",
            "actions": [
                "erase old session keys",
                "retire old session_id to expiry log",
                "transition new session to ACTIVE",
            ],
        },
        {
            "from_state": "EXPIRED or INVALIDATED",
            "event": "envelope received referencing this session_id",
            "to_state": "(no transition)",
            "actions": ["reject envelope with reason_code 'handshake_invalid'"],
        },
    ]

    concurrent = [
        ("Client A opens session, then opens another from Client A",
         "Old session invalidated, new session accepted"),
        ("Federation peer opens session while one already exists",
         "Old session invalidated, new session accepted"),
        ("Two federation peers initiate simultaneously",
         "Lower session_id lexicographically is abandoned"),
        ("Active sessions reach server maximum",
         "New handshakes rejected with server_at_capacity"),
    ]

    rekey = [
        ("Rekey attempted before 80% of TTL",
         "Permitted (SHOULD wait, not MUST)"),
        ("Rekey attempted after session expiry",
         "MUST be rejected; full handshake required"),
        ("11th rekey in same session",
         "MUST be rejected; maximum 10 rekeys per session"),
        ("Two rekeys within 60 seconds",
         "Second MUST be rejected; minimum 1 minute gap"),
    ]

    return {
        "version": "1.0.0",
        "category": "session-lifecycle",
        "description": (
            "Session state transitions, concurrency limits, and rekey limits. "
            "Source of truth: VECTORS.md §9."
        ),
        "spec_reference": "VECTORS.md §9; SESSION.md §2.3, §2.4, §2.5, §3",
        "vectors": [
            {
                "id": "session-state-transitions",
                "description": (
                    "Authoritative state machine: each row is a (from_state, "
                    "event) -> (to_state, actions) transition. Implementations "
                    "MUST drive their session state through these and only "
                    "these transitions."
                ),
                "spec_reference": "VECTORS.md §9.1; SESSION.md §2.3, §2.4, §3",
                "samples": transitions,
            },
            {
                "id": "concurrent-session-limits",
                "description": (
                    "Behavior when a new handshake arrives while one or more "
                    "sessions are already active for the same identity, or "
                    "when the server reaches its concurrent-session ceiling."
                ),
                "spec_reference": "VECTORS.md §9.2; SESSION.md §2.5",
                "samples": [
                    {"scenario": s, "expected_behavior": b} for s, b in concurrent
                ],
            },
            {
                "id": "rekey-limits",
                "description": (
                    "Per-session rekey constraints: minimum elapsed time, "
                    "maximum count per session, and post-expiry handling."
                ),
                "spec_reference": "VECTORS.md §9.3; SESSION.md §3",
                "samples": [
                    {"condition": c, "expected_behavior": b} for c, b in rekey
                ],
            },
        ],
    }


# ---- Delivery status vectors (§10 + §11) ------------------------------------


def build_delivery_status_json() -> dict:
    ack_to_ui = [
        ("delivered", "Confirmed delivery indicator", ""),
        ("rejected", "Failure indicator + reason", "Reason accessible to user"),
        ("silent", "Unacknowledged (distinct)", "MUST be visually distinct from above"),
        ("legacy_required", "Degradation warning", "Await user confirmation before SMTP send"),
        ("recipient_not_found", "Undeliverable indicator", "No fallback available"),
        ("queued", "Pending indicator", "Update when delivery event received"),
    ]

    queued_transitions = [
        ("queued", "delivered", "Update to confirmed delivery indicator"),
        ("queued", "rejected", "Update to failure indicator + reason"),
        ("queued", "silent", "Update to unacknowledged indicator"),
    ]

    discovery_to_submission = [
        ("semp", None, "(proceed with delivery)", "Envelope delivered via SEMP"),
        ("legacy", "legacy_required", "Surface degradation, await confirm", None),
        ("not_found", "recipient_not_found", "Surface as undeliverable", None),
    ]

    multi_recipient = [
        {"address": "alice@semp.example", "discovery_outcome": "semp", "submission_status": "delivered"},
        {"address": "bob@legacy.example", "discovery_outcome": "legacy", "submission_status": "legacy_required"},
        {"address": "carol@gone.invalid", "discovery_outcome": "not_found", "submission_status": "recipient_not_found"},
    ]

    return {
        "version": "1.0.0",
        "category": "delivery-status",
        "description": (
            "Mapping from server acknowledgments and discovery outcomes to "
            "client UI state and submission status, including multi-recipient "
            "mixed outcomes. Source of truth: VECTORS.md §10 and §11."
        ),
        "spec_reference": "VECTORS.md §10, §11; DELIVERY.md §1.4; CLIENT.md §6.3, §7.1; DISCOVERY.md §7.1",
        "vectors": [
            {
                "id": "acknowledgment-to-ui-state",
                "description": (
                    "Maps the server acknowledgment status carried in a "
                    "submission response to the client UI state and any "
                    "additional behavior the client MUST drive."
                ),
                "spec_reference": "VECTORS.md §10.1; CLIENT.md §7.1",
                "samples": [
                    {
                        "server_acknowledgment": ack,
                        "client_ui_state": ui,
                        "additional_behavior": extra,
                    }
                    for ack, ui, extra in ack_to_ui
                ],
            },
            {
                "id": "queued-to-final-transitions",
                "description": (
                    "After a queued submission, the asynchronous delivery "
                    "event drives the final UI state. A client MUST NOT "
                    "display a confirmed delivery indicator for a queued "
                    "envelope until a delivered event is received."
                ),
                "spec_reference": "VECTORS.md §10.2; CLIENT.md §7.1",
                "samples": [
                    {
                        "initial_status": initial,
                        "delivery_event_status": event,
                        "client_action": action,
                    }
                    for initial, event, action in queued_transitions
                ],
            },
            {
                "id": "discovery-outcome-to-submission-status",
                "description": (
                    "Maps the per-recipient discovery outcome to the "
                    "submission status returned to the client and the "
                    "client action that follows."
                ),
                "spec_reference": "VECTORS.md §11.1; DISCOVERY.md §7.1; CLIENT.md §6.3",
                "samples": [
                    {
                        "discovery_outcome": disc,
                        "submission_status": sub,
                        "client_action": action,
                        "delivery_note": note,
                    }
                    for disc, sub, action, note in discovery_to_submission
                ],
            },
            {
                "id": "multi-recipient-mixed-outcomes",
                "description": (
                    "An envelope addressed to three recipients with "
                    "different discovery outcomes. The server returns "
                    "per-recipient results in the submission response. The "
                    "client surfaces each recipient's status individually "
                    "and MUST NOT suppress or aggregate partial failure. "
                    "legacy_required for a per-recipient degradation MUST "
                    "await user confirmation before SMTP fallback."
                ),
                "spec_reference": "VECTORS.md §11.2; CLIENT.md §6.3",
                "inputs": {
                    "recipients": [r["address"] for r in multi_recipient],
                },
                "expected": {
                    "per_recipient": multi_recipient,
                    "client_must_not": [
                        "suppress partial failure",
                        "aggregate per-recipient outcomes into a single status",
                        "perform SMTP fallback for legacy_required without user confirmation",
                    ],
                },
            },
        ],
    }


# ---- Key revocation vectors -------------------------------------------------


def build_key_revocation_json() -> dict:
    revocation_response = {
        "address": "user@example.com",
        "key_type": "encryption",
        "key_id": "old-key-fp",
        "revocation": {
            "reason": "key_compromise",
            "revoked_at": "2025-06-10T19:49:15Z",
            "replacement_key_id": "new-key-fp",
        },
    }

    rules = [
        ("Revocation present",
         "MUST NOT use old-key-fp"),
        ("replacement_key_id present",
         "SHOULD fetch and use new-key-fp"),
        ("Key was cached locally",
         "MUST invalidate cached entry and re-fetch"),
        ("No replacement_key_id",
         "Delivery cannot proceed for this recipient"),
    ]

    return {
        "version": "1.0.0",
        "category": "key-revocation",
        "description": (
            "Sender-side handling when a SEMP_KEYS lookup returns a revoked "
            "key with optional replacement. Source of truth: VECTORS.md §12."
        ),
        "spec_reference": "VECTORS.md §12; KEY.md §8",
        "vectors": [
            {
                "id": "revoked-key-response",
                "description": (
                    "A SEMP_KEYS response carrying a revocation block. The "
                    "rules samples enumerate the conditional sender behavior."
                ),
                "spec_reference": "VECTORS.md §12.1; KEY.md §8",
                "inputs": {
                    "revoked_key_record": revocation_response,
                },
                "expected": {
                    "rules": [
                        {"condition": cond, "action": action}
                        for cond, action in rules
                    ],
                },
            },
        ],
    }


# ---- Scoped device certificate vectors (§14) --------------------------------


VALID_DEVICE_CERT = {
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
                {"type": "user", "address": "subscriber1@example.com"},
                {"type": "domain", "domain": "company.example"},
            ],
            "rate_limits": [
                {"period_seconds": 3600, "amount_allowed": 200},
                {"period_seconds": 86400, "amount_allowed": 2000},
            ],
        },
        "receive": {"mode": "none", "rate_limits": [], "delivery_stage": 1},
        "blocklist": {"read": False, "write": False, "rate_limits": []},
        "keys": {"read": False, "write": False, "rate_limits": []},
        "devices": {"read": False, "write": False, "rate_limits": []},
    },
    "signature": {
        "algorithm": "ed25519",
        "key_id": "primary-device-key-fingerprint",
        "value": "base64-valid-signature",
    },
}


def build_device_certificates_json() -> dict:
    valid_checks = [
        ("Signature valid against primary key", "pass"),
        ("Primary device authorized for account", "pass"),
        ("Certificate not expired", "pass"),
        ("Scope fields present and well-formed", "pass"),
        ("Certificate registered on server", "accepted"),
    ]

    failures = [
        ("Signature does not verify against primary key", "reject", None),
        ("issued_by device is not registered for account", "reject", None),
        ("issued_by device has been revoked", "reject", None),
        ("expires_at is in the past", "reject", None),
        ("Combined allow + deny in a matcher exceeds 10000 entries",
         "reject", "scope_invalid"),
        ("Matcher contains both allow and deny", "reject", "scope_invalid"),
        ("scope.send.mode is restricted but allow is missing",
         "reject", "scope_invalid"),
        ("scope.send.mode is denylist but deny is missing",
         "reject", "scope_invalid"),
        ("Required scope fields missing (including limits)",
         "reject", "scope_invalid"),
        ("expires_at exceeds issued_at + 365 days",
         "reject", "scope_invalid"),
    ]

    enforcement = [
        ("subscriber1@example.com", "matches user", "accept", None),
        ("anyone@company.example", "matches domain", "accept", None),
        ("other@unrelated.example", "no match", "reject", "scope_exceeded"),
        ("subscriber1@example.com + other@unrelated.example",
         "partial match",
         "reject",
         "scope_exceeded (the non-matching recipient causes whole-submission rejection)"),
    ]

    mode_enforcement = [
        ("unrestricted", "any address", "accept", None),
        ("restricted", "address in allow list", "accept", None),
        ("restricted", "address not in allow", "reject", "scope_exceeded"),
        ("denylist", "address in deny list", "reject", "scope_exceeded"),
        ("denylist", "address not in deny list", "accept", None),
        ("none", "any address", "reject", "scope_exceeded"),
    ]

    receive_matcher = [
        {
            "device": "A",
            "scope_receive": {"mode": "unrestricted"},
            "inbound_sender": "any",
            "expected": "delivered to A",
        },
        {
            "device": "B",
            "scope_receive": {
                "mode": "restricted",
                "allow": [{"type": "domain", "domain": "trusted.example"}],
            },
            "inbound_sender": "alice@trusted.example",
            "expected": "delivered to B",
        },
        {
            "device": "B",
            "scope_receive": {
                "mode": "restricted",
                "allow": [{"type": "domain", "domain": "trusted.example"}],
            },
            "inbound_sender": "mallory@other.example",
            "expected": "not delivered to B (device A still receives)",
        },
        {
            "device": "C",
            "scope_receive": {"mode": "none"},
            "inbound_sender": "any",
            "expected": "not delivered to C",
        },
    ]

    rate_limit_single_tier = [
        ("1 to 100 submissions in rolling hour", "accept",
         "rate_limit: {period_seconds: 3600, amount_allowed: 100}"),
        ("101st submission in the same hour", "reject:rate_limited",
         "Counters MUST NOT record the rejected attempt; rolling window advance permits next send"),
    ]
    rate_limit_two_tier = [
        ("100 sends in the last hour, 300 in the last day",
         "reject", "Hourly tier at cap"),
        ("50 sends in the last hour, 500 in the last day",
         "reject", "Daily tier at cap"),
        ("50 sends in the last hour, 300 in the last day",
         "accept", None),
    ]
    rate_limit_blocklist = [
        ("Any update count when scope.blocklist.rate_limits = []",
         "Protocol imposes no cap; operator policy MAY still apply"),
    ]

    rw_enforcement_scope = {
        "blocklist": {"read": True, "write": False, "rate_limits": []},
        "keys": {"read": False, "write": False, "rate_limits": []},
        "devices": {"read": True, "write": True, "rate_limits": []},
    }
    rw_operations = [
        ("GET block list", "accept", None),
        ("POST block entry", "reject", "scope_exceeded"),
        ("GET key rotation history", "reject", "scope_exceeded"),
        ("POST key rotation", "reject", "scope_exceeded"),
        ("GET devices list", "accept", None),
        ("POST new delegated device whose issued_by is a full-access device",
         "accept", "(with issuer-signature requirement)"),
        ("POST new delegated device whose issued_by is this delegated device",
         "reject", "scope_invalid (nested delegation)"),
    ]

    lifecycle_ops = [
        ("Primary client issues new certificate (scope update)",
         "session continues", "New scope enforced on next submission"),
        ("Primary client rotates delegated device key",
         "session invalidated", "Delegated client must re-handshake"),
        ("Primary client revokes delegated device key",
         "session invalidated", "Delegated client cannot re-handshake"),
        ("Certificate expires",
         "session continues",
         "All submissions rejected until new certificate issued"),
    ]

    staged_devices = [
        {
            "device": "Filter (delegated)",
            "scope_receive": {
                "mode": "unrestricted",
                "rate_limits": [],
                "delivery_stage": 1,
            },
        },
        {
            "device": "Main (full-access)",
            "scope_receive": "no certificate (implicit stage 2)",
        },
    ]
    staged_steps = [
        {
            "step": "1",
            "trigger": "envelope passes the ordinary delivery pipeline",
            "server_action": "partition devices by stage; deliver to Filter (stage 1); hold for Main (stage 2) in queue",
        },
        {
            "step": "2a",
            "trigger": "Filter emits delivery-disposition with disposition=advance",
            "server_action": "release envelope from queue; deliver to Main",
        },
        {
            "step": "2b",
            "trigger": "Filter emits delivery-disposition with disposition=suppress",
            "server_action": "drop envelope from queue; Main does not receive",
        },
        {
            "step": "2c",
            "trigger": "Filter is offline; stage timeout elapses (RECOMMENDED 30s)",
            "server_action": "advance to stage 2 (fail open); deliver to Main",
        },
    ]
    staged_aggregation = [
        ("A: advance, B: advance, C: advance", "advance to stage 2"),
        ("A: advance, B: advance, C: suppress", "suppress (any suppress wins)"),
        ("A: advance, B: no response, C: no response; timeout",
         "advance to stage 2"),
        ("A: no response, B: no response, C: no response; timeout",
         "advance to stage 2 (fail open)"),
    ]
    disposition_envelope = {
        "brief": {
            "from": "alice@example.com",
            "to": "alice@example.com",
            "extensions": {
                "semp.dev/device-sync": {
                    "required": True,
                    "data": {
                        "kind": "delivery-disposition",
                        "source_envelope_id": "01HF3X7M8N9P0Q1R2S3T4U5V6W",
                        "disposition": "suppress",
                        "reason": "spam",
                        "device_id": "filter-device-ulid",
                    },
                }
            },
        }
    }
    disposition_checks = [
        ("data.device_id matches authenticated session's device id", "proceed"),
        ("data.device_id does not match authenticated session's device id",
         "reject envelope"),
        ("source_envelope_id references an envelope held for this account at the submitter's stage or earlier",
         "apply disposition"),
        ("source_envelope_id does not reference any held envelope",
         "discard disposition silently"),
        ("Envelope carries brief-layer sync fields other than semp.dev/device-sync",
         "reject: extension_unsupported"),
    ]

    return {
        "version": "1.0.0",
        "category": "device-certificates",
        "description": (
            "Scoped device certificate validation, scope enforcement, rate "
            "limits, resource read/write enforcement, certificate lifecycle, "
            "and staged delivery. Source of truth: VECTORS.md §14."
        ),
        "spec_reference": "VECTORS.md §14; KEY.md §10.3; CLIENT.md §2.3, §2.4",
        "vectors": [
            {
                "id": "valid-device-certificate",
                "description": "A well-formed SEMP_DEVICE_CERTIFICATE and the per-check expected outcomes.",
                "spec_reference": "VECTORS.md §14.1; KEY.md §10.3",
                "inputs": {"certificate_json": VALID_DEVICE_CERT},
                "expected": {
                    "checks": [{"check": c, "result": r} for c, r in valid_checks],
                },
            },
            {
                "id": "certificate-validation-failures",
                "description": (
                    "Conditions under which a registration MUST be rejected, "
                    "with the reason_code surfaced where the spec defines one."
                ),
                "spec_reference": "VECTORS.md §14.2; KEY.md §10.3",
                "samples": [
                    {
                        "condition": cond,
                        "expected_action": action,
                        "reason_code": code,
                    }
                    for cond, action, code in failures
                ],
            },
            {
                "id": "scope-enforcement-by-recipient",
                "description": (
                    "Per-recipient enforcement of scope.send for the §14.1 "
                    "certificate. Mixed-recipient submissions reject "
                    "atomically when ANY recipient is outside scope."
                ),
                "spec_reference": "VECTORS.md §14.3; CLIENT.md §2.3",
                "samples": [
                    {
                        "recipient_address": addr,
                        "scope_match": match,
                        "expected_action": action,
                        "reason_code": code,
                    }
                    for addr, match, action, code in enforcement
                ],
            },
            {
                "id": "scope-mode-enforcement",
                "description": "scope.send.mode semantics across all four modes.",
                "spec_reference": "VECTORS.md §14.4; CLIENT.md §2.3",
                "samples": [
                    {
                        "scope_send_mode": mode,
                        "recipient": rcp,
                        "expected_action": action,
                        "reason_code": code,
                    }
                    for mode, rcp, action, code in mode_enforcement
                ],
            },
            {
                "id": "receive-matcher-enforcement",
                "description": (
                    "scope.receive enforcement. Multiple devices on the same "
                    "account can have independent matchers; an inbound "
                    "envelope is delivered to each device whose matcher "
                    "accepts the sender."
                ),
                "spec_reference": "VECTORS.md §14.4.1; CLIENT.md §2.4",
                "samples": receive_matcher,
            },
            {
                "id": "rate-limit-enforcement",
                "description": (
                    "scope.send.rate_limits and scope.blocklist.rate_limits "
                    "behavior. Counters MUST NOT record rejected attempts."
                ),
                "spec_reference": "VECTORS.md §14.4.2; CLIENT.md §2.3",
                "samples": [
                    {
                        "tier_config": "single tier {period: 3600, amount: 100}",
                        "state": s,
                        "expected_action": a,
                        "note": n,
                    }
                    for s, a, n in rate_limit_single_tier
                ] + [
                    {
                        "tier_config": "two tiers {3600, 100} and {86400, 500}",
                        "state": s,
                        "expected_action": a,
                        "note": n,
                    }
                    for s, a, n in rate_limit_two_tier
                ] + [
                    {
                        "tier_config": "scope.blocklist.rate_limits = []",
                        "state": s,
                        "expected_action": "no protocol-imposed cap",
                        "note": n,
                    }
                    for s, n in rate_limit_blocklist
                ],
            },
            {
                "id": "resource-read-write-enforcement",
                "description": (
                    "Operations on managed resources (blocklist, keys, "
                    "devices) are gated by per-resource read/write flags in "
                    "the scope. Nested delegation is forbidden."
                ),
                "spec_reference": "VECTORS.md §14.4.3; CLIENT.md §2.4",
                "inputs": {"scope_excerpt": rw_enforcement_scope},
                "expected": {
                    "operations": [
                        {
                            "operation": op,
                            "expected_action": action,
                            "reason_code_or_note": code,
                        }
                        for op, action, code in rw_operations
                    ],
                },
            },
            {
                "id": "certificate-lifecycle-operations",
                "description": (
                    "Effect of certificate lifecycle operations on existing "
                    "delegated sessions."
                ),
                "spec_reference": "VECTORS.md §14.5; KEY.md §10.3",
                "samples": [
                    {
                        "operation": op,
                        "session_impact": impact,
                        "expected_behavior": behavior,
                    }
                    for op, impact, behavior in lifecycle_ops
                ],
            },
            {
                "id": "staged-delivery",
                "description": (
                    "Multi-stage delivery with at least one filter device "
                    "(stage 1) and a primary device (stage 2). The filter "
                    "emits delivery-disposition envelopes that drive whether "
                    "the original envelope advances to stage 2."
                ),
                "spec_reference": "VECTORS.md §14.6; CLIENT.md §2.4",
                "inputs": {
                    "devices": staged_devices,
                    "disposition_envelope_example": disposition_envelope,
                },
                "expected": {
                    "single_filter_steps": staged_steps,
                    "three_filter_aggregation": [
                        {"dispositions": d, "outcome": o}
                        for d, o in staged_aggregation
                    ],
                    "disposition_verification": [
                        {"condition": c, "expected_behavior": b}
                        for c, b in disposition_checks
                    ],
                },
            },
        ],
    }


# ---- Seal round-trip vectors (Layer 3, baseline suite) ----------------------
#
# Implements the wire format pinned in ENVELOPE.md §4.4.1 for the
# x25519-chacha20-poly1305 suite. The post-quantum suite lands in a
# follow-up once pqcrypto is added to requirements.txt.


def x25519_pubkey_from_priv(priv_bytes: bytes) -> bytes:
    """Derive the 32-byte X25519 public key from a 32-byte private key."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    priv = X25519PrivateKey.from_private_bytes(priv_bytes)
    from cryptography.hazmat.primitives import serialization

    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def x25519_ecdh(priv_bytes: bytes, peer_pub_bytes: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )

    priv = X25519PrivateKey.from_private_bytes(priv_bytes)
    peer = X25519PublicKey.from_public_bytes(peer_pub_bytes)
    return priv.exchange(peer)


def chacha20_poly1305_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def chacha20_poly1305_open(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)


def xchacha20_poly1305_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """RFC 8439-derived XChaCha20-Poly1305 (24-byte nonce). Used by the
    post-quantum suite's large-attachment AEAD per ATTACHMENTS.md §3.2."""
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt

    if len(nonce) != 24:
        raise ValueError("XChaCha20-Poly1305 nonce MUST be 24 bytes")
    return crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)


def xchacha20_poly1305_open(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt

    if len(nonce) != 24:
        raise ValueError("XChaCha20-Poly1305 nonce MUST be 24 bytes")
    return crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, aad, nonce, key)


WRAP_INFO = b"SEMP-v1-wrap"


def seal_wrap_baseline(
    K: bytes, recipient_pub: bytes, ephemeral_priv: bytes
) -> tuple[bytes, dict]:
    """Wrap K under recipient_pub using x25519-chacha20-poly1305 per
    ENVELOPE.md §4.4.1.

    ephemeral_priv is the pinned X25519 private key (32 bytes). In production
    this is freshly generated per Wrap call; vectors pin it so the output
    bytes are reproducible.

    Returns (wrapped_b64, intermediates_for_inspection).
    """
    if len(recipient_pub) != 32:
        raise ValueError("baseline suite expects 32-byte X25519 recipient pub")
    if len(ephemeral_priv) != 32:
        raise ValueError("baseline suite expects 32-byte X25519 ephemeral priv")

    ephemeral_pub = x25519_pubkey_from_priv(ephemeral_priv)
    shared_secret = x25519_ecdh(ephemeral_priv, recipient_pub)
    kem_ct = ephemeral_pub  # baseline: kem_ct == ephemeral_pub

    salt = kem_ct + recipient_pub
    prk = hkdf_extract(salt, shared_secret)
    wrap_key = hkdf_expand(prk, WRAP_INFO, 32)

    nonce = b"\x00" * 12
    aead_ct = chacha20_poly1305_seal(wrap_key, nonce, K, recipient_pub)

    wrapped = kem_ct + aead_ct
    import base64

    inter = {
        "ephemeral_pub_hex": ephemeral_pub.hex(),
        "shared_secret_hex": shared_secret.hex(),
        "kem_ct_hex": kem_ct.hex(),
        "hkdf_salt_hex": salt.hex(),
        "prk_hex": prk.hex(),
        "wrap_key_hex": wrap_key.hex(),
        "aead_nonce_hex": nonce.hex(),
        "aead_aad_hex": recipient_pub.hex(),
        "aead_ct_hex": aead_ct.hex(),
        "wrapped_bytes_hex": wrapped.hex(),
    }
    return base64.b64encode(wrapped).decode("ascii"), inter


def seal_unwrap_baseline(
    wrapped_b64: str, recipient_priv: bytes, recipient_pub: bytes
) -> bytes:
    """Reverse seal_wrap_baseline."""
    import base64

    raw = base64.b64decode(wrapped_b64)
    if len(raw) < 32 + 16:
        raise ValueError("wrapped payload too short for baseline suite")
    kem_ct = raw[:32]
    aead_ct = raw[32:]

    shared_secret = x25519_ecdh(recipient_priv, kem_ct)
    salt = kem_ct + recipient_pub
    prk = hkdf_extract(salt, shared_secret)
    wrap_key = hkdf_expand(prk, WRAP_INFO, 32)

    nonce = b"\x00" * 12
    return chacha20_poly1305_open(wrap_key, nonce, aead_ct, recipient_pub)


# Kyber768 / ML-KEM-768 deterministic API via kyber-py.
KYBER768_EK_SIZE = 1184       # encapsulation (public) key
KYBER768_DK_SIZE = 2400       # decapsulation (private) key
KYBER768_CT_SIZE = 1088       # ciphertext
PQ_RECIPIENT_PUB_SIZE = KYBER768_EK_SIZE + 32  # || X25519 pub
PQ_KEM_CT_SIZE = KYBER768_CT_SIZE + 32         # || X25519 ephemeral pub


def kyber768_keygen_internal(d_seed: bytes, z_seed: bytes) -> tuple[bytes, bytes]:
    """FIPS 203 ML-KEM-768 deterministic keygen. d, z are each 32 bytes."""
    from kyber_py.ml_kem import ML_KEM_768

    return ML_KEM_768._keygen_internal(d_seed, z_seed)


def kyber768_encaps_internal(ek: bytes, m: bytes) -> tuple[bytes, bytes]:
    """FIPS 203 ML-KEM-768 deterministic encaps. m is 32 bytes of randomness.
    Returns (shared_secret_32B, ciphertext_1088B)."""
    from kyber_py.ml_kem import ML_KEM_768

    return ML_KEM_768._encaps_internal(ek, m)


def kyber768_decaps_internal(dk: bytes, ct: bytes) -> bytes:
    from kyber_py.ml_kem import ML_KEM_768

    return ML_KEM_768._decaps_internal(dk, ct)


def seal_wrap_pq(
    K: bytes,
    recipient_pub: bytes,
    ephemeral_priv: bytes,
    kyber_encaps_randomness: bytes,
) -> tuple[bytes, dict]:
    """Wrap K under recipient_pub using pq-kyber768-x25519 per ENVELOPE.md
    §4.4.1 (PQ branch).

    recipient_pub is the 1216-byte hybrid public key:
      kyber768_ek (1184) || x25519_pub (32).
    ephemeral_priv is the 32-byte X25519 ephemeral private key.
    kyber_encaps_randomness is the 32-byte input to ML-KEM-768 encaps that
    determines kyber_ct and kyber_ss; pinning it makes the wrap output
    byte-deterministic.
    """
    if len(recipient_pub) != PQ_RECIPIENT_PUB_SIZE:
        raise ValueError(
            f"pq suite expects {PQ_RECIPIENT_PUB_SIZE}-byte recipient pub"
        )
    if len(ephemeral_priv) != 32:
        raise ValueError("pq suite expects 32-byte X25519 ephemeral priv")
    if len(kyber_encaps_randomness) != 32:
        raise ValueError("pq suite expects 32-byte kyber encaps randomness")

    rcp_kyber_pub = recipient_pub[:KYBER768_EK_SIZE]
    rcp_x25519_pub = recipient_pub[KYBER768_EK_SIZE:]

    kyber_ss, kyber_ct = kyber768_encaps_internal(rcp_kyber_pub, kyber_encaps_randomness)
    ephemeral_pub = x25519_pubkey_from_priv(ephemeral_priv)
    x25519_ss = x25519_ecdh(ephemeral_priv, rcp_x25519_pub)

    shared_secret = kyber_ss + x25519_ss              # 64 bytes
    kem_ct = kyber_ct + ephemeral_pub                 # 1120 bytes

    salt = kem_ct + recipient_pub
    prk = hkdf_extract(salt, shared_secret)
    wrap_key = hkdf_expand(prk, WRAP_INFO, 32)

    nonce = b"\x00" * 12
    aead_ct = chacha20_poly1305_seal(wrap_key, nonce, K, recipient_pub)

    wrapped = kem_ct + aead_ct
    import base64

    inter = {
        "kyber_ct_hex": kyber_ct.hex(),
        "kyber_shared_secret_hex": kyber_ss.hex(),
        "ephemeral_pub_hex": ephemeral_pub.hex(),
        "x25519_shared_secret_hex": x25519_ss.hex(),
        "shared_secret_hex": shared_secret.hex(),
        "kem_ct_hex": kem_ct.hex(),
        "hkdf_salt_hex": salt.hex(),
        "prk_hex": prk.hex(),
        "wrap_key_hex": wrap_key.hex(),
        "aead_nonce_hex": nonce.hex(),
        "aead_aad_hex": recipient_pub.hex(),
        "aead_ct_hex": aead_ct.hex(),
        "wrapped_bytes_length": len(wrapped),
    }
    return base64.b64encode(wrapped).decode("ascii"), inter


def seal_unwrap_pq(
    wrapped_b64: str, recipient_priv: bytes, recipient_pub: bytes
) -> bytes:
    """Reverse seal_wrap_pq. recipient_priv is 32 bytes X25519 || the
    Kyber dk (2400 bytes), in that concatenation order: recipient_priv =
    kyber_dk (2400) || x25519_priv (32). recipient_pub matches the
    encapsulation order kyber_ek (1184) || x25519_pub (32)."""
    import base64

    if len(recipient_priv) != KYBER768_DK_SIZE + 32:
        raise ValueError(
            f"pq suite expects {KYBER768_DK_SIZE + 32}-byte recipient priv"
        )
    raw = base64.b64decode(wrapped_b64)
    if len(raw) < PQ_KEM_CT_SIZE + 16:
        raise ValueError("wrapped payload too short for pq suite")

    kem_ct = raw[:PQ_KEM_CT_SIZE]
    aead_ct = raw[PQ_KEM_CT_SIZE:]
    kyber_ct = kem_ct[:KYBER768_CT_SIZE]
    ephemeral_pub = kem_ct[KYBER768_CT_SIZE:]

    rcp_kyber_dk = recipient_priv[:KYBER768_DK_SIZE]
    rcp_x25519_priv = recipient_priv[KYBER768_DK_SIZE:]

    kyber_ss = kyber768_decaps_internal(rcp_kyber_dk, kyber_ct)
    x25519_ss = x25519_ecdh(rcp_x25519_priv, ephemeral_pub)
    shared_secret = kyber_ss + x25519_ss

    salt = kem_ct + recipient_pub
    prk = hkdf_extract(salt, shared_secret)
    wrap_key = hkdf_expand(prk, WRAP_INFO, 32)

    nonce = b"\x00" * 12
    return chacha20_poly1305_open(wrap_key, nonce, aead_ct, recipient_pub)


def build_seal_roundtrip_json() -> dict:
    """Three pinned-input wrap cases for the baseline suite. Every byte is
    deterministic given the inputs; an implementation that produces the same
    `wrapped_b64` for the same `K`, `recipient_pub`, and `ephemeral_priv`
    is interoperable at the seal-wrap layer."""

    cases = []

    # Case 1: 32-byte K (typical K_brief / K_enclosure size).
    K1 = bytes.fromhex("4242424242424242424242424242424242424242424242424242424242424242")
    rcp_priv_1 = bytes.fromhex(
        "1010101010101010101010101010101010101010101010101010101010101010"
    )
    rcp_pub_1 = x25519_pubkey_from_priv(rcp_priv_1)
    eph_priv_1 = bytes.fromhex(
        "2020202020202020202020202020202020202020202020202020202020202020"
    )
    wrapped_1, inter_1 = seal_wrap_baseline(K1, rcp_pub_1, eph_priv_1)
    # Round-trip sanity: unwrap MUST recover K.
    assert seal_unwrap_baseline(wrapped_1, rcp_priv_1, rcp_pub_1) == K1
    cases.append({
        "id": "seal-wrap-baseline-32B-key",
        "description": (
            "Baseline x25519-chacha20-poly1305 wrap of a 32-byte symmetric "
            "key, all inputs pinned for byte reproducibility."
        ),
        "spec_reference": "ENVELOPE.md §4.4.1; VECTORS.md §17.1",
        "inputs": {
            "suite": "x25519-chacha20-poly1305",
            "symmetric_key_hex": K1.hex(),
            "recipient_private_key_hex": rcp_priv_1.hex(),
            "recipient_public_key_hex": rcp_pub_1.hex(),
            "ephemeral_private_key_hex": eph_priv_1.hex(),
        },
        "intermediates": inter_1,
        "expected": {
            "wrapped_b64": wrapped_1,
            "wrapped_byte_length": (len(eph_priv_1) + len(K1) + 16),
            "round_trip_recovers_K": True,
        },
    })

    # Case 2: a different 32-byte K with different ephemeral material.
    K2 = bytes.fromhex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
    rcp_priv_2 = bytes.fromhex(
        "3030303030303030303030303030303030303030303030303030303030303030"
    )
    rcp_pub_2 = x25519_pubkey_from_priv(rcp_priv_2)
    eph_priv_2 = bytes.fromhex(
        "4040404040404040404040404040404040404040404040404040404040404040"
    )
    wrapped_2, inter_2 = seal_wrap_baseline(K2, rcp_pub_2, eph_priv_2)
    assert seal_unwrap_baseline(wrapped_2, rcp_priv_2, rcp_pub_2) == K2
    cases.append({
        "id": "seal-wrap-baseline-distinct-recipient",
        "description": (
            "Same suite, different recipient and ephemeral key. Confirms "
            "the construction is deterministic with respect to inputs and "
            "produces independent ciphertexts for independent recipients."
        ),
        "spec_reference": "ENVELOPE.md §4.4.1; VECTORS.md §17.1",
        "inputs": {
            "suite": "x25519-chacha20-poly1305",
            "symmetric_key_hex": K2.hex(),
            "recipient_private_key_hex": rcp_priv_2.hex(),
            "recipient_public_key_hex": rcp_pub_2.hex(),
            "ephemeral_private_key_hex": eph_priv_2.hex(),
        },
        "intermediates": inter_2,
        "expected": {
            "wrapped_b64": wrapped_2,
            "wrapped_byte_length": (len(eph_priv_2) + len(K2) + 16),
            "round_trip_recovers_K": True,
        },
    })

    # Case 3: same K and recipient as case 1, different ephemeral. Proves
    # that the wrapped ciphertext changes when only the ephemeral changes.
    eph_priv_3 = bytes.fromhex(
        "5050505050505050505050505050505050505050505050505050505050505050"
    )
    wrapped_3, inter_3 = seal_wrap_baseline(K1, rcp_pub_1, eph_priv_3)
    assert seal_unwrap_baseline(wrapped_3, rcp_priv_1, rcp_pub_1) == K1
    assert wrapped_3 != wrapped_1, "ephemeral change MUST change wrapped output"
    cases.append({
        "id": "seal-wrap-baseline-ephemeral-changes-output",
        "description": (
            "Same K and recipient as the first case, different "
            "ephemeral_private_key. The wrapped ciphertext MUST differ from "
            "the first case's, confirming that the ephemeral is bound into "
            "the construction (no nonce reuse possible across calls)."
        ),
        "spec_reference": "ENVELOPE.md §4.4.1; VECTORS.md §17.1",
        "inputs": {
            "suite": "x25519-chacha20-poly1305",
            "symmetric_key_hex": K1.hex(),
            "recipient_private_key_hex": rcp_priv_1.hex(),
            "recipient_public_key_hex": rcp_pub_1.hex(),
            "ephemeral_private_key_hex": eph_priv_3.hex(),
        },
        "intermediates": inter_3,
        "expected": {
            "wrapped_b64": wrapped_3,
            "wrapped_byte_length": (len(eph_priv_3) + len(K1) + 16),
            "round_trip_recovers_K": True,
            "differs_from_case_1": True,
        },
    })

    # ---- PQ suite (pq-kyber768-x25519) cases --------------------------------

    K4 = bytes.fromhex("9090909090909090909090909090909090909090909090909090909090909090")
    rcp_kyber_d_4 = bytes([0x60] * 32)
    rcp_kyber_z_4 = bytes([0x61] * 32)
    rcp_x25519_priv_4 = bytes([0x62] * 32)
    rcp_kyber_ek_4, rcp_kyber_dk_4 = kyber768_keygen_internal(
        rcp_kyber_d_4, rcp_kyber_z_4
    )
    rcp_x25519_pub_4 = x25519_pubkey_from_priv(rcp_x25519_priv_4)
    rcp_pub_4 = rcp_kyber_ek_4 + rcp_x25519_pub_4
    rcp_priv_4 = rcp_kyber_dk_4 + rcp_x25519_priv_4

    eph_priv_4 = bytes([0x63] * 32)
    kyber_encaps_m_4 = bytes([0x64] * 32)
    wrapped_4, inter_4 = seal_wrap_pq(K4, rcp_pub_4, eph_priv_4, kyber_encaps_m_4)
    assert seal_unwrap_pq(wrapped_4, rcp_priv_4, rcp_pub_4) == K4
    cases.append({
        "id": "seal-wrap-pq-32B-key",
        "description": (
            "Hybrid pq-kyber768-x25519 wrap of a 32-byte symmetric key. "
            "Both the X25519 ephemeral priv and the ML-KEM-768 encaps "
            "randomness (m) are pinned, so the entire wrapped output is "
            "byte-deterministic. The recipient public key is the 1216-byte "
            "concatenation kyber_ek || x25519_pub; the recipient private "
            "key is kyber_dk || x25519_priv."
        ),
        "spec_reference": "ENVELOPE.md §4.4.1; VECTORS.md §17.1",
        "inputs": {
            "suite": "pq-kyber768-x25519",
            "symmetric_key_hex": K4.hex(),
            "recipient_kyber_keygen_d_hex": rcp_kyber_d_4.hex(),
            "recipient_kyber_keygen_z_hex": rcp_kyber_z_4.hex(),
            "recipient_x25519_private_key_hex": rcp_x25519_priv_4.hex(),
            "recipient_kyber_public_key_hex": rcp_kyber_ek_4.hex(),
            "recipient_x25519_public_key_hex": rcp_x25519_pub_4.hex(),
            "recipient_hybrid_public_key_hex": rcp_pub_4.hex(),
            "ephemeral_x25519_private_key_hex": eph_priv_4.hex(),
            "kyber_encaps_randomness_m_hex": kyber_encaps_m_4.hex(),
        },
        "intermediates": inter_4,
        "expected": {
            "wrapped_b64": wrapped_4,
            "wrapped_byte_length": (PQ_KEM_CT_SIZE + len(K4) + 16),
            "round_trip_recovers_K": True,
        },
    })

    K5 = bytes.fromhex("0011223344556677889900aabbccddeeff00112233445566778899aabbccddee")
    rcp_kyber_d_5 = bytes([0x70] * 32)
    rcp_kyber_z_5 = bytes([0x71] * 32)
    rcp_x25519_priv_5 = bytes([0x72] * 32)
    rcp_kyber_ek_5, rcp_kyber_dk_5 = kyber768_keygen_internal(
        rcp_kyber_d_5, rcp_kyber_z_5
    )
    rcp_x25519_pub_5 = x25519_pubkey_from_priv(rcp_x25519_priv_5)
    rcp_pub_5 = rcp_kyber_ek_5 + rcp_x25519_pub_5
    rcp_priv_5 = rcp_kyber_dk_5 + rcp_x25519_priv_5

    eph_priv_5 = bytes([0x73] * 32)
    kyber_encaps_m_5 = bytes([0x74] * 32)
    wrapped_5, inter_5 = seal_wrap_pq(K5, rcp_pub_5, eph_priv_5, kyber_encaps_m_5)
    assert seal_unwrap_pq(wrapped_5, rcp_priv_5, rcp_pub_5) == K5
    cases.append({
        "id": "seal-wrap-pq-distinct-recipient",
        "description": (
            "Same suite as the previous case, different recipient hybrid "
            "key and different X25519 ephemeral / Kyber encaps randomness. "
            "Confirms the construction is deterministic with respect to "
            "inputs and produces independent ciphertexts for independent "
            "recipients."
        ),
        "spec_reference": "ENVELOPE.md §4.4.1; VECTORS.md §17.1",
        "inputs": {
            "suite": "pq-kyber768-x25519",
            "symmetric_key_hex": K5.hex(),
            "recipient_kyber_keygen_d_hex": rcp_kyber_d_5.hex(),
            "recipient_kyber_keygen_z_hex": rcp_kyber_z_5.hex(),
            "recipient_x25519_private_key_hex": rcp_x25519_priv_5.hex(),
            "recipient_kyber_public_key_hex": rcp_kyber_ek_5.hex(),
            "recipient_x25519_public_key_hex": rcp_x25519_pub_5.hex(),
            "recipient_hybrid_public_key_hex": rcp_pub_5.hex(),
            "ephemeral_x25519_private_key_hex": eph_priv_5.hex(),
            "kyber_encaps_randomness_m_hex": kyber_encaps_m_5.hex(),
        },
        "intermediates": inter_5,
        "expected": {
            "wrapped_b64": wrapped_5,
            "wrapped_byte_length": (PQ_KEM_CT_SIZE + len(K5) + 16),
            "round_trip_recovers_K": True,
        },
    })

    return {
        "version": "1.0.0",
        "category": "seal-roundtrip",
        "description": (
            "Layer 3 round-trip vectors for the seal wrap construction "
            "pinned in ENVELOPE.md §4.4.1. Every random input is supplied "
            "as part of the vector so the wrapped output is "
            "byte-deterministic. Implementations MUST expose a "
            "deterministic-compose code path that accepts random material "
            "instead of generating it; that path is test-only and MUST NOT "
            "be reachable from production senders."
        ),
        "spec_reference": "VECTORS.md §17.1; ENVELOPE.md §4.4.1",
        "construction": {
            "baseline": {
                "shared_secret": "X25519 ECDH(ephemeral_priv, recipient_pub)",
                "kem_ct": "ephemeral_pub (32 bytes)",
                "wrapped_byte_length_for_32B_K": 80,
            },
            "pq_kyber768_x25519": {
                "shared_secret": "kyber_ss (32 B) || x25519_ss (32 B) = 64 bytes",
                "kem_ct": "kyber_ct (1088 B) || ephemeral_pub (32 B) = 1120 bytes",
                "recipient_pub_layout": "kyber_ek (1184 B) || x25519_pub (32 B) = 1216 bytes",
                "recipient_priv_layout": "kyber_dk (2400 B) || x25519_priv (32 B) = 2432 bytes",
                "wrapped_byte_length_for_32B_K": 1168,
            },
            "shared": {
                "hkdf_salt": "kem_ct || recipient_pub",
                "hkdf_info_utf8": "SEMP-v1-wrap",
                "hkdf_hash": "SHA-512",
                "wrap_key_length_bytes": 32,
                "aead": "ChaCha20-Poly1305",
                "aead_nonce": "12 bytes of 0x00",
                "aead_aad": "recipient_pub (full hybrid pub for pq)",
                "wire_format": "base64( kem_ct || aead_ct )",
            },
        },
        "suites_covered": [
            "x25519-chacha20-poly1305",
            "pq-kyber768-x25519",
        ],
        "vectors": cases,
    }


# ---- Sender-signature vectors (Layer 3) -------------------------------------
#
# Implements ENVELOPE.md §6.5: Ed25519 signature over the canonical enclosure
# with the SEMP-ENCLOSURE-SENDER: domain-separation prefix.


def ed25519_pubkey_from_priv(priv_bytes: bytes) -> bytes:
    """Derive the 32-byte Ed25519 public key from a 32-byte seed."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.from_private_bytes(priv_bytes)
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def ed25519_sign(priv_bytes: bytes, message: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.from_private_bytes(priv_bytes).sign(message)


def ed25519_verify(pub_bytes: bytes, signature: bytes, message: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(pub_bytes).verify(signature, message)
        return True
    except InvalidSignature:
        return False


def fingerprint_hex(pub_bytes: bytes) -> str:
    """KEY.md §4.4: lowercase hex of SHA-256(public_key)."""
    return hashlib.sha256(pub_bytes).hexdigest()


SENDER_SIGNATURE_PREFIX = b"SEMP-ENCLOSURE-SENDER:"


def sender_signature_canonical(enclosure: dict) -> bytes:
    """Per ENVELOPE.md §6.5.2 step 4: canonical JSON of the enclosure with
    sender_signature.value blanked."""
    e = copy.deepcopy(enclosure)
    if "sender_signature" not in e:
        raise ValueError("enclosure missing sender_signature block")
    e["sender_signature"]["value"] = ""
    return canonical_json(e)


def sender_signature_compute(enclosure: dict, identity_priv: bytes) -> tuple[dict, dict]:
    """Apply ENVELOPE.md §6.5.2 to produce a signed enclosure.

    Returns (signed_enclosure, intermediates).
    """
    canonical = sender_signature_canonical(enclosure)
    prefixed = SENDER_SIGNATURE_PREFIX + canonical
    sig = ed25519_sign(identity_priv, prefixed)

    import base64

    signed = copy.deepcopy(enclosure)
    signed["sender_signature"]["value"] = base64.b64encode(sig).decode("ascii")

    inter = {
        "canonical_enclosure_with_blanked_signature_utf8": canonical.decode("utf-8"),
        "signing_input_prefix_utf8": SENDER_SIGNATURE_PREFIX.decode("utf-8"),
        "signing_input_hex": prefixed.hex(),
        "signature_hex": sig.hex(),
    }
    return signed, inter


def sender_signature_verify(signed_enclosure: dict, sender_identity_pub: bytes) -> bool:
    """Per ENVELOPE.md §6.5.3."""
    import base64

    sig_b64 = signed_enclosure["sender_signature"]["value"]
    sig = base64.b64decode(sig_b64)
    canonical = sender_signature_canonical(signed_enclosure)
    prefixed = SENDER_SIGNATURE_PREFIX + canonical
    return ed25519_verify(sender_identity_pub, sig, prefixed)


def build_sender_signature_json() -> dict:
    """Three pinned-input cases for §6.5: a valid signature, a body-tampered
    failure, and a wrong-key failure."""

    # Pinned identity key A (the legitimate sender).
    seed_a = bytes([0x11] * 32)
    pub_a = ed25519_pubkey_from_priv(seed_a)
    fp_a = fingerprint_hex(pub_a)

    # Pinned identity key B (a different sender; used to demonstrate that
    # signing with B and verifying as A fails).
    seed_b = bytes([0x22] * 32)
    pub_b = ed25519_pubkey_from_priv(seed_b)
    fp_b = fingerprint_hex(pub_b)

    base_enclosure = {
        "subject": "Layer 3 vector check",
        "content_type": "text/plain",
        "body": {
            "text/plain": "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4=",
        },
        "attachments": [],
        "forwarded_from": None,
        "extensions": {},
        "sender_signature": {
            "algorithm": "ed25519",
            "key_id": fp_a,
            "value": "",
        },
    }

    # Case 1: valid signature.
    signed_valid, inter_valid = sender_signature_compute(base_enclosure, seed_a)
    assert sender_signature_verify(signed_valid, pub_a)

    # Case 2: same as case 1 but with the body altered after signing. The
    # verification reconstructs the canonical bytes from the tampered
    # enclosure, which differ from the bytes that were signed, so Ed25519
    # verify rejects.
    tampered = copy.deepcopy(signed_valid)
    tampered["body"]["text/plain"] = (
        "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBaYXp5IGRvZy4="
    )  # one byte differs
    assert not sender_signature_verify(tampered, pub_a)

    # Case 3: enclosure signed by B but presented with key_id pointing at A
    # (or attempted verification against A). Verification fails because the
    # signature was produced by a different private key. We model this as
    # producing a signature with seed_b and presenting the enclosure with
    # sender_signature.key_id still claiming key A; verification against
    # pub_a fails.
    enclosure_for_wrong_key = copy.deepcopy(base_enclosure)
    enclosure_for_wrong_key["sender_signature"]["key_id"] = fp_a  # claims A
    signed_with_b, inter_wrong = sender_signature_compute(
        enclosure_for_wrong_key, seed_b
    )
    assert not sender_signature_verify(signed_with_b, pub_a)
    # Sanity: it WOULD verify against pub_b, since seed_b actually signed it.
    assert sender_signature_verify(signed_with_b, pub_b)

    return {
        "version": "1.0.0",
        "category": "sender-signature",
        "description": (
            "Layer 3 round-trip vectors for the enclosure sender_signature "
            "construction in ENVELOPE.md §6.5: Ed25519 over the canonical "
            "enclosure (with sender_signature.value blanked) prefixed with "
            "the SEMP-ENCLOSURE-SENDER: domain separator."
        ),
        "spec_reference": "VECTORS.md §17.2; ENVELOPE.md §6.5; KEY.md §4.4",
        "construction": {
            "signature_algorithm": "Ed25519",
            "domain_separation_prefix_utf8": "SEMP-ENCLOSURE-SENDER:",
            "canonical_form": (
                "Per ENVELOPE.md §4.3: sorted keys at every nesting level, "
                "no insignificant whitespace, UTF-8 encoding. Apply with "
                "enclosure.sender_signature.value set to \"\"."
            ),
            "signing_input": "prefix || canonical_enclosure_bytes",
            "key_id_construction": "lowercase hex of SHA-256(public_key) per KEY.md §4.4",
        },
        "vectors": [
            {
                "id": "sender-signature-valid",
                "description": (
                    "Pinned identity key signs a pinned enclosure. "
                    "Verification with the matching public key succeeds."
                ),
                "spec_reference": "VECTORS.md §17.2; ENVELOPE.md §6.5.2, §6.5.3",
                "inputs": {
                    "identity_private_seed_hex": seed_a.hex(),
                    "identity_public_key_hex": pub_a.hex(),
                    "identity_key_id": fp_a,
                    "enclosure_pre_sign_json": base_enclosure,
                },
                "intermediates": inter_valid,
                "expected": {
                    "signed_enclosure_json": signed_valid,
                    "signature_b64": signed_valid["sender_signature"]["value"],
                    "verifies_with_correct_key": True,
                },
            },
            {
                "id": "sender-signature-tampered-body",
                "description": (
                    "Take the §17.2/sender-signature-valid output and change "
                    "one byte of the body text/plain. The reconstructed "
                    "canonical bytes differ from what was signed, so Ed25519 "
                    "verify MUST reject."
                ),
                "spec_reference": "VECTORS.md §17.2; ENVELOPE.md §6.5.3",
                "inputs": {
                    "identity_public_key_hex": pub_a.hex(),
                    "tampered_signed_enclosure_json": tampered,
                },
                "expected": {
                    "verifies_with_correct_key": False,
                    "rejection_reason": "ed25519 signature mismatch after canonical reconstruction",
                },
            },
            {
                "id": "sender-signature-wrong-key",
                "description": (
                    "Enclosure has key_id pointing at identity A but was "
                    "actually signed by identity B's private key. Verification "
                    "against A's public key MUST fail; sanity-check that the "
                    "signature DOES verify against B's public key, isolating "
                    "the failure to the key-mismatch path."
                ),
                "spec_reference": "VECTORS.md §17.2; ENVELOPE.md §6.5.3",
                "inputs": {
                    "claimed_identity_key_id": fp_a,
                    "claimed_identity_public_key_hex": pub_a.hex(),
                    "actual_signer_private_seed_hex": seed_b.hex(),
                    "actual_signer_public_key_hex": pub_b.hex(),
                    "signed_enclosure_json": signed_with_b,
                },
                "expected": {
                    "verifies_with_claimed_key": False,
                    "verifies_with_actual_signer_key": True,
                    "rejection_reason": "key_id does not match the public key that produced the signature",
                },
            },
        ],
    }


# ---- Envelope round-trip vectors (Layer 3, ENVELOPE.md §7.1) ----------------


SEAL_SIGNATURE_PREFIX = b"SEMP-ENVELOPE:"


def encrypt_brief_or_enclosure(
    K: bytes, nonce: bytes, canonical_plaintext: bytes, postmark_id: str
) -> str:
    """ENVELOPE.md §7.1.1: AEAD.Seal under K with postmark.id (UTF-8) as AAD;
    envelope-field encoding is base64(nonce || ct)."""
    import base64

    aad = postmark_id.encode("utf-8")
    ct = chacha20_poly1305_seal(K, nonce, canonical_plaintext, aad)
    return base64.b64encode(nonce + ct).decode("ascii")


def decrypt_brief_or_enclosure(
    blob_b64: str, K: bytes, postmark_id: str, nonce_size: int = 12
) -> bytes:
    """Inverse of encrypt_brief_or_enclosure."""
    import base64

    raw = base64.b64decode(blob_b64)
    nonce = raw[:nonce_size]
    ct = raw[nonce_size:]
    aad = postmark_id.encode("utf-8")
    return chacha20_poly1305_open(K, nonce, ct, aad)


def envelope_canonical_for_signature(envelope: dict) -> bytes:
    """ENVELOPE.md §4.3 canonical form for seal.signature / seal.session_mac:
    blank seal.signature and seal.session_mac, omit postmark.hop_count and
    top-level padding, sort keys, no whitespace.
    """
    return canonical_envelope(envelope)


def _compose_envelope_vector(
    *,
    suite_id: str,
    sender_identity_seed: bytes,
    sender_domain_seed: bytes,
    K_brief: bytes,
    K_enclosure: bytes,
    brief_nonce: bytes,
    enclosure_nonce: bytes,
    K_env_mac: bytes,
    postmark_id: str,
    session_id: str,
    brief_obj: dict,
    enclosure_obj_pre_sign: dict,
    recipient_client_pub: bytes,
    recipient_client_priv: bytes,
    recipient_client_fp: str,
    recipient_domain_pub: bytes,
    recipient_domain_priv: bytes,
    recipient_domain_fp: str,
    wrap_fn,            # callable that takes (K, recipient_pub) -> (b64, intermediates)
    unwrap_fn,          # callable that takes (b64, recipient_priv, recipient_pub) -> bytes
    extra_inputs: dict,
) -> tuple[dict, dict]:
    """Drive the §7.1 compose flow + §7.2 verify flow with the given suite
    primitives, returning (vector_dict, intermediates_dict). Suite-specific
    bits (recipient pub layout, wrap function) are injected so this single
    function builds vectors for both the baseline and PQ suites."""

    sender_identity_pub = ed25519_pubkey_from_priv(sender_identity_seed)
    sender_identity_fp = fingerprint_hex(sender_identity_pub)
    sender_domain_pub = ed25519_pubkey_from_priv(sender_domain_seed)
    sender_domain_fp = fingerprint_hex(sender_domain_pub)

    enclosure_pre_sign = copy.deepcopy(enclosure_obj_pre_sign)
    enclosure_pre_sign["sender_signature"]["key_id"] = sender_identity_fp
    enclosure_signed, _ = sender_signature_compute(
        enclosure_pre_sign, sender_identity_seed
    )

    brief_canonical = canonical_json(brief_obj)
    enclosure_canonical = canonical_json(enclosure_signed)
    brief_blob = encrypt_brief_or_enclosure(
        K_brief, brief_nonce, brief_canonical, postmark_id
    )
    enclosure_blob = encrypt_brief_or_enclosure(
        K_enclosure, enclosure_nonce, enclosure_canonical, postmark_id
    )

    wrapped_brief_for_client, _ = wrap_fn(K_brief, recipient_client_pub, "brief_for_client")
    wrapped_brief_for_domain, _ = wrap_fn(K_brief, recipient_domain_pub, "brief_for_domain")
    wrapped_enclosure_for_client, _ = wrap_fn(K_enclosure, recipient_client_pub, "enclosure_for_client")

    envelope = {
        "type": "SEMP_ENVELOPE",
        "version": "1.0.0",
        "postmark": {
            "id": postmark_id,
            "session_id": session_id,
            "from_domain": "a.example",
            "to_domain": "b.example",
            "expires": "2026-05-15T09:00:00Z",
            "extensions": {},
        },
        "seal": {
            "algorithm": suite_id,
            "key_id": sender_domain_fp,
            "signature": "",
            "session_mac": "",
            "brief_recipients": {
                recipient_client_fp: wrapped_brief_for_client,
                recipient_domain_fp: wrapped_brief_for_domain,
            },
            "enclosure_recipients": {
                recipient_client_fp: wrapped_enclosure_for_client,
            },
            "extensions": {},
        },
        "brief": brief_blob,
        "enclosure": enclosure_blob,
    }

    canonical = envelope_canonical_for_signature(envelope)
    seal_signature = ed25519_sign(
        sender_domain_seed, SEAL_SIGNATURE_PREFIX + canonical
    )
    session_mac = hmac_sha256(K_env_mac, canonical)

    import base64

    final_envelope = copy.deepcopy(envelope)
    final_envelope["seal"]["signature"] = base64.b64encode(seal_signature).decode("ascii")
    final_envelope["seal"]["session_mac"] = base64.b64encode(session_mac).decode("ascii")

    # §7.2 verification asserted at generation time.
    canonical_after = envelope_canonical_for_signature(final_envelope)
    assert ed25519_verify(
        sender_domain_pub, seal_signature, SEAL_SIGNATURE_PREFIX + canonical_after
    )
    assert hmac_sha256(K_env_mac, canonical_after) == session_mac

    K_brief_server = unwrap_fn(
        final_envelope["seal"]["brief_recipients"][recipient_domain_fp],
        recipient_domain_priv, recipient_domain_pub,
    )
    assert K_brief_server == K_brief
    brief_recovered = decrypt_brief_or_enclosure(
        final_envelope["brief"], K_brief, postmark_id
    )
    assert json.loads(brief_recovered.decode("utf-8")) == brief_obj

    K_brief_client = unwrap_fn(
        final_envelope["seal"]["brief_recipients"][recipient_client_fp],
        recipient_client_priv, recipient_client_pub,
    )
    assert K_brief_client == K_brief
    K_enclosure_client = unwrap_fn(
        final_envelope["seal"]["enclosure_recipients"][recipient_client_fp],
        recipient_client_priv, recipient_client_pub,
    )
    assert K_enclosure_client == K_enclosure

    enclosure_recovered_bytes = decrypt_brief_or_enclosure(
        final_envelope["enclosure"], K_enclosure, postmark_id
    )
    enclosure_recovered = json.loads(enclosure_recovered_bytes.decode("utf-8"))
    assert sender_signature_verify(enclosure_recovered, sender_identity_pub)

    inputs = {
        "sender_identity_seed_hex": sender_identity_seed.hex(),
        "sender_identity_pub_hex": sender_identity_pub.hex(),
        "sender_identity_key_id": sender_identity_fp,
        "sender_domain_signing_seed_hex": sender_domain_seed.hex(),
        "sender_domain_signing_pub_hex": sender_domain_pub.hex(),
        "sender_domain_signing_key_id": sender_domain_fp,
        "recipient_client_pub_hex": recipient_client_pub.hex(),
        "recipient_client_key_id": recipient_client_fp,
        "recipient_server_domain_pub_hex": recipient_domain_pub.hex(),
        "recipient_server_domain_key_id": recipient_domain_fp,
        "K_brief_hex": K_brief.hex(),
        "K_enclosure_hex": K_enclosure.hex(),
        "brief_aead_nonce_hex": brief_nonce.hex(),
        "enclosure_aead_nonce_hex": enclosure_nonce.hex(),
        "K_env_mac_hex": K_env_mac.hex(),
        "brief_pre_encrypt_json": brief_obj,
        "enclosure_pre_sign_json": enclosure_pre_sign,
        "enclosure_post_sign_json": enclosure_signed,
        "postmark_id": postmark_id,
    }
    inputs.update(extra_inputs)

    intermediates = {
        "brief_canonical_utf8": brief_canonical.decode("utf-8"),
        "enclosure_canonical_utf8": enclosure_canonical.decode("utf-8"),
        "envelope_canonical_for_signature_utf8": canonical.decode("utf-8"),
        "seal_signature_input_prefix_utf8": SEAL_SIGNATURE_PREFIX.decode("utf-8"),
        "seal_signature_hex": seal_signature.hex(),
        "session_mac_hex": session_mac.hex(),
    }

    expected = {
        "envelope_json": final_envelope,
        "round_trip_recovers_brief": True,
        "round_trip_recovers_enclosure": True,
        "seal_signature_verifies": True,
        "session_mac_verifies": True,
        "sender_signature_verifies": True,
    }

    return {
        "inputs": inputs,
        "intermediates": intermediates,
        "expected": expected,
    }, intermediates


def build_envelope_roundtrip_json() -> dict:
    """Compose complete envelopes end-to-end for both the baseline and PQ
    suites, every random input pinned so the resulting JSON is byte
    deterministic. Exercises §7.1 steps 1-13 plus the §7.2 verification path."""

    # --- Baseline (x25519-chacha20-poly1305) ---------------------------------
    sender_identity_seed_b = bytes([0xA1] * 32)
    sender_domain_seed_b = bytes([0xA2] * 32)

    recipient_priv_b = bytes([0xB1] * 32)
    recipient_pub_b = x25519_pubkey_from_priv(recipient_priv_b)
    recipient_fp_b = fingerprint_hex(recipient_pub_b)

    recipient_domain_priv_b = bytes([0xB2] * 32)
    recipient_domain_pub_b = x25519_pubkey_from_priv(recipient_domain_priv_b)
    recipient_domain_fp_b = fingerprint_hex(recipient_domain_pub_b)

    eph_priv_baseline = {
        "brief_for_client": bytes([0xC1] * 32),
        "brief_for_domain": bytes([0xC2] * 32),
        "enclosure_for_client": bytes([0xC3] * 32),
    }

    def baseline_wrap(K, rcp_pub, slot):
        return seal_wrap_baseline(K, rcp_pub, eph_priv_baseline[slot])

    def baseline_unwrap(b64, priv, pub):
        return seal_unwrap_baseline(b64, priv, pub)

    K_brief_b = bytes([0xD1] * 32)
    K_enclosure_b = bytes([0xD2] * 32)
    brief_nonce_b = bytes([0xE1] * 12)
    enclosure_nonce_b = bytes([0xE2] * 12)
    K_env_mac_b = bytes([0xF1] * 32)

    brief_b = {
        "message_id": "msg-2026-05-08-0001",
        "from": "alice@a.example",
        "to": ["bob@b.example"],
        "sent_at": "2026-05-08T09:00:00Z",
    }
    enclosure_pre_sign_b = {
        "subject": "Round-trip vector check",
        "content_type": "text/plain",
        "body": {
            "text/plain": "SGVsbG8gQm9iLCB0aGlzIGlzIGEgcm91bmQtdHJpcCB2ZWN0b3IuIC0tIEFsaWNl",
        },
        "attachments": [],
        "forwarded_from": None,
        "extensions": {},
        "sender_signature": {
            "algorithm": "ed25519",
            "key_id": "",
            "value": "",
        },
    }

    baseline_vector_data, _ = _compose_envelope_vector(
        suite_id="x25519-chacha20-poly1305",
        sender_identity_seed=sender_identity_seed_b,
        sender_domain_seed=sender_domain_seed_b,
        K_brief=K_brief_b,
        K_enclosure=K_enclosure_b,
        brief_nonce=brief_nonce_b,
        enclosure_nonce=enclosure_nonce_b,
        K_env_mac=K_env_mac_b,
        postmark_id="01J7TESTPOSTMARKIDXXXXXXXXXX",
        session_id="01J7TESTSESSIONIDXXXXXXXXXXX",
        brief_obj=brief_b,
        enclosure_obj_pre_sign=enclosure_pre_sign_b,
        recipient_client_pub=recipient_pub_b,
        recipient_client_priv=recipient_priv_b,
        recipient_client_fp=recipient_fp_b,
        recipient_domain_pub=recipient_domain_pub_b,
        recipient_domain_priv=recipient_domain_priv_b,
        recipient_domain_fp=recipient_domain_fp_b,
        wrap_fn=baseline_wrap,
        unwrap_fn=baseline_unwrap,
        extra_inputs={
            "recipient_client_priv_hex": recipient_priv_b.hex(),
            "recipient_server_domain_priv_hex": recipient_domain_priv_b.hex(),
            "ephemeral_priv_brief_for_client_hex": eph_priv_baseline["brief_for_client"].hex(),
            "ephemeral_priv_brief_for_domain_hex": eph_priv_baseline["brief_for_domain"].hex(),
            "ephemeral_priv_enclosure_for_client_hex": eph_priv_baseline["enclosure_for_client"].hex(),
        },
    )
    baseline_vector = {
        "id": "envelope-roundtrip-baseline-single-recipient",
        "description": (
            "End-to-end compose for a single-recipient envelope under the "
            "baseline suite (x25519-chacha20-poly1305): brief is wrapped "
            "for both the recipient server domain and the recipient client; "
            "enclosure is wrapped for the recipient client only. The vector "
            "pins every random input and records the final envelope JSON; "
            "round-trip verification is asserted at generation time across "
            "all seven §7.2 steps."
        ),
        "spec_reference": "VECTORS.md §17.4; ENVELOPE.md §7.1, §7.1.1, §7.2",
        **baseline_vector_data,
    }

    # --- PQ suite (pq-kyber768-x25519) ---------------------------------------
    sender_identity_seed_p = bytes([0xA3] * 32)
    sender_domain_seed_p = bytes([0xA4] * 32)

    rcp_kyber_d = bytes([0xB3] * 32)
    rcp_kyber_z = bytes([0xB4] * 32)
    rcp_x25519_priv = bytes([0xB5] * 32)
    rcp_kyber_ek, rcp_kyber_dk = kyber768_keygen_internal(rcp_kyber_d, rcp_kyber_z)
    rcp_x25519_pub = x25519_pubkey_from_priv(rcp_x25519_priv)
    recipient_pub_p = rcp_kyber_ek + rcp_x25519_pub
    recipient_priv_p = rcp_kyber_dk + rcp_x25519_priv
    recipient_fp_p = fingerprint_hex(recipient_pub_p)

    rcp_dom_kyber_d = bytes([0xB6] * 32)
    rcp_dom_kyber_z = bytes([0xB7] * 32)
    rcp_dom_x25519_priv = bytes([0xB8] * 32)
    rcp_dom_kyber_ek, rcp_dom_kyber_dk = kyber768_keygen_internal(
        rcp_dom_kyber_d, rcp_dom_kyber_z
    )
    rcp_dom_x25519_pub = x25519_pubkey_from_priv(rcp_dom_x25519_priv)
    recipient_domain_pub_p = rcp_dom_kyber_ek + rcp_dom_x25519_pub
    recipient_domain_priv_p = rcp_dom_kyber_dk + rcp_dom_x25519_priv
    recipient_domain_fp_p = fingerprint_hex(recipient_domain_pub_p)

    eph_x25519_pq = {
        "brief_for_client": bytes([0xC4] * 32),
        "brief_for_domain": bytes([0xC5] * 32),
        "enclosure_for_client": bytes([0xC6] * 32),
    }
    kyber_m_pq = {
        "brief_for_client": bytes([0xC7] * 32),
        "brief_for_domain": bytes([0xC8] * 32),
        "enclosure_for_client": bytes([0xC9] * 32),
    }

    def pq_wrap(K, rcp_pub, slot):
        return seal_wrap_pq(K, rcp_pub, eph_x25519_pq[slot], kyber_m_pq[slot])

    def pq_unwrap(b64, priv, pub):
        return seal_unwrap_pq(b64, priv, pub)

    K_brief_p = bytes([0xD3] * 32)
    K_enclosure_p = bytes([0xD4] * 32)
    brief_nonce_p = bytes([0xE3] * 12)
    enclosure_nonce_p = bytes([0xE4] * 12)
    K_env_mac_p = bytes([0xF2] * 32)

    pq_vector_data, _ = _compose_envelope_vector(
        suite_id="pq-kyber768-x25519",
        sender_identity_seed=sender_identity_seed_p,
        sender_domain_seed=sender_domain_seed_p,
        K_brief=K_brief_p,
        K_enclosure=K_enclosure_p,
        brief_nonce=brief_nonce_p,
        enclosure_nonce=enclosure_nonce_p,
        K_env_mac=K_env_mac_p,
        postmark_id="01J7PQPOSTMARKIDXXXXXXXXXXXX",
        session_id="01J7PQSESSIONIDXXXXXXXXXXXXX",
        brief_obj=brief_b,
        enclosure_obj_pre_sign=enclosure_pre_sign_b,
        recipient_client_pub=recipient_pub_p,
        recipient_client_priv=recipient_priv_p,
        recipient_client_fp=recipient_fp_p,
        recipient_domain_pub=recipient_domain_pub_p,
        recipient_domain_priv=recipient_domain_priv_p,
        recipient_domain_fp=recipient_domain_fp_p,
        wrap_fn=pq_wrap,
        unwrap_fn=pq_unwrap,
        extra_inputs={
            "recipient_client_kyber_keygen_d_hex": rcp_kyber_d.hex(),
            "recipient_client_kyber_keygen_z_hex": rcp_kyber_z.hex(),
            "recipient_client_x25519_priv_hex": rcp_x25519_priv.hex(),
            "recipient_server_domain_kyber_keygen_d_hex": rcp_dom_kyber_d.hex(),
            "recipient_server_domain_kyber_keygen_z_hex": rcp_dom_kyber_z.hex(),
            "recipient_server_domain_x25519_priv_hex": rcp_dom_x25519_priv.hex(),
            "ephemeral_x25519_priv_brief_for_client_hex": eph_x25519_pq["brief_for_client"].hex(),
            "ephemeral_x25519_priv_brief_for_domain_hex": eph_x25519_pq["brief_for_domain"].hex(),
            "ephemeral_x25519_priv_enclosure_for_client_hex": eph_x25519_pq["enclosure_for_client"].hex(),
            "kyber_encaps_m_brief_for_client_hex": kyber_m_pq["brief_for_client"].hex(),
            "kyber_encaps_m_brief_for_domain_hex": kyber_m_pq["brief_for_domain"].hex(),
            "kyber_encaps_m_enclosure_for_client_hex": kyber_m_pq["enclosure_for_client"].hex(),
        },
    )
    pq_vector = {
        "id": "envelope-roundtrip-pq-single-recipient",
        "description": (
            "End-to-end compose for a single-recipient envelope under the "
            "post-quantum suite (pq-kyber768-x25519): seal wraps use the "
            "hybrid Kyber768+X25519 KEM per ENVELOPE.md §4.4.1 PQ branch; "
            "brief and enclosure AEAD are still ChaCha20-Poly1305 per §7.3. "
            "Recipient public keys are the 1216-byte hybrid concatenation; "
            "recipient private keys are the 2432-byte concatenation. All "
            "X25519 ephemerals and Kyber encaps randomness (m) are pinned "
            "so the wrapped seal entries are byte-deterministic."
        ),
        "spec_reference": "VECTORS.md §17.4; ENVELOPE.md §4.4.1, §7.1, §7.1.1, §7.2",
        **pq_vector_data,
    }

    return {
        "version": "1.0.0",
        "category": "envelope-roundtrip",
        "description": (
            "Layer 3 round-trip vectors covering the full ENVELOPE.md §7.1 "
            "compose flow and §7.2 verification path. Every random input "
            "(symmetric keys, nonces, ephemerals, Kyber encaps randomness) "
            "is pinned so the final envelope JSON is byte-deterministic. "
            "Both currently-defined suites are exercised."
        ),
        "spec_reference": "VECTORS.md §17.4; ENVELOPE.md §4, §6.5, §7.1, §7.1.1, §7.2",
        "construction": {
            "seal_signature_prefix_utf8": "SEMP-ENVELOPE:",
            "session_mac_algorithm": "HMAC-SHA-256",
            "brief_aead": "ChaCha20-Poly1305(K_brief, brief_nonce, canonical_brief_json, aad=postmark.id)",
            "enclosure_aead": "ChaCha20-Poly1305(K_enclosure, enclosure_nonce, canonical_enclosure_json, aad=postmark.id)",
            "envelope_brief_field": "base64(brief_nonce || aead_ct)",
            "envelope_enclosure_field": "base64(enclosure_nonce || aead_ct)",
            "seal_wrap_construction": "ENVELOPE.md §4.4.1 (see seal-roundtrip.json)",
            "sender_signature_construction": "ENVELOPE.md §6.5 (see sender-signature.json)",
        },
        "suites_covered": [
            "x25519-chacha20-poly1305",
            "pq-kyber768-x25519",
        ],
        "vectors": [baseline_vector, pq_vector],
    }


# ---- Large-attachment vectors (Layer 3, ATTACHMENTS.md §3) ------------------


ATTACHMENT_KDF_INFO_PREFIX = b"semp-attachment:"


def derive_K_attachment(K_enclosure: bytes, attachment_id: str, length: int = 32) -> bytes:
    """ATTACHMENTS.md §3.1: K_attachment = HKDF-Expand(PRK=K_enclosure,
    info='semp-attachment:' || attachment_id, L=length).

    Note: ATTACHMENTS.md §3.1 uses HKDF-Expand directly with K_enclosure
    serving as the PRK (already 32 high-entropy bytes from the seal layer);
    no Extract step is needed for an already-uniform input.
    """
    info = ATTACHMENT_KDF_INFO_PREFIX + attachment_id.encode("utf-8")
    return hkdf_expand(K_enclosure, info, length)


def attachment_aad(item: dict) -> bytes:
    """ATTACHMENTS.md §3.2: AEAD AAD is the canonical JSON of the item with
    ciphertext_hash, aead_nonce, and extensions blanked."""
    blanked = copy.deepcopy(item)
    blanked["ciphertext_hash"] = ""
    blanked["aead_nonce"] = ""
    blanked["extensions"] = {}
    return canonical_json(blanked)


def build_large_attachment_json() -> dict:
    """Three vectors covering: valid round-trip, metadata tamper (AEAD AAD
    mismatch), and ciphertext tamper (hash + AEAD both fail)."""
    import base64

    # Pinned K_enclosure (would normally come from the envelope's seal).
    K_enclosure = bytes([0xE5] * 32)
    attachment_id = "01J7ATTACHMENTIDXXXXXXXXXXXX"
    K_attachment = derive_K_attachment(K_enclosure, attachment_id)

    # Pinned plaintext and nonce.
    plaintext = b"This is a synthetic 64-byte plaintext used as a vector input."
    plaintext = plaintext + b"\x00" * (64 - len(plaintext))
    aead_nonce = bytes([0xE6] * 12)

    # Build the item BEFORE encryption to compute the AEAD AAD.
    item_template = {
        "id": attachment_id,
        "filename": "memo.txt",
        "mime_type": "text/plain",
        "plaintext_size": len(plaintext),
        "url": "https://blobs.example.com/a/01J7ATTACHMENTIDXXXXXXXXXXXX",
        "ciphertext_hash": "",   # set after encryption
        "aead_algorithm": "chacha20-poly1305",
        "aead_nonce": "",        # set after encryption
        "extensions": {},
    }
    aad = attachment_aad(item_template)
    aead_ct = chacha20_poly1305_seal(K_attachment, aead_nonce, plaintext, aad)
    ct_hash_hex = hashlib.sha256(aead_ct).hexdigest()

    item_final = copy.deepcopy(item_template)
    item_final["ciphertext_hash"] = "sha256:" + ct_hash_hex
    item_final["aead_nonce"] = base64.b64encode(aead_nonce).decode("ascii")

    # Round-trip sanity.
    aad_decrypt = attachment_aad(item_final)  # blanks ct_hash + nonce again
    recovered = chacha20_poly1305_open(K_attachment, aead_nonce, aead_ct, aad_decrypt)
    assert recovered == plaintext

    # Vector 1: valid.
    valid_vector = {
        "id": "large-attachment-baseline-valid",
        "description": (
            "Round-trip encrypt + decrypt of a 64-byte plaintext under "
            "K_attachment derived from a pinned K_enclosure and the item "
            "id. Both the SHA-256 ciphertext_hash and the AEAD authentication "
            "tag MUST verify on decrypt."
        ),
        "spec_reference": "VECTORS.md §17.6; ATTACHMENTS.md §3",
        "inputs": {
            "K_enclosure_hex": K_enclosure.hex(),
            "attachment_id": attachment_id,
            "plaintext_hex": plaintext.hex(),
            "aead_nonce_hex": aead_nonce.hex(),
            "item_pre_encrypt_template": item_template,
        },
        "intermediates": {
            "kdf_info_utf8": ATTACHMENT_KDF_INFO_PREFIX.decode("utf-8") + attachment_id,
            "K_attachment_hex": K_attachment.hex(),
            "canonical_aad_utf8": aad.decode("utf-8"),
            "aead_ct_hex": aead_ct.hex(),
            "ct_sha256_hex": ct_hash_hex,
        },
        "expected": {
            "item_final_json": item_final,
            "ciphertext_at_url_hex": aead_ct.hex(),
            "round_trip_recovers_plaintext": True,
        },
    }

    # Vector 2: tampered metadata. The verifier holds a modified item
    # (e.g. a different filename), so the recomputed AAD differs and
    # AEAD verify rejects.
    item_tampered_meta = copy.deepcopy(item_final)
    item_tampered_meta["filename"] = "renamed.txt"  # attacker swap
    aad_tampered = attachment_aad(item_tampered_meta)
    try:
        chacha20_poly1305_open(K_attachment, aead_nonce, aead_ct, aad_tampered)
        meta_decrypts = True
    except Exception:
        meta_decrypts = False
    assert not meta_decrypts

    tampered_meta_vector = {
        "id": "large-attachment-tampered-metadata",
        "description": (
            "Take the valid output and change item.filename. The recomputed "
            "AEAD AAD differs from the AAD used at encryption time, so the "
            "Poly1305 tag fails to verify and decryption rejects. "
            "Demonstrates the §3.2 metadata binding."
        ),
        "spec_reference": "VECTORS.md §17.6; ATTACHMENTS.md §3.2",
        "inputs": {
            "tampered_item_json": item_tampered_meta,
            "ciphertext_at_url_hex": aead_ct.hex(),
            "K_attachment_hex": K_attachment.hex(),
            "aead_nonce_hex": aead_nonce.hex(),
        },
        "intermediates": {
            "tampered_canonical_aad_utf8": aad_tampered.decode("utf-8"),
            "original_canonical_aad_utf8": aad.decode("utf-8"),
        },
        "expected": {
            "decryption_succeeds": meta_decrypts,
            "rejection_reason": (
                "AEAD AAD mismatch: filename was bound at encryption time "
                "and any subsequent change invalidates the tag"
            ),
        },
    }

    # Vector 3: tampered ciphertext. Flipping any byte of aead_ct triggers
    # both a SHA-256 hash mismatch (item.ciphertext_hash) AND an AEAD tag
    # failure on decrypt.
    aead_ct_tampered = bytearray(aead_ct)
    aead_ct_tampered[10] ^= 0x01  # flip one bit
    aead_ct_tampered = bytes(aead_ct_tampered)
    tampered_hash_hex = hashlib.sha256(aead_ct_tampered).hexdigest()
    hash_matches = ("sha256:" + tampered_hash_hex) == item_final["ciphertext_hash"]
    try:
        chacha20_poly1305_open(K_attachment, aead_nonce, aead_ct_tampered, aad)
        aead_succeeds = True
    except Exception:
        aead_succeeds = False
    assert not aead_succeeds
    assert not hash_matches

    tampered_ct_vector = {
        "id": "large-attachment-tampered-ciphertext",
        "description": (
            "Flip one bit of the ciphertext stored at item.url. Two "
            "independent integrity layers reject: (a) SHA-256(ciphertext) "
            "no longer equals item.ciphertext_hash, surfaced before "
            "decryption attempts; (b) the Poly1305 tag fails to verify on "
            "AEAD.Open. A receiver SHOULD short-circuit on (a) to avoid "
            "feeding adversarial input to the AEAD."
        ),
        "spec_reference": "VECTORS.md §17.6; ATTACHMENTS.md §3, §6",
        "inputs": {
            "item_json": item_final,
            "tampered_ciphertext_hex": aead_ct_tampered.hex(),
            "K_attachment_hex": K_attachment.hex(),
            "aead_nonce_hex": aead_nonce.hex(),
        },
        "intermediates": {
            "tampered_ciphertext_sha256_hex": tampered_hash_hex,
            "expected_ciphertext_hash_field": item_final["ciphertext_hash"],
        },
        "expected": {
            "ciphertext_hash_matches": hash_matches,
            "aead_decryption_succeeds": aead_succeeds,
            "rejection_reason": "ciphertext integrity check fails before AEAD; AEAD also rejects",
        },
    }

    # ---- PQ suite (XChaCha20-Poly1305) --------------------------------------

    K_enclosure_p = bytes([0xF5] * 32)
    attachment_id_p = "01J7PQATTACHMENTIDXXXXXXXXXX"
    K_attachment_p = derive_K_attachment(K_enclosure_p, attachment_id_p)

    plaintext_p = b"PQ suite XChaCha20-Poly1305 large-attachment vector input."
    plaintext_p = plaintext_p + b"\x00" * (64 - len(plaintext_p))
    aead_nonce_p = bytes([0xF6] * 24)  # 24 bytes for XChaCha20-Poly1305

    item_template_p = {
        "id": attachment_id_p,
        "filename": "presentation.pdf",
        "mime_type": "application/pdf",
        "plaintext_size": len(plaintext_p),
        "url": "https://blobs.example.com/a/01J7PQATTACHMENTIDXXXXXXXXXX",
        "ciphertext_hash": "",
        "aead_algorithm": "xchacha20-poly1305",
        "aead_nonce": "",
        "extensions": {},
    }
    aad_p = attachment_aad(item_template_p)
    aead_ct_p = xchacha20_poly1305_seal(K_attachment_p, aead_nonce_p, plaintext_p, aad_p)
    ct_hash_hex_p = hashlib.sha256(aead_ct_p).hexdigest()

    item_final_p = copy.deepcopy(item_template_p)
    item_final_p["ciphertext_hash"] = "sha256:" + ct_hash_hex_p
    item_final_p["aead_nonce"] = base64.b64encode(aead_nonce_p).decode("ascii")

    # Round-trip sanity.
    aad_decrypt_p = attachment_aad(item_final_p)
    recovered_p = xchacha20_poly1305_open(
        K_attachment_p, aead_nonce_p, aead_ct_p, aad_decrypt_p
    )
    assert recovered_p == plaintext_p

    pq_vector = {
        "id": "large-attachment-pq-valid",
        "description": (
            "Round-trip encrypt + decrypt of a 64-byte plaintext under "
            "K_attachment derived from a pinned K_enclosure for the "
            "post-quantum suite. The AEAD is XChaCha20-Poly1305 with a "
            "24-byte nonce per ATTACHMENTS.md §3.2. Construction is "
            "otherwise identical to the baseline case (same KDF, same "
            "metadata-bound AAD, same SHA-256 integrity check)."
        ),
        "spec_reference": "VECTORS.md §17.6; ATTACHMENTS.md §3.2",
        "inputs": {
            "K_enclosure_hex": K_enclosure_p.hex(),
            "attachment_id": attachment_id_p,
            "plaintext_hex": plaintext_p.hex(),
            "aead_nonce_hex": aead_nonce_p.hex(),
            "item_pre_encrypt_template": item_template_p,
        },
        "intermediates": {
            "kdf_info_utf8": ATTACHMENT_KDF_INFO_PREFIX.decode("utf-8") + attachment_id_p,
            "K_attachment_hex": K_attachment_p.hex(),
            "canonical_aad_utf8": aad_p.decode("utf-8"),
            "aead_ct_hex": aead_ct_p.hex(),
            "ct_sha256_hex": ct_hash_hex_p,
        },
        "expected": {
            "item_final_json": item_final_p,
            "ciphertext_at_url_hex": aead_ct_p.hex(),
            "round_trip_recovers_plaintext": True,
        },
    }

    return {
        "version": "1.0.0",
        "category": "large-attachment",
        "description": (
            "Layer 3 vectors for the large-attachment extension "
            "(semp.dev/large-attachment) per ATTACHMENTS.md §3: per-item "
            "key derivation from K_enclosure, AEAD with metadata bound as "
            "AAD, and SHA-256 integrity check on the ciphertext stored at "
            "item.url."
        ),
        "spec_reference": "VECTORS.md §17.6; ATTACHMENTS.md §3",
        "construction": {
            "key_derivation": (
                "K_attachment = HKDF-Expand(PRK=K_enclosure, "
                "info='semp-attachment:' || attachment_id, L=32). "
                "K_enclosure already has full entropy from the seal layer, "
                "so no Extract step is needed."
            ),
            "aead_baseline": "ChaCha20-Poly1305, 12-byte nonce (suite x25519-chacha20-poly1305)",
            "aead_pq": "XChaCha20-Poly1305, 24-byte nonce (suite pq-kyber768-x25519)",
            "aead_aad": (
                "Canonical JSON of the item with ciphertext_hash, "
                "aead_nonce, and extensions blanked. Binds filename, "
                "mime_type, plaintext_size, url, aead_algorithm, and id "
                "into the tag so an attacker cannot swap them."
            ),
            "ciphertext_at_url": "raw aead_ct (ciphertext || tag), no framing",
            "ciphertext_hash_format": "sha256:<hex of SHA-256(aead_ct)>",
        },
        "suites_covered": [
            "x25519-chacha20-poly1305 (ChaCha20-Poly1305, 12-byte nonce)",
            "pq-kyber768-x25519 (XChaCha20-Poly1305, 24-byte nonce)",
        ],
        "vectors": [valid_vector, tampered_meta_vector, tampered_ct_vector, pq_vector],
    }


# ---- Delivery-receipt vectors (Layer 3, DELIVERY.md §1.1.1) -----------------


DELIVERY_RECEIPT_PREFIX = b"SEMP-DELIVERY-RECEIPT:"


def receipt_canonical(receipt: dict) -> bytes:
    r = copy.deepcopy(receipt)
    if "signature" not in r:
        raise ValueError("receipt missing signature block")
    r["signature"]["value"] = ""
    return canonical_json(r)


def receipt_compute(receipt: dict, domain_priv: bytes) -> tuple[dict, dict]:
    canonical = receipt_canonical(receipt)
    prefixed = DELIVERY_RECEIPT_PREFIX + canonical
    sig = ed25519_sign(domain_priv, prefixed)

    import base64

    signed = copy.deepcopy(receipt)
    signed["signature"]["value"] = base64.b64encode(sig).decode("ascii")

    inter = {
        "canonical_receipt_with_blanked_signature_utf8": canonical.decode("utf-8"),
        "signing_input_prefix_utf8": DELIVERY_RECEIPT_PREFIX.decode("utf-8"),
        "signing_input_hex": prefixed.hex(),
        "signature_hex": sig.hex(),
    }
    return signed, inter


def receipt_verify(signed_receipt: dict, domain_pub: bytes) -> bool:
    import base64

    sig_b64 = signed_receipt["signature"]["value"]
    sig = base64.b64decode(sig_b64)
    canonical = receipt_canonical(signed_receipt)
    prefixed = DELIVERY_RECEIPT_PREFIX + canonical
    return ed25519_verify(domain_pub, sig, prefixed)


def build_delivery_receipt_json() -> dict:
    """Three vectors for DELIVERY.md §1.1.1: valid receipt, tampered
    envelope (envelope_hash mismatches recomputation), tampered receipt
    body (Ed25519 verify fails)."""

    # Recipient domain signing key.
    domain_seed = bytes([0xC1] * 32)
    domain_pub = ed25519_pubkey_from_priv(domain_seed)
    domain_fp = fingerprint_hex(domain_pub)

    # Pin a small reference envelope. We don't need to fully encrypt it for
    # the receipt — we just need its canonical bytes for the SHA-256 digest.
    # The envelope below has all the §4.3 canonicalization corner cases
    # (sorted keys, blanked signature/session_mac, padding/hop_count
    # omitted) covered by canonical_envelope.
    reference_envelope = {
        "type": "SEMP_ENVELOPE",
        "version": "1.0.0",
        "postmark": {
            "id": "01J7RECEIPTPOSTMARKXXXXXXXXX",
            "session_id": "01J7RECEIPTSESSIONXXXXXXXXXX",
            "from_domain": "alice.example",
            "to_domain": "bob.example",
            "expires": "2026-04-22T00:00:00Z",
            "extensions": {},
        },
        "seal": {
            "algorithm": "x25519-chacha20-poly1305",
            "key_id": "alice-domain-fp",
            "signature": "EXAMPLE_SIGNATURE",
            "session_mac": "EXAMPLE_SESSION_MAC",
            "brief_recipients": {"bob-fp": "WRAPPED_K_BRIEF"},
            "enclosure_recipients": {"bob-fp": "WRAPPED_K_ENCLOSURE"},
            "extensions": {},
        },
        "brief": "BRIEF_CIPHERTEXT_PLACEHOLDER",
        "enclosure": "ENCLOSURE_CIPHERTEXT_PLACEHOLDER",
    }

    canonical_env_bytes = envelope_canonical_for_signature(reference_envelope)
    envelope_digest = sha256(canonical_env_bytes)

    import base64

    receipt_pre_sign = {
        "type": "SEMP_DELIVERY_RECEIPT",
        "version": "1.0.0",
        "envelope_hash": {
            "algorithm": "sha-256",
            "value": base64.b64encode(envelope_digest).decode("ascii"),
        },
        "recipient_domain": "bob.example",
        "accepted_at": "2026-04-21T10:15:32Z",
        "signature": {
            "algorithm": "ed25519",
            "key_id": domain_fp,
            "value": "",
        },
    }

    # Case 1: valid receipt.
    receipt_signed, inter_valid = receipt_compute(receipt_pre_sign, domain_seed)
    assert receipt_verify(receipt_signed, domain_pub)

    # Case 2: tampered envelope. Compute the receipt over the original
    # envelope's hash; the verifier holding a tampered envelope recomputes a
    # different SHA-256 and the §1.1.1.7 step 4 comparison fails. The
    # signature itself still verifies because the receipt body is unchanged.
    tampered_envelope = copy.deepcopy(reference_envelope)
    tampered_envelope["postmark"]["from_domain"] = "mallory.example"  # forged
    tampered_canonical = envelope_canonical_for_signature(tampered_envelope)
    tampered_digest = sha256(tampered_canonical)
    digest_matches = tampered_digest == envelope_digest

    # Case 3: tampered receipt body. Take the valid signed receipt, change
    # `accepted_at` post-hoc, and try to verify. Ed25519 verify rejects.
    tampered_receipt = copy.deepcopy(receipt_signed)
    tampered_receipt["accepted_at"] = "2026-04-21T10:15:33Z"  # one second later
    receipt_verifies_after_tamper = receipt_verify(tampered_receipt, domain_pub)
    assert not receipt_verifies_after_tamper

    return {
        "version": "1.0.0",
        "category": "delivery-receipt",
        "description": (
            "Layer 3 vectors for DELIVERY.md §1.1.1: signed delivery "
            "receipts. The receipt binds (envelope_hash, recipient_domain, "
            "accepted_at) under the recipient domain's Ed25519 signing key "
            "with the SEMP-DELIVERY-RECEIPT: domain-separation prefix."
        ),
        "spec_reference": "VECTORS.md §17.5; DELIVERY.md §1.1.1",
        "construction": {
            "envelope_hash_algorithm": "SHA-256",
            "envelope_hash_input": "canonical envelope bytes per ENVELOPE.md §4.3",
            "signature_algorithm": "Ed25519",
            "domain_separation_prefix_utf8": "SEMP-DELIVERY-RECEIPT:",
            "canonical_form": (
                "Per ENVELOPE.md §4.3: sorted keys at every nesting level, "
                "no insignificant whitespace, UTF-8 encoding. Apply with "
                "receipt.signature.value set to \"\"."
            ),
            "signing_input": "prefix || canonical_receipt_bytes",
            "key_id_construction": "SHA-256(public_key) lowercase hex per KEY.md §4.4",
        },
        "vectors": [
            {
                "id": "delivery-receipt-valid",
                "description": (
                    "Pinned recipient domain key signs a receipt over the "
                    "pinned reference envelope. Both the envelope_hash "
                    "comparison (step 4 of §1.1.1.7) and the Ed25519 "
                    "signature verification (step 3) succeed."
                ),
                "spec_reference": "VECTORS.md §17.5; DELIVERY.md §1.1.1.4, §1.1.1.7",
                "inputs": {
                    "recipient_domain_seed_hex": domain_seed.hex(),
                    "recipient_domain_pub_hex": domain_pub.hex(),
                    "recipient_domain_key_id": domain_fp,
                    "reference_envelope_json": reference_envelope,
                    "receipt_pre_sign_json": receipt_pre_sign,
                },
                "intermediates": {
                    "canonical_envelope_for_hash_utf8": canonical_env_bytes.decode("utf-8"),
                    "envelope_hash_hex": envelope_digest.hex(),
                    **inter_valid,
                },
                "expected": {
                    "signed_receipt_json": receipt_signed,
                    "signature_b64": receipt_signed["signature"]["value"],
                    "signature_verifies": True,
                    "envelope_hash_matches_recomputation": True,
                },
            },
            {
                "id": "delivery-receipt-tampered-envelope",
                "description": (
                    "The receipt is genuine (signature still verifies) but "
                    "the envelope has been altered. A verifier holding both "
                    "the receipt and the tampered envelope recomputes a "
                    "SHA-256 that differs from receipt.envelope_hash.value, "
                    "so the §1.1.1.7 step 4 comparison fails. The receipt "
                    "MUST NOT be treated as proof for this envelope."
                ),
                "spec_reference": "VECTORS.md §17.5; DELIVERY.md §1.1.1.7",
                "inputs": {
                    "signed_receipt_json": receipt_signed,
                    "tampered_envelope_json": tampered_envelope,
                    "recipient_domain_pub_hex": domain_pub.hex(),
                },
                "intermediates": {
                    "tampered_canonical_envelope_utf8": tampered_canonical.decode("utf-8"),
                    "tampered_envelope_hash_hex": tampered_digest.hex(),
                    "receipt_envelope_hash_hex": envelope_digest.hex(),
                },
                "expected": {
                    "receipt_signature_still_verifies": True,
                    "envelope_hash_matches_recomputation": digest_matches,
                    "rejection_reason": (
                        "envelope_hash mismatch: receipt was issued for a "
                        "different envelope than the one being inspected"
                    ),
                },
            },
            {
                "id": "delivery-receipt-tampered-body",
                "description": (
                    "Take the valid signed receipt and change accepted_at "
                    "by one second. The reconstructed canonical bytes differ "
                    "from what was signed, so Ed25519 verify rejects. "
                    "Demonstrates that every receipt field other than "
                    "signature.value is bound by the signature."
                ),
                "spec_reference": "VECTORS.md §17.5; DELIVERY.md §1.1.1.4",
                "inputs": {
                    "tampered_receipt_json": tampered_receipt,
                    "recipient_domain_pub_hex": domain_pub.hex(),
                },
                "expected": {
                    "signature_verifies": receipt_verifies_after_tamper,
                    "rejection_reason": (
                        "receipt body altered post-signing; canonical bytes "
                        "no longer match the signed input"
                    ),
                },
            },
        ],
    }


# ---- Forwarding vectors (Layer 3, ENVELOPE.md §6.6) -------------------------


FORWARDER_ATTESTATION_PREFIX = b"SEMP-FORWARDER-ATTESTATION:"


def forwarder_attestation_canonical(forwarded_from: dict) -> bytes:
    """Per ENVELOPE.md §6.6.3: canonical JSON of the forwarded_from object
    with forwarder_attestation.value set to "".
    """
    f = copy.deepcopy(forwarded_from)
    if "forwarder_attestation" not in f:
        raise ValueError("forwarded_from missing forwarder_attestation block")
    f["forwarder_attestation"]["value"] = ""
    return canonical_json(f)


def forwarder_attestation_compute(
    forwarded_from: dict, forwarder_priv: bytes
) -> tuple[dict, dict]:
    canonical = forwarder_attestation_canonical(forwarded_from)
    prefixed = FORWARDER_ATTESTATION_PREFIX + canonical
    sig = ed25519_sign(forwarder_priv, prefixed)

    import base64

    signed = copy.deepcopy(forwarded_from)
    signed["forwarder_attestation"]["value"] = base64.b64encode(sig).decode("ascii")

    inter = {
        "canonical_forwarded_from_with_blanked_attestation_utf8": canonical.decode("utf-8"),
        "signing_input_prefix_utf8": FORWARDER_ATTESTATION_PREFIX.decode("utf-8"),
        "signing_input_hex": prefixed.hex(),
        "signature_hex": sig.hex(),
    }
    return signed, inter


def forwarder_attestation_verify(
    forwarded_from: dict, forwarder_pub: bytes
) -> bool:
    import base64

    sig_b64 = forwarded_from["forwarder_attestation"]["value"]
    sig = base64.b64decode(sig_b64)
    canonical = forwarder_attestation_canonical(forwarded_from)
    prefixed = FORWARDER_ATTESTATION_PREFIX + canonical
    return ed25519_verify(forwarder_pub, sig, prefixed)


def build_forwarding_json() -> dict:
    """Forwarded envelope vectors per ENVELOPE.md §6.6.

    A forward composes a fresh outer envelope addressed to the new
    recipient. The outer enclosure carries:
      - The forwarder's own subject/body (their commentary).
      - A `forwarded_from` block containing the original sender's
        decrypted enclosure (with the original sender_signature
        preserved verbatim) plus the forwarder's attestation.
      - The forwarder's outer sender_signature.

    Verification by the new recipient is a three-step chain
    (§6.6.4):
      1. outer enclosure.sender_signature  -> authenticates forwarder
      2. forwarded_from.forwarder_attestation -> authenticates forwarding act
      3. forwarded_from.original_enclosure_plaintext.sender_signature
         -> authenticates original sender
    """
    # Identity A: original sender (alice@a.example).
    seed_a = bytes([0x11] * 32)
    pub_a = ed25519_pubkey_from_priv(seed_a)
    fp_a = fingerprint_hex(pub_a)

    # Identity B: forwarder (bob@b.example).
    seed_b = bytes([0x22] * 32)
    pub_b = ed25519_pubkey_from_priv(seed_b)
    fp_b = fingerprint_hex(pub_b)

    # Build the original enclosure A composed and signed (this is what A
    # originally sent to B).
    original_enclosure_pre_sign = {
        "subject": "Lunch on Friday?",
        "content_type": "text/plain",
        "body": {
            "text/plain": "SGV5IEJvYiwgYXJlIHlvdSBhcm91bmQgRnJpZGF5PyAtLSBBbGljZQ==",
        },
        "attachments": [],
        "forwarded_from": None,
        "extensions": {},
        "sender_signature": {
            "algorithm": "ed25519",
            "key_id": fp_a,
            "value": "",
        },
    }
    original_signed, _ = sender_signature_compute(original_enclosure_pre_sign, seed_a)
    assert sender_signature_verify(original_signed, pub_a)

    # Build the forwarded_from block. B is forwarding A's message to C.
    forwarded_from_pre_sign = {
        "original_enclosure_plaintext": original_signed,
        "original_seal": {
            "algorithm": "x25519-chacha20-poly1305",
            "key_id": "alice-domain-key-fp",
        },
        "original_postmark": {
            "id": "01J5ALICE0000000000000000000",
            "from_domain": "a.example",
            "to_domain": "b.example",
            "expires": "2025-06-15T00:00:00Z",
            "session_id": "01J5ALICESESSIONXXXXXXXXXXXX",
        },
        "original_sender_address": "alice@a.example",
        "received_at": "2026-04-15T14:30:00Z",
        "forwarder_attestation": {
            "algorithm": "ed25519",
            "key_id": fp_b,
            "value": "",
        },
    }
    forwarded_signed, inter_attest = forwarder_attestation_compute(
        forwarded_from_pre_sign, seed_b
    )
    assert forwarder_attestation_verify(forwarded_signed, pub_b)

    # Build the outer (new) enclosure that B sends to C, carrying the
    # signed forwarded_from block.
    outer_enclosure_pre_sign = {
        "subject": "Fwd: Lunch on Friday?",
        "content_type": "text/plain",
        "body": {
            "text/plain": "Q2hhcmxpZSwgcGxlYXNlIHNlZSBhdHRhY2hlZCBmcm9tIEFsaWNlLiAtLSBCb2I=",
        },
        "attachments": [],
        "forwarded_from": forwarded_signed,
        "extensions": {},
        "sender_signature": {
            "algorithm": "ed25519",
            "key_id": fp_b,
            "value": "",
        },
    }
    outer_signed, inter_outer = sender_signature_compute(
        outer_enclosure_pre_sign, seed_b
    )
    # Verify the full three-step chain.
    assert sender_signature_verify(outer_signed, pub_b)
    assert forwarder_attestation_verify(outer_signed["forwarded_from"], pub_b)
    assert sender_signature_verify(
        outer_signed["forwarded_from"]["original_enclosure_plaintext"], pub_a
    )

    # Vector 1: full valid chain.
    valid_vector = {
        "id": "forward-valid-three-step-chain",
        "description": (
            "B forwards A's signed enclosure to C. The outer enclosure's "
            "sender_signature authenticates B, the forwarded_from's "
            "forwarder_attestation authenticates the forwarding act, and "
            "the inner original_enclosure_plaintext.sender_signature "
            "authenticates A as the original author. All three checks "
            "MUST pass."
        ),
        "spec_reference": "VECTORS.md §17.3; ENVELOPE.md §6.6.3, §6.6.4",
        "inputs": {
            "original_sender_identity_seed_hex": seed_a.hex(),
            "original_sender_identity_pub_hex": pub_a.hex(),
            "original_sender_key_id": fp_a,
            "original_sender_address": "alice@a.example",
            "forwarder_identity_seed_hex": seed_b.hex(),
            "forwarder_identity_pub_hex": pub_b.hex(),
            "forwarder_key_id": fp_b,
            "forwarder_address": "bob@b.example",
            "received_at": "2026-04-15T14:30:00Z",
        },
        "intermediates": {
            "forwarder_attestation": inter_attest,
            "outer_sender_signature": inter_outer,
        },
        "expected": {
            "outer_enclosure_json": outer_signed,
            "step_1_outer_sender_signature_verifies": True,
            "step_2_forwarder_attestation_verifies": True,
            "step_3_original_sender_signature_verifies": True,
            "key_id_consistency": (
                "forwarded_from.forwarder_attestation.key_id == "
                "outer_enclosure.sender_signature.key_id"
            ),
        },
    }

    # Vector 2: tampered original_enclosure_plaintext.
    # Take the valid outer envelope, modify the original body. The original
    # sender_signature MUST fail; the forwarder_attestation MUST also fail
    # (because it covers the original_enclosure_plaintext as part of the
    # forwarded_from canonicalization).
    tampered_outer = copy.deepcopy(outer_signed)
    tampered_outer["forwarded_from"]["original_enclosure_plaintext"]["body"][
        "text/plain"
    ] = (
        "VEFNUEVSRUQgQk9EWSBJTk5FUkxZIQ=="  # different bytes
    )
    step1_tampered = sender_signature_verify(tampered_outer, pub_b)
    step2_tampered = forwarder_attestation_verify(
        tampered_outer["forwarded_from"], pub_b
    )
    step3_tampered = sender_signature_verify(
        tampered_outer["forwarded_from"]["original_enclosure_plaintext"], pub_a
    )
    # Step 1 still verifies (we only mutated the inner body, not the outer
    # canonical bytes? Actually no — the outer canonicalization includes the
    # forwarded_from contents, so step 1 also fails). Let's assert what we
    # observe rather than what we predict, since the canonical outer bytes
    # cover the inner block too.
    tampered_vector = {
        "id": "forward-tampered-original-content",
        "description": (
            "Take the §17.3/forward-valid-three-step-chain output and alter "
            "one byte of forwarded_from.original_enclosure_plaintext.body. "
            "Multiple checks MUST reject because the outer canonical bytes "
            "and the forwarded_from canonical bytes both cover this region. "
            "The recorded results below show which steps in the §6.6.4 "
            "verification chain fail."
        ),
        "spec_reference": "VECTORS.md §17.3; ENVELOPE.md §6.6.4",
        "inputs": {
            "tampered_outer_enclosure_json": tampered_outer,
            "outer_sender_pub_hex": pub_b.hex(),
            "forwarder_pub_hex": pub_b.hex(),
            "original_sender_pub_hex": pub_a.hex(),
        },
        "expected": {
            "step_1_outer_sender_signature_verifies": step1_tampered,
            "step_2_forwarder_attestation_verifies": step2_tampered,
            "step_3_original_sender_signature_verifies": step3_tampered,
            "any_failure_means_reject": True,
        },
    }

    # Vector 3: forwarder identity mismatch.
    # forwarder_attestation.key_id claims B but the outer sender_signature
    # was actually produced by A (i.e., the outer envelope was signed by
    # someone other than the claimed forwarder). §6.6.3 requires
    # forwarder_attestation.key_id == outer enclosure sender_signature.key_id.
    # We construct: B does the attestation correctly, but A signs the outer.
    outer_signed_by_a_pre = copy.deepcopy(outer_enclosure_pre_sign)
    # Swap the outer sender_signature key_id to claim B (matching attestation)
    # while having A actually sign — this is the spoof we detect.
    outer_signed_by_a_pre["sender_signature"]["key_id"] = fp_b
    outer_signed_by_a, _ = sender_signature_compute(outer_signed_by_a_pre, seed_a)
    # Now sender_signature was produced by A but key_id claims B.
    # Verification against pub_b (the claimed key) MUST fail.
    spoofed_step1 = sender_signature_verify(outer_signed_by_a, pub_b)
    # And the §6.6.3 cross-check (forwarder_attestation.key_id must equal
    # outer sender_signature.key_id) is satisfied syntactically (both claim
    # B), but step 1 still fails because the signature isn't B's.
    mismatch_vector = {
        "id": "forward-spoofed-outer-signer",
        "description": (
            "The outer envelope's sender_signature.key_id claims forwarder "
            "B, and forwarder_attestation.key_id matches B, satisfying the "
            "syntactic cross-check in §6.6.3. But the outer signature was "
            "actually produced by A's private key. Verification of step 1 "
            "(outer sender_signature) against B's public key MUST fail, and "
            "the recipient MUST NOT display the original content as "
            "authored by the claimed sender."
        ),
        "spec_reference": "VECTORS.md §17.3; ENVELOPE.md §6.6.3, §6.6.4",
        "inputs": {
            "spoofed_outer_enclosure_json": outer_signed_by_a,
            "claimed_forwarder_key_id": fp_b,
            "claimed_forwarder_pub_hex": pub_b.hex(),
            "actual_outer_signer_pub_hex": pub_a.hex(),
        },
        "expected": {
            "step_1_outer_sender_signature_verifies_against_claimed_key": spoofed_step1,
            "key_id_syntactic_match": (
                outer_signed_by_a["sender_signature"]["key_id"]
                == outer_signed_by_a["forwarded_from"]["forwarder_attestation"]["key_id"]
            ),
            "rejection_reason": (
                "ed25519 verify of outer sender_signature against the "
                "public key indicated by sender_signature.key_id fails; "
                "the spoofer cannot forge B's signature without B's "
                "private key"
            ),
        },
    }

    return {
        "version": "1.0.0",
        "category": "forwarding",
        "description": (
            "Layer 3 vectors for forwarded envelopes per ENVELOPE.md §6.6: "
            "the three-signature chain (outer sender_signature, "
            "forwarder_attestation, original sender_signature) and the "
            "tamper-detection properties that follow from it."
        ),
        "spec_reference": "VECTORS.md §17.3; ENVELOPE.md §6.6",
        "construction": {
            "forwarder_attestation_prefix_utf8": "SEMP-FORWARDER-ATTESTATION:",
            "outer_sender_signature_prefix_utf8": "SEMP-ENCLOSURE-SENDER:",
            "original_sender_signature_prefix_utf8": "SEMP-ENCLOSURE-SENDER:",
            "canonical_form": (
                "Per ENVELOPE.md §4.3: sorted keys at every nesting level, "
                "no insignificant whitespace, UTF-8 encoding. Apply with "
                "the relevant signature .value field set to \"\"."
            ),
            "verification_order": [
                "1. outer enclosure.sender_signature (§6.5.3) -> forwarder identity",
                "2. forwarded_from.forwarder_attestation (§6.6.3) -> forwarding act",
                "3. forwarded_from.original_enclosure_plaintext.sender_signature (§6.5.3) -> original author",
            ],
        },
        "vectors": [valid_vector, tampered_vector, mismatch_vector],
    }


# ---- Account recovery bundle (Layer 5) -------------------------------------


RECOVERY_BUNDLE_PREFIX = b"SEMP-RECOVERY-BUNDLE:"


def argon2id_kdf(
    secret: bytes, salt: bytes, memory_kb: int, iterations: int, length: int = 32
) -> bytes:
    """RECOVERY.md §2.5: K_bundle = Argon2id(secret, salt, memory, iterations,
    parallelism). PyNaCl wraps libsodium's crypto_pwhash with the
    argon2id13 algorithm (RFC 9106 Argon2id v1.3)."""
    from nacl.pwhash.argon2id import kdf as _kdf

    return _kdf(
        length,
        secret,
        salt,
        opslimit=iterations,
        memlimit=memory_kb * 1024,
    )


def build_account_recovery_json() -> dict:
    """RECOVERY.md §2: backup-bundle round-trip. Argon2id derives K_bundle,
    XChaCha20-Poly1305 encrypts the payload, the user's identity key signs
    the canonical bundle bytes with the SEMP-RECOVERY-BUNDLE: prefix.
    Modest Argon2id parameters chosen so the vector regenerates in a
    fraction of a second; production deployments use the §2.5
    recommendations."""
    import base64

    recovery_secret = b"correct-horse-battery-staple-vector-input"
    salt = bytes([0x81] * 16)
    memory_kb = 65536  # 64 MiB; below the §2.5 RECOMMENDED but enough for vectors
    iterations = 3

    K_bundle = argon2id_kdf(recovery_secret, salt, memory_kb, iterations, 32)

    identity_seed = bytes([0x82] * 32)
    identity_pub = ed25519_pubkey_from_priv(identity_seed)
    identity_fp = fingerprint_hex(identity_pub)

    # Pinned payload. In production this also carries every encryption key
    # the user has ever held; we keep it small for byte determinism.
    payload = {
        "identity_key": {
            "algorithm": "ed25519",
            "public_key": base64.b64encode(identity_pub).decode("ascii"),
            "private_key": base64.b64encode(identity_seed).decode("ascii"),
            "created": "2025-01-15T08:30:00Z",
            "expires": "2026-01-15T08:30:00Z",
        },
        "encryption_keys": [],
        "metadata": {
            "accepted_senders_version": 0,
        },
    }
    payload_bytes = canonical_json(payload)
    payload_nonce = bytes([0x83] * 24)
    encrypted_payload = xchacha20_poly1305_seal(
        K_bundle, payload_nonce, payload_bytes, b""
    )

    bundle_pre_sign = {
        "type": "SEMP_BACKUP_BUNDLE",
        "version": "1.0.0",
        "user_id": "alice@example.com",
        "bundle_id": "01J7BUNDLE0000000000000000",
        "created_at": "2026-04-18T10:00:00Z",
        "supersedes": None,
        "kdf": {
            "algorithm": "argon2id",
            "salt": base64.b64encode(salt).decode("ascii"),
            "memory_kb": memory_kb,
            "iterations": iterations,
            "parallelism": 1,
        },
        "payload_algorithm": "xchacha20-poly1305",
        "payload_nonce": base64.b64encode(payload_nonce).decode("ascii"),
        "encrypted_payload": base64.b64encode(encrypted_payload).decode("ascii"),
        "recovery_verify_pk": {
            "algorithm": "ed25519",
            "public_key": base64.b64encode(identity_pub).decode("ascii"),
        },
        "signature": {
            "algorithm": "ed25519",
            "key_id": identity_fp,
            "value": "",
        },
    }
    signed_bundle, sig_inter = _sign_doc(
        bundle_pre_sign, identity_seed, RECOVERY_BUNDLE_PREFIX, ["signature"]
    )
    assert _verify_doc(signed_bundle, identity_pub, RECOVERY_BUNDLE_PREFIX, ["signature"])

    # Round-trip: re-derive K_bundle, decrypt, parse payload, recover the
    # identity_key. Fail fast at generation time on any mismatch.
    K_bundle_again = argon2id_kdf(recovery_secret, salt, memory_kb, iterations, 32)
    assert K_bundle_again == K_bundle
    plaintext = xchacha20_poly1305_open(
        K_bundle, payload_nonce, encrypted_payload, b""
    )
    assert json.loads(plaintext.decode("utf-8")) == payload

    return {
        "version": "1.0.0",
        "category": "account-recovery",
        "description": (
            "RECOVERY.md §2: backup-bundle construction. Argon2id derives "
            "K_bundle from the recovery secret and the bundle's KDF "
            "parameters; XChaCha20-Poly1305 encrypts the payload under "
            "K_bundle; the user's currently active identity key signs the "
            "canonical bundle with the SEMP-RECOVERY-BUNDLE: prefix. "
            "Round-trip (KDF re-derive, AEAD decrypt, signature verify) "
            "is asserted at generation time."
        ),
        "spec_reference": "VECTORS.md §17.13; RECOVERY.md §2",
        "construction": {
            "kdf": "Argon2id (RFC 9106) via libsodium's crypto_pwhash_argon2id13",
            "payload_aead": "XChaCha20-Poly1305 with empty AAD and 24-byte nonce",
            "domain_separation_prefix_utf8": "SEMP-RECOVERY-BUNDLE:",
            "signing_key": "user's currently active identity key",
        },
        "vectors": [
            {
                "id": "recovery-bundle-roundtrip",
                "description": (
                    "Pinned recovery secret derives K_bundle through "
                    "Argon2id with modest parameters (64 MiB, 3 iterations); "
                    "production deployments use §2.5's RECOMMENDED 256 MiB. "
                    "The encrypted payload contains the user's identity "
                    "keypair (a real Ed25519 seed/public key for the same "
                    "identity that signs the outer bundle)."
                ),
                "spec_reference": "VECTORS.md §17.13; RECOVERY.md §2.4, §2.5",
                "inputs": {
                    "recovery_secret_utf8": recovery_secret.decode("utf-8"),
                    "kdf_salt_hex": salt.hex(),
                    "kdf_memory_kb": memory_kb,
                    "kdf_iterations": iterations,
                    "kdf_parallelism": 1,
                    "identity_seed_hex": identity_seed.hex(),
                    "identity_pub_hex": identity_pub.hex(),
                    "identity_key_id": identity_fp,
                    "payload_nonce_hex": payload_nonce.hex(),
                    "payload_pre_encrypt_json": payload,
                },
                "intermediates": {
                    "K_bundle_hex": K_bundle.hex(),
                    "payload_canonical_utf8": payload_bytes.decode("utf-8"),
                    "encrypted_payload_hex": encrypted_payload.hex(),
                    **sig_inter,
                },
                "expected": {
                    "signed_bundle_json": signed_bundle,
                    "round_trip_decrypts_payload": True,
                    "kdf_redeterms_K_bundle": True,
                    "signature_verifies": True,
                },
            },
        ],
    }


# ---- First-contact token + clock tolerance ---------------------------------


def build_first_contact_token_json() -> dict:
    """HANDSHAKE.md §2.2a.4: first-contact token bound to a postmark.id."""
    import base64

    challenge_id = "01J7CHALLENGE0000000000000000"
    prefix = bytes([0x71] * 16)
    difficulty = 16
    issued_by = "recipient.example.com"
    postmark_id = "01J7FIRSTCONTACTPOSTMARKXXXX"

    # Brute-force a nonce that satisfies the difficulty under
    # H(prefix || nonce) per §2.2a.4 step 3. (The §4 PoW vector binds the
    # challenge_id; first-contact §2.2a.4 binds postmark_id additionally,
    # but the difficulty check is over H(prefix || nonce).)
    nonce_int = 0
    while True:
        nonce_bytes = nonce_int.to_bytes(8, "big")
        digest = hashlib.sha256(prefix + nonce_bytes).digest()
        if leading_zero_bits(digest) >= difficulty:
            break
        nonce_int += 1
        if nonce_int > 10_000_000:
            raise RuntimeError("could not find PoW nonce in budget")

    token = {
        "challenge_id": challenge_id,
        "algorithm": "sha256",
        "prefix": base64.b64encode(prefix).decode("ascii"),
        "difficulty": difficulty,
        "postmark_id": postmark_id,
        "nonce": base64.b64encode(nonce_bytes).decode("ascii"),
        "issued_by": issued_by,
    }

    # Bind verification: postmark_id MUST equal carrying envelope's
    # postmark.id. We model that with two cases below.

    # Case 1: token presented inside an envelope whose postmark.id matches.
    matching_postmark_id = postmark_id
    case_1_postmark_match = (token["postmark_id"] == matching_postmark_id)
    case_1_pow_ok = leading_zero_bits(
        hashlib.sha256(prefix + nonce_bytes).digest()
    ) >= difficulty

    # Case 2: same token presented inside an envelope whose postmark.id
    # differs (replay attempt). §2.2a.4 step 4 MUST reject.
    other_postmark_id = "01J7OTHERPOSTMARKXXXXXXXXXXX"
    case_2_postmark_match = (token["postmark_id"] == other_postmark_id)

    return {
        "version": "1.0.0",
        "category": "first-contact-token",
        "description": (
            "HANDSHAKE.md §2.2a.4: first-contact tokens bind a solved PoW "
            "challenge to a specific postmark_id, preventing token replay "
            "across envelopes. The recipient server checks both that "
            "H(prefix || nonce) satisfies the difficulty and that "
            "token.postmark_id equals the carrying envelope's postmark.id."
        ),
        "spec_reference": "VECTORS.md §17.12; HANDSHAKE.md §2.2a.3, §2.2a.4",
        "construction": {
            "pow_hash": "SHA-256(prefix || nonce)",
            "difficulty_check": "leading zero bits >= token.difficulty",
            "binding_check": "token.postmark_id == carrying_envelope.postmark.id",
        },
        "vectors": [
            {
                "id": "first-contact-token-valid",
                "description": (
                    "Pinned challenge_id and prefix; nonce was searched to "
                    "satisfy the difficulty. The token is presented inside "
                    "an envelope whose postmark.id matches the bound "
                    "postmark_id; both verification predicates succeed."
                ),
                "spec_reference": "VECTORS.md §17.12; HANDSHAKE.md §2.2a.4",
                "inputs": {
                    "token_json": token,
                    "carrying_envelope_postmark_id": matching_postmark_id,
                },
                "expected": {
                    "pow_satisfies_difficulty": case_1_pow_ok,
                    "postmark_binding_matches": case_1_postmark_match,
                    "token_accepted": case_1_pow_ok and case_1_postmark_match,
                },
            },
            {
                "id": "first-contact-token-replay-rejected",
                "description": (
                    "Same valid token presented inside a DIFFERENT envelope "
                    "(different postmark.id). The PoW difficulty check "
                    "still passes, but the postmark binding check fails, "
                    "so the recipient server MUST reject with "
                    "reason_code policy_forbidden per §2.2a.4. This "
                    "demonstrates §2.2a.4's per-envelope single-use "
                    "enforcement."
                ),
                "spec_reference": "VECTORS.md §17.12; HANDSHAKE.md §2.2a.4",
                "inputs": {
                    "token_json": token,
                    "carrying_envelope_postmark_id": other_postmark_id,
                },
                "expected": {
                    "pow_satisfies_difficulty": case_1_pow_ok,
                    "postmark_binding_matches": case_2_postmark_match,
                    "token_accepted": case_1_pow_ok and case_2_postmark_match,
                    "rejection_reason_code": "policy_forbidden",
                },
            },
        ],
    }


def build_clock_tolerance_json() -> dict:
    """CONFORMANCE.md §9.3.1: clock-skew tolerance for future-dated and
    expires-at fields."""

    def fut(secs: int):
        return {"T_minus_now_seconds": secs}

    def exp(secs: int):
        return {"now_minus_expiresAt_seconds": secs}

    future_samples = [
        {**fut(0), "expected": "accept", "reason": "T == now"},
        {**fut(60), "expected": "accept", "reason": "1 min ahead, well under 5"},
        {**fut(5 * 60), "expected": "accept_or_reject_at_implementor_choice",
         "reason": "boundary: SHOULD reject at >5 min, MUST accept at <=5 min"},
        {**fut(10 * 60), "expected": "accept_or_reject_at_implementor_choice",
         "reason": "between SHOULD-reject (5 min) and MUST-reject (15 min)"},
        {**fut(15 * 60), "expected": "reject",
         "reason": "boundary: MUST reject when T - now > 15 min; equality is the limit"},
        {**fut(30 * 60), "expected": "reject", "reason": "30 min ahead, well past 15"},
    ]

    expires_samples = [
        {**exp(-60), "expected": "accept",
         "reason": "now is 1 min before expires_at"},
        {**exp(0), "expected": "accept",
         "reason": "now == expires_at; SHOULD reject but MAY apply 0-5 min grace"},
        {**exp(60), "expected": "accept_or_reject_at_implementor_choice",
         "reason": "1 min past expires; MAY apply up to 5 min grace"},
        {**exp(5 * 60), "expected": "accept_or_reject_at_implementor_choice",
         "reason": "5 min past; boundary of grace window"},
        {**exp(10 * 60), "expected": "accept_or_reject_at_implementor_choice",
         "reason": "10 min past; outside grace but inside MUST-reject window"},
        {**exp(15 * 60 + 1), "expected": "reject",
         "reason": "15 min + 1 sec past: MUST reject"},
    ]

    return {
        "version": "1.0.0",
        "category": "clock-tolerance",
        "description": (
            "CONFORMANCE.md §9.3.1 clock-skew tolerance. Future-dated "
            "fields and expires_at fields have separate tiered rules; "
            "this vector enumerates the boundaries (0, 5, 15 minutes) so "
            "implementations can verify they fall in the right tier at "
            "the right boundary value."
        ),
        "spec_reference": "VECTORS.md §17.12; CONFORMANCE.md §9.3.1",
        "vectors": [
            {
                "id": "clock-tolerance-future-dated",
                "description": (
                    "Future-dated timestamp samples. T - now ranges from 0 "
                    "to 30 minutes. Per §9.3.1: MUST accept at 0-5 min; "
                    "SHOULD reject at >5 min; MUST reject at >15 min."
                ),
                "spec_reference": "VECTORS.md §17.12; CONFORMANCE.md §9.3.1",
                "samples": future_samples,
            },
            {
                "id": "clock-tolerance-expires-at",
                "description": (
                    "expires_at samples. now - T ranges from -60 sec to "
                    "15+ min. Per §9.3.1: implementations SHOULD reject "
                    "at now > T; MAY apply up to 5 min grace; MUST "
                    "reject at now > T + 15 min."
                ),
                "spec_reference": "VECTORS.md §17.12; CONFORMANCE.md §9.3.1",
                "samples": expires_samples,
            },
        ],
    }


# ---- Session resumption (Layer 4) -------------------------------------------


def build_session_resumption_json() -> dict:
    """HANDSHAKE.md §2.8: resume-request + resume-accepted vectors plus the
    §2.8.3 key-derivation vector that mixes K_resumption with a fresh
    ephemeral shared secret."""
    server_domain_seed = bytes([0x51] * 32)
    server_domain_pub = ed25519_pubkey_from_priv(server_domain_seed)
    server_domain_fp = fingerprint_hex(server_domain_pub)

    resume_request = {
        "type": "SEMP_HANDSHAKE",
        "step": "resume",
        "party": "client",
        "version": "1.0.0",
        "nonce": "cmVzdW1lLW5vbmNlLWNsaWVudC1iYXNlNjQtMzItYnl0ZXM=",
        "resumption_ticket": "PINNED-OPAQUE-TICKET-BYTES",
        "client_ephemeral_key": {
            "algorithm": "x25519-chacha20-poly1305",
            "key": "Y2xpZW50LWVwaGVtZXJhbC1rZXk=",
            "key_id": "client-eph-fp",
        },
        "transport": "ws",
        "extensions": {},
    }
    resume_request_canonical = canonical_json(resume_request)

    resume_accepted_pre_sign = {
        "type": "SEMP_HANDSHAKE",
        "step": "accepted",
        "party": "server",
        "version": "1.0.0",
        "session_id": "01J7RESUMESESSIONXXXXXXXXXXX",
        "session_ttl": 300,
        "server_nonce": "cmVzdW1lLW5vbmNlLXNlcnZlci1iYXNlNjQtMzItYnl0ZXM=",
        "server_ephemeral_key": {
            "algorithm": "x25519-chacha20-poly1305",
            "key": "c2VydmVyLWVwaGVtZXJhbC1rZXk=",
            "key_id": "server-eph-fp",
        },
        "resumption_ticket": {
            "value": "PINNED-FRESH-OPAQUE-TICKET-BYTES",
            "expires_at": "2026-05-15T09:00:00Z",
        },
        "server_signature": "",
        "extensions": {},
    }
    resume_accepted_signed, resume_accepted_inter = handshake_sign(
        resume_accepted_pre_sign, server_domain_seed
    )
    assert handshake_verify(resume_accepted_signed, server_domain_pub)

    # Resumption key derivation per §2.8.3.
    ephemeral_ss = bytes([0x53] * 32)
    K_resumption = bytes([0x54] * 32)
    client_nonce = bytes([0xAA] * 32)
    server_nonce = bytes([0xBB] * 32)
    ikm_resume = ephemeral_ss + K_resumption
    salt = client_nonce + server_nonce
    prk_resume = hkdf_extract(salt, ikm_resume)
    keys = {
        name: hkdf_expand(prk_resume, label.encode("utf-8"), 32)
        for name, label in INFO_LABELS_UTF8.items()
    }
    K_resumption_next = hkdf_expand(prk_resume, b"SEMP-v1-resumption-next", 32)

    return {
        "version": "1.0.0",
        "category": "session-resumption",
        "description": (
            "HANDSHAKE.md §2.8 resumption vectors: the two-message resume "
            "exchange and the §2.8.3 key derivation that mixes K_resumption "
            "with a fresh ephemeral shared secret."
        ),
        "spec_reference": "VECTORS.md §17.11; HANDSHAKE.md §2.8",
        "vectors": [
            {
                "id": "resume-request-canonical",
                "description": (
                    "ClientResume request. The outer message is unsigned "
                    "by design (the resumption_ticket alone authenticates "
                    "the holder, and a fresh ephemeral DH provides forward "
                    "secrecy for the resumed session). Pinned canonical "
                    "bytes match what an implementation MUST produce on "
                    "the wire."
                ),
                "spec_reference": "VECTORS.md §17.11; HANDSHAKE.md §2.8.2",
                "inputs": {"message_json": resume_request},
                "expected": {
                    "canonical_utf8": resume_request_canonical.decode("utf-8"),
                    "is_signed": False,
                },
            },
            {
                "id": "resume-accepted-signed",
                "description": (
                    "ServerResume accepted response. Same construction as "
                    "the four-step handshake's accepted message: "
                    "SEMP-HANDSHAKE: prefix over canonical(message) with "
                    "server_signature blanked. Carries a fresh session_id, "
                    "a fresh server_ephemeral_key, and a fresh "
                    "resumption_ticket replacing the one consumed in the "
                    "request."
                ),
                "spec_reference": "VECTORS.md §17.11; HANDSHAKE.md §2.8.2",
                "inputs": {
                    "server_domain_seed_hex": server_domain_seed.hex(),
                    "server_domain_pub_hex": server_domain_pub.hex(),
                    "server_domain_key_id": server_domain_fp,
                    "message_pre_sign_json": resume_accepted_pre_sign,
                },
                "intermediates": resume_accepted_inter,
                "expected": {
                    "signed_message_json": resume_accepted_signed,
                    "server_signature_b64": resume_accepted_signed["server_signature"],
                    "signature_verifies": True,
                },
            },
            {
                "id": "resume-key-derivation",
                "description": (
                    "Resumed-session key derivation per §2.8.3. The HKDF "
                    "input keying material is the concatenation of the "
                    "fresh ephemeral shared secret and K_resumption "
                    "recovered from the ticket. The salt and per-key "
                    "info labels match the initial-handshake schedule "
                    "(§2.1), so a fresh ephemeral DH is what preserves "
                    "forward secrecy: an attacker holding the ticket "
                    "alone cannot derive session keys."
                ),
                "spec_reference": "VECTORS.md §17.11; HANDSHAKE.md §2.8.3; SESSION.md §2.1",
                "inputs": {
                    "ephemeral_shared_secret_hex": ephemeral_ss.hex(),
                    "K_resumption_hex": K_resumption.hex(),
                    "client_nonce_hex": client_nonce.hex(),
                    "server_nonce_hex": server_nonce.hex(),
                    "ikm_construction": "ephemeral_shared_secret || K_resumption",
                    "salt_construction": "client_nonce || server_nonce",
                    "info_labels_utf8": dict(INFO_LABELS_UTF8),
                    "K_resumption_next_info_utf8": "SEMP-v1-resumption-next",
                },
                "expected": {
                    "ikm_resume_hex": ikm_resume.hex(),
                    "salt_hex": salt.hex(),
                    "prk_resume_hex": prk_resume.hex(),
                    "keys": {f"{k}_hex": v.hex() for k, v in keys.items()},
                    "K_resumption_next_hex": K_resumption_next.hex(),
                },
            },
        ],
    }


# ---- Discovery-signed + Transparency STH (Layer 5) -------------------------


DISCOVERY_PREFIX = b"SEMP-DISCOVERY:"
TRANSPARENCY_STH_PREFIX = b"SEMP-TRANSPARENCY-STH:"


def build_discovery_signed_json() -> dict:
    """SEMP_DISCOVERY response signed with the SEMP-DISCOVERY: prefix per
    §4.3."""
    domain_seed = bytes([0x41] * 32)
    domain_pub = ed25519_pubkey_from_priv(domain_seed)
    domain_fp = fingerprint_hex(domain_pub)

    response_pre_sign = {
        "type": "SEMP_DISCOVERY",
        "step": "response",
        "version": "1.0.0",
        "id": "01J7DISCOVERYRESPONSEXXXXXXX",
        "timestamp": "2026-04-19T12:00:00Z",
        "results": [
            {
                "address": "alice@example.com",
                "status": "semp",
                "transports": ["ws", "h2"],
                "extensions": ["semp.dev/device-sync"],
                "server": "semp.example.com",
                "ttl": 3600,
            },
        ],
        "signature": {
            "algorithm": "ed25519",
            "key_id": domain_fp,
            "value": "",
        },
        "extensions": {},
    }
    signed, inter = _sign_doc(
        response_pre_sign, domain_seed, DISCOVERY_PREFIX, ["signature"]
    )
    assert _verify_doc(signed, domain_pub, DISCOVERY_PREFIX, ["signature"])

    return {
        "version": "1.0.0",
        "category": "discovery-signed",
        "description": (
            "DISCOVERY.md §7: SEMP_DISCOVERY responses are signed by the "
            "responding server's domain key with the SEMP-DISCOVERY: "
            "prefix. Verifiers reject unsigned or invalid responses "
            "before caching or acting on per-address results."
        ),
        "spec_reference": "VECTORS.md §17.10; DISCOVERY.md §7; ENVELOPE.md §4.3",
        "construction": {
            "domain_separation_prefix_utf8": "SEMP-DISCOVERY:",
            "signing_key": "responding server's domain signing key",
            "canonical_form": "ENVELOPE.md §4.3 with signature.value blanked",
        },
        "vectors": [
            {
                "id": "discovery-response-signed-valid",
                "description": (
                    "Pinned domain key signs a single-result SEMP_DISCOVERY "
                    "response. Signature verifies under the published "
                    "domain public key. Companion to discovery.json's "
                    "discovery-response-parsing vector, which covers the "
                    "structural parsing path; this vector covers the "
                    "signature path."
                ),
                "spec_reference": "VECTORS.md §17.10; DISCOVERY.md §7.1",
                "inputs": {
                    "domain_seed_hex": domain_seed.hex(),
                    "domain_pub_hex": domain_pub.hex(),
                    "domain_key_id": domain_fp,
                    "response_pre_sign_json": response_pre_sign,
                },
                "intermediates": inter,
                "expected": {
                    "signed_response_json": signed,
                    "signature_b64": signed["signature"]["value"],
                    "signature_verifies": True,
                },
            },
        ],
    }


def merkle_leaf_hash(leaf_data: bytes) -> bytes:
    """RFC 6962 §2.1: leaf hash is SHA-256(0x00 || leaf_data)."""
    return hashlib.sha256(b"\x00" + leaf_data).digest()


def merkle_internal_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 §2.1: internal node hash is SHA-256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaves: list[bytes]) -> bytes:
    """Compute the RFC 6962 Merkle root of a list of leaves (each already
    leaf-hashed)."""
    if len(leaves) == 0:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    # split point: largest power of two strictly less than n
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return merkle_internal_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def merkle_inclusion_path(leaves: list[bytes], leaf_index: int) -> list[bytes]:
    """RFC 6962 §2.1.1 inclusion proof: returns the sibling hashes along the
    path from leaf_index up to the root."""
    if not (0 <= leaf_index < len(leaves)):
        raise ValueError("leaf_index out of range")

    def helper(start: int, end: int, target: int) -> list[bytes]:
        if end - start == 1:
            return []
        k = 1
        while k * 2 < end - start:
            k *= 2
        mid = start + k
        if target < mid:
            return helper(start, mid, target) + [merkle_root(leaves[mid:end])]
        return helper(mid, end, target) + [merkle_root(leaves[start:mid])]

    return helper(0, len(leaves), leaf_index)


def merkle_consistency_proof(leaves: list[bytes], n1: int, n2: int) -> list[bytes]:
    """RFC 6962 §2.1.2 consistency proof from tree size n1 to n2 (n2 >= n1)."""
    if not (0 < n1 <= n2 <= len(leaves)):
        raise ValueError("require 0 < n1 <= n2 <= len(leaves)")
    if n1 == n2:
        return []

    def subproof(m: int, start: int, end: int, b: bool) -> list[bytes]:
        # m is the size of the smaller tree we're proving consistency from;
        # start/end define the current subtree window over the larger tree;
        # b is True iff we are at the original "right edge" path of the
        # smaller tree.
        n = end - start
        if m == n:
            if b:
                return []
            return [merkle_root(leaves[start:end])]
        k = 1
        while k * 2 < n:
            k *= 2
        if m <= k:
            return subproof(m, start, start + k, b) + [merkle_root(leaves[start + k : end])]
        else:
            return subproof(m - k, start + k, end, False) + [merkle_root(leaves[start : start + k])]

    return subproof(n1, 0, n2, True)


def merkle_verify_consistency(
    n1: int,
    n2: int,
    proof: list[bytes],
    root1: bytes,
    root2: bytes,
) -> bool:
    """RFC 6962 §2.1.2 consistency-proof verification."""
    if n1 == 0 or n1 == n2:
        return n1 != 0 or len(proof) == 0
    if n1 > n2 or n2 == 0:
        return False
    if (n1 == n2) and len(proof) > 0:
        return False

    # If n1 is a power of two not equal to n2, prepend root1 to the proof.
    if (n1 & (n1 - 1)) == 0:
        path = [root1] + list(proof)
    else:
        path = list(proof)

    if not path:
        return False

    fn = n1 - 1
    sn = n2 - 1
    while fn % 2 == 1:
        fn //= 2
        sn //= 2

    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            fr = merkle_internal_hash(c, fr)
            sr = merkle_internal_hash(c, sr)
            while not (fn == 0 or fn % 2 == 1):
                fn //= 2
                sn //= 2
        else:
            sr = merkle_internal_hash(sr, c)
        fn //= 2
        sn //= 2

    return sn == 0 and fr == root1 and sr == root2


def merkle_verify_inclusion(
    leaf_hash: bytes,
    leaf_index: int,
    log_size: int,
    path: list[bytes],
    expected_root: bytes,
) -> bool:
    """RFC 6962 §2.1.1 inclusion-proof verification."""
    if not (0 <= leaf_index < log_size):
        return False
    fn = leaf_index
    sn = log_size - 1
    r = leaf_hash
    for p in path:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            r = merkle_internal_hash(p, r)
            while not (fn == 0 or fn % 2 == 1):
                fn //= 2
                sn //= 2
        else:
            r = merkle_internal_hash(r, p)
        fn //= 2
        sn //= 2
    return sn == 0 and r == expected_root


def build_transparency_json() -> dict:
    """Layer 5 vectors for TRANSPARENCY.md §2-§3: signed tree head plus an
    RFC 6962 inclusion-proof round-trip."""
    import base64

    domain_seed = bytes([0x42] * 32)
    domain_pub = ed25519_pubkey_from_priv(domain_seed)
    domain_fp = fingerprint_hex(domain_pub)

    # Build a tiny tree of 8 leaves so paths have meaningful depth.
    leaf_payloads = [f"transparency-leaf-{i}".encode("utf-8") for i in range(8)]
    leaves = [merkle_leaf_hash(p) for p in leaf_payloads]
    root = merkle_root(leaves)
    log_size = len(leaves)

    sth_pre_sign = {
        "log_size": log_size,
        "root_hash": base64.b64encode(root).decode("ascii"),
        "timestamp": "2026-04-19T12:00:00Z",
        "signature": {
            "algorithm": "ed25519",
            "key_id": domain_fp,
            "value": "",
        },
    }
    sth_signed, sth_inter = _sign_doc(
        sth_pre_sign, domain_seed, TRANSPARENCY_STH_PREFIX, ["signature"]
    )
    assert _verify_doc(sth_signed, domain_pub, TRANSPARENCY_STH_PREFIX, ["signature"])

    # Inclusion proof for leaf 4 (arbitrary middle entry).
    leaf_index = 4
    path = merkle_inclusion_path(leaves, leaf_index)
    inclusion_verifies = merkle_verify_inclusion(
        leaves[leaf_index], leaf_index, log_size, path, root
    )
    assert inclusion_verifies

    # Tampered inclusion: flip one bit of one path element; verification rejects.
    if path:
        bad_path = list(path)
        bad_first = bytearray(bad_path[0])
        bad_first[0] ^= 0x01
        bad_path[0] = bytes(bad_first)
        bad_inclusion_verifies = merkle_verify_inclusion(
            leaves[leaf_index], leaf_index, log_size, bad_path, root
        )
        assert not bad_inclusion_verifies
    else:
        bad_path = path
        bad_inclusion_verifies = False

    sth_vector = {
        "id": "transparency-sth-signed",
        "description": (
            "Signed Tree Head per TRANSPARENCY.md §2.3. Domain key signs "
            "{log_size, root_hash, timestamp, signature.algorithm, "
            "signature.key_id} (with signature.value blanked) prefixed "
            "with SEMP-TRANSPARENCY-STH:. The pinned tree has 8 leaves "
            "with payloads 'transparency-leaf-0' through "
            "'transparency-leaf-7' so the root is reproducible."
        ),
        "spec_reference": "VECTORS.md §17.10; TRANSPARENCY.md §2.3",
        "inputs": {
            "domain_seed_hex": domain_seed.hex(),
            "domain_pub_hex": domain_pub.hex(),
            "domain_key_id": domain_fp,
            "leaf_payloads_utf8": [p.decode("utf-8") for p in leaf_payloads],
            "sth_pre_sign_json": sth_pre_sign,
        },
        "intermediates": {
            "leaf_hashes_hex": [h.hex() for h in leaves],
            "root_hash_hex": root.hex(),
            **sth_inter,
        },
        "expected": {
            "sth_signed_json": sth_signed,
            "signature_b64": sth_signed["signature"]["value"],
            "signature_verifies": True,
        },
    }

    inclusion_vector = {
        "id": "transparency-inclusion-proof",
        "description": (
            "RFC 6962 §2.1.1 inclusion proof for leaf 4 in the §17.10 STH "
            "tree. The path is the sequence of sibling hashes from the "
            "leaf up to the root; verification recomputes the root and "
            "compares against the STH's root_hash. Verification of a "
            "tampered path (one bit flipped in the first sibling) "
            "rejects, demonstrating the proof's integrity."
        ),
        "spec_reference": "VECTORS.md §17.10; TRANSPARENCY.md §3.1; RFC 6962 §2.1.1",
        "inputs": {
            "log_size": log_size,
            "leaf_index": leaf_index,
            "leaf_hash_hex": leaves[leaf_index].hex(),
            "expected_root_hex": root.hex(),
            "path_hex": [h.hex() for h in path],
        },
        "expected": {
            "valid_path_verifies": inclusion_verifies,
            "tampered_path_first_element_hex": (
                bad_path[0].hex() if path else None
            ),
            "tampered_path_verifies": bad_inclusion_verifies,
        },
    }

    # Consistency proof from a smaller earlier tree (5 leaves) to the
    # current 8-leaf tree. The earlier tree is a prefix of the current
    # tree if and only if any append-only log has been honestly extended.
    n1 = 5
    leaves_n1 = leaves[:n1]
    root_n1 = merkle_root(leaves_n1)
    consistency_path = merkle_consistency_proof(leaves, n1, log_size)
    consistency_verifies = merkle_verify_consistency(
        n1, log_size, consistency_path, root_n1, root
    )
    assert consistency_verifies

    # Tampered consistency: flip a bit on one path element.
    bad_consistency_path = list(consistency_path)
    if bad_consistency_path:
        first = bytearray(bad_consistency_path[0])
        first[0] ^= 0x01
        bad_consistency_path[0] = bytes(first)
    bad_consistency_verifies = merkle_verify_consistency(
        n1, log_size, bad_consistency_path, root_n1, root
    )
    assert not bad_consistency_verifies

    consistency_vector = {
        "id": "transparency-consistency-proof",
        "description": (
            "RFC 6962 §2.1.2 consistency proof showing that the 5-leaf "
            "earlier tree is a prefix of the §17.10 8-leaf tree. The "
            "verifier holds two STHs (one for n1=5, one for n2=8) and "
            "the proof; verification recomputes both roots from the "
            "proof path and confirms they match. Tampering one bit of "
            "the path causes verification to reject, the property an "
            "honest log relies on to detect equivocation."
        ),
        "spec_reference": "VECTORS.md §17.10; TRANSPARENCY.md §3.2; RFC 6962 §2.1.2",
        "inputs": {
            "n1": n1,
            "n2": log_size,
            "root_n1_hex": root_n1.hex(),
            "root_n2_hex": root.hex(),
            "path_hex": [h.hex() for h in consistency_path],
        },
        "expected": {
            "valid_path_verifies": consistency_verifies,
            "tampered_path_first_element_hex": (
                bad_consistency_path[0].hex() if consistency_path else None
            ),
            "tampered_path_verifies": bad_consistency_verifies,
        },
    }

    return {
        "version": "1.0.0",
        "category": "transparency",
        "description": (
            "Layer 5 vectors for TRANSPARENCY.md: domain-signed tree heads "
            "plus RFC 6962 inclusion and consistency proofs. The §4 "
            "augmented key-fetch path is TODO."
        ),
        "spec_reference": "VECTORS.md §17.10; TRANSPARENCY.md §2-§3",
        "construction": {
            "merkle_leaf_hash": "SHA-256(0x00 || leaf_data) per RFC 6962 §2.1",
            "merkle_internal_hash": "SHA-256(0x01 || left || right) per RFC 6962 §2.1",
            "sth_signature_prefix_utf8": "SEMP-TRANSPARENCY-STH:",
            "canonical_form": "ENVELOPE.md §4.3 with signature.value blanked",
        },
        "vectors": [sth_vector, inclusion_vector, consistency_vector],
    }


# ---- Account closure / user policy / migration (Layer 4 Ed25519 patterns) --


def _sign_doc(doc: dict, priv: bytes, prefix: bytes, signature_path: list[str]) -> tuple[dict, dict]:
    """Generic Ed25519 signed-document helper. signature_path is the list of
    keys to descend to reach the signature object (e.g. ['signature'] for a
    top-level signature, or ['old_identity_signature'] for nested ones).
    Blanks .value at that path, canonicalises, prefixes with the given
    domain-separation prefix, signs, base64-encodes, replaces."""
    import base64

    d = copy.deepcopy(doc)
    cur = d
    for k in signature_path[:-1]:
        cur = cur[k]
    cur[signature_path[-1]]["value"] = ""
    canonical = canonical_json(d)
    prefixed = prefix + canonical
    sig = ed25519_sign(priv, prefixed)
    cur[signature_path[-1]]["value"] = base64.b64encode(sig).decode("ascii")
    return d, {
        "canonical_with_blanked_signature_utf8": canonical.decode("utf-8"),
        "signing_input_prefix_utf8": prefix.decode("utf-8"),
        "signing_input_hex": prefixed.hex(),
        "signature_hex": sig.hex(),
    }


def _verify_doc(doc: dict, pub: bytes, prefix: bytes, signature_path: list[str]) -> bool:
    import base64

    cur = doc
    for k in signature_path[:-1]:
        cur = cur[k]
    sig_b64 = cur[signature_path[-1]]["value"]
    sig = base64.b64decode(sig_b64)
    d = copy.deepcopy(doc)
    cur2 = d
    for k in signature_path[:-1]:
        cur2 = cur2[k]
    cur2[signature_path[-1]]["value"] = ""
    canonical = canonical_json(d)
    return ed25519_verify(pub, sig, prefix + canonical)


ACCOUNT_CLOSURE_PREFIX = b"SEMP-ACCOUNT-CLOSURE:"
USER_POLICY_PREFIX = b"SEMP-USER-POLICY:"
MIGRATION_RECORD_PREFIX = b"SEMP-MIGRATION-RECORD:"


def build_account_closure_json() -> dict:
    """CLOSURE.md §2: account closure request signed by a full-access device."""
    primary_seed = bytes([0x31] * 32)
    primary_pub = ed25519_pubkey_from_priv(primary_seed)
    primary_fp = fingerprint_hex(primary_pub)

    request_pre_sign = {
        "type": "SEMP_ACCOUNT_CLOSURE",
        "step": "request",
        "version": "1.0.0",
        "user_id": "alice@example.com",
        "requested_at": "2026-04-19T12:00:00Z",
        "grace_period_seconds": 2592000,
        "issued_by": "01JPRIMARY00000000000000000",
        "signature": {
            "algorithm": "ed25519",
            "key_id": primary_fp,
            "value": "",
        },
    }
    signed, inter = _sign_doc(
        request_pre_sign, primary_seed, ACCOUNT_CLOSURE_PREFIX, ["signature"]
    )
    assert _verify_doc(signed, primary_pub, ACCOUNT_CLOSURE_PREFIX, ["signature"])

    return {
        "version": "1.0.0",
        "category": "account-closure",
        "description": (
            "CLOSURE.md §2: account closure requests are signed by a "
            "full-access device's identity key with the "
            "SEMP-ACCOUNT-CLOSURE: domain-separation prefix over the "
            "canonical document with signature.value blanked."
        ),
        "spec_reference": "VECTORS.md §17.9; CLOSURE.md §2",
        "construction": {
            "domain_separation_prefix_utf8": "SEMP-ACCOUNT-CLOSURE:",
            "signing_key": "full-access device identity key",
            "canonical_form": "ENVELOPE.md §4.3 with signature.value blanked",
        },
        "vectors": [
            {
                "id": "account-closure-request-valid",
                "description": (
                    "Pinned full-access device key signs a closure request "
                    "for alice@example.com with a 30-day grace period. "
                    "Signature MUST verify under the device's public key."
                ),
                "spec_reference": "VECTORS.md §17.9; CLOSURE.md §2.3",
                "inputs": {
                    "primary_device_seed_hex": primary_seed.hex(),
                    "primary_device_pub_hex": primary_pub.hex(),
                    "primary_device_key_id": primary_fp,
                    "request_pre_sign_json": request_pre_sign,
                },
                "intermediates": inter,
                "expected": {
                    "signed_request_json": signed,
                    "signature_b64": signed["signature"]["value"],
                    "signature_verifies": True,
                },
            },
        ],
    }


def build_user_policy_json() -> dict:
    """DELIVERY.md §7: SEMP_USER_POLICY signed by originating device."""
    device_seed = bytes([0x32] * 32)
    device_pub = ed25519_pubkey_from_priv(device_seed)
    device_fp = fingerprint_hex(device_pub)

    update_pre_sign = {
        "type": "SEMP_USER_POLICY",
        "step": "update",
        "version": "1.0.0",
        "user_id": "alice@example.com",
        "device_id": "01JDEVICE000000000000000000",
        "policy_version": 42,
        "timestamp": "2026-05-08T10:00:00Z",
        "operations": [
            {
                "op": "add",
                "kind": "semp.dev/block",
                "entry": {
                    "id": "01JBLOCK0000000000000000000",
                    "address": "spam@bad.example",
                },
            },
            {
                "op": "modify",
                "kind": "semp.dev/first_contact",
                "entry": {"mode": "challenge"},
            },
        ],
        "signature": {
            "algorithm": "ed25519",
            "key_id": device_fp,
            "value": "",
        },
    }
    signed, inter = _sign_doc(
        update_pre_sign, device_seed, USER_POLICY_PREFIX, ["signature"]
    )
    assert _verify_doc(signed, device_pub, USER_POLICY_PREFIX, ["signature"])

    return {
        "version": "1.0.0",
        "category": "user-policy",
        "description": (
            "DELIVERY.md §7.1: SEMP_USER_POLICY messages are signed by the "
            "originating device with the SEMP-USER-POLICY: prefix. The "
            "home server verifies the signature, checks policy_version "
            "monotonicity, and propagates accepted updates to other "
            "registered devices."
        ),
        "spec_reference": "VECTORS.md §17.9; DELIVERY.md §7",
        "construction": {
            "domain_separation_prefix_utf8": "SEMP-USER-POLICY:",
            "signing_key": "originating device identity key",
            "canonical_form": "ENVELOPE.md §4.3 with signature.value blanked",
        },
        "vectors": [
            {
                "id": "user-policy-update-valid",
                "description": (
                    "Pinned device key signs a SEMP_USER_POLICY update "
                    "carrying two operations across distinct kinds (an "
                    "add to semp.dev/block and a modify to "
                    "semp.dev/first_contact). All operations apply "
                    "atomically per §7.2 with respect to policy_version "
                    "advancement."
                ),
                "spec_reference": "VECTORS.md §17.9; DELIVERY.md §7.2",
                "inputs": {
                    "device_seed_hex": device_seed.hex(),
                    "device_pub_hex": device_pub.hex(),
                    "device_key_id": device_fp,
                    "update_pre_sign_json": update_pre_sign,
                },
                "intermediates": inter,
                "expected": {
                    "signed_update_json": signed,
                    "signature_b64": signed["signature"]["value"],
                    "signature_verifies": True,
                },
            },
        ],
    }


def build_migration_json() -> dict:
    """MIGRATION.md §3: four-signature chain (cooperative) over the
    canonical migration record. Signatures land in the §3.3 order:
    old_identity, new_identity, new_domain, old_domain."""
    import base64

    old_id_seed = bytes([0x33] * 32)
    old_id_pub = ed25519_pubkey_from_priv(old_id_seed)
    old_id_fp = fingerprint_hex(old_id_pub)

    new_id_seed = bytes([0x34] * 32)
    new_id_pub = ed25519_pubkey_from_priv(new_id_seed)
    new_id_fp = fingerprint_hex(new_id_pub)

    old_dom_seed = bytes([0x35] * 32)
    old_dom_pub = ed25519_pubkey_from_priv(old_dom_seed)
    old_dom_fp = fingerprint_hex(old_dom_pub)

    new_dom_seed = bytes([0x36] * 32)
    new_dom_pub = ed25519_pubkey_from_priv(new_dom_seed)
    new_dom_fp = fingerprint_hex(new_dom_pub)

    record = {
        "type": "SEMP_MIGRATION",
        "version": "1.0.0",
        "record_id": "01JMIGRATION0000000000000000",
        "old_address": "alice@old.example",
        "new_address": "alice@new.example",
        "old_identity_key_id": old_id_fp,
        "new_identity_key_id": new_id_fp,
        "new_identity_public_key": base64.b64encode(new_id_pub).decode("ascii"),
        "migrated_at": "2026-04-18T12:00:00Z",
        "forwarding_window_until": "2026-10-15T12:00:00Z",
        "mode": "cooperative",
        "old_identity_signature": {"algorithm": "ed25519", "key_id": old_id_fp, "value": ""},
        "new_identity_signature": {"algorithm": "ed25519", "key_id": new_id_fp, "value": ""},
        "old_domain_signature": {"algorithm": "ed25519", "key_id": old_dom_fp, "value": ""},
        "new_domain_signature": {"algorithm": "ed25519", "key_id": new_dom_fp, "value": ""},
        "extensions": {},
    }

    # §3.3 sign order: old_identity -> new_identity -> new_domain -> old_domain.
    intermediates_chain = []
    after_old_id, inter1 = _sign_doc(
        record, old_id_seed, MIGRATION_RECORD_PREFIX, ["old_identity_signature"]
    )
    intermediates_chain.append({"step": "1: old_identity_signature", **inter1})
    after_new_id, inter2 = _sign_doc(
        after_old_id, new_id_seed, MIGRATION_RECORD_PREFIX, ["new_identity_signature"]
    )
    intermediates_chain.append({"step": "2: new_identity_signature", **inter2})
    after_new_dom, inter3 = _sign_doc(
        after_new_id, new_dom_seed, MIGRATION_RECORD_PREFIX, ["new_domain_signature"]
    )
    intermediates_chain.append({"step": "3: new_domain_signature", **inter3})
    final, inter4 = _sign_doc(
        after_new_dom, old_dom_seed, MIGRATION_RECORD_PREFIX, ["old_domain_signature"]
    )
    intermediates_chain.append({"step": "4: old_domain_signature", **inter4})

    # Verify all four signatures: each verifies against the canonical bytes
    # WITH THE SIGNATURES BELOW IT BLANKED. We test this by re-blanking
    # each signature in turn and verifying it independently.
    def verify_chain(rec):
        # Build a "signing-time" doc for each signature in chain order:
        # at step N, signatures 1..N-1 are at their final values and
        # signatures N..4 are blank.
        steps = [
            ("old_identity_signature", old_id_pub),
            ("new_identity_signature", new_id_pub),
            ("new_domain_signature", new_dom_pub),
            ("old_domain_signature", old_dom_pub),
        ]
        results = []
        for i, (field, pub) in enumerate(steps):
            doc = copy.deepcopy(rec)
            for j, (later_field, _) in enumerate(steps):
                if j > i:
                    doc[later_field]["value"] = ""
            ok = _verify_doc(doc, pub, MIGRATION_RECORD_PREFIX, [field])
            results.append((field, ok))
        return results

    chain_results = verify_chain(final)
    for field, ok in chain_results:
        assert ok, f"signature in chain failed: {field}"

    return {
        "version": "1.0.0",
        "category": "migration",
        "description": (
            "MIGRATION.md §3: provider-migration record. Cooperative "
            "migrations carry four Ed25519 signatures applied in §3.3 "
            "order: old_identity, new_identity, new_domain, old_domain. "
            "Each signature is computed over the canonical record with "
            "ALL prior signatures at their final values and the signing "
            "signature's value blanked, prefixed with "
            "SEMP-MIGRATION-RECORD:."
        ),
        "spec_reference": "VECTORS.md §17.9; MIGRATION.md §3",
        "construction": {
            "domain_separation_prefix_utf8": "SEMP-MIGRATION-RECORD:",
            "signature_order": [
                "1. old_identity_signature (proves old user authorised migration)",
                "2. new_identity_signature (proves new user accepted migration)",
                "3. new_domain_signature  (new provider commits to host alice@new.example)",
                "4. old_domain_signature  (cooperative only: old provider commits to forwarding)",
            ],
            "canonical_form": (
                "Sorted keys, no whitespace, UTF-8. At signature N, "
                "signatures 1..N-1 are at final values; signature N is "
                "blanked; signatures N+1..4 are blanked."
            ),
        },
        "vectors": [
            {
                "id": "migration-cooperative-four-signature-chain",
                "description": (
                    "Cooperative migration record signed by all four "
                    "parties in §3.3 order. Verification of any single "
                    "signature reproduces the canonical bytes that were "
                    "signed by re-blanking all signatures that come "
                    "AFTER it in the chain and keeping the ones BEFORE "
                    "it at their final values. The verify_chain assertion "
                    "in the generator runs all four checks before any "
                    "JSON is written."
                ),
                "spec_reference": "VECTORS.md §17.9; MIGRATION.md §3.3",
                "inputs": {
                    "old_identity_seed_hex": old_id_seed.hex(),
                    "new_identity_seed_hex": new_id_seed.hex(),
                    "old_domain_seed_hex": old_dom_seed.hex(),
                    "new_domain_seed_hex": new_dom_seed.hex(),
                    "old_identity_pub_hex": old_id_pub.hex(),
                    "new_identity_pub_hex": new_id_pub.hex(),
                    "old_domain_pub_hex": old_dom_pub.hex(),
                    "new_domain_pub_hex": new_dom_pub.hex(),
                    "record_pre_sign_json": record,
                },
                "intermediates": {
                    "signature_chain": intermediates_chain,
                },
                "expected": {
                    "signed_record_json": final,
                    "all_four_signatures_verify": all(
                        ok for _, ok in chain_results
                    ),
                    "verification_results": [
                        {"field": field, "verifies": ok}
                        for field, ok in chain_results
                    ],
                },
            },
        ],
    }


# ---- Handshake message vectors (Layer 4) ------------------------------------


HANDSHAKE_PREFIX = b"SEMP-HANDSHAKE:"


def handshake_canonical_with_blank_signature(message: dict, signature_field: str = "server_signature") -> bytes:
    """Canonical bytes of a handshake message with the named signature field
    blanked. Per ENVELOPE.md §4.3, the canonical form sorts keys at every
    nesting level and emits no insignificant whitespace; the same rules
    apply to handshake messages."""
    m = copy.deepcopy(message)
    if signature_field in m:
        m[signature_field] = ""
    return canonical_json(m)


def handshake_sign(message: dict, server_priv: bytes, signature_field: str = "server_signature") -> tuple[dict, dict]:
    canonical = handshake_canonical_with_blank_signature(message, signature_field)
    prefixed = HANDSHAKE_PREFIX + canonical
    sig = ed25519_sign(server_priv, prefixed)
    import base64

    signed = copy.deepcopy(message)
    signed[signature_field] = base64.b64encode(sig).decode("ascii")
    inter = {
        "canonical_with_blanked_signature_utf8": canonical.decode("utf-8"),
        "signing_input_prefix_utf8": HANDSHAKE_PREFIX.decode("utf-8"),
        "signing_input_hex": prefixed.hex(),
        "signature_hex": sig.hex(),
    }
    return signed, inter


def handshake_verify(message: dict, server_pub: bytes, signature_field: str = "server_signature") -> bool:
    import base64

    sig_b64 = message[signature_field]
    sig = base64.b64decode(sig_b64)
    canonical = handshake_canonical_with_blank_signature(message, signature_field)
    prefixed = HANDSHAKE_PREFIX + canonical
    return ed25519_verify(server_pub, sig, prefixed)


def build_handshake_messages_json() -> dict:
    """Layer 4 vectors covering canonical bytes and Ed25519 signature for
    the four-step handshake (init, response, confirm, accepted) plus a
    rejection. Baseline suite only; PQ payloads differ only in the
    advertised algorithm strings and ephemeral_key sizes — the canonical
    bytes / signature construction is identical."""
    import base64

    server_domain_seed = bytes([0x21] * 32)
    server_domain_pub = ed25519_pubkey_from_priv(server_domain_seed)
    server_domain_fp = fingerprint_hex(server_domain_pub)

    # --- Message 1: init / client (NOT signed) -------------------------------
    init_msg = {
        "type": "SEMP_HANDSHAKE",
        "step": "init",
        "party": "client",
        "version": "1.0.0",
        "nonce": "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqs=",
        "transport": "ws",
        "client_ephemeral_key": {
            "algorithm": "x25519-chacha20-poly1305",
            "key": "Y2xpZW50LWVwaGVtZXJhbC1rZXk=",
            "key_id": "client-eph-fp",
        },
        "capabilities": {
            "encryption_algorithms": [
                "pq-kyber768-x25519",
                "x25519-chacha20-poly1305",
            ],
            "extensions": [
                "semp.dev/device-sync",
                "semp.dev/large-attachment",
            ],
        },
        "extensions": {},
    }
    init_canonical = canonical_json(init_msg)

    init_vector = {
        "id": "handshake-init-canonical",
        "description": (
            "Pinned ClientInit (party=client, step=init). The init message "
            "is anonymous and NOT signed per §2.2 — verification of its "
            "integrity occurs in message 3 via the confirmation_hash. The "
            "vector pins the canonical bytes used both for the "
            "confirmation_hash input and for any implementation that needs "
            "to reproduce the wire format."
        ),
        "spec_reference": "VECTORS.md §17.8; HANDSHAKE.md §2.2",
        "inputs": {"message_json": init_msg},
        "expected": {
            "canonical_utf8": init_canonical.decode("utf-8"),
            "is_signed": False,
        },
    }

    # --- Message 2: response / server (server-signed) ------------------------
    response_msg = {
        "type": "SEMP_HANDSHAKE",
        "step": "response",
        "party": "server",
        "version": "1.0.0",
        "session_id": "01J7SESSION0000000000000000",
        "client_nonce": "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqs=",
        "server_nonce": "u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s=",
        "server_ephemeral_key": {
            "algorithm": "x25519-chacha20-poly1305",
            "key": "c2VydmVyLWVwaGVtZXJhbC1rZXk=",
            "key_id": "server-eph-fp",
        },
        "server_identity_proof": {
            "domain": "example.com",
            "key_id": server_domain_fp,
            "signature": "PINNED-IDENTITY-PROOF-SIGNATURE-BYTES",
        },
        "negotiated": {
            "encryption_algorithm": "x25519-chacha20-poly1305",
            "extensions": [
                "semp.dev/device-sync",
                "semp.dev/large-attachment",
            ],
            "max_envelope_size": 26214400,
        },
        "server_signature": "",
        "extensions": {},
    }
    response_signed, response_inter = handshake_sign(response_msg, server_domain_seed)
    assert handshake_verify(response_signed, server_domain_pub)

    response_vector = {
        "id": "handshake-response-signed",
        "description": (
            "Pinned ServerResponse (party=server, step=response). Outer "
            "server_signature is computed over canonical(message) prefixed "
            "with SEMP-HANDSHAKE:, with server_signature.value blanked "
            "before canonicalization. The inner server_identity_proof "
            "carries its own signature over (server_ephemeral_key || "
            "nonces) per §2.3 and is left as a pinned placeholder string "
            "in this vector (the inner-signature construction is exercised "
            "separately when used by future identity-proof vectors)."
        ),
        "spec_reference": "VECTORS.md §17.8; HANDSHAKE.md §2.3",
        "inputs": {
            "server_domain_seed_hex": server_domain_seed.hex(),
            "server_domain_pub_hex": server_domain_pub.hex(),
            "server_domain_key_id": server_domain_fp,
            "message_pre_sign_json": response_msg,
        },
        "intermediates": response_inter,
        "expected": {
            "signed_message_json": response_signed,
            "outer_server_signature_b64": response_signed["server_signature"],
            "outer_signature_verifies": True,
        },
    }

    # --- Message 3: confirm / client (NOT outer-signed) ----------------------
    confirm_msg = {
        "type": "SEMP_HANDSHAKE",
        "step": "confirm",
        "party": "client",
        "version": "1.0.0",
        "session_id": "01J7SESSION0000000000000000",
        "confirmation_hash": "HCOwn5wOk9vB3DGp2dxMaABhkbXBLT3/oKFT9elyzD0=",
        "identity_proof": "PINNED-OPAQUE-CIPHERTEXT-OF-IDENTITY-PROOF-BLOCK",
        "extensions": {},
    }
    confirm_canonical = canonical_json(confirm_msg)
    confirm_vector = {
        "id": "handshake-confirm-canonical",
        "description": (
            "Pinned ClientConfirm. The outer message has no signature; "
            "authentication of the client comes from the inner "
            "identity_proof block (a JSON object encrypted under K_enc_c2s, "
            "left here as an opaque pinned string). The "
            "confirmation_hash field MUST equal "
            "SHA-256(canonical(init) || canonical(response)) per §17.1 — "
            "the value here matches the §5.1 confirmation-hash vector."
        ),
        "spec_reference": "VECTORS.md §17.8; HANDSHAKE.md §2.5",
        "inputs": {"message_json": confirm_msg},
        "expected": {
            "canonical_utf8": confirm_canonical.decode("utf-8"),
            "confirmation_hash_matches_§5.1_vector": True,
            "is_outer_signed": False,
        },
    }

    # --- Message 4: accepted / server (server-signed) ------------------------
    accepted_msg = {
        "type": "SEMP_HANDSHAKE",
        "step": "accepted",
        "party": "server",
        "version": "1.0.0",
        "session_id": "01J7SESSION0000000000000000",
        "session_ttl": 300,
        "permissions": ["send", "receive"],
        "resumption_ticket": {
            "value": "PINNED-RESUMPTION-TICKET-OPAQUE-BYTES",
            "expires_at": "2026-05-15T09:00:00Z",
        },
        "server_signature": "",
        "extensions": {},
    }
    accepted_signed, accepted_inter = handshake_sign(accepted_msg, server_domain_seed)
    assert handshake_verify(accepted_signed, server_domain_pub)

    accepted_vector = {
        "id": "handshake-accepted-signed",
        "description": (
            "Pinned ServerAccepted (party=server, step=accepted) carrying "
            "session_ttl, permissions, and a resumption_ticket. Signed "
            "the same way as the response message: SEMP-HANDSHAKE: prefix "
            "over canonical(message) with server_signature blanked."
        ),
        "spec_reference": "VECTORS.md §17.8; HANDSHAKE.md §2.7",
        "inputs": {
            "server_domain_seed_hex": server_domain_seed.hex(),
            "server_domain_pub_hex": server_domain_pub.hex(),
            "server_domain_key_id": server_domain_fp,
            "message_pre_sign_json": accepted_msg,
        },
        "intermediates": accepted_inter,
        "expected": {
            "signed_message_json": accepted_signed,
            "server_signature_b64": accepted_signed["server_signature"],
            "signature_verifies": True,
        },
    }

    # --- Rejection: rejected / server (server-signed) ------------------------
    rejected_msg = {
        "type": "SEMP_HANDSHAKE",
        "step": "rejected",
        "party": "server",
        "version": "1.0.0",
        "session_id": "01J7SESSION0000000000000000",
        "reason_code": "auth_failed",
        "reason": "Identity signature could not be verified.",
        "server_signature": "",
        "extensions": {},
    }
    rejected_signed, rejected_inter = handshake_sign(rejected_msg, server_domain_seed)
    assert handshake_verify(rejected_signed, server_domain_pub)

    rejected_vector = {
        "id": "handshake-rejected-signed",
        "description": (
            "Pinned ServerRejected (step=rejected). Same construction as "
            "accepted; the message body carries reason_code and a "
            "human-readable reason instead of permissions / "
            "resumption_ticket."
        ),
        "spec_reference": "VECTORS.md §17.8; HANDSHAKE.md §2.7",
        "inputs": {
            "server_domain_seed_hex": server_domain_seed.hex(),
            "server_domain_pub_hex": server_domain_pub.hex(),
            "server_domain_key_id": server_domain_fp,
            "message_pre_sign_json": rejected_msg,
        },
        "intermediates": rejected_inter,
        "expected": {
            "signed_message_json": rejected_signed,
            "server_signature_b64": rejected_signed["server_signature"],
            "signature_verifies": True,
        },
    }

    return {
        "version": "1.0.0",
        "category": "handshake-messages",
        "description": (
            "Layer 4 vectors covering the canonical bytes and Ed25519 "
            "signature path for the four-step handshake (init, response, "
            "confirm, accepted) plus a rejection. Server-signed messages "
            "use the SEMP-HANDSHAKE: domain-separation prefix over "
            "canonical(message) with the named signature field blanked. "
            "Init and Confirm have no outer signature (init is anonymous "
            "by design; confirm authenticates via the inner encrypted "
            "identity_proof block, which is opaque ciphertext at the "
            "outer message level)."
        ),
        "spec_reference": "VECTORS.md §17.8; HANDSHAKE.md §2; ENVELOPE.md §4.3",
        "construction": {
            "domain_separation_prefix_utf8": "SEMP-HANDSHAKE:",
            "canonical_form": (
                "Per ENVELOPE.md §4.3: sorted keys at every nesting level, "
                "no insignificant whitespace, UTF-8 encoding. Apply with "
                "the relevant signature field set to \"\" before signing."
            ),
            "signed_messages": ["response", "accepted", "rejected"],
            "unsigned_outer_messages": ["init", "confirm"],
        },
        "vectors": [
            init_vector,
            response_vector,
            confirm_vector,
            accepted_vector,
            rejected_vector,
        ],
    }


# ---- Negative envelope-rejection vectors (Layer 3 must-reject) -------------


def build_negative_envelope_rejection_json() -> dict:
    """Three concrete must-reject cases that exercise the §7.2 decryption
    flow's rejection paths:

      1. envelope_expired       (step 2: postmark.expires in past)
      2. seal_invalid           (step 1: seal.signature does not verify)
      3. session_mac_invalid    (step 4: seal.session_mac does not verify)

    Each vector is built from a small but otherwise well-formed envelope so
    the rejection is unambiguously attributable to the targeted field, not
    to a confounding error somewhere else in the structure.
    """
    import base64

    sender_identity_seed = bytes([0x91] * 32)
    sender_identity_pub = ed25519_pubkey_from_priv(sender_identity_seed)
    sender_identity_fp = fingerprint_hex(sender_identity_pub)
    sender_domain_seed = bytes([0x92] * 32)
    sender_domain_pub = ed25519_pubkey_from_priv(sender_domain_seed)
    sender_domain_fp = fingerprint_hex(sender_domain_pub)

    recipient_priv = bytes([0x93] * 32)
    recipient_pub = x25519_pubkey_from_priv(recipient_priv)
    recipient_fp = fingerprint_hex(recipient_pub)

    K_brief = bytes([0x94] * 32)
    K_enclosure = bytes([0x95] * 32)
    brief_nonce = bytes([0x96] * 12)
    enclosure_nonce = bytes([0x97] * 12)
    K_env_mac = bytes([0x98] * 32)
    eph_priv_brief = bytes([0x99] * 32)
    eph_priv_enclosure = bytes([0x9A] * 32)

    postmark_id = "01J7NEGPOSTMARKIDXXXXXXXXXXX"
    session_id = "01J7NEGSESSIONIDXXXXXXXXXXXX"

    brief = {
        "message_id": "negative-test-msg",
        "from": "sender@example",
        "to": ["recipient@example"],
        "sent_at": "2026-05-08T10:00:00Z",
    }
    enclosure_pre_sign = {
        "subject": "Negative test",
        "content_type": "text/plain",
        "body": {"text/plain": "VGVzdA=="},
        "attachments": [],
        "forwarded_from": None,
        "extensions": {},
        "sender_signature": {
            "algorithm": "ed25519",
            "key_id": sender_identity_fp,
            "value": "",
        },
    }
    enclosure_signed, _ = sender_signature_compute(
        enclosure_pre_sign, sender_identity_seed
    )

    brief_blob = encrypt_brief_or_enclosure(
        K_brief, brief_nonce, canonical_json(brief), postmark_id
    )
    enclosure_blob = encrypt_brief_or_enclosure(
        K_enclosure, enclosure_nonce, canonical_json(enclosure_signed), postmark_id
    )

    wrapped_brief, _ = seal_wrap_baseline(K_brief, recipient_pub, eph_priv_brief)
    wrapped_enclosure, _ = seal_wrap_baseline(
        K_enclosure, recipient_pub, eph_priv_enclosure
    )

    def make_envelope(*, expires: str) -> dict:
        env = {
            "type": "SEMP_ENVELOPE",
            "version": "1.0.0",
            "postmark": {
                "id": postmark_id,
                "session_id": session_id,
                "from_domain": "example",
                "to_domain": "example",
                "expires": expires,
                "extensions": {},
            },
            "seal": {
                "algorithm": "x25519-chacha20-poly1305",
                "key_id": sender_domain_fp,
                "signature": "",
                "session_mac": "",
                "brief_recipients": {recipient_fp: wrapped_brief},
                "enclosure_recipients": {recipient_fp: wrapped_enclosure},
                "extensions": {},
            },
            "brief": brief_blob,
            "enclosure": enclosure_blob,
        }
        canonical = envelope_canonical_for_signature(env)
        sig = ed25519_sign(sender_domain_seed, SEAL_SIGNATURE_PREFIX + canonical)
        mac = hmac_sha256(K_env_mac, canonical)
        env["seal"]["signature"] = base64.b64encode(sig).decode("ascii")
        env["seal"]["session_mac"] = base64.b64encode(mac).decode("ascii")
        return env

    # Sanity baseline: a fully valid envelope that should pass §7.2 steps 1
    # and 4. We mutate copies of this for each negative case.
    valid_env = make_envelope(expires="2026-12-31T23:59:59Z")
    valid_canonical = envelope_canonical_for_signature(valid_env)
    valid_sig = base64.b64decode(valid_env["seal"]["signature"])
    valid_mac = base64.b64decode(valid_env["seal"]["session_mac"])
    assert ed25519_verify(
        sender_domain_pub, valid_sig, SEAL_SIGNATURE_PREFIX + valid_canonical
    )
    assert hmac_sha256(K_env_mac, valid_canonical) == valid_mac

    # Vector 1: envelope_expired.
    expired_env = make_envelope(expires="2020-01-01T00:00:00Z")
    # Step 1 (signature) still passes because we re-signed over the
    # expired envelope's canonical bytes. Step 2 (expires) is what rejects.
    expired_canonical = envelope_canonical_for_signature(expired_env)
    expired_sig = base64.b64decode(expired_env["seal"]["signature"])
    expired_step_1 = ed25519_verify(
        sender_domain_pub, expired_sig, SEAL_SIGNATURE_PREFIX + expired_canonical
    )

    expired_vector = {
        "id": "envelope-expired",
        "description": (
            "A well-formed envelope whose postmark.expires is in the past. "
            "§7.2 step 1 (seal.signature verification) still passes — the "
            "envelope was correctly signed over its own canonical bytes — "
            "but step 2 MUST reject with reason_code envelope_expired "
            "before any further processing."
        ),
        "spec_reference": "VECTORS.md §17.7; ENVELOPE.md §7.2 step 2; ERRORS.md envelope_expired",
        "inputs": {
            "envelope_json": expired_env,
            "sender_domain_pub_hex": sender_domain_pub.hex(),
            "K_env_mac_hex": K_env_mac.hex(),
            "now_iso": "2026-05-08T10:00:00Z",
        },
        "expected": {
            "step_1_seal_signature_verifies": expired_step_1,
            "step_2_postmark_expires_in_past": True,
            "rejection_step": "step 2 (postmark.expires)",
            "rejection_reason_code": "envelope_expired",
        },
    }

    # Vector 2: seal_invalid (bad signature).
    bad_sig_env = copy.deepcopy(valid_env)
    # Replace seal.signature with a different (valid Ed25519 length but
    # wrong) value. We pick the signature of an UNRELATED message so it has
    # legitimate format but doesn't verify against the canonical envelope.
    bogus_signature = ed25519_sign(sender_domain_seed, b"unrelated payload")
    bad_sig_env["seal"]["signature"] = base64.b64encode(bogus_signature).decode("ascii")
    bad_sig_canonical = envelope_canonical_for_signature(bad_sig_env)
    bad_sig_step_1 = ed25519_verify(
        sender_domain_pub, bogus_signature, SEAL_SIGNATURE_PREFIX + bad_sig_canonical
    )
    assert not bad_sig_step_1

    bad_sig_vector = {
        "id": "seal-signature-invalid",
        "description": (
            "Take the valid envelope and replace seal.signature with a "
            "well-formed but unrelated Ed25519 signature (signed over "
            "different bytes). §7.2 step 1 MUST reject with reason_code "
            "seal_invalid before any further processing. Routing servers "
            "perform this verification per §4.3 'Two-Layer Verification'."
        ),
        "spec_reference": "VECTORS.md §17.7; ENVELOPE.md §7.2 step 1; ERRORS.md seal_invalid",
        "inputs": {
            "envelope_json": bad_sig_env,
            "sender_domain_pub_hex": sender_domain_pub.hex(),
        },
        "expected": {
            "step_1_seal_signature_verifies": bad_sig_step_1,
            "rejection_step": "step 1 (seal.signature)",
            "rejection_reason_code": "seal_invalid",
        },
    }

    # Vector 3: session_mac_invalid.
    bad_mac_env = copy.deepcopy(valid_env)
    # Replace session_mac with an HMAC computed under a different key (so
    # the value has correct length and shape, but verification under the
    # actual K_env_mac fails).
    other_key = bytes([0xCC] * 32)
    bogus_mac = hmac_sha256(other_key, valid_canonical)
    bad_mac_env["seal"]["session_mac"] = base64.b64encode(bogus_mac).decode("ascii")
    # The seal.signature still verifies because we changed only session_mac
    # AFTER the signature was computed... actually no, both are blanked
    # during canonicalization, so changing session_mac post-signature does
    # NOT invalidate seal.signature. Verify that explicitly.
    bad_mac_canonical = envelope_canonical_for_signature(bad_mac_env)
    bad_mac_sig = base64.b64decode(bad_mac_env["seal"]["signature"])
    bad_mac_step_1 = ed25519_verify(
        sender_domain_pub, bad_mac_sig, SEAL_SIGNATURE_PREFIX + bad_mac_canonical
    )
    assert bad_mac_step_1, "seal.signature should still verify when only session_mac is mutated"
    expected_mac_step_4 = hmac_sha256(K_env_mac, bad_mac_canonical)
    bad_mac_step_4 = expected_mac_step_4 == bogus_mac
    assert not bad_mac_step_4

    bad_mac_vector = {
        "id": "session-mac-invalid",
        "description": (
            "Take the valid envelope and replace seal.session_mac with an "
            "HMAC computed under a different key. §4.3 canonicalization "
            "blanks both seal.signature and seal.session_mac before either "
            "is computed, so seal.signature still verifies (step 1 passes) "
            "— this is the receiving-server-only check at step 4. The "
            "recipient server MUST reject with reason_code "
            "session_mac_invalid; the rejection is distinct from "
            "seal_invalid because routing servers cannot perform this "
            "check (they do not hold K_env_mac)."
        ),
        "spec_reference": "VECTORS.md §17.7; ENVELOPE.md §7.2 step 4; ERRORS.md session_mac_invalid",
        "inputs": {
            "envelope_json": bad_mac_env,
            "sender_domain_pub_hex": sender_domain_pub.hex(),
            "K_env_mac_hex": K_env_mac.hex(),
            "wrong_key_used_to_forge_mac_hex": other_key.hex(),
        },
        "expected": {
            "step_1_seal_signature_verifies": bad_mac_step_1,
            "step_4_session_mac_verifies": bad_mac_step_4,
            "rejection_step": "step 4 (seal.session_mac)",
            "rejection_reason_code": "session_mac_invalid",
        },
    }

    return {
        "version": "1.0.0",
        "category": "negative-envelope-rejection",
        "description": (
            "Concrete must-reject cases for the §7.2 decryption flow. "
            "Each vector targets exactly one §7.2 step so the rejection "
            "is unambiguously attributable; rejection_reason_code is "
            "drawn from ERRORS.md and exercised in rejection-codes.json. "
            "Every byte is reproducible via the deterministic compose "
            "path used elsewhere in Layer 3."
        ),
        "spec_reference": "VECTORS.md §17.7; ENVELOPE.md §7.2; ERRORS.md",
        "vectors": [expired_vector, bad_sig_vector, bad_mac_vector],
    }


# ---- Recipient status vectors (§15) -----------------------------------------


def build_recipient_status_json() -> dict:
    visibility = [
        ("nobody", "any sender", False),
        ("everyone", "any sender", True),
        ("users", "listed user address", True),
        ("users", "unlisted user address", False),
        ("domains", "address at listed domain", True),
        ("domains", "address at unlisted domain", False),
        ("servers", "routed through listed server", True),
        ("servers", "not routed through listed server", False),
    ]
    delivery = [
        ("available", True, "delivered", None),
        ("away", True, "delivered", "with status if visible"),
        ("do_not_disturb", True, "delivered", "with status if visible"),
        ("away", False, "rejected", "seal_invalid"),
    ]

    return {
        "version": "1.0.0",
        "category": "recipient-status",
        "description": (
            "Recipient-status visibility rules and the rule that recipient "
            "status MUST NOT influence the delivery decision. Source of "
            "truth: VECTORS.md §15."
        ),
        "spec_reference": "VECTORS.md §15; DELIVERY.md §1.6",
        "vectors": [
            {
                "id": "status-visibility-rules",
                "description": (
                    "When the sender does NOT match the recipient's "
                    "visibility configuration, the acknowledgment MUST omit "
                    "the recipient_status field entirely. Omission MUST be "
                    "indistinguishable from a recipient who has not "
                    "configured status at all."
                ),
                "spec_reference": "VECTORS.md §15.1; DELIVERY.md §1.6",
                "samples": [
                    {
                        "visibility_mode": mode,
                        "sender_identity": sender,
                        "status_included": included,
                    }
                    for mode, sender, included in visibility
                ],
            },
            {
                "id": "status-does-not-affect-delivery",
                "description": (
                    "Status MUST NOT influence the delivery decision. An "
                    "invalid envelope is rejected regardless of recipient "
                    "status; a valid envelope is delivered regardless of "
                    "recipient status."
                ),
                "spec_reference": "VECTORS.md §15.2; DELIVERY.md §1.6",
                "samples": [
                    {
                        "recipient_state": state,
                        "envelope_valid": valid,
                        "expected_acknowledgment": ack,
                        "note": note,
                    }
                    for state, valid, ack, note in delivery
                ],
            },
        ],
    }


# ---------------------------------------------------------------------------
# Drive

OUTDIR = Path(__file__).resolve().parent.parent / "v1.0.0"


def serialize(obj: dict) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


def write_or_check(path: Path, obj: dict, mode: str) -> bool:
    """Returns True on match (verify) / write success; False on diff (verify)."""
    new = serialize(obj)
    if mode == "write":
        path.write_text(new, encoding="utf-8")
        print(f"WROTE {path.relative_to(OUTDIR.parent.parent)}")
        return True
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    if existing == new:
        print(f"OK    {path.relative_to(OUTDIR.parent.parent)}")
        return True
    print(f"DIFF  {path.relative_to(OUTDIR.parent.parent)}")
    if mode == "diff":
        for line in difflib.unified_diff(
            existing.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=str(path) + " (on disk)",
            tofile=str(path) + " (generated)",
        ):
            sys.stdout.write(line)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    g = parser.add_mutually_exclusive_group()
    g.add_argument("--verify", action="store_true", help="exit non-zero on diff")
    g.add_argument("--diff", action="store_true", help="show diff but don't write")
    args = parser.parse_args()

    mode = "write"
    if args.verify:
        mode = "verify"
    elif args.diff:
        mode = "diff"

    OUTDIR.mkdir(parents=True, exist_ok=True)

    # Build vectors; some are inputs to others.
    hkdf = build_hkdf_json()
    baseline_keys = {
        k.removesuffix("_hex"): bytes.fromhex(v)
        for k, v in hkdf["vectors"][0]["expected"]["keys"].items()
    }
    env_canonical = build_envelope_canonical_json()
    minimal_canonical = env_canonical["vectors"][0]["expected"]["canonical_utf8"].encode(
        "utf-8"
    )
    session_mac = build_session_mac_json(baseline_keys, minimal_canonical)
    confirmation = build_confirmation_hash_json()

    files = [
        (OUTDIR / "hkdf.json", hkdf),
        (OUTDIR / "envelope-canonical.json", env_canonical),
        (OUTDIR / "envelope-buckets.json", build_envelope_buckets_json()),
        (OUTDIR / "session-mac.json", session_mac),
        (OUTDIR / "confirmation-hash.json", confirmation),
        (OUTDIR / "pow.json", build_pow_json()),
        (OUTDIR / "discovery.json", build_discovery_json()),
        (OUTDIR / "rejection-codes.json", build_rejection_codes_json()),
        (OUTDIR / "extension-entries.json", build_extension_entries_json()),
        (OUTDIR / "session-lifecycle.json", build_session_lifecycle_json()),
        (OUTDIR / "delivery-status.json", build_delivery_status_json()),
        (OUTDIR / "key-revocation.json", build_key_revocation_json()),
        (OUTDIR / "device-certificates.json", build_device_certificates_json()),
        (OUTDIR / "recipient-status.json", build_recipient_status_json()),
        (OUTDIR / "seal-roundtrip.json", build_seal_roundtrip_json()),
        (OUTDIR / "sender-signature.json", build_sender_signature_json()),
        (OUTDIR / "forwarding.json", build_forwarding_json()),
        (OUTDIR / "envelope-roundtrip.json", build_envelope_roundtrip_json()),
        (OUTDIR / "delivery-receipt.json", build_delivery_receipt_json()),
        (OUTDIR / "large-attachment.json", build_large_attachment_json()),
        (OUTDIR / "negative-envelope-rejection.json", build_negative_envelope_rejection_json()),
        (OUTDIR / "handshake-messages.json", build_handshake_messages_json()),
        (OUTDIR / "account-closure.json", build_account_closure_json()),
        (OUTDIR / "user-policy.json", build_user_policy_json()),
        (OUTDIR / "migration.json", build_migration_json()),
        (OUTDIR / "discovery-signed.json", build_discovery_signed_json()),
        (OUTDIR / "transparency.json", build_transparency_json()),
        (OUTDIR / "session-resumption.json", build_session_resumption_json()),
        (OUTDIR / "first-contact-token.json", build_first_contact_token_json()),
        (OUTDIR / "clock-tolerance.json", build_clock_tolerance_json()),
        (OUTDIR / "account-recovery.json", build_account_recovery_json()),
    ]

    ok = True
    for path, obj in files:
        if not write_or_check(path, obj, mode):
            ok = False

    if mode in ("verify", "diff") and not ok:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
