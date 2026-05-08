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
    """ENVELOPE.md §4.4.1: next power of 2 with floor 2 (or 1 for the
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
        "spec_reference": "VECTORS.md §3.3, §3.4; ENVELOPE.md §2.4.1, §4.4.1",
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
                "spec_reference": "VECTORS.md §3.4; ENVELOPE.md §4.4.1",
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
