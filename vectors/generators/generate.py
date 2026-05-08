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
