# Copyright © 2025-2026 CERTCRYPT, Inc., its affiliates or licensors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Author fixtures/primitives/ecdsa-p256-deterministic/vectors.json from the
generator's own primitives and python-ecdsa (run with
PYTHONPATH=<conformance>/generator).

Deterministic: every value is a pure function of the keys and messages below
(RFC 6979 leaves no randomness in the signature), so a re-run reproduces the
committed file byte for byte. emit_primitives.py re-derives every nonce and
signature with its own RFC 6979 code rather than trusting this script."""
import base64
import hashlib
import json
import sys
from collections import OrderedDict

from ecdsa import NIST256p, SigningKey
from ecdsa.rfc6979 import generate_k
from ecdsa.util import sigencode_strings

import primitives as P

OUT = sys.argv[1]

N = NIST256p.order
HALF_N = N >> 1


# ── keys ────────────────────────────────────────────────────────────────────


def issuer_scalar(master: bytes) -> int:
    """issuer-key-derivation/1: the key an issuer signs base_certificates with."""
    material = hashlib.sha3_256(master + b"issuer-cert-key/p256").digest()
    return int.from_bytes(material, "big") % (N - 1) + 1


def ceremony_scalar(seed: bytes) -> int:
    """key-derivation/1: the P-256 half of a ceremony seed's composite key."""
    priv, _ = P.p256_keypair_from_seed(seed)
    return priv.private_numbers().private_value


def key(source: str, **kw) -> OrderedDict:
    if source == "issuer-key-derivation":
        d = issuer_scalar(bytes.fromhex(kw["master_seed_hex"]))
        k = OrderedDict([("source", source), ("master_seed_hex", kw["master_seed_hex"])])
    elif source == "key-derivation":
        d = ceremony_scalar(bytes.fromhex(kw["seed_hex"]))
        k = OrderedDict([("source", source), ("seed_hex", kw["seed_hex"])])
    elif source == "scalar":
        d = kw["d"]
        k = OrderedDict([("source", source)])
    else:
        raise ValueError(source)
    vk = SigningKey.from_secret_exponent(d, curve=NIST256p).get_verifying_key()
    k["scalar_hex"] = d.to_bytes(32, "big").hex()
    k["expected_pub_p256_b64"] = base64.b64encode(b"\x04" + vk.to_string()).decode("ascii")
    return k


COUNTING = bytes(range(32)).hex()
KEYS = {
    "ikd-counting": key("issuer-key-derivation", master_seed_hex=COUNTING),
    "ikd-42": key("issuer-key-derivation", master_seed_hex="42" * 32),
    "ikd-ff": key("issuer-key-derivation", master_seed_hex="ff" * 32),
    "kd-counting": key("key-derivation", seed_hex=COUNTING),
    "kd-zero": key("key-derivation", seed_hex="00" * 32),
    "scalar-1": key("scalar", d=1),
    "scalar-n-1": key("scalar", d=N - 1),
}


# ── signing ─────────────────────────────────────────────────────────────────


def sign(d: int, message: bytes) -> dict:
    h = hashlib.sha3_256(message).digest()
    sk = SigningKey.from_secret_exponent(d, curve=NIST256p)
    k = generate_k(N, d, hashlib.sha3_256, h)
    r, s = sk.sign_digest_deterministic(h, hashfunc=hashlib.sha3_256, sigencode=sigencode_strings)
    r_i, s_i = int.from_bytes(r, "big"), int.from_bytes(s, "big")
    high = s_i > HALF_N
    if high:
        s_i = N - s_i
    raw = r_i.to_bytes(32, "big") + s_i.to_bytes(32, "big")
    return {
        "prehash": h.hex(),
        "k": k.to_bytes(32, "big").hex(),
        "low_s_applied": high,
        "sig": raw,
    }


def message_vector(name, why, key_ref, message: bytes, utf8: bool = False) -> OrderedDict:
    k = KEYS[key_ref]
    sig = sign(int(k["scalar_hex"], 16), message)
    out = OrderedDict([("name", name), ("why", why), ("key", key_ref)])
    if utf8:
        out["message_utf8"] = message.decode("utf-8")
    out["message_hex"] = message.hex()
    out["expected_prehash_sha3_256_hex"] = sig["prehash"]
    out["expected_nonce_k_hex"] = sig["k"]
    out["expected_low_s_applied"] = sig["low_s_applied"]
    out["expected_sig_hex"] = sig["sig"].hex()
    out["expected_sig_b64"] = base64.b64encode(sig["sig"]).decode("ascii")
    return out


def composite_case(name, why, key_ref, payload_digest_hex) -> OrderedDict:
    k = KEYS[key_ref]
    m = P.composite_m_prime(P.PROFILE_P256_MLDSA65, payload_digest_hex)
    sig = sign(int(k["scalar_hex"], 16), m)
    return OrderedDict(
        [
            ("name", name),
            ("why", why),
            ("key", key_ref),
            ("composite_alg_id", P.PROFILE_P256_MLDSA65),
            ("payload_canon_digest_hex", payload_digest_hex),
            ("expected_m_prime_hex", m.hex()),
            (
                "expected_ecdsa_component",
                OrderedDict(
                    [
                        ("alg", "ECDSA-P256-SHA3-256"),
                        ("encoding", "raw-rs-64"),
                        ("low_s", True),
                        ("sig_b64", base64.b64encode(sig["sig"]).decode("ascii")),
                    ]
                ),
            ),
            ("expected_low_s_applied", sig["low_s_applied"]),
        ]
    )


LONG = (bytes(range(256)) * 4)[:1000]
M_CANON = P.composite_m_prime(P.PROFILE_P256_MLDSA65, "aa" * 32)

vectors = [
    message_vector("issuer key, counting seed, composite M'", "the exact message an issuer's base_certificate signature covers",
                   "ikd-counting", M_CANON),
    message_vector("issuer key, counting seed, abc", "a short text message", "ikd-counting", b"abc", utf8=True),
    message_vector("issuer key, counting seed, empty message", "zero bytes still hash to a 32-byte prehash and sign",
                   "ikd-counting", b""),
    message_vector("issuer key, 0x42 seed, abc", "a second issuer key over the same message: a different nonce and signature",
                   "ikd-42", b"abc", utf8=True),
    message_vector("issuer key, all-ff seed, every byte value", "a binary message covering 0x00..0xff",
                   "ikd-ff", bytes(range(256))),
    message_vector("ceremony key, counting seed, composite M'", "the key-derivation/1 key over the same M' as the first vector",
                   "kd-counting", M_CANON),
    message_vector("ceremony key, all-zero seed, abc", "the key-derivation/1 key of the all-zero seed",
                   "kd-zero", b"abc", utf8=True),
    message_vector("scalar 1, abc", "the smallest private scalar", "scalar-1", b"abc", utf8=True),
    message_vector("scalar n-1, abc", "the largest private scalar", "scalar-n-1", b"abc", utf8=True),
    message_vector("scalar n-1, 1000-byte message", "a message longer than one SHA3-256 block",
                   "scalar-n-1", LONG),
    message_vector("issuer key, 0x42 seed, sample", "the RFC 6979 A.2.5 message text, under this profile's SHA3-256",
                   "ikd-42", b"sample", utf8=True),
    message_vector("issuer key, 0x42 seed, test", "the second RFC 6979 A.2.5 message text, under this profile's SHA3-256",
                   "ikd-42", b"test", utf8=True),
]

composite_cases = [
    composite_case("issuer key, counting seed", "the ECDSA component of a composite as it goes on the wire",
                   "ikd-counting", "aa" * 32),
    composite_case("issuer key, 0x42 seed", "another issuer, another payload digest", "ikd-42",
                   hashlib.sha3_256(b"certcrypt/conformance/ecdsa-p256-deterministic").hexdigest()),
    composite_case("ceremony key, counting seed", "a key-derivation/1 key signing a composite",
                   "kd-counting", "bb" * 32),
]

# Both branches of low-s normalization must be pinned, or an implementation that
# skips it (or always applies it) passes half the file by luck.
flags = [v["expected_low_s_applied"] for v in vectors]
assert any(flags) and not all(flags), f"low-s coverage incomplete: {flags}"

doc = OrderedDict(
    [
        ("profile", "ecdsa-p256-deterministic/1"),
        (
            "description",
            "ECDSA P-256 signatures as an issuer emits them: SHA3-256 prehash, an RFC 6979 deterministic nonce, "
            "low-s, raw r||s. One key over one message yields exactly one signature, so two implementations "
            "that sign the same base_certificate with the same key emit the same bytes.",
        ),
        (
            "rules",
            OrderedDict(
                [
                    ("curve", "P-256 (secp256r1). n is the group order, G the base point."),
                    (
                        "prehash",
                        "h = SHA3-256(message), 32 bytes. The message is the exact byte string signed; for a composite "
                        "signature it is M' (see composite-m-prime). It is hashed once.",
                    ),
                    (
                        "nonce",
                        "k per RFC 6979 section 3.2 with H = SHA3-256: HMAC-SHA3-256 throughout, qlen = 256, x = the "
                        "private scalar as 32 big-endian bytes, h1 = h, bits2octets(h1) = (int_be(h1) mod n) as 32 "
                        "bytes, no additional data. The first candidate k in [1, n-1] for which r and s are non-zero "
                        "is used.",
                    ),
                    (
                        "signature",
                        "r = x(k*G) mod n; s = k^-1 * (int_be(h) + r*x) mod n.",
                    ),
                    (
                        "low_s",
                        "If s > n/2 (n >> 1), s is replaced by n - s. expected_low_s_applied records whether that "
                        "happened; the nonce is unchanged either way.",
                    ),
                    (
                        "encoding",
                        "raw-rs-64: r || s, 32 bytes each, big-endian. Not DER. In a composite the component is "
                        "{alg: \"ECDSA-P256-SHA3-256\", encoding: \"raw-rs-64\", low_s: true, sig_b64} with standard "
                        "base64 and padding.",
                    ),
                    (
                        "keys",
                        "Each key names its source. issuer-key-derivation: the scalar of that family from "
                        "master_seed_hex. key-derivation: the P-256 scalar of that family from seed_hex. scalar: "
                        "scalar_hex as given. scalar_hex is always written out so an implementation can sign "
                        "without deriving.",
                    ),
                    (
                        "not_the_hmac_hash",
                        "The HMAC hash is SHA3-256, the hash applied to the message. A signer that derives k with "
                        "HMAC-SHA-256 over the same SHA3-256 prehash is deterministic too, and its signatures verify, "
                        "but its bytes are not these. A signer with a random nonce likewise verifies and does not match.",
                    ),
                ]
            ),
        ),
        (
            "why_this_is_a_primitive",
            "Every verifier accepts any valid low-s signature, so a divergence here never fails a verification. "
            "What it breaks is reproducibility: the same issuer, key and certificate produce different bytes in "
            "different implementations, and a test that compares two emissions can only check that each verifies. "
            "Pinning the nonce makes the signature itself comparable.",
        ),
        ("keys", KEYS),
        ("vectors", vectors),
        ("composite_cases", composite_cases),
    ]
)

with open(OUT, "w", encoding="utf-8") as fh:
    json.dump(doc, fh, indent=2, ensure_ascii=False)
    fh.write("\n")
print("keys:", len(KEYS), "vectors:", len(vectors), "composite_cases:", len(composite_cases),
      "low_s_applied:", sum(flags))
