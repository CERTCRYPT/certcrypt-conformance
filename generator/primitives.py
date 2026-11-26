"""
Canonical crypto primitives for the CERTCRYPT conformance generator.

Implements the public rules that produce the committed fixtures: SHA3-256, JCS
(RFC 8785), insertion-ordered canonical JSON, both Merkle schemes, ECDSA P-256
(RFC 6979 deterministic), Ed25519 (RFC 8032 deterministic), and ML-DSA-65
(FIPS 204 deterministic variant). Determinism per generator/DETERMINISM.md.

No dependency on any verifier implementation (README §Language): only hashlib
(SHA3), `cryptography` (Ed25519, key serialization), `ecdsa` (RFC 6979 P-256),
and `dilithium_py` (ML-DSA-65).
"""

import base64
import datetime
import hashlib
import json
import re
from typing import Any

from cryptography.hazmat.primitives import serialization
from dilithium_py.ml_dsa import ML_DSA_65


# ── SHA3-256 ──────────────────────────────────────────────────────────────

def digest_hex_bytes(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def digest_hex_text(text: str) -> str:
    return hashlib.sha3_256(text.encode("utf-8")).hexdigest()


# ── JCS (RFC 8785) ────────────────────────────────────────────────────────
# Lexicographic key sort, no whitespace, ECMAScript number serialization.
# JSON `null` members are PRESERVED (serialized as "key":null) — RFC 8785 does
# NOT drop null-valued members; the Rust reference (serde_json_canonicalizer)
# keeps them, and system-manifest/1 entries carry null members by design
# (valid_until, predecessor_kid, successor_kid, predecessor_signatures,
# predecessor_manifest_fingerprint).

def _jcs_stringify(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("JCS does not support Infinity or NaN")
        # Integers-as-floats serialize without a trailing .0 in ECMAScript.
        if value.is_integer():
            return str(int(value))
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(_jcs_stringify(v) for v in value) + "]"
    if isinstance(value, dict):
        # RFC 8785 §3.2.3: sort keys by UTF-16 code unit. Python's default
        # `sorted()` compares by Unicode CODE POINT, which diverges from UTF-16
        # code-unit order for supplementary-plane keys (a key ≥ U+10000 sorts by
        # its high surrogate 0xD800-0xDBFF, i.e. BELOW the U+E000-U+FFFF range,
        # not above it). The canonical verifier uses JS `Array.sort()` = UTF-16
        # code-unit order; we MUST match it, so key on the UTF-16-BE encoding.
        # (Do NOT "fix" this to a code-point sort — see subject-context-snapshot
        # UTF-16 vector.)
        keys = sorted(value.keys(), key=lambda k: k.encode("utf-16-be"))
        members = [
            json.dumps(k, ensure_ascii=False) + ":" + _jcs_stringify(value[k])
            for k in keys
        ]
        return "{" + ",".join(members) + "}"
    raise ValueError(f"JCS: unsupported type {type(value)}")


def jcs_canonicalize_bytes(obj: Any) -> bytes:
    return _jcs_stringify(obj).encode("utf-8")


# ── Canonical JSON (insertion-ordered, NOT JCS) ───────────────────────────
# Settlement preimages: order is prescribed by the field list, not sorted.
# Equivalent to JS JSON.stringify of an object built in that key order.

def canonical_json_bytes(ordered_fields: list[tuple[str, Any]]) -> bytes:
    obj = dict(ordered_fields)  # Python 3.7+ preserves insertion order
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ── Subject byte-canonicalizers (opaque-byte profiles) ─────────────────────
# subject.text/1 and subject.email/1 operate on the RAW input bytes (the subject
# context is opaque bytes per CCCP/1 §6.2 — no UTF-8 validation, no Unicode
# normalization, no BOM stripping, embedded NUL preserved). Byte-for-byte mirror
# of the canonical verifier ports; pinned by primitives/subject-{text,email}.

def _normalize_crlf(raw: bytes) -> bytes:
    """§11.2 line-ending normalization: single left-to-right pass over the
    ORIGINAL bytes, CRLF longest-match, then lone CR -> CRLF, lone LF -> CRLF."""
    out = bytearray()
    i, n = 0, len(raw)
    while i < n:
        b = raw[i]
        if b == 0x0D and i + 1 < n and raw[i + 1] == 0x0A:
            out += b"\r\n"; i += 2
        elif b == 0x0D:
            out += b"\r\n"; i += 1
        elif b == 0x0A:
            out += b"\r\n"; i += 1
        else:
            out.append(b); i += 1
    return bytes(out)


def canonical_subject_text(raw: bytes) -> bytes:
    """canonical_bytes for subject.text/1 (§11.2 CRLF normalization, then §11.3
    strip the trailing CRLF run and append exactly one CRLF). All other bytes
    preserved. Empty/all-CRLF input -> exactly one CRLF."""
    out = bytearray(_normalize_crlf(raw))
    while out.endswith(b"\r\n"):
        out = out[:-2]
    out += b"\r\n"
    return bytes(out)


def canonical_subject_email(raw: bytes) -> bytes:
    """canonical_bytes for subject.email/1 (subject.email/1 §11):
    §11.2 global CRLF normalization -> §11.3 split at the FIRST CRLF CRLF (the
    4-byte delimiter removed from both sides; absent -> all headers, empty body)
    -> §11.4 RFC 5322 §2.2.3 header unfolding (delete each CRLF immediately
    followed by a WSP byte SP 0x20 / HTAB 0x09, preserve the WSP) -> §11.5 body
    trailing-terminator normalization (non-empty body ends in exactly one CRLF;
    empty body stays empty) -> §11.6 headers || CRLF CRLF || body (delimiter
    always present). Idempotent."""
    msg = _normalize_crlf(raw)
    delim = msg.find(b"\r\n\r\n")
    if delim < 0:
        headers, body = msg, b""
    else:
        headers, body = msg[:delim], msg[delim + 4:]
    uf = bytearray()
    i, n = 0, len(headers)
    while i < n:
        if (
            headers[i] == 0x0D
            and i + 2 < n
            and headers[i + 1] == 0x0A
            and headers[i + 2] in (0x20, 0x09)
        ):
            i += 2  # delete the CRLF; the following WSP is copied next iteration
        else:
            uf.append(headers[i]); i += 1
    headers = bytes(uf)
    if body:
        while body.endswith(b"\r\n"):
            body = body[:-2]
        body += b"\r\n"
    return headers + b"\r\n\r\n" + body


# ── Settlement Merkle (settlement.binding/1) ──────────────────────────────
# leaf = SHA3-256(0x00 || preimage); node = SHA3-256(0x01 || L || R);
# odd width promotes the lone right edge unchanged.

def compute_leaf_hash(canonical_bytes: bytes) -> str:
    return digest_hex_bytes(b"\x00" + canonical_bytes)


def compute_node_hash(left_hex: str, right_hex: str) -> str:
    return digest_hex_bytes(b"\x01" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex))


def compute_merkle_root(leaf_hashes: list[str]) -> str:
    if not leaf_hashes:
        raise ValueError("Cannot compute Merkle root of empty leaf set")
    if len(leaf_hashes) == 1:
        return leaf_hashes[0]
    level = list(leaf_hashes)
    while len(level) > 1:
        nxt: list[str] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(compute_node_hash(level[i], level[i + 1]))
            else:
                nxt.append(level[i])
        level = nxt
    return level[0]


def generate_inclusion_proof(leaf_hashes: list[str], leaf_index: int) -> list[str]:
    if len(leaf_hashes) <= 1:
        return []
    siblings: list[str] = []
    level = list(leaf_hashes)
    idx = leaf_index
    while len(level) > 1:
        has_sibling = (idx % 2 == 1) or (idx + 1 < len(level))
        if has_sibling:
            sibling_idx = idx + 1 if idx % 2 == 0 else idx - 1
            siblings.append(level[sibling_idx])
        nxt: list[str] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(compute_node_hash(level[i], level[i + 1]))
            else:
                nxt.append(level[i])
        level = nxt
        idx //= 2
    return siblings


# ── Collection Merkle (collection.merkle-sha3-256/1) ──────────────────────
# DISTINCT from the settlement Merkle above. The scheme that hides the leaves of
# a subject.collection/1 subject behind one root, per
# collection.merkle-sha3-256/1 §10-13:
#   leaf_preimage = utf8("CERTCRYPT:collection.merkle-sha3-256/1:leaf")
#     || u64be(len(collection_salt)) || collection_salt
#     || u64be(len(leaf_profile)) || leaf_profile
#     || u64be(len(leaf_canonical_bytes)) || leaf_canonical_bytes
#   leaf_hash = SHA3-256(leaf_preimage)
#   node_preimage = utf8("CERTCRYPT:collection.merkle-sha3-256/1:node") || L || R
#     (L, R each 32 raw bytes)  node_hash = SHA3-256(node_preimage)
#   root: 1 leaf -> that leaf_hash; else pair left-to-right, promote a lone
#   right-edge hash unchanged, until one remains. Empty tree is invalid (§12.4).
# NOT interchangeable with the settlement 0x00/0x01 scheme — different preimages,
# different roots (verifier-toolkit/1 §8.5.3).

COLLECTION_MERKLE_SCHEME = "collection.merkle-sha3-256/1"
_COLLECTION_LEAF_TAG = b"CERTCRYPT:collection.merkle-sha3-256/1:leaf"
_COLLECTION_NODE_TAG = b"CERTCRYPT:collection.merkle-sha3-256/1:node"


def _u64be(n: int) -> bytes:
    if not isinstance(n, int) or n < 0:
        raise ValueError(f"u64be requires a non-negative integer, got {n}")
    return n.to_bytes(8, "big")


def collection_leaf_hash(
    collection_salt: bytes, leaf_profile: str, leaf_canonical_bytes: bytes
) -> str:
    """leaf_hash for one collection leaf under `leaf_profile` (lowercase hex).

    `collection_salt` is bound into every leaf (§9-10) so the same leaf set under a
    different salt yields a different root. Opaque bytes here: under
    subject.collection/1 §8 it is the anchor `nonce_hex` as ASCII, but the scheme
    MUST NOT interpret it. An empty salt is rejected — accepting one would silently
    reproduce the unsalted construction.
    """
    if not collection_salt:
        raise ValueError(
            "collection.merkle-sha3-256/1: a non-empty collection salt is required (§9)"
        )
    profile_bytes = leaf_profile.encode("utf-8")
    preimage = (
        _COLLECTION_LEAF_TAG
        + _u64be(len(collection_salt))
        + collection_salt
        + _u64be(len(profile_bytes))
        + profile_bytes
        + _u64be(len(leaf_canonical_bytes))
        + leaf_canonical_bytes
    )
    return digest_hex_bytes(preimage)


def collection_node_hash(left_hex: str, right_hex: str) -> str:
    """node_hash for two child hashes (lowercase hex in, lowercase hex out)."""
    return digest_hex_bytes(
        _COLLECTION_NODE_TAG + bytes.fromhex(left_hex) + bytes.fromhex(right_hex)
    )


def collection_merkle_root(leaf_hashes: list[str]) -> str:
    """Collection root from ordered leaf hashes (§13). Single leaf -> its hash;
    else pair left-to-right, promote a lone right-edge hash unchanged. Empty is
    invalid (§12.4)."""
    if not leaf_hashes:
        raise ValueError(
            "collection.merkle-sha3-256/1: empty tree is invalid (§12.4)"
        )
    level = list(leaf_hashes)
    while len(level) > 1:
        nxt: list[str] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(collection_node_hash(level[i], level[i + 1]))
            else:
                nxt.append(level[i])  # promote lone right-edge hash unchanged (§12.3)
        level = nxt
    return level[0]


def collection_inclusion_proof(leaf_hashes: list[str], leaf_index: int) -> list[str]:
    """Ordered `sibling_hashes` for one leaf's inclusion proof under the
    collection scheme. A promoted lone right-edge node contributes NO sibling,
    so the proof may carry fewer siblings than the tree has levels — the exact
    dual of the inclusion fold a verifier runs."""
    siblings: list[str] = []
    level = list(leaf_hashes)
    idx = leaf_index
    while len(level) > 1:
        is_right = idx % 2 == 1
        has_sibling = is_right or (idx + 1 < len(level))
        if has_sibling:
            sibling_idx = idx - 1 if is_right else idx + 1
            siblings.append(level[sibling_idx])
        nxt: list[str] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(collection_node_hash(level[i], level[i + 1]))
            else:
                nxt.append(level[i])
        level = nxt
        idx //= 2
    return siblings


_HEX64_RE = re.compile(r"[0-9a-f]{64}")
_CANONICAL_UINT_RE = re.compile(r"(0|[1-9][0-9]*)")


def verify_collection_inclusion(
    collection_salt: bytes,
    leaf_profile: str,
    leaf_canonical_bytes: bytes,
    proof: dict,
    declared_cardinality: str,
    declared_root: str,
) -> bool:
    """Element-level inclusion verification (collection.merkle-sha3-256/1
    §14/§15/§16) — the cross-implementation dual of the verifier-toolkit-js
    `verifyCollectionInclusion`. Returns True only when the one leaf provably
    belongs to `declared_root`, WITHOUT the rest of the collection. Fail-closed:
    any malformed input returns False (never raises for adversary-controlled
    proof data)."""
    # A salt is required (§9, §16). Returned as a rejection, never raised: this
    # entry point is fail-closed for adversary-controlled material.
    if not isinstance(collection_salt, bytes) or not collection_salt:
        return False
    if not isinstance(declared_root, str) or not _HEX64_RE.fullmatch(declared_root):
        return False
    if not isinstance(declared_cardinality, str) or not _CANONICAL_UINT_RE.fullmatch(declared_cardinality):
        return False
    n = int(declared_cardinality)
    if n < 1:
        return False
    # Exactly the three members of §14 (§14.4): an additional member fails.
    if not isinstance(proof, dict) or set(proof) != {"proof_version", "leaf_index", "sibling_hashes"}:
        return False
    if proof.get("proof_version") != COLLECTION_MERKLE_SCHEME:
        return False
    li = proof.get("leaf_index")
    if not isinstance(li, str) or not _CANONICAL_UINT_RE.fullmatch(li):
        return False
    i = int(li)
    if i >= n:
        return False
    siblings = proof.get("sibling_hashes")
    if not isinstance(siblings, list):
        return False
    for s in siblings:
        if not isinstance(s, str) or not _HEX64_RE.fullmatch(s):
            return False
    current = collection_leaf_hash(collection_salt, leaf_profile, leaf_canonical_bytes)
    idx = i
    width = n
    cursor = 0
    while width > 1:
        is_lone_rightmost = width % 2 == 1 and idx == width - 1
        if not is_lone_rightmost:
            if cursor >= len(siblings):
                return False  # too few siblings
            sib = siblings[cursor]
            cursor += 1
            current = (
                collection_node_hash(current, sib)
                if idx % 2 == 0
                else collection_node_hash(sib, current)
            )
        idx //= 2
        width = (width + 1) // 2
    if cursor != len(siblings):
        return False  # too many siblings
    return current == declared_root


# ── Ed25519 (RFC 8032, deterministic) ─────────────────────────────────────

# Fixed PKCS#8 DER prefix for an Ed25519 private key (16 bytes) + 32-byte seed.
_ED25519_PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")


def load_ed25519_pkcs8_b64(pkcs8_b64: str):
    return serialization.load_der_private_key(base64.b64decode(pkcs8_b64), password=None)


def deterministic_ed25519(label: str):
    """Reproducible Ed25519 keypair from a label (DETERMINISM.md §2).

    Returns (private_key_obj, raw_pub_bytes, pub_b64).
    """
    seed = bytes.fromhex(digest_hex_text(f"certcrypt/conformance/ed25519/1:{label}"))[:32]
    der = _ED25519_PKCS8_PREFIX + seed
    priv = serialization.load_der_private_key(der, password=None)
    pub_der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    raw_pub = pub_der[-32:]
    return priv, raw_pub, base64.b64encode(raw_pub).decode("ascii")


def ed25519_sign_b64(priv, message: bytes) -> str:
    return base64.b64encode(priv.sign(message)).decode("ascii")


# ── ML-DSA-65 (FIPS 204, deterministic variant) ──────────────────────────
# keygen from a fixed 32-byte seed (ξ) via the internal keygen; deterministic
# signing. The FIPS 204 deterministic signature is reproducible across
# conformant implementations.

# 0x01 0x02 ... 0x20
ML_DSA_TEST_SEED = bytes(range(1, 33))


def ml_dsa65_keypair_from_seed(seed: bytes = ML_DSA_TEST_SEED) -> tuple[bytes, bytes]:
    return ML_DSA_65._keygen_internal(seed)  # (pk, sk)


def ml_dsa65_sign_b64(secret_key: bytes, message: bytes) -> str:
    sig = ML_DSA_65.sign(secret_key, message, deterministic=True)
    return base64.b64encode(sig).decode("ascii")


def deterministic_ml_dsa65(label: str) -> tuple[bytes, bytes]:
    """Reproducible ML-DSA-65 keypair from a label (DETERMINISM.md §2).

    The 32-byte seed (ξ) is SHA3-256(label) truncated to 32 bytes, the same
    label-derived discipline as `deterministic_ed25519`. Used for the zero-data
    capacity fixture key material (holder operation-key tree, system-domain
    Level-1 key): each fixture's keys are a pure function of a frozen label
    string, never an RNG. Returns (pk, sk).
    """
    seed = bytes.fromhex(digest_hex_text(f"certcrypt/conformance/ml-dsa/1:{label}"))[:32]
    return ML_DSA_65._keygen_internal(seed)


# ── Composite hybrid signature (`composite-signature/1`) ───────────────────
# CERTCRYPT emission + root-of-trust signatures are a PQ/T hybrid composite:
# the signed material M' is domain-separated (mirror of
# draft-ietf-lamps-pq-composite-sigs), and BOTH components — the classical one
# (ECDSA P-256 under the canonical profile, Ed25519 under the additional one)
# and ML-DSA-65 — sign that SAME M'. Verification is AND (valid iff both
# verify). The domain prefix bound into M' is what stops a component signature
# being lifted out of the composite and replayed alone (anti-stripping).
#
# Wire is JSON-native, NOT the X.509 byte-concatenation of the draft: the
# composite is ONE logical signature object `{alg, mode, signatures}` whose
# `signatures` array carries the two components, classical first, each named by
# its own `alg`, so a consumer cannot treat either half as optional.

COMPOSITE_DOMAIN_PREFIX = b"CERTCRYPT-Composite-Signature-v1"
COMPOSITE_SEP = b"\x00"

PROFILE_P256_MLDSA65 = "certcrypt-composite-p256-mldsa65-v1"
PROFILE_ED25519_MLDSA65 = "certcrypt-composite-ed25519-mldsa65-v1"

ALG_ECDSA_P256 = "ECDSA-P256-SHA3-256"
ALG_ED25519 = "Ed25519"
ALG_MLDSA65 = "ML-DSA-65"


def composite_m_prime(composite_alg_id: str, payload_canon_digest_hex: str) -> bytes:
    """The domain-separated message every component signs.

    M' = ASCII(prefix) || 0x00 || ASCII(composite_alg_id) || 0x00
         || ASCII(payload_canon_digest_hex)

    `composite_alg_id` is the PROFILE id, bound in so a signature under one
    profile cannot be reinterpreted under another. 0x00 separators make the field
    split injective. Mirror of Rust `composite::composite_m_prime`.
    """
    return (
        COMPOSITE_DOMAIN_PREFIX
        + COMPOSITE_SEP
        + composite_alg_id.encode("ascii")
        + COMPOSITE_SEP
        + payload_canon_digest_hex.encode("ascii")
    )


def composite_root_fingerprint(classical_pub: bytes, mldsa_pub: bytes) -> str:
    """system_root_fingerprint for a composite root.

    SHA3-256(classical_pub || mldsa_pub) — classical first (matching component
    order), PQC second. Load-bearing; per composite-signature/1.
    """
    return digest_hex_bytes(classical_pub + mldsa_pub)


# ── ECDSA P-256 (secp256r1) — classical component of the canonical profile ──
# raw-rs-64 signature (r||s, 64 bytes, NOT DER), low-s enforced; ECDSA over
# SHA3-256(M') (composite-signature/1).

from cryptography.hazmat.primitives import hashes as _hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec as _ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import (  # noqa: E402
    Prehashed,
    decode_dss_signature,
)

_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_HALF_N = _P256_N >> 1


# Domain-separation info for deriving the P-256 component from a master seed.
# MUST byte-match the runtime (capacity-verify::ecdsa_p256::P256_DERIVE_INFO).
P256_DERIVE_INFO = b"certcrypt/composite/p256/v1"


def p256_keypair_from_seed(seed: bytes):
    """Deterministic P-256 key from a 32-byte master seed via HKDF-SHA3-256 with
    domain separation — byte-identical to the runtime's `signing_key_from_seed`
    (capacity-verify::ecdsa_p256). HKDF-Expand to 48 bytes (oversampled), reduce
    mod n, map 0→1. Returns (private_key, sec1_uncompressed_pub_65B).
    """
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF
    okm = _HKDF(
        algorithm=_hashes.SHA3_256(), length=48, salt=None, info=P256_DERIVE_INFO
    ).derive(seed)
    secret_int = int.from_bytes(okm, "big") % _P256_N
    if secret_int == 0:
        secret_int = 1
    priv = _ec.derive_private_key(secret_int, _ec.SECP256R1())
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    return priv, pub


def p256_sign_raw_rs_64_b64(priv, message: bytes) -> str:
    """Sign over SHA3-256(message), return raw-rs-64 base64, low-s, RFC 6979.

    Prehash SHA3-256, low-s, raw r||s. The nonce is RFC 6979 DETERMINISTIC with
    H = SHA3-256 for the HMAC too, the construction the `ecdsa-p256-deterministic`
    family pins. Determinism is load-bearing: it makes the fixtures
    byte-reproducible (DETERMINISM.md). A signer deterministic under another HMAC
    hash (e.g. HMAC-SHA-256 over the same prehash) verifies but does not match
    these bytes. `cryptography`'s ECDSA uses a RANDOM nonce, so we route signing
    through python-ecdsa, which supports RFC 6979 directly.
    """
    import ecdsa as _ecdsa
    from ecdsa.util import sigencode_string_canonize as _canonize
    # Extract the secret scalar from the cryptography private key and rebuild it
    # as a python-ecdsa SigningKey over NIST P-256 (secp256r1).
    secret_int = priv.private_numbers().private_value
    sk = _ecdsa.SigningKey.from_secret_exponent(secret_int, curve=_ecdsa.NIST256p)
    digest = hashlib.sha3_256(message).digest()
    # sign_digest_deterministic: RFC 6979 nonce derived with HMAC-SHA3-256; canonize
    # encodes raw r||s with low-s normalization (s ≤ n/2).
    raw = sk.sign_digest_deterministic(
        digest, hashfunc=hashlib.sha3_256, sigencode=_canonize
    )
    return base64.b64encode(raw).decode("ascii")


def deterministic_p256(label: str):
    """Reproducible P-256 keypair from a label (DETERMINISM.md §2).

    Returns (private_key, sec1_uncompressed_pub_65B, pub_b64).
    """
    seed = bytes.fromhex(digest_hex_text(f"certcrypt/conformance/p256/1:{label}"))[:32]
    priv, pub = p256_keypair_from_seed(seed)
    return priv, pub, base64.b64encode(pub).decode("ascii")


# ── Commitment sub-tree (leaf = sub-tree of accepted commitments) ──────────
# The commitment sub-tree (independence.proof/1, settlement.binding/1):
#   commitment leaf preimage { v: "ccab1-commit", commitment_id }  (insertion-order)
#   commitment leaf hash    = SHA3-256(0x00 || ordered_json(preimage))
#   subtree_root            = compute_merkle_root over those leaf hashes
#   commitment→subtree path = generate_inclusion_proof (shared Merkle scheme)
# The economic fields stay per-leaf on the settlement LeafPreimage; a commitment
# node carries only its self-identifying id.

COMMITMENT_LEAF_VERSION = "ccab1-commit"


def commitment_leaf_hash(commitment_id: str) -> str:
    """SHA3-256(0x00 || ordered_json({v, commitment_id})) — one sub-tree leaf.

    Insertion-ordered (NOT JCS):
    the field order {v, commitment_id} is the canonical order and is load-bearing.
    """
    preimage = canonical_json_bytes(
        [("v", COMMITMENT_LEAF_VERSION), ("commitment_id", commitment_id)]
    )
    return compute_leaf_hash(preimage)


def compute_subtree_root(commitment_ids: list[str]) -> tuple[str, list[str]]:
    """`subtree_root` over the accepted commitments of one leaf + their hashes.

    `commitment_ids` are the
    commitments that survived validation for this leaf, in canonical leaf order.
    A leaf MUST carry ≥1 accepted commitment (the empty case forms no leaf and is
    resolved upstream — reaching it here is a caller bug).
    """
    if not commitment_ids:
        raise ValueError(
            "a settlement leaf must carry at least one accepted commitment; "
            "a submission-set with zero accepted commitments forms no leaf"
        )
    leaf_hashes = [commitment_leaf_hash(cid) for cid in commitment_ids]
    return compute_merkle_root(leaf_hashes), leaf_hashes


def build_commitment_inclusion_proof(
    commitment_ids: list[str], commitment_index: int
) -> dict:
    """`commitment → subtree_root` inclusion proof for one commitment.

    Field set + order: commitment_id, commitment_leaf_hash, commitment_index,
    commitment_siblings, subtree_size; numeric fields are decimal strings.
    """
    _root, leaf_hashes = compute_subtree_root(commitment_ids)
    siblings = generate_inclusion_proof(leaf_hashes, commitment_index)
    return {
        "commitment_id": commitment_ids[commitment_index],
        "commitment_leaf_hash": leaf_hashes[commitment_index],
        "commitment_index": str(commitment_index),
        "commitment_siblings": siblings,
        "subtree_size": str(len(leaf_hashes)),
    }


# ── SHA3-256 operation-scoped pseudonyms ──────────────────────────────────
# Byte-exact against `CCCP/1`, and the vectors below are what every port —
# issuer-side and verifier-side — is checked against:
#   pseudonym(field) = SHA3-256( framed(salt) || framed(domain_tag) || framed(id) )
# where framed(b) prepends an 8-byte big-endian length prefix so the field
# boundaries are unambiguous (prevents a||b colliding with a'||b'). Output is
# 32 bytes rendered lowercase hex (256-bit). Domain tags are the exact strings
# the Rust `Domain::tag()` returns: "holder", "pool", "authorization".
#
# Hash: SHA3-256 (FIPS 202 fixed-output), NOT SHAKE-256. The output is a fixed
# 32 bytes, so the XOF buys nothing and carries the SHAKE prefix hazard; SHA3-256
# is the fixed-length choice, aligns with CCCP/1 §7.1, and is what the pinned
# primitives/pseudonym/vectors.json (kdf: "SHA3-256") and the canonical verifier
# reproduce. (A SHAKE-256 derivation does NOT match those vectors.)

_PSEUDONYM_LEN = 32  # bytes


def _absorb_framed(h, field: bytes) -> None:
    h.update(len(field).to_bytes(8, "big"))
    h.update(field)


def pseudonym_derive(operation_salt: bytes, domain_tag: str, stable_id: str) -> str:
    """Operation-scoped pseudonym, mirror of pseudonym::derive.

    `domain_tag` is one of "holder" / "pool" / "authorization". Identical inputs
    yield an identical pseudonym (so the verifier can recompute bindings);
    a fresh `operation_salt` per operation yields unrelated pseudonyms.
    """
    h = hashlib.sha3_256()
    _absorb_framed(h, operation_salt)
    _absorb_framed(h, domain_tag.encode("utf-8"))
    _absorb_framed(h, stable_id.encode("utf-8"))
    return h.digest().hex()


# ── Holder operation-key tree ─────────────────────────────────────────────
# Byte-exact against `holder-keyset.merkle-sha3-256/1`.
#   leaf hash of an operation public key: SHA3-256(0x00 || public_key)
#   tree root / inclusion proof: the shared settlement Merkle rules above
#     (compute_merkle_root / generate_inclusion_proof) — odd child promoted.
# The 0x00 leaf prefix is the same byte the settlement leaf rule uses; the only
# difference is what is hashed (a raw public key, not a canonical preimage), so
# there is exactly one Merkle implementation, as in Rust.

_KEY_LEAF_PREFIX = b"\x00"


def operation_key_leaf_hash(public_key: bytes) -> str:
    """SHA3-256(0x00 || public_key) as lowercase hex (holder key-set leaf)."""
    return digest_hex_bytes(_KEY_LEAF_PREFIX + public_key)


def holder_key_set_root(public_keys: list[bytes]) -> str:
    """The `holder_key_set_root` the Level-2 authorization commits to.

    Merkle root over SHA3-256(0x00 || pk) leaves, using the shared settlement
    Merkle construction (odd child promoted unchanged).
    """
    return compute_merkle_root([operation_key_leaf_hash(pk) for pk in public_keys])


def holder_key_disclosure(public_keys: list[bytes], leaf_index: int) -> dict:
    """The `OperationKeyDisclosure` for the commitment signed by `leaf_index`.

    Mirrors HolderKeySet::disclosure: the leaf public key (base64), its index,
    its inclusion proof to the root, and the tree size. The secret key never
    travels — only this disclosure does. Field set matches the Rust struct
    (leaf_index, public_key_b64, inclusion_proof, tree_size).
    """
    leaf_hashes = [operation_key_leaf_hash(pk) for pk in public_keys]
    return {
        "leaf_index": leaf_index,
        "public_key_b64": base64.b64encode(public_keys[leaf_index]).decode("ascii"),
        "inclusion_proof": generate_inclusion_proof(leaf_hashes, leaf_index),
        "tree_size": len(public_keys),
    }


_DISCLOSURE_MEMBERS = {"leaf_index", "public_key_b64", "inclusion_proof", "tree_size"}
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_b64_decode(s: Any) -> bytes | None:
    """RFC 4648 base64, standard alphabet, with padding and canonical trailing
    bits (decode(encode(x)) == x and encode(decode(s)) == s). None if not."""
    if not isinstance(s, str) or not s:
        return None
    try:
        raw = base64.b64decode(s, validate=True)
    except Exception:
        return None
    return raw if base64.b64encode(raw).decode("ascii") == s else None


def _json_uint(x: Any) -> bool:
    """A JSON integer (not a boolean, not a float, not a string), >= 0."""
    return isinstance(x, int) and not isinstance(x, bool) and x >= 0


def verify_holder_key_disclosure(disclosure: Any, root: str) -> tuple[bool, str | None]:
    """Membership of one disclosed operation key in `root`, under
    holder-keyset.merkle-sha3-256/1 §11-§13, fail-closed. Returns
    (valid, failure) — failure names the first condition that fired."""
    if not isinstance(disclosure, dict) or set(disclosure) != _DISCLOSURE_MEMBERS:
        return False, "disclosure members are not exactly the four of §11"
    n, i = disclosure["tree_size"], disclosure["leaf_index"]
    if not _json_uint(n) or n < 1:
        return False, "tree_size is not a positive JSON integer"
    if not _json_uint(i):
        return False, "leaf_index is not a non-negative JSON integer"
    if i >= n:
        return False, "leaf_index >= tree_size"
    pk = _canonical_b64_decode(disclosure["public_key_b64"])
    if pk is None:
        return False, "public_key_b64 is not canonical base64"
    proof = disclosure["inclusion_proof"]
    if not isinstance(proof, list) or not all(isinstance(h, str) and _HEX64.match(h) for h in proof):
        return False, "an inclusion_proof entry is not 64-char lowercase hex"
    if not isinstance(root, str) or not _HEX64.match(root):
        return False, "root is not 64-char lowercase hex"
    cur, idx, width, cursor = operation_key_leaf_hash(pk), i, n, 0
    while width > 1:
        if not (width % 2 == 1 and idx == width - 1):
            if cursor >= len(proof):
                return False, "inclusion_proof has too few entries"
            sib = proof[cursor]
            cursor += 1
            cur = compute_node_hash(cur, sib) if idx % 2 == 0 else compute_node_hash(sib, cur)
        idx //= 2
        width = (width + 1) // 2
    if cursor != len(proof):
        return False, "inclusion_proof has unconsumed entries"
    if cur != root:
        return False, "recomputed root differs"
    return True, None


# ── JSON-object subject preconditions ──────────────────────────────────────
# Field-set / value-discipline preconditions enforced BEFORE canonicalization
# for the three JSON-object subject profiles:
# canonical_bytes(subject) is defined ONLY for an object satisfying the profile
# in full; any other object MUST fail closed (the profile does not apply). The
# string-only discipline (no JSON number/boolean/null at any depth) is what keeps
# RFC 8785 free of number serialization — the one cross-language divergence the
# profiles exist to eliminate.

class StrictJsonError(ValueError):
    """The text is not RFC 8259 JSON, or an object repeats a member name."""


def _reject_constant(token: str):
    raise StrictJsonError(f"non-finite number {token} is not JSON")


def _unique_members(pairs: list) -> dict:
    out: dict = {}
    for name, value in pairs:
        if name in out:
            raise StrictJsonError(f"duplicate member name {name!r}")
        out[name] = value
    return out


def strict_json_loads(text: str) -> Any:
    """Parse strict JSON (`strict-json` vectors; CCSP/1 §8.1). The standard
    decoder hands each object's members over as decoded (name, value) pairs, so
    duplicates are seen after escape decoding and at every depth; arrays never
    reach the hook. NaN/Infinity and a leading BOM are refused."""
    if text.startswith("\ufeff"):
        raise StrictJsonError("byte-order mark before the JSON text")
    try:
        return json.loads(text, object_pairs_hook=_unique_members, parse_constant=_reject_constant)
    except json.JSONDecodeError as e:
        raise StrictJsonError(str(e)) from e


class SubjectPreconditionError(Exception):
    """Raised when a JSON-object subject violates its profile precondition."""

    def __init__(self, profile: str, detail: str) -> None:
        super().__init__(f"subject precondition failed for {profile}: {detail}")
        self.profile = profile


def _is_plain_object(v: Any) -> bool:
    return isinstance(v, dict)


def assert_string_only(profile: str, value: Any, path: str) -> None:
    """Every value at any depth MUST be a string, object, or array. A JSON
    number, boolean, or null token anywhere is non-conformant. Mirror of
    assertStringOnly. NOTE: bool is checked before int (in Python bool is an int
    subclass) so True/False are correctly rejected as booleans."""
    if isinstance(value, str):
        return
    if isinstance(value, list):
        for i, el in enumerate(value):
            assert_string_only(profile, el, f"{path}[{i}]")
        return
    if _is_plain_object(value):
        for k in value.keys():
            assert_string_only(profile, value[k], f"{path}.{k}" if path else k)
        return
    kind = "null" if value is None else ("boolean" if isinstance(value, bool) else "number")
    raise SubjectPreconditionError(
        profile,
        f"value at {path or '(root)'} is a JSON {kind}; every value must be a "
        f"string, object, or array (no numbers/booleans/nulls)",
    )


_CARDINALITY_MAX = 18446744073709551615  # 2^64 - 1
_HEX64 = re.compile(r"[0-9a-f]{64}")
_CANONICAL_UINT = re.compile(r"[1-9][0-9]*")

# subject.ai-decision/1 §7.4 and §7.3.
AI_DECISION_IO_PROFILES = ("subject.text/1", "subject.binary/1", "subject.email/1",
                           "subject.ai-decision/1")
_DECIDED_AT = re.compile(
    r"[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])"
    r"T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z", re.ASCII)
_AI_TOKEN = re.compile(r"[a-z][a-z0-9._-]{0,63}", re.ASCII)
_MIME_ESSENCE = re.compile(r"[a-z0-9!#$%&'*+.^_`|~-]+/[a-z0-9!#$%&'*+.^_`|~-]+", re.ASCII)
_AI_PART_KEYS = {
    "id", "role", "media_type", "profile", "material_nonce_hex",
    "commitment_digest_hex",
}
_AI_MAP_MAX = 128
_AI_PART_MAX = 256


def assert_collection_precondition(value: Any) -> None:
    """subject.collection/1: exactly four members; leaf shape; root shape under
    the sha3-256 scheme; declared_cardinality grammar + agreement with leaves.
    Mirror of assertCollectionPrecondition."""
    P = "subject.collection/1"
    if not _is_plain_object(value):
        raise SubjectPreconditionError(P, "subject is not a JSON object")
    REQUIRED = ["commitment_scheme", "root", "declared_cardinality", "leaves"]
    STRING_MEMBERS = ["commitment_scheme", "root", "declared_cardinality"]
    keys = list(value.keys())
    for k in REQUIRED:
        if k not in value:
            raise SubjectPreconditionError(P, f'missing member "{k}"')
    for k in keys:
        if k not in REQUIRED:
            raise SubjectPreconditionError(
                P, f'unexpected member "{k}" (exactly four members allowed)'
            )
        if k in STRING_MEMBERS and not isinstance(value[k], str):
            raise SubjectPreconditionError(P, f'member "{k}" must be a string')
    leaves = value["leaves"]
    if not isinstance(leaves, list) or len(leaves) == 0:
        raise SubjectPreconditionError(P, '"leaves" must be a non-empty array')
    for i, leaf in enumerate(leaves):
        if not _is_plain_object(leaf):
            raise SubjectPreconditionError(P, f'"leaves[{i}]" must be an object')
        lk = list(leaf.keys())
        if len(lk) != 2 or "profile" not in leaf or "commitment_digest_hex" not in leaf:
            raise SubjectPreconditionError(
                P, f'"leaves[{i}]" must contain exactly "profile" and "commitment_digest_hex"'
            )
        for k in lk:
            if not isinstance(leaf[k], str):
                raise SubjectPreconditionError(P, f'"leaves[{i}].{k}" must be a string')
        if not _HEX64.fullmatch(leaf["commitment_digest_hex"]):
            raise SubjectPreconditionError(
                P, f'"leaves[{i}].commitment_digest_hex" must be 64 lowercase hex characters'
            )
    if str(len(leaves)) != value["declared_cardinality"]:
        raise SubjectPreconditionError(
            P,
            f'"declared_cardinality" ({value["declared_cardinality"]}) does not equal '
            f"the number of leaves ({len(leaves)})",
        )
    dc = value["declared_cardinality"]
    if not _CANONICAL_UINT.fullmatch(dc):
        raise SubjectPreconditionError(
            P,
            '"declared_cardinality" must be a canonical unsigned base-10 integer '
            "with no sign and no leading zeros",
        )
    if int(dc) > _CARDINALITY_MAX:
        raise SubjectPreconditionError(P, '"declared_cardinality" exceeds 2^64 - 1')
    if value["commitment_scheme"] == "collection.merkle-sha3-256/1":
        if not _HEX64.fullmatch(value["root"]):
            raise SubjectPreconditionError(
                P, '"root" must be a 64-character lowercase hex string under '
                   "collection.merkle-sha3-256/1"
            )
    assert_string_only(P, value, "")


def _assert_nested_string_object(profile, obj, name, required, optional) -> None:
    if not _is_plain_object(obj):
        raise SubjectPreconditionError(profile, f'member "{name}" must be an object')
    allowed = set(required) | set(optional)
    for k in required:
        if k not in obj:
            raise SubjectPreconditionError(profile, f'"{name}" missing member "{k}"')
    for k in obj.keys():
        if k not in allowed:
            raise SubjectPreconditionError(profile, f'"{name}" has unexpected member "{k}"')
        if not isinstance(obj[k], str):
            raise SubjectPreconditionError(profile, f'"{name}.{k}" must be a string')


def assert_ai_decision_precondition(value: Any) -> None:
    """Validate the closed, bounded subject.ai-decision/1 record shape."""
    P = "subject.ai-decision/1"
    if not _is_plain_object(value):
        raise SubjectPreconditionError(P, "record is not a JSON object")
    REQUIRED = ["profile", "decision_id", "decided_at", "model", "observation_scope",
                "input", "output", "decision"]
    OPTIONAL = ["parameters", "context", "started_at", "actor_id", "policy_ref"]
    allowed = set(REQUIRED) | set(OPTIONAL)
    for k in REQUIRED:
        if k not in value:
            raise SubjectPreconditionError(P, f'missing required member "{k}"')
    for k in value.keys():
        if k not in allowed:
            raise SubjectPreconditionError(P, f'unexpected member "{k}"')
    if value["profile"] != P:
        raise SubjectPreconditionError(P, f'"profile" must equal "{P}"')
    for k in ("profile", "decision_id", "decided_at", "observation_scope", "decision"):
        if not isinstance(value[k], str):
            raise SubjectPreconditionError(P, f'member "{k}" must be a string')
    if not _AI_TOKEN.fullmatch(value["decision_id"]):
        raise SubjectPreconditionError(P, '"decision_id" is not a valid canonical token')
    if not value["decision"]:
        raise SubjectPreconditionError(P, '"decision" must be non-empty')

    def valid_time(name: str) -> None:
        raw = value[name]
        if not isinstance(raw, str) or not _DECIDED_AT.fullmatch(raw):
            raise SubjectPreconditionError(P, f'"{name}" must be a valid Gregorian UTC millisecond timestamp')
        try:
            datetime.datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError as exc:
            raise SubjectPreconditionError(P, f'"{name}" must be a valid Gregorian UTC millisecond timestamp') from exc

    valid_time("decided_at")
    if "started_at" in value:
        valid_time("started_at")
        if value["started_at"] > value["decided_at"]:
            raise SubjectPreconditionError(P, '"started_at" must not be later than "decided_at"')
    _assert_nested_string_object(P, value["model"], "model", ["id", "provider"], ["version"])
    for key, member in value["model"].items():
        if not member:
            raise SubjectPreconditionError(P, f'"model.{key}" must be non-empty')
    ids = set()
    material_nonces = set()
    total = 0
    for side in ("input", "output"):
        parts = value[side]
        if not isinstance(parts, list):
            raise SubjectPreconditionError(P, f'member "{side}" must be an array')
        if not parts:
            raise SubjectPreconditionError(P, f'member "{side}" must be a non-empty array')
        total += len(parts)
        for i, part in enumerate(parts):
            path = f"{side}[{i}]"
            if not _is_plain_object(part) or set(part.keys()) != _AI_PART_KEYS:
                raise SubjectPreconditionError(P, f'"{path}" has the wrong exact member set')
            if any(not isinstance(v, str) for v in part.values()):
                raise SubjectPreconditionError(P, f'"{path}" members must be strings')
            if not _AI_TOKEN.fullmatch(part["id"]):
                raise SubjectPreconditionError(P, f'"{path}.id" is not a valid material id')
            if part["id"] in ids:
                raise SubjectPreconditionError(P, f'material id {part["id"]!r} is duplicated')
            ids.add(part["id"])
            if not part["role"]:
                raise SubjectPreconditionError(P, f'"{path}.role" must be non-empty')
            if not _MIME_ESSENCE.fullmatch(part["media_type"]):
                raise SubjectPreconditionError(P, f'"{path}.media_type" must be a lowercase MIME essence without parameters')
            if part["profile"] not in AI_DECISION_IO_PROFILES:
                raise SubjectPreconditionError(P, f'"{path}.profile" is not admitted')
            if not _HEX64.fullmatch(part["material_nonce_hex"]):
                raise SubjectPreconditionError(
                    P, f'"{path}.material_nonce_hex" must be 64 lowercase hex characters')
            if part["material_nonce_hex"] in material_nonces:
                raise SubjectPreconditionError(
                    P, f'material nonce {part["material_nonce_hex"]!r} is duplicated')
            material_nonces.add(part["material_nonce_hex"])
            if not _HEX64.fullmatch(part["commitment_digest_hex"]):
                raise SubjectPreconditionError(
                    P, f'"{path}.commitment_digest_hex" must be 64 lowercase hex characters')
    if total < 1 or total > _AI_PART_MAX:
        raise SubjectPreconditionError(P, f'input and output must contain 1..{_AI_PART_MAX} parts in total')
    for map_name in ("parameters", "context"):
        if map_name not in value:
            continue
        flat = value[map_name]
        if not _is_plain_object(flat):
            raise SubjectPreconditionError(P, f'"{map_name}" must be an object when present')
        if len(flat) > _AI_MAP_MAX:
            raise SubjectPreconditionError(P, f'"{map_name}" must contain at most {_AI_MAP_MAX} members')
        for k, v in flat.items():
            if not isinstance(v, str):
                raise SubjectPreconditionError(P, f'"{map_name}.{k}" must be a string')
    for k in ("actor_id", "policy_ref"):
        if k in value and not isinstance(value[k], str):
            raise SubjectPreconditionError(P, f'optional member "{k}" must be a string')
    assert_string_only(P, value, "")
    if len(jcs_canonicalize_bytes(value)) > 1024 * 1024:
        raise SubjectPreconditionError(P, "canonical material exceeds 1048576 bytes")


def canonical_subject_ai_decision(raw: bytes) -> bytes:
    """Canonicalize one bounded, BOM-free subject.ai-decision/1 source."""
    P = "subject.ai-decision/1"
    if len(raw) > 1024 * 1024:
        raise SubjectPreconditionError(P, "source material exceeds 1048576 bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SubjectPreconditionError(P, "source material is not UTF-8") from exc
    if text.startswith("\ufeff"):
        raise SubjectPreconditionError(P, "source material must not begin with a UTF-8 BOM")
    try:
        value = strict_json_loads(text)
    except StrictJsonError as exc:
        raise SubjectPreconditionError(P, str(exc)) from exc
    assert_ai_decision_precondition(value)
    canonical = jcs_canonicalize_bytes(value)
    if len(canonical) > 1024 * 1024:
        raise SubjectPreconditionError(P, "canonical material exceeds 1048576 bytes")
    return canonical


def assert_context_snapshot_precondition(value: Any) -> None:
    """subject.context-snapshot/1 §7.1: a JSON object with no JSON number at any
    depth; booleans and nulls are permitted (no member set — the shape is governed
    by the higher layer). Mirror of assertContextSnapshotPrecondition."""
    P = "subject.context-snapshot/1"
    if not _is_plain_object(value):
        raise SubjectPreconditionError(P, "snapshot is not a JSON object")

    def no_number(v: Any, path: str) -> None:
        if isinstance(v, bool) or v is None or isinstance(v, str):
            return
        if isinstance(v, (int, float)):
            raise SubjectPreconditionError(P, f"value at {path or '(root)'} is a JSON number")
        if isinstance(v, list):
            for i, el in enumerate(v):
                no_number(el, f"{path}[{i}]")
            return
        if isinstance(v, dict):
            for k, el in v.items():
                no_number(el, f"{path}.{k}" if path else k)

    no_number(value, "")
