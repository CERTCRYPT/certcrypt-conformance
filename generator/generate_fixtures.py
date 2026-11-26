#!/usr/bin/env python3
"""
Reference fixture generator for the CERTCRYPT conformance suite.

Generates the full fixture corpus (P-series positive, V-series negative, plus
foundation F001-F018, k-of-n quorum negatives QN1-QN8 and the successor-binding
positive P009, node-attestation positive P010, signature authenticity S001-S011, PQC Q001-Q005 and CCSP/1 envelope C001-C019 fixtures) with cryptographically valid synthetic data. The
system root is a system-manifest/1 k-of-n composite quorum; the foundation
embeds the bootstrap manifest and is authorized by a quorum of member
signatures (system_root_fingerprint = SHA3-256(JCS(manifest))). Positive
fixtures have correct SHA3-256 digests and valid Merkle proofs. Negative
fixtures break exactly one
property per the vector definition.

It depends only on the shared `primitives` module (hashlib SHA3-256, the
`cryptography` library for Ed25519, `ecdsa` for RFC 6979 P-256, and `dilithium_py`
for ML-DSA-65) — no
dependency on any verifier implementation. Determinism per
generator/DETERMINISM.md; the committed fixtures are the authoritative contract.

Output is written under ../fixtures/ (conformance/ + adversarial/) relative to
this generator, or to --out DIR if supplied.
"""

import argparse
import base64
import copy
import json
import os
from typing import Any, Optional

import primitives
from primitives import (
    digest_hex_bytes,
    digest_hex_text,
    jcs_canonicalize_bytes,
    canonical_json_bytes,
    compute_leaf_hash,
    compute_merkle_root,
    generate_inclusion_proof,
    load_ed25519_pkcs8_b64,
    deterministic_ed25519,
    ed25519_sign_b64,
    ml_dsa65_keypair_from_seed,
    ml_dsa65_sign_b64,
    deterministic_ml_dsa65,
    pseudonym_derive,
    holder_key_set_root,
    holder_key_disclosure,
    composite_m_prime,
    p256_keypair_from_seed,
    p256_sign_raw_rs_64_b64,
    PROFILE_P256_MLDSA65,
    ALG_ECDSA_P256,
    ALG_MLDSA65,
)

# ── Conformance-domain configuration ───────────────────────────────────────

TEST_ROOT_PUBLIC_KEY_B64 = "D2kjT6WSGEknyyBD4t2X83i8g1TaXPqorHY6s5XeC9I="
TEST_ROOT_PRIVATE_KEY_PKCS8_B64 = (
    "MC4CAQAwBQYDK2VwBCIEIDv85cnBe1na5TqrMkCvEBLRgjyguwJA3h7VpQqHgAOW"
)
TEST_ROOT_FINGERPRINT = (
    "12e236790358eeae049c2a8f8be4b0005f2f0e108a2f4d3df9e7ea73ec20b334"
)

# The conformance fixtures carry the environment-agnostic contract rules_version
# `rules/conformance`: they exercise the PROTOCOL MECHANICS (leaf hashing,
# inclusion proofs, bindings, fail-closed cases), not any operational environment,
# so a verifier of any environment runs them under its conformance config.
#
# SETTLEMENT IS XRPL. Supply is destroyed by paying the CERT MPT back to its own
# ISSUER: XRPL has no burn operation for Multi-Purpose Tokens, and a transfer to
# an unspendable address would leave the supply existing (merely immobile), which
# is not destruction — see settlement.aggregated.xrpl/1 §7.1.
#
# The `contract` field names the MPT ISSUANCE rather than a contract account:
# XRPL has no contracts, and the issuance is the object whose supply the
# settlement destroys (§9.2). `action_ordinal` is always "0": XRPL has no
# sub-position inside a transaction, and a synthesized index would be
# indistinguishable from a re-inclusion that never happened (§8.1).
config = {
    "system_id": "certcrypt",
    "system_root_fingerprint": TEST_ROOT_FINGERPRINT,
    "supported_rules_versions": ["rules/conformance"],
    "settlement_profile_id": "settlement.aggregated.xrpl/1",
    # XRPL has no chain_id; its identity is the network id (0 mainnet, 1 testnet),
    # carried as a namespaced string a verifier compares but never parses (§6.1).
    # The conformance domain settles on no real network, so it declares its own.
    "xrpl_chain_id": "xrpl-network-conformance",
    # The MPT issuance (48 hex chars). Fixed for the conformance domain.
    "xrpl_mpt_issuance_id": "00000000C1F0A0E6E5F1D7B4A9C8E3F2D1B0A9C8E7F6D5C4",
    "xrpl_issuer_account": "rCONFORMANCEiSSUERaccountXXXXXXXXXX",
    "xrpl_pool_account": "rCONFORMANCEpOOLaccountXXXXXXXXXXXX",
    "xrpl_action_name": "payment",
    # The public, permissionless record that witnesses finality. The verifier
    # asserts witness.substrate == env.substrate and fails closed on a mismatch,
    # so a literal here would certify verifiers against the wrong chain.
    "substrate": "xrpl",
    "xrpl_token_symbol": "CERT",
    "xrpl_asset_scale": 2,
    "xrpl_memo_prefix": "ccab1:",
    # Capacity-commitment TTL for the rules/conformance domain. It is not a
    # real deadline: it is the fixed value under which the deterministic P001
    # fixtures are minted (issued_at 2026-04-11 → expires_at 2026-05-11), so it
    # is 2592000s (30d) to keep the goldens reproducible byte-for-byte. The TTL
    # is a rules-domain parameter; another domain uses its own value.
    # `expires_at = issued_at + this`.
    "commitment_ttl_seconds": 2592000,
}

# ── Fixed Ed25519 test keypair ─────────────────────────────────────────────

ed25519_priv = load_ed25519_pkcs8_b64(TEST_ROOT_PRIVATE_KEY_PKCS8_B64)
ed25519_pub_b64 = TEST_ROOT_PUBLIC_KEY_B64
synthetic_fingerprint = TEST_ROOT_FINGERPRINT

# ── ML-DSA-65 test keypair (FIPS 204 deterministic) ────────────────────────

ml_dsa_pk, ml_dsa_sk = ml_dsa65_keypair_from_seed()
ml_dsa_pub_key_b64 = base64.b64encode(ml_dsa_pk).decode("ascii")

# The conformance root is a system-manifest/1 quorum (below); its fingerprint
# is the root id a verifier's conformance configuration must carry.


def sign_ml_dsa65(payload_bytes: bytes) -> str:
    return ml_dsa65_sign_b64(ml_dsa_sk, payload_bytes)


def ed25519_sign(message: bytes) -> str:
    return ed25519_sign_b64(ed25519_priv, message)


# ── Composite root key material (`composite-signature/1`) ──────────────────
# Canonical profile `certcrypt-composite-p256-mldsa65-v1`: the classical
# component is ECDSA P-256 (NOT Ed25519 — that is the additional profile), the
# PQC component is the fixed ML-DSA-65 test key. Both sign the SAME M'; AND. The
# composite root fingerprint is SHA3-256(p256_pub || mldsa_pub) — classical first.

# Deterministic P-256 test root (classical component of the canonical profile).
P256_TEST_SEED = bytes(range(33, 65))  # 0x21..0x40, distinct from the ML-DSA seed
p256_root_priv, p256_root_pub_sec1 = p256_keypair_from_seed(P256_TEST_SEED)
p256_root_pub_b64 = base64.b64encode(p256_root_pub_sec1).decode("ascii")

# ── Root quorum (system-manifest/1 k-of-n) ─────────────────────────────────
# The root is not a single composite key: it is a k-of-n quorum of
# composite member keys catalogued in a `system-manifest/1` bootstrap manifest.
# `system_root_fingerprint = SHA3-256(JCS(manifest))` (NOT SHA3(p256||mldsa)).
#
# Member 0 reuses the existing root composite keypair (p256_root_priv / ml_dsa_sk)
# so the emission-certificate issuer is also a member of the active entry — per
# system-manifest/1 §15, an operational artifact is signed by ONE member of the
# active quorum. Members 1..n-1 are fresh deterministic composite keypairs.

ROOT_QUORUM_K = 2
ROOT_QUORUM_N = 3
ROOT_KID = "conformance-root-1"
ROOT_VALID_FROM = "2026-04-10T00:00:00Z"


def _deterministic_composite_member(label: str):
    """A deterministic composite member keypair (P-256 + ML-DSA-65) from a label.
    Returns (p256_priv, p256_pub_b64, mldsa_sk, mldsa_pub_b64)."""
    p256_seed = bytes.fromhex(
        digest_hex_text(f"certcrypt/conformance/member-p256/1:{label}")
    )[:32]
    p256_priv, p256_pub_sec1 = p256_keypair_from_seed(p256_seed)
    mldsa_pk, mldsa_sk = deterministic_ml_dsa65(f"member-mldsa:{label}")
    return (
        p256_priv,
        base64.b64encode(p256_pub_sec1).decode("ascii"),
        mldsa_sk,
        base64.b64encode(mldsa_pk).decode("ascii"),
    )


# Member 0 = the existing root composite keypair (issuer).
_member_signers = {
    "m0": {"p256_priv": p256_root_priv, "mldsa_sk": ml_dsa_sk},
}
_root_members = [
    {
        "member_kid": "m0",
        "public_key_p256_b64": p256_root_pub_b64,
        "public_key_mldsa_b64": ml_dsa_pub_key_b64,
    }
]
for _i in range(1, ROOT_QUORUM_N):
    _mkid = f"m{_i}"
    _p256_priv, _p256_pub_b64, _mldsa_sk, _mldsa_pub_b64 = _deterministic_composite_member(_mkid)
    _member_signers[_mkid] = {"p256_priv": _p256_priv, "mldsa_sk": _mldsa_sk}
    _root_members.append(
        {
            "member_kid": _mkid,
            "public_key_p256_b64": _p256_pub_b64,
            "public_key_mldsa_b64": _mldsa_pub_b64,
        }
    )


def build_bootstrap_manifest() -> dict:
    """The `system-manifest/1` bootstrap manifest version (sequence 0, one entry,
    k-of-n quorum). Closed schema: 4 top-level members, 10 entry members; the five
    bootstrap-entry null members are PRESERVED under JCS (RFC 8785), per
    system-manifest/1."""
    return {
        "manifest_profile_id": "system-manifest/1",
        "system_id": config["system_id"],
        "manifest_sequence": 0,
        "entries": [
            {
                "kid": ROOT_KID,
                "algorithm": PROFILE_P256_MLDSA65,
                "quorum": {"k": ROOT_QUORUM_K, "n": ROOT_QUORUM_N},
                "members": _root_members,
                "valid_from": ROOT_VALID_FROM,
                "valid_until": None,
                "predecessor_kid": None,
                "successor_kid": None,
                "predecessor_signatures": None,
                "predecessor_manifest_fingerprint": None,
            }
        ],
    }


bootstrap_manifest = build_bootstrap_manifest()

# system_root_fingerprint = SHA3-256(UTF-8(JCS(manifest))) — system-manifest/1 §10.
composite_root_fp = digest_hex_bytes(jcs_canonicalize_bytes(bootstrap_manifest))

# The domain root id is the manifest digest. Override config + synthetic_fingerprint
# so every fixture anchors to the root a verifier's conformance configuration expects.
config["system_root_fingerprint"] = composite_root_fp
synthetic_fingerprint = composite_root_fp


def composite_sign_member(payload_canon_digest_hex: str, member_kid: str) -> dict:
    """Composite-sign with a specific quorum MEMBER's component keys."""
    s = _member_signers[member_kid]
    return composite_sign_with(payload_canon_digest_hex, s["p256_priv"], s["mldsa_sk"])


def composite_sign_with(payload_canon_digest_hex: str, p256_priv, mldsa_sk: bytes) -> dict:
    """Sign a payload-canon digest under the canonical P-256+ML-DSA-65 composite
    with the GIVEN component keys. Returns the wire object `{alg, mode,
    signatures:[...]}` — classical (P-256) first, PQC (ML-DSA) second, AND.
    Per composite-signature/1.
    """
    m_prime = composite_m_prime(PROFILE_P256_MLDSA65, payload_canon_digest_hex)
    return {
        "alg": PROFILE_P256_MLDSA65,
        "mode": "AND",
        "signatures": [
            {
                "alg": ALG_ECDSA_P256,
                "encoding": "raw-rs-64",
                "low_s": True,
                "sig_b64": p256_sign_raw_rs_64_b64(p256_priv, m_prime),
            },
            {"alg": ALG_MLDSA65, "sig_b64": ml_dsa65_sign_b64(mldsa_sk, m_prime)},
        ],
    }


def composite_sign(payload_canon_digest_hex: str) -> dict:
    """Composite-sign with the ROOT keys (emission cert, system-foundation)."""
    return composite_sign_with(payload_canon_digest_hex, p256_root_priv, ml_dsa_sk)


# ── Zero-data capacity evidence ────────────────────────────────────────────
# Byte-exact against `capacity.evidence/1`. The vectors emitted here are the
# authority a reimplementation checks itself against.
#
# TWO distinct canonicalizations live here (see capacity-evidence/vectors.json):
#   1. ProjectedCommitment.signing_bytes and Level1AuthorizationBinding.signing_bytes
#      are INSERTION-ORDERED JSON in the DECLARED field order — NOT JCS. An
#      ML-DSA signature covers them, so the byte order is load-bearing. We build
#      the dicts in the exact declared field order below (Python 3.7+ preserves
#      insertion order; canonical_json_bytes serializes with no whitespace,
#      ensure_ascii=False).
#   2. CapacityEvidence.evidence_digest_hex uses RFC 8785 JCS (sorted keys) via
#      jcs_canonicalize_bytes — deterministic and language-agnostic over the
#      deeply nested whole-evidence object.
#
# Field orders are the ones capacity.evidence/1 declares. Do NOT reorder.

ZERO_DATA_PROFILE = "zero-data.unlinkable"

# ProjectedCommitment field order (capacity.evidence/1).
_PROJECTED_COMMITMENT_ORDER = [
    "commitment_version",
    "system_id",
    "system_root_fingerprint",
    "rules_version",
    "authorization_pseudonym",
    "holder_pseudonym",
    "pool_pseudonym",
    "certificate_commitment_digest",
    "consumed_quantity",
    "declared_effective_units",
    "issued_at",
    "expires_at",
]

# Level1AuthorizationBinding field order (capacity.evidence/1).
# No version tag: the binding is the signed sub-object of the zero-data
# capacity.holder-authorization/1, not a standalone artifact.
_LEVEL1_BINDING_ORDER = [
    "system_id",
    "rules_version",
    "system_root_fingerprint",
    "authorized_role",
    "authorization_issuer_kid",
    "valid_from",
    "valid_until",
    "holder_key_set_root",
]


def _ordered(d: dict, order: list[str]) -> list[tuple[str, Any]]:
    return [(k, d[k]) for k in order]


def build_capacity_evidence(
    *,
    system_id: str,
    system_root_fingerprint: str,
    rules_version: str,
    authorized_role: str,
    authorization_issuer_kid: str,
    valid_from: str,
    valid_until: str,
    certificate_commitment_digest: str,
    consumed_quantity: str,
    declared_effective_units: str,
    issued_at: str,
    expires_at: str,
    holder_id: str,
    pool_id: str,
    authorization_id: str,
    operation_salt: bytes,
    holder_keys: list[tuple[bytes, bytes]],
    leaf_index: int,
    system_domain_secret_key: bytes,
    system_domain_p256_priv,
) -> dict:
    """Assemble a complete CapacityEvidence.

    `holder_keys` is the holder's operation-key tree as a list of (pk, sk)
    ML-DSA-65 keypairs; `leaf_index` selects the non-reused leaf that signs this
    commitment (a non-reused leaf per commitment). `system_domain_secret_key` is the Level-1 key
    that authorizes the key-set root. ML-DSA signing uses the DETERMINISTIC FIPS
    204 variant (DETERMINISM.md §3) so the L1 + commitment signatures are a pure
    function of (seed, message).
    """
    salt = operation_salt
    holder_pseudonym = pseudonym_derive(salt, "holder", holder_id)
    pool_pseudonym = pseudonym_derive(salt, "pool", pool_id)
    authorization_pseudonym = pseudonym_derive(salt, "authorization", authorization_id)

    public_keys = [pk for (pk, _sk) in holder_keys]
    root = holder_key_set_root(public_keys)

    # --- Projected commitment (signed by the per-operation leaf key) ---
    projected_commitment = {
        "commitment_version": "capacity.commitment/1",
        "system_id": system_id,
        "system_root_fingerprint": system_root_fingerprint,
        "rules_version": rules_version,
        "authorization_pseudonym": authorization_pseudonym,
        "holder_pseudonym": holder_pseudonym,
        "pool_pseudonym": pool_pseudonym,
        "certificate_commitment_digest": certificate_commitment_digest,
        "consumed_quantity": consumed_quantity,
        "declared_effective_units": declared_effective_units,
        "issued_at": issued_at,
        "expires_at": expires_at,
    }
    pc_signing_bytes = canonical_json_bytes(
        _ordered(projected_commitment, _PROJECTED_COMMITMENT_ORDER)
    )
    leaf_sk = holder_keys[leaf_index][1]
    commitment_signature_b64 = ml_dsa65_sign_b64(leaf_sk, pc_signing_bytes)

    disclosure = holder_key_disclosure(public_keys, leaf_index)

    # --- Level-1 authorization binding (signed by the system-domain key) ---
    level1_binding = {
        "system_id": system_id,
        "rules_version": rules_version,
        "system_root_fingerprint": system_root_fingerprint,
        "authorized_role": authorized_role,
        "authorization_issuer_kid": authorization_issuer_kid,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "holder_key_set_root": root,
    }
    l1_signing_bytes = canonical_json_bytes(
        _ordered(level1_binding, _LEVEL1_BINDING_ORDER)
    )
    # Composite L1 anchor (`composite-signature/1`): all components sign M'(profile, SHA3(l1_signing_bytes)).
    level1_signature = composite_sign_with(
        digest_hex_bytes(l1_signing_bytes),
        system_domain_p256_priv,
        system_domain_secret_key,
    )

    # --- Projected authorization ---
    projected_authorization = {
        "system_id": system_id,
        "rules_version": rules_version,
        "system_root_fingerprint": system_root_fingerprint,
        "authorized_role": authorized_role,
        "authorization_issuer_kid": authorization_issuer_kid,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "holder_key_set_root": root,
        "level1_binding": level1_binding,
        "level1_signature": level1_signature,
        "authorization_pseudonym": authorization_pseudonym,
        "holder_pseudonym": holder_pseudonym,
    }

    return {
        "profile": ZERO_DATA_PROFILE,
        "operation_salt_hex": salt.hex(),
        "projected_authorization": projected_authorization,
        "projected_commitment": projected_commitment,
        "operation_key": disclosure,
        "commitment_signature_b64": commitment_signature_b64,
    }


def capacity_evidence_digest_hex(evidence: dict) -> str:
    """Whole-evidence digest bound into the `independence_proof`.

    RFC 8785 JCS (sorted keys), SHA3-256 — NOT the insertion-ordered signing
    bytes.
    """
    return digest_hex_bytes(jcs_canonicalize_bytes(evidence))


# ── JSON serialization mirroring JSON.stringify ────────────────────────────
# JS JSON.stringify(data, null, 2) + "\n": 2-space indent, escapes non-ASCII
# with \uXXXX (matches Python ensure_ascii=True default). All fixture data is
# ASCII, so this is equivalent.

def stringify_pretty(data: Any) -> str:
    return json.dumps(data, indent=2) + "\n"


def stringify_compact(data: Any) -> str:
    # JS JSON.stringify(data) — no spaces.
    return json.dumps(data, separators=(",", ":"))


def compute_proof_digest(proof: dict) -> str:
    """Canonical `proof_digest` (independence.proof/1 §10.11) — ONE formula
    across all producers.

    SHA3-256 of the JCS-canonical proof with `proof_digest` EMPTY, not removed —
    the same formula the reference proof producer uses, so the producer, this
    generator and any independent recomputation agree byte-for-byte.
    """
    view = {**proof, "proof_digest": ""}
    return digest_hex_bytes(jcs_canonicalize_bytes(view))


# ── Proof of Independence sealing (independence.proof/1) ───────────────────
# Every proof is SIGNED: a composite (ECDSA P-256 + ML-DSA-65) by the system-domain
# Level-1 capacity key, the same key every fixture foundation publishes as
# system_domain_capacity_key_{p256,mldsa}_b64 (§10.13). Fixtures that mutate a
# signed field re-seal the proof, so the property under test fails on its own
# check rather than on the signature.

PROOF_SIGNING_KID = "system-domain-kid-1"

# The eight members of the identity view `proof_id` digests (§10.3.1).
PROOF_IDENTITY_FIELDS = [
    "proof_version",
    "system_id",
    "rules_version",
    "system_root_fingerprint",
    "subtree_root",
    "closure_time",
    "consumed_commitment_ids",
    "settlement_ref",
]

# The signed view (§10.13.1): the identity view plus proof_id, anti_replay and,
# when present, node_attestation.
PROOF_SIGNED_FIELDS = PROOF_IDENTITY_FIELDS + ["proof_id", "anti_replay", "node_attestation"]


def derive_anti_replay(settlement_ref: str, subtree_root: str) -> dict:
    """`anti_replay` (§10.9): two domain-separated SHA3-256 digests of
    `settlement_ref:subtree_root`."""
    return {
        "nonce": digest_hex_text(f"certcrypt/anti-replay/1/nonce:{settlement_ref}:{subtree_root}"),
        "derivation": digest_hex_text(
            f"certcrypt/anti-replay/1/derivation:{settlement_ref}:{subtree_root}"
        ),
    }


def compute_proof_id(proof: dict) -> str:
    """`proof_id` = SHA3-256(JCS(identity view)) (§10.3.1)."""
    return digest_hex_bytes(
        jcs_canonicalize_bytes({k: proof[k] for k in PROOF_IDENTITY_FIELDS})
    )


def proof_signing_digest_hex(proof: dict) -> str:
    """SHA3-256(JCS(signed view)); absent members are omitted, never null."""
    view = {k: proof[k] for k in PROOF_SIGNED_FIELDS if k in proof}
    return digest_hex_bytes(jcs_canonicalize_bytes(view))


def seal_proof(proof: dict) -> None:
    """Recompute `proof_id`, sign the signed view with the system-domain Level-1
    composite key, then recompute `proof_digest` over the whole signed proof."""
    proof["proof_id"] = compute_proof_id(proof)
    _sd_mldsa_pub, sd_mldsa_sk = primitives.deterministic_ml_dsa65("system-domain")
    sd_p256_priv, _sd_p256_pub, _sd_p256_pub_b64 = primitives.deterministic_p256("system-domain-p256")
    proof["signature"] = {
        "signing_kid": PROOF_SIGNING_KID,
        **composite_sign_with(proof_signing_digest_hex(proof), sd_p256_priv, sd_mldsa_sk),
    }
    proof["proof_digest"] = compute_proof_digest(proof)


def write_json(file_path: str, data: Any) -> None:
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(stringify_pretty(data))


def write_text(file_path: str, text: str) -> None:
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(text)


def write_bytes(file_path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "wb") as f:
        f.write(data)


def ensure_dir(d: str) -> None:
    os.makedirs(d, exist_ok=True)


# ── Canonical JSON field builders ──────────────────────────────────────────

def build_bbp_fields(bbp: dict) -> list[tuple[str, Any]]:
    return [
        ("v", bbp["v"]),
        ("system_id", bbp["system_id"]),
        ("rules_version", bbp["rules_version"]),
        ("settlement_profile_id", bbp["settlement_profile_id"]),
        ("batch_id", bbp["batch_id"]),
        ("window_id", bbp["window_id"]),
        ("leaf_count", bbp["leaf_count"]),
        ("total_quantity", bbp["total_quantity"]),
        ("settlement_root", bbp["settlement_root"]),
    ]


def refresh_certificate_payload(cert: dict) -> None:
    anchor_canon_hex = digest_hex_bytes(jcs_canonicalize_bytes(cert["payload"]["anchor"]))
    cert["payload"]["anchor_commitment_digest_hex"] = digest_hex_text(
        cert["payload"]["anchor"]["nonce_hex"] + anchor_canon_hex
    )
    canonical_payload_bytes = jcs_canonicalize_bytes(cert["payload"])
    cert["payload_canon_digest_hex"] = digest_hex_bytes(canonical_payload_bytes)


def recompose_cert_signature(cert: dict) -> None:
    """Re-sign the composite issuer entry over the cert's current payload digest.

    Refreshes BOTH component signatures of the composite over the new M'. Call
    after any change to `payload_canon_digest_hex` (e.g. after refresh).
    """
    sig = composite_sign(cert["payload_canon_digest_hex"])
    cert["signatures"][0]["alg"] = sig["alg"]
    cert["signatures"][0]["mode"] = sig["mode"]
    cert["signatures"][0]["signatures"] = sig["signatures"]


def inject_after_first(text: str, marker: str, insertion: str) -> str:
    """Insert raw `insertion` right after the first `marker` in `text`. Used to
    write JSON that no JSON serializer would produce (a repeated member name)."""
    at = text.index(marker) + len(marker)
    return text[:at] + insertion + text[at:]


def clone_fixture(src: dict) -> dict:
    return copy.deepcopy(src)


# ── Fixture writer ─────────────────────────────────────────────────────────

# ── Foundation builders ────────────────────────────────────────────────────

def build_foundation_payload_digest(f: dict) -> str:
    """system-foundation/1 §9 canonical unsigned statement payload digest.

    The payload embeds the full `system_manifest` and carries the two
    `system_domain_capacity_key_*` members INSIDE the signed bytes (system-foundation/1 §9).
    Canonicalization is RFC 8785 JCS (sorted keys, null members preserved); the
    listing order below is human-readable only and does not affect the digest.
    """
    payload = {
        "foundation_profile_id": f["foundation_profile_id"],
        "foundation_statement_id": f["foundation_statement_id"],
        "system_id": f["system_id"],
        "system_root_fingerprint": f["system_root_fingerprint"],
        "system_manifest": f["system_manifest"],
        "root_fingerprint_derivation": f["root_fingerprint_derivation"],
        "system_domain_capacity_key_p256_b64": f["system_domain_capacity_key_p256_b64"],
        "system_domain_capacity_key_mldsa_b64": f["system_domain_capacity_key_mldsa_b64"],
        "published_rules_versions": f["published_rules_versions"],
        "statement_issued_at": f["statement_issued_at"],
    }
    return digest_hex_bytes(jcs_canonicalize_bytes(payload))


def sign_foundation(f: dict) -> list:
    """Sign the statement with a QUORUM of the bootstrap entry's members.

    Returns `statement_signatures`: a list of `{signer_member_kid, signature}`
    objects, one per signing member. At least `quorum.k` distinct members sign
    over M' = composite_m_prime(SHA3-256(JCS(§9 payload))). Default: members
    m0..m{k-1} (exactly k distinct members) — the canonical positive case.
    """
    payload_digest_hex = build_foundation_payload_digest(f)
    k = f["system_manifest"]["entries"][0]["quorum"]["k"]
    signer_kids = [m["member_kid"] for m in f["system_manifest"]["entries"][0]["members"]][:k]
    return [
        {"signer_member_kid": mkid, "signature": composite_sign_member(payload_digest_hex, mkid)}
        for mkid in signer_kids
    ]


def recompose_foundation_signature(f: dict) -> None:
    """Re-sign the foundation's quorum statement_signatures in place.

    Call after mutating any §9 payload field.
    """
    f["statement_signatures"] = sign_foundation(f)



# ── Lineage constants ──────────────────────────────────────────────────────

FULL_LINEAGE = {
    "certcrypt_domain_bound": True,
    "independence_under_certcrypt_rules": True,
    "settlement_bound": True,
    "capacity_consumption_bound": True,
    "history_bound_under_certcrypt": True,
}

NO_LINEAGE = {
    "certcrypt_domain_bound": False,
    "independence_under_certcrypt_rules": False,
    "settlement_bound": False,
    "capacity_consumption_bound": False,
    "history_bound_under_certcrypt": False,
}


# ── P001 — zero-data + commitment sub-tree (the canonical positive fixture) ─
# Builder for a positive fixture on the zero-data + commitment sub-tree model.
#
# Model:
#   - settlement leaf = sub-tree of accepted commitment_ids (clear, server-side),
#     committed by subtree_root in the leaf/proof.
#   - hybrid emission binding: the cert carries no leaf commitment of its own;
#     the link is SHA3(JCS(cert)) == certificate_commitment_digest (inside the
#     zero-data CapacityEvidence) AND commitment_id ∈ subtree_root (CommitmentInclusionProof).
#   - the proof binds capacity_evidence_digest and lists consumed_commitment_ids.

def compute_cost_commitment_subtree(subtree_root: str, declared_effective_units: str = "1") -> str:
    """cost_commitment preimage binding subtree_root; `v` is cccc1.

    `declared_effective_units` defaults to "1" (single non-collection subject,
    submission-set/1 §13.2). Multi-subject fixtures pass the summed per-subject
    units so the cost_commitment preimage binds the SAME value the capacity
    evidence carries (capacity.commitment/1 §13.1); the two MUST agree or the
    fixture would bind a value the EFFECTIVE_UNITS_BINDING_VALID check rejects.
    """
    preimage = {
        "v": "cccc1",
        "subtree_root": subtree_root,
        "rule_schema_id": "rules/conformance",
        "economically_relevant_assertion_set": {
            "declared_effective_units": declared_effective_units,
        },
        "canonicalization_domain": "jcs/rfc8785",
    }
    return digest_hex_bytes(jcs_canonicalize_bytes(preimage))


def build_system_domain_foundation(sd_capacity_key_mldsa_b64: str, sd_capacity_key_p256_b64: str) -> dict:
    """A `system-foundation/1` statement that EMBEDS a `system-manifest/1` bootstrap
    manifest (k-of-n composite quorum) and is authorized by a quorum of that
    manifest's bootstrap-entry members.

    Three notions, do not conflate:
      - The bootstrap ROOT is a k-of-n quorum of composite member keys, catalogued
        in `system_manifest.entries[0].members`; `system_root_fingerprint =
        SHA3-256(JCS(system_manifest))` (system-manifest/1 §10). The statement is
        authorized by `statement_signatures` (≥ k member composite signatures over
        the §9 payload).
      - The system-domain Level-1 capacity key (signer of the PoI + Level-1 binding)
        is a DISTINCT composite key carried at statement level in
        `system_domain_capacity_key_{p256,mldsa}_b64` and INSIDE the signed payload
        (system-foundation/1 §9); the verifier's capacity-binding resolves the L1 anchor there.
      - The emission-certificate issuer signs with member m0's composite keypair
        (one member of the active entry, system-manifest/1 §15)."""
    foundation = {
        "foundation_profile_id": "system-foundation/1",
        "foundation_statement_id": "test-foundation-P001-zero-data",
        "system_id": config["system_id"],
        "system_root_fingerprint": composite_root_fp,
        "system_manifest": build_bootstrap_manifest(),
        "root_fingerprint_derivation": "sha3-256-system-manifest-jcs-v1",
        "published_rules_versions": ["rules/conformance"],
        "statement_issued_at": "2026-04-12T00:00:00Z",
        # Distinct COMPOSITE Level-1 key for the zero-data capacity anchor (`composite-signature/1`):
        # classical (P-256) + PQC (ML-DSA) component pubkeys (L1 binding signs
        # composite, AND).
        "system_domain_capacity_key_p256_b64": sd_capacity_key_p256_b64,
        "system_domain_capacity_key_mldsa_b64": sd_capacity_key_mldsa_b64,
    }
    foundation["statement_signatures"] = sign_foundation(foundation)
    return foundation


def build_zero_data_fixture(
    p: dict,
    cert_mutator=None,
    evidence_mutator=None,
    subjects=None,
    declared_effective_units="1",
    auth_valid_from="2026-01-01T00:00:00Z",
    auth_role="capacity_commitment_holder",
) -> dict:
    """A positive fixture on the zero-data + commitment sub-tree model.

    Parameterized over the P00x identity/economics (fixtureId, batchId, …,
    issuerScope, capacityAuthRef, leafIndex, batchSize, consumedQuantity,
    totalQuantity, blockNum, libNum). Returns dict with baseCert, proof,
    material, capacityEvidence, foundation, commitmentInclusionProof.

    `cert_mutator`, if supplied, is called as cert_mutator(base_cert) AFTER the
    certificate is built and signed but BEFORE the certificate_commitment_digest
    (ccd = SHA3(JCS(cert))) is computed and the capacity evidence is signed over
    it. This keeps the whole emission binding coherent for any certificate change
    (a PQC dual-sign entry, a corrupted/replaced signature): the ccd anchors the
    MUTATED cert and the evidence signature covers that ccd, so the only failing
    check is the one the mutation targets (BASE_CERTIFICATE_AUTHENTIC, which
    carries the normative ML-DSA-65 component) — never a spurious binding or capacity-evidence failure. Used by
    the S-series (signature authenticity) and Q-series (PQC) fixtures.

    `evidence_mutator`, if supplied, is called as evidence_mutator(capacity_evidence)
    AFTER the evidence is built but BEFORE its digest (= commitment_id) and the
    sub-tree are computed, so the binding chain stays coherent and only the INTERNAL
    capacity-evidence verification fails (CAPACITY_EVIDENCE_VALID in isolation)."""
    fixture_id = p["fixtureId"]
    batch_id = p["batchId"]
    window_id = p["windowId"]
    trx_id = p["trxId"]
    leaf_index = p["leafIndex"]
    batch_size = p["batchSize"]
    consumed_quantity = p["consumedQuantity"]   # the target leaf's consumption
    total_quantity = p["totalQuantity"]         # whole batch
    block_num, lib_num = p["blockNum"], p["libNum"]
    issuer_scope = p["issuerScope"]
    capacity_auth_ref = p["capacityAuthRef"]
    leaf_label = f"leaf-{fixture_id}"

    # ── 1. Base certificate (no leaf commitment in payload — hybrid binding) ──
    nonce_hex = digest_hex_text(
        f"certcrypt/conformance/nonce/1:{leaf_label}:anchor.nonce_hex:0"
    )
    subject_commitment_hex = digest_hex_text(f"subject:{leaf_label}")
    # Default: one non-collection (binary) subject → declared_effective_units "1".
    # `subjects`, when supplied, overrides the anchor subject list (multi-subject
    # fixtures for the effective-units binding). The caller is responsible for
    # passing a matching `declared_effective_units` (Σ per-subject units).
    if subjects is None:
        subjects = [
            {"profile": "subject.binary/1", "commitment_digest_hex": subject_commitment_hex}
        ]
    anchor = {
        "root_id": config["system_root_fingerprint"],
        "issued_at": "2026-04-11T12:00:00Z",
        "nonce_hex": nonce_hex,
        "subjects": subjects,
    }
    anchor_canon_hex = digest_hex_bytes(jcs_canonicalize_bytes(anchor))
    anchor_commitment_hex = digest_hex_text(nonce_hex + anchor_canon_hex)
    payload = {
        "anchor": anchor,
        "anchor_commitment_digest_hex": anchor_commitment_hex,
        "system_id": config["system_id"],
        "rules_version": "rules/conformance",
        # No leaf commitment in the payload: the emission binding is hybrid.
    }
    payload_digest_hex = digest_hex_bytes(jcs_canonicalize_bytes(payload))
    cert_composite = composite_sign(payload_digest_hex)
    base_cert = {
        "schema": "certcrypt-certificate",
        "payload": payload,
        "payload_canon_digest_hex": payload_digest_hex,
        "signatures": [
            {
                "role": "issuer",
                "sig_target": "payload_canon_digest_hex",
                "alg": cert_composite["alg"],
                "mode": cert_composite["mode"],
                "signatures": cert_composite["signatures"],
                "signer": {
                    "id": issuer_scope,
                    "pub_p256_b64": p256_root_pub_b64,
                    "pub_mldsa_b64": ml_dsa_pub_key_b64,
                },
            }
        ],
    }

    # Optional certificate mutation (authenticity/PQC fixtures): applied before
    # the ccd is computed so the binding + evidence stay coherent with the cert
    # actually shipped.
    if cert_mutator is not None:
        cert_mutator(base_cert)

    # ── 2. certificate_commitment_digest = SHA3-256(JCS(whole cert)) ──
    certificate_commitment_digest = digest_hex_bytes(jcs_canonicalize_bytes(base_cert))

    # ── 3. Zero-data capacity evidence for the verified (target) commitment ──
    # Built BEFORE the sub-tree: in the zero-data profile a commitment's id IS the
    # canonical digest of its capacity evidence (commitment_id =
    # evidence_digest_hex of the evidence). The fixture must satisfy the
    # same invariant the verifier enforces in LEAF_BINDING_VALID
    # (independence.proof/1 §7.10), so the target commitment_id is derived from the
    # evidence, not synthesized. The holder's operation-key tree is per-fixture; the
    # system-domain Level-1 key is SHARED across fixtures (one system domain
    # authorizes all holders).
    holder_label = issuer_scope.replace("issuer:", "")
    holder_keys = [
        primitives.deterministic_ml_dsa65(f"{fixture_id}-holder-op-key-{i}")
        for i in range(4)
    ]
    sd_pub, sd_sec = primitives.deterministic_ml_dsa65("system-domain")
    sd_pub_b64 = base64.b64encode(sd_pub).decode("ascii")
    # P-256 classical component of the composite system-domain L1 key (`composite-signature/1`).
    sd_p256_priv, _sd_p256_pub, sd_p256_pub_b64 = primitives.deterministic_p256("system-domain-p256")

    capacity_evidence = build_capacity_evidence(
        system_id=config["system_id"],
        system_root_fingerprint=config["system_root_fingerprint"],
        rules_version="rules/conformance",
        authorized_role=auth_role,
        authorization_issuer_kid="system-domain-kid-1",
        valid_from=auth_valid_from,
        valid_until="2027-01-01T00:00:00Z",
        certificate_commitment_digest=certificate_commitment_digest,
        consumed_quantity=consumed_quantity,
        # Per-subject effective units (submission-set/1 §13.2): defaults to "1"
        # (one non-collection subject). Multi-subject fixtures pass Σ per-subject
        # units. MUST match the value the leaf's cost_commitment preimage binds
        # (compute_cost_commitment_subtree below) — the same value the verifier's
        # EFFECTIVE_UNITS_BINDING_VALID check binds to the certified subjects.
        declared_effective_units=declared_effective_units,
        issued_at="2026-04-11T12:00:00Z",
        expires_at="2026-05-11T12:00:00Z",
        holder_id=f"holder:{holder_label}",
        pool_id=f"pool:{holder_label}-default",
        authorization_id=f"auth:{holder_label}-{fixture_id}",
        operation_salt=f"operation-salt-{fixture_id}".encode("utf-8"),
        holder_keys=holder_keys,
        leaf_index=0,
        system_domain_secret_key=sd_sec,
        system_domain_p256_priv=sd_p256_priv,
    )
    # evidence_mutator, if supplied, mutates the capacity evidence BEFORE its digest
    # (= commitment_id) is computed and the sub-tree is built. This keeps the whole
    # binding chain coherent (commitment_id, leaf hash, subtree_root, proof digest all
    # derive from the MUTATED evidence), so LEAF_BINDING_VALID still passes and the
    # only failing check is the INTERNAL capacity-evidence verification the mutation
    # targets (a bad L1 signature, a broken pseudonym binding, tampered membership) —
    # i.e. CAPACITY_EVIDENCE_VALID in isolation. Mirrors cert_mutator for the emission
    # binding. Preserves the zero-data/unlinkable projection (mutations touch signed
    # bindings, not identifiers).
    if evidence_mutator is not None:
        evidence_mutator(capacity_evidence)
    capacity_evidence_digest = capacity_evidence_digest_hex(capacity_evidence)

    # ── 3.bis Commitment sub-tree: 2 commitments, same issuer_scope+cap_auth ──
    #   The verified cert corresponds to the target commitment (index 0), whose id
    #   is the digest of the evidence above (the §7.10 binding). The sibling is a
    #   second accepted commitment of the same issuer in the leaf; its id stays a
    #   distinct opaque 64-hex value (its own evidence is not carried — a verifier
    #   evaluating the target cert never sees it, per §7.10).
    target_commitment_id = capacity_evidence_digest
    sibling_commitment_id = digest_hex_text(
        f"commitment:{issuer_scope}:{capacity_auth_ref}:{fixture_id}-sibling"
    )
    commitment_ids = [target_commitment_id, sibling_commitment_id]
    subtree_root, _commit_leaf_hashes = primitives.compute_subtree_root(commitment_ids)
    commitment_inclusion_proof = primitives.build_commitment_inclusion_proof(
        commitment_ids, 0
    )

    cost_commitment = compute_cost_commitment_subtree(subtree_root, declared_effective_units)
    # Zero-data: the resolved-authorization digest is SHA3-256 of the
    # capacity evidence's Level-1 binding signing bytes — the same value the
    # verifier recomputes from the evidence. It identifies the authorization
    # without a correlating cleartext issuer_scope (see the aggregated settlement profile).
    resolved_auth_digest = digest_hex_bytes(
        canonical_json_bytes(
            _ordered(
                capacity_evidence["projected_authorization"]["level1_binding"],
                _LEVEL1_BINDING_ORDER,
            )
        )
    )

    # ── 4. Settlement leaf preimage (committed by subtree_root) ──
    leaf_preimage = {
        "v": "ccab1-leaf",
        "system_id": config["system_id"],
        "rules_version": "rules/conformance",
        "settlement_profile_id": config["settlement_profile_id"],
        "batch_id": batch_id,
        "leaf_index": str(leaf_index),
        "subtree_root": subtree_root,
        "cost_commitment": cost_commitment,
        "consumed_quantity": consumed_quantity,
    }
    leaf_fields = [
        ("v", leaf_preimage["v"]),
        ("system_id", leaf_preimage["system_id"]),
        ("rules_version", leaf_preimage["rules_version"]),
        ("settlement_profile_id", leaf_preimage["settlement_profile_id"]),
        ("batch_id", leaf_preimage["batch_id"]),
        ("leaf_index", leaf_preimage["leaf_index"]),
        ("subtree_root", leaf_preimage["subtree_root"]),
        ("cost_commitment", leaf_preimage["cost_commitment"]),
        ("consumed_quantity", leaf_preimage["consumed_quantity"]),
    ]
    target_leaf_hash = compute_leaf_hash(canonical_json_bytes(leaf_fields))

    # Batch of `batch_size` leaves: the target leaf at `leaf_index`, the rest
    # placeholder leaves (other issuers). Single-leaf batches (batch_size 1) get
    # just the target — its hash IS the settlement root.
    leaf_hashes = []
    for i in range(batch_size):
        if i == leaf_index:
            leaf_hashes.append(target_leaf_hash)
        else:
            leaf_hashes.append(
                compute_leaf_hash(
                    canonical_json_bytes(
                        [("v", "ccab1-leaf"), ("placeholder", f"{fixture_id}-other-leaf-{i}")]
                    )
                )
            )
    settlement_root = compute_merkle_root(leaf_hashes)
    sibling_hashes = generate_inclusion_proof(leaf_hashes, leaf_index)

    # ── 5. Batch binding preimage + memo ──
    bbp = {
        "v": "ccab1",
        "system_id": config["system_id"],
        "rules_version": "rules/conformance",
        "settlement_profile_id": config["settlement_profile_id"],
        "batch_id": batch_id,
        "window_id": window_id,
        "leaf_count": str(batch_size),
        "total_quantity": total_quantity,
        "settlement_root": settlement_root,
    }
    batch_binding_digest = digest_hex_bytes(canonical_json_bytes(build_bbp_fields(bbp)))
    memo = f"{config['xrpl_memo_prefix']}{batch_binding_digest}"

    # ── 6. Foundation carrying the ML-DSA system-domain key ──
    # (capacity_evidence + its digest were built in step 3, before the sub-tree,
    # so the target commitment_id could be derived from the evidence digest.)
    foundation = build_system_domain_foundation(sd_pub_b64, sd_p256_pub_b64)

    # ── 8. Independence proof: subtree_root + capacity binding + consumed ids ──
    settlement_ref_str = f"{config['xrpl_chain_id']}:{trx_id}:0:{batch_id}:{window_id}"
    proof = {
        "proof_version": "independence.proof/1",
        "system_id": config["system_id"],
        "system_root_fingerprint": config["system_root_fingerprint"],
        "rules_version": "rules/conformance",
        "subtree_root": subtree_root,
        "settlement_ref": settlement_ref_str,
        "settlement": {
            "profile_id": config["settlement_profile_id"],
            "ref": settlement_ref_str,
            # Finality as a list of witnesses (one witness here).
            "finality_proofs": [
                {
                    "substrate": config["substrate"],
                    "block_height": str(block_num),
                    "timestamp": "2026-04-11T12:00:00Z",
                    "confirmation_level": "irreversible",
                }
            ],
        },
        "batch": {"root": settlement_root, "index": str(leaf_index), "size": str(batch_size)},
        "inclusion_proof": sibling_hashes,
        "anti_replay": derive_anti_replay(settlement_ref_str, subtree_root),
        "independence_result": "independent",
        "proof_id": "",
        "closure_time": "2026-04-11T12:00:00Z",
        "consumed_commitment_ids": commitment_ids,
        "proof_digest": "",
    }
    seal_proof(proof)

    # ── 9. Settlement material (submission_assignment_proof, subtree_root) ──
    material = {
        "settlement_profile_id": config["settlement_profile_id"],
        "settlement_action": {
            # An XRPL `Payment` of the CERT MPT from the aggregate pool BACK TO THE
            # ISSUER. Paying an MPT to its own issuer destroys that amount: it is
            # how supply ceases to exist on this substrate, and the only way — a
            # transfer elsewhere leaves the supply existing, merely immobile.
            #
            # `from` is the pool, never an issuer: the ledger must not reveal which
            # issuer certified (unlinkability).
            "from": config["xrpl_pool_account"],
            "quantity": f"{total_quantity} {config['xrpl_token_symbol']}",
            "memo": memo,
            # Names the MPT ISSUANCE, not a contract account: XRPL has no
            # contracts, and the issuance is the object whose supply is destroyed.
            "contract": config["xrpl_mpt_issuance_id"],
            "name": config["xrpl_action_name"],
            "chain_id": config["xrpl_chain_id"],
            "trx_id": trx_id,
            # ALWAYS "0". XRPL has no sub-position inside a transaction, and a
            # synthesized index would read as a re-inclusion that never happened.
            "action_ordinal": "0",
        },
        "finality_proof": {
            "block_num": str(block_num),
            "block_id": digest_hex_text(f"block:{block_num}"),
            # On XRPL finality is BINARY: a validated ledger is final, and there is
            # no depth trailing behind it. So the irreversibility fields name the
            # SAME ledger as the inclusion — not an approximation, and a verifier
            # must not expect a gap (settlement.aggregated.xrpl/1 §11.1).
            "last_irreversible_block_num": str(block_num),
            "last_irreversible_block_id": digest_hex_text(f"block:{block_num}"),
            # The ledger's own consensus close time (the capacity-consumption
            # "when"). Before the evidence's expires_at for positive fixtures.
            "block_timestamp": "2026-04-11T12:00:00Z",
        },
        "batch_manifest": {
            "batch_id": batch_id,
            "window_id": window_id,
            "leaf_count": str(batch_size),
            "total_quantity": total_quantity,
            "settlement_root": settlement_root,
            "system_id": config["system_id"],
            "rules_version": "rules/conformance",
            "settlement_profile_id": config["settlement_profile_id"],
        },
        "capacity_consumption_proof": {
            "total_quantity": total_quantity,
            "leaf_quantity": consumed_quantity,
            "token_symbol": config["xrpl_token_symbol"],
            "token_contract": config["xrpl_mpt_issuance_id"],
        },
        "submission_assignment_proof": {
            "subtree_root": subtree_root,
            "leaf_index": str(leaf_index),
            "leaf_preimage": leaf_preimage,
            "leaf_hash": target_leaf_hash,
            "sibling_hashes": sibling_hashes,
        },
        # One bridge per distinct resolved authorization in the leaf (settlement-material/1 §9).
        # These base fixtures are single-authorization, so the array has one entry;
        # the multi-authorization case is exercised by a dedicated fixture.
        "authorization_bridge_proofs": [
            {
                "resolved_authorization_digest": resolved_auth_digest,
                "cost_commitment": cost_commitment,
                "consumed_quantity": consumed_quantity,
                "batch_binding_preimage": bbp,
            }
        ],
        "coherence_material": {
            "system_id": config["system_id"],
            "rules_version": "rules/conformance",
            "settlement_profile_id": config["settlement_profile_id"],
        },
    }

    return {
        "baseCert": base_cert,
        "proof": proof,
        "material": material,
        "capacityEvidence": capacity_evidence,
        "foundation": foundation,
        "commitmentInclusionProof": commitment_inclusion_proof,
    }


def write_original_material(fixture_dir: str, original_material: list) -> None:
    """Write the §8.5 original-material delivery container for the opt-in
    ORIGINAL_MATERIAL_COMPARISON_VALID plane, and return nothing (side-effect only).

    `original_material` is a list of per-subject entries in subject index order:
      - {"material_utf8": "<str>"} or {"material_bytes": b"..."} → single blob (writes
        material-<i>.bin, manifest entry {"material_file": ...})
      - {"leaf_materials_utf8": ["<str>", ...],
         "collection_object": {...}}                        → collection (writes
        leaf-<i>-<j>.bin per leaf, manifest entry {"collection": ..., "leaf_files": [...]})
      - {"material_utf8": "<record>", "nested_materials": [{"id": "<id>",
         "material_utf8": "<str>"}]}                         → an AI-decision record with
        any disclosed parts keyed by their record-local ids. A nested entry may
        instead carry {"prehashed": true, "subject_local_digest_hex": "..."}.
    (leaf_files → one collection's leaves, material_file → a single blob)."""
    material_dir = os.path.join(fixture_dir, "material")
    os.makedirs(material_dir, exist_ok=True)
    manifest = []
    for i, entry in enumerate(original_material):
        if "leaf_materials_utf8" in entry:
            leaf_files = []
            for j, leaf in enumerate(entry["leaf_materials_utf8"]):
                fn = f"leaf-{i}-{j}.bin"
                write_text(os.path.join(material_dir, fn), leaf)
                leaf_files.append(fn)
            manifest.append({"collection": entry["collection_object"], "leaf_files": leaf_files})
        else:
            fn = f"material-{i}.bin"
            if "material_bytes" in entry:
                write_bytes(os.path.join(material_dir, fn), entry["material_bytes"])
            else:
                write_text(os.path.join(material_dir, fn), entry["material_utf8"])
            m = {"material_file": fn}
            if "nested_materials" in entry:
                m["materials"] = []
                for j, nested in enumerate(entry["nested_materials"]):
                    delivered = {"id": nested["id"]}
                    if nested.get("prehashed") is True:
                        delivered.update({
                            "prehashed": True,
                            "subject_local_digest_hex": nested["subject_local_digest_hex"],
                        })
                        if "byte_length" in nested:
                            delivered["byte_length"] = nested["byte_length"]
                    else:
                        sfn = f"nested-{i}-{j}.bin"
                        if "material_bytes" in nested:
                            write_bytes(os.path.join(material_dir, sfn), nested["material_bytes"])
                        else:
                            write_text(os.path.join(material_dir, sfn), nested["material_utf8"])
                        delivered["material_file"] = sfn
                    m["materials"].append(delivered)
            manifest.append(m)
    write_json(os.path.join(material_dir, "manifest.json"), manifest)


def write_zero_data_fixture(
    conformance_dir: str, fixture_id: str, f: dict, readme: str, expected_extra: dict = None,
    original_material: list = None
) -> None:
    fixture_dir = os.path.join(conformance_dir, fixture_id)
    artifacts_dir = os.path.join(fixture_dir, "artifacts")
    request = {
        "verification_target_requested": "independent",
        "input_mode": "artifact_set",
        "base_certificate_path": "artifacts/base-certificate.json",
        "independence_proof_path": "artifacts/independence-proof.json",
        "settlement_material_path": "artifacts/settlement-material.json",
        "capacity_evidence_path": "artifacts/capacity-evidence.json",
        "commitment_inclusion_proof_path": "artifacts/commitment-inclusion-proof.json",
        "system_foundation_path": "artifacts/system-foundation.json",
    }
    # Opt-in original-material plane (§8.5): when supplied, the verifier runs
    # ORIGINAL_MATERIAL_COMPARISON_VALID against the delivered subject material.
    if original_material is not None:
        write_original_material(fixture_dir, original_material)
        request["original_material_path"] = "material/manifest.json"
    write_json(os.path.join(fixture_dir, "input.json"), request)
    write_json(os.path.join(artifacts_dir, "base-certificate.json"), f["baseCert"])
    write_json(os.path.join(artifacts_dir, "independence-proof.json"), f["proof"])
    write_json(os.path.join(artifacts_dir, "settlement-material.json"), f["material"])
    write_json(os.path.join(artifacts_dir, "capacity-evidence.json"), f["capacityEvidence"])
    write_json(os.path.join(artifacts_dir, "system-foundation.json"), f["foundation"])
    write_json(
        os.path.join(artifacts_dir, "commitment-inclusion-proof.json"),
        f["commitmentInclusionProof"],
    )
    expected = {
        "result_code": "INDEPENDENT_VALID",
        "failed_check_ids": [],
        "certcrypt_lineage": FULL_LINEAGE,
    }
    if expected_extra:
        expected.update(expected_extra)
    write_json(os.path.join(fixture_dir, "expected-result.json"), expected)
    write_text(os.path.join(fixture_dir, "README.md"), readme)


def write_negative_zero_data(
    adversarial_dir: str,
    fixture_id: str,
    f: dict,
    expected_result: dict,
    readme: str,
    original_material: list = None,
) -> None:
    """Write a negative fixture on the zero-data model: the full artifact set (as
    `write_zero_data_fixture`) but with a caller-supplied expected_result that
    encodes the broken property. `f` is a (cloned + mutated) zero-data fixture.
    `original_material` (optional) delivers §8.5 subject material to exercise the
    ORIGINAL_MATERIAL_COMPARISON_VALID plane negatively (mismatch/cardinality/etc.)."""
    fixture_dir = os.path.join(adversarial_dir, fixture_id)
    artifacts_dir = os.path.join(fixture_dir, "artifacts")
    request = {
        "verification_target_requested": "independent",
        "input_mode": "artifact_set",
        "base_certificate_path": "artifacts/base-certificate.json",
        "independence_proof_path": "artifacts/independence-proof.json",
        "settlement_material_path": "artifacts/settlement-material.json",
        "capacity_evidence_path": "artifacts/capacity-evidence.json",
        "commitment_inclusion_proof_path": "artifacts/commitment-inclusion-proof.json",
        "system_foundation_path": "artifacts/system-foundation.json",
    }
    if original_material is not None:
        write_original_material(fixture_dir, original_material)
        request["original_material_path"] = "material/manifest.json"
    write_json(os.path.join(fixture_dir, "input.json"), request)
    write_json(os.path.join(artifacts_dir, "base-certificate.json"), f["baseCert"])
    write_json(os.path.join(artifacts_dir, "independence-proof.json"), f["proof"])
    write_json(os.path.join(artifacts_dir, "settlement-material.json"), f["material"])
    write_json(os.path.join(artifacts_dir, "capacity-evidence.json"), f["capacityEvidence"])
    write_json(os.path.join(artifacts_dir, "system-foundation.json"), f["foundation"])
    write_json(
        os.path.join(artifacts_dir, "commitment-inclusion-proof.json"),
        f["commitmentInclusionProof"],
    )
    write_json(os.path.join(fixture_dir, "expected-result.json"), expected_result)
    write_text(os.path.join(fixture_dir, "README.md"), readme)


def build_multi_auth_fixture(*, fixture_id: str, target_index: int) -> dict:
    """A positive fixture where ONE leaf groups TWO commitments under TWO DISTINCT
    Level-1 authorizations (settlement-material/1 §9). Both commitments are accepted into the
    same leaf/subtree; the settlement material carries TWO authorization bridges
    (one per distinct resolved authorization). This builds the artifact set that
    VERIFIES the certificate at `target_index` (0 or 1): the verifier must select
    the bridge whose resolved_authorization_digest matches THIS evidence's L1
    binding. Calling with both indices proves every member of a multi-auth leaf
    reaches INDEPENDENT_VALID.

    The two authorizations differ by holder key-set (distinct holder_key_set_root
    -> distinct level1_binding -> distinct digest), both signed by the SAME shared
    system-domain Level-1 key. Returns the standard fixture dict.
    """
    batch_id = f"batch-{fixture_id}"
    window_id = f"window-{fixture_id}"
    trx_id = f"trx-{fixture_id}"
    leaf_index, batch_size = 0, 1
    consumed_quantity = "5.00"
    total_quantity = "10.00"
    block_num, lib_num = 4000, 4010

    sd_pub, sd_sec = primitives.deterministic_ml_dsa65("system-domain")
    sd_pub_b64 = base64.b64encode(sd_pub).decode("ascii")
    sd_p256_priv, _sd_p256_pub, sd_p256_pub_b64 = primitives.deterministic_p256("system-domain-p256")

    # Build the two members (A, B): each a cert + a capacity evidence whose digest
    # IS its commitment_id, under its OWN holder key-set (distinct authorization).
    members = []
    for label in ("a", "b"):
        nonce_hex = digest_hex_text(f"certcrypt/conformance/nonce/1:{fixture_id}-{label}")
        subject_commitment_hex = digest_hex_text(f"subject:{fixture_id}-{label}")
        anchor = {
            "root_id": config["system_root_fingerprint"],
            "issued_at": "2026-04-11T12:00:00Z",
            "nonce_hex": nonce_hex,
            "subjects": [
                {"profile": "subject.binary/1", "commitment_digest_hex": subject_commitment_hex}
            ],
        }
        anchor_canon_hex = digest_hex_bytes(jcs_canonicalize_bytes(anchor))
        anchor_commitment_hex = digest_hex_text(nonce_hex + anchor_canon_hex)
        payload = {
            "anchor": anchor,
            "anchor_commitment_digest_hex": anchor_commitment_hex,
            "system_id": config["system_id"],
            "rules_version": "rules/conformance",
        }
        payload_digest_hex = digest_hex_bytes(jcs_canonicalize_bytes(payload))
        cert_composite = composite_sign(payload_digest_hex)
        base_cert = {
            "schema": "certcrypt-certificate",
            "payload": payload,
            "payload_canon_digest_hex": payload_digest_hex,
            "signatures": [
                {
                    "role": "issuer",
                    "sig_target": "payload_canon_digest_hex",
                    "alg": cert_composite["alg"],
                    "mode": cert_composite["mode"],
                    "signatures": cert_composite["signatures"],
                    "signer": {
                        "id": f"issuer:{fixture_id}-{label}",
                        "pub_p256_b64": p256_root_pub_b64,
                        "pub_mldsa_b64": ml_dsa_pub_key_b64,
                    },
                }
            ],
        }
        ccd = digest_hex_bytes(jcs_canonicalize_bytes(base_cert))
        # DISTINCT holder key-set per member -> distinct holder_key_set_root ->
        # distinct level1_binding -> distinct resolved_authorization_digest.
        holder_keys = [
            primitives.deterministic_ml_dsa65(f"{fixture_id}-{label}-holder-op-key-{i}")
            for i in range(4)
        ]
        evidence = build_capacity_evidence(
            system_id=config["system_id"],
            system_root_fingerprint=config["system_root_fingerprint"],
            rules_version="rules/conformance",
            authorized_role="capacity_commitment_holder",
            authorization_issuer_kid="system-domain-kid-1",
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2027-01-01T00:00:00Z",
            certificate_commitment_digest=ccd,
            consumed_quantity=consumed_quantity,
            declared_effective_units="1",
            issued_at="2026-04-11T12:00:00Z",
            expires_at="2026-05-11T12:00:00Z",
            holder_id=f"holder:{fixture_id}-{label}",
            pool_id=f"pool:{fixture_id}-{label}-default",
            authorization_id=f"auth:{fixture_id}-{label}",
            operation_salt=f"operation-salt-{fixture_id}-{label}".encode("utf-8"),
            holder_keys=holder_keys,
            leaf_index=0,
            system_domain_secret_key=sd_sec,
            system_domain_p256_priv=sd_p256_priv,
        )
        commitment_id = capacity_evidence_digest_hex(evidence)
        resolved_auth_digest = digest_hex_bytes(
            canonical_json_bytes(
                _ordered(evidence["projected_authorization"]["level1_binding"], _LEVEL1_BINDING_ORDER)
            )
        )
        members.append({
            "base_cert": base_cert,
            "evidence": evidence,
            "commitment_id": commitment_id,
            "resolved_auth_digest": resolved_auth_digest,
        })

    # Shared leaf: subtree over BOTH commitment_ids, in member order (a, b).
    commitment_ids = [m["commitment_id"] for m in members]
    subtree_root, _ = primitives.compute_subtree_root(commitment_ids)
    cost_commitment = compute_cost_commitment_subtree(subtree_root)

    leaf_preimage = {
        "v": "ccab1-leaf", "system_id": config["system_id"], "rules_version": "rules/conformance",
        "settlement_profile_id": config["settlement_profile_id"], "batch_id": batch_id,
        "leaf_index": str(leaf_index), "subtree_root": subtree_root,
        "cost_commitment": cost_commitment, "consumed_quantity": consumed_quantity,
    }
    target_leaf_hash = compute_leaf_hash(canonical_json_bytes([(k, leaf_preimage[k]) for k in
        ["v","system_id","rules_version","settlement_profile_id","batch_id","leaf_index","subtree_root","cost_commitment","consumed_quantity"]]))
    settlement_root = compute_merkle_root([target_leaf_hash])
    sibling_hashes = generate_inclusion_proof([target_leaf_hash], leaf_index)

    bbp = {
        "v": "ccab1", "system_id": config["system_id"], "rules_version": "rules/conformance",
        "settlement_profile_id": config["settlement_profile_id"], "batch_id": batch_id,
        "window_id": window_id, "leaf_count": str(batch_size), "total_quantity": total_quantity,
        "settlement_root": settlement_root,
    }
    memo = f"{config['xrpl_memo_prefix']}{digest_hex_bytes(canonical_json_bytes(build_bbp_fields(bbp)))}"
    foundation = build_system_domain_foundation(sd_pub_b64, sd_p256_pub_b64)
    settlement_ref_str = f"{config['xrpl_chain_id']}:{trx_id}:0:{batch_id}:{window_id}"

    # The artifact set VERIFIES the target member; its evidence/cert/inclusion are
    # the target's, while the shared material carries BOTH bridges.
    tgt = members[target_index]
    commitment_inclusion_proof = primitives.build_commitment_inclusion_proof(commitment_ids, target_index)

    proof = {
        "proof_version": "independence.proof/1", "system_id": config["system_id"],
        "system_root_fingerprint": config["system_root_fingerprint"], "rules_version": "rules/conformance",
        "subtree_root": subtree_root, "settlement_ref": settlement_ref_str,
        "settlement": {"profile_id": config["settlement_profile_id"], "ref": settlement_ref_str,
            "finality_proofs": [{"substrate": config["substrate"], "block_height": str(block_num),
                "timestamp": "2026-04-11T12:00:00Z", "confirmation_level": "irreversible"}]},
        "batch": {"root": settlement_root, "index": str(leaf_index), "size": str(batch_size)},
        "inclusion_proof": sibling_hashes,
        "anti_replay": derive_anti_replay(settlement_ref_str, subtree_root),
        "independence_result": "independent",
        "proof_id": "", "closure_time": "2026-04-11T12:00:00Z",
        "consumed_commitment_ids": commitment_ids, "proof_digest": "",
    }
    seal_proof(proof)

    material = {
        "settlement_profile_id": config["settlement_profile_id"],
        "settlement_action": {"from": config["xrpl_pool_account"],
            "quantity": f"{total_quantity} {config['xrpl_token_symbol']}",
            "memo": memo, "contract": config["xrpl_mpt_issuance_id"],
            "name": config["xrpl_action_name"],
            "chain_id": config["xrpl_chain_id"], "trx_id": trx_id, "action_ordinal": "0"},
        "finality_proof": {"block_num": str(block_num), "block_id": digest_hex_text(f"block:{block_num}"),
            "last_irreversible_block_num": str(lib_num), "last_irreversible_block_id": digest_hex_text(f"block:{lib_num}"),
            "block_timestamp": "2026-04-11T12:00:00Z"},
        "batch_manifest": {"batch_id": batch_id, "window_id": window_id, "leaf_count": str(batch_size),
            "total_quantity": total_quantity, "settlement_root": settlement_root, "system_id": config["system_id"],
            "rules_version": "rules/conformance", "settlement_profile_id": config["settlement_profile_id"]},
        "capacity_consumption_proof": {"total_quantity": total_quantity, "leaf_quantity": consumed_quantity,
            "token_symbol": config["xrpl_token_symbol"], "token_contract": config["xrpl_mpt_issuance_id"]},
        "submission_assignment_proof": {"subtree_root": subtree_root, "leaf_index": str(leaf_index),
            "leaf_preimage": leaf_preimage, "leaf_hash": target_leaf_hash, "sibling_hashes": sibling_hashes},
        # TWO bridges — one per distinct resolved authorization (members a, b).
        "authorization_bridge_proofs": [
            {"resolved_authorization_digest": m["resolved_auth_digest"], "cost_commitment": cost_commitment,
             "consumed_quantity": consumed_quantity, "batch_binding_preimage": bbp}
            for m in members
        ],
        "coherence_material": {"system_id": config["system_id"], "rules_version": "rules/conformance",
            "settlement_profile_id": config["settlement_profile_id"]},
    }

    return {
        "baseCert": tgt["base_cert"], "proof": proof, "material": material,
        "capacityEvidence": tgt["evidence"], "foundation": foundation,
        "commitmentInclusionProof": commitment_inclusion_proof,
    }


# ── CCVP/1 consistency vectors (fixtures/primitives/ccvp-consistency) ───────
# Every target and every context snapshot is a signed CCSP/1 certificate of the
# conformance domain, so an implementation runs CCVP/1 exactly as the
# specification describes it: verify each certificate under the Issued route,
# derive each snapshot issuer from its signature (signer.id + composite key
# fingerprint), and resolve. Keys are fixed by label and both signature
# components are deterministic, so the file is reproduced byte for byte.

CCVP_CONTEXT_SET = "ctx-set"


def _ccvp_key(label: str, signer_id: str) -> dict:
    p256_priv, p256_pub_b64, mldsa_sk, mldsa_pub_b64 = _deterministic_composite_member(
        f"ccvp:{label}"
    )
    fingerprint = digest_hex_bytes(
        base64.b64decode(p256_pub_b64) + base64.b64decode(mldsa_pub_b64)
    )
    return {
        "signer_id": signer_id,
        "pub_p256_b64": p256_pub_b64,
        "pub_mldsa_b64": mldsa_pub_b64,
        "fingerprint": fingerprint,
        "_p256_priv": p256_priv,
        "_mldsa_sk": mldsa_sk,
    }


def _ccvp_certificate(name: str, key: dict, issued_at: str, *, subjects=None,
                      snapshot=None, context=None, kid=None,
                      snapshot_commitment_of=None) -> dict:
    """A signed CCSP/1 certificate. With `snapshot`, it is a context snapshot:
    `payload.snapshot` plus one subject.context-snapshot/1 subject whose
    commitment is the CCCP commitment of the snapshot's canonical bytes (or of
    `snapshot_commitment_of`, to build a commitment that does not match)."""
    nonce_hex = digest_hex_text(f"certcrypt/conformance/nonce/1:ccvp-{name}:anchor.nonce_hex:0")
    if snapshot is not None:
        committed = snapshot if snapshot_commitment_of is None else snapshot_commitment_of
        local = digest_hex_bytes(jcs_canonicalize_bytes(committed))
        subjects = [{
            "profile": "subject.context-snapshot/1",
            "commitment_digest_hex": digest_hex_text(nonce_hex + local),
        }]
    elif subjects is None:
        subjects = ["subject.binary/1"]
    if subjects and isinstance(subjects[0], str):
        subjects = [
            {"profile": p,
             "commitment_digest_hex": digest_hex_text(f"subject:ccvp-{name}:{i}")}
            for i, p in enumerate(subjects)
        ]
    anchor = {"issued_at": issued_at, "nonce_hex": nonce_hex, "subjects": subjects}
    payload = {
        "anchor": anchor,
        "anchor_commitment_digest_hex": digest_hex_text(
            nonce_hex + digest_hex_bytes(jcs_canonicalize_bytes(anchor))),
        "system_id": config["system_id"],
        "rules_version": "rules/conformance",
    }
    if snapshot is not None:
        payload["snapshot"] = snapshot
    if context is not None:
        payload["context"] = context
    digest = digest_hex_bytes(jcs_canonicalize_bytes(payload))
    composite = composite_sign_with(digest, key["_p256_priv"], key["_mldsa_sk"])
    signature = {
        "role": "issuer",
        "sig_target": "payload_canon_digest_hex",
        "alg": composite["alg"],
        "mode": composite["mode"],
        "signatures": composite["signatures"],
        "signer": {
            "id": key["signer_id"],
            "pub_p256_b64": key["pub_p256_b64"],
            "pub_mldsa_b64": key["pub_mldsa_b64"],
        },
    }
    if kid is not None:
        signature["kid"] = kid
    return {
        "schema": "certcrypt-certificate",
        "payload": payload,
        "payload_canon_digest_hex": digest,
        "signatures": [signature],
    }


def build_ccvp_consistency_vectors() -> dict:
    acme = _ccvp_key("issuer-acme", "acme")
    acme_rotated = _ccvp_key("issuer-acme-rotated", "acme")
    ctx = _ccvp_key("context-issuer", "ctx-issuer")
    impostor = _ccvp_key("context-impostor", "ctx-issuer")

    namespace = {
        "snapshot_issuer_id": ctx["signer_id"],
        "snapshot_issuer_fingerprint_digest_hex": ctx["fingerprint"],
        "context_set_id": CCVP_CONTEXT_SET,
    }

    def entry(**over):
        e = {
            "issuer_id": "acme",
            "pub_fingerprint_digest_hex": acme["fingerprint"],
            "status": "active",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": None,
        }
        e.update(over)
        return e

    def snap(snapshot_id, issued_at, entries, context_set_id=CCVP_CONTEXT_SET, **extra):
        s = {
            "context_set_id": context_set_id,
            "snapshot_id": snapshot_id,
            "issued_at": issued_at,
            "entries": entries,
        }
        s.update(extra)
        return s

    jan = snap("01JAN0000000000000000000AA", "2026-01-01T00:00:00Z", [entry()])
    mar_revoked = snap("01MAR0000000000000000000AA", "2026-03-01T00:00:00Z", [entry(
        status="revoked", valid_to="2026-03-01T00:00:00Z",
        revoked_at="2026-03-01T00:00:00Z", revocation_reason="key-rotation")])

    certificates = {}

    def add(name, cert, note, issued_valid=True):
        certificates[name] = {"certificate": cert, "issued_valid": issued_valid, "note": note}

    # ── Targets ──
    add("T_apr", _ccvp_certificate("T_apr", acme, "2026-04-12T10:00:00Z", context=namespace),
        "acme, issued 2026-04-12, one subject.binary/1 subject, declares the ctx namespace")
    add("T_apr_kid", _ccvp_certificate("T_apr_kid", acme, "2026-04-12T10:00:00Z",
                                       context=namespace, kid="acme-key-2026"),
        "as T_apr, and the issuer signature carries kid \"acme-key-2026\"")
    add("T_feb", _ccvp_certificate("T_feb", acme, "2026-02-01T00:00:00Z", context=namespace),
        "acme, issued 2026-02-01")
    add("T_dec2025", _ccvp_certificate("T_dec2025", acme, "2025-12-01T00:00:00Z", context=namespace),
        "acme, issued 2025-12-01, before any snapshot")
    add("T_mar_fraction", _ccvp_certificate("T_mar_fraction", acme, "2026-03-01T00:00:00.000Z",
                                            context=namespace),
        "acme, issued at 2026-03-01T00:00:00.000Z: the same instant as 2026-03-01T00:00:00Z, "
        "which sorts AFTER it as a string")
    add("T_email", _ccvp_certificate("T_email", acme, "2026-04-12T10:00:00Z",
                                     subjects=["subject.email/1"], context=namespace),
        "acme, issued 2026-04-12, one subject.email/1 subject")
    add("T_rotated", _ccvp_certificate("T_rotated", acme_rotated, "2026-04-12T10:00:00Z",
                                       context=namespace),
        "signer.id \"acme\" but signed by another key (acme-rotated)")
    add("T_no_context", _ccvp_certificate("T_no_context", acme, "2026-04-12T10:00:00Z"),
        "acme, no payload.context")
    add("T_no_fingerprint", _ccvp_certificate(
            "T_no_fingerprint", acme, "2026-04-12T10:00:00Z",
            context={"snapshot_issuer_id": ctx["signer_id"], "context_set_id": CCVP_CONTEXT_SET}),
        "payload.context names the snapshot issuer by label only, without its key fingerprint")
    t_tampered = copy.deepcopy(certificates["T_apr"]["certificate"])
    t_tampered["payload"]["anchor"]["issued_at"] = "2026-04-13T10:00:00Z"
    t_tampered["payload"]["anchor_commitment_digest_hex"] = digest_hex_text(
        t_tampered["payload"]["anchor"]["nonce_hex"]
        + digest_hex_bytes(jcs_canonicalize_bytes(t_tampered["payload"]["anchor"])))
    t_tampered["payload_canon_digest_hex"] = digest_hex_bytes(
        jcs_canonicalize_bytes(t_tampered["payload"]))
    add("T_tampered", t_tampered,
        "T_apr with its issuance time changed after signing: the issuer signature fails", False)

    # ── Snapshots in the namespace ──
    def add_snap(name, key, snapshot, note, anchor_at=None, **kw):
        # The certificate's own issuance time is the snapshot's effective time,
        # unless that is deliberately malformed (the anchor must stay valid CCSP/1).
        add(name, _ccvp_certificate(name, key, anchor_at or snapshot["issued_at"],
                                    snapshot=snapshot, **kw), note)

    add_snap("S_jan", ctx, jan, "effective 2026-01-01: acme active from 2026-01-01, open-ended, no kid")
    add_snap("S_mar_revoked", ctx, mar_revoked,
             "effective 2026-03-01: acme revoked, window closed at 2026-03-01")
    add_snap("S_jan_identical", ctx, copy.deepcopy(jan),
             "another certificate carrying a snapshot byte-identical to S_jan")
    add_snap("S_jan_equivocal", ctx, snap("01JAN0000000000000000000BB", "2026-01-01T00:00:00Z", []),
             "same effective time as S_jan, different snapshot (no entries)")
    add_snap("S_jan_respelled", ctx,
             snap("01JAN0000000000000000000AA", "2026-01-01T00:00:00.000Z", [entry()]),
             "S_jan with its effective time spelled 2026-01-01T00:00:00.000Z: same instant, "
             "different canonical bytes")
    add_snap("S_later", ctx, snap("01SEP0000000000000000000AA", "2026-09-01T00:00:00Z", [entry()]),
             "effective 2026-09-01, after every target")
    add_snap("S_window", ctx, snap("01JAN0000000000000000000CC", "2026-01-01T00:00:00Z",
                                   [entry(valid_to="2026-03-01T00:00:00Z")]),
             "effective 2026-01-01: acme active only until 2026-03-01 (exclusive)")
    add_snap("S_kid", ctx, snap("01JAN0000000000000000000DD", "2026-01-01T00:00:00Z",
                                [entry(kid="acme-key-2026")]),
             "effective 2026-01-01: the acme entry names kid \"acme-key-2026\"")
    add_snap("S_scope_email", ctx, snap("01JAN0000000000000000000EE", "2026-01-01T00:00:00Z",
                                        [entry(scope={"subject_profiles": ["subject.email/1"]})]),
             "effective 2026-01-01: the acme entry is restricted to subject.email/1")
    add_snap("S_roles_other", ctx, snap("01JAN0000000000000000000FF", "2026-01-01T00:00:00Z",
                                        [entry(roles=["countersigner"])]),
             "effective 2026-01-01: the acme entry applies only to a role CCSP/1 never signs under")
    add_snap("S_other_set", ctx, snap("01JAN0000000000000000000GG", "2026-01-01T00:00:00Z",
                                      [entry()], context_set_id="other-set"),
             "signed by ctx, covers acme, but for context_set_id \"other-set\"")
    add_snap("S_bad_commitment", ctx,
             snap("01FEB0000000000000000000AA", "2026-02-01T00:00:00Z", []),
             "effective 2026-02-01, validly signed, but its subject.context-snapshot/1 commitment "
             "is over a different snapshot than the one it carries",
             snapshot_commitment_of=snap("01FEB0000000000000000000AA", "2026-02-01T00:00:00Z",
                                         [entry()]))
    add_snap("S_bad_timestamp", ctx,
             snap("01FEB0000000000000000000BB", "2026-02-01T00:00:00+00:00", []),
             "validly signed, commitment correct, but its effective time carries a numeric "
             "offset, outside the CCVP/1 timestamp form",
             anchor_at="2026-02-01T00:00:00Z")

    # ── Snapshots outside the namespace, or not snapshots at all ──
    add_snap("S_impostor_empty", impostor,
             snap("01FEB0000000000000000000CC", "2026-02-15T00:00:00Z", []),
             "signer.id \"ctx-issuer\" but signed by another key; effective 2026-02-15, no entries")
    add_snap("S_impostor_covering", impostor, copy.deepcopy(jan),
             "signer.id \"ctx-issuer\" but signed by another key; carries S_jan's snapshot")
    s_tampered = copy.deepcopy(certificates["S_mar_revoked"]["certificate"])
    s_tampered["payload"]["snapshot"]["entries"][0]["revocation_reason"] = "compromised"
    add("S_tampered", s_tampered,
        "S_mar_revoked altered after signing: its issuer signature fails", False)
    certificates["S_bare_value"] = {
        "certificate": copy.deepcopy(jan), "issued_valid": False,
        "note": "S_jan's snapshot value on its own, not a certificate",
    }

    def case(name, target, snapshots, outcome, why):
        return {"name": name, "target": target, "snapshots": snapshots,
                "expected_outcome": outcome, "why": why}

    M, X, U = "consistency-match", "consistency-mismatch", "consistency-unknown"
    cases = [
        case("eligible_at_issuance", "T_apr", ["S_jan"], M,
             "S_jan governs and its entry binds acme's label and composite key fingerprint"),
        case("no_snapshot_at_all", "T_apr", [], U,
             "no snapshot governs; absence invalidates nothing"),
        case("before_any_snapshot", "T_dec2025", ["S_jan"], U,
             "the only snapshot takes effect after issuance"),
        case("published_after_issuance", "T_apr", ["S_later"], U,
             "a snapshot cannot reach back before its effective time"),
        case("retired_later_still_covered", "T_feb", ["S_jan", "S_mar_revoked"], M,
             "selection is by issuance time: the March revocation is not effective in February"),
        case("revoked_before_issuance", "T_apr", ["S_jan", "S_mar_revoked"], X,
             "S_mar_revoked governs April and its entry is not active"),
        case("instant_not_string", "T_mar_fraction", ["S_jan", "S_mar_revoked"], X,
             "2026-03-01T00:00:00.000Z is the instant 2026-03-01T00:00:00Z, so S_mar_revoked "
             "governs; a string comparison would select S_jan and answer match"),
        case("window_open", "T_feb", ["S_window"], M, "valid_from <= issued_at < valid_to"),
        case("window_closed", "T_apr", ["S_window"], X,
             "issued after valid_to: the window is half-open at the top"),
        case("context_equivocation", "T_apr", ["S_jan", "S_jan_equivocal"], U,
             "two different snapshots share the maximal effective time"),
        case("identical_tie_is_one_snapshot", "T_apr", ["S_jan", "S_jan_identical"], M,
             "the tied snapshots have identical canonical bytes"),
        case("respelled_tie_is_equivocation", "T_apr", ["S_jan", "S_jan_respelled"], U,
             "same instant, different canonical bytes: equivocation"),
        case("substituted_key_does_not_inherit", "T_rotated", ["S_jan"], X,
             "the label matches but the key fingerprint does not"),
        case("kid_in_entry_and_signature", "T_apr_kid", ["S_kid"], M,
             "the entry's kid equals the signature's"),
        case("kid_in_entry_only", "T_apr", ["S_kid"], X,
             "the entry names a kid the signature does not carry"),
        case("kid_in_signature_only", "T_apr_kid", ["S_jan"], M,
             "an entry without kid ignores the signature's kid"),
        case("scope_excludes_profile", "T_apr", ["S_scope_email"], X,
             "the only matching entry is scoped to subject.email/1 and T_apr has none"),
        case("scope_includes_profile", "T_email", ["S_scope_email"], M,
             "T_email has a subject.email/1 subject"),
        case("role_excludes", "T_apr", ["S_roles_other"], X,
             "the entry's roles do not contain \"issuer\""),
        case("foreign_context_set_does_not_govern", "T_apr", ["S_other_set"], U,
             "same snapshot issuer, other context_set_id"),
        case("namespace_impersonation_is_ignored", "T_apr", ["S_jan", "S_impostor_empty"], M,
             "S_impostor_empty borrows the label ctx-issuer but not its key; were it admitted "
             "it would govern April and answer mismatch"),
        case("namespace_impersonation_alone", "T_apr", ["S_impostor_covering"], U,
             "a snapshot signed by another key under the same label is outside the namespace"),
        case("tampered_snapshot_discarded", "T_apr", ["S_tampered"], U,
             "a snapshot that is not Issued-valid takes no part"),
        case("tampered_snapshot_beside_valid", "T_apr", ["S_jan", "S_tampered"], M,
             "the altered revocation is discarded, S_jan governs"),
        case("bare_snapshot_value_ignored", "T_apr", ["S_bare_value"], U,
             "snapshots are certificates; a bare value has no signature and no issuer"),
        case("non_conformant_snapshot_blocks", "T_apr", ["S_jan", "S_bad_commitment"], U,
             "a non-conformant snapshot from the namespace key, effective between the selected "
             "snapshot and issuance, cannot be skipped"),
        case("bad_timestamp_blocks", "T_apr", ["S_jan", "S_bad_timestamp"], U,
             "an unreadable effective time from the namespace key cannot be skipped"),
        case("superseded_non_conformant_ignored", "T_apr",
             ["S_jan", "S_bad_commitment", "S_mar_revoked"], X,
             "the non-conformant snapshot is older than the selected S_mar_revoked"),
        case("target_not_issued_valid", "T_tampered", ["S_jan"], U,
             "a target that is not Issued-valid has no issuer signature to bind"),
        case("target_without_context", "T_no_context", ["S_jan"], U,
             "no declared context namespace"),
        case("namespace_without_fingerprint", "T_no_fingerprint", ["S_jan"], U,
             "a namespace named by label alone is incomplete"),
    ]

    keys = {
        name: {"signer_id": k["signer_id"], "pub_p256_b64": k["pub_p256_b64"],
               "pub_mldsa_b64": k["pub_mldsa_b64"],
               "composite_key_fingerprint_digest_hex": k["fingerprint"]}
        for name, k in (("acme", acme), ("acme-rotated", acme_rotated),
                        ("ctx-issuer", ctx), ("ctx-impostor", impostor))
    }

    return {
        "primitive": "ccvp_consistency_resolution",
        "description": (
            "CCVP/1 consistency resolution over signed certificates. Every target and every "
            "snapshot is a CCSP/1 certificate of the conformance domain (system_id \"certcrypt\", "
            "rules_version \"rules/conformance\"). A conforming implementation verifies each "
            "certificate under the Issued route, derives each snapshot issuer from its issuer "
            "signature (signer.id + composite key fingerprint, CCVP/1 Section 8.1), checks each "
            "snapshot's object, timestamps and subject.context-snapshot/1 commitment, and "
            "reproduces every expected outcome from the public rules alone."
        ),
        "outcome_semantics": {
            M: "an applicable entry in the governing snapshot covers this issuance",
            X: "a snapshot governs and no entry covers the key that signed",
            U: "no snapshot governs, the context is equivocal or unreadable, or there is no "
               "verification unit",
        },
        "non_claims": (
            "A consistency outcome is NOT a trust class and NOT a partial form of Independent "
            "(CCVP/1 Section 10). consistency-unknown invalidates nothing. An implementation "
            "that feeds any of these outcomes into an Issued or Independent verdict is "
            "non-conformant."
        ),
        "namespace_note": (
            "The target names its snapshot issuer by label AND composite key fingerprint "
            "(payload.context). A snapshot signed by another key is outside the namespace "
            "whatever its signer.id: the namespace_impersonation cases pin that."
        ),
        "timestamp_note": (
            "C.payload.anchor.issued_at is the target's issuance time; "
            "S.payload.snapshot.issued_at is the snapshot's effective time. All CCVP/1 "
            "timestamps use the UTC form of CCSP/1 anchor.issued_at and are compared as "
            "instants, never as strings."
        ),
        "namespace": namespace,
        "keys": keys,
        "certificates": certificates,
        "cases": cases,
    }


def write_ccvp_consistency_vectors(fixtures_root: str) -> None:
    out = os.path.join(fixtures_root, "primitives", "ccvp-consistency")
    ensure_dir(out)
    write_json(os.path.join(out, "vectors.json"), build_ccvp_consistency_vectors())


def build_collection_element_vectors() -> dict:
    """verifier-toolkit/1 §8.4.2: element inclusion from the certificate alone.

    Three certificates of the conformance domain. `A` declares a heterogeneous
    collection whose leaves are signed inside it — binary "alpha", text "beta",
    binary "alpha" again, binary "gamma". `B` declares the same leaves under a root
    they do not fold to, correctly signed. `A_altered` is `A` with its issued_at
    changed after signing. Each case names one leaf VALUE and the outcome a
    toolkit must reach from the certificate and that value alone.
    """
    leaves = [("subject.binary/1", "alpha"), ("subject.text/1", "beta"),
              ("subject.binary/1", "alpha"), ("subject.binary/1", "gamma")]

    def canonical(profile: str, value: str) -> bytes:
        b = value.encode("utf-8")
        return primitives.canonical_subject_text(b) if profile == "subject.text/1" else b

    def collection_cert(label: str, root_override: Optional[str]) -> dict:
        def mut(cert):
            nonce = cert["payload"]["anchor"]["nonce_hex"]
            salt = nonce.encode("ascii")
            hashes = [primitives.collection_leaf_hash(salt, prof, canonical(prof, val))
                      for prof, val in leaves]
            obj = {
                "commitment_scheme": "collection.merkle-sha3-256/1",
                "root": root_override or primitives.collection_merkle_root(hashes),
                "declared_cardinality": str(len(leaves)),
                "leaves": [{"profile": prof, "commitment_digest_hex": h}
                           for (prof, _), h in zip(leaves, hashes)],
            }
            sld = digest_hex_bytes(jcs_canonicalize_bytes(obj))
            cert["payload"]["anchor"]["subjects"] = [{
                "profile": "subject.collection/1",
                "commitment_digest_hex": digest_hex_text(nonce + sld),
                "collection": obj,
            }]
            refresh_certificate_payload(cert)
            recompose_cert_signature(cert)
        f = build_zero_data_fixture({
            "fixtureId": label, "batchId": f"batch-{label}", "windowId": f"window-{label}",
            "trxId": f"trx-{label}", "leafIndex": 0, "batchSize": 1,
            "consumedQuantity": "1.00", "totalQuantity": "1.00",
            "blockNum": 9000, "libNum": 9010,
            "issuerScope": "issuer:collection-element", "capacityAuthRef": f"cap-auth-{label}",
        }, cert_mutator=mut, declared_effective_units=str(len(leaves)))
        return f["baseCert"]

    cert_a = collection_cert("collection-element-A", None)
    cert_b = collection_cert("collection-element-B", digest_hex_text("not the fold of these leaves"))
    cert_altered = copy.deepcopy(cert_a)
    cert_altered["payload"]["anchor"]["issued_at"] = "2026-04-11T12:00:01Z"

    def member(*matches):
        return {"outcome": "member", "matches": [
            {"subject_index": 0, "profile": prof, "leaf_indices": idx} for prof, idx in matches]}

    cases = [
        {"name": "repeated_value_every_position", "certificate": "A", "value_utf8": "alpha",
         "expected": member(("subject.binary/1", [0, 2]))},
        {"name": "text_leaf_found_under_its_own_profile", "certificate": "A", "value_utf8": "beta",
         "expected": member(("subject.text/1", [1]))},
        {"name": "text_leaf_matches_after_canonicalization", "certificate": "A", "value_utf8": "beta\n",
         "expected": member(("subject.text/1", [1]))},
        {"name": "last_leaf_lone_right_edge", "certificate": "A", "value_utf8": "gamma",
         "expected": member(("subject.binary/1", [3]))},
        {"name": "absent_value_is_a_negative_outcome", "certificate": "A", "value_utf8": "delta",
         "expected": {"outcome": "not_member", "matches": []}},
        {"name": "leaves_do_not_fold_to_root", "certificate": "B", "value_utf8": "alpha",
         "expected": {"outcome": "rejected", "matches": []}},
        {"name": "certificate_not_issued_valid", "certificate": "A_altered", "value_utf8": "alpha",
         "expected": {"outcome": "certificate_not_issued_valid", "matches": []}},
    ]
    return {
        "family": "collection-merkle",
        "operation": "element inclusion from the certificate alone (verifier-toolkit/1 §8.4.2)",
        "certificates": {"A": cert_a, "B": cert_b, "A_altered": cert_altered},
        "cases": cases,
    }


def write_collection_element_vectors(fixtures_root: str) -> None:
    out = os.path.join(fixtures_root, "primitives", "collection-merkle")
    ensure_dir(out)
    write_json(os.path.join(out, "certificate-element.json"), build_collection_element_vectors())


def pin_verification_targets(*dirs: str) -> None:
    """Every expected result pins the target the verifier resolves.

    A fixture that does not state it explicitly resolves to the target its request
    names (`issued` → Issued, `independent` → Independent); an `auto` request must
    state it. The member is written right after `result_code`.
    """
    for d in dirs:
        for fid in sorted(os.listdir(d)):
            fixture_dir = os.path.join(d, fid)
            exp_path = os.path.join(fixture_dir, "expected-result.json")
            if not os.path.isfile(exp_path):
                continue
            with open(os.path.join(fixture_dir, "input.json"), encoding="utf-8") as fh:
                requested = json.load(fh)["verification_target_requested"]
            with open(exp_path, encoding="utf-8") as fh:
                expected = json.load(fh)
            target = expected.get("verification_target")
            if target is None:
                if requested == "auto":
                    raise SystemExit(f"{fid}: an auto request must pin verification_target")
                target = "Issued" if requested == "issued" else "Independent"
            ordered = {"result_code": expected["result_code"], "verification_target": target}
            ordered.update({k: v for k, v in expected.items() if k not in ordered})
            write_json(exp_path, ordered)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate CERTCRYPT conformance fixtures.")
    parser.add_argument("--out", default=None, help="Output base dir (contains fixtures/).")
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    if args.out:
        fixtures_root = args.out
    else:
        fixtures_root = os.path.join(script_dir, "..", "fixtures")
    conformance_dir = os.path.join(fixtures_root, "conformance")
    adversarial_dir = os.path.join(fixtures_root, "adversarial")

    print("Generating CERTCRYPT conformance fixtures...\n")

    # === POSITIVE FIXTURES ===

    # Positives on the commitment sub-tree + zero-data model. The negatives
    # clone the P001 fixture below (`p001`), so the whole suite is on one model.
    p001 = build_zero_data_fixture({
        "fixtureId": "P001", "batchId": "batch-P001", "windowId": "window-P001",
        "trxId": "trx-P001", "leafIndex": 0, "batchSize": 2,
        "consumedQuantity": "5.00", "totalQuantity": "10.00",
        "blockNum": 1000, "libNum": 1005,
        "issuerScope": "issuer:acme-corp", "capacityAuthRef": "cap-auth-P001",
    })
    write_zero_data_fixture(
        conformance_dir, "P001", p001,
        "# P001 — Canonical Valid Aggregated Independence\n\n"
        "2-leaf batch, leaf index 0. The target leaf is a sub-tree of 2 accepted\n"
        "commitments (same issuer_scope + capacity_authorization_ref); the verified\n"
        "certificate corresponds to commitment index 0. Zero-data capacity evidence\n"
        "is bound into the proof; the emission binding is hybrid\n"
        "(SHA3(cert) == certificate_commitment_digest + commitment_id ∈ subtree_root).\n"
        "Pins subject_scope: the one subject.binary/1 subject is opaque, so the verdict\n"
        "covers that input as one input and asserts nothing about anything inside it.\n"
        "All checks pass.",
        expected_extra={"subject_scope": [{"profile": "subject.binary/1", "opaque": True}]},
    )
    print("  P001 generated")

    p002 = build_zero_data_fixture({
        "fixtureId": "P002", "batchId": "batch-P002", "windowId": "window-P002",
        "trxId": "trx-P002", "leafIndex": 1, "batchSize": 2,
        "consumedQuantity": "3.00", "totalQuantity": "6.00",
        "blockNum": 1001, "libNum": 1001,
        "issuerScope": "issuer:beta-inc", "capacityAuthRef": "cap-auth-P002",
    })
    write_zero_data_fixture(
        conformance_dir, "P002", p002,
        "# P002 — Valid at Exact Finality Threshold\n\n"
        "2-leaf batch, leaf index 1. last_irreversible_block_num === block_num.",
    )
    print("  P002 generated")

    p003 = build_zero_data_fixture({
        "fixtureId": "P003", "batchId": "batch-P003", "windowId": "window-P003",
        "trxId": "trx-P003", "leafIndex": 0, "batchSize": 1,
        "consumedQuantity": "2.00", "totalQuantity": "2.00",
        "blockNum": 1002, "libNum": 1010,
        "issuerScope": "issuer:gamma-llc", "capacityAuthRef": "cap-auth-P003",
    })
    write_zero_data_fixture(
        conformance_dir, "P003", p003,
        "# P003 — Valid Single-Leaf Batch\n\n"
        "Single leaf in batch (its hash is the settlement root).",
    )
    print("  P003 generated")

    # P004 / P005 — multi-authorization leaf (settlement-material/1 §9). ONE leaf groups TWO
    # commitments under TWO DISTINCT Level-1 authorizations; the material carries
    # TWO authorization bridges. P004 verifies member A, P005 verifies member B —
    # both must reach INDEPENDENT_VALID, proving the verifier selects the bridge
    # matching the evidence under verification.
    p004 = build_multi_auth_fixture(fixture_id="P004", target_index=0)
    write_zero_data_fixture(
        conformance_dir, "P004", p004,
        "# P004 — Multi-Authorization Leaf, Member A\n\n"
        "A leaf groups two commitments under two distinct Level-1 authorizations.\n"
        "This set verifies member A; the material carries both bridges and the\n"
        "verifier selects A's. Expected: INDEPENDENT_VALID.",
    )
    print("  P004 generated")

    p005 = build_multi_auth_fixture(fixture_id="P004", target_index=1)
    write_zero_data_fixture(
        conformance_dir, "P005", p005,
        "# P005 — Multi-Authorization Leaf, Member B\n\n"
        "Same multi-authorization leaf as P004, but verifies member B. Proves the\n"
        "second authorization's commitment also reconstructs its bridge.\n"
        "Expected: INDEPENDENT_VALID.",
    )
    print("  P005 generated")

    # === NEGATIVE FIXTURES ===

    # V001 — hybrid binding STEP 1 broken (cert digest != certificate_commitment_digest).
    # Mutate a payload field that ONLY affects SHA3(JCS(cert)) — issued_at — so the
    # recomputed cert digest no longer matches the certificate_commitment_digest
    # baked into the (unchanged) capacity evidence. We re-sign the cert (refresh
    # anchor_commitment + payload digest) so the only break is the binding, not the
    # base-cert structure/authenticity.
    v = clone_fixture(p001)
    v["baseCert"]["payload"]["anchor"]["issued_at"] = "2026-04-11T13:30:00Z"
    refresh_certificate_payload(v["baseCert"])
    recompose_cert_signature(v["baseCert"])
    write_negative_zero_data(
        adversarial_dir, "V001", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["LEAF_BINDING_VALID"]},
        "# V001 — Cross-Leaf Proof Splice (hybrid binding STEP 1)\n\n"
        "The certificate's anchor.issued_at was altered (and the cert re-signed), so\n"
        "SHA3(JCS(base_certificate)) no longer equals the\n"
        "capacity_evidence.projected_commitment.certificate_commitment_digest the\n"
        "commitment was bound to. The emission binding fails its first leg.\n"
        "Expected: INDEPENDENT_INVALID (LEAF_BINDING_VALID)",
    )
    print("  V001 generated")

    # V002
    v = clone_fixture(p001)
    v["proof"]["system_id"] = "certcrypt-clone"
    v["proof"]["system_root_fingerprint"] = digest_hex_text("fake-root")
    seal_proof(v["proof"])
    write_negative_zero_data(
        adversarial_dir, "V002", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["SYSTEM_DOMAIN_EXACT", "CLONE_OR_FORK_REJECTED"], "certcrypt_lineage": {"certcrypt_domain_bound": False, "history_bound_under_certcrypt": False}},
        "# V002 — Cross-System Proof Splice\n\nproof.system_id is 'certcrypt-clone'.\nExpected: INDEPENDENT_INVALID (SYSTEM_DOMAIN_EXACT, CLONE_OR_FORK_REJECTED)",
    )
    print("  V002 generated")

    # V003 — rules-domain mismatch between proof and base certificate. The proof
    # keeps rules/conformance; the base certificate names rules/conformance-uncommitted, another
    # version the conformance verifier supports, so the certificate is valid on its
    # own and RULES_DOMAIN_EXACT (proof vs cert) is the only break. The cert is
    # re-signed so base-certificate authenticity is not the break either.
    v = clone_fixture(p001)
    v["baseCert"]["payload"]["rules_version"] = "rules/conformance-uncommitted"
    refresh_certificate_payload(v["baseCert"])
    recompose_cert_signature(v["baseCert"])
    write_negative_zero_data(
        adversarial_dir, "V003", v,
        {"result_code": "REJECTED", "failed_check_ids": ["RULES_DOMAIN_EXACT"]},
        "# V003 — Rules-Domain Mismatch\n\nbase_certificate.payload.rules_version differs from proof.rules_version.\nExpected: REJECTED (RULES_DOMAIN_EXACT)",
    )
    print("  V003 generated")

    # V004
    v = clone_fixture(p001)
    v["material"]["coherence_material"]["settlement_profile_id"] = "unsupported.profile/1"
    write_negative_zero_data(
        adversarial_dir, "V004", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["AGGREGATED_INTERPRETATION_UNIQUE"]},
        "# V004 — Settlement-Profile Mismatch\n\ncoherence_material.settlement_profile_id differs from proof.\nExpected: INDEPENDENT_INVALID (AGGREGATED_INTERPRETATION_UNIQUE)",
    )
    print("  V004 generated")

    # V005
    v = clone_fixture(p001)
    del v["material"]["authorization_bridge_proofs"]
    write_negative_zero_data(
        adversarial_dir, "V005", v,
        {"result_code": "INCOMPLETE", "failed_check_ids": ["CAPACITY_NOT_RECONSTRUCTED"]},
        "# V005 — Missing Authorization Bridge\n\nauthorization_bridge_proofs is absent.\nExpected: INCOMPLETE (CAPACITY_NOT_RECONSTRUCTED)",
    )
    print("  V005 generated")

    # V006
    v = clone_fixture(p001)
    v["material"]["capacity_consumption_proof"]["leaf_quantity"] = "0.00"
    write_negative_zero_data(
        adversarial_dir, "V006", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["CAPACITY_BINDING_VALID"]},
        "# V006 — Detached Authorization as Consumption\n\nleaf_quantity in capacity_consumption_proof does not match leaf consumed_quantity.\nExpected: INDEPENDENT_INVALID (CAPACITY_BINDING_VALID)",
    )
    print("  V006 generated")

    # V007
    v = clone_fixture(p001)
    v["proof"]["anti_replay"]["nonce"] = ""
    v["proof"]["anti_replay"]["derivation"] = ""
    seal_proof(v["proof"])
    write_negative_zero_data(
        adversarial_dir, "V007", v,
        {"result_code": "REJECTED", "failed_check_ids": ["PROOF_STRUCTURE_VALID"]},
        "# V007 — Reusable Binding Digest\n\nanti_replay nonce and derivation are empty.\nExpected: REJECTED (PROOF_STRUCTURE_VALID)",
    )
    print("  V007 generated")

    # V008 — a settlement profile the rules domain does not select. Uses a DIRECT
    # (non-aggregated) profile name: plausible enough that a lax verifier might
    # accept it as "close enough", which is the point — the identifier is exact or
    # it is nothing.
    v = clone_fixture(p001)
    v["proof"]["settlement"]["profile_id"] = "settlement.direct.xrpl/1"
    seal_proof(v["proof"])
    write_negative_zero_data(
        adversarial_dir, "V008", v,
        {"result_code": "REJECTED", "failed_check_ids": ["SETTLEMENT_REF_VALID"]},
        "# V008 — Unsupported Settlement Profile\n\nsettlement.profile_id is 'settlement.direct.xrpl/1' — a profile this rules domain does not select.\nExpected: REJECTED (SETTLEMENT_REF_VALID)",
    )
    print("  V008 generated")

    # V009
    v = clone_fixture(p001)
    v["material"]["finality_proof"]["last_irreversible_block_num"] = "999"
    v["proof"]["settlement"]["finality_proofs"][0]["confirmation_level"] = "pending"
    seal_proof(v["proof"])
    write_negative_zero_data(
        adversarial_dir, "V009", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["FINALITY_SUFFICIENT"], "certcrypt_lineage": {"certcrypt_domain_bound": True, "settlement_bound": False, "history_bound_under_certcrypt": False}},
        "# V009 — Insufficient Finality\n\nlast_irreversible_block_num < block_num and confirmation_level is 'pending'.\nExpected: INDEPENDENT_INVALID (FINALITY_SUFFICIENT)",
    )
    print("  V009 generated")

    # V010 — Wrong MPT issuance. The settlement must destroy supply of the EXACT
    # issuance the rules domain names; a payment of some other token proves
    # nothing about this one's capacity. On XRPL the `contract` field carries the
    # issuance id, so the wrong-target case is a wrong issuance.
    v = clone_fixture(p001)
    v["material"]["settlement_action"]["contract"] = (
        "00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    )
    write_negative_zero_data(
        adversarial_dir, "V010", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["CAPACITY_BINDING_VALID"], "certcrypt_lineage": {"capacity_consumption_bound": False, "history_bound_under_certcrypt": False}},
        "# V010 — Wrong MPT Issuance\n\nsettlement_action.contract names an MPT issuance other than the one the rules domain selects.\nExpected: INDEPENDENT_INVALID (CAPACITY_BINDING_VALID)",
    )
    print("  V010 generated")

    # V011
    v = clone_fixture(p001)
    v["material"]["capacity_consumption_proof"]["leaf_quantity"] = "99.00"
    write_negative_zero_data(
        adversarial_dir, "V011", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["CAPACITY_BINDING_VALID"]},
        "# V011 — Quantity Mismatch\n\ncapacity_consumption_proof.leaf_quantity differs from leaf consumed_quantity.\nExpected: INDEPENDENT_INVALID (CAPACITY_BINDING_VALID)",
    )
    print("  V011 generated")

    # V012
    v = clone_fixture(p001)
    v["baseCert"]["payload"]["anchor"]["root_id"] = ""
    write_negative_zero_data(
        adversarial_dir, "V012", v,
        {"result_code": "REJECTED", "failed_check_ids": ["BASE_CERTIFICATE_STRUCTURE_VALID"]},
        "# V012 — Issuance-Time Participation Repaired Post Hoc\n\npayload.anchor.root_id cleared — anchor commitment recomputation fails.\nExpected: REJECTED (BASE_CERTIFICATE_STRUCTURE_VALID)",
    )
    print("  V012 generated")

    # V013 — hybrid binding STEP 2 broken (commitment_id NOT in subtree_root).
    # The cert still matches certificate_commitment_digest, but the commitment
    # inclusion proof's sibling is wrong, so commitment_id does not recompute to
    # subtree_root: the second leg of the emission binding fails.
    v = clone_fixture(p001)
    v["commitmentInclusionProof"]["commitment_siblings"] = [
        digest_hex_text("V013-wrong-sibling")
    ]
    write_negative_zero_data(
        adversarial_dir, "V013", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["LEAF_BINDING_VALID"]},
        "# V013 — Package-Level Coexistence Without Coherence (hybrid binding STEP 2)\n\n"
        "Each artifact is individually well-formed, but the commitment inclusion\n"
        "proof carries a wrong sibling, so the target commitment_id no longer\n"
        "recomputes to the proof's subtree_root. The emission binding fails its\n"
        "second leg (commitment_id ∉ subtree_root).\n"
        "Expected: INDEPENDENT_INVALID (LEAF_BINDING_VALID)",
    )
    print("  V013 generated")

    # V014 — missing settlement material. Writes the artifact set
    # (cert, proof, capacity evidence, commitment inclusion proof, foundation) but
    # OMITS settlement-material.json and its input path, so the settlement leg of
    # the path cannot complete. Written inline because write_negative_zero_data
    # always includes settlement_material_path.
    v = clone_fixture(p001)
    v014_dir = os.path.join(adversarial_dir, "V014")
    v014_art = os.path.join(v014_dir, "artifacts")
    ensure_dir(v014_art)
    write_json(os.path.join(v014_art, "base-certificate.json"), v["baseCert"])
    write_json(os.path.join(v014_art, "independence-proof.json"), v["proof"])
    write_json(os.path.join(v014_art, "capacity-evidence.json"), v["capacityEvidence"])
    write_json(os.path.join(v014_art, "system-foundation.json"), v["foundation"])
    write_json(os.path.join(v014_art, "commitment-inclusion-proof.json"), v["commitmentInclusionProof"])
    write_json(os.path.join(v014_dir, "input.json"), {
        "verification_target_requested": "independent",
        "input_mode": "artifact_set",
        "base_certificate_path": "artifacts/base-certificate.json",
        "independence_proof_path": "artifacts/independence-proof.json",
        "capacity_evidence_path": "artifacts/capacity-evidence.json",
        "commitment_inclusion_proof_path": "artifacts/commitment-inclusion-proof.json",
        "system_foundation_path": "artifacts/system-foundation.json",
    })
    write_json(os.path.join(v014_dir, "expected-result.json"),
               {"result_code": "INCOMPLETE", "failed_check_ids": ["SETTLEMENT_REF_VALID"]})
    write_text(os.path.join(v014_dir, "README.md"),
               "# V014 — Missing Settlement Material\n\nindependence_proof present but settlement_material absent.\nExpected: INCOMPLETE (SETTLEMENT_REF_VALID)")
    print("  V014 generated")

    # V015 — a well-formed certificate whose text repeats a top-level member.
    # The duplicate is caught by the parser, before any structure check: no
    # last-wins or first-wins reading of it is ever evaluated.
    v = clone_fixture(p001)
    write_negative_zero_data(
        adversarial_dir, "V015", v,
        {"result_code": "REJECTED", "failed_check_ids": ["INPUT_COMBINATION_VALID"]},
        "# V015 — Parser Tolerance Rescue\n\n"
        "The base certificate repeats its top-level `schema` member. A parser that\n"
        "keeps the last (or the first) value would read a valid certificate; CCSP/1\n"
        "§8.1 makes any duplicate member non-conformant.\n"
        "Expected: REJECTED (INPUT_COMBINATION_VALID)",
    )
    write_text(
        os.path.join(adversarial_dir, "V015", "artifacts", "base-certificate.json"),
        inject_after_first(stringify_pretty(v["baseCert"]),
                           '"schema": "certcrypt-certificate",',
                           '\n  "schema": "certcrypt-certificate",'),
    )
    print("  V015 generated")

    # V016
    v = clone_fixture(p001)
    v["proof"]["settlement"]["profile_id"] = config["settlement_profile_id"] + ".1"
    seal_proof(v["proof"])
    write_negative_zero_data(
        adversarial_dir, "V016", v,
        {"result_code": "REJECTED", "failed_check_ids": ["SETTLEMENT_REF_VALID"]},
        "# V016 — Near-Match Profile Identifier\n\nsettlement.profile_id is the selected profile with a version suffix appended (near-match).\nExpected: REJECTED (SETTLEMENT_REF_VALID)",
    )
    print("  V016 generated")

    # V017
    v = clone_fixture(p001)
    v["proof"]["settlement"]["profile_id"] = config["settlement_profile_id"].replace("/1", "-v2/1")
    seal_proof(v["proof"])
    write_negative_zero_data(
        adversarial_dir, "V017", v,
        {"result_code": "REJECTED", "failed_check_ids": ["SETTLEMENT_REF_VALID"]},
        "# V017 — Profile Variant Suffix Match\n\nsettlement.profile_id is the selected profile with a `-v2` variant suffix.\nExpected: REJECTED (SETTLEMENT_REF_VALID)",
    )
    print("  V017 generated")

    # V018
    v = clone_fixture(p001)
    v["proof"]["settlement"]["finality_proofs"][0]["confirmation_level"] = "nearly-irreversible"
    seal_proof(v["proof"])
    write_negative_zero_data(
        adversarial_dir, "V018", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["FINALITY_SUFFICIENT"]},
        "# V018 — Near-Match Finality Label\n\nconfirmation_level is 'nearly-irreversible' (not exactly 'irreversible').\nExpected: INDEPENDENT_INVALID (FINALITY_SUFFICIENT)",
    )
    print("  V018 generated")

    # V019
    v = clone_fixture(p001)
    v["proof"]["system_root_fingerprint"] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    seal_proof(v["proof"])
    write_negative_zero_data(
        adversarial_dir, "V019", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["SYSTEM_ROOT_BINDING_VALID", "CLONE_OR_FORK_REJECTED"]},
        "# V019 — System Root Spoof\n\nsystem_id is 'certcrypt' but system_root_fingerprint is wrong.\nExpected: INDEPENDENT_INVALID (SYSTEM_ROOT_BINDING_VALID, CLONE_OR_FORK_REJECTED)",
    )
    print("  V019 generated")

    # V020 — retroactive proof fabrication. anchor.root_id is set to a fabricated
    # root so it no longer equals proof.system_root_fingerprint. The mutation is
    # applied via the cert_mutator hook, BEFORE the ccd and the capacity evidence
    # are computed, so the hybrid binding stays coherent end-to-end (SHA3(cert) ==
    # certificate_commitment_digest AND commitment_id == evidence digest, §7.10)
    # and the break lands exactly at ISSUANCE_PARTICIPATION_VALID — not earlier at
    # LEAF_BINDING. Re-pointing the digest after the fact would instead break the
    # §7.10 binding.
    def fabricate_root_v020(cert: dict) -> None:
        cert["payload"]["anchor"]["root_id"] = digest_hex_text("retroactive-root-V020")
        refresh_certificate_payload(cert)
        recompose_cert_signature(cert)

    v = build_zero_data_fixture(
        {
            "fixtureId": "V020", "batchId": "batch-V020", "windowId": "window-V020",
            "trxId": "trx-V020", "leafIndex": 0, "batchSize": 2,
            "blockNum": 1000, "libNum": 1005,
            "consumedQuantity": "5.00", "totalQuantity": "10.00",
            "issuerScope": "issuer:acme-corp", "capacityAuthRef": "cap-auth-V020",
        },
        cert_mutator=fabricate_root_v020,
    )
    write_negative_zero_data(
        adversarial_dir, "V020", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["ISSUANCE_PARTICIPATION_VALID"]},
        "# V020 — Retroactive Proof Fabrication\n\n"
        "Later proof and settlement material are present, but the issuance-time root binding does not match the claimed proof context.\n"
        "Expected: INDEPENDENT_INVALID (ISSUANCE_PARTICIPATION_VALID)",
    )
    print("  V020 generated")

    # V021 — certificate + settlement material present, but no independence_proof.
    # Written inline (write_negative_zero_data always includes the proof).
    v = clone_fixture(p001)
    v021_dir = os.path.join(adversarial_dir, "V021")
    v021_art = os.path.join(v021_dir, "artifacts")
    ensure_dir(v021_art)
    write_json(os.path.join(v021_art, "base-certificate.json"), v["baseCert"])
    write_json(os.path.join(v021_art, "settlement-material.json"), v["material"])
    write_json(os.path.join(v021_art, "capacity-evidence.json"), v["capacityEvidence"])
    write_json(os.path.join(v021_art, "system-foundation.json"), v["foundation"])
    write_json(os.path.join(v021_art, "commitment-inclusion-proof.json"), v["commitmentInclusionProof"])
    write_json(os.path.join(v021_dir, "input.json"), {
        "verification_target_requested": "independent",
        "input_mode": "artifact_set",
        "base_certificate_path": "artifacts/base-certificate.json",
        "settlement_material_path": "artifacts/settlement-material.json",
        "capacity_evidence_path": "artifacts/capacity-evidence.json",
        "commitment_inclusion_proof_path": "artifacts/commitment-inclusion-proof.json",
        "system_foundation_path": "artifacts/system-foundation.json",
    })
    write_json(os.path.join(v021_dir, "expected-result.json"),
               {"result_code": "INCOMPLETE", "failed_check_ids": ["TARGET_AUTO_RESOLUTION_VALID"]})
    write_text(os.path.join(v021_dir, "README.md"),
               "# V021 — Hash-Plus-Anchor Reduction\n\n"
               "A certificate and settlement-like material are present, but no canonical independence_proof exists.\n"
               "Expected: INCOMPLETE (TARGET_AUTO_RESOLUTION_VALID)")
    print("  V021 generated")

    # V022 — proof present, no settlement material. Written inline.
    v = clone_fixture(p001)
    v022_dir = os.path.join(adversarial_dir, "V022")
    v022_art = os.path.join(v022_dir, "artifacts")
    ensure_dir(v022_art)
    write_json(os.path.join(v022_art, "base-certificate.json"), v["baseCert"])
    write_json(os.path.join(v022_art, "independence-proof.json"), v["proof"])
    write_json(os.path.join(v022_art, "capacity-evidence.json"), v["capacityEvidence"])
    write_json(os.path.join(v022_art, "system-foundation.json"), v["foundation"])
    write_json(os.path.join(v022_art, "commitment-inclusion-proof.json"), v["commitmentInclusionProof"])
    write_json(os.path.join(v022_dir, "input.json"), {
        "verification_target_requested": "independent",
        "input_mode": "artifact_set",
        "base_certificate_path": "artifacts/base-certificate.json",
        "independence_proof_path": "artifacts/independence-proof.json",
        "capacity_evidence_path": "artifacts/capacity-evidence.json",
        "commitment_inclusion_proof_path": "artifacts/commitment-inclusion-proof.json",
        "system_foundation_path": "artifacts/system-foundation.json",
    })
    write_json(os.path.join(v022_dir, "expected-result.json"),
               {"result_code": "INCOMPLETE", "failed_check_ids": ["SETTLEMENT_REF_VALID"]})
    write_text(os.path.join(v022_dir, "README.md"),
               "# V022 — Issuer-Dependent Verification\n\n"
               "The artifact set would require issuer-side rescue or reconstruction to complete the path.\n"
               "Expected: INCOMPLETE (SETTLEMENT_REF_VALID)")
    print("  V022 generated")

    # V023
    v = clone_fixture(p001)
    del v["material"]["finality_proof"]
    write_negative_zero_data(
        adversarial_dir, "V023", v,
        {"result_code": "INCOMPLETE", "failed_check_ids": ["FINALITY_SUFFICIENT"]},
        "# V023 — Provider-Dependent Verification\n\n"
        "The canonical artifact set lacks finality proof material, so a live provider lookup would be required to continue.\n"
        "Expected: INCOMPLETE (FINALITY_SUFFICIENT)",
    )
    print("  V023 generated")

    # V024
    v = clone_fixture(p001)
    del v["material"]["submission_assignment_proof"]
    write_negative_zero_data(
        adversarial_dir, "V024", v,
        {"result_code": "INCOMPLETE", "failed_check_ids": ["INCLUSION_PROOF_VALID"]},
        "# V024 — Receipt Equivalence\n\n"
        "Receipt-like settlement material is present, but the canonical submission inclusion path is absent.\n"
        "Expected: INCOMPLETE (INCLUSION_PROOF_VALID)",
    )
    print("  V024 generated")

    # V025
    v = clone_fixture(p001)
    v["proof"]["batch"]["index"] = "1"
    seal_proof(v["proof"])
    write_negative_zero_data(
        adversarial_dir, "V025", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["AGGREGATED_INTERPRETATION_UNIQUE"]},
        "# V025 — Multi-Proof Ambiguity\n\n"
        "The claimed batch index does not resolve to one exact submission assignment.\n"
        "Expected: INDEPENDENT_INVALID (AGGREGATED_INTERPRETATION_UNIQUE)",
    )
    print("  V025 generated")

    # V026
    v = clone_fixture(p001)
    v["material"]["capacity_consumption_proof"]["token_symbol"] = "FAKE"
    write_negative_zero_data(
        adversarial_dir, "V026", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["CAPACITY_BINDING_VALID"]},
        "# V026 — Capacity Spoofing\n\n"
        "Capacity-like evidence is present but not bound to the required settlement token semantics.\n"
        "Expected: INDEPENDENT_INVALID (CAPACITY_BINDING_VALID)",
    )
    print("  V026 generated")

    # V027 — replay/recontextualization: submission_assignment_proof.subtree_root
    # is replaced with a wrong value, so it disagrees with proof.subtree_root and
    # the leaf_preimage.subtree_root → the assignment no longer resolves uniquely.
    v = clone_fixture(p001)
    v["material"]["submission_assignment_proof"]["subtree_root"] = digest_hex_text("subtree:replayed-V027")
    write_negative_zero_data(
        adversarial_dir, "V027", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["AGGREGATED_INTERPRETATION_UNIQUE"]},
        "# V027 — Replay or Recontextualization\n\n"
        "Submission-assignment material from one context is replayed into another:\n"
        "submission_assignment_proof.subtree_root disagrees with the proof's subtree_root.\n"
        "Expected: INDEPENDENT_INVALID (AGGREGATED_INTERPRETATION_UNIQUE)",
    )
    print("  V027 generated")

    # V028 — post-hoc reconstruction: anchor.root_id is removed. Applied
    # via cert_mutator BEFORE the ccd + evidence are computed, so the hybrid
    # binding stays coherent (§7.10) and the structurally-valid cert simply has no
    # admissible issuance-time root binding — the break lands at
    # ISSUANCE_PARTICIPATION_VALID, not earlier.
    def clear_root_v028(cert: dict) -> None:
        del cert["payload"]["anchor"]["root_id"]
        refresh_certificate_payload(cert)
        recompose_cert_signature(cert)

    v = build_zero_data_fixture(
        {
            "fixtureId": "V028", "batchId": "batch-V028", "windowId": "window-V028",
            "trxId": "trx-V028", "leafIndex": 0, "batchSize": 2,
            "blockNum": 1000, "libNum": 1005,
            "consumedQuantity": "5.00", "totalQuantity": "10.00",
            "issuerScope": "issuer:acme-corp", "capacityAuthRef": "cap-auth-V028",
        },
        cert_mutator=clear_root_v028,
    )
    write_negative_zero_data(
        adversarial_dir, "V028", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["ISSUANCE_PARTICIPATION_VALID"]},
        "# V028 — Post-Hoc Reconstruction Without Issuance Binding\n\n"
        "The certificate is structurally valid (root_id is optional in CCSP/1), but it carries no issuance-time root binding.\n"
        "Expected: INDEPENDENT_INVALID (ISSUANCE_PARTICIPATION_VALID)",
    )
    print("  V028 generated")

    # V029
    v = clone_fixture(p001)
    v["proof"]["settlement"]["ref"] = f"{v['proof']['settlement_ref']}-compatible"
    seal_proof(v["proof"])
    write_negative_zero_data(
        adversarial_dir, "V029", v,
        {"result_code": "REJECTED", "failed_check_ids": ["SETTLEMENT_REF_VALID"]},
        "# V029 — Compatible-Enough Acceptance\n\n"
        "The path looks close to valid, but settlement reference coherence is not exact.\n"
        "Expected: REJECTED (SETTLEMENT_REF_VALID)",
    )
    print("  V029 generated")

    # V030 — settlement_ref bound to material (settlement-material/1 §12.7). The SIGNED settlement_ref
    # encodes chain_id:trx_id:action_ordinal:batch_id:window_id. Mutate ONLY the
    # material's settlement_action.trx_id (an UNSIGNED field) so it diverges from
    # the signed ref. The verifier must parse the ref and reject the divergence.
    v = clone_fixture(p001)
    v["material"]["settlement_action"]["trx_id"] = "trx-attacker-swapped"
    write_negative_zero_data(
        adversarial_dir, "V030", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["SETTLEMENT_REF_VALID"]},
        "# V030 — Settlement Material Diverges From Signed settlement_ref\n\n"
        "settlement_action.trx_id (unsigned) is swapped while the proof's signed\n"
        "settlement_ref is left intact, so the material no longer matches what the\n"
        "system domain signed.\n"
        "Expected: INDEPENDENT_INVALID (SETTLEMENT_REF_VALID)",
    )
    print("  V030 generated")

    # V031 — multi-auth leaf MISSING the bridge for the verified evidence
    # (settlement-material/1 §12.6). P004 verifies member A; drop A's bridge, leaving only B's.
    # The verifier cannot reconstruct A's authorization -> fail.
    v = clone_fixture(p004)
    # P004 verifies member A (index 0); its bridge is entry 0. Keep only B's.
    v["material"]["authorization_bridge_proofs"] = [
        v["material"]["authorization_bridge_proofs"][1]
    ]
    write_negative_zero_data(
        adversarial_dir, "V031", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["CAPACITY_NOT_RECONSTRUCTED"]},
        "# V031 — Multi-Auth Leaf Missing the Verified Member's Bridge\n\n"
        "The leaf has two authorizations but the material omits the bridge whose\n"
        "digest matches the evidence under verification.\n"
        "Expected: INDEPENDENT_INVALID (CAPACITY_NOT_RECONSTRUCTED)",
    )
    print("  V031 generated")

    # V032 — two bridges DISAGREE on batch_binding_preimage (settlement-material/1 §12.7). The
    # memo is batch-level (one per settlement); diverging bbp across bridges is
    # incoherent. The verifier requires all entries to share one bbp.
    v = clone_fixture(p004)
    bad_bbp = json.loads(json.dumps(v["material"]["authorization_bridge_proofs"][1]["batch_binding_preimage"]))
    bad_bbp["total_quantity"] = "999.00"
    v["material"]["authorization_bridge_proofs"][1]["batch_binding_preimage"] = bad_bbp
    write_negative_zero_data(
        adversarial_dir, "V032", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["CAPACITY_NOT_RECONSTRUCTED"]},
        "# V032 — Multi-Auth Bridges Disagree on batch_binding_preimage\n\n"
        "The batch binding is batch-level (one memo per settlement); two bridges\n"
        "carrying different batch_binding_preimage is incoherent.\n"
        "Expected: INDEPENDENT_INVALID (CAPACITY_NOT_RECONSTRUCTED)",
    )
    print("  V032 generated")

    # V033 — ANTI-SPLICING: the verified commitment_id is NOT among the proof's
    # consumed_commitment_ids. The commitment inclusion proof (commitment_id →
    # subtree_root) and the hybrid emission binding stay INTACT, so LEAF_BINDING
    # passes; only the membership cross-check fails — the proof anchors a subtree
    # but does not DECLARE it consumed this commitment. This is the isolated
    # ANTI_SPLICING_VALID negative (baseline atomic check, independence.proof/1 §10):
    # a proof spliced onto a leaf it never consumed. consumed_commitment_ids is in
    # the signed proof view, so the proof_digest is recomputed (still a coherent,
    # self-consistent proof — the ONLY defect is the missing membership). The
    # commitment_id remains an opaque zero-data digest (unlinkability preserved).
    v = clone_fixture(p001)
    cip_cid = v["commitmentInclusionProof"]["commitment_id"]
    v["proof"]["consumed_commitment_ids"] = [
        digest_hex_text("V033-other-commitment") if c == cip_cid else c
        for c in v["proof"]["consumed_commitment_ids"]
    ]
    seal_proof(v["proof"])
    write_negative_zero_data(
        adversarial_dir, "V033", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["ANTI_SPLICING_VALID"]},
        "# V033 — Anti-Splicing: Commitment Not Declared Consumed\n\n"
        "The verified commitment_id is absent from proof.consumed_commitment_ids,\n"
        "while the inclusion proof (commitment_id -> subtree_root) and the hybrid\n"
        "emission binding remain intact. LEAF_BINDING_VALID passes (the path still\n"
        "verifies against subtree_root); the membership cross-check is the break —\n"
        "a proof spliced onto a leaf it never declares it consumed.\n"
        "Expected: INDEPENDENT_INVALID (ANTI_SPLICING_VALID)",
    )
    print("  V033 generated")

    # V034 — SETTLEMENT NOT RETROACTIVE: the settlement block time is AFTER the
    # capacity commitment's expires_at. A burn cannot consume capacity that had already
    # expired when it landed. The finality is otherwise sufficient (lib >= block,
    # irreversible), so FINALITY_SUFFICIENT passes and the temporal check is the
    # isolated break (settlement.aggregated.xrpl/1 §12; settlement.binding/1 §9).
    # block_timestamp comes from the substrate (NEVER CERTCRYPT's clock), so this
    # is the honest anti-retroactivity guard. The proof's finality witness is a
    # projection of the material (independence.proof/1 §10.6), so it carries the
    # same block time and the proof is re-sealed: the witness stays coherent and
    # the temporal check remains the isolated break.
    v = clone_fixture(p001)
    # Push the settlement block time past the evidence's expires_at, years
    # later — unambiguously after.
    expires_at = v["capacityEvidence"]["projected_commitment"]["expires_at"]
    v["material"]["finality_proof"]["block_timestamp"] = "2099-01-01T00:00:00.000Z"
    v["proof"]["settlement"]["finality_proofs"][0]["timestamp"] = "2099-01-01T00:00:00.000Z"
    seal_proof(v["proof"])
    write_negative_zero_data(
        adversarial_dir, "V034", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["SETTLEMENT_NOT_RETROACTIVE"]},
        "# V034 — Settlement Is Retroactive (block time after expiry)\n\n"
        "settlement_material.finality_proof.block_timestamp is AFTER the capacity\n"
        "commitment's expires_at: the on-chain burn landed once the capacity had\n"
        f"already expired ({expires_at}). Finality is otherwise sufficient, so the\n"
        "temporal no-retroactivity check is the isolated break. The block time is the\n"
        "substrate's own (never asserted by the issuing system).\n"
        "Expected: INDEPENDENT_INVALID (SETTLEMENT_NOT_RETROACTIVE)",
    )
    print("  V034 generated")

    # V035 — CAPACITY_EVIDENCE_VALID: the zero-data evidence recomputes to its
    # commitment_id (LEAF_BINDING passes) but its INTERNAL binding is broken — the
    # projected commitment's holder_pseudonym does not match the projected
    # authorization's. This is the per-commitment capacity-evidence check, a
    # baseline-atomic check (independence.proof/1 §10), in isolation. Because the evidence is mutated
    # BEFORE its digest and the sub-tree are built (evidence_mutator hook), the whole
    # binding chain (commitment_id, leaf hash, subtree_root, proof digest) stays
    # coherent, so ONLY CAPACITY_EVIDENCE_VALID fails — the isolated N>1 splice a
    # single proof-level digest could never catch. Pseudonyms remain scoped/opaque
    # (zero-data + unlinkability preserved); the defect is the internal binding, not a
    # leaked identifier.
    def _break_pseudonym_binding(ev: dict) -> None:
        # Diverge the commitment's holder_pseudonym from the authorization's. A
        # spliced-in commitment from a DIFFERENT holder-projection would present
        # exactly this mismatch. Still a valid-shaped scoped pseudonym (opaque).
        ev["projected_commitment"]["holder_pseudonym"] = digest_hex_text(
            "V035-spliced-holder-pseudonym"
        )
    v035 = build_zero_data_fixture({
        "fixtureId": "V035", "batchId": "batch-V035", "windowId": "window-V035",
        "trxId": "trx-V035", "leafIndex": 0, "batchSize": 2,
        "consumedQuantity": "5.00", "totalQuantity": "10.00",
        "blockNum": 1000, "libNum": 1005,
        "issuerScope": "issuer:acme-corp", "capacityAuthRef": "cap-auth-V035",
    }, evidence_mutator=_break_pseudonym_binding)
    write_negative_zero_data(
        adversarial_dir, "V035", v035,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["CAPACITY_EVIDENCE_VALID"]},
        "# V035 — Capacity Evidence Internal Binding Broken (pseudonym splice)\n\n"
        "The zero-data capacity evidence recomputes to its commitment_id (so the\n"
        "hybrid emission binding and inclusion path pass), but the projected\n"
        "commitment's holder_pseudonym does not match the projected authorization's —\n"
        "the internal per-commitment binding is broken, as if evidence from a\n"
        "different holder-projection were spliced into this leaf. This is the\n"
        "isolated CAPACITY_EVIDENCE_VALID negative for the N>1 binding.\n"
        "Expected: INDEPENDENT_INVALID (CAPACITY_EVIDENCE_VALID)",
    )
    print("  V035 generated")

    # V036 — UNSUPPORTED result_code: the proof declares an unsupported proof_version.
    # This is the taxonomy's UNSUPPORTED verdict (verifier-toolkit/1 §9).
    # PROOF_VERSION_SUPPORTED fails UNSUPPORTED (not INVALID/
    # REJECTED) when proof_version != "independence.proof/1": the verifier cannot assert the
    # verdict under an unknown proof schema, which is distinct from a proof that is
    # understood-and-wrong. proof_digest is recomputed so the version mismatch is the
    # isolated break.
    v = clone_fixture(p001)
    v["proof"]["proof_version"] = "independence.proof/99"
    seal_proof(v["proof"])
    write_negative_zero_data(
        adversarial_dir, "V036", v,
        {"result_code": "UNSUPPORTED", "failed_check_ids": ["PROOF_VERSION_SUPPORTED"]},
        "# V036 — Unsupported Proof Version\n\n"
        "proof.proof_version is \"independence.proof/99\", a schema the toolkit does not\n"
        "implement. The verdict is UNSUPPORTED (not INDEPENDENT_INVALID/REJECTED): the\n"
        "toolkit cannot assert a verdict under an unknown proof schema — the taxonomy's\n"
        "UNSUPPORTED case (verifier-toolkit/1 §9).\n"
        "Expected: UNSUPPORTED (PROOF_VERSION_SUPPORTED)",
    )
    print("  V036 generated")

    # V037 — FOUNDATION_SYSTEM_ID_VALID: the foundation statement's system_id does not
    # match the verifier's configured system domain. system-foundation/1 §11 step 2
    # runs BEFORE the quorum-signature check, so this is the isolated system-domain
    # break at the foundation layer (distinct from the proof's SYSTEM_DOMAIN_EXACT,
    # V002). The (now-stale) quorum signature is not recomputed: the system_id check
    # fires before the quorum is verified.
    v = clone_fixture(p001)
    v["foundation"]["system_id"] = "certcrypt-impostor"
    write_negative_zero_data(
        adversarial_dir, "V037", v,
        {"result_code": "REJECTED", "failed_check_ids": ["FOUNDATION_SYSTEM_ID_VALID"]},
        "# V037 — Foundation System-ID Mismatch\n\n"
        "system-foundation/1 statement carries system_id \"certcrypt-impostor\", not the\n"
        "verifier's configured system domain. system-foundation/1 §11 (step 2) rejects\n"
        "before the quorum signature is even considered — the foundation-layer\n"
        "system-domain binding.\n"
        "Expected: REJECTED (FOUNDATION_SYSTEM_ID_VALID)",
    )
    print("  V037 generated")

    # P006 — extra (unused) bridge is TOLERATED (settlement-material/1 §9). The verifier is
    # per-commitment: it selects the bridge matching THIS evidence and ignores
    # others. Exact-set is a PRODUCER invariant (the assembler emits exactly the
    # leaf's authorizations), not checkable per-commitment, so an extra bridge does
    # not by itself fail a verdict. This fixture pins that contract.
    p006 = build_multi_auth_fixture(fixture_id="P004", target_index=0)
    p006["material"]["authorization_bridge_proofs"].append({
        "resolved_authorization_digest": "ee" * 32,
        "cost_commitment": p006["material"]["authorization_bridge_proofs"][0]["cost_commitment"],
        "consumed_quantity": "5.00",
        "batch_binding_preimage": p006["material"]["authorization_bridge_proofs"][0]["batch_binding_preimage"],
    })
    write_zero_data_fixture(
        conformance_dir, "P006", p006,
        "# P006 — Extra Unused Bridge Tolerated\n\n"
        "A third bridge with a digest matching no commitment is present. The\n"
        "per-commitment verifier selects the matching bridge and ignores extras;\n"
        "exact-set is a producer invariant. Expected: INDEPENDENT_VALID.",
    )
    print("  P006 generated")

    # === FOUNDATION FIXTURES ===

    print("\nGenerating foundation fixtures...\n")

    # F-series — FOUNDATION statement, on the hybrid leaf=subtree model. Each
    # fixture clones a hybrid base and overrides ONLY system-foundation.json. The
    # base certificate is untouched, so the emission binding (SHA3(cert)==ccd) holds
    # naturally and the only variable is the foundation. A broken foundation is
    # REJECTED in the foundation phase, which runs (and returns) before the capacity
    # binding that resolves the system-domain Level-1 key — so a mutated/replaced
    # foundation cannot pollute capacity checks. The valid F001/F005 (written to
    # conformance/, being positive) reuse the base's own hybrid foundation (which
    # carries system_domain_capacity_key_{p256,mldsa}_b64), keeping the full Independent path
    # green.
    #
    # The foundation quorum signatures (build_foundation_payload_digest) cover the
    # signed §9 payload INCLUDING the system_domain_capacity_key_{p256,mldsa}_b64
    # fields, so mutating any covered field and re-signing with sign_foundation
    # re-binds them all (an unsigned capacity key would be a forge vector — system-foundation/1 §9).

    def write_foundation_fixture(fixture_id, base, foundation, expected, readme):
        """Write the hybrid artifact set with a foundation override (negative)."""
        f = clone_fixture(base)
        f["foundation"] = foundation
        write_negative_zero_data(adversarial_dir, fixture_id, f, expected, readme)

    def write_valid_foundation_fixture(fixture_id, base, foundation, readme):
        """Write the hybrid artifact set with a foundation override (positive)."""
        f = clone_fixture(base)
        f["foundation"] = foundation
        write_zero_data_fixture(conformance_dir, fixture_id, f, readme)

    f_base = build_zero_data_fixture({
        "fixtureId": "F001", "batchId": "batch-F001", "windowId": "window-F001",
        "trxId": "trx-F001", "leafIndex": 0, "batchSize": 1,
        "consumedQuantity": "3.00", "totalQuantity": "3.00",
        "blockNum": 2000, "libNum": 2010,
        "issuerScope": "issuer:foundation-test", "capacityAuthRef": "cap-auth-F001",
    })
    valid_foundation = f_base["foundation"]

    # F001 — valid foundation (the base's own hybrid system-foundation/1).
    write_valid_foundation_fixture(
        "F001", f_base, valid_foundation,
        "# F001 — Valid Foundation (Local Offline)\n\n"
        "A system-foundation/1 statement embedding a system-manifest/1 bootstrap\n"
        "manifest (k-of-n composite quorum) and carrying the system-domain Level-1\n"
        "capacity key for the zero-data anchor. Fingerprint = SHA3-256(JCS(manifest));\n"
        "statement authorized by a quorum of member signatures. All checks pass.\n"
        "Expected: INDEPENDENT_VALID",
    )
    print("  F001 generated")

    # F002 — fingerprint derivation mismatch.
    bad_foundation = json.loads(json.dumps(valid_foundation))
    bad_foundation["system_root_fingerprint"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    recompose_foundation_signature(bad_foundation)
    write_foundation_fixture(
        "F002", f_base, bad_foundation,
        {"result_code": "REJECTED", "failed_check_ids": ["FOUNDATION_FINGERPRINT_RECOMPUTED"]},
        "# F002 — Fingerprint Derivation Mismatch\n\n"
        "system_root_fingerprint does not match recomputation from the embedded system_manifest.\n"
        "Expected: REJECTED (FOUNDATION_FINGERPRINT_RECOMPUTED)",
    )
    print("  F002 generated")

    # F003 — invalid foundation signature (ML-DSA-65 component corrupted). Under
    # the composite AND, a broken component drops that member below verifying, so
    # the quorum falls under k → FOUNDATION_SIGNATURE_VALID fails. Corrupt the
    # ML-DSA component of ENOUGH members (n-k+1 = 2) that the verifying count < k.
    bad_sig_foundation = json.loads(json.dumps(valid_foundation))
    _f003_k = bad_sig_foundation["system_manifest"]["entries"][0]["quorum"]["k"]
    _f003_sigs = bad_sig_foundation["statement_signatures"]
    _f003_to_break = len(_f003_sigs) - _f003_k + 1  # drop below k distinct verifiers
    for _f003_entry in _f003_sigs[:_f003_to_break]:
        _f003_mldsa = _f003_entry["signature"]["signatures"][1]  # ML-DSA component
        _f003_bad = bytearray(base64.b64decode(_f003_mldsa["sig_b64"]))
        _f003_bad[0] = _f003_bad[0] ^ 0xFF
        _f003_mldsa["sig_b64"] = base64.b64encode(bytes(_f003_bad)).decode("ascii")
    write_foundation_fixture(
        "F003", f_base, bad_sig_foundation,
        {"result_code": "REJECTED", "failed_check_ids": ["FOUNDATION_SIGNATURE_VALID"]},
        "# F003 — Invalid Foundation Signature\n\n"
        "The ML-DSA-65 component of enough member statement_signatures is corrupted\n"
        "that fewer than quorum.k distinct members verify. Composite verification is\n"
        "AND, so each tampered member fails; the quorum is not met.\n"
        "Expected: REJECTED (FOUNDATION_SIGNATURE_VALID)",
    )
    print("  F003 generated")

    # F004 — right root, right statement id, other signed content. The bootstrap
    # quorum signs a second statement over the same manifest and id that differs
    # in one signed member (published_rules_versions, which is metadata); only the
    # registered payload digest tells it from the registered statement.
    other_payload_foundation = json.loads(json.dumps(valid_foundation))
    other_payload_foundation["published_rules_versions"] = ["rules/conformance", "rules/2027-01"]
    recompose_foundation_signature(other_payload_foundation)
    write_foundation_fixture(
        "F004", f_base, other_payload_foundation,
        {"result_code": "REJECTED", "failed_check_ids": ["FOUNDATION_BOOTSTRAP_MATCHES_RULES"]},
        "# F004 — Second Statement Over the Registered Bootstrap\n\n"
        "The bootstrap quorum signs another statement with the registered root and the\n"
        "registered foundation_statement_id, differing only in published_rules_versions.\n"
        "Every signature verifies, and the list is metadata that gates nothing; but the\n"
        "statement's payload digest is not the registered foundation_payload_digest, so\n"
        "it is not the one bootstrap statement (system-domain/1 registry entry §6).\n"
        "Expected: REJECTED (FOUNDATION_BOOTSTRAP_MATCHES_RULES)",
    )
    print("  F004 generated")

    # F005 — publication ref present, ignored for validity.
    f005_base = build_zero_data_fixture({
        "fixtureId": "F005", "batchId": "batch-F005", "windowId": "window-F005",
        "trxId": "trx-F005", "leafIndex": 0, "batchSize": 1,
        "consumedQuantity": "1.00", "totalQuantity": "1.00",
        "blockNum": 3000, "libNum": 3010,
        "issuerScope": "issuer:pub-test", "capacityAuthRef": "cap-auth-F005",
    })
    pub_ref_foundation = json.loads(json.dumps(f005_base["foundation"]))
    pub_ref_foundation["publication_refs"] = [{
        "publication_profile": "arweave.publication/1",
        "publication_reference": "arweave-tx-fake-12345",
    }]
    write_valid_foundation_fixture(
        "F005", f005_base, pub_ref_foundation,
        "# F005 — Publication Ref Present, Ignored for Validity\n\n"
        "Foundation has a publication_ref (arweave). Validation passes "
        "because publication_refs are provenance only, not required.\n"
        "Expected: INDEPENDENT_VALID",
    )
    print("  F005 generated")

    # F006 — publication locator used as pseudo-root.
    pseudo_root_foundation = json.loads(json.dumps(valid_foundation))
    pseudo_root_foundation["foundation_profile_id"] = "arweave-txid-root/1"
    recompose_foundation_signature(pseudo_root_foundation)
    write_foundation_fixture(
        "F006", f_base, pseudo_root_foundation,
        {"result_code": "REJECTED", "failed_check_ids": ["FOUNDATION_PROFILE_VALID"]},
        "# F006 — Publication Locator Used as Pseudo-Root\n\n"
        "foundation_profile_id is 'arweave-txid-root/1' instead of 'system-foundation/1'.\n"
        "A publication locator cannot substitute for the exact foundation profile.\n"
        "Expected: REJECTED (FOUNDATION_PROFILE_VALID)",
    )
    print("  F006 generated")

    # F007 — foundation valid internally but mismatches published bootstrap.
    # We preserve system_domain_capacity_key_*_b64 so the only break is the
    # bootstrap mismatch (which is REJECTED before capacity checks).
    # A separate k-of-n quorum of DISTINCT composite members → a distinct
    # bootstrap manifest → a distinct, internally-valid system_root_fingerprint
    # that is correctly quorum-signed, but != the published bootstrap.
    _f007_members = []
    _f007_signers = {}
    for _i in range(ROOT_QUORUM_N):
        _mkid = f"m{_i}"
        _pp, _ppub, _msk, _mpub = _deterministic_composite_member(f"F007-other-root:{_mkid}")
        _f007_signers[_mkid] = {"p256_priv": _pp, "mldsa_sk": _msk}
        _f007_members.append({
            "member_kid": _mkid,
            "public_key_p256_b64": _ppub,
            "public_key_mldsa_b64": _mpub,
        })
    other_manifest = {
        "manifest_profile_id": "system-manifest/1",
        "system_id": config["system_id"],
        "manifest_sequence": 0,
        "entries": [{
            "kid": "conformance-other-root-1",
            "algorithm": PROFILE_P256_MLDSA65,
            "quorum": {"k": ROOT_QUORUM_K, "n": ROOT_QUORUM_N},
            "members": _f007_members,
            "valid_from": ROOT_VALID_FROM,
            "valid_until": None,
            "predecessor_kid": None,
            "successor_kid": None,
            "predecessor_signatures": None,
            "predecessor_manifest_fingerprint": None,
        }],
    }
    other_fingerprint = digest_hex_bytes(jcs_canonicalize_bytes(other_manifest))
    other_foundation = {
        "foundation_profile_id": "system-foundation/1",
        "foundation_statement_id": "test-foundation-other-root",
        "system_id": config["system_id"],
        "system_root_fingerprint": other_fingerprint,
        "system_manifest": other_manifest,
        "root_fingerprint_derivation": "sha3-256-system-manifest-jcs-v1",
        "published_rules_versions": ["rules/conformance"],
        "statement_issued_at": "2026-04-12T00:00:00Z",
        "system_domain_capacity_key_p256_b64": valid_foundation["system_domain_capacity_key_p256_b64"],
        "system_domain_capacity_key_mldsa_b64": valid_foundation["system_domain_capacity_key_mldsa_b64"],
    }
    _other_digest = build_foundation_payload_digest(other_foundation)
    other_foundation["statement_signatures"] = [
        {"signer_member_kid": mkid,
         "signature": composite_sign_with(_other_digest, _f007_signers[mkid]["p256_priv"], _f007_signers[mkid]["mldsa_sk"])}
        for mkid in [f"m{_i}" for _i in range(ROOT_QUORUM_K)]
    ]
    write_foundation_fixture(
        "F007", f_base, other_foundation,
        {"result_code": "REJECTED", "failed_check_ids": ["FOUNDATION_BOOTSTRAP_MATCHES_RULES"]},
        "# F007 — Foundation Valid Internally But Mismatches Published Bootstrap\n\n"
        "A separate k-of-n composite quorum produces a valid, correctly\n"
        "quorum-signed foundation statement embedding its own bootstrap manifest,\n"
        "but its derived system_root_fingerprint does not match the published\n"
        "bootstrap for rules/conformance.\n"
               "This is the exact attack system-domain/1 and system-foundation/1 prevent:\n"
               "a valid-looking foundation cannot redefine the CERTCRYPT root.\n"
               "Expected: REJECTED (FOUNDATION_BOOTSTRAP_MATCHES_RULES)")
    print("  F007 generated")

    # F008 — capacity-key substitution with the ORIGINAL statement signature intact
    # (signed-payload coverage, system-foundation/1 §9). Take the valid foundation, swap ONLY the
    # system_domain_capacity_key_{mldsa,p256}_b64 for an attacker key, and DO NOT
    # re-sign. Because the capacity key is inside the signed §9 payload, the
    # untouched statement signature no longer verifies → REJECTED at
    # FOUNDATION_SIGNATURE_VALID. A capacity key outside the signed payload would
    # let this swap pass and forge the whole capacity/proof chain.
    atk_mldsa_pk, _atk_mldsa_sk = deterministic_ml_dsa65("F008-attacker-capacity-mldsa")
    _atk_p256_priv, _atk_p256_pub, atk_p256_pub_b64 = primitives.deterministic_p256("F008-attacker-capacity-p256")
    swapped_foundation = json.loads(json.dumps(valid_foundation))
    swapped_foundation["system_domain_capacity_key_mldsa_b64"] = base64.b64encode(atk_mldsa_pk).decode("ascii")
    swapped_foundation["system_domain_capacity_key_p256_b64"] = atk_p256_pub_b64
    # NOTE: statement_signatures deliberately left as the ORIGINAL valid_foundation
    # quorum signatures — the attacker cannot re-sign without ≥ k genuine member keys.
    write_foundation_fixture(
        "F008", f_base, swapped_foundation,
        {"result_code": "REJECTED", "failed_check_ids": ["FOUNDATION_SIGNATURE_VALID"]},
        "# F008 — Capacity-Key Substitution (Signed-Payload Coverage)\n\n"
        "The Level-1 composite capacity key — which signs the IndependenceProof and\n"
        "the capacity Level-1 binding — is swapped for an attacker key while the\n"
        "original statement signature is left intact. Because the capacity key is\n"
        "covered by the statement signature, the swap invalidates it.\n"
        "Expected: REJECTED (FOUNDATION_SIGNATURE_VALID)")
    print("  F008 generated")

    # F009 — right root, wrong statement. The statement is internally valid and
    # correctly quorum-signed over the published bootstrap manifest, so its
    # fingerprint matches; but its foundation_statement_id is not the one the
    # registry entry declares. The registered bootstrap is one exact statement.
    other_id_foundation = json.loads(json.dumps(valid_foundation))
    other_id_foundation["foundation_statement_id"] = "test-foundation-other-statement"
    recompose_foundation_signature(other_id_foundation)
    write_foundation_fixture(
        "F009", f_base, other_id_foundation,
        {"result_code": "REJECTED", "failed_check_ids": ["FOUNDATION_BOOTSTRAP_MATCHES_RULES"]},
        "# F009 — Bootstrap Statement Id Not the Registered One\n\n"
        "A correctly quorum-signed statement over the published bootstrap manifest\n"
        "(same root fingerprint) carries a foundation_statement_id other than the one\n"
        "the registry entry declares. Matching the root is not enough: the registered\n"
        "bootstrap is one exact statement.\n"
        "Expected: REJECTED (FOUNDATION_BOOTSTRAP_MATCHES_RULES)")
    print("  F009 generated")

    # === CLOSED SHAPES OF THE STATEMENT AND THE BOOTSTRAP MANIFEST ===
    # (system-foundation/1 §6, system-manifest/1 §6, §7.3). Each mutates one thing,
    # recomputes the fingerprint when the manifest changed, and re-signs with the
    # quorum, so the only defect left is the one the README names.

    def _compress_p256_b64(b64: str) -> str:
        """The same P-256 point, compressed to 33 bytes: same key, other bytes."""
        raw = base64.b64decode(b64)
        prefix = b"\x03" if raw[64] & 1 else b"\x02"
        return base64.b64encode(prefix + raw[1:33]).decode("ascii")

    def _refingerprint(f: dict) -> None:
        f["system_root_fingerprint"] = digest_hex_bytes(jcs_canonicalize_bytes(f["system_manifest"]))
        recompose_foundation_signature(f)

    def _shape_fixture(fixture_id, mutate, check, title, body):
        f = json.loads(json.dumps(valid_foundation))
        mutate(f)
        write_foundation_fixture(
            fixture_id, f_base, f,
            {"result_code": "REJECTED", "failed_check_ids": [check]},
            f"# {fixture_id} — {title}\n\n{body}\nExpected: REJECTED ({check})",
        )
        print(f"  {fixture_id} generated")

    def _m_extra(f):
        f["system_manifest"]["note"] = "not a manifest member"
        _refingerprint(f)
    _shape_fixture("F010", _m_extra, "FOUNDATION_FINGERPRINT_RECOMPUTED",
        "Manifest Member Outside the Closed Schema",
        "The embedded manifest carries a top-level member system-manifest/1 §6 does\n"
        "not define. The fingerprint is recomputed over it and the statement re-signed,\n"
        "so only the closed schema rejects it.")

    def _m_compressed(f):
        m = f["system_manifest"]["entries"][0]["members"][1]
        m["public_key_p256_b64"] = _compress_p256_b64(m["public_key_p256_b64"])
        _refingerprint(f)
    _shape_fixture("F011", _m_compressed, "FOUNDATION_FINGERPRINT_RECOMPUTED",
        "Member Key in Compressed SEC1 Form",
        "A bootstrap member's P-256 key is the same point compressed to 33 bytes. The\n"
        "field admits one encoding, SEC1 uncompressed (65 bytes): another encoding of\n"
        "the same key would give the manifest another fingerprint (system-manifest/1\n"
        "§7.3, composite-signature/1 §9.1).")

    def _l1_compressed(f):
        f["system_domain_capacity_key_p256_b64"] = _compress_p256_b64(f["system_domain_capacity_key_p256_b64"])
        recompose_foundation_signature(f)
    _shape_fixture("F012", _l1_compressed, "FOUNDATION_SIGNATURE_VALID",
        "Level-1 Key in Compressed SEC1 Form",
        "The statement's Level-1 capacity key is the same point compressed to 33 bytes,\n"
        "and the quorum re-signs the statement over it. The field admits only the\n"
        "65-byte SEC1 uncompressed encoding (system-foundation/1 §6).")

    def _seq1(f):
        f["system_manifest"]["manifest_sequence"] = 1
        _refingerprint(f)
    _shape_fixture("F013", _seq1, "FOUNDATION_FINGERPRINT_RECOMPUTED",
        "Embedded Manifest Not at Sequence 0",
        "The embedded manifest declares manifest_sequence 1 with its single entry. A\n"
        "statement embeds only the bootstrap version (system-foundation/1 §7).")

    def _k1(f):
        f["system_manifest"]["entries"][0]["quorum"]["k"] = 1
        _refingerprint(f)
    _shape_fixture("F014", _k1, "FOUNDATION_FINGERPRINT_RECOMPUTED",
        "Single-Key Quorum",
        "The bootstrap entry declares quorum k = 1. The single-key root is not\n"
        "representable under /1: 2 <= k <= n (system-manifest/1 §6, §7.3).")

    def _members_not_n(f):
        f["system_manifest"]["entries"][0]["quorum"]["n"] = 4
        _refingerprint(f)
    _shape_fixture("F015", _members_not_n, "FOUNDATION_FINGERPRINT_RECOMPUTED",
        "Member Count Differs From n",
        "The bootstrap entry declares n = 4 and lists three members. members MUST hold\n"
        "exactly n elements (system-manifest/1 §7.3).")

    def _ed25519_root(f):
        f["system_manifest"]["entries"][0]["algorithm"] = "certcrypt-composite-ed25519-mldsa65-v1"
        _refingerprint(f)
    _shape_fixture("F016", _ed25519_root, "FOUNDATION_FINGERPRINT_RECOMPUTED",
        "Root Under the Ed25519 Profile",
        "The bootstrap entry declares certcrypt-composite-ed25519-mldsa65-v1. That\n"
        "profile MUST NOT be the default of a system-foundation root\n"
        "(composite-signature/1 §7), and the verifier supports the canonical profile\n"
        "for the root.")

    def _stmt_extra(f):
        f["statement_note"] = "not a statement member"
    _shape_fixture("F017", _stmt_extra, "FOUNDATION_PROFILE_VALID",
        "Statement Member Outside the Closed Set",
        "The statement carries a member system-foundation/1 §6 does not define. It is\n"
        "outside the signed payload, so every signature still verifies; the closed\n"
        "member set rejects it.")

    def _l1_mldsa_len(f):
        f["system_domain_capacity_key_mldsa_b64"] = base64.b64encode(
            base64.b64decode(f["system_domain_capacity_key_mldsa_b64"])[:-1]).decode("ascii")
        recompose_foundation_signature(f)
    _shape_fixture("F018", _l1_mldsa_len, "FOUNDATION_SIGNATURE_VALID",
        "Level-1 ML-DSA Key of the Wrong Length",
        "The statement's Level-1 ML-DSA-65 key is one byte short of the 1952 bytes\n"
        "FIPS 204 fixes, and the quorum re-signs the statement over it\n"
        "(system-foundation/1 §6).")

    # === k-OF-n QUORUM NEGATIVES (system-manifest/1 §12.3, system-foundation/1 §9) ===
    # These exercise the quorum-counting rule of the bootstrap statement: a rotation/
    # bootstrap is authorized iff ≥ k DISTINCT members verify, each counted by real
    # composite verification. Each takes the valid foundation and
    # rewrites ONLY statement_signatures to a specific quorum-counting failure mode.

    _qn_payload_digest = build_foundation_payload_digest(valid_foundation)

    def _member_sig(member_kid, signer_kid=None):
        """A {signer_member_kid, signature} object: composite-signed by member
        `signer_kid` (default = member_kid), tagged as `member_kid`."""
        return {
            "signer_member_kid": member_kid,
            "signature": composite_sign_member(_qn_payload_digest, signer_kid or member_kid),
        }

    # QN1 — insufficient quorum: only k-1 = 1 valid member signature (m0) against k=2.
    qn1 = json.loads(json.dumps(valid_foundation))
    qn1["statement_signatures"] = [_member_sig("m0")]
    write_foundation_fixture(
        "QN1", f_base, qn1,
        {"result_code": "REJECTED", "failed_check_ids": ["FOUNDATION_SIGNATURE_VALID"]},
        "# QN1 — Insufficient Quorum (k-1 signatures)\n\n"
        "Only 1 valid member signature is present against a k=2 bootstrap entry.\n"
        "Fewer than quorum.k distinct members verify → the statement is not\n"
        "self-anchored.\n"
        "Expected: REJECTED (FOUNDATION_SIGNATURE_VALID)")
    print("  QN1 generated")

    # QN2 — non-member signature: m0 (valid) + a signature from a key that is NOT a
    # member, tagged with a bogus signer_member_kid. The non-member never counts →
    # only 1 distinct member → < k.
    _nm_p256_priv, _nm_p256_pub, _nm_p256_pub_b64 = primitives.deterministic_p256("QN2-nonmember-p256")
    _nm_mldsa_pk, _nm_mldsa_sk = deterministic_ml_dsa65("QN2-nonmember-mldsa")
    qn2 = json.loads(json.dumps(valid_foundation))
    qn2["statement_signatures"] = [
        _member_sig("m0"),
        {"signer_member_kid": "not-a-member",
         "signature": composite_sign_with(_qn_payload_digest, _nm_p256_priv, _nm_mldsa_sk)},
    ]
    write_foundation_fixture(
        "QN2", f_base, qn2,
        {"result_code": "REJECTED", "failed_check_ids": ["FOUNDATION_SIGNATURE_VALID"]},
        "# QN2 — Non-Member Signature Does Not Count\n\n"
        "Two signatures, but the second is from a key that is not a member of the\n"
        "bootstrap entry (signer_member_kid 'not-a-member'). A non-member signature\n"
        "never contributes to the quorum, so only 1 distinct member verifies < k=2.\n"
        "Expected: REJECTED (FOUNDATION_SIGNATURE_VALID)")
    print("  QN2 generated")

    # QN3 — duplicate member counts once: m0 signs twice (two distinct objects, same
    # member). Anti-stuffing: duplicate signer_member_kid counts as ONE distinct
    # member → 1 < k=2.
    qn3 = json.loads(json.dumps(valid_foundation))
    qn3["statement_signatures"] = [_member_sig("m0"), _member_sig("m0")]
    write_foundation_fixture(
        "QN3", f_base, qn3,
        {"result_code": "REJECTED", "failed_check_ids": ["FOUNDATION_SIGNATURE_VALID"]},
        "# QN3 — Duplicate Member Signature Counts Once (Anti-Stuffing)\n\n"
        "Member m0 signs twice. Duplicate signer_member_kid values count as one\n"
        "distinct member, so the quorum reaches only 1 < k=2.\n"
        "Expected: REJECTED (FOUNDATION_SIGNATURE_VALID)")
    print("  QN3 generated")

    # === SUCCESSOR-BINDING OBSERVATIONS (system-manifest/1 §9, §12.3, §12.5) ===
    # A successor-binding observation is the §9 payload plus the predecessor
    # quorum's `predecessor_signatures` over it. The foundation file carries them
    # in `successor_binding_observations`, OUTSIDE the signed statement payload:
    # an observation's only authority is >= k distinct members of the predecessor
    # entry (here the embedded bootstrap entry, k=2 of n=3) each composite-signing
    # M'(SHA3-256(UTF-8(JCS(payload)))). A verifier authenticates every observation
    # before comparing it; one that does not reach the quorum is rejected
    # (FOUNDATION_SUCCESSOR_QUORUM_VALID), and two authenticated observations that
    # disagree over one index tuple are equivocation.
    rot_pred = build_bootstrap_manifest()
    rot_pred_fp = digest_hex_bytes(jcs_canonicalize_bytes(rot_pred))

    def _successor_binding(succ_kid, succ_label, succ_valid_from):
        """The §9 payload for a 2-of-2 successor quorum (members s0, s1) derived
        from fixed labels, authorized against the bootstrap entry."""
        succ_members = []
        for i in range(2):
            _pp, ppub, _msk, mpub = _deterministic_composite_member(f"{succ_label}:s{i}")
            succ_members.append({
                "member_kid": f"s{i}",
                "public_key_p256_b64": ppub,
                "public_key_mldsa_b64": mpub,
            })
        return {
            "binding_profile": "system-manifest/1:successor-binding",
            "system_id": rot_pred["system_id"],
            "predecessor_kid": rot_pred["entries"][-1]["kid"],
            "predecessor_manifest_fingerprint": rot_pred_fp,
            "predecessor_manifest_sequence": rot_pred["manifest_sequence"],
            "successor_kid": succ_kid,
            "successor_algorithm": PROFILE_P256_MLDSA65,
            "successor_quorum": {"k": 2, "n": 2},
            "successor_members": succ_members,
            "successor_valid_from": succ_valid_from,
        }

    def _binding_digest(binding):
        return digest_hex_bytes(jcs_canonicalize_bytes(binding))

    def _pred_sig(binding, member_kid):
        """{signer_member_kid, signature}: bootstrap member `member_kid` signs the binding."""
        return {
            "signer_member_kid": member_kid,
            "signature": composite_sign_member(_binding_digest(binding), member_kid),
        }

    def _observation(binding, pred_sigs):
        return {"successor_binding": binding, "predecessor_signatures": pred_sigs}

    def _with_observations(observations):
        fnd = json.loads(json.dumps(valid_foundation))
        fnd["successor_binding_observations"] = observations
        return fnd

    # One honest rotation, reused by P009 and the quorum negatives QN5-QN8: each
    # negative changes ONLY predecessor_signatures, so the binding is identical
    # and the quorum is the single variable.
    rot_binding = _successor_binding("conformance-root-2", "ROT-succ", "2027-01-01T00:00:00Z")

    # P009 — valid rotation: m0 and m1 (k=2 of n=3) sign the successor binding.
    p009 = clone_fixture(f_base)
    p009["foundation"] = _with_observations([
        _observation(rot_binding, [_pred_sig(rot_binding, "m0"), _pred_sig(rot_binding, "m1")]),
    ])
    write_zero_data_fixture(
        conformance_dir, "P009", p009,
        "# P009 — Successor Binding Authorized by the Predecessor Quorum\n\n"
        "The foundation is accompanied by one successor-binding observation: a\n"
        "system-manifest/1 §9 payload naming the bootstrap entry as predecessor and a\n"
        "2-of-2 successor quorum, signed by bootstrap members m0 and m1 (k=2 of n=3).\n"
        "Both composite signatures verify over SHA3-256(UTF-8(JCS(payload))), so the\n"
        "rotation is authorized (§12.3) and the observation is accepted.\n"
        "Expected: INDEPENDENT_VALID",
    )
    print("  P009 generated")

    # QN4 — equivocation: the bootstrap quorum authorizes TWO distinct successor
    # bindings over the same predecessor index tuple. Both observations are
    # authenticated (m0+m1 sign each), so the conflict is evidence, not noise.
    qn4_binding_a = _successor_binding("conformance-root-2a", "QN4-succ-A", "2027-01-01T00:00:00Z")
    qn4_binding_b = _successor_binding("conformance-root-2b", "QN4-succ-B", "2027-02-01T00:00:00Z")
    qn4 = _with_observations([
        _observation(qn4_binding_a, [_pred_sig(qn4_binding_a, "m0"), _pred_sig(qn4_binding_a, "m1")]),
        _observation(qn4_binding_b, [_pred_sig(qn4_binding_b, "m0"), _pred_sig(qn4_binding_b, "m1")]),
    ])
    write_foundation_fixture(
        "QN4", f_base, qn4,
        {"result_code": "REJECTED", "failed_check_ids": ["FOUNDATION_EQUIVOCATION_DETECTED"]},
        "# QN4 — Equivocation: Two Successor Sets Over One Predecessor State\n\n"
        "The bootstrap quorum authorizes TWO distinct successor-bindings sharing the\n"
        "same (system_id, predecessor_manifest_fingerprint, predecessor_manifest_\n"
        "sequence, predecessor_kid) but differing in successor_kid/members/valid_from.\n"
        "Each observation carries a verifying predecessor quorum (m0, m1), so both\n"
        "are authenticated. Under system-manifest/1 §12.5 this is equivocation: the\n"
        "implicated manifest versions are terminally invalid.\n"
        "Expected: REJECTED (FOUNDATION_EQUIVOCATION_DETECTED)")
    print("  QN4 generated")

    # QN5 — quorum not met: only m0 signs (k-1 = 1 of k = 2).
    write_foundation_fixture(
        "QN5", f_base,
        _with_observations([_observation(rot_binding, [_pred_sig(rot_binding, "m0")])]),
        {"result_code": "REJECTED", "failed_check_ids": ["FOUNDATION_SUCCESSOR_QUORUM_VALID"]},
        "# QN5 — Successor Binding Below the Predecessor Quorum (k-1)\n\n"
        "Only bootstrap member m0 signs the successor binding; the bootstrap entry\n"
        "requires k=2 distinct members (system-manifest/1 §12.3).\n"
        "Expected: REJECTED (FOUNDATION_SUCCESSOR_QUORUM_VALID)")
    print("  QN5 generated")

    # QN6 — non-member: m0 plus a valid composite signature by a key that is not
    # a member of the bootstrap entry. The non-member never counts → 1 < k.
    _rnm_p256_priv, _rnm_p256_pub, _rnm_p256_pub_b64 = primitives.deterministic_p256("QN6-nonmember-p256")
    _rnm_mldsa_pk, _rnm_mldsa_sk = deterministic_ml_dsa65("QN6-nonmember-mldsa")
    write_foundation_fixture(
        "QN6", f_base,
        _with_observations([_observation(rot_binding, [
            _pred_sig(rot_binding, "m0"),
            {"signer_member_kid": "not-a-member",
             "signature": composite_sign_with(_binding_digest(rot_binding), _rnm_p256_priv, _rnm_mldsa_sk)},
        ])]),
        {"result_code": "REJECTED", "failed_check_ids": ["FOUNDATION_SUCCESSOR_QUORUM_VALID"]},
        "# QN6 — Successor Binding Signed by a Non-Member\n\n"
        "m0 signs, and a second signature verifies under a key that is not a member of\n"
        "the bootstrap entry (signer_member_kid 'not-a-member'). A non-member never\n"
        "counts toward the quorum, so only 1 distinct member verifies < k=2.\n"
        "Expected: REJECTED (FOUNDATION_SUCCESSOR_QUORUM_VALID)")
    print("  QN6 generated")

    # QN7 — tampered signature: m0 valid; m1's ML-DSA-65 component corrupted.
    # The composite is AND, so m1 does not verify → 1 < k.
    qn7_m1 = _pred_sig(rot_binding, "m1")
    _qn7_comp = next(c for c in qn7_m1["signature"]["signatures"] if c["alg"] == ALG_MLDSA65)
    _qn7_bytes = bytearray(base64.b64decode(_qn7_comp["sig_b64"]))
    _qn7_bytes[0] = _qn7_bytes[0] ^ 0xFF
    _qn7_comp["sig_b64"] = base64.b64encode(bytes(_qn7_bytes)).decode("ascii")
    write_foundation_fixture(
        "QN7", f_base,
        _with_observations([_observation(rot_binding, [_pred_sig(rot_binding, "m0"), qn7_m1])]),
        {"result_code": "REJECTED", "failed_check_ids": ["FOUNDATION_SUCCESSOR_QUORUM_VALID"]},
        "# QN7 — Successor Binding With a Tampered Member Signature\n\n"
        "m0's signature verifies; m1's ML-DSA-65 component is corrupted. The composite\n"
        "verifies AND over both components, so m1 does not count and only 1 distinct\n"
        "member verifies < k=2.\n"
        "Expected: REJECTED (FOUNDATION_SUCCESSOR_QUORUM_VALID)")
    print("  QN7 generated")

    # QN8 — duplicate signer: m0 signs twice (two valid signatures). A repeated
    # signer_member_kid counts once → 1 < k.
    write_foundation_fixture(
        "QN8", f_base,
        _with_observations([_observation(rot_binding, [_pred_sig(rot_binding, "m0"), _pred_sig(rot_binding, "m0")])]),
        {"result_code": "REJECTED", "failed_check_ids": ["FOUNDATION_SUCCESSOR_QUORUM_VALID"]},
        "# QN8 — Duplicate Signer Counted Once\n\n"
        "Bootstrap member m0 signs the successor binding twice. Duplicate\n"
        "signer_member_kid values count as one distinct member (system-manifest/1\n"
        "§12.3), so the quorum reaches only 1 < k=2.\n"
        "Expected: REJECTED (FOUNDATION_SUCCESSOR_QUORUM_VALID)")
    print("  QN8 generated")

    # === SIGNATURE AUTHENTICITY FIXTURES ===

    print("\nGenerating signature authenticity fixtures...\n")

    # S-series — SIGNATURE AUTHENTICITY (composite P-256 + ML-DSA-65). On the hybrid (leaf=subtree)
    # model like every other fixture: the authenticity break is the ONLY variable.
    # S002–S005 mutate the certificate's signature/public-key via build_zero_data_
    # fixture's cert_mutator hook, which runs BEFORE the ccd is computed and the
    # capacity evidence is signed — so the mutated cert is the one the binding and
    # the evidence anchor. The only failing check is BASE_CERTIFICATE_AUTHENTIC;
    # the binding and capacity-evidence stay valid.

    # Composite (`composite-signature/1`): the issuer signature is AND over both components. Breaking
    # EITHER component must fail BASE_CERTIFICATE_AUTHENTIC. S002–S005 each break a
    # different facet so the suite exercises both halves of the composite.

    def _mldsa_comp(cert):
        return next(c for c in cert["signatures"][0]["signatures"] if c["alg"] == ALG_MLDSA65)

    def _p256_comp(cert):
        return next(c for c in cert["signatures"][0]["signatures"] if c["alg"] == ALG_ECDSA_P256)

    def break_sig_bytes(cert):
        # Corrupt the ML-DSA-65 component bytes (the post-quantum half).
        comp = _mldsa_comp(cert)
        sig_bytes = bytearray(base64.b64decode(comp["sig_b64"]))
        sig_bytes[0] = sig_bytes[0] ^ 0xFF
        comp["sig_b64"] = base64.b64encode(bytes(sig_bytes)).decode("ascii")

    def break_sig_b64(cert):
        # Malformed P-256 component encoding (the classical half).
        _p256_comp(cert)["sig_b64"] = "not!valid!base64!!!"

    def break_pub_b64(cert):
        # Malformed ML-DSA-65 component public key encoding.
        cert["signatures"][0]["signer"]["pub_mldsa_b64"] = "also!not!base64!!!"

    def break_wrong_key(cert):
        # Valid P-256 component signature, but declared against a DIFFERENT P-256
        # public key → the classical half fails, so the composite fails.
        cert["signatures"][0]["signer"]["pub_p256_b64"] = primitives.deterministic_p256("S005-wrong-key")[2]

    # A node id has the shape `op:` + 22 base64 characters (§10.15).
    P010_NODE_ID = "op:Q29uZm9ybWFuY2VOb2RlMQ"

    def base_params(fixture_id, cap_ref):
        return {
            "fixtureId": fixture_id, "batchId": f"batch-{fixture_id}",
            "windowId": f"window-{fixture_id}", "trxId": f"trx-{fixture_id}",
            "leafIndex": 0, "batchSize": 1,
            "consumedQuantity": "1.00", "totalQuantity": "1.00",
            "blockNum": 5000, "libNum": 5010,
            "issuerScope": "issuer:auth-test", "capacityAuthRef": cap_ref,
        }

    # S001 — valid composite base certificate authenticity.
    a001 = build_zero_data_fixture(base_params("S001", "cap-auth-S001"))
    write_zero_data_fixture(
        conformance_dir, "S001", a001,
        "# S001 — Valid Base Certificate Authenticity\n\n"
        "The issuer's composite signature (P-256 + ML-DSA-65, AND) over the payload\n"
        "is real, on the hybrid leaf=subtree model. Tests that\n"
        "BASE_CERTIFICATE_AUTHENTIC passes: both components verify.\n"
        "Expected: INDEPENDENT_VALID",
    )
    print("  S001 generated")

    # S002 — corrupted ML-DSA-65 component bytes.
    fp = build_zero_data_fixture(base_params("S002", "cap-auth-S002"), cert_mutator=break_sig_bytes)
    write_negative_zero_data(
        adversarial_dir, "S002", fp,
        {"result_code": "ISSUED_INVALID", "failed_check_ids": ["BASE_CERTIFICATE_AUTHENTIC"]},
        "# S002 — Invalid Signature Component\n\n"
        "The ML-DSA-65 component's bytes are corrupted, so the composite (AND) must\n"
        "fail. The cert is mutated before the ccd is computed, so the only failing\n"
        "check is authenticity.\n"
        "Expected: ISSUED_INVALID (BASE_CERTIFICATE_AUTHENTIC)",
    )
    print("  S002 generated")

    # S003 — signature not valid base64.
    fp = build_zero_data_fixture(base_params("S003", "cap-auth-S003"), cert_mutator=break_sig_b64)
    write_negative_zero_data(
        adversarial_dir, "S003", fp,
        {"result_code": "REJECTED", "failed_check_ids": ["BASE_CERTIFICATE_AUTHENTIC"]},
        "# S003 — Malformed Signature Encoding\n\n"
        "Signature is not valid RFC 4648 base64.\n"
        "Expected: REJECTED (BASE_CERTIFICATE_AUTHENTIC)",
    )
    print("  S003 generated")

    # S004 — public key not valid base64.
    fp = build_zero_data_fixture(base_params("S004", "cap-auth-S004"), cert_mutator=break_pub_b64)
    write_negative_zero_data(
        adversarial_dir, "S004", fp,
        {"result_code": "REJECTED", "failed_check_ids": ["BASE_CERTIFICATE_AUTHENTIC"]},
        "# S004 — Malformed Public Key Encoding\n\n"
        "Public key is not valid RFC 4648 base64.\n"
        "Expected: REJECTED (BASE_CERTIFICATE_AUTHENTIC)",
    )
    print("  S004 generated")

    # S005 — valid signature, wrong declared public key.
    fp = build_zero_data_fixture(base_params("S005", "cap-auth-S005"), cert_mutator=break_wrong_key)
    write_negative_zero_data(
        adversarial_dir, "S005", fp,
        {"result_code": "ISSUED_INVALID", "failed_check_ids": ["BASE_CERTIFICATE_AUTHENTIC"]},
        "# S005 — Wrong Public Key For Valid Signature\n\n"
        "The P-256 component was signed by a different key than the declared\n"
        "pub_p256_b64, so the composite (AND) must fail.\n"
        "Expected: ISSUED_INVALID (BASE_CERTIFICATE_AUTHENTIC)",
    )
    print("  S005 generated")

    # S006 — POSITIVE: the Proof of Independence carries its composite signature
    # (P-256 + ML-DSA-65, AND) by the system-domain Level-1 capacity key, and the
    # verifier verifies it (PROOF_SIGNATURE_VALID). Every proof in the suite is
    # signed the same way; S006 is the fixture whose README states it.
    a006 = build_zero_data_fixture(base_params("S006", "cap-auth-S006"))
    write_zero_data_fixture(
        conformance_dir, "S006", a006,
        "# S006 — Proof of Independence Composite Signature\n\n"
        "A valid Independent whose Proof of Independence carries a composite signature\n"
        "(P-256 + ML-DSA-65, AND) by the system-domain Level-1 capacity key published in\n"
        "the foundation (system_domain_capacity_key_p256_b64 / _mldsa_b64). The signature\n"
        "covers the signed view of independence.proof/1 §10.13.1 and is mandatory:\n"
        "PROOF_SIGNATURE_VALID runs the composite verification over that view. All checks\n"
        "pass. production_verification is not asserted: the conformance domain is\n"
        "synthetic.",
    )
    print("  S006 generated")

    # P010 — POSITIVE: the proof carries a node attestation (independence.proof/1
    # §10.15) inside its signed view. The verifier authenticates it through the
    # proof signature and exposes the attested node in its result.
    p010 = build_zero_data_fixture(base_params("P010", "cap-auth-P010"))
    p010["proof"]["node_attestation"] = {
        "node_id": P010_NODE_ID,
        "recognized_at": "2026-04-11T12:00:00Z",
    }
    seal_proof(p010["proof"])
    write_zero_data_fixture(
        conformance_dir, "P010", p010,
        "# P010 — Proof With a Node Attestation\n\n"
        "The Proof of Independence carries `node_attestation` (independence.proof/1\n"
        "§10.15): the recognized node that carried the submission and the instant its\n"
        "recognition was checked. The attestation sits inside the signed view, so the\n"
        "proof signature authenticates it; no registry is consulted. The verifier\n"
        "returns INDEPENDENT_VALID and reports the attested node in `attested_node`.",
        expected_extra={
            "attested_node": {"node_id": P010_NODE_ID, "recognized_at": "2026-04-11T12:00:00Z"},
        },
    )
    print("  P010 generated")

    # S007 — the node attestation is altered after signing (another node id). The
    # signed view changed, so the signature no longer verifies.
    v = clone_fixture(p010)
    v["proof"]["node_attestation"]["node_id"] = "op:QW5vdGhlck5vZGVJZDAwMD"
    v["proof"]["proof_digest"] = compute_proof_digest(v["proof"])
    write_negative_zero_data(
        adversarial_dir, "S007", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["PROOF_SIGNATURE_VALID"],
         "attested_node": None},
        "# S007 — Altered Node Attestation\n\n"
        "P010 with `node_attestation.node_id` replaced after the proof was signed\n"
        "(`proof_digest` recomputed, signature left as it was). The attestation is part\n"
        "of the signed view, so the composite signature fails and no node is reported.\n"
        "Expected: INDEPENDENT_INVALID (PROOF_SIGNATURE_VALID)",
    )
    print("  S007 generated")

    # S008 — the proof carries no signature. The signature is mandatory under
    # independence.proof/1 §10.13, whatever the rules domain.
    v = clone_fixture(p001)
    del v["proof"]["signature"]
    v["proof"]["proof_digest"] = compute_proof_digest(v["proof"])
    write_negative_zero_data(
        adversarial_dir, "S008", v,
        {"result_code": "INCOMPLETE", "failed_check_ids": ["PROOF_SIGNATURE_VALID"]},
        "# S008 — Unsigned Proof of Independence\n\n"
        "P001 with the proof's `signature` removed (`proof_digest` recomputed). The\n"
        "signature is mandatory (independence.proof/1 §10.13): without it the signed\n"
        "fields carry no authenticity, so the verifier cannot reach Independent.\n"
        "Expected: INCOMPLETE (PROOF_SIGNATURE_VALID)",
    )
    print("  S008 generated")

    # S009–S011 — the proof signature verifies cryptographically in each, but its
    # layout is not the profile's: composite-signature/1 §6 step 3 and §8 make
    # that a structural defect, reported as such.
    def _proof_layout_fixture(fixture_id, mutate, title, body):
        v = clone_fixture(p001)
        mutate(v["proof"]["signature"])
        v["proof"]["proof_digest"] = compute_proof_digest(v["proof"])
        write_negative_zero_data(
            adversarial_dir, fixture_id, v,
            {"result_code": "REJECTED", "failed_check_ids": ["PROOF_SIGNATURE_VALID"]},
            f"# {fixture_id} — {title}\n\n{body}\nExpected: REJECTED (PROOF_SIGNATURE_VALID)",
        )
        print(f"  {fixture_id} generated")

    _proof_layout_fixture("S009", lambda sig: sig["signatures"].reverse(),
        "Proof Signature Components Reordered",
        "The two components are present and each verifies over M', but the ML-DSA-65\n"
        "component comes first. The order is normative: classical first, PQC second\n"
        "(composite-signature/1 §7, §8).")
    _proof_layout_fixture("S010", lambda sig: sig["signatures"][0].update({"low_s": False}),
        "ECDSA Component Declares low_s false",
        "The ECDSA component is a valid low-s signature but declares low_s: false. The\n"
        "field's value is fixed to true (composite-signature/1 §9.1).")
    _proof_layout_fixture("S011", lambda sig: sig.update({"note": "not a member"}),
        "Proof Signature Object With an Extra Member",
        "The proof signature object carries a member beyond signing_kid, alg, mode and\n"
        "signatures (independence.proof/1 §10.13, composite-signature/1 §8).")

    # P007 — COLLECTION SUBJECT end-to-end (§8.5 original-material plane). A valid
    # Independent whose base certificate carries a `subject.collection/1` subject, with
    # the ordered leaf materials DELIVERED so the verifier runs
    # ORIGINAL_MATERIAL_COMPARISON_VALID: it recomputes each leaf under its own declared profile,
    # reconstructs the collection root under `collection.merkle-sha3-256/1`, requires it
    # to equal the committed root AND the participating-leaf count to equal
    # declared_cardinality (volume-fairness check, verifier-toolkit/1 §8.5.3/§17),
    # then recomputes the subject commitment (CCCP/1) and matches the certificate's
    # commitment_digest_hex. The collection_object + leaf materials are the canonical primitive vector values
    # (original-material/vectors.json), reproduced deterministically here.
    P007_LEAF_MATERIALS = ["record-1", "record-2", "record-3"]
    P007_LEAF_PROFILE = "subject.binary/1"
    # Compute the collection root under collection.merkle-sha3-256/1 from the leaf
    # materials rather than hardcoding it — the same scheme the verifier uses and
    # the original-material/collection-merkle primitives pin; deriving it keeps
    # this fixture in lock-step with the primitive.
    def _p007_collection_object(nonce_hex: str) -> dict:
        """The collection object for a given certificate.

        Built per certificate, not once: under `subject.collection/1` §8 the leaf
        preimage is salted with the anchor `nonce_hex`, so the root is
        nonce-dependent. A module-level constant would pin one certificate's root
        onto every fixture.
        """
        salt = nonce_hex.encode("ascii")
        leaf_hashes = [
            primitives.collection_leaf_hash(salt, P007_LEAF_PROFILE, m.encode("utf-8"))
            for m in P007_LEAF_MATERIALS
        ]
        return {
            "commitment_scheme": "collection.merkle-sha3-256/1",
            "root": primitives.collection_merkle_root(leaf_hashes),
            "declared_cardinality": str(len(P007_LEAF_MATERIALS)),
            # Each leaf declares its OWN profile and commitment (subject.collection/1
            # §7.4). Homogeneous here, but the shape is the heterogeneous one: there is
            # no abbreviated form, so implementations have a single code path.
            "leaves": [
                {"profile": P007_LEAF_PROFILE, "commitment_digest_hex": h}
                for h in leaf_hashes
            ],
        }

    # Filled by _inject_collection_subject once the certificate's nonce exists; the
    # material manifest is written afterwards (write_original_material), so it sees
    # the same object the certificate committed to.
    _p007_material_entry: dict = {"leaf_materials_utf8": P007_LEAF_MATERIALS}

    def _inject_collection_subject(cert: dict) -> None:
        # Replace the single binary subject with a collection subject whose
        # commitment_digest_hex = CCCP/1 over THIS cert's nonce: SHA3(nonce ||
        # SHA3(JCS(collection_object))). Then refresh the anchor commitment,
        # payload digest, and re-sign (the emission stays valid — only the subject
        # profile changed). subject_local_digest is nonce-independent (matches the
        # primitive vector's b728db…); the final commitment binds this cert's nonce.
        nonce = cert["payload"]["anchor"]["nonce_hex"]
        collection_object = _p007_collection_object(nonce)
        _p007_material_entry["collection_object"] = collection_object
        subject_local_digest = digest_hex_bytes(jcs_canonicalize_bytes(collection_object))
        commitment = digest_hex_text(nonce + subject_local_digest)
        cert["payload"]["anchor"]["subjects"] = [
            {
                "profile": "subject.collection/1",
                "commitment_digest_hex": commitment,
                # The collection object travels in the subject so the verifier resolves
                # scheme/root/cardinality/leaves (verifier-toolkit/1 §8.5.2).
                "collection": collection_object,
            }
        ]
        refresh_certificate_payload(cert)
        recompose_cert_signature(cert)

    # declared_effective_units="3": the single subject is a subject.collection/1
    # with declared_cardinality 3, so its effective declared units are 3
    # (capacity.commitment/1 §13.1). Original material is delivered, so the
    # verifier resolves the cardinality and enforces the exact equality
    # (EFFECTIVE_UNITS_BINDING_VALID): Σ = 3 == declared 3.
    p007 = build_zero_data_fixture(
        base_params("P007", "cap-auth-P007"),
        cert_mutator=_inject_collection_subject,
        declared_effective_units="3",
    )
    write_zero_data_fixture(
        conformance_dir, "P007", p007,
        "# P007 — Collection Subject, Verified Against Delivered Material\n\n"
        "A valid Independent whose base certificate carries a subject.collection/1 subject.\n"
        "The ordered leaf materials (record-1..3) are delivered, so the verifier runs\n"
        "ORIGINAL_MATERIAL_COMPARISON_VALID: recompute each leaf under subject.binary/1,\n"
        "rebuild the root under collection.merkle-sha3-256/1, require root == committed root\n"
        "AND participating-leaf count == declared_cardinality (3), then match the CCCP/1\n"
        "subject commitment. Drives a collection subject through the full pipeline.\n"
        "Also exercises EFFECTIVE_UNITS_BINDING_VALID with a collection: declared_effective_units\n"
        "is \"3\" and the resolved declared_cardinality is 3, so the exact per-subject sum (3)\n"
        "equals the declared units (capacity.commitment/1 §13.1.1).\n"
        "All checks pass.",
        original_material=[_p007_material_entry],
        expected_extra={
            # Assert the complete-verification-against-material plane actually RAN and
            # matched — guards against a verifier that silently ignores the material.
            "complete_verification_against_original_material_performed": True,
            "complete_verification_against_original_material_passed": True,
            # A declared collection is not opaque: its elements are covered at the
            # declared resolution, unlike P001's single opaque subject.
            "subject_scope": [{"profile": "subject.collection/1", "opaque": False}],
        },
    )
    print("  P007 generated")

    # --- Collection / original-material NEGATIVES (§8.5 comparison plane) ---
    # A reusable mutator that injects a collection subject bound to THIS cert's nonce
    # for a given collection_object (CCCP/1 commitment over SHA3(JCS(collection_object))).
    def _collection_mutator(collection_object, leaf_materials=None):
        """Inject a collection subject.

        When `leaf_materials` is given, `root` is recomputed from them under THIS
        certificate's nonce (subject.collection/1 §8) — the honest baseline an
        adversarial fixture then lies about elsewhere. When it is omitted, the
        caller's `root` is used verbatim, which is what a root-lying fixture wants.
        """
        def mut(cert):
            nonce = cert["payload"]["anchor"]["nonce_hex"]
            obj = dict(collection_object)
            if leaf_materials is not None:
                salt = nonce.encode("ascii")
                # `_leaf_profile` is the caller's build hint, not a descriptor field:
                # under subject.collection/1 §7.4 the profile lives per leaf.
                profile = obj.pop("_leaf_profile")
                lh = [primitives.collection_leaf_hash(salt, profile, m.encode("utf-8"))
                      for m in leaf_materials]
                obj["root"] = primitives.collection_merkle_root(lh)
                obj["leaves"] = [
                    {"profile": profile, "commitment_digest_hex": h} for h in lh
                ]
            collection_object.clear(); collection_object.update(obj)
            sld = digest_hex_bytes(jcs_canonicalize_bytes(collection_object))
            cert["payload"]["anchor"]["subjects"] = [{
                "profile": "subject.collection/1",
                "commitment_digest_hex": digest_hex_text(nonce + sld),
                "collection": collection_object,
            }]
            refresh_certificate_payload(cert)
            recompose_cert_signature(cert)
        return mut

    # V038 — CARDINALITY LIE: declared_cardinality=5 but only 3 leaves participate.
    # The collection object (committed in the cert) and the delivered material AGREE on
    # the object, so the CCCP commitment matches and the emission is valid — but the
    # verifier counts 3 participating leaves != declared 5 and fails closed. This is the
    # executable form of the volume-fairness check (verifier-toolkit/1 §8.5.3).
    col_lie = {
        "commitment_scheme": "collection.merkle-sha3-256/1",
        "root": "9ff3b3569348505ecc50cef582143ddc59be60a59696b16e25e25dc1965d6a37",
        "declared_cardinality": "5",  # lies: only 3 leaves are delivered/participate
        "_leaf_profile": "subject.binary/1",
    }
    v = build_zero_data_fixture(base_params("V038", "cap-auth-V038"),
                                cert_mutator=_collection_mutator(col_lie, P007_LEAF_MATERIALS),
                                declared_effective_units="5")
    write_negative_zero_data(
        adversarial_dir, "V038", v,
        {"result_code": "REJECTED", "failed_check_ids": ["ORIGINAL_MATERIAL_COMPARISON_VALID"]},
        "# V038 — Collection Cardinality Lie\n\n"
        "declared_cardinality is 5 but only 3 leaf materials participate in the root.\n"
        "The committed collection object and the delivered material agree (so the CCCP\n"
        "commitment matches and emission is valid); the volume-fairness count is the break.\n"
        "Expected: REJECTED (ORIGINAL_MATERIAL_COMPARISON_VALID)",
        original_material=[{"leaf_materials_utf8": ["record-1", "record-2", "record-3"],
                            "collection_object": col_lie}],
    )
    print("  V038 generated")

    # V039 — MATERIAL MISMATCH: a delivered leaf is tampered, so the reconstructed root
    # != the committed root. Same collection object (commitment matches, emission valid);
    # the material simply does not reproduce the committed collection.
    col_ok = {
        "commitment_scheme": "collection.merkle-sha3-256/1",
        "root": "9ff3b3569348505ecc50cef582143ddc59be60a59696b16e25e25dc1965d6a37",
        "declared_cardinality": "3",
        "_leaf_profile": "subject.binary/1",
    }
    v = build_zero_data_fixture(base_params("V039", "cap-auth-V039"),
                                cert_mutator=_collection_mutator(col_ok, P007_LEAF_MATERIALS),
                                declared_effective_units="3")
    write_negative_zero_data(
        adversarial_dir, "V039", v,
        {"result_code": "ISSUED_INVALID", "failed_check_ids": ["ORIGINAL_MATERIAL_COMPARISON_VALID"]},
        "# V039 — Collection Material Does Not Reproduce the Committed Root\n\n"
        "One delivered leaf is tampered (record-3 → record-TAMPERED), so the reconstructed\n"
        "collection.merkle-sha3-256/1 root differs from the committed root. The subject\n"
        "commitment still matches (same collection object), so the break is the material\n"
        "comparison, not the emission binding. The comparison belongs to the Issued\n"
        "route (verifier-toolkit/1 §11.1 step 3), so the code is ISSUED_INVALID; the\n"
        "independence axis is evaluated separately and is not what failed.\n"
        "Expected: ISSUED_INVALID (ORIGINAL_MATERIAL_COMPARISON_VALID)",
        original_material=[{"leaf_materials_utf8": ["record-1", "record-2", "record-TAMPERED"],
                            "collection_object": col_ok}],
    )
    print("  V039 generated")

    # V040 — non-admitted leaf profile inside a collection: a leaf declares a subject
    # profile the rules domain does not admit. The rules domain binds every leaf
    # profile, so the certificate is non-conformant and the material plane fails
    # closed (REJECTED) before any leaf is canonicalized — it is not reported as a
    # merely unsupported profile.
    col_badprofile = {
        "commitment_scheme": "collection.merkle-sha3-256/1",
        # root and leaf commitments are arbitrary — the run fails on the leaf
        # profile check, before any leaf is canonicalized or the root compared.
        "root": "9ff3b3569348505ecc50cef582143ddc59be60a59696b16e25e25dc1965d6a37",
        "declared_cardinality": "3",
        "leaves": [
            {"profile": "subject.unsupported/99", "commitment_digest_hex": f"{i:064x}"}
            for i in range(3)
        ],
    }
    v = build_zero_data_fixture(base_params("V040", "cap-auth-V040"),
                                cert_mutator=_collection_mutator(col_badprofile),
                                declared_effective_units="3")
    write_negative_zero_data(
        adversarial_dir, "V040", v,
        {"result_code": "REJECTED", "failed_check_ids": ["ORIGINAL_MATERIAL_COMPARISON_VALID"]},
        "# V040 — Collection Leaf Profile Not Admitted\n\n"
        "A collection leaf declares subject.unsupported/99, a subject profile the\n"
        "rules domain does not admit. The admitted set binds every leaf of a\n"
        "collection, so the certificate is non-conformant: the material plane fails\n"
        "closed before any leaf is canonicalized, rather than reporting the profile\n"
        "as merely unsupported.\n"
        "Expected: REJECTED (ORIGINAL_MATERIAL_COMPARISON_VALID)",
        original_material=[{"leaf_materials_utf8": ["record-1", "record-2", "record-3"],
                            "collection_object": col_badprofile}],
    )
    print("  V040 generated")

    # --- Effective-units binding ---
    # capacity.commitment/1 §13.1/§13.1.1 requires declared_effective_units to
    # EQUAL the sum of per-subject effective units over the certified subjects
    # (non-collection → 1). The verifier is the only actor holding both the
    # subjects (base-cert anchor) and the declared units (capacity evidence), so
    # it enforces the equality under EFFECTIVE_UNITS_BINDING_VALID.
    def _three_binary_subjects():
        # Three distinct, well-formed non-collection subjects. Each contributes
        # exactly 1 effective declared unit (§13.1); Σ = 3.
        return [
            {
                "profile": "subject.binary/1",
                "commitment_digest_hex": digest_hex_text(f"subject:multi:{i}"),
            }
            for i in range(3)
        ]

    # P008 — VALID multi-subject: 3 subjects, declared_effective_units="3". The
    # recomputed Σ per-subject units (3) equals the declared value → the binding
    # holds and EFFECTIVE_UNITS_BINDING_VALID passes. No original material is
    # needed: non-collection subjects are exactly computable from the anchor alone.
    p008 = build_zero_data_fixture(
        base_params("P008", "cap-auth-P008"),
        subjects=_three_binary_subjects(),
        declared_effective_units="3",
    )
    write_zero_data_fixture(
        conformance_dir, "P008", p008,
        "# P008 — Multi-Subject, Truthfully Declared Effective Units\n\n"
        "The base certificate anchors THREE subject.binary/1 subjects and the capacity\n"
        "evidence declares declared_effective_units=\"3\". The verifier recomputes the sum\n"
        "of per-subject effective units (each non-collection subject contributes 1;\n"
        "capacity.commitment/1 §13.1) and requires it to equal the declared value. 3 == 3,\n"
        "so EFFECTIVE_UNITS_BINDING_VALID passes: a truthful multi-subject declaration\n"
        "verifies.\n"
        "All checks pass.",
    )
    print("  P008 generated")

    # V041 — effective-units under-declaration: 3 subjects but
    # declared_effective_units="1". Everything is cryptographically well-formed —
    # the cert is authentic, the emission binding holds, the leaf's
    # cost_commitment binds "1" coherently — yet the declared units understate the
    # 3 certified subjects. Σ per-subject units = 3 != 1, so the verifier fails
    # closed (capacity.commitment/1 §13.1.1).
    v041 = build_zero_data_fixture(
        base_params("V041", "cap-auth-V041"),
        subjects=_three_binary_subjects(),
        declared_effective_units="1",
    )
    write_negative_zero_data(
        adversarial_dir, "V041", v041,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["EFFECTIVE_UNITS_BINDING_VALID"]},
        "# V041 — Effective-Units Under-Declaration\n\n"
        "The base certificate anchors THREE subject.binary/1 subjects, but the capacity\n"
        "evidence declares declared_effective_units=\"1\" — one unit declared for three\n"
        "certified subjects. The certificate is cryptographically valid and the emission\n"
        "binding holds; the break is purely the effective-units equality. The verifier\n"
        "recomputes Σ per-subject units = 3 (capacity.commitment/1 §13.1) != declared 1\n"
        "and fails closed. Under the zero-data profile the settlement plane carries\n"
        "evidence digests, not the subjects, so the offline verifier is the only actor\n"
        "that can catch this (§13.1.1).\n"
        "Expected: INDEPENDENT_INVALID (EFFECTIVE_UNITS_BINDING_VALID)",
    )
    print("  V041 generated")

    # V042 — a rules domain the verifier declares support for but holds no corpus
    # commitment for. rules-domain/1 §13.3.1 requires a conforming verifier to
    # carry the certified corpus commitment of every rules domain it supports:
    # its parameters are compiled in and never read from the published corpus at
    # evaluation time, so the commitment is what lets a third party confirm the
    # build was made against the authentic rules text rather than an altered
    # registry entry.
    #
    # The artifacts here are entirely well-formed — every signature verifies and
    # every digest matches. What fails is the verifier's own conformance, and it
    # fails closed: absence of the commitment is not absence of constraint. That
    # is the whole point of the class, so this fixture carries a rules_version the
    # conformance profile supports while deliberately falling outside its
    # commitment map.
    v = clone_fixture(p001)
    v["proof"]["rules_version"] = "rules/conformance-uncommitted"
    v["baseCert"]["payload"]["rules_version"] = "rules/conformance-uncommitted"
    seal_proof(v["proof"])
    # The foundation is the registered one, whose published_rules_versions does
    # not list this rules version: the list is metadata (system-foundation/1 §6),
    # so the vector still reaches the check it exists to exercise.
    refresh_certificate_payload(v["baseCert"])
    recompose_cert_signature(v["baseCert"])
    write_negative_zero_data(
        adversarial_dir, "V042", v,
        {"result_code": "REJECTED", "failed_check_ids": ["RULES_CORPUS_COMMITMENT_PRESENT"]},
        "# V042 — Rules Domain Without a Corpus Commitment\n\n"
        "The rules_version resolves, but the verifier holds no certified corpus\n"
        "commitment for it, so it cannot be shown to have been built against the\n"
        "authentic rules text (rules-domain/1 §13.3.1).\n"
        "Expected: REJECTED (RULES_CORPUS_COMMITMENT_PRESENT)",
    )
    print("  V042 generated")

    # V043 — a burn smaller than the ANCHORED batch total, with every unanchored
    # copy of the total restated to match the burn. The memo commits to
    # batch_binding_preimage.total_quantity ("10.00" here, settlement.binding/1
    # §5); batch_manifest is producer-supplied material that nothing anchors. The
    # material burns "5.00" and declares "5.00" in settlement_action,
    # capacity_consumption_proof and batch_manifest, so all three agree with one
    # another. Only the anchored preimage disagrees — and it is the reference
    # (settlement.aggregated.xrpl/1 §10.1). The memo, the leaf and the inclusion
    # path are untouched, so the break is isolated to the consumption check.
    v = clone_fixture(p001)
    v["material"]["settlement_action"]["quantity"] = f"5.00 {config['xrpl_token_symbol']}"
    v["material"]["capacity_consumption_proof"]["total_quantity"] = "5.00"
    v["material"]["batch_manifest"]["total_quantity"] = "5.00"
    write_negative_zero_data(
        adversarial_dir, "V043", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["CAPACITY_BINDING_VALID"]},
        "# V043 — Burn Below the Anchored Total, Manifest Restated to Match\n\n"
        "The memo anchors batch_binding_preimage.total_quantity = 10.00. The payment\n"
        "burns 5.00, and capacity_consumption_proof.total_quantity and\n"
        "batch_manifest.total_quantity are both restated as 5.00, so every\n"
        "unanchored copy of the total agrees with the burn. The verifier compares the\n"
        "burned quantity with the anchored preimage total, not with the manifest\n"
        "(settlement.aggregated.xrpl/1 §10.1).\n"
        "Expected: INDEPENDENT_INVALID (CAPACITY_BINDING_VALID)",
    )
    print("  V043 generated")

    # V044 — burn and anchor agree; only batch_manifest's copy of the total
    # diverges. The manifest copy is accepted only when it repeats the anchored
    # value (settlement.aggregated.xrpl/1 §10.1), so a verifier that merely stops
    # consulting the manifest does not pass this vector.
    v = clone_fixture(p001)
    v["material"]["batch_manifest"]["total_quantity"] = "11.00"
    write_negative_zero_data(
        adversarial_dir, "V044", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["CAPACITY_BINDING_VALID"]},
        "# V044 — Manifest Total Diverges From the Anchored Total\n\n"
        "The payment burns 10.00 and the memo anchors 10.00, but\n"
        "batch_manifest.total_quantity declares 11.00. The material's copy of the\n"
        "total MUST equal the anchored batch_binding_preimage.total_quantity.\n"
        "Expected: INDEPENDENT_INVALID (CAPACITY_BINDING_VALID)",
    )
    print("  V044 generated")

    # V045 — settlement material without batch_manifest. The settlement-root
    # coherence is three-way — batch_manifest, batch_binding_preimage and the
    # proof's batch.root MUST match exactly (settlement.binding/1 §6;
    # independence.proof/1 §10.13.1) — so without the manifest it cannot be
    # established. The verifier must report the missing component and fail
    # closed, not dereference it. Everything else is untouched: the memo, the
    # leaf and the inclusion path verify, so the break is isolated to the
    # coherence check.
    v = clone_fixture(p001)
    del v["material"]["batch_manifest"]
    write_negative_zero_data(
        adversarial_dir, "V045", v,
        {"result_code": "INCOMPLETE", "failed_check_ids": ["AGGREGATED_INTERPRETATION_UNIQUE"]},
        "# V045 — Missing Batch Manifest\n\n"
        "batch_manifest is absent from the settlement material. The settlement_root\n"
        "coherence across batch_manifest, batch_binding_preimage and proof.batch.root\n"
        "cannot be established without it (settlement.binding/1 §6).\n"
        "Expected: INCOMPLETE (AGGREGATED_INTERPRETATION_UNIQUE)",
    )
    print("  V045 generated")

    # V046 — the batch_manifest restates a different leaf_count. The anchor binds
    # the batch's size only through batch_binding_preimage.leaf_count (2 here,
    # settlement.binding/1 §5); the manifest copy is accepted only when it repeats
    # the anchored value (settlement.aggregated.xrpl/1 §10.1; settlement.binding/1
    # §6). Same family as V044: the memo, the leaf, the inclusion path and every
    # total are untouched, so the break is isolated to the manifest's copy.
    v = clone_fixture(p001)
    anchored_leaf_count = (
        v["material"]["authorization_bridge_proofs"][0]["batch_binding_preimage"]["leaf_count"]
    )
    v["material"]["batch_manifest"]["leaf_count"] = str(int(anchored_leaf_count) + 1)
    write_negative_zero_data(
        adversarial_dir, "V046", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["CAPACITY_BINDING_VALID"]},
        "# V046 — Manifest Leaf Count Diverges From the Anchored Leaf Count\n\n"
        f"The memo anchors batch_binding_preimage.leaf_count = {anchored_leaf_count}, but\n"
        f"batch_manifest.leaf_count declares {int(anchored_leaf_count) + 1}. The material's\n"
        "copy of the batch size MUST equal the anchored value\n"
        "(settlement.aggregated.xrpl/1 §10.1; settlement.binding/1 §6).\n"
        "Expected: INDEPENDENT_INVALID (CAPACITY_BINDING_VALID)",
    )
    print("  V046 generated")

    # V047 — the batch_manifest restates a different batch_id. The signed
    # settlement_ref binds batch_binding_preimage.batch_id, the anchored copy; the
    # manifest's copy is bound by nothing and is accepted only when it repeats the
    # anchored value (settlement.aggregated.xrpl/1 §10.1; settlement.binding/1 §6).
    # Same family as V044 and V046: everything anchored is untouched.
    v = clone_fixture(p001)
    anchored_batch_id = (
        v["material"]["authorization_bridge_proofs"][0]["batch_binding_preimage"]["batch_id"]
    )
    restated_batch_id = f"{anchored_batch_id}-restated"
    v["material"]["batch_manifest"]["batch_id"] = restated_batch_id
    write_negative_zero_data(
        adversarial_dir, "V047", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["CAPACITY_BINDING_VALID"]},
        "# V047 — Manifest Batch Id Diverges From the Anchored Batch Id\n\n"
        f"The memo anchors batch_binding_preimage.batch_id = {anchored_batch_id}, and the\n"
        "signed settlement_ref names it, but batch_manifest.batch_id declares\n"
        f"{restated_batch_id}. The material's copy of the batch identity MUST equal\n"
        "the anchored value (settlement.aggregated.xrpl/1 §10.1; settlement.binding/1 §6).\n"
        "Expected: INDEPENDENT_INVALID (CAPACITY_BINDING_VALID)",
    )
    print("  V047 generated")

    # V048 — Not a payment. The profile settles with a `Payment` (§7, §9.2); an
    # action of any other name cannot have moved the MPT, so the name is
    # load-bearing.
    v = clone_fixture(p001)
    v["material"]["settlement_action"]["name"] = "consume"
    write_negative_zero_data(
        adversarial_dir, "V048", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["CAPACITY_BINDING_VALID"], "certcrypt_lineage": {"capacity_consumption_bound": False, "history_bound_under_certcrypt": False}},
        "# V048 — Wrong Transaction Type\n\nsettlement_action.name is `consume`, not `payment`, the only settlement action the profile accepts (settlement.aggregated.xrpl/1 §9.2).\nExpected: INDEPENDENT_INVALID (CAPACITY_BINDING_VALID)",
    )
    print("  V048 generated")

    # V049 — Settled from the wrong account. The debit must come from the
    # aggregate pool: an issuer settling its own consumption would put its
    # identity on the public ledger, breaking unlinkability, and would also let a
    # holder claim capacity it never pooled (settlement.aggregated.xrpl/1 §7.2).
    v = clone_fixture(p001)
    v["material"]["settlement_action"]["from"] = "rNOTtheCONFORMANCEpoolXXXXXXXXXXXXX"
    write_negative_zero_data(
        adversarial_dir, "V049", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["CAPACITY_BINDING_VALID"], "certcrypt_lineage": {"capacity_consumption_bound": False, "history_bound_under_certcrypt": False}},
        "# V049 — Settled From The Wrong Account\n\nsettlement_action.from is not the aggregate pool (settlement.aggregated.xrpl/1 §7.2, §9.2).\nExpected: INDEPENDENT_INVALID (CAPACITY_BINDING_VALID)",
    )
    print("  V049 generated")

    # V050 — Synthesized action ordinal. XRPL has no sub-position inside a
    # transaction, so the profile pins `action_ordinal` to "0" (§8.1). A non-zero
    # value names an index the substrate does not define, so it is not
    # resolvable, and accepting it would make a re-read look like a re-inclusion.
    v = clone_fixture(p001)
    v["material"]["settlement_action"]["action_ordinal"] = "1"
    write_negative_zero_data(
        adversarial_dir, "V050", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["SETTLEMENT_REF_VALID"], "certcrypt_lineage": {"capacity_consumption_bound": False, "history_bound_under_certcrypt": False}},
        "# V050 — Non-Zero Action Ordinal\n\nsettlement_action.action_ordinal is `1`. The profile defines no sub-position inside a transaction and requires `0` (settlement.aggregated.xrpl/1 §8.1).\nExpected: INDEPENDENT_INVALID (SETTLEMENT_REF_VALID)",
    )
    print("  V050 generated")

    # V051 — Irreversibility that trails the inclusion. A validated ledger IS
    # final, so the irreversibility fields name the inclusion ledger or a later
    # validated one (settlement.aggregated.xrpl/1 §11.1). Material whose
    # irreversibility points at an EARLIER ledger states, by its own evidence,
    # that the settlement is not yet irreversible.
    v = clone_fixture(p001)
    fp = v["material"]["finality_proof"]
    fp["last_irreversible_block_num"] = str(int(fp["block_num"]) - 10)
    write_negative_zero_data(
        adversarial_dir, "V051", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["FINALITY_SUFFICIENT"], "certcrypt_lineage": {"certcrypt_domain_bound": True, "settlement_bound": False, "history_bound_under_certcrypt": False}},
        "# V051 — Irreversibility Trails Inclusion\n\nfinality_proof.last_irreversible_block_num is lower than block_num. A validated ledger is itself final, so the irreversibility fields must name the inclusion ledger or a later one (settlement.aggregated.xrpl/1 §11.1).\nExpected: INDEPENDENT_INVALID (FINALITY_SUFFICIENT)",
    )
    print("  V051 generated")

    # V052 — anchor subject profile not admitted. The certificate is otherwise
    # well formed and correctly signed; its only defect is a subject profile
    # outside the rules domain's admitted set, which makes it non-conformant
    # whether or not a verifier could canonicalize that profile.
    def _unadmitted_anchor_profile(cert):
        cert["payload"]["anchor"]["subjects"][0]["profile"] = "subject.unsupported/99"
        refresh_certificate_payload(cert)
        recompose_cert_signature(cert)
    v = build_zero_data_fixture(base_params("V052", "cap-auth-V052"),
                                cert_mutator=_unadmitted_anchor_profile)
    write_negative_zero_data(
        adversarial_dir, "V052", v,
        {"result_code": "REJECTED", "failed_check_ids": ["BASE_CERTIFICATE_STRUCTURE_VALID"]},
        "# V052 — Anchor Subject Profile Not Admitted\n\n"
        "A correctly signed certificate declares subject.unsupported/99 for its\n"
        "subject, a profile the rules domain does not admit. The certificate is\n"
        "non-conformant and fails closed on its structure, before authenticity.\n"
        "Expected: REJECTED (BASE_CERTIFICATE_STRUCTURE_VALID)",
    )
    print("  V052 generated")

    # V053 — proof_id does not digest the identity view (§10.3.1). The producer
    # signed it that way, so the signature verifies: only the recomputation of
    # proof_id catches it.
    v = clone_fixture(p001)
    seal_proof(v["proof"])
    v["proof"]["proof_id"] = digest_hex_text("V053-not-the-identity-view")
    _sd_mldsa_pub, _sd_mldsa_sk = primitives.deterministic_ml_dsa65("system-domain")
    _sd_p256_priv, _sd_p256_pub, _sd_p256_pub_b64 = primitives.deterministic_p256("system-domain-p256")
    v["proof"]["signature"] = {
        "signing_kid": PROOF_SIGNING_KID,
        **composite_sign_with(proof_signing_digest_hex(v["proof"]), _sd_p256_priv, _sd_mldsa_sk),
    }
    v["proof"]["proof_digest"] = compute_proof_digest(v["proof"])
    write_negative_zero_data(
        adversarial_dir, "V053", v,
        {"result_code": "REJECTED", "failed_check_ids": ["PROOF_STRUCTURE_VALID"]},
        "# V053 — proof_id Not Derived From the Identity View\n\n"
        "P001 whose `proof_id` is an arbitrary digest, signed as such by the system\n"
        "domain. The signature verifies; `proof_id` does not equal\n"
        "SHA3-256(JCS(identity view)) (independence.proof/1 §10.3.1).\n"
        "Expected: REJECTED (PROOF_STRUCTURE_VALID)",
    )
    print("  V053 generated")

    # V054 — closure_time absent. It is a mandatory member of the identity and
    # signed views (§10.4.3).
    v = clone_fixture(p001)
    del v["proof"]["closure_time"]
    v["proof"]["proof_digest"] = compute_proof_digest(v["proof"])
    write_negative_zero_data(
        adversarial_dir, "V054", v,
        {"result_code": "REJECTED", "failed_check_ids": ["PROOF_STRUCTURE_VALID"]},
        "# V054 — Proof Without closure_time\n\n"
        "P001 with `closure_time` removed (`proof_digest` recomputed). The field is\n"
        "mandatory (independence.proof/1 §10.4.3).\n"
        "Expected: REJECTED (PROOF_STRUCTURE_VALID)",
    )
    print("  V054 generated")

    # V055 — anti_replay present, non-empty and signed, but not the derivation of
    # §10.9. Presence alone is not enough: the verifier recomputes it.
    v = clone_fixture(p001)
    v["proof"]["anti_replay"] = derive_anti_replay(
        v["proof"]["settlement_ref"] + "-other-container", v["proof"]["subtree_root"]
    )
    seal_proof(v["proof"])
    write_negative_zero_data(
        adversarial_dir, "V055", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["NON_REPLAY_VALID"]},
        "# V055 — anti_replay Bound to Another Settlement Context\n\n"
        "P001 whose `anti_replay` is the derivation for a different settlement_ref,\n"
        "signed by the system domain. It is well formed and authentic, but it does not\n"
        "equal the derivation from this proof's settlement_ref and subtree_root\n"
        "(independence.proof/1 §10.9).\n"
        "Expected: INDEPENDENT_INVALID (NON_REPLAY_VALID)",
    )
    print("  V055 generated")

    # V056 — the proof's finality witness names another ledger than the settlement
    # material. The material is authoritative (§10.6); a witness that disagrees
    # with it is an incoherent proof.
    v = clone_fixture(p001)
    v["proof"]["settlement"]["finality_proofs"][0]["block_height"] = str(
        int(v["material"]["finality_proof"]["block_num"]) + 1
    )
    seal_proof(v["proof"])
    write_negative_zero_data(
        adversarial_dir, "V056", v,
        {"result_code": "REJECTED", "failed_check_ids": ["FINALITY_SUFFICIENT"]},
        "# V056 — Finality Witness Disagrees With the Settlement Material\n\n"
        "P001 whose finality witness declares `block_height` one ledger after the\n"
        "settlement material's `finality_proof.block_num`. The witness is a projection\n"
        "of the material (independence.proof/1 §10.6): `block_height` and `timestamp`\n"
        "must equal `block_num` and `block_timestamp`.\n"
        "Expected: REJECTED (FINALITY_SUFFICIENT)",
    )
    print("  V056 generated")

    # --- AI-decision subject with its input/output material (§8.5.6) ---
    # The record binds independently salted commitments to a text prompt, a binary
    # image, and a text answer. With the record matched, the verifier recomputes each
    # delivered side under the declared profile and checks its salted commitment.
    AI_PROMPT = "Classify synthetic sample alpha."
    AI_IMAGE = "synthetic-png-byte-stream"
    AI_ANSWER = "label: category-a"

    def _ai_record(answer_material: str) -> dict:
        def descriptor(part_id: str, role: str, media_type: str, profile: str,
                       material: bytes, nonce_byte: str) -> dict:
            if profile == "subject.text/1":
                canonical = primitives.canonical_subject_text(material)
            elif profile == "subject.binary/1":
                canonical = material
            else:
                raise ValueError(profile)
            material_nonce_hex = nonce_byte * 64
            local_digest = digest_hex_bytes(canonical)
            return {
                "id": part_id,
                "role": role,
                "media_type": media_type,
                "profile": profile,
                "material_nonce_hex": material_nonce_hex,
                "commitment_digest_hex": digest_hex_text(material_nonce_hex + local_digest),
            }
        return {
            "profile": "subject.ai-decision/1",
            "decision_id": "synthetic-event-01",
            "decided_at": "2026-04-11T11:30:00.000Z",
            "started_at": "2026-04-11T11:29:58.000Z",
            "model": {"id": "synthetic-model", "provider": "synthetic-runtime",
                      "version": "synthetic-model-v1"},
            "observation_scope": "client",
            "parameters": {"temperature": "0.0"},
            "context": {"channel": "synthetic-channel-01"},
            "input": [
                descriptor("prompt", "prompt", "text/plain", "subject.text/1",
                           AI_PROMPT.encode("utf-8"), "1"),
                descriptor("image", "image", "image/png", "subject.binary/1",
                           AI_IMAGE.encode("utf-8"), "2"),
            ],
            "output": [descriptor("answer", "response", "text/plain", "subject.text/1",
                                  answer_material.encode("utf-8"), "3")],
            "decision": "category-a",
        }

    AI_RECORD = _ai_record(AI_ANSWER)
    AI_RECORD_UTF8 = json.dumps(AI_RECORD, separators=(",", ":"))

    def _ai_decision_subject(cert: dict) -> None:
        nonce = cert["payload"]["anchor"]["nonce_hex"]
        sld = digest_hex_bytes(jcs_canonicalize_bytes(AI_RECORD))
        cert["payload"]["anchor"]["subjects"] = [{
            "profile": "subject.ai-decision/1",
            "commitment_digest_hex": digest_hex_text(nonce + sld),
        }]
        refresh_certificate_payload(cert)
        recompose_cert_signature(cert)

    p011 = build_zero_data_fixture(
        base_params("P011", "cap-auth-P011"),
        cert_mutator=_ai_decision_subject,
    )
    write_zero_data_fixture(
        conformance_dir, "P011", p011,
        "# P011 — AI-Decision Subject, Input and Output Verified\n\n"
        "A valid Independent whose single subject is a subject.ai-decision/1 record. The\n"
        "record is delivered with a text prompt, a binary image supplied through the\n"
        "streaming-digest path, and a text answer. The verifier matches the record against\n"
        "the certificate's commitment, then recomputes every disclosed part's salted\n"
        "commitment under the profile and nonce the matched record declares\n"
        "(verifier-toolkit/1 §8.5.6).\n"
        "All checks pass. The match says the held materials are the ones the\n"
        "committed record names; it says nothing about the decision's merit.",
        original_material=[{"material_utf8": AI_RECORD_UTF8, "nested_materials": [
            {"id": "prompt", "material_utf8": AI_PROMPT},
            {"id": "image", "prehashed": True,
             "subject_local_digest_hex": digest_hex_bytes(AI_IMAGE.encode("utf-8")),
             "byte_length": len(AI_IMAGE.encode("utf-8"))},
            {"id": "answer", "material_utf8": AI_ANSWER},
        ]}],
        expected_extra={
            "complete_verification_against_original_material_performed": True,
            "complete_verification_against_original_material_passed": True,
        },
    )
    print("  P011 generated")

    # V057 — the record matches the certificate, but the delivered output is not the
    # answer the record names.
    v = build_zero_data_fixture(
        base_params("V057", "cap-auth-V057"),
        cert_mutator=_ai_decision_subject,
    )
    write_negative_zero_data(
        adversarial_dir, "V057", v,
        {"result_code": "ISSUED_INVALID", "failed_check_ids": ["ORIGINAL_MATERIAL_COMPARISON_VALID"]},
        "# V057 — AI-Decision Output Does Not Match the Committed Record\n\n"
        "The subject.ai-decision/1 record matches the certificate's commitment, and the\n"
        "delivered prompt matches the part named `prompt`; the part delivered as `answer` is\n"
        "different, so it does not reproduce that part's salted commitment\n"
        "(verifier-toolkit/1 §8.5.6). Like any material mismatch, a failure of the Issued\n"
        "route.\n"
        "Expected: ISSUED_INVALID (ORIGINAL_MATERIAL_COMPARISON_VALID)",
        original_material=[{"material_utf8": AI_RECORD_UTF8, "nested_materials": [
            {"id": "prompt", "material_utf8": AI_PROMPT},
            {"id": "answer", "material_utf8": "label: category-b"},
        ]}],
    )
    print("  V057 generated")

    # V058 — action_ordinal other than "0", with the signed settlement_ref naming
    # the same value. Ref and material agree, so only the profile rule catches it
    # (settlement.aggregated.xrpl/1 §8.1).
    v = clone_fixture(p001)
    v["material"]["settlement_action"]["action_ordinal"] = "1"
    _ref = v["proof"]["settlement_ref"].split(":")
    _ref[2] = "1"
    v["proof"]["settlement_ref"] = ":".join(_ref)
    v["proof"]["settlement"]["ref"] = v["proof"]["settlement_ref"]
    v["proof"]["anti_replay"] = derive_anti_replay(
        v["proof"]["settlement_ref"], v["proof"]["subtree_root"]
    )
    seal_proof(v["proof"])
    write_negative_zero_data(
        adversarial_dir, "V058", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["SETTLEMENT_REF_VALID"]},
        "# V058 — Non-Zero Action Ordinal Named By The Signed Reference\n\n"
        "settlement_action.action_ordinal is `1` and the signed settlement_ref names\n"
        "the same ordinal, so the two agree. The profile defines no sub-position\n"
        "inside a transaction and requires `0` (settlement.aggregated.xrpl/1 §8.1).\n"
        "Expected: INDEPENDENT_INVALID (SETTLEMENT_REF_VALID)",
    )
    print("  V058 generated")

    # V059 — the proof's batch.size is not the anchored leaf_count. batch.size is
    # outside the proof's signed view; the tree width comes from the anchored
    # batch_binding_preimage (settlement.binding/1 §6).
    v = clone_fixture(p001)
    v["proof"]["batch"]["size"] = str(
        int(v["material"]["authorization_bridge_proofs"][0]["batch_binding_preimage"]["leaf_count"]) + 1
    )
    v["proof"]["proof_digest"] = compute_proof_digest(v["proof"])
    write_negative_zero_data(
        adversarial_dir, "V059", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["INCLUSION_PROOF_VALID"]},
        "# V059 — Tree Width Not The Anchored leaf_count\n\n"
        "P001 whose independence proof declares batch.size one more than the\n"
        "anchored batch_binding_preimage.leaf_count. The width of the settlement tree\n"
        "is the anchored leaf_count (settlement.binding/1 §6).\n"
        "Expected: INDEPENDENT_INVALID (INCLUSION_PROOF_VALID)",
    )
    print("  V059 generated")

    # V060-V062 — settlement quantities that are not a canonical, strictly
    # positive amount at the asset scale (settlement.aggregated.xrpl/1 §9.3).
    for _fid, _qty, _why in (
        ("V060", "1.000 CERT", "three fractional digits, one more than the asset scale"),
        ("V061", "0.00 CERT", "zero, which settles nothing"),
        ("V062", "-1.00 CERT", "a signed amount"),
    ):
        v = clone_fixture(p001)
        v["material"]["settlement_action"]["quantity"] = _qty
        write_negative_zero_data(
            adversarial_dir, _fid, v,
            {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["CAPACITY_BINDING_VALID"]},
            f"# {_fid} — Settlement Quantity `{_qty}`\n\n"
            f"settlement_action.quantity is `{_qty}`: {_why}. The quantity is\n"
            "`<integer>.<2 digits> CERT` and strictly positive\n"
            "(settlement.aggregated.xrpl/1 §9.3).\n"
            "Expected: INDEPENDENT_INVALID (CAPACITY_BINDING_VALID)",
        )
        print(f"  {_fid} generated")

    # V063 — finality proof without the inclusion ledger's hash. block_id names
    # the validated ledger that includes the settlement (settlement.aggregated.xrpl/1
    # §8.3, §11.3); an empty one is not a finality proof.
    v = clone_fixture(p001)
    v["material"]["finality_proof"]["block_id"] = ""
    write_negative_zero_data(
        adversarial_dir, "V063", v,
        {"result_code": "REJECTED", "failed_check_ids": ["FINALITY_SUFFICIENT"]},
        "# V063 — Finality Proof Without block_id\n\n"
        "finality_proof.block_id is empty. It is the hash of the validated ledger\n"
        "that includes the settlement and MUST be present and non-empty\n"
        "(settlement.aggregated.xrpl/1 §8.3, §11.3).\n"
        "Expected: REJECTED (FINALITY_SUFFICIENT)",
    )
    print("  V063 generated")

    # V064 — commitment issued before its authorization's window opens. The window
    # [valid_from, valid_until] is inclusive at both ends (capacity.evidence/1 §7);
    # one second early is outside it.
    v = build_zero_data_fixture(
        base_params("V064", "cap-auth-V064"), auth_valid_from="2026-04-11T12:00:01Z"
    )
    write_negative_zero_data(
        adversarial_dir, "V064", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["CAPACITY_EVIDENCE_VALID"]},
        "# V064 — Commitment Issued Before The Authorization Window\n\n"
        "The capacity commitment's issued_at (2026-04-11T12:00:00Z) is one second\n"
        "before the Level-1 binding's valid_from. The window is inclusive at both\n"
        "ends, and this instant is outside it (capacity.evidence/1 §7).\n"
        "Expected: INDEPENDENT_INVALID (CAPACITY_EVIDENCE_VALID)",
    )
    print("  V064 generated")

    # P012 — commitment issued exactly at the authorization's valid_from: the
    # inclusive boundary of the window (capacity.evidence/1 §7).
    v = build_zero_data_fixture(
        base_params("P012", "cap-auth-P012"), auth_valid_from="2026-04-11T12:00:00Z"
    )
    write_zero_data_fixture(
        conformance_dir, "P012", v,
        "# P012 — Commitment Issued At The Window's Opening Instant\n\n"
        "The capacity commitment's issued_at equals the Level-1 binding's valid_from.\n"
        "The authorization window is inclusive at both ends (capacity.evidence/1 §7).\n"
        "Expected: INDEPENDENT_VALID",
    )
    print("  P012 generated")

    # === ISSUED ROUTE, MATERIAL DELIVERY, TARGET RESOLUTION AND PACKAGES ===

    def _binary_subject(material: str):
        """A single subject.binary/1 subject over `material`, under THIS cert's nonce."""
        def mut(cert):
            nonce = cert["payload"]["anchor"]["nonce_hex"]
            sld = digest_hex_bytes(material.encode("utf-8"))
            cert["payload"]["anchor"]["subjects"] = [{
                "profile": "subject.binary/1",
                "commitment_digest_hex": digest_hex_text(nonce + sld),
            }]
            refresh_certificate_payload(cert)
            recompose_cert_signature(cert)
        return mut

    def _email_subject(material: bytes):
        """A single subject.email/1 subject over `material`, under THIS cert's nonce."""
        def mut(cert):
            nonce = cert["payload"]["anchor"]["nonce_hex"]
            canonical = primitives.canonical_subject_email(material)
            sld = digest_hex_bytes(canonical)
            cert["payload"]["anchor"]["subjects"] = [{
                "profile": "subject.email/1",
                "commitment_digest_hex": digest_hex_text(nonce + sld),
            }]
            refresh_certificate_payload(cert)
            recompose_cert_signature(cert)
        return mut

    ISSUED_MATERIAL = "issued-route subject material"

    def write_issued_fixture(parent_dir, fixture_id, f, material_entry, expected, readme):
        """Target `issued`: the certificate and its subject material, nothing else."""
        fixture_dir = os.path.join(parent_dir, fixture_id)
        write_original_material(fixture_dir, [material_entry])
        write_json(os.path.join(fixture_dir, "input.json"), {
            "verification_target_requested": "issued",
            "input_mode": "artifact_set",
            "base_certificate_path": "artifacts/base-certificate.json",
            "original_material_path": "material/manifest.json",
        })
        write_json(os.path.join(fixture_dir, "artifacts", "base-certificate.json"), f["baseCert"])
        write_json(os.path.join(fixture_dir, "expected-result.json"), expected)
        write_text(os.path.join(fixture_dir, "README.md"), readme)

    # P013 — the Issued route, complete: a certificate verified against its material,
    # with no independence artifact at all.
    f = build_zero_data_fixture(base_params("P013", "cap-auth-P013"),
                                cert_mutator=_binary_subject(ISSUED_MATERIAL))
    write_issued_fixture(
        conformance_dir, "P013", f, {"material_utf8": ISSUED_MATERIAL},
        {"result_code": "ISSUED_VALID", "verification_target": "Issued", "failed_check_ids": [],
         "complete_verification_against_original_material_performed": True,
         "complete_verification_against_original_material_passed": True},
        "# P013 — Issued Verification Against Original Material\n\n"
        "Target `issued`: the certificate alone, with its subject material. The issuer\n"
        "signature verifies and the material recomputes to the committed subject\n"
        "(verifier-toolkit/1 §11.1). No proof is supplied and none is needed.\n"
        "Expected: ISSUED_VALID",
    )
    print("  P013 generated")

    # V065 — the same route with material that is not the committed one: a failure
    # of the Issued route, reported with the Issued code.
    f = build_zero_data_fixture(base_params("V065", "cap-auth-V065"),
                                cert_mutator=_binary_subject(ISSUED_MATERIAL))
    write_issued_fixture(
        adversarial_dir, "V065", f, {"material_utf8": ISSUED_MATERIAL + " (altered)"},
        {"result_code": "ISSUED_INVALID", "verification_target": "Issued",
         "failed_check_ids": ["ORIGINAL_MATERIAL_COMPARISON_VALID"]},
        "# V065 — Issued Verification, Material Does Not Match\n\n"
        "Target `issued`, a valid certificate, and material that does not recompute to\n"
        "the committed subject. The Issued route completed and failed: ISSUED_INVALID,\n"
        "never a code of the Independent route (verifier-toolkit/1 §9.1, §8.5.2).\n"
        "Expected: ISSUED_INVALID (ORIGINAL_MATERIAL_COMPARISON_VALID)",
    )
    print("  V065 generated")

    EMAIL_EMITTED = (
        b"From: sender@example.test\r\n"
        b"Subject: a long\r\n subject\r\n"
        b"\r\n"
        b"body\r\n\r\n"
    )
    EMAIL_EQUIVALENT = (
        b"From: sender@example.test\n"
        b"Subject: a long subject\n"
        b"\n"
        b"body"
    )

    # P016 — differences only where subject.email/1 defines equivalence.
    f = build_zero_data_fixture(base_params("P016", "cap-auth-P016"),
                                cert_mutator=_email_subject(EMAIL_EMITTED))
    write_issued_fixture(
        conformance_dir, "P016", f, {"material_bytes": EMAIL_EQUIVALENT},
        {"result_code": "ISSUED_VALID", "verification_target": "Issued", "failed_check_ids": [],
         "complete_verification_against_original_material_performed": True,
         "complete_verification_against_original_material_passed": True,
         "subject_scope": [{"profile": "subject.email/1", "opaque": True}]},
        "# P016 — Email Original Material Matches\n\n"
        "Target `issued`: the certificate commits to one complete emitted message under\n"
        "`subject.email/1`. The delivered message differs only in line-ending style, a\n"
        "header-fold position at existing whitespace, and trailing body terminators.\n"
        "Those representations have the same canonical bytes (subject.email/1 §11).\n"
        "Expected: ISSUED_VALID",
    )
    print("  P016 generated")

    # V082 — a transit-added header survives canonicalization and denotes
    # different material.
    email_received = b"Received: by recipient.example.test\r\n" + EMAIL_EMITTED
    f = build_zero_data_fixture(base_params("V082", "cap-auth-V082"),
                                cert_mutator=_email_subject(EMAIL_EMITTED))
    write_issued_fixture(
        adversarial_dir, "V082", f, {"material_bytes": email_received},
        {"result_code": "ISSUED_INVALID", "verification_target": "Issued",
         "failed_check_ids": ["ORIGINAL_MATERIAL_COMPARISON_VALID"],
         "complete_verification_against_original_material_performed": True,
         "complete_verification_against_original_material_passed": False,
         "subject_scope": [{"profile": "subject.email/1", "opaque": True}]},
        "# V082 — Transit-Mutated Email Does Not Match\n\n"
        "Target `issued`: the certificate commits to the emitted message, while the\n"
        "delivered copy contains an additional transit header. The profile preserves\n"
        "header presence, so this is different material, not an equivalent export.\n"
        "Expected: ISSUED_INVALID (ORIGINAL_MATERIAL_COMPARISON_VALID)",
    )
    print("  V082 generated")

    # V083 — Independent-route artifacts are present, so `auto` resolves to
    # Independent. The certificate is absent: this is an incomplete request,
    # not a malformed or ambiguous combination.
    v083_dir = os.path.join(adversarial_dir, "V083")
    v083_art = os.path.join(v083_dir, "artifacts")
    ensure_dir(v083_art)
    write_json(os.path.join(v083_art, "independence-proof.json"), p001["proof"])
    write_json(os.path.join(v083_art, "settlement-material.json"), p001["material"])
    write_json(os.path.join(v083_dir, "input.json"), {
        "verification_target_requested": "auto",
        "input_mode": "artifact_set",
        "independence_proof_path": "artifacts/independence-proof.json",
        "settlement_material_path": "artifacts/settlement-material.json",
    })
    write_json(os.path.join(v083_dir, "expected-result.json"), {
        "result_code": "INCOMPLETE",
        "verification_target": "Independent",
        "failed_check_ids": ["BASE_CERTIFICATE_PRESENT"],
        "required_artifacts_missing": ["base_certificate"],
    })
    write_text(
        os.path.join(v083_dir, "README.md"),
        "# V083 — Missing Base Certificate\n\n"
        "The artifact set carries an independence proof and settlement material but no "
        "base certificate. `auto` therefore resolves to Independent, and the absent "
        "certificate makes the request incomplete rather than malformed.\n"
        "Expected: INCOMPLETE (BASE_CERTIFICATE_PRESENT)",
    )
    print("  V083 generated")

    # V066 — material delivered for a subject the certificate does not declare.
    v = build_zero_data_fixture(base_params("V066", "cap-auth-V066"),
                                cert_mutator=_binary_subject(ISSUED_MATERIAL))
    write_negative_zero_data(
        adversarial_dir, "V066", v,
        {"result_code": "REJECTED", "failed_check_ids": ["ORIGINAL_MATERIAL_COMPARISON_VALID"]},
        "# V066 — Material For An Undeclared Subject Index\n\n"
        "The certificate declares one subject; the delivery carries material for index 0\n"
        "(correct) and for index 1, which the certificate does not declare. The\n"
        "certificate alone fixes cardinality and order, so the delivery is non-conformant\n"
        "(verifier-toolkit/1 §8.5.1) — rejected, not ignored.\n"
        "Expected: REJECTED (ORIGINAL_MATERIAL_COMPARISON_VALID)",
        original_material=[{"material_utf8": ISSUED_MATERIAL},
                           {"material_utf8": "an extra subject"}],
    )
    print("  V066 generated")

    # V067 — a collection under a commitment scheme the verifier does not implement.
    col_scheme = {
        "commitment_scheme": "collection.merkle-sha3-512/1",
        "root": "",
        "declared_cardinality": "3",
        "_leaf_profile": "subject.binary/1",
    }
    v = build_zero_data_fixture(base_params("V067", "cap-auth-V067"),
                                cert_mutator=_collection_mutator(col_scheme, P007_LEAF_MATERIALS),
                                declared_effective_units="3")
    write_negative_zero_data(
        adversarial_dir, "V067", v,
        {"result_code": "UNSUPPORTED", "failed_check_ids": ["ORIGINAL_MATERIAL_COMPARISON_VALID"]},
        "# V067 — Unsupported Collection Commitment Scheme\n\n"
        "The collection declares commitment_scheme collection.merkle-sha3-512/1, which\n"
        "the verifier does not implement. Comparing the delivered leaves needs the\n"
        "scheme, so the comparison fails closed as UNSUPPORTED — no fallback to another\n"
        "scheme (verifier-toolkit/1 §8.4, §8.5.1).\n"
        "Expected: UNSUPPORTED (ORIGINAL_MATERIAL_COMPARISON_VALID)",
        original_material=[{"leaf_materials_utf8": P007_LEAF_MATERIALS,
                            "collection_object": col_scheme}],
    )
    print("  V067 generated")

    # V068 — automatic target selection with Independent evidence and no proof.
    v = build_zero_data_fixture(base_params("V068", "cap-auth-V068"))
    v068_dir = os.path.join(adversarial_dir, "V068")
    write_json(os.path.join(v068_dir, "input.json"), {
        "verification_target_requested": "auto",
        "input_mode": "artifact_set",
        "base_certificate_path": "artifacts/base-certificate.json",
        "capacity_evidence_path": "artifacts/capacity-evidence.json",
        "commitment_inclusion_proof_path": "artifacts/commitment-inclusion-proof.json",
    })
    write_json(os.path.join(v068_dir, "artifacts", "base-certificate.json"), v["baseCert"])
    write_json(os.path.join(v068_dir, "artifacts", "capacity-evidence.json"), v["capacityEvidence"])
    write_json(os.path.join(v068_dir, "artifacts", "commitment-inclusion-proof.json"),
               v["commitmentInclusionProof"])
    write_json(os.path.join(v068_dir, "expected-result.json"), {
        "result_code": "INCOMPLETE", "verification_target": "Independent",
        "failed_check_ids": ["TARGET_AUTO_RESOLUTION_VALID"],
    })
    write_text(os.path.join(v068_dir, "README.md"),
               "# V068 — Automatic Target With Independent Evidence And No Proof\n\n"
               "Target `auto`, a valid certificate, its capacity evidence and its commitment\n"
               "inclusion proof — and no independence_proof. Independent evidence without its\n"
               "proof is an incomplete Independent verification; it is never answered as an\n"
               "Issued one (verifier-toolkit/1 §11.4).\n"
               "Expected: INCOMPLETE (TARGET_AUTO_RESOLUTION_VALID), target Independent")
    print("  V068 generated")

    # V074 — a collection-style delivery for an opaque subject: an attempt to have the
    # verifier read one subject.binary/1 input as many records.
    v = build_zero_data_fixture(base_params("V074", "cap-auth-V074"),
                                cert_mutator=_binary_subject(ISSUED_MATERIAL))
    write_negative_zero_data(
        adversarial_dir, "V074", v,
        {"result_code": "REJECTED", "failed_check_ids": ["ORIGINAL_MATERIAL_COMPARISON_VALID"]},
        "# V074 — Opaque Subject Delivered As Records\n\n"
        "The certificate's one subject is subject.binary/1: one opaque input. The delivery\n"
        "hands it over as a list of leaf files, as if it were a collection. Proving a\n"
        "container is not proving its contents, and the verifier does not decompose an\n"
        "opaque subject (verifier-toolkit/1 §8.5.4).\n"
        "Expected: REJECTED (ORIGINAL_MATERIAL_COMPARISON_VALID)",
        original_material=[{"material_utf8": ISSUED_MATERIAL}],
    )
    v074_material = os.path.join(adversarial_dir, "V074", "material")
    os.remove(os.path.join(v074_material, "material-0.bin"))
    for j, part in enumerate(["issued-route ", "subject material"]):
        write_text(os.path.join(v074_material, f"leaf-0-{j}.bin"), part)
    write_json(os.path.join(v074_material, "manifest.json"),
               [{"leaf_files": ["leaf-0-0.bin", "leaf-0-1.bin"]}])
    print("  V074 generated")

    # --- verification-package/1 ---
    def package_of(f, **overrides):
        """The flat package of verification-package/1 §22.1 over one fixture."""
        pkg = {
            "base_certificate": f["baseCert"],
            "independence_proof": f["proof"],
            "verification_context": {
                "rules_version": f["proof"]["rules_version"],
                "system_id": f["proof"]["system_id"],
            },
            "capacity_evidence": f["capacityEvidence"],
            "commitment_inclusion_proof": f["commitmentInclusionProof"],
            "settlement_material": f["material"],
            "settlement_reference": f["proof"]["settlement_ref"],
        }
        for k, val in overrides.items():
            if val is None:
                pkg.pop(k, None)
            else:
                pkg[k] = val
        return pkg

    def write_package_fixture(parent_dir, fixture_id, pkg, foundation, expected, readme,
                              target="independent"):
        fixture_dir = os.path.join(parent_dir, fixture_id)
        request = {
            "verification_target_requested": target,
            "input_mode": "package",
            "verification_package_path": "artifacts/verification-package.json",
        }
        if foundation is not None:
            request["system_foundation_path"] = "artifacts/system-foundation.json"
            write_json(os.path.join(fixture_dir, "artifacts", "system-foundation.json"), foundation)
        write_json(os.path.join(fixture_dir, "input.json"), request)
        write_json(os.path.join(fixture_dir, "artifacts", "verification-package.json"), pkg)
        write_json(os.path.join(fixture_dir, "expected-result.json"), expected)
        write_text(os.path.join(fixture_dir, "README.md"), readme)

    f = build_zero_data_fixture(base_params("P014", "cap-auth-P014"))
    write_package_fixture(
        conformance_dir, "P014", package_of(f), f["foundation"],
        {"result_code": "INDEPENDENT_VALID", "verification_target": "Independent",
         "failed_check_ids": [], "certcrypt_lineage": FULL_LINEAGE},
        "# P014 — Independent Verification From A Verification Package\n\n"
        "The artifacts arrive as one verification-package/1 object: base_certificate,\n"
        "independence_proof, verification_context, capacity_evidence,\n"
        "commitment_inclusion_proof, settlement_material and settlement_reference — the\n"
        "closed member set of §9.4. The system foundation is not a member: the verifier\n"
        "supplies it from its own configuration (verifier-toolkit/1 §8.2).\n"
        "Expected: INDEPENDENT_VALID",
    )
    print("  P014 generated")

    f = build_zero_data_fixture(base_params("P015", "cap-auth-P015"))
    write_package_fixture(
        conformance_dir, "P015", {"base_certificate": f["baseCert"],
                                  "verification_context": {"rules_version": "rules/conformance",
                                                           "system_id": "certcrypt"}},
        None,
        {"result_code": "ISSUED_VALID", "verification_target": "Issued", "failed_check_ids": []},
        "# P015 — Issued Verification From A Verification Package\n\n"
        "A package carrying only base_certificate and verification_context, the two\n"
        "members every package carries (verification-package/1 §9.1), verified with\n"
        "target `issued`.\n"
        "Expected: ISSUED_VALID",
        target="issued",
    )
    print("  P015 generated")

    package_negatives = [
        ("V069", {"original_material": "issued-route subject material"},
         {"result_code": "REJECTED", "failed_check_ids": ["PACKAGE_STRUCTURE_VALID"]},
         "Package Carrying Original Material",
         "The package adds an `original_material` member. A package never carries\n"
         "original material (verification-package/1 §10, §18), and its member set is\n"
         "closed (§9.4): the member is refused, not skipped."),
        ("V070", {"verification_context": None},
         {"result_code": "REJECTED", "failed_check_ids": ["PACKAGE_STRUCTURE_VALID"]},
         "Package Without verification_context",
         "The package omits `verification_context`, which every package carries\n"
         "(verification-package/1 §9.1)."),
        ("V071", {"verification_context": {"rules_version": "rules/conformance-uncommitted",
                                           "system_id": "certcrypt"}},
         {"result_code": "REJECTED", "failed_check_ids": ["PACKAGE_CONTEXT_COHERENT"]},
         "Package Declaring Another Rules Version",
         "`verification_context.rules_version` names rules/conformance-uncommitted, while\n"
         "the certificate and the proof it carries name rules/conformance. A package whose\n"
         "declaration contradicts its artifacts admits two readings (verification-package/1\n"
         "§13, §22.5)."),
        ("V072", {"settlement_reference": "0" * 64},
         {"result_code": "REJECTED", "failed_check_ids": ["PACKAGE_CONTEXT_COHERENT"]},
         "Package settlement_reference Differs From The Proof",
         "`settlement_reference` is not the proof's `settlement_ref`. The member is a\n"
         "convenience copy and MUST repeat it exactly (verification-package/1 §9.4)."),
    ]
    for fixture_id, overrides, expected, title, body in package_negatives:
        f = build_zero_data_fixture(base_params(fixture_id, f"cap-auth-{fixture_id}"))
        write_package_fixture(
            adversarial_dir, fixture_id, package_of(f, **overrides), f["foundation"], expected,
            f"# {fixture_id} — {title}\n\n{body}\n"
            f"Expected: {expected['result_code']} ({', '.join(expected['failed_check_ids'])})",
        )
        print(f"  {fixture_id} generated")

    # V073 — mixed-package substitution: every artifact of one leaf, and the
    # certificate of another. Each is valid on its own and the declared context is
    # the same; only the binding tells them apart.
    f = build_zero_data_fixture(base_params("V073", "cap-auth-V073"))
    other = build_zero_data_fixture(base_params("V073-other", "cap-auth-V073-other"))
    write_package_fixture(
        adversarial_dir, "V073", package_of(f, base_certificate=other["baseCert"]),
        f["foundation"],
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["LEAF_BINDING_VALID"]},
        "# V073 — Mixed-Package Substitution\n\n"
        "The package carries the proof, evidence, inclusion proof and settlement material\n"
        "of one certificate, and the base_certificate of another. Both certificates are\n"
        "valid and name the same system domain and rules version, so the package context\n"
        "is coherent; the emission binding is what fails (verifier-toolkit/1 §13).\n"
        "Expected: INDEPENDENT_INVALID (LEAF_BINDING_VALID)",
    )
    print("  V073 generated")

    # V075 — independence_result other than `independent`. The member is outside
    # the signed view, so the signature still verifies; under /1 the value is
    # exactly `independent` (independence.proof/1 §10.10, §12.1).
    v = clone_fixture(p001)
    v["proof"]["independence_result"] = "rejected"
    v["proof"]["proof_digest"] = compute_proof_digest(v["proof"])
    write_negative_zero_data(
        adversarial_dir, "V075", v,
        {"result_code": "REJECTED", "failed_check_ids": ["PROOF_STRUCTURE_VALID"]},
        "# V075 — independence_result Is Not `independent`\n\n"
        "P001 whose independence proof carries `independence_result: \"rejected\"`, with\n"
        "proof_digest recomputed. The member is outside the signed view, so the signature\n"
        "still verifies. Under /1 the value is exactly `independent`; any other value is a\n"
        "malformed proof, never read as a result (independence.proof/1 §10.10, §12.1).\n"
        "Expected: REJECTED (PROOF_STRUCTURE_VALID)",
    )
    print("  V075 generated")

    # V076 — an authorization granting another role. Everything is signed honestly
    # (Level-1 binding, commitment, evidence digest bound into the sub-tree); only
    # the role is not `capacity_commitment_holder`
    # (capacity.holder-authorization/1 §7 step 2).
    v = build_zero_data_fixture(
        base_params("V076", "cap-auth-V076"), auth_role="capacity_observer"
    )
    write_negative_zero_data(
        adversarial_dir, "V076", v,
        {"result_code": "INDEPENDENT_INVALID", "failed_check_ids": ["CAPACITY_EVIDENCE_VALID"]},
        "# V076 — Authorization For Another Role\n\n"
        "The Level-1 binding, signed by the system domain, and the projected authorization\n"
        "agree on `authorized_role: \"capacity_observer\"`. Every signature verifies and the\n"
        "evidence digest is the committed one; the authorization does not grant the\n"
        "commitment-holder role (capacity.holder-authorization/1 §7 step 2,\n"
        "capacity.evidence/1 §8 step 3).\n"
        "Expected: INDEPENDENT_INVALID (CAPACITY_EVIDENCE_VALID)",
    )
    print("  V076 generated")

    # V077-V081 — capacity.evidence/1 is a closed runtime artifact. These
    # mutations are made after all cryptographic values have been generated so
    # the structural refusal is the first and only applicable failure.
    capacity_evidence_shape_cases = [
        (
            "V077",
            lambda evidence: evidence.pop("projected_commitment"),
            "Capacity Evidence Without projected_commitment",
            "The capacity evidence omits the mandatory `projected_commitment` member.",
        ),
        (
            "V078",
            lambda evidence: evidence.__setitem__("operation_salt_hex", "AA"),
            "Capacity Evidence With Non-Canonical Salt",
            "The operation salt uses uppercase hexadecimal instead of lowercase hexadecimal bytes.",
        ),
        (
            "V079",
            lambda evidence: evidence["projected_commitment"].__setitem__(
                "issued_at", "2026-01-01T01:00:00+01:00"
            ),
            "Capacity Commitment With Non-Canonical issued_at",
            "The commitment instant uses an offset instead of RFC 3339 UTC with whole seconds.",
        ),
        (
            "V080",
            lambda evidence: evidence.__setitem__("unexpected", "member"),
            "Capacity Evidence With An Additional Member",
            "The capacity evidence carries a member outside its closed member set.",
        ),
        (
            "V081",
            lambda evidence: evidence["projected_authorization"]["level1_binding"].__setitem__(
                "unexpected", "member"
            ),
            "Level-1 Binding With An Additional Member",
            "The nested Level-1 binding carries a member outside its closed member set.",
        ),
    ]
    for fixture_id, mutate, title, body in capacity_evidence_shape_cases:
        v = clone_fixture(p001)
        mutate(v["capacityEvidence"])
        write_negative_zero_data(
            adversarial_dir,
            fixture_id,
            v,
            {
                "result_code": "INDEPENDENT_INVALID",
                "failed_check_ids": ["CAPACITY_EVIDENCE_VALID"],
            },
            f"# {fixture_id} — {title}\n\n{body}\n\n"
            "A verifier refuses the artifact before dereferencing or interpreting its members "
            "(capacity.evidence/1 Sections 4 to 8).\n"
            "Expected: INDEPENDENT_INVALID (CAPACITY_EVIDENCE_VALID)",
        )
        print(f"  {fixture_id} generated")

    # === PQC COMPOSITE FIXTURES ===

    print("\nGenerating PQC composite fixtures...\n")

    # Q-series — ML-DSA-65 component of the composite signature, on the hybrid
    # leaf=subtree model. The component is NORMATIVE: a PQC failure fails
    # BASE_CERTIFICATE_AUTHENTIC (see Q003 below). Each fixture that mutates a
    # signatures[] entry does so via build_zero_data_fixture's cert_mutator hook,
    # BEFORE the ccd is computed and the capacity evidence is signed — so the
    # binding + capacity-evidence anchor the final cert and the only failing check
    # is BASE_CERTIFICATE_AUTHENTIC.

    def q_params(fixture_id, issuer, block):
        return {
            "fixtureId": fixture_id, "batchId": f"batch-{fixture_id}",
            "windowId": f"window-{fixture_id}", "trxId": f"trx-{fixture_id}",
            "leafIndex": 0, "batchSize": 1,
            "consumedQuantity": "1.00", "totalQuantity": "1.00",
            "blockNum": block, "libNum": block + 10,
            "issuerScope": issuer, "capacityAuthRef": f"cap-auth-{fixture_id}",
        }

    # Q-series — COMPOSITE PQC-component-mandatory (`composite-signature/1`). Under the hybrid
    # composite the ML-DSA-65 component is NORMATIVE, not a sidecar: AND semantics
    # mean a broken PQC half breaks the whole result. These fixtures assert that
    # property.

    # The ML-DSA-65 component's outcome is also surfaced on its own in
    # additional_verifications.pqc_base_certificate_authentic. Q001 (pass) and
    # Q003 (fail) pin that slot so it cannot regress to `performed: false`
    # ("not_attempted") on a component that was in fact verified. `reason` is not
    # pinned: its wording is implementation-specific.
    def pqc_slot(passed):
        return {
            "additional_verifications": {
                "pqc_base_certificate_authentic": {
                    "performed": True,
                    "algorithm": "ML-DSA-65",
                    "passed": passed,
                }
            }
        }

    def break_mldsa_component_bytes(cert):
        # Valid P-256 half, corrupted ML-DSA-65 half → composite must fail.
        comp = next(c for c in cert["signatures"][0]["signatures"] if c["alg"] == ALG_MLDSA65)
        sig_bytes = bytearray(base64.b64decode(comp["sig_b64"]))
        sig_bytes[0] = sig_bytes[0] ^ 0xFF
        comp["sig_b64"] = base64.b64encode(bytes(sig_bytes)).decode("ascii")

    def break_strip_to_classical(cert):
        # Attempt to "downgrade" to classical-only by removing the PQC component.
        # The composite is structurally AND with a mandatory PQC floor → fail-closed.
        sigs = cert["signatures"][0]["signatures"]
        cert["signatures"][0]["signatures"] = [c for c in sigs if c["alg"] != ALG_MLDSA65]

    def break_domain_prefix(cert):
        # Anti cross-profile: change the composite profile `alg` so the components
        # no longer bind to THIS profile (alg is bound into M'). Verifying under a
        # different profile must fail.
        cert["signatures"][0]["alg"] = "certcrypt-composite-WRONG-vN"

    # Q001 — valid composite (both components verify). The canonical positive for
    # the composite emission signature.
    q001 = build_zero_data_fixture(q_params("Q001", "issuer:composite-ok", 6000))
    write_zero_data_fixture(
        conformance_dir, "Q001", q001,
        "# Q001 — Valid Composite Emission Signature (P-256 + ML-DSA-65)\n\n"
        "Certificate carries a single composite issuer signature with both component\n"
        "signatures over the domain-separated M'. Both verify (AND).\n"
        "Also pins additional_verifications.pqc_base_certificate_authentic:\n"
        "performed=true, passed=true.\n"
        "Expected: INDEPENDENT_VALID",
        expected_extra=pqc_slot(True),
    )
    print("  Q001 generated")

    # Q002 — second valid composite (distinct issuer/economics), to keep a positive
    # composite fixture in the conformance set alongside Q001.
    q002 = build_zero_data_fixture(q_params("Q002", "issuer:composite-ok-2", 6100))
    write_zero_data_fixture(
        conformance_dir, "Q002", q002,
        "# Q002 — Valid Composite Emission Signature (second instance)\n\n"
        "A second valid composite certificate (distinct issuer + economics).\n"
        "Expected: INDEPENDENT_VALID",
    )
    print("  Q002 generated")

    # Q003 — valid P-256 half, corrupted ML-DSA-65 half. Under AND this FAILS.
    # Proves the PQC floor is mandatory.
    fp = build_zero_data_fixture(
        q_params("Q003", "issuer:pqc-broken", 6200), cert_mutator=break_mldsa_component_bytes
    )
    write_negative_zero_data(
        adversarial_dir, "Q003", fp,
        {"result_code": "ISSUED_INVALID", "failed_check_ids": ["BASE_CERTIFICATE_AUTHENTIC"],
         **pqc_slot(False)},
        "# Q003 — Composite With Broken ML-DSA-65 Component\n\n"
        "The P-256 component is valid but the ML-DSA-65 component is corrupted.\n"
        "Composite verification is AND: a broken PQC half fails the whole signature\n"
        "(the post-quantum floor is mandatory, not a sidecar).\n"
        "Also pins additional_verifications.pqc_base_certificate_authentic:\n"
        "performed=true, passed=false — the component was verified and failed, so\n"
        "the slot must not read `not_attempted`.\n"
        "Expected: ISSUED_INVALID (BASE_CERTIFICATE_AUTHENTIC)",
    )
    print("  Q003 generated")

    # Q004 — stripping attempt: PQC half removed (empty). Fails closed.
    fp = build_zero_data_fixture(
        q_params("Q004", "issuer:pqc-stripped", 6300), cert_mutator=break_strip_to_classical
    )
    write_negative_zero_data(
        adversarial_dir, "Q004", fp,
        {"result_code": "REJECTED", "failed_check_ids": ["BASE_CERTIFICATE_STRUCTURE_VALID"]},
        "# Q004 — Composite Stripping Attempt (PQC half removed)\n\n"
        "An attacker zeroes the ML-DSA-65 component to 'downgrade' to classical-only.\n"
        "The composite is structurally AND: a missing component is a structural defect.\n"
        "Expected: REJECTED (BASE_CERTIFICATE_STRUCTURE_VALID)",
    )
    print("  Q004 generated")

    # Q005 — anti-stripping: wrong domain label. Components signed over the real
    # M' do not verify under a different label.
    fp = build_zero_data_fixture(
        q_params("Q005", "issuer:wrong-domain", 6400), cert_mutator=break_domain_prefix
    )
    write_negative_zero_data(
        adversarial_dir, "Q005", fp,
        {"result_code": "ISSUED_INVALID", "failed_check_ids": ["BASE_CERTIFICATE_AUTHENTIC"]},
        "# Q005 — Composite Domain-Separation Mismatch\n\n"
        "The component signatures were made over M' with the canonical label, but the\n"
        "certificate declares a different domain. Re-deriving M' with the wrong label\n"
        "makes both components fail — this is the anti-stripping binding.\n"
        "Expected: ISSUED_INVALID (BASE_CERTIFICATE_AUTHENTIC)",
    )
    print("  Q005 generated")


    # C-series — the CCSP/1 certificate envelope. Every certificate below is built
    # through build_zero_data_fixture's cert_mutator, so the emission binding and
    # the capacity evidence anchor the mutated certificate and the only defect is
    # the envelope rule under test. Payload mutations are re-signed, so the issuer
    # signature is valid over what the certificate carries.

    def c_params(fixture_id, block):
        return {
            "fixtureId": fixture_id, "batchId": f"batch-{fixture_id}",
            "windowId": f"window-{fixture_id}", "trxId": f"trx-{fixture_id}",
            "leafIndex": 0, "batchSize": 1,
            "consumedQuantity": "1.00", "totalQuantity": "1.00",
            "blockNum": block, "libNum": block + 10,
            "issuerScope": "issuer:envelope", "capacityAuthRef": f"cap-auth-{fixture_id}",
        }

    def resign(cert):
        refresh_certificate_payload(cert)
        recompose_cert_signature(cert)

    # C001 — the optional members are accepted, and repeated array elements are
    # data, not duplicate members. The emission binding hashes the whole
    # certificate, so metadata and extensions are bound like every other member.
    def c001(cert):
        cert["metadata"] = {"labels": ["invoice", "invoice", "march"], "note": "unsigned annotation"}
        cert["extensions"] = {"com.example.transport": {"hops": ["a", "a"]}}
        cert["signatures"][0]["kid"] = "issuer-key-1"
        cert["payload"]["anchor_canon_digest_hex"] = digest_hex_bytes(
            jcs_canonicalize_bytes(cert["payload"]["anchor"]))
        resign(cert)
    f = build_zero_data_fixture(c_params("C001", 7000), cert_mutator=c001)
    write_zero_data_fixture(
        conformance_dir, "C001", f,
        "# C001 — Envelope With Every Optional Member\n\n"
        "The certificate carries `metadata`, `extensions`, an issuer `kid` and a\n"
        "published `payload.anchor_canon_digest_hex` that matches its recomputation.\n"
        "Arrays in metadata and extensions repeat elements, which is ordinary data,\n"
        "not a repeated member name. The emission binding covers the whole\n"
        "certificate, these members included (CCSP/1 §6.2).\n"
        "Expected: INDEPENDENT_VALID",
    )
    print("  C001 generated")

    def write_c_negative(fixture_id, block, mutate, expected, title, body):
        f = build_zero_data_fixture(c_params(fixture_id, block), cert_mutator=mutate)
        write_negative_zero_data(
            adversarial_dir, fixture_id, f, expected,
            f"# {fixture_id} — {title}\n\n{body}\n"
            f"Expected: {expected['result_code']} ({', '.join(expected['failed_check_ids'])})",
        )
        print(f"  {fixture_id} generated")
        return f

    structure_rejected = {"result_code": "REJECTED", "failed_check_ids": ["BASE_CERTIFICATE_STRUCTURE_VALID"]}

    def payload_member(name, value):
        def m(cert):
            cert["payload"][name] = value
            resign(cert)
        return m

    def anchor_member(name, value):
        def m(cert):
            cert["payload"]["anchor"][name] = value
            resign(cert)
        return m

    c_negatives = [
        ("C002", payload_member("consensus", {"bind": "CCCP/1:" + "0" * 64}),
         "Reserved payload.consensus",
         "A correctly signed certificate carries `payload.consensus`, a name CCSP/1 §9\n"
         "reserves. Anchoring and settlement live outside the certificate."),
        ("C003", payload_member("economics", {"units": "1"}),
         "Reserved payload.economics",
         "A correctly signed certificate carries `payload.economics`, a name CCSP/1 §9\n"
         "reserves."),
        ("C004", anchor_member("claim", "declared-context"),
         "Reserved payload.anchor.claim",
         "A correctly signed certificate carries `payload.anchor.claim`, a name\n"
         "CCSP/1 §9 reserves."),
        ("C005", anchor_member("economic_policy_id", "policy-1"),
         "Reserved payload.anchor.economic_policy_id",
         "A correctly signed certificate carries `payload.anchor.economic_policy_id`,\n"
         "a name CCSP/1 §9 reserves."),
        ("C006", lambda cert: cert.__setitem__("receipt", {"status": "settled"}),
         "Wrapper Member At The Top Level",
         "The certificate object carries a `receipt` member. The top level is closed\n"
         "(CCSP/1 §6): wrappers and receipts live outside the certificate."),
        ("C007", anchor_member("issuer_id", "acme"),
         "Unknown Member Inside The Anchor",
         "A correctly signed certificate adds `issuer_id` to `payload.anchor`, which\n"
         "is closed (CCSP/1 §7.3.1)."),
        ("C008", anchor_member("issued_at", "2026-04-11T15:00:00+02:00"),
         "issued_at With A Numeric Offset",
         "`payload.anchor.issued_at` uses a `+02:00` offset. CCSP/1 §7.3.1 requires\n"
         "UTC with the `Z` suffix, so every verifier reads the same instant."),
        ("C009", anchor_member("root_id", "root-not-hex"),
         "root_id Not 64 Lowercase Hex",
         "`payload.anchor.root_id` is present but is not 64 lowercase hexadecimal\n"
         "characters (CCSP/1 §7.3.1)."),
        ("C010", lambda cert: cert["signatures"].append(copy.deepcopy(cert["signatures"][0])),
         "Two Issuer Signatures",
         "`signatures[]` carries the issuer signature twice. CCSP/1 §7.4 admits\n"
         "exactly one signature object, so no verifier has to choose between them."),
        ("C011", lambda cert: cert["signatures"][0].__setitem__("receipt", "accepted"),
         "Unknown Member In The Issuer Signature",
         "The issuer signature object carries a `receipt` member. The object is\n"
         "closed (CCSP/1 §7.4)."),
        ("C012", lambda cert: cert["signatures"][0]["signer"].__setitem__(
            "pub_b64", cert["signatures"][0]["signer"]["pub_p256_b64"]),
         "Unknown Member In The Signer",
         "The signer object carries a `pub_b64` member beside its two component\n"
         "keys. The signer is closed (CCSP/1 §7.4)."),
        ("C013", payload_member("anchor_canon_digest_hex", "0" * 64),
         "Published Anchor Digest Mismatch",
         "A correctly signed certificate publishes `payload.anchor_canon_digest_hex`\n"
         "with a value that is not SHA3-256(JCS(anchor)). A published digest is\n"
         "recomputed and a mismatch fails closed (CCCP/1 §7.3)."),
        ("C014", lambda cert: cert.__setitem__("payload_canon_digest_hex", "0" * 64),
         "Published Payload Digest Mismatch",
         "The top-level `payload_canon_digest_hex` is not SHA3-256(JCS(payload)).\n"
         "A published digest is recomputed and a mismatch fails closed (CCSP/1 §7.5)."),
        ("C015", payload_member("system_id", "certcrypt-impostor"),
         "Certificate Of Another System Domain",
         "A correctly signed certificate names `payload.system_id` of a system domain\n"
         "other than the one under evaluation (CCSP/1 §7.3)."),
        ("C016", lambda cert: cert["signatures"][0].__setitem__(
            "signatures", list(reversed(cert["signatures"][0]["signatures"]))),
         "Composite Components Out Of Order",
         "The issuer signature lists ML-DSA-65 before the classical component. The\n"
         "component order is fixed by the profile (composite-signature/1 §8) and is\n"
         "part of the closed issuer signature layout (CCSP/1 §7.4)."),
    ]
    block = 7100
    for fixture_id, mutate, title, body in c_negatives:
        write_c_negative(fixture_id, block, mutate, structure_rejected, title, body)
        block += 100

    # C017 — a rules version this verifier does not evaluate is not malformed; it
    # is outside what the verifier supports. Requested as `issued` with the
    # certificate alone: under `independent` the proof's rules version would
    # disagree with the certificate's and decide the fixture first.
    def c017(cert):
        cert["payload"]["rules_version"] = "rules/9999-01"
        resign(cert)
    f = build_zero_data_fixture(c_params("C017", block), cert_mutator=c017)
    c017_dir = os.path.join(adversarial_dir, "C017")
    write_json(os.path.join(c017_dir, "input.json"), {
        "verification_target_requested": "issued",
        "input_mode": "artifact_set",
        "base_certificate_path": "artifacts/base-certificate.json",
    })
    write_json(os.path.join(c017_dir, "artifacts", "base-certificate.json"), f["baseCert"])
    write_json(os.path.join(c017_dir, "expected-result.json"),
               {"result_code": "UNSUPPORTED", "failed_check_ids": ["BASE_CERTIFICATE_STRUCTURE_VALID"]})
    write_text(os.path.join(c017_dir, "README.md"),
               "# C017 — Rules Version Not Evaluated By The Verifier\n\n"
               "A correctly signed certificate names `payload.rules_version` \"rules/9999-01\",\n"
               "which the verifier does not evaluate. It cannot decide the certificate\n"
               "under rules it does not hold (CCSP/1 §7.3).\n"
               "Expected: UNSUPPORTED (BASE_CERTIFICATE_STRUCTURE_VALID)")
    print("  C017 generated")
    block += 100

    # C018 / C019 — repeated member names the parser must refuse. The text of an
    # otherwise valid certificate is rewritten with one duplicate.
    input_rejected = {"result_code": "REJECTED", "failed_check_ids": ["INPUT_COMBINATION_VALID"]}
    f = write_c_negative(
        "C018", block, None, input_rejected,
        "Escaped Duplicate Inside The Anchor",
        "`payload.anchor` carries `issued_at` twice; the second spelling escapes a\n"
        "letter (`\\u0069ssued_at`). Member names are compared after decoding, so this\n"
        "is a duplicate, and any duplicate is non-conformant at any depth (CCSP/1 §8.1).",
    )
    cert_text = stringify_pretty(f["baseCert"])
    issued = f["baseCert"]["payload"]["anchor"]["issued_at"]
    write_text(
        os.path.join(adversarial_dir, "C018", "artifacts", "base-certificate.json"),
        inject_after_first(cert_text, f'"issued_at": "{issued}",',
                           '\n        "\\u0069ssued_at": "2030-01-01T00:00:00Z",'),
    )
    block += 100

    def with_metadata(cert):
        cert["metadata"] = {"note": "first"}
    f = write_c_negative(
        "C019", block, with_metadata, input_rejected,
        "Duplicate Inside metadata",
        "`metadata` carries `note` twice. metadata is part of the certificate the\n"
        "emission binding hashes, so a duplicate there is as ambiguous as anywhere\n"
        "else (CCSP/1 §8.1).",
    )
    write_text(
        os.path.join(adversarial_dir, "C019", "artifacts", "base-certificate.json"),
        inject_after_first(stringify_pretty(f["baseCert"]), '"note": "first"',
                           ',\n    "note": "second"'),
    )

    pin_verification_targets(conformance_dir, adversarial_dir)

    write_ccvp_consistency_vectors(fixtures_root)
    print("  primitives/ccvp-consistency generated")
    write_collection_element_vectors(fixtures_root)
    print("  primitives/collection-merkle/certificate-element generated")

    _n_conf = len([d for d in os.listdir(conformance_dir) if os.path.isdir(os.path.join(conformance_dir, d))])
    _n_adv = len([d for d in os.listdir(adversarial_dir) if os.path.isdir(os.path.join(adversarial_dir, d))])
    print(f"\nAll {_n_conf + _n_adv} fixtures generated successfully "
          f"({_n_conf} conformance + {_n_adv} adversarial).")

    # Gate: the primitive byte-contract vectors (fixtures/primitives/) are authored
    # artifacts (prose + pinned bytes), not regenerated files — except
    # ccvp-consistency, which is written above because its certificates carry
    # signatures this generator produces. emit_primitives
    # RECOMPUTES every deterministic value from each vector's own inputs and
    # asserts a byte-for-byte match, and verifies the three external goldens'
    # embedded signatures. It runs against the canonical repo fixtures regardless
    # of --out, so a rules drift (like a stale recomputed digest) fails the run.
    import emit_primitives
    repo_fixtures = os.path.join(script_dir, "..", "fixtures")
    print("\nVerifying primitive byte-contract vectors...")
    rc = emit_primitives.main_check(repo_fixtures)
    if rc != 0:
        raise SystemExit(rc)

    # Gate: the normative JSON Schemas are valid Draft 2020-12 and every fixture
    # request conforms to the input schema (validate_schemas.py — self-contained,
    # no verifier dependency; the output schema is checked against a real
    # verifier's result in the verifier-toolkit test suite).
    import validate_schemas
    repo_schemas = os.path.join(script_dir, "..", "schemas")
    print("\nValidating normative JSON Schemas...")
    rc = validate_schemas.main_check(repo_fixtures, repo_schemas)
    if rc != 0:
        raise SystemExit(rc)


if __name__ == "__main__":
    main()
