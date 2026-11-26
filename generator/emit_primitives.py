#!/usr/bin/env python3
"""Reproduce-and-verify oracle for fixtures/primitives/*.

The primitive vectors are AUTHORED artifacts (prose + pinned bytes), except
`ccvp-consistency`, whose signed certificates generate_fixtures.py writes. This
oracle does NOT rewrite them; it RECOMPUTES every deterministic `expected_*` value from
each vector's own inputs, using only generator/primitives.py, and asserts the
result matches the committed file byte-for-byte. For the three goldens that embed
signatures produced by the reference producer implementation with test keys
(hedged ML-DSA-65 + composite, plus the pinned system-domain public keys), it
recomputes the deterministic envelope (JCS/SHA3
digests) AND verifies the embedded signatures validate against the pinned keys —
it does not (cannot) regenerate a hedged signature byte-for-byte.

This is what "the generator reproduces the primitives" means for a suite whose
primitive layer is a cross-language byte contract: any conformant generator, in
any language, that follows the public rules reproduces every value this oracle
recomputes. Run it as a release gate:

    PYTHONPATH=. python emit_primitives.py            # verify against ../fixtures
    PYTHONPATH=. python emit_primitives.py --fixtures DIR

A non-zero exit means a primitive drifted from the rules: a committed value no
longer follows from its own inputs, such as a submission_set_id that was not
recomputed after its members changed.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
import re
import sys

from dilithium_py.ml_dsa import ML_DSA_65

import primitives as P

# ── result plumbing ────────────────────────────────────────────────────────
_FAILS: list[str] = []
_CHECKS = 0


def _eq(label: str, got, exp) -> bool:
    global _CHECKS
    _CHECKS += 1
    if got != exp:
        _FAILS.append(f"{label}\n     got: {got!r}\n     exp: {exp!r}")
        return False
    return True


def _load(fixtures: str, *parts: str) -> dict:
    with open(os.path.join(fixtures, "primitives", *parts), encoding="utf-8") as fh:
        return json.load(fh)


# CCCP/1 §8.1 commitment: SHA3-256(ASCII(nonce_hex) || ASCII(subject_local_digest_hex))
def _cccp_commitment(nonce_hex: str, subject_local_digest_hex: str) -> str:
    return P.digest_hex_text(nonce_hex + subject_local_digest_hex)


def _subject_local_digest(profile: str, material_utf8: str) -> str:
    """SHA3-256(canonical_bytes(material)) under the declared leaf/io profile.
    subject.text/1 -> CRLF canonicalization; subject.binary/1 -> byte identity."""
    raw = material_utf8.encode("utf-8")
    if profile == "subject.text/1":
        canon = P.canonical_subject_text(raw)
    elif profile == "subject.binary/1":
        canon = raw
    elif profile == "subject.email/1":
        canon = P.canonical_subject_email(raw)
    elif profile == "subject.ai-decision/1":
        canon = P.canonical_subject_ai_decision(raw)
    else:
        raise ValueError(f"unsupported io profile for digest: {profile}")
    return P.digest_hex_bytes(canon)


# ── deterministic primitives ────────────────────────────────────────────────

def check_pseudonym(fx: str) -> None:
    v = _load(fx, "pseudonym", "vectors.json")
    for vec in v["vectors"]:
        got = P.pseudonym_derive(
            vec["operation_salt_utf8"].encode("utf-8"), vec["domain"], vec["stable_id"]
        )
        _eq(f"pseudonym[{vec['name']}]", got, vec["expected_pseudonym_hex"])


def check_holder_keyset(fx: str) -> None:
    v = _load(fx, "holder-keyset", "vectors.json")
    pks = [bytes.fromhex(l["public_key_bytes_hex"]) for l in v["leaves"]]
    for leaf in v["leaves"]:
        got = P.operation_key_leaf_hash(bytes.fromhex(leaf["public_key_bytes_hex"]))
        _eq(f"holder-keyset leaf[{leaf['leaf_index']}]", got, leaf["expected_leaf_hash"])
    _eq("holder-keyset root", P.holder_key_set_root(pks), v["expected_root"])
    leaf_hashes = [P.operation_key_leaf_hash(pk) for pk in pks]
    for ip in v["inclusion_proofs"]:
        idx = ip["leaf_index"]
        got = P.generate_inclusion_proof(leaf_hashes, idx)
        _eq(f"holder-keyset proof[{idx}]", got, ip["sibling_hashes"])
    for t in v["trees"]:
        tpks = [bytes.fromhex(h) for h in t["public_keys_bytes_hex"]]
        tag = f"holder-keyset tree[{t['tree_size']}]"
        _eq(f"{tag} size", len(tpks), t["tree_size"])
        _eq(f"{tag} root", P.holder_key_set_root(tpks), t["expected_root"])
        tlh = [P.operation_key_leaf_hash(pk) for pk in tpks]
        for ip in t["inclusion_proofs"]:
            idx = ip["leaf_index"]
            _eq(f"{tag} proof[{idx}]", P.generate_inclusion_proof(tlh, idx), ip["sibling_hashes"])
    for c in v["disclosure_cases"]:
        ok, failure = P.verify_holder_key_disclosure(c["disclosure"], c["root"])
        _eq(f"holder-keyset case[{c['name']}] verdict", ok, c["expected_valid"])
        _eq(f"holder-keyset case[{c['name']}] failure", failure, c.get("failure"))


def _check_one_collection_merkle(v: dict, tag: str) -> None:
    leaves = [bytes.fromhex(h) for h in v["leaves_hex"]]
    salt = bytes.fromhex(v["collection_salt_hex"])
    leaf_hashes = [P.collection_leaf_hash(salt, v["leaf_profile"], b) for b in leaves]
    _eq(f"{tag} root", P.collection_merkle_root(leaf_hashes), v["root"])
    for ip in v["inclusion_proofs"]:
        idx = int(ip["leaf_index"])
        got = P.collection_inclusion_proof(leaf_hashes, idx)
        _eq(f"{tag} proof[{idx}]", got, ip["sibling_hashes"])


def _check_collection_inclusion_cases(v: dict, tag: str) -> None:
    """Element-level inclusion oracle (verify_collection_inclusion): each case's
    verdict MUST equal expected_valid. Pins the negative surface (spec §16) and a
    control positive across implementations for the collection.merkle-sha3-256/1
    element-inclusion operation."""
    for case in v["cases"]:
        salt_hex = case.get("collection_salt_hex", v["collection_salt_hex"])
        got = P.verify_collection_inclusion(
            bytes.fromhex(salt_hex),
            v["leaf_profile"],
            bytes.fromhex(case["leaf_hex"]),
            case["proof"],
            case["declared_cardinality"],
            case["root"],
        )
        _eq(f"{tag} case[{case['name']}] valid", got, case["expected_valid"])


def check_collection_merkle(fx: str) -> None:
    base = os.path.join(fx, "primitives", "collection-merkle")
    for name in sorted(os.listdir(base)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(base, name)
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        if name.startswith("vector-"):
            _check_one_collection_merkle(doc, f"collection-merkle/{name}")
        elif name == "negative-inclusion.json":
            _check_collection_inclusion_cases(doc, f"collection-merkle/{name}")
        elif name == "certificate-element.json":
            _check_certificate_element_cases(doc, f"collection-merkle/{name}")


def _certificate_element_outcome(cert, value: bytes) -> dict:
    """Reference for verifier-toolkit/1 §8.4.2, written from the spec: an
    Issued-valid certificate; every collection's declared leaves fold to its root;
    the value tried under each distinct declared leaf profile; every position
    holding its salted leaf hash under that profile is a match."""
    if not _ccvp_issued_valid(cert):
        return {"outcome": "certificate_not_issued_valid", "matches": []}
    anchor = cert["payload"]["anchor"]
    salt = anchor["nonce_hex"].encode("ascii")
    matches = []
    for si, subject in enumerate(anchor["subjects"]):
        if subject["profile"] != "subject.collection/1":
            continue
        coll = subject["collection"]
        hashes = [leaf["commitment_digest_hex"] for leaf in coll["leaves"]]
        if P.collection_merkle_root(hashes) != coll["root"]:
            return {"outcome": "rejected", "matches": []}
        profiles = list(dict.fromkeys(leaf["profile"] for leaf in coll["leaves"]))
        for profile in profiles:
            canonical = (P.canonical_subject_text(value) if profile == "subject.text/1"
                         else value)
            own = P.collection_leaf_hash(salt, profile, canonical)
            at = [li for li, leaf in enumerate(coll["leaves"])
                  if leaf["profile"] == profile and leaf["commitment_digest_hex"] == own]
            if at:
                matches.append({"subject_index": si, "profile": profile, "leaf_indices": at})
    return {"outcome": "member" if matches else "not_member", "matches": matches}


def _check_certificate_element_cases(doc: dict, tag: str) -> None:
    for case in doc["cases"]:
        cert = doc["certificates"][case["certificate"]]
        got = _certificate_element_outcome(cert, case["value_utf8"].encode("utf-8"))
        _eq(f"{tag} case[{case['name']}]", got, case["expected"])


def check_subject_text(fx: str) -> None:
    v = _load(fx, "subject-text", "vectors.json")
    for vec in v["vectors"]:
        c = P.canonical_subject_text(bytes.fromhex(vec["input_hex"]))
        _eq(f"subject-text[{vec['name']}] canon", c.hex(), vec["canonical_hex"])
        _eq(f"subject-text[{vec['name']}] digest",
            P.digest_hex_bytes(c), vec["subject_local_digest_hex"])


def check_subject_email(fx: str) -> None:
    v = _load(fx, "subject-email", "vectors.json")
    for vec in v["vectors"]:
        c = P.canonical_subject_email(bytes.fromhex(vec["input_hex"]))
        _eq(f"subject-email[{vec['name']}] canon", c.hex(), vec["canonical_hex"])
        _eq(f"subject-email[{vec['name']}] digest",
            P.digest_hex_bytes(c), vec["subject_local_digest_hex"])


def check_subject_binary(fx: str) -> None:
    v = _load(fx, "subject-binary", "vectors.json")
    nonce = v["nonce_hex"]
    for vec in v["vectors"]:
        raw = bytes.fromhex(vec["input_hex"])
        d = P.digest_hex_bytes(raw)  # identity canonicalization
        _eq(f"subject-binary[{vec['name']}] digest", d, vec["subject_local_digest_hex"])
        _eq(f"subject-binary[{vec['name']}] commitment",
            _cccp_commitment(nonce, d), vec["expected_commitment_digest_hex"])


def _check_jcs_subject(fx: str, folder: str, obj_key: str,
                       digest_key: str, canon_key: str) -> None:
    v = _load(fx, folder, "vectors.json")
    for vec in v["vectors"]:
        c = P.jcs_canonicalize_bytes(vec[obj_key])
        _eq(f"{folder}[{vec['name']}] canon", c.decode("utf-8"), vec[canon_key])
        _eq(f"{folder}[{vec['name']}] digest", P.digest_hex_bytes(c), vec[digest_key])


def _check_precondition_negatives(v: dict, folder: str, obj_key: str,
                                  precondition, assert_fn) -> None:
    """Every negative_cases[] entry MUST be rejected by the profile precondition
    (SubjectPreconditionError), i.e. canonical_bytes is undefined for it and a
    conformant implementation fails closed. Pins the rejection surface as a
    cross-language contract."""
    for case in v.get("negative_cases", []):
        rejected = False
        try:
            precondition(case[obj_key])
        except P.SubjectPreconditionError:
            rejected = True
        _eq(f"{folder} NEG[{case['name']}] rejected", rejected, True)
        # the contract also declares the outcome as REJECTED (fail-closed).
        _eq(f"{folder} NEG[{case['name']}] outcome",
            case.get("expected_outcome"), "REJECTED")
    # positive_cases[]: inputs the precondition MUST accept, with pinned canonical
    # bytes — e.g. the booleans and nulls subject.context-snapshot/1 preserves.
    for case in v.get("positive_cases", []):
        precondition(case[obj_key])
        c = P.jcs_canonicalize_bytes(case[obj_key])
        _eq(f"{folder} POS[{case['name']}] canon",
            c.decode("utf-8"), case["expected_canonical_bytes_utf8"])
        _eq(f"{folder} POS[{case['name']}] digest",
            P.digest_hex_bytes(c), case["expected_digest_hex"])


def check_subject_context_snapshot(fx: str) -> None:
    _check_jcs_subject(fx, "subject-context-snapshot", "snapshot_object",
                       "subject_local_digest_hex", "expected_canonical_utf8")
    v = _load(fx, "subject-context-snapshot", "vectors.json")
    _check_precondition_negatives(v, "subject-context-snapshot", "snapshot_object",
                                  P.assert_context_snapshot_precondition, None)


def check_subject_collection(fx: str) -> None:
    v = _load(fx, "subject-collection", "vectors.json")
    nonce = v["nonce_hex"]
    for vec in v["vectors"]:
        c = P.jcs_canonicalize_bytes(vec["collection_subject"])
        _eq(f"subject-collection[{vec['name']}] canon",
            c.decode("utf-8"), vec["expected_canonical_utf8"])
        d = P.digest_hex_bytes(c)
        _eq(f"subject-collection[{vec['name']}] digest",
            d, vec["expected_subject_local_digest_hex"])
        _eq(f"subject-collection[{vec['name']}] commitment",
            _cccp_commitment(nonce, d), vec["expected_commitment_digest_hex"])
    _check_precondition_negatives(v, "subject-collection", "collection_subject",
                                  P.assert_collection_precondition, None)


def check_subject_ai_decision(fx: str) -> None:
    v = _load(fx, "subject-ai-decision", "vectors.json")
    nonce = v["nonce_hex"]
    for vec in v["vectors"]:
        declared = {part["id"]: part for side in ("input", "output")
                    for part in vec["decision_record"][side]}
        for part_id, material in vec["part_materials"].items():
            part = declared[part_id]
            local_digest = _subject_local_digest(part["profile"], material)
            got = P.digest_hex_text(part["material_nonce_hex"] + local_digest)
            _eq(f"ai-decision[{vec['name']}] part {part_id} commitment",
                got, part["commitment_digest_hex"])
        c = P.canonical_subject_ai_decision(
            json.dumps(vec["decision_record"], ensure_ascii=False,
                       separators=(",", ":")).encode("utf-8"))
        _eq(f"ai-decision[{vec['name']}] canon",
            c.decode("utf-8"), vec["expected_canonical_utf8"])
        d = P.digest_hex_bytes(c)
        _eq(f"ai-decision[{vec['name']}] digest",
            d, vec["expected_subject_local_digest_hex"])
        _eq(f"ai-decision[{vec['name']}] commitment",
            _cccp_commitment(nonce, d), vec["expected_commitment_digest_hex"])
    _check_precondition_negatives(v, "subject-ai-decision", "decision_record",
                                  P.assert_ai_decision_precondition, None)
    valid_raw = json.dumps(v["vectors"][0]["decision_record"],
                           separators=(",", ":")).encode("utf-8")
    for name, raw in (
        ("source over 1 MiB", b" " * (1024 * 1024 + 1)),
        ("leading BOM", b"\xef\xbb\xbf" + valid_raw),
    ):
        rejected = False
        try:
            P.canonical_subject_ai_decision(raw)
        except P.SubjectPreconditionError:
            rejected = True
        _eq(f"subject-ai-decision NEG[{name}] rejected", rejected, True)
    too_large = dict(v["vectors"][0]["decision_record"])
    too_large["observation_scope"] = "x" * (1024 * 1024)
    rejected = False
    try:
        P.assert_ai_decision_precondition(too_large)
    except P.SubjectPreconditionError:
        rejected = True
    _eq("subject-ai-decision NEG[canonical over 1 MiB] rejected", rejected, True)


def check_strict_json(fx: str) -> None:
    """Every case parses or is refused exactly as declared, and every profile
    material case is accepted or refused before its precondition runs."""
    v = _load(fx, "strict-json", "vectors.json")
    for case in v["cases"]:
        try:
            P.strict_json_loads(case["json_text"])
            got = "ACCEPT"
        except P.StrictJsonError:
            got = "REJECTED"
        _eq(f"strict-json[{case['name']}]", got, case["expected"])
    preconditions = {
        "subject.ai-decision/1": P.assert_ai_decision_precondition,
        "subject.collection/1": P.assert_collection_precondition,
        "subject.context-snapshot/1": P.assert_context_snapshot_precondition,
    }
    for case in v["profile_material_cases"]:
        try:
            value = P.strict_json_loads(case["material_utf8"])
            preconditions[case["profile"]](value)
            got = "ACCEPT"
        except P.StrictJsonError:
            got = "REJECTED"
        _eq(f"strict-json material[{case['name']}]", got, case["expected_outcome"])


def check_original_material(fx: str) -> None:
    v = _load(fx, "original-material", "vectors.json")
    nonce = v["nonce_hex"]
    for s in v["subjects"]:
        if s["profile"] == "subject.binary/1":
            d = P.digest_hex_bytes(s["material_utf8"].encode("utf-8"))
            _eq(f"original-material[{s['index']}] binary digest",
                d, s["expected_subject_local_digest_hex"])
            _eq(f"original-material[{s['index']}] binary commitment",
                _cccp_commitment(nonce, d), s["expected_commitment_digest_hex"])
        elif s["profile"] == "subject.collection/1":
            # subject.collection/1 §8: the salt IS the anchor nonce, as ASCII bytes.
            # Pinned here rather than in the primitive vectors, which treat the salt
            # as opaque — this is the vector that binds scheme to profile.
            leaf_hashes = [
                P.collection_leaf_hash(
                    nonce.encode("ascii"), s["leaf_profile"], m.encode("utf-8")
                )
                for m in s["leaf_materials_utf8"]
            ]
            _eq(f"original-material[{s['index']}] leaf hashes",
                leaf_hashes, s["expected_leaf_hashes"])
            _eq(f"original-material[{s['index']}] root",
                P.collection_merkle_root(leaf_hashes), s["expected_root"])
            c = P.jcs_canonicalize_bytes(s["collection_object"])
            _eq(f"original-material[{s['index']}] collection canon",
                c.decode("utf-8"), s["expected_collection_canonical_utf8"])
            d = P.digest_hex_bytes(c)
            _eq(f"original-material[{s['index']}] collection digest",
                d, s["expected_subject_local_digest_hex"])
            _eq(f"original-material[{s['index']}] collection commitment",
                _cccp_commitment(nonce, d), s["expected_commitment_digest_hex"])


_PROJECTED_COMMITMENT_ORDER = [
    "commitment_version", "system_id", "system_root_fingerprint", "rules_version",
    "authorization_pseudonym", "holder_pseudonym", "pool_pseudonym",
    "certificate_commitment_digest", "consumed_quantity", "declared_effective_units",
    "issued_at", "expires_at",
]


def check_capacity_evidence_vectors(fx: str) -> None:
    v = _load(fx, "capacity-evidence", "vectors.json")
    pc = v["projected_commitment"]
    # signing bytes are insertion-ordered (NOT JCS) in the declared struct order
    b = P.canonical_json_bytes([(k, pc[k]) for k in _PROJECTED_COMMITMENT_ORDER])
    _eq("capacity-evidence signing bytes", b.decode("utf-8"), v["expected_signing_bytes_utf8"])
    _eq("capacity-evidence signing digest",
        P.digest_hex_bytes(b), v["expected_signing_bytes_digest"])


_CCVP_TS = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def _ccvp_instant(v):
    """CCVP/1 Section 6.3: nanoseconds since the epoch, or None if `v` is not a
    timestamp in the CCSP/1 anchor.issued_at form naming a real instant."""
    if not isinstance(v, str):
        return None
    m = _CCVP_TS.match(v)
    if not m:
        return None
    y, mo, d, h, mi, se = (int(x) for x in m.groups()[:6])
    try:
        day = datetime.date(y, mo, d)
    except ValueError:
        return None
    if h > 23 or mi > 59 or se > 59:
        return None
    days = (day - datetime.date(1970, 1, 1)).days
    frac = int((m.group(7) or "").ljust(9, "0"))
    return ((days * 86400 + h * 3600 + mi * 60 + se) * 1_000_000_000) + frac


def _ccvp_issued_valid(cert) -> bool:
    """The Issued checks these vectors exercise: envelope present, conformance
    domain, anchor commitment recomputed, composite issuer signature over
    M'(SHA3(JCS(payload))) under the signer's two keys."""
    if not isinstance(cert, dict) or cert.get("schema") != "certcrypt-certificate":
        return False
    p, sigs = cert.get("payload"), cert.get("signatures")
    if not isinstance(p, dict) or not isinstance(sigs, list) or len(sigs) != 1:
        return False
    if p.get("system_id") != "certcrypt" or p.get("rules_version") != "rules/conformance":
        return False
    a = p["anchor"]
    if _ccvp_instant(a.get("issued_at")) is None:
        return False
    anchor_commitment = P.digest_hex_text(
        a["nonce_hex"] + P.digest_hex_bytes(P.jcs_canonicalize_bytes(a)))
    if anchor_commitment != p.get("anchor_commitment_digest_hex"):
        return False
    digest = P.digest_hex_bytes(P.jcs_canonicalize_bytes(p))
    if cert.get("payload_canon_digest_hex", digest) != digest:
        return False
    s = sigs[0]
    try:
        return _composite_verify_over_digest(
            digest, s, s["signer"]["pub_p256_b64"], s["signer"]["pub_mldsa_b64"])
    except Exception:
        return False


def _ccvp_fingerprint(signer) -> str:
    # CCVP/1 Section 8.1: SHA3-256(pub_p256_bytes || pub_mldsa_bytes).
    return P.digest_hex_bytes(
        base64.b64decode(signer["pub_p256_b64"]) + base64.b64decode(signer["pub_mldsa_b64"]))


def _ccvp_snapshot_conformant(cert) -> bool:
    """CCVP/1 Section 5.1 requirements 2-3 and Sections 6, 6.3, 7.1."""
    p = cert["payload"]
    snap = p.get("snapshot")
    if not isinstance(snap, dict):
        return False
    try:
        P.assert_context_snapshot_precondition(snap)
    except Exception:
        return False
    markers = [s for s in p["anchor"]["subjects"] if s["profile"] == "subject.context-snapshot/1"]
    if len(markers) != 1:
        return False
    local = P.digest_hex_bytes(P.jcs_canonicalize_bytes(snap))
    if markers[0]["commitment_digest_hex"] != P.digest_hex_text(p["anchor"]["nonce_hex"] + local):
        return False
    for k in ("context_set_id", "snapshot_id"):
        if not isinstance(snap.get(k), str) or not snap[k]:
            return False
    if _ccvp_instant(snap.get("issued_at")) is None or not isinstance(snap.get("entries"), list):
        return False
    for e in snap["entries"]:
        if not isinstance(e, dict):
            return False
        if not isinstance(e.get("issuer_id"), str) or not e["issuer_id"]:
            return False
        if not isinstance(e.get("pub_fingerprint_digest_hex"), str) or \
                not _HEX64_RE.match(e["pub_fingerprint_digest_hex"]):
            return False
        if not isinstance(e.get("status"), str) or _ccvp_instant(e.get("valid_from")) is None:
            return False
        for k in ("valid_to", "revoked_at"):
            if e.get(k) is not None and _ccvp_instant(e[k]) is None:
                return False
        if "kid" in e and not isinstance(e["kid"], str):
            return False
        if "roles" in e and not (isinstance(e["roles"], list)
                                 and all(isinstance(r, str) for r in e["roles"])):
            return False
        if "scope" in e:
            sc = e["scope"]
            if not isinstance(sc, dict):
                return False
            if "subject_profiles" in sc and not (
                    isinstance(sc["subject_profiles"], list)
                    and all(isinstance(x, str) for x in sc["subject_profiles"])):
                return False
    return True


def _ccvp_resolve(target, candidates) -> str:
    """CCVP/1 Sections 5-10, reimplemented from the specification."""
    if not _ccvp_issued_valid(target):
        return "consistency-unknown"
    ctx = target["payload"].get("context")
    if not isinstance(ctx, dict):
        return "consistency-unknown"
    ns_id, ns_fp, ns_set = (ctx.get("snapshot_issuer_id"),
                            ctx.get("snapshot_issuer_fingerprint_digest_hex"),
                            ctx.get("context_set_id"))
    if not isinstance(ns_id, str) or not isinstance(ns_set, str) or not ns_set \
            or not isinstance(ns_fp, str) or not _HEX64_RE.match(ns_fp):
        return "consistency-unknown"
    t_cert = _ccvp_instant(target["payload"]["anchor"]["issued_at"])

    conformant, non_conformant = [], []
    for s in candidates:
        if not _ccvp_issued_valid(s):
            continue
        p = s["payload"]
        is_snapshot = "snapshot" in p or any(
            x["profile"] == "subject.context-snapshot/1" for x in p["anchor"]["subjects"])
        signer = s["signatures"][0]["signer"]
        if not is_snapshot or signer["id"] != ns_id or _ccvp_fingerprint(signer) != ns_fp:
            continue
        snap = p.get("snapshot")
        if not isinstance(snap, dict) or snap.get("context_set_id") != ns_set:
            continue
        (conformant if _ccvp_snapshot_conformant(s) else non_conformant).append(snap)

    eligible = [s for s in conformant if _ccvp_instant(s["issued_at"]) <= t_cert]
    selected_at = max((_ccvp_instant(s["issued_at"]) for s in eligible), default=None)
    for snap in non_conformant:
        at = _ccvp_instant(snap.get("issued_at"))
        if at is not None and (at > t_cert or (selected_at is not None and at < selected_at)):
            continue
        return "consistency-unknown"
    if selected_at is None:
        return "consistency-unknown"
    tied = [s for s in eligible if _ccvp_instant(s["issued_at"]) == selected_at]
    if len({P.jcs_canonicalize_bytes(s) for s in tied}) > 1:
        return "consistency-unknown"

    sig = target["signatures"][0]
    fp = _ccvp_fingerprint(sig["signer"])
    profiles = [x["profile"] for x in target["payload"]["anchor"]["subjects"]]

    def applies(e) -> bool:
        if e["issuer_id"] != sig["signer"]["id"] or e["pub_fingerprint_digest_hex"] != fp:
            return False
        if "kid" in e and sig.get("kid") != e["kid"]:
            return False
        if e["status"] != "active" or _ccvp_instant(e["valid_from"]) > t_cert:
            return False
        if e.get("valid_to") is not None and not t_cert < _ccvp_instant(e["valid_to"]):
            return False
        if "roles" in e and "issuer" not in e["roles"]:
            return False
        sp = e.get("scope", {}).get("subject_profiles")
        if sp is not None and not any(pr in sp for pr in profiles):
            return False
        return True

    return "consistency-match" if any(applies(e) for e in tied[0]["entries"]) \
        else "consistency-mismatch"


def check_ccvp_consistency(fx: str) -> None:
    """CCVP/1 over signed certificates, reimplemented from the public rules.

    Deliberately independent of any SDK or toolkit: every certificate's
    Issued-validity is recomputed (anchor commitment and composite signature),
    every snapshot issuer is derived from its signature, and every outcome is
    resolved here from the specification and compared with the vector."""
    v = _load(fx, "ccvp-consistency", "vectors.json")
    certs = v["certificates"]
    for name, c in certs.items():
        _eq(f"ccvp issued_valid [{name}]", _ccvp_issued_valid(c["certificate"]), c["issued_valid"])
    for name, k in v["keys"].items():
        _eq(f"ccvp key fingerprint [{name}]",
            _ccvp_fingerprint({"pub_p256_b64": k["pub_p256_b64"],
                               "pub_mldsa_b64": k["pub_mldsa_b64"]}),
            k["composite_key_fingerprint_digest_hex"])

    seen = set()
    for case in v["cases"]:
        actual = _ccvp_resolve(certs[case["target"]]["certificate"],
                               [certs[n]["certificate"] for n in case["snapshots"]])
        _eq(f"ccvp resolution [{case['name']}]", actual, case["expected_outcome"])
        seen.add(case["expected_outcome"])

    # A vector set asserting one outcome only would pass against an
    # implementation that always returned it.
    for outcome in ("consistency-match", "consistency-mismatch", "consistency-unknown"):
        _eq(f"ccvp vectors expect {outcome}", outcome in seen, True)
    # The cases that pin the model rather than the arithmetic must stay.
    names = {c["name"] for c in v["cases"]}
    for required in ("namespace_impersonation_is_ignored", "namespace_impersonation_alone",
                     "scope_excludes_profile", "instant_not_string", "kid_in_entry_only",
                     "kid_in_signature_only", "target_not_issued_valid",
                     "tampered_snapshot_discarded", "non_conformant_snapshot_blocks"):
        _eq(f"ccvp vectors pin {required}", required in names, True)


def check_submission_set(fx: str) -> None:
    v = _load(fx, "submission-set", "vectors.json")
    art = _load(fx, "submission-set", "artifacts", "submission-set.json")
    no_id = {k: val for k, val in art.items() if k != "submission_set_id"}
    got = P.digest_hex_bytes(P.jcs_canonicalize_bytes(no_id))
    _eq("submission-set id (recompute over no-id view)", got, v["expected_submission_set_id"])
    # the artifact's own embedded id, if present, must also equal the recompute
    if "submission_set_id" in art:
        _eq("submission-set id (embedded == recompute)", art["submission_set_id"], got)


# ── external goldens: verify, don't regenerate ─────────────────────────────
# These embed signatures produced by the reference producer implementation with
# test keys (hedged ML-DSA-65 + composite, so verified rather than reproduced),
# plus the pinned system-domain public keys. Python verifies the deterministic envelope and that
# the embedded signatures validate; it does not reproduce a hedged signature.

def _composite_verify_over_digest(payload_digest_hex: str, sig_obj: dict,
                                  p256_pub_b64: str, mldsa_pub_b64: str) -> bool:
    """Verify a `composite-signature/1` composite (ECDSA-P256-SHA3-256 + ML-DSA-65, AND) over
    M' = composite_m_prime(alg, payload_digest_hex)."""
    m_prime = P.composite_m_prime(sig_obj["alg"], payload_digest_hex)
    comps = {s["alg"]: s for s in sig_obj["signatures"]}
    # ML-DSA-65 component
    mldsa = comps.get("ML-DSA-65")
    mldsa_ok = ML_DSA_65.verify(
        base64.b64decode(mldsa_pub_b64), m_prime, base64.b64decode(mldsa["sig_b64"])
    )
    # ECDSA-P256 component (raw r||s over SHA3-256(M'))
    p256 = comps.get("ECDSA-P256-SHA3-256")
    p256_ok = _p256_verify_raw_rs(
        base64.b64decode(p256_pub_b64),
        base64.b64decode(p256["sig_b64"]),
        m_prime,
    )
    return bool(mldsa_ok and p256_ok)


def _composite_verify_jcs(view_obj: dict, sig_obj: dict,
                          p256_pub_b64: str, mldsa_pub_b64: str) -> bool:
    """Composite over M'(SHA3(JCS(view))) — used where the signed payload is the
    JCS canonicalization of a view (the `independence_proof` no-sig view)."""
    return _composite_verify_over_digest(
        P.digest_hex_bytes(P.jcs_canonicalize_bytes(view_obj)),
        sig_obj, p256_pub_b64, mldsa_pub_b64,
    )


def _p256_verify_raw_rs(pub_sec1: bytes, raw_rs_64: bytes, message: bytes) -> bool:
    import hashlib
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        Prehashed, encode_dss_signature,
    )
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.exceptions import InvalidSignature
    if len(raw_rs_64) != 64:
        return False
    r = int.from_bytes(raw_rs_64[:32], "big")
    s = int.from_bytes(raw_rs_64[32:], "big")
    der = encode_dss_signature(r, s)
    digest = hashlib.sha3_256(message).digest()
    pub = _ec.EllipticCurvePublicKey.from_encoded_point(_ec.SECP256R1(), pub_sec1)
    try:
        pub.verify(der, digest, _ec.ECDSA(Prehashed(_hashes.SHA3_256())))
        return True
    except InvalidSignature:
        return False


def _proof_signing_view(proof: dict) -> dict:
    """The signed view of independence.proof/1 §10.13.1 (the view the reference
    proof producer signs and the reference verifier rebuilds). NOT "proof minus
    signature": the eight identity members plus `proof_id`, `anti_replay` and,
    only when present, `node_attestation`; `proof_digest` is EXCLUDED (it is
    computed over the whole proof AFTER the signature is attached). An absent
    `node_attestation` is omitted, never null, so JCS matches byte-for-byte."""
    view = {
        "proof_version": proof["proof_version"],
        "system_id": proof["system_id"],
        "rules_version": proof["rules_version"],
        "system_root_fingerprint": proof["system_root_fingerprint"],
        "proof_id": proof["proof_id"],
        "subtree_root": proof["subtree_root"],
        "closure_time": proof["closure_time"],
        "consumed_commitment_ids": proof["consumed_commitment_ids"],
        "settlement_ref": proof["settlement_ref"],
        "anti_replay": proof["anti_replay"],
    }
    if "node_attestation" in proof:
        view["node_attestation"] = proof["node_attestation"]
    return view


def check_independence_proof_signature(fx: str) -> None:
    v = _load(fx, "independence-proof-signature", "vectors.json")
    proof = v["proof"]
    ok = _composite_verify_jcs(
        _proof_signing_view(proof), proof["signature"],
        v["system_domain_p256_public_key_b64"],
        v["system_domain_mldsa_public_key_b64"],
    )
    _eq("independence-proof-signature composite verifies (AND)", ok, True)
    # The kid names no deployment: a neutral namespace plus the first 16 bytes of
    # SHA3-256 of the ML-DSA-65 public key it identifies.
    mldsa_pk = base64.b64decode(v["system_domain_mldsa_public_key_b64"])
    want_kid = "conformance:" + base64.b64encode(hashlib.sha3_256(mldsa_pk).digest()[:16]).decode()
    _eq("independence-proof-signature signing_kid", proof["signature"]["signing_kid"], want_kid)


# Level-1 binding signing bytes are INSERTION-ordered (NOT JCS), in this exact
# field order (capacity.evidence/1). The composite signs SHA3 of these.
_LEVEL1_BINDING_ORDER = [
    "system_id", "rules_version", "system_root_fingerprint",
    "authorized_role", "authorization_issuer_kid",
    "valid_from", "valid_until", "holder_key_set_root",
]


def _level1_binding_digest_hex(binding: dict) -> str:
    b = P.canonical_json_bytes([(k, binding[k]) for k in _LEVEL1_BINDING_ORDER])
    return P.digest_hex_bytes(b)


def check_capacity_evidence_golden(fx: str) -> None:
    g = _load(fx, "capacity-evidence", "golden-e2e.json")
    ev = g["evidence"]
    # (1) deterministic envelope: evidence_digest = SHA3(JCS(evidence))
    got = P.digest_hex_bytes(P.jcs_canonicalize_bytes(ev))
    _eq("capacity-evidence golden evidence_digest", got, g["expected_evidence_digest"])
    # (2) holder commitment signature verifies against the disclosed leaf key
    pc = ev["projected_commitment"]
    pc_bytes = P.canonical_json_bytes([(k, pc[k]) for k in _PROJECTED_COMMITMENT_ORDER])
    leaf_pk = base64.b64decode(ev["operation_key"]["public_key_b64"])
    _eq("capacity-evidence golden commitment signature verifies",
        ML_DSA_65.verify(leaf_pk, pc_bytes,
                         base64.b64decode(ev["commitment_signature_b64"])), True)
    # (3) Level-1 composite binding signature verifies against system-domain keys.
    #     The composite signs M'(SHA3(insertion-ordered L1 binding bytes)), NOT JCS.
    auth = ev["projected_authorization"]
    ok = _composite_verify_over_digest(
        _level1_binding_digest_hex(auth["level1_binding"]),
        auth["level1_signature"],
        g["system_domain_p256_public_key_b64"],
        g["system_domain_mldsa_public_key_b64"],
    )
    _eq("capacity-evidence golden L1 composite verifies (AND)", ok, True)
    # (4) operation-key Merkle membership -> holder_key_set_root
    ok_m = _verify_key_membership(ev["operation_key"], auth["holder_key_set_root"])
    _eq("capacity-evidence golden operation-key membership", ok_m, True)


def _verify_key_membership(disclosure: dict, expected_root: str) -> bool:
    pk = base64.b64decode(disclosure["public_key_b64"])
    cur = P.operation_key_leaf_hash(pk)
    sibs = disclosure["inclusion_proof"]
    idx = disclosure["leaf_index"]
    width = disclosure["tree_size"]
    si = 0
    level = 0
    while width > 1:
        is_right = ((idx >> level) & 1) == 1
        has_sib = is_right or (idx >> level) + 1 < width
        if has_sib:
            sib = sibs[si]; si += 1
            cur = (P.compute_node_hash(sib, cur) if is_right
                   else P.compute_node_hash(cur, sib))
        width = (width + 1) // 2
        level += 1
    return si == len(sibs) and cur == expected_root


def check_verification_package_golden(fx: str) -> None:
    g = _load(fx, "verification-package", "golden-e2e.json")
    pkg = g["package"]
    got = P.digest_hex_bytes(P.jcs_canonicalize_bytes(pkg))
    _eq("verification-package golden package_digest", got, g["expected_package_digest"])
    # embedded capacity-evidence commitment signature verifies against leaf key
    ce = pkg["capacity_evidence"]
    pc = ce["projected_commitment"]
    pc_bytes = P.canonical_json_bytes([(k, pc[k]) for k in _PROJECTED_COMMITMENT_ORDER])
    leaf_pk = base64.b64decode(ce["operation_key"]["public_key_b64"])
    _eq("verification-package golden commitment signature verifies",
        ML_DSA_65.verify(leaf_pk, pc_bytes,
                         base64.b64decode(ce["commitment_signature_b64"])), True)


# ── driver ───────────────────────────────────────────────────────────────
def check_key_derivation(fx: str) -> None:
    """Both composite components, re-derived from the seed by an INDEPENDENT
    implementation (hashlib + ecdsa + dilithium_py) rather than trusted.

    This is the point of the vector: if this Python and the Rust runtime agree
    starting only from the written rule, the rule is implementable. If they
    disagree, one of them is wrong and the fixture says which — instead of a
    signature failing months later with no explanation."""
    import hashlib, hmac
    from ecdsa import SigningKey, NIST256p

    def hkdf_sha3_256(ikm: bytes, info: bytes, length: int) -> bytes:
        # Extract with no salt: a zero-filled key of hash length (RFC 5869 §2.2).
        prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha3_256).digest()
        okm, block, counter = b"", b"", 1
        while len(okm) < length:
            block = hmac.new(prk, block + info + bytes([counter]),
                             hashlib.sha3_256).digest()
            okm += block
            counter += 1
        return okm[:length]

    v = _load(fx, "key-derivation", "vectors.json")
    n = NIST256p.order
    for vec in v["vectors"]:
        seed = bytes.fromhex(vec["seed_hex"])
        _eq(f"key-derivation[{vec['label']}].seed_len", len(seed), 32)

        # P-256: HKDF-SHA3-256 → 48 bytes → big-endian int → mod n (0 maps to 1).
        okm = hkdf_sha3_256(seed, b"certcrypt/composite/p256/v1", 48)
        scalar = int.from_bytes(okm, "big") % n or 1
        sk = SigningKey.from_secret_exponent(scalar, curve=NIST256p)
        vk = sk.get_verifying_key()
        _eq(f"key-derivation[{vec['label']}].p256_uncompressed",
            (b"\x04" + vk.to_string()).hex(),
            vec["p256_public_key_sec1_uncompressed_hex"])
        _eq(f"key-derivation[{vec['label']}].p256_compressed",
            vk.to_string("compressed").hex(),
            vec["p256_public_key_sec1_compressed_hex"])

        # ML-DSA-65: the seed IS the FIPS 204 xi, with no KDF in between.
        mldsa_pk, _ = ML_DSA_65.key_derive(seed)
        _eq(f"key-derivation[{vec['label']}].mldsa65",
            base64.b64encode(mldsa_pk).decode(),
            vec["mldsa65_public_key_b64"])

        # The composite root fingerprint over both public keys, classical first.
        # Recomputing it is what keeps a swapped root from passing as published.
        fp = hashlib.sha3_256(b"\x04" + vk.to_string() + mldsa_pk).hexdigest()
        _eq(f"key-derivation[{vec['label']}].composite_root_fingerprint",
            fp, vec["composite_root_fingerprint"])


def check_level1_binding(fx: str) -> None:
    """The Level-1 binding signs INSERTION-ORDERED bytes, not JCS.

    Two assertions, and the second matters as much as the first: the declared
    order reproduces the pinned digest, AND applying JCS produces a different
    one. Without the negative half an implementation could pass by accident on a
    sample whose keys happen to already be sorted."""
    v = _load(fx, "level1-binding", "vectors.json")
    order = ["system_id", "rules_version", "system_root_fingerprint",
             "authorized_role", "authorization_issuer_kid",
             "valid_from", "valid_until", "holder_key_set_root"]
    for vec in v["vectors"]:
        b = vec["binding"]
        _eq(f"level1-binding[{vec['label']}].field_order", list(b.keys()), order)

        canon = P.canonical_json_bytes([(k, b[k]) for k in order])
        _eq(f"level1-binding[{vec['label']}].signing_bytes",
            canon.decode("utf-8"), vec["expected_signing_bytes_utf8"])
        _eq(f"level1-binding[{vec['label']}].digest",
            P.digest_hex_bytes(canon), vec["expected_signing_bytes_digest"])

        # The tripwire: JCS must NOT reproduce the signing digest.
        jcs = P.digest_hex_bytes(P.jcs_canonicalize_bytes(b))
        _eq(f"level1-binding[{vec['label']}].jcs_differs",
            jcs, vec["expected_digest_if_jcs_wrongly_applied"])
        if jcs == vec["expected_signing_bytes_digest"]:
            _eq(f"level1-binding[{vec['label']}].jcs_must_differ", jcs, "<a different digest>")


def check_rules_domain(fx: str) -> None:
    """The rules-domain table: TTL and settlement profile per domain.

    Nothing to recompute here — the table IS the specification. What the check
    enforces is that it stays coherent: every domain answers both columns or
    neither, the TTLs are the two documented values, and an unknown domain
    answers null on both so an implementation cannot invent a fallback."""
    v = _load(fx, "rules-domain", "vectors.json")
    seen = set()
    for row in v["vectors"]:
        rv = row["rules_version"]
        _eq(f"rules-domain[{rv}].unique", rv in seen, False)
        seen.add(rv)

        ttl, prof = row["commitment_ttl_seconds"], row["settlement_profile_id"]
        # Both or neither: a domain with a TTL but no profile would admit
        # material that nothing knows how to settle.
        _eq(f"rules-domain[{rv}].both_or_neither",
            (ttl is None) == (prof is None), True)
        if ttl is not None:
            _eq(f"rules-domain[{rv}].ttl_is_known_value",
                ttl in (86_400, 2_592_000), True)

    _eq("rules-domain.covers_unknown",
        any(r["commitment_ttl_seconds"] is None for r in v["vectors"]), True)


def check_operator_receipt(fx: str) -> None:
    """The operator receipt: id derivation, JCS canonicalization, and the
    ML-DSA-65 signature actually verified — not just its bytes compared.

    Also re-derives operator_id from the public key: a receipt whose signature
    checks out under an unrelated key would otherwise pass as this operator."""
    v = _load(fx, "operator-receipt", "vectors.json")
    for vec in v["vectors"]:
        pk = base64.b64decode(vec["operator_public_key_b64"])
        seed = bytes.fromhex(vec["operator_seed_hex"])

        # The published key must be the one that seed derives.
        derived_pk, _ = ML_DSA_65.key_derive(seed)
        _eq(f"operator-receipt[{vec['label']}].pk_from_seed",
            base64.b64encode(derived_pk).decode(), vec["operator_public_key_b64"])

        # op: + base64(SHA3-256(pk)[0:16]), no padding.
        oid = "op:" + base64.b64encode(
            hashlib.sha3_256(pk).digest()[:16]).decode().rstrip("=")
        _eq(f"operator-receipt[{vec['label']}].operator_id",
            oid, vec["receipt"]["operator_id"])

        r = vec["receipt"]
        view = {k: r[k] for k in ("receipt_version", "operator_id",
                                  "submission_set_id", "system_id",
                                  "rules_version", "issued_at")}
        canon = P.jcs_canonicalize_bytes(view)
        _eq(f"operator-receipt[{vec['label']}].signing_bytes",
            canon.decode("utf-8"), vec["expected_signing_bytes_utf8"])
        _eq(f"operator-receipt[{vec['label']}].signing_digest",
            P.digest_hex_bytes(canon), vec["expected_signing_bytes_digest"])

        sig = base64.b64decode(r["signature"]["signature_b64"])
        _eq(f"operator-receipt[{vec['label']}].signature_verifies",
            ML_DSA_65.verify(pk, canon, sig), True)


def check_manifest_resolution(fx: str) -> None:
    """Manifest resolution: the lookup table, and the half-open activity window.

    Nothing cryptographic to recompute — this vector pins BEHAVIOUR, which is
    why it exists (see its `why_this_is_a_primitive`). What the oracle enforces
    is that the stated cases stay consistent with the stated view: every case
    that expects a resolution names a pair the view actually holds, every case
    that expects a miss names one it does not, and each activity case agrees
    with the half-open rule computed from the entry's own window. A vector whose
    cases contradict its own manifest would teach an implementation the wrong
    contract with no signature to catch it."""
    from datetime import datetime

    def _t(iso: str) -> datetime:
        return datetime.fromisoformat(iso.replace("Z", "+00:00"))

    v = _load(fx, "manifest-resolution", "vectors.json")
    view = {
        ver["system_root_fingerprint"]: {e["kid"]: e for e in ver["entries"]}
        for ver in v["manifest_view"]["versions"]
    }

    for c in v["resolution_cases"]:
        fp, kid = c["fingerprint"], c["kid"]
        if fp not in view:
            expected = "unknown_fingerprint"
        elif kid not in view[fp]:
            expected = "unknown_kid"
        else:
            expected = "resolved"
        _eq(f"manifest-resolution[{c['name']}].outcome", c["expected_outcome"], expected)
        if expected == "resolved":
            _eq(f"manifest-resolution[{c['name']}].kid", c.get("expected_kid"), kid)

    # The cross-version case is the load-bearing one: it must name a kid that
    # exists SOMEWHERE but not under the queried fingerprint. Without that, the
    # case would be an ordinary unknown-kid and would not catch a resolver keyed
    # on kid alone.
    cross = [c for c in v["resolution_cases"] if "cross-version" in c["name"]]
    _eq("manifest-resolution.has_cross_version_case", len(cross), 1)
    for c in cross:
        elsewhere = any(c["kid"] in kids for fp, kids in view.items() if fp != c["fingerprint"])
        _eq(f"manifest-resolution[{c['name']}].kid_exists_elsewhere", elsewhere, True)
        _eq(f"manifest-resolution[{c['name']}].absent_here",
            c["kid"] not in view.get(c["fingerprint"], {}), True)

    for c in v["fingerprint_known_cases"]:
        _eq(f"manifest-resolution.fingerprint_known[{c['fingerprint'][:8]}]",
            c["expected_known"], c["fingerprint"] in view)

    entries = {k: e for kids in view.values() for k, e in kids.items()}
    for c in v["activity_cases"]:
        e = entries[c["kid"]]
        t = _t(c["reference_time"])
        # Half-open: valid_from <= t < valid_until.
        active = _t(e["valid_from"]) <= t < _t(e["valid_until"])
        _eq(f"manifest-resolution.activity[{c['name']}]", c["expected_active"], active)
        # An entry in the view resolves regardless of its window.
        if "expected_resolution" in c:
            _eq(f"manifest-resolution.activity[{c['name']}].still_resolves",
                c["expected_resolution"], "resolved")

    # The boundary cases must actually be present: a vector that lost them would
    # still pass every check above while no longer pinning the half-open rule.
    bounds = {c["reference_time"] for c in v["activity_cases"]}
    _eq("manifest-resolution.pins_valid_from_boundary",
        any(_t(b) == _t(entries["system-domain-kid-1"]["valid_from"]) for b in bounds), True)
    _eq("manifest-resolution.pins_valid_until_boundary",
        any(_t(b) == _t(entries["system-domain-kid-1"]["valid_until"]) for b in bounds), True)


def check_submission_set_limits(fx: str) -> None:
    """The member cap and the system constants.

    A table, like rules-domain: the values ARE the specification. The oracle
    enforces internal coherence — that the cases agree with the declared cap on
    both sides of it, that the boundary and its neighbour are both present, and
    that the constants match the ones every other vector in this suite carries.
    That last cross-check is the one with teeth: a constant pinned here that
    disagreed with the bytes pinned elsewhere would be a contract at war with
    itself."""
    v = _load(fx, "submission-set-limits", "vectors.json")
    cap = v["member_cap"]["max_submission_set_members"]

    for c in v["cardinality_cases"]:
        n = c["member_count"]
        expected = "admitted" if 1 <= n <= cap else "rejected"
        _eq(f"submission-set-limits[{c['name']}]", c["expected_outcome"], expected)

    counts = {c["member_count"] for c in v["cardinality_cases"]}
    _eq("submission-set-limits.pins_the_boundary", cap in counts, True)
    _eq("submission-set-limits.pins_one_over", cap + 1 in counts, True)
    _eq("submission-set-limits.pins_empty", 0 in counts, True)

    # The system_id pinned here must be the one the other vectors sign.
    sid = v["system_constants"]["system_id"]["value"]
    receipt = _load(fx, "operator-receipt", "vectors.json")
    for vec in receipt["vectors"]:
        _eq(f"submission-set-limits.system_id_matches_receipt[{vec['label']}]",
            vec["receipt"]["system_id"], sid)
    leaf = _load(fx, "settlement-preimages", "vectors.json")
    _eq("submission-set-limits.system_id_matches_leaf",
        leaf["leaf_preimage"]["preimage"]["system_id"], sid)

    for c in v["system_constant_cases"]:
        declared = v["system_constants"][c["field"]]["value"]
        expected = "accepted" if c["candidate"] == declared else "rejected"
        _eq(f"submission-set-limits.constant[{c['name']}]", c["expected_outcome"], expected)


def check_issuer_key_derivation(fx: str) -> None:
    """The issuer's composite signing key, re-derived from the seed alone.

    Every public key is recomputed with an independent stack (hashlib + ecdsa +
    dilithium_py) from the written rule, never copied from the file. The key-id
    cases then pin the property the family exists for: the id is a label, so
    the same seed under any id gives the same two public keys. The coverage
    checks keep a shorter file from passing while no longer fixing that."""
    from ecdsa import SigningKey, NIST256p

    v = _load(fx, "issuer-key-derivation", "vectors.json")
    _eq("issuer-key-derivation.profile", v["profile"], "issuer-key-derivation/1")
    n = NIST256p.order

    def derive(master: bytes) -> dict:
        material = hashlib.sha3_256(master + b"issuer-cert-key/p256").digest()
        scalar = int.from_bytes(material, "big") % (n - 1) + 1
        vk = SigningKey.from_secret_exponent(scalar, curve=NIST256p).get_verifying_key()
        xi = hashlib.sha3_256(master + b"issuer-cert-key/mldsa").digest()
        mldsa_pk, _ = ML_DSA_65._keygen_internal(xi)
        return {
            "material": material.hex(),
            "scalar": scalar.to_bytes(32, "big").hex(),
            "p256": base64.b64encode(b"\x04" + vk.to_string()).decode("ascii"),
            "xi": xi.hex(),
            "mldsa": base64.b64encode(mldsa_pk).decode("ascii"),
        }

    keys_by_seed: dict[str, dict] = {}
    for vec in v["vectors"]:
        tag = f"issuer-key-derivation[{vec['name']}]"
        master = bytes.fromhex(vec["master_seed_hex"])
        _eq(f"{tag}.seed_len", len(master), 32)
        k = keys_by_seed.setdefault(vec["master_seed_hex"], derive(master))
        _eq(f"{tag}.p256_material", k["material"], vec["expected_p256_material_hex"])
        _eq(f"{tag}.p256_scalar", k["scalar"], vec["expected_p256_scalar_hex"])
        _eq(f"{tag}.pub_p256", k["p256"], vec["expected_pub_p256_b64"])
        _eq(f"{tag}.mldsa_xi", k["xi"], vec["expected_mldsa_xi_hex"])
        _eq(f"{tag}.pub_mldsa", k["mldsa"], vec["expected_pub_mldsa_b64"])
        pks = [
            ML_DSA_65._keygen_internal(
                hashlib.sha3_256(master + f"op-key/{i}".encode("utf-8")).digest())[0]
            for i in range(vec["tree_size"])
        ]
        root = P.holder_key_set_root(pks)
        _eq(f"{tag}.root", root, vec["expected_holder_key_set_root"])
        _eq(f"{tag}.default_key_id", f"issuer:{root[:32]}", vec["expected_default_key_id"])

    for case in v["key_id_cases"]:
        tag = f"issuer-key-derivation.key_id[{case['name']}]"
        k = keys_by_seed.get(case["master_seed_hex"]) or derive(bytes.fromhex(case["master_seed_hex"]))
        _eq(f"{tag}.pub_p256", case["expected_pub_p256_b64"], k["p256"])
        _eq(f"{tag}.pub_mldsa", case["expected_pub_mldsa_b64"], k["mldsa"])

    # Coverage: several seeds, several tree sizes per seed, one seed whose
    # default key ids differ while its key does not, and key-id cases that
    # include a non-default label.
    seeds = {vec["master_seed_hex"] for vec in v["vectors"]}
    _eq("issuer-key-derivation.pins_several_seeds", len(seeds) >= 3, True)
    sizes = {vec["tree_size"] for vec in v["vectors"]}
    _eq("issuer-key-derivation.pins_several_tree_sizes", len(sizes) >= 3, True)
    _eq("issuer-key-derivation.pins_default_id_moves_key_does_not", any(
        len({x["expected_default_key_id"] for x in v["vectors"] if x["master_seed_hex"] == s}) > 1
        and len({x["expected_pub_p256_b64"] for x in v["vectors"] if x["master_seed_hex"] == s}) == 1
        for s in seeds), True)
    defaults = {vec["expected_default_key_id"] for vec in v["vectors"]}
    _eq("issuer-key-derivation.pins_a_non_default_key_id",
        any(c["issuer_key_id"] not in defaults for c in v["key_id_cases"]), True)


def check_artifact_shape(fx: str) -> None:
    """The field sets of the signed preimages.

    The oracle's job here is to prove the declared field sets are the REAL ones,
    by checking each against the artifact the suite already pins bytes for. A
    shape vector that drifted from the byte vectors would be worse than no shape
    vector: it would authorize the wrong object with the suite's own authority."""
    v = _load(fx, "artifact-shape", "vectors.json")
    by_name = {a["artifact"]: a for a in v["artifacts"]}

    for a in v["artifacts"]:
        _eq(f"artifact-shape[{a['artifact']}].count_matches_list",
            a["field_count"], len(a["fields"]))
        _eq(f"artifact-shape[{a['artifact']}].fields_unique",
            len(set(a["fields"])), len(a["fields"]))

    # level1-binding: the declared set must be the keys of the pinned binding.
    l1 = _load(fx, "level1-binding", "vectors.json")
    declared = by_name["capacity.holder-authorization/1 — Level-1 binding"]["fields"]
    for vec in l1["vectors"]:
        got = list(json.loads(vec["expected_signing_bytes_utf8"]).keys())
        _eq(f"artifact-shape.level1_matches_bytes[{vec.get('label', '?')}]", got, declared)

    # capacity-evidence: same, against the pinned projected commitment.
    ev = _load(fx, "capacity-evidence", "vectors.json")
    declared = by_name["capacity.evidence/1 — projected commitment"]["fields"]
    got = list(json.loads(ev["expected_signing_bytes_utf8"]).keys())
    _eq("artifact-shape.capacity_evidence_matches_bytes", got, declared)

    # operator-receipt: JCS sorts, so compare as a SET, and confirm the
    # signature is excluded from the signed view but present on the receipt.
    rc = _load(fx, "operator-receipt", "vectors.json")
    spec = by_name["operator.receipt/1"]
    for vec in rc["vectors"]:
        got = set(json.loads(vec["expected_signing_bytes_utf8"]).keys())
        _eq(f"artifact-shape.receipt_matches_bytes[{vec['label']}]", got, set(spec["fields"]))
        for excluded in spec["excluded_from_signing"]:
            _eq(f"artifact-shape.receipt_excludes[{vec['label']}].{excluded}",
                excluded in got, False)
            _eq(f"artifact-shape.receipt_carries[{vec['label']}].{excluded}",
                excluded in vec["receipt"], True)

    # settlement preimages: against the bytes pinned in their own vector.
    sp = _load(fx, "settlement-preimages", "vectors.json")
    for key, name in (("leaf_preimage", "settlement leaf preimage (ccab1-leaf)"),
                      ("batch_binding_preimage", "settlement batch-binding preimage (ccab1)")):
        got = list(json.loads(sp[key]["expected_bytes_utf8"]).keys())
        _eq(f"artifact-shape.{key}_matches_bytes", got, by_name[name]["fields"])
        _eq(f"artifact-shape.{key}_matches_field_order", got, sp[key]["field_order"])


def check_settlement_preimages(fx: str) -> None:
    """The settlement leaf and batch-binding preimages, recomputed.

    Every value is recomputed from the preimage objects the vector declares:
    the insertion-ordered bytes, the leaf hash with its 0x00 domain prefix, the
    batch-binding digest and memo — plus both JCS tripwires, so the vector's
    claim about what the wrong canonicalization produces is itself verified.

    Then the cross-check that gives this vector its authority: the same values
    must appear in the P001 conformance fixture. These preimages are P001's own;
    if the two ever disagree, one of them is lying about the contract."""
    v = _load(fx, "settlement-preimages", "vectors.json")

    def ordered(obj) -> bytes:
        # Insertion-ordered compact JSON — what Rust's serde emits, and what
        # these artifacts sign. NOT JCS.
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    lp = v["leaf_preimage"]
    _eq("settlement-preimages.leaf_field_order", list(lp["preimage"].keys()), lp["field_order"])
    lb = ordered(lp["preimage"])
    _eq("settlement-preimages.leaf_bytes", lb.decode("utf-8"), lp["expected_bytes_utf8"])
    _eq("settlement-preimages.leaf_hash",
        hashlib.sha3_256(b"\x00" + lb).hexdigest(), lp["expected_leaf_hash"])
    # The tripwires: what the two natural wrong guesses actually produce.
    _eq("settlement-preimages.leaf_jcs_tripwire",
        hashlib.sha3_256(b"\x00" + P.jcs_canonicalize_bytes(lp["preimage"])).hexdigest(),
        lp["tripwire_if_jcs_used"])
    _eq("settlement-preimages.leaf_no_prefix_tripwire",
        hashlib.sha3_256(lb).hexdigest(), lp["tripwire_if_domain_prefix_omitted"])
    # A tripwire equal to the real value would pin nothing.
    _eq("settlement-preimages.leaf_tripwires_differ",
        len({lp["expected_leaf_hash"], lp["tripwire_if_jcs_used"],
             lp["tripwire_if_domain_prefix_omitted"]}), 3)

    bb = v["batch_binding_preimage"]
    _eq("settlement-preimages.bbp_field_order", list(bb["preimage"].keys()), bb["field_order"])
    bbb = ordered(bb["preimage"])
    _eq("settlement-preimages.bbp_bytes", bbb.decode("utf-8"), bb["expected_bytes_utf8"])
    digest = hashlib.sha3_256(bbb).hexdigest()
    _eq("settlement-preimages.bbp_digest", digest, bb["expected_digest"])
    _eq("settlement-preimages.bbp_memo", "ccab1:" + digest, bb["expected_memo"])
    _eq("settlement-preimages.bbp_jcs_tripwire",
        hashlib.sha3_256(P.jcs_canonicalize_bytes(bb["preimage"])).hexdigest(),
        bb["tripwire_if_jcs_used"])
    _eq("settlement-preimages.bbp_tripwire_differs",
        bb["expected_digest"] != bb["tripwire_if_jcs_used"], True)

    # Cross-check against P001: same preimages, same digests.
    p001 = os.path.join(fx, "conformance", "P001", "artifacts", "settlement-material.json")
    if os.path.exists(p001):
        with open(p001, encoding="utf-8") as fh:
            sm = json.load(fh)
        sap = sm["submission_assignment_proof"]
        _eq("settlement-preimages.p001_leaf_preimage", sap["leaf_preimage"], lp["preimage"])
        _eq("settlement-preimages.p001_leaf_hash", sap["leaf_hash"], lp["expected_leaf_hash"])
        _eq("settlement-preimages.p001_memo",
            sm["settlement_action"]["memo"], bb["expected_memo"])
        _eq("settlement-preimages.p001_settlement_root",
            sm["batch_manifest"]["settlement_root"], bb["preimage"]["settlement_root"])


def check_composite_m_prime(fx: str) -> None:
    """The composite M' framing, recomputed from each vector's own inputs.

    Every value here is derived, not trusted: the bytes, their length and their
    digest all come from re-running the construction the vector states in prose.
    A vector whose pinned bytes did not match its own stated rule would teach an
    implementation the wrong framing with the suite's authority behind it.

    Also enforced, because they are the properties the framing exists for: the
    profile must actually change M' (otherwise a signature is reinterpretable
    across profiles), and the separators must be NUL bytes rather than text."""
    v = _load(fx, "composite-m-prime", "vectors.json")
    prefix = b"CERTCRYPT-Composite-Signature-v1"

    seen_by_digest: dict[str, set[str]] = {}
    for vec in v["vectors"]:
        label = vec["label"]
        alg, digest = vec["composite_alg_id"], vec["payload_canon_digest_hex"]
        m = prefix + b"\x00" + alg.encode() + b"\x00" + digest.encode()

        _eq(f"composite-m-prime[{label}].bytes", m.hex(), vec["expected_m_prime_hex"])
        _eq(f"composite-m-prime[{label}].len", len(m), vec["expected_m_prime_len"])
        _eq(f"composite-m-prime[{label}].digest",
            hashlib.sha3_256(m).hexdigest(), vec["expected_m_prime_sha3_256"])

        # The digest travels as lowercase hex TEXT. Raw bytes would be half as long.
        _eq(f"composite-m-prime[{label}].digest_is_lowercase_hex",
            digest == digest.lower() and len(digest) == 64, True)
        # Exactly two separators, and nothing after the digest.
        _eq(f"composite-m-prime[{label}].separator_count", m.count(b"\x00"), 2)
        _eq(f"composite-m-prime[{label}].ends_with_digest",
            m.endswith(digest.encode()), True)
        _eq(f"composite-m-prime[{label}].starts_with_prefix", m.startswith(prefix), True)

        seen_by_digest.setdefault(digest, set()).add(m.hex())

    # The load-bearing property: one payload digest under two profiles must give
    # two different M'. A vector set that lost that case would stop pinning the
    # reason the profile is in the framing at all.
    multi = [d for d, ms in seen_by_digest.items() if len(ms) > 1]
    _eq("composite-m-prime.profile_changes_m_prime", len(multi) >= 1, True)


_COMPOSITE_LAYOUT = {
    "certcrypt-composite-p256-mldsa65-v1": [
        ("ECDSA-P256-SHA3-256", {"alg", "encoding", "low_s", "sig_b64"}, {"encoding": "raw-rs-64", "low_s": True}),
        ("ML-DSA-65", {"alg", "sig_b64"}, {}),
    ],
    "certcrypt-composite-ed25519-mldsa65-v1": [
        ("Ed25519", {"alg", "sig_b64"}, {}),
        ("ML-DSA-65", {"alg", "sig_b64"}, {}),
    ],
}


def _composite_layout_ok(expected_alg: str, sig, classical_key_b64: str, mldsa_key_b64: str) -> bool:
    """composite-signature/1 §6 step 3, §8, §9, written from the spec: the exact
    object, components and fixed values of the profile, and the one encoding of
    each key."""
    layout = _COMPOSITE_LAYOUT.get(expected_alg)
    if layout is None or not isinstance(sig, dict) or set(sig) != {"alg", "mode", "signatures"}:
        return False
    if sig["alg"] != expected_alg or sig["mode"] != "AND":
        return False
    comps = sig["signatures"]
    if not isinstance(comps, list) or len(comps) != len(layout):
        return False
    for comp, (alg, members, fixed) in zip(comps, layout):
        if not isinstance(comp, dict) or comp.get("alg") != alg or set(comp) != members:
            return False
        if any(comp[k] != val or type(comp[k]) is not type(val) for k, val in fixed.items()):
            return False
    ck = base64.b64decode(classical_key_b64)
    if layout[0][0] == "ECDSA-P256-SHA3-256":
        if len(ck) != 65 or ck[0] != 0x04:
            return False
    elif len(ck) != 32:
        return False
    return len(base64.b64decode(mldsa_key_b64)) == 1952


def check_composite_verification(fx: str) -> None:
    """The composite verification table: recompute what each case really is.

    The oracle does not take a case's label for its word. For every entry it
    re-derives the structural facts from the signature itself — which components
    are present, whether the declared profile matches, whether the mode is AND —
    and asserts the stated outcome follows from them. Where the case is meant to
    fail cryptographically, it VERIFIES the components against the pinned keys and
    asserts the expected half actually fails.

    That matters because this vector's whole value is in the negatives: a case
    labelled `tampered` whose signature still verified would teach an
    implementation that a forged signature is acceptable, with the suite's
    authority behind it."""
    v = _load(fx, "composite-verification", "vectors.json")
    digest = v["payload_canon_digest_hex"]
    p256_pub = v["system_domain_p256_public_key_b64"]
    mldsa_pub = v["system_domain_mldsa_public_key_b64"]

    # The table is derived from the independence-proof golden: same keys, the
    # digest of that proof's signing view, and its signature as the valid case.
    # A regenerated golden with a stale table fails here rather than leaving two
    # vectors that disagree about which signature is the real one.
    g = _load(fx, "independence-proof-signature", "vectors.json")
    _eq("composite-verification.p256_key == golden",
        p256_pub, g["system_domain_p256_public_key_b64"])
    _eq("composite-verification.mldsa_key == golden",
        mldsa_pub, g["system_domain_mldsa_public_key_b64"])
    _eq("composite-verification.digest == golden signing view",
        digest, P.digest_hex_bytes(P.jcs_canonicalize_bytes(_proof_signing_view(g["proof"]))))
    # The composite object is the golden proof signature without the member the
    # proof adds around it (`signing_kid`, independence.proof/1 §10.13).
    _eq("composite-verification.valid == golden signature",
        next(c["signature"] for c in v["cases"] if c["label"] == "valid"),
        {k: g["proof"]["signature"][k] for k in ("alg", "mode", "signatures")})

    saw_valid = False
    for case in v["cases"]:
        label = case["label"]
        sig = case["signature"]
        expected_alg = case["expected_composite_alg_id"]
        key_b64 = case.get("classical_public_key_b64", p256_pub)
        structurally_ok = _composite_layout_ok(expected_alg, sig, key_b64, mldsa_pub)

        if case["expected_outcome"] == "accepted":
            saw_valid = True
            _eq(f"composite-verification[{label}].structurally_ok", structurally_ok, True)
            # A case claiming acceptance must actually verify, both halves.
            _eq(f"composite-verification[{label}].verifies",
                _composite_verify_over_digest(digest, sig, p256_pub, mldsa_pub), True)
            continue

        # Every other case must be refusable. Either the structure already rules
        # it out, or the cryptography must reject it — never neither.
        if structurally_ok:
            _eq(f"composite-verification[{label}].crypto_rejects",
                _composite_verify_over_digest(digest, sig, p256_pub, mldsa_pub), False)
        else:
            _eq(f"composite-verification[{label}].refused_structurally", structurally_ok, False)

        # A negative case must state WHY, so an implementation can pin the reason
        # and not merely the fact of failing.
        _eq(f"composite-verification[{label}].has_reason", "expected_reason" in case, True)

    _eq("composite-verification.has_a_valid_case", saw_valid, True)
    # Without the PQC-floor case the vector loses the one refusal no cryptographic
    # check can make for you.
    _eq("composite-verification.pins_the_pqc_floor",
        any(c["label"] == "missing-mldsa-component" for c in v["cases"]), True)


# ── ECDSA P-256, RFC 6979, written out ─────────────────────────────────────
# The author script signs with python-ecdsa. This oracle does not: it carries its
# own RFC 6979 nonce derivation and its own curve arithmetic, small enough to read
# against the RFC, and proves them on the RFC's own published example before
# trusting them with the vectors. The resulting signatures are then verified by
# a third stack (`cryptography`/OpenSSL).

_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_A = _P256_P - 3
_P256_N_ = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


def _p256_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    (x1, y1), (x2, y2) = a, b
    if x1 == x2 and (y1 + y2) % _P256_P == 0:
        return None
    if a == b:
        lam = (3 * x1 * x1 + _P256_A) * pow(2 * y1, -1, _P256_P) % _P256_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P256_P) % _P256_P
    x3 = (lam * lam - x1 - x2) % _P256_P
    return x3, (lam * (x1 - x3) - y1) % _P256_P


def _p256_mul(k: int, pt=_P256_G):
    acc = None
    while k:
        if k & 1:
            acc = _p256_add(acc, pt)
        pt = _p256_add(pt, pt)
        k >>= 1
    return acc


def _rfc6979_k(x: int, h1: bytes, hashfunc) -> int:
    """RFC 6979 §3.2 for a 256-bit order, with HMAC over `hashfunc`."""
    import hmac as _hmac
    n = _P256_N_
    hlen = hashfunc().digest_size
    x_oct = x.to_bytes(32, "big")
    h_oct = (int.from_bytes(h1, "big") % n).to_bytes(32, "big")  # bits2octets
    v = b"\x01" * hlen
    k = b"\x00" * hlen
    k = _hmac.new(k, v + b"\x00" + x_oct + h_oct, hashfunc).digest()
    v = _hmac.new(k, v, hashfunc).digest()
    k = _hmac.new(k, v + b"\x01" + x_oct + h_oct, hashfunc).digest()
    v = _hmac.new(k, v, hashfunc).digest()
    while True:
        t = b""
        while len(t) < 32:
            v = _hmac.new(k, v, hashfunc).digest()
            t += v
        cand = int.from_bytes(t[:32], "big")
        if 1 <= cand < n:
            return cand
        k = _hmac.new(k, v + b"\x00", hashfunc).digest()
        v = _hmac.new(k, v, hashfunc).digest()


def _ecdsa_sign_rfc6979(x: int, h: bytes, hashfunc) -> tuple[int, int, int]:
    """Returns (k, r, s) before low-s normalization."""
    n = _P256_N_
    k = _rfc6979_k(x, h, hashfunc)
    r = _p256_mul(k)[0] % n
    s = pow(k, -1, n) * (int.from_bytes(h, "big") + r * x) % n
    return k, r, s


def check_ecdsa_p256_deterministic(fx: str) -> None:
    """Every signature re-derived from its key and message alone.

    The RFC 6979 code above is first held to RFC 6979 Appendix A.2.5 (P-256,
    SHA-256, messages "sample" and "test"), so a mistake in it cannot agree with
    the vectors by accident. It then recomputes each key's public point, the
    prehash, the nonce and the signature with H = SHA3-256, and `cryptography`
    verifies the result. The coverage checks keep a shorter file from passing
    while no longer pinning both low-s branches and both key families."""
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF
    from cryptography.hazmat.primitives import hashes as _hashes

    n = _P256_N_
    # RFC 6979 A.2.5: the published example, before any vector is trusted.
    x_rfc = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    for msg, k_exp, r_exp, s_exp in [
        (b"sample",
         0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60,
         0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716,
         0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8),
        (b"test",
         0xD16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0,
         0xF1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367,
         0x019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083),
    ]:
        got = _ecdsa_sign_rfc6979(x_rfc, hashlib.sha256(msg).digest(), hashlib.sha256)
        _eq(f"ecdsa-p256-deterministic.rfc6979_a25[{msg.decode()}]", got, (k_exp, r_exp, s_exp))

    v = _load(fx, "ecdsa-p256-deterministic", "vectors.json")
    _eq("ecdsa-p256-deterministic.profile", v["profile"], "ecdsa-p256-deterministic/1")

    scalars: dict[str, int] = {}
    pubs: dict[str, bytes] = {}
    for ref, k in v["keys"].items():
        tag = f"ecdsa-p256-deterministic.key[{ref}]"
        if k["source"] == "issuer-key-derivation":
            material = hashlib.sha3_256(bytes.fromhex(k["master_seed_hex"]) + b"issuer-cert-key/p256").digest()
            d = int.from_bytes(material, "big") % (n - 1) + 1
        elif k["source"] == "key-derivation":
            okm = _HKDF(algorithm=_hashes.SHA3_256(), length=48, salt=None,
                        info=b"certcrypt/composite/p256/v1").derive(bytes.fromhex(k["seed_hex"]))
            d = int.from_bytes(okm, "big") % n or 1
        elif k["source"] == "scalar":
            d = int(k["scalar_hex"], 16)
        else:
            _eq(f"{tag}.source", k["source"], "a known source")
            continue
        _eq(f"{tag}.scalar", d.to_bytes(32, "big").hex(), k["scalar_hex"])
        _eq(f"{tag}.in_range", 1 <= d < n, True)
        px, py = _p256_mul(d)
        pub = b"\x04" + px.to_bytes(32, "big") + py.to_bytes(32, "big")
        _eq(f"{tag}.pub_p256", base64.b64encode(pub).decode("ascii"), k["expected_pub_p256_b64"])
        scalars[ref], pubs[ref] = d, pub

    def signed(ref: str, message: bytes) -> tuple[str, int, bool, bytes]:
        h = hashlib.sha3_256(message).digest()
        k, r, s = _ecdsa_sign_rfc6979(scalars[ref], h, hashlib.sha3_256)
        high = s > (n >> 1)
        if high:
            s = n - s
        return h.hex(), k, high, r.to_bytes(32, "big") + s.to_bytes(32, "big")

    for vec in v["vectors"]:
        tag = f"ecdsa-p256-deterministic[{vec['name']}]"
        msg = bytes.fromhex(vec["message_hex"])
        if "message_utf8" in vec:
            _eq(f"{tag}.message_utf8", vec["message_utf8"].encode("utf-8"), msg)
        h, k, high, sig = signed(vec["key"], msg)
        _eq(f"{tag}.prehash", h, vec["expected_prehash_sha3_256_hex"])
        _eq(f"{tag}.nonce_k", k.to_bytes(32, "big").hex(), vec["expected_nonce_k_hex"])
        _eq(f"{tag}.low_s_applied", high, vec["expected_low_s_applied"])
        _eq(f"{tag}.sig_hex", sig.hex(), vec["expected_sig_hex"])
        _eq(f"{tag}.sig_b64", base64.b64encode(sig).decode("ascii"), vec["expected_sig_b64"])
        _eq(f"{tag}.verifies", _p256_verify_raw_rs(pubs[vec["key"]], sig, msg), True)

    for case in v["composite_cases"]:
        tag = f"ecdsa-p256-deterministic.composite[{case['name']}]"
        m = P.composite_m_prime(case["composite_alg_id"], case["payload_canon_digest_hex"])
        _eq(f"{tag}.m_prime", m.hex(), case["expected_m_prime_hex"])
        _, _, high, sig = signed(case["key"], m)
        _eq(f"{tag}.component", case["expected_ecdsa_component"], {
            "alg": "ECDSA-P256-SHA3-256",
            "encoding": "raw-rs-64",
            "low_s": True,
            "sig_b64": base64.b64encode(sig).decode("ascii"),
        })
        _eq(f"{tag}.low_s_applied", high, case["expected_low_s_applied"])
        _eq(f"{tag}.verifies", _p256_verify_raw_rs(pubs[case["key"]], sig, m), True)

    # Coverage: both low-s branches, both seed-derived key families plus the
    # scalar edges, an empty message, and the composite wire form.
    flags = [x["expected_low_s_applied"] for x in v["vectors"]]
    _eq("ecdsa-p256-deterministic.pins_low_s_applied", any(flags), True)
    _eq("ecdsa-p256-deterministic.pins_low_s_not_applied", not all(flags), True)
    sources = {k["source"] for k in v["keys"].values()}
    _eq("ecdsa-p256-deterministic.pins_key_sources",
        sources >= {"issuer-key-derivation", "key-derivation", "scalar"}, True)
    edge = {int(k["scalar_hex"], 16) for k in v["keys"].values()}
    _eq("ecdsa-p256-deterministic.pins_scalar_edges", {1, n - 1} <= edge, True)
    _eq("ecdsa-p256-deterministic.pins_empty_message",
        any(x["message_hex"] == "" for x in v["vectors"]), True)
    _eq("ecdsa-p256-deterministic.pins_composite_cases", len(v["composite_cases"]) >= 2, True)


# ── operator.domain-binding/1 ─────────────────────────────────────────────
# An independent implementation of the rules: the authoring script computes the
# bytes, and the verdicts it records were written by hand from the
# specification. Everything below re-derives them.

_ODB_PREFIX = b"certcrypt:operator-domain-binding:1|"
_ODB_MEMBERS = (
    "artifact_type", "intent", "domain_binding_method", "operator_id",
    "operator_public_key", "domain_ascii", "sequence", "issued_at",
    "valid_until", "signature_alg", "signature_b64",
)
_ODB_UNSIGNED = _ODB_MEMBERS[:9]
_ODB_NON_PUBLIC_TLDS = ("localhost", "invalid", "test", "local", "arpa", "onion", "alt", "internal")
_ODB_MAX_BYTES = 65536
_ODB_MAX_ENTRIES = 8
_ODB_SEQUENCE_MAX = 9007199254740991
_ODB_INSTANT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


class _OdbDuplicate(ValueError):
    pass


def _odb_pairs(pairs):
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise _OdbDuplicate(k)
        seen[k] = v
    return seen


def _odb_loads(text: str):
    """Parse JSON text, refusing a member name repeated in any object."""
    return json.loads(text, object_pairs_hook=_odb_pairs)


def _odb_instant(s: str):
    if not isinstance(s, str) or not _ODB_INSTANT.fullmatch(s):
        return None
    try:
        return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None


def _odb_b64(s: str):
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        return None


def _odb_operator_id(pk: bytes) -> str:
    return "op:" + base64.b64encode(hashlib.sha3_256(pk).digest()[:16]).decode().rstrip("=")


def _odb_payload(st: dict) -> bytes:
    return P.jcs_canonicalize_bytes({k: st[k] for k in _ODB_UNSIGNED})


def _odb_normalize(typed: str):
    """§5 producer side: what the operator typed → (domain_ascii, None) or (None, rule)."""
    import ipaddress

    import idna

    s = typed.strip()
    if s.endswith("."):
        s = s[:-1]
    if not s:
        return None, "5-empty"
    if "*" in s:
        return None, "5-wildcard"
    if "_" in s:
        return None, "5-underscore"
    if s.startswith("["):
        return None, "5-ip-literal"
    try:
        ipaddress.ip_address(s)
        return None, "5-ip-literal"
    except ValueError:
        pass
    try:
        ascii_name = idna.encode(s, uts46=True, std3_rules=True, transitional=False).decode("ascii")
    except (idna.IDNAError, UnicodeError):
        return None, "5-idna"
    ascii_name = ascii_name.lower()
    labels = ascii_name.split(".")
    if len(ascii_name) > 253 or any(not (1 <= len(lb) <= 63) for lb in labels):
        return None, "5-idna"
    if len(labels) < 2:
        return None, "5-single-label"
    if labels[-1].isdigit():
        return None, "5-numeric-tld"
    if labels[-1] in _ODB_NON_PUBLIC_TLDS:
        return None, "5-non-public-tld"
    return ascii_name, None


def _odb_icann_public_suffix(name: str, psl: dict) -> bool:
    """True when `name` is itself a public suffix whose prevailing rule is in the
    ICANN section (Public Suffix List algorithm over the pinned excerpt)."""
    labels = name.split(".")
    rules = [(r, "icann") for r in psl["icann"]] + [(r, "private") for r in psl["private"]]

    def matches(rule: str) -> bool:
        rl = rule.lstrip("!").split(".")
        if len(rl) > len(labels):
            return False
        return all(a == "*" or a == b for a, b in zip(reversed(rl), reversed(labels)))

    hits = [(r, sec) for r, sec in rules if matches(r)]
    exceptions = [(r, sec) for r, sec in hits if r.startswith("!")]
    if exceptions:
        rule, sec = max(exceptions, key=lambda x: len(x[0].split(".")))
        n = len(rule.lstrip("!").split(".")) - 1
    elif hits:
        rule, sec = max(hits, key=lambda x: len(x[0].split(".")))
        n = len(rule.split("."))
    else:
        sec, n = None, 1  # the default rule `*`
    return sec == "icann" and n == len(labels)


def _odb_carried(domain, psl: dict):
    """§5 consumer side: a carried domain_ascii → None (accepted) or the rule."""
    if not isinstance(domain, str):
        return "4-members"
    canonical, _ = _odb_normalize(domain)
    if canonical is None or canonical != domain:
        return "5-host-name"
    if _odb_icann_public_suffix(domain, psl):
        return "5-public-suffix"
    return None


def _odb_check(st, now: datetime.datetime, psl: dict):
    """Every stateless check of §4–§7.1 on one parsed statement; None or the rule."""
    if not isinstance(st, dict) or set(st) != set(_ODB_MEMBERS):
        return "4-members"
    if any(not isinstance(st[m], str) for m in _ODB_MEMBERS):
        return "4-members"
    if (st["artifact_type"] != "operator.domain-binding/1"
            or st["intent"] not in ("bind", "unbind")
            or st["domain_binding_method"] != "https-well-known"
            or st["signature_alg"] != "ml-dsa-65-fips204-v1"):
        return "4-values"
    issued, until = _odb_instant(st["issued_at"]), _odb_instant(st["valid_until"])
    pk, sig = _odb_b64(st["operator_public_key"]), _odb_b64(st["signature_b64"])
    if issued is None or until is None or pk is None or not sig:
        return "4-values"
    seq = st["sequence"]
    if not re.fullmatch(r"[1-9][0-9]*", seq) or int(seq) > _ODB_SEQUENCE_MAX:
        return "7.2-sequence"
    host = _odb_carried(st["domain_ascii"], psl)
    if host:
        return host
    if _odb_operator_id(pk) != st["operator_id"]:
        return "6-operator-id"
    try:
        verifies = ML_DSA_65.verify(pk, _ODB_PREFIX + _odb_payload(st), sig)
    except Exception:
        verifies = False
    if not verifies:
        return "6-signature"
    if issued >= until:
        return "7.1-order"
    if st["intent"] == "bind" and until > issued + datetime.timedelta(days=90):
        return "7.1-bind-max-validity"
    if issued > now + datetime.timedelta(seconds=300):
        return "7.1-future"
    if now >= until:
        return "7.1-expired"
    return None


def _odb_document(body: bytes, host: str, operator_id: str, now, psl: dict):
    """§8.1–§8.3 and §9 step 2 → (document rule or None, matching digest or None)."""
    if len(body) > _ODB_MAX_BYTES:
        return "8.1-size", None
    try:
        doc = _odb_loads(body.decode("utf-8"))
    except _OdbDuplicate:
        return "8.2-duplicate", None
    except ValueError:
        return "8.1-format", None
    if not isinstance(doc, dict) or set(doc) != {"bindings"} or not isinstance(doc["bindings"], list):
        return "8.1-format", None
    if not 1 <= len(doc["bindings"]) <= _ODB_MAX_ENTRIES:
        return "8.1-entries", None
    for st in doc["bindings"]:
        # Every element a well-formed statement: member set and types (§8.1).
        if (not isinstance(st, dict) or set(st) != set(_ODB_MEMBERS)
                or any(not isinstance(st[m], str) for m in _ODB_MEMBERS)):
            return "8.1-statement", None
    for st in doc["bindings"]:
        if (isinstance(st, dict) and st.get("domain_ascii") == host
                and st.get("operator_id") == operator_id and st.get("intent") == "bind"
                and _odb_check(st, now, psl) is None):
            return None, hashlib.sha3_256(_odb_payload(st)).hexdigest()
    return None, None


def _odb_checked_state(body: bytes, rule, match, checked_digest: str, now, psl: dict) -> str:
    """§8.3/§10.2 for a party looking for one statement by its digest."""
    if rule is not None:
        return "malformed"
    if match == checked_digest:
        return "matched"
    carried = [st for st in json.loads(body.decode("utf-8"))["bindings"]
               if hashlib.sha3_256(_odb_payload(st)).hexdigest() == checked_digest]
    if not carried:
        return "absent"
    # Carried but not matching: expired when that is its only defect.
    until = _odb_instant(carried[0]["valid_until"])
    if until is not None and now >= until and _odb_check(carried[0], until - datetime.timedelta(seconds=1), psl) is None:
        return "expired"
    return "malformed"


def _odb_sequence(accepted: list, received: dict) -> str:
    """§7.2 for a party that keeps state per operator_id."""
    mine = [a for a in accepted if a["operator_id"] == received["operator_id"]]
    for a in mine:
        if a["sequence"] == received["sequence"]:
            return "idempotent" if a["statement_digest_hex"] == received["statement_digest_hex"] else "conflict"
    if mine and int(received["sequence"]) < max(int(a["sequence"]) for a in mine):
        return "rejected"
    return "candidate"


def check_operator_domain_binding(fx: str) -> None:
    """operator.domain-binding/1: construction bytes and signatures, the
    stateless statement checks, host names, the published document and the
    sequence rules — each verdict re-derived, each signature verified, and the
    deterministic signatures reproduced."""
    v = _load(fx, "operator-domain-binding", "vectors.json")
    d = _load(fx, "operator-domain-binding", "documents.json")
    tag = "operator-domain-binding"
    psl = v["host_names"]["public_suffix_list_excerpt"]

    c = v["constants"]
    _eq(f"{tag}.constants", (c["signing_prefix"].encode(), c["well_known_max_bytes"],
                             c["well_known_max_entries"], int(c["sequence_max"]),
                             c["bind_max_validity_days"], c["issued_at_future_tolerance_seconds"]),
        (_ODB_PREFIX, _ODB_MAX_BYTES, _ODB_MAX_ENTRIES, _ODB_SEQUENCE_MAX, 90, 300))

    keys = {}
    for k in v["keys"]:
        pk, sk = ML_DSA_65.key_derive(bytes.fromhex(k["seed_hex"]))
        keys[k["label"]] = (pk, sk)
        _eq(f"{tag}.key[{k['label']}].public_key", base64.b64encode(pk).decode(), k["public_key_b64"])
        _eq(f"{tag}.key[{k['label']}].operator_id", _odb_operator_id(pk), k["operator_id"])

    # Construction: rebuild each statement from its inputs alone.
    statements = {}
    for case in v["construction"]["cases"]:
        t, i, e = f"{tag}.construction[{case['label']}]", case["inputs"], case["expected"]
        pk, sk = keys[i["operator_key"]]
        domain, rule = _odb_normalize(i["domain"])
        _eq(f"{t}.domain_ascii", domain, e["domain_ascii"])
        st = {
            "artifact_type": "operator.domain-binding/1",
            "intent": i["intent"],
            "domain_binding_method": "https-well-known",
            "operator_id": _odb_operator_id(pk),
            "operator_public_key": base64.b64encode(pk).decode(),
            "domain_ascii": domain,
            "sequence": str(i["sequence"]),
            "issued_at": i["issued_at"],
            "valid_until": i["valid_until"],
        }
        payload = _odb_payload(st)
        message = _ODB_PREFIX + payload
        st["signature_alg"] = "ml-dsa-65-fips204-v1"
        st["signature_b64"] = base64.b64encode(ML_DSA_65.sign(sk, message, deterministic=True)).decode()
        _eq(f"{t}.operator_id", st["operator_id"], e["operator_id"])
        _eq(f"{t}.signed_payload_jcs", payload.decode(), e["signed_payload_jcs_utf8"])
        _eq(f"{t}.statement_digest", hashlib.sha3_256(payload).hexdigest(), e["statement_digest_hex"])
        _eq(f"{t}.signing_message", message.decode(), e["signing_message_utf8"])
        _eq(f"{t}.signing_message_digest", hashlib.sha3_256(message).hexdigest(),
            e["signing_message_sha3_256_hex"])
        artifact = P.jcs_canonicalize_bytes(st)
        _eq(f"{t}.artifact_jcs", artifact.decode(), e["artifact_jcs_utf8"])
        _eq(f"{t}.artifact_jcs_digest", hashlib.sha3_256(artifact).hexdigest(), e["artifact_jcs_sha3_256_hex"])
        _eq(f"{t}.signature_reproduces", st["signature_b64"], e["signature_b64"])
        _eq(f"{t}.signature_verifies",
            ML_DSA_65.verify(pk, message, base64.b64decode(e["signature_b64"])), e["signature_verifies"])
        _eq(f"{t}.statement", case["statement"], st)
        statements[case["label"]] = st
        if "tampered" in case:
            tp = case["tampered"]["statement"]
            _eq(f"{t}.tampered_differs_only_in_signature",
                {k: tp[k] for k in _ODB_MEMBERS if k != "signature_b64"},
                {k: st[k] for k in _ODB_MEMBERS if k != "signature_b64"})
            _eq(f"{t}.tampered_verifies",
                ML_DSA_65.verify(pk, _ODB_PREFIX + _odb_payload(tp), base64.b64decode(tp["signature_b64"])),
                case["tampered"]["expected_signature_verifies"])

    # Statement validity, from the exact JSON text.
    rules_seen = set()
    for case in v["statement_validity"]["cases"]:
        t = f"{tag}.validity[{case['label']}]"
        try:
            rule = _odb_check(_odb_loads(case["statement_json_utf8"]), _odb_instant(case["now"]), psl)
        except _OdbDuplicate:
            rule = "4-members"
        _eq(t, {"accepted": rule is None, "rule": rule}, case["expected"])
        rules_seen.add(rule)
    _eq(f"{tag}.validity.covers_every_rule", rules_seen >= {
        None, "4-members", "4-values", "5-host-name", "5-public-suffix", "6-operator-id", "6-signature",
        "7.1-order", "7.1-bind-max-validity", "7.1-future", "7.1-expired", "7.2-sequence"}, True)

    # The signed-without-prefix case is a real signature over the bare payload:
    # it fails for the context, not because it is garbage.
    bare = next(x for x in v["statement_validity"]["cases"] if x["label"] == "signed-without-prefix")
    st = json.loads(bare["statement_json_utf8"])
    _eq(f"{tag}.validity[signed-without-prefix].verifies_over_bare_payload",
        ML_DSA_65.verify(keys["operator-a"][0], _odb_payload(st), base64.b64decode(st["signature_b64"])), True)

    # Host names.
    h = v["host_names"]
    for case in h["input_cases"]:
        domain, rule = _odb_normalize(case["input"])
        _eq(f"{tag}.host_input[{case['label']}]", {"domain_ascii": domain, "rule": rule}, case["expected"])
    for case in h["carried_cases"]:
        rule = _odb_carried(case["domain_ascii"], psl)
        _eq(f"{tag}.host_carried[{case['label']}]", {"accepted": rule is None, "rule": rule}, case["expected"])
    np = h["non_public_top_level_names"]
    _eq(f"{tag}.non_public_names", tuple(np["names"]), _ODB_NON_PUBLIC_TLDS)
    for name in np["names"]:
        host = np["template"].format(name=name)
        domain, rule = _odb_normalize(host)
        _eq(f"{tag}.non_public[{name}].input", {"domain_ascii": domain, "rule": rule}, np["expected"]["input"])
        rule = _odb_carried(host, psl)
        _eq(f"{tag}.non_public[{name}].carried", {"accepted": rule is None, "rule": rule},
            np["expected"]["carried"])

    # Sequence and unbind precedence. The identities must be the construction's.
    def same_identity(r):
        st = statements[r["statement"]]
        return (r["operator_id"], r["sequence"], r["intent"], r["domain_ascii"], r["statement_digest_hex"]) == (
            st["operator_id"], st["sequence"], st["intent"], st["domain_ascii"],
            hashlib.sha3_256(_odb_payload(st)).hexdigest())

    seq = v["sequence"]
    for case in seq["cases"]:
        t = f"{tag}.sequence[{case['label']}]"
        _eq(f"{t}.identities", all(same_identity(r) for r in case["accepted"] + [case["received"]]), True)
        _eq(t, _odb_sequence(case["accepted"], case["received"]), case["expected"])
    _eq(f"{tag}.sequence.covers_every_result",
        {c["expected"] for c in seq["cases"]} == {"candidate", "idempotent", "conflict", "rejected"}, True)
    for case in seq["unbind_precedence_cases"]:
        t = f"{tag}.unbind_precedence[{case['label']}]"
        ck = case["checked"]
        _eq(f"{t}.identities", all(same_identity(r) for r in case["accepted"] + [ck]), True)
        blocked = any(a["intent"] == "unbind" and a["operator_id"] == ck["operator_id"]
                      and a["domain_ascii"] == ck["domain_ascii"] and int(a["sequence"]) > int(ck["sequence"])
                      for a in case["accepted"])
        _eq(t, ck["intent"] == "bind" and ck in case["accepted"] and not blocked, case["expected_established"])

    # The published document.
    bodies = {}
    for case in d["cases"]:
        t = f"{tag}.document[{case['label']}]"
        if "body_construction" in case:
            bc = case["body_construction"]
            base = bodies[bc["from_case"]]
            body = base + b" " * (bc["append_spaces_to_total_bytes"] - len(base))
            _eq(f"{t}.size", len(body), bc["append_spaces_to_total_bytes"])
        else:
            body = case["body_utf8"].encode("utf-8")
        bodies[case["label"]] = body
        rule, match = _odb_document(body, case["host"], case["operator_id"], _odb_instant(case["now"]), psl)
        _eq(t, {"document_accepted": rule is None, "document_rule": rule, "matching_statement_digest_hex": match},
            {k: case["expected"][k] for k in ("document_accepted", "document_rule",
                                              "matching_statement_digest_hex")})
        _eq(f"{t}.checked_statement_exists", case["checked_statement"] in statements, True)
        checked = hashlib.sha3_256(_odb_payload(statements[case["checked_statement"]])).hexdigest()
        _eq(f"{t}.checked_statement_state",
            _odb_checked_state(body, rule, match, checked, _odb_instant(case["now"]), psl),
            case["expected"]["checked_statement_state"])
    _eq(f"{tag}.documents.cover_every_rule",
        {c["expected"]["document_rule"] for c in d["cases"]} >=
        {None, "8.1-size", "8.1-entries", "8.1-format", "8.1-statement", "8.2-duplicate"}, True)
    _eq(f"{tag}.documents.cover_every_state",
        {c["expected"]["checked_statement_state"] for c in d["cases"]} ==
        {"matched", "absent", "malformed", "expired"}, True)
    _eq(f"{tag}.sequence.pins_idempotent_below_highest",
        any(c["expected"] == "idempotent" and int(c["received"]["sequence"]) <
            max(int(a["sequence"]) for a in c["accepted"] if a["operator_id"] == c["received"]["operator_id"])
            for c in seq["cases"]), True)


_DETERMINISTIC = [
    ("key-derivation", check_key_derivation),
    ("level1-binding", check_level1_binding),
    ("rules-domain", check_rules_domain),
    ("operator-receipt", check_operator_receipt),
    ("pseudonym", check_pseudonym),
    ("holder-keyset", check_holder_keyset),
    ("collection-merkle", check_collection_merkle),
    ("subject-text", check_subject_text),
    ("subject-email", check_subject_email),
    ("subject-binary", check_subject_binary),
    ("subject-context-snapshot", check_subject_context_snapshot),
    ("subject-collection", check_subject_collection),
    ("subject-ai-decision", check_subject_ai_decision),
    ("strict-json", check_strict_json),
    ("original-material", check_original_material),
    ("capacity-evidence/vectors", check_capacity_evidence_vectors),
    ("ccvp-consistency", check_ccvp_consistency),
    ("submission-set", check_submission_set),
    ("submission-set-limits", check_submission_set_limits),
    ("issuer-key-derivation", check_issuer_key_derivation),
    ("ecdsa-p256-deterministic", check_ecdsa_p256_deterministic),
    ("settlement-preimages", check_settlement_preimages),
    ("manifest-resolution", check_manifest_resolution),
    ("artifact-shape", check_artifact_shape),
    ("composite-m-prime", check_composite_m_prime),
    ("operator-domain-binding", check_operator_domain_binding),
]
_GOLDENS = [
    ("independence-proof-signature", check_independence_proof_signature),
    ("capacity-evidence/golden-e2e", check_capacity_evidence_golden),
    ("verification-package/golden-e2e", check_verification_package_golden),
    ("composite-verification", check_composite_verification),
]


def main_check(fx: str) -> int:
    """Verify every primitive vector under `fx`/primitives. Returns 0 on success,
    1 on any drift. Importable so generate_fixtures.py can run it as a gate;
    resets counters so repeated calls in one process are independent."""
    global _FAILS, _CHECKS
    _FAILS = []
    _CHECKS = 0

    print("Verifying primitive vectors (deterministic — recomputed from inputs)...\n")
    for name, fn in _DETERMINISTIC:
        before = len(_FAILS)
        fn(fx)
        mark = "ok " if len(_FAILS) == before else "FAIL"
        print(f"  [{mark}] {name}")

    print("\nVerifying goldens (external signatures — envelope recomputed + signatures verified)...\n")
    for name, fn in _GOLDENS:
        before = len(_FAILS)
        fn(fx)
        mark = "ok " if len(_FAILS) == before else "FAIL"
        print(f"  [{mark}] {name}")

    print(f"\n{_CHECKS} checks, {len(_FAILS)} failed.")
    if _FAILS:
        print("\nFAILURES:")
        for f in _FAILS:
            print(f"  - {f}")
        return 1
    print("All primitive vectors reproduce byte-for-byte from the public rules.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Verify fixtures/primitives/* against the public rules."
    )
    ap.add_argument("--fixtures", default=None, help="fixtures/ dir (default ../fixtures)")
    args = ap.parse_args()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    fx = args.fixtures or os.path.join(script_dir, "..", "fixtures")
    return main_check(fx)


if __name__ == "__main__":
    sys.exit(main())
