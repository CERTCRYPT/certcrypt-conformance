#!/usr/bin/env python3
"""Author the subject.ai-decision/1 primitive vectors deterministically."""

import copy
import json
from pathlib import Path

import primitives as P


NONCE = "ab" * 32
OUT = Path(__file__).resolve().parents[1] / "fixtures/primitives/subject-ai-decision/vectors.json"


def canonical(profile: str, material: bytes) -> bytes:
    if profile == "subject.binary/1":
        return material
    if profile == "subject.text/1":
        return P.canonical_subject_text(material)
    if profile == "subject.email/1":
        return P.canonical_subject_email(material)
    if profile == "subject.ai-decision/1":
        value = json.loads(material)
        P.assert_ai_decision_precondition(value)
        return P.jcs_canonicalize_bytes(value)
    raise ValueError(profile)


def part(part_id: str, role: str, media_type: str, profile: str, material: bytes,
         material_nonce_hex: str) -> dict:
    local_digest = P.digest_hex_bytes(canonical(profile, material))
    return {
        "id": part_id,
        "role": role,
        "media_type": media_type,
        "profile": profile,
        "material_nonce_hex": material_nonce_hex,
        "commitment_digest_hex": P.digest_hex_text(material_nonce_hex + local_digest),
    }


def vector(name: str, record: dict, materials: dict[str, bytes], why: str) -> dict:
    P.assert_ai_decision_precondition(record)
    canon = P.jcs_canonicalize_bytes(record)
    local = P.digest_hex_bytes(canon)
    return {
        "name": name,
        "decision_record": record,
        "part_materials": {key: value.decode("utf-8") for key, value in materials.items()},
        "expected_canonical_utf8": canon.decode("utf-8"),
        "expected_subject_local_digest_hex": local,
        "expected_commitment_digest_hex": P.digest_hex_text(NONCE + local),
        "why": why,
    }


prompt = b"Classify synthetic sample alpha."
image = b"synthetic-png-byte-stream"
answer = b"label: category-a"
public_record = {
    "profile": "subject.ai-decision/1",
    "decision_id": "synthetic-event-01",
    "decided_at": "2026-06-17T10:30:00.000Z",
    "started_at": "2026-06-17T10:29:58.000Z",
    "model": {"id": "synthetic-model", "provider": "synthetic-runtime", "version": "synthetic-model-v1"},
    "observation_scope": "client",
    "parameters": {"temperature": "0.0"},
    "context": {"sample_ref": "synthetic-sample-01"},
    "input": [
        part("prompt", "prompt", "text/plain", "subject.text/1", prompt, "01" * 32),
        part("image", "image", "image/png", "subject.binary/1", image, "02" * 32),
    ],
    "output": [part("answer", "response", "text/plain", "subject.text/1", answer, "03" * 32)],
    "decision": "category-a",
}

runtime_input = b"synthetic runtime features"
runtime_output = b"category-b"
runtime_record = {
    "profile": "subject.ai-decision/1",
    "decision_id": "synthetic-runtime-event-01",
    "decided_at": "2026-08-01T09:15:00.000Z",
    "model": {"id": "synthetic-runtime-model", "provider": "synthetic-runtime"},
    "observation_scope": "runtime",
    "input": [part("features", "features", "application/octet-stream", "subject.binary/1",
                   runtime_input, "04" * 32)],
    "output": [part("outcome", "response", "text/plain", "subject.text/1", runtime_output,
                    "05" * 32)],
    "decision": "category-b",
    "actor_id": "synthetic-actor-01",
    "policy_ref": "synthetic-policy-01",
}

prior_bytes = P.jcs_canonicalize_bytes(runtime_record)
chain_answer = b"category-c"
chain_record = {
    "profile": "subject.ai-decision/1",
    "decision_id": "synthetic-chain-event-01",
    "decided_at": "2026-08-01T09:16:00.000Z",
    "model": {"id": "synthetic-chain-model", "provider": "synthetic-runtime"},
    "observation_scope": "runtime",
    "input": [part("prior", "prior-decision", "application/json", "subject.ai-decision/1",
                   prior_bytes, "06" * 32)],
    "output": [part("review", "response", "text/plain", "subject.text/1", chain_answer,
                    "07" * 32)],
    "decision": "category-c",
}

vectors = [
    vector("multimodal-synthetic", public_record, {"prompt": prompt, "image": image, "answer": answer},
           "Multiple input media and one output are bound by ids unique within the record."),
    vector("runtime-synthetic", runtime_record, {"features": runtime_input, "outcome": runtime_output},
           "A runtime observation binds one input and one output part."),
    vector("chained-decision", chain_record, {"prior": prior_bytes, "review": chain_answer},
           "A part may itself be a conforming subject.ai-decision/1 record."),
]


def invalid(name: str, mutate) -> dict:
    value = copy.deepcopy(public_record)
    mutate(value)
    return {"name": name, "decision_record": value, "expected_outcome": "REJECTED"}


negative_cases = [
    invalid("missing decision_id", lambda v: v.pop("decision_id")),
    invalid("invalid decision_id", lambda v: v.update(decision_id="Bad ID")),
    invalid("legacy singular input", lambda v: v.update(input=v["input"][0])),
    invalid("duplicate part id", lambda v: v["output"][0].update(id="prompt")),
    invalid("empty role", lambda v: v["input"][0].update(role="")),
    invalid("uppercase media type", lambda v: v["input"][0].update(media_type="Text/Plain")),
    invalid("media type parameters", lambda v: v["input"][0].update(media_type="text/plain; charset=utf-8")),
    invalid("unadmitted part profile", lambda v: v["input"][0].update(profile="subject.collection/1")),
    invalid("malformed material nonce", lambda v: v["input"][0].update(material_nonce_hex="A" * 64)),
    invalid("malformed part commitment", lambda v: v["input"][0].update(commitment_digest_hex="A" * 64)),
    invalid("duplicate material nonce", lambda v: v["output"][0].update(
        material_nonce_hex=v["input"][0]["material_nonce_hex"])),
    invalid("legacy raw digest", lambda v: v["input"][0].update(
        digest_hex="a" * 64)),
    invalid("issuer-provided local digest", lambda v: v["input"][0].update(
        subject_local_digest_hex="a" * 64)),
    invalid("invalid Gregorian date", lambda v: v.update(decided_at="2026-02-29T10:30:00.000Z")),
    invalid("missing milliseconds", lambda v: v.update(decided_at="2026-06-17T10:30:00Z")),
    invalid("one-digit millisecond precision", lambda v: v.update(decided_at="2026-06-17T10:30:00.1Z")),
    invalid("two-digit millisecond precision", lambda v: v.update(decided_at="2026-06-17T10:30:00.12Z")),
    invalid("four-digit millisecond precision", lambda v: v.update(decided_at="2026-06-17T10:30:00.0000Z")),
    invalid("non-UTC timestamp", lambda v: v.update(decided_at="2026-06-17T12:30:00+02:00")),
    invalid("started_at missing canonical milliseconds", lambda v: v.update(started_at="2026-06-17T10:29:58Z")),
    invalid("started after decision", lambda v: v.update(started_at="2026-06-17T10:30:00.001Z")),
    invalid("nested context", lambda v: v.update(context={"nested": {"x": "1"}})),
    invalid("JSON number", lambda v: v.update(parameters={"temperature": 0})),
    invalid("no parts", lambda v: v.update(input=[], output=[])),
    invalid("empty input", lambda v: v.update(input=[])),
    invalid("empty output", lambda v: v.update(output=[])),
    invalid("empty decision", lambda v: v.update(decision="")),
    invalid("empty model id", lambda v: v["model"].update(id="")),
]

document = {
    "primitive": "subject_ai_decision_canonicalization",
    "description": "Canonicalization and record-local material binding for subject.ai-decision/1.",
    "profile": "subject.ai-decision/1",
    "nonce_hex": NONCE,
    "vectors": vectors,
    "positive_cases": [{"name": v["name"], "decision_record": v["decision_record"],
                        "expected_canonical_bytes_utf8": v["expected_canonical_utf8"],
                        "expected_digest_hex": v["expected_subject_local_digest_hex"]} for v in vectors],
    "negative_cases": negative_cases,
}

OUT.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
