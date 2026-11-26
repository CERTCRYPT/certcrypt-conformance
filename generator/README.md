# Generator

Reference fixture generator for the CERTCRYPT conformance suite.

The generator produces the fixtures committed in [`../fixtures/`](../fixtures/) from synthetic inputs by applying the public rules — SHA3-256 digests, RFC 8785 (JCS) canonicalization, Merkle construction, and the published settlement profile.

## Language

The generator is written in Python. Python is chosen because the cryptographic standards community (NIST, IETF drafts, cryptographic auditors) commonly reads it, so the generator is readable and reproducible by any third party without learning a verifier's implementation language.

## Dependencies

The generator depends only on widely available cryptographic standards
(pinned in [`requirements.txt`](requirements.txt)):

- `hashlib` (Python standard library) for SHA3-256 / SHAKE-256
- `cryptography` for Ed25519 (RFC 8032, deterministic)
- `dilithium-py` for ML-DSA-65 (FIPS 204, deterministic variant)
- `ecdsa` for ECDSA P-256 (RFC 6979 deterministic). Deliberately not
  `cryptography`, whose ECDSA signs with a random nonce: that would make the
  fixtures irreproducible and diverge from the reference implementation, which
  uses RFC 6979 signing. See [`DETERMINISM.md`](DETERMINISM.md) §3.
- `jsonschema` for the Draft 2020-12 check in `validate_schemas.py`
- `idna` for UTS #46 processing of host names in `emit_primitives.py`
  (`operator-domain-binding`)
- JCS RFC 8785 — implemented in-tree (`primitives.py`)
- both Merkle schemes (settlement `0x00`/`0x01`; collection domain-tag/u64be) — in-tree

No dependency on any verifier implementation. The generator is the authoritative
tool for reproducing the conformance suite; it can be audited and run by any
third party without clone-and-build of any verifier.

## Layout

- `primitives.py` — canonical crypto primitives (SHA3, JCS, canonical-json,
  both Merkle schemes — settlement `0x00`/`0x01` and collection domain-tag/u64be,
  the subject.text/subject.email byte-canonicalizers, operation-scoped
  pseudonyms, Ed25519, ML-DSA-65, ECDSA P-256).
- `generate_fixtures.py` — builds the `conformance/` + `adversarial/` fixtures,
  then runs the primitive and schema gates below. `--out DIR` writes the
  fixtures elsewhere (e.g. for a no-touch diff).
- `emit_primitives.py` — reproduce-and-verify oracle for `../fixtures/primitives`:
  recomputes every deterministic vector's `expected_*` from its own inputs and
  asserts a byte-for-byte match, and verifies the three goldens' embedded
  signatures — produced by the reference producer implementation with test keys
  (hedged, so verified rather than reproduced) — against the pinned keys.
- `validate_schemas.py` — checks the normative JSON Schemas are valid Draft
  2020-12 and that every fixture request conforms to the input schema.
- `DETERMINISM.md` — how byte-for-byte reproducibility is achieved.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python generate_fixtures.py            # writes ../fixtures/, then gates primitives + schemas
python generate_fixtures.py --out /tmp/check       # regenerate elsewhere, then:
diff -rq /tmp/check ../fixtures                    # only README.md + primitives/ differ
PYTHONPATH=. python emit_primitives.py             # primitive byte-contract oracle, standalone
PYTHONPATH=. python validate_schemas.py            # normative-schema gate, standalone
```

## Status

Active. `generate_fixtures.py` reproduces the committed `conformance/` and
`adversarial/` fixtures **byte-for-byte**, including the Ed25519, ML-DSA-65 and
ECDSA-P256 signatures. Because ML-DSA-65 is signed with the FIPS 204
deterministic variant and P-256 with RFC 6979, the signatures are reproducible
across conformant implementations, not just within this one. The run then gates
the `fixtures/primitives/*` byte-contract vectors (`emit_primitives.py` —
recompute-and-verify, including verifying the three hedged-signature goldens) and
the normative JSON Schemas (`validate_schemas.py`). A drift in any layer fails
the run.

## Reproducibility

Running the generator from this directory produces the fixtures committed in `../fixtures/` byte-for-byte. If a regeneration produces fixtures that diverge from the committed set, the divergence MUST be resolved before any release of the conformance suite — either the generator is wrong, the committed fixtures are wrong, or both, and the public rules are the arbiter.

## License

Copyright © 2025-2026 CERTCRYPT, Inc., its affiliates or licensors. All rights reserved.

Licensed under the Apache License, Version 2.0. See [`../LICENSE`](../LICENSE) for the full text.

## Issuer key derivation vectors

`fixtures/primitives/issuer-key-derivation/vectors.json` is not written by
`generate_fixtures.py`. It is authored by
`author_issuer_key_derivation_vectors.py`, from the primitives in this directory
and python-ecdsa:

```sh
PYTHONPATH=. python author_issuer_key_derivation_vectors.py ../fixtures/primitives/issuer-key-derivation/vectors.json
```

Every value is a pure function of the seeds and tree sizes in the script, so a
re-run reproduces the committed file byte for byte; `emit_primitives.py`
re-derives every public key and default key id from the written rule.

## ECDSA P-256 deterministic vectors

`fixtures/primitives/ecdsa-p256-deterministic/vectors.json` is authored by
`author_ecdsa_p256_deterministic_vectors.py`, with python-ecdsa signing over keys
taken from `issuer-key-derivation`, `key-derivation` and two edge scalars:

```sh
PYTHONPATH=. python author_ecdsa_p256_deterministic_vectors.py ../fixtures/primitives/ecdsa-p256-deterministic/vectors.json
```

RFC 6979 leaves no randomness in the signature, so a re-run reproduces the
committed file byte for byte. `emit_primitives.py` does not reuse python-ecdsa to
check it: it carries its own RFC 6979 nonce derivation and curve arithmetic,
first proves them on RFC 6979 Appendix A.2.5 (P-256, SHA-256, "sample" and
"test"), then re-derives every public key, nonce and signature with SHA3-256 and
verifies each signature with `cryptography`.

## Operator domain binding vectors

`fixtures/primitives/operator-domain-binding/` (`vectors.json` and
`documents.json`) is authored by `author_operator_domain_binding_vectors.py`:

```sh
PYTHONPATH=. python author_operator_domain_binding_vectors.py ../fixtures/primitives/operator-domain-binding
```

The script computes bytes only — ML-DSA-65 keys from fixed seeds, the JCS
payloads and signed messages, digests, and FIPS 204 deterministic signatures —
so a re-run reproduces both files byte for byte. The verdicts are written out
by hand from `operator.domain-binding/1`; `emit_primitives.py` re-derives every
one with its own implementation of the rules (member set, values, UTS #46 host
names, the Public Suffix List algorithm over the pinned excerpt, the validity
window, the published document and the sequence table), reproduces each
signature and verifies it.
