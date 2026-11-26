# Fixtures

Deterministic test vectors: the verdicts every conformant CERTCRYPT verifier MUST return, and the exact bytes every implementation MUST reproduce.

## Layout

```
fixtures/
├── conformance/        Positive cases a verifier MUST accept (return *_VALID)
│   ├── P001/           End-to-end positive paths
│   ├── F001/           Valid system-foundation statements
│   ├── S001/           Valid signatures
│   ├── Q001/           Valid post-quantum composite signatures
│   └── …
├── adversarial/        Negative cases: the exact non-valid result is pinned
│   ├── V001/           Verification-path violations (binding, settlement, capacity, …)
│   ├── F002/           Broken or substituted system-foundation statements
│   ├── S002/           Broken signatures
│   ├── Q003/           Broken or stripped post-quantum composites
│   ├── QN1/            Quorum-counting violations
│   └── …
└── primitives/         Byte-contract vectors for the constructions underneath
```

The first two bind verifiers: they assert a `VerifierResult`. `primitives/` binds
implementations on either side of the protocol — key derivation, holder key sets,
submission sets, subject canonicalization — by asserting exact bytes rather than a
verdict, each implementation to the families for the constructions it performs (see
*Which vectors apply to which implementation* in the root `README.md`).
See [`primitives/README.md`](primitives/README.md).

## Per-fixture layout

Each fixture directory contains:

```
<FIXTURE_ID>/
├── README.md             Human description: what is being tested and why
├── input.json            The VerifierRequest: the requested target, the input mode and the artifact paths
├── expected-result.json  The exact VerifierResult a conformant verifier must produce
├── artifacts/            Input artifacts to feed the verifier (each when the request names it)
│   ├── base-certificate.json
│   ├── independence-proof.json
│   ├── capacity-evidence.json
│   ├── commitment-inclusion-proof.json
│   ├── settlement-material.json
│   ├── system-foundation.json
│   └── verification-package.json
└── material/             Original material for the opt-in comparison (when the request supplies it)
```

A conformant verifier passes the fixture if and only if the `VerifierResult` it produces matches `expected-result.json` on:

- `result_code` (one of `ISSUED_VALID`, `ISSUED_INVALID`, `INDEPENDENT_VALID`, `INDEPENDENT_INVALID`, `INCOMPLETE`, `UNSUPPORTED`, `REJECTED`)
- `verification_target` (the target the verifier resolved and evaluated)
- `failed_check_ids`, compared as a SET: nothing missing and nothing extra, order not compared (non-empty for `*_INVALID` and `INCOMPLETE` results)
- every further member the fixture's `expected-result.json` declares (`certcrypt_lineage`, `additional_verifications`, `attested_node`, `subject_scope`, `production_verification`, `complete_verification_against_original_material_*`). For `additional_verifications` only the fields it declares are compared: `Q001` and `Q003` pin `pqc_base_certificate_authentic` (`performed`, `algorithm`, `passed`) and leave `reason` free, since its wording is implementation-specific

Implementation-specific fields (timestamps, library version strings, runtime annotations) are not compared.

## Identifier semantics

The prefix of each fixture ID names the dimension under test; the directory
(`conformance/` or `adversarial/`) names the polarity. A dimension can have
fixtures on both sides.

- **`P`** — end-to-end positive paths through `Issued` and `Independent`
- **`V`** — verification-path violations: emission binding, rules and system domain, settlement reference and profile, finality, capacity binding, anti-splicing, original material, input handling
- **`F`** — the `system-foundation/1` statement: fingerprint derivation, quorum signature, profile, bootstrap match, the closed shapes of the statement and of the embedded bootstrap manifest, and the one encoding of each key (`F001` and `F005` are valid statements; the others fail closed)
- **`S`** — signature authenticity: the issuer's composite signature on the base certificate (`S001`–`S005`) and the mandatory signature of the `independence_proof` itself (`S006` valid, `S007` node attestation altered after signing, `S008` unsigned, `S009`–`S011` a composite whose layout is not the profile's: components reordered, `low_s` false, an extra member)
- **`Q`** — the post-quantum composite: the ML-DSA-65 component is normative, so a broken, stripped or mis-domained component fails
- **`QN`** — k-of-n quorum counting for the bootstrap statement and successor bindings
- **`C`** — the CCSP/1 certificate envelope: closed objects, reserved names, field formats, the single issuer signature, published digests, the domains the certificate names, repeated member names (`C001` valid, with every optional member)

Numbers are stable. A fixture is identified by its ID, not by its position in the directory listing.

## Adding or modifying fixtures

Fixtures are reproducible. The reference generator lives in this repository, in [`generator/`](../generator): `generate_fixtures.py` produces the conformance and adversarial vectors, `emit_primitives.py` the primitive byte-contract vectors. It recomputes every deterministic value from each vector's own inputs and asserts a byte-for-byte match on every run, so a fixture that drifts from the generator fails before it can ship.

Any change to a fixture (input artifacts or expected result) is a normative change to the conformance contract and MUST go through a version bump per the policy in the root `README.md`.

## Fail-closed reminder

A conformant verifier MUST be fail-closed: in the absence of evidence or under structural doubt, the result is never `Independent`. Every fixture under `adversarial/` exists to enforce this property at a specific point in the verification path.
