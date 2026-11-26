# Primitive byte-contract vectors

Low-level golden vectors for the constructions underneath the verdicts: subject
canonicalization, key derivation, the zero-data capacity-evidence profile
(`zero-data.unlinkable`), submission sets, settlement preimages and composite
signatures.
Distinct from `../conformance` and `../adversarial`, which exercise the full
verifier and assert a `VerifierResult`. These assert the **exact bytes** every
conformant implementation MUST reproduce, in any language.

If two implementations disagree on a single byte here, every higher-level
binding fails silently — so these vectors are the anti-drift control for
cross-language parity between the Rust `certcrypt-node-core`, the issuer SDKs
(`certcrypt-sdk-*`) and the verifier toolkits (`certcrypt-verifier-toolkit-*`).
Each implementation is held to the families for the constructions it performs
(see *Which vectors apply to which implementation* in the root `README.md`).

## Layout

```
primitives/
│   ── identity: what a seed materializes ──────────────────────────────
├── key-derivation/   one 32-byte seed → P-256 + ML-DSA-65 + composite fingerprint
├── issuer-key-derivation/  the issuer's signing key from its seed alone; the key id is a label
├── ecdsa-p256-deterministic/  one key + one message → one P-256 signature (RFC 6979, SHA3-256, low-s)
│   ── canonicalization: what gets signed ──────────────────────────────
├── level1-binding/   holder authorization — INSERTION-ORDERED bytes (not JCS)
├── operator-receipt/ the node's carriage receipt — JCS over the no-signature view
├── operator-domain-binding/  an operator key declaring a host name: statement bytes, checks, the published document
├── capacity-evidence/  assembled evidence → its canonical digest (JCS)
├── submission-set/   submission_set_id recompute
├── pseudonym/        operation-scoped pseudonyms, length-framed
│   ── trees ───────────────────────────────────────────────────────────
├── holder-keyset/    operation-key Merkle tree (leaf hash, root, inclusion proof, disclosure verdicts)
├── collection-merkle/  collection fold, incl. odd widths and a 1024-leaf tree
│   ── policy: what a rules domain fixes ───────────────────────────────
├── rules-domain/     commitment TTL and settlement profile per domain
├── submission-set-limits/  member cap and the system-wide constants
│   ── production side: what a node emits ──────────────────────────────
├── settlement-preimages/   leaf + batch-binding preimage bytes and digests
│   ── shape: what a signed preimage contains ──────────────────────────
├── artifact-shape/   the exact field set of each signed artifact
│   ── behaviour: what a resolver must refuse ──────────────────────────
├── manifest-resolution/  (fingerprint, kid) lookup and the activity window
│   ── signatures ──────────────────────────────────────────────────────
├── composite-m-prime/  the domain-separated message M′ every component signs
├── composite-verification/  what a composite verifier must refuse (PQC floor, order, encodings)
├── independence-proof-signature/  a signed proof verified against the system-domain keys
│   ── consistency ─────────────────────────────────────────────────────
├── ccvp-consistency/  CCVP/1 outcomes over signed certificates
│   ── subjects ────────────────────────────────────────────────────────
├── subject-{binary,text,email,collection,ai-decision,context-snapshot}/
├── strict-json/      which JSON parses: no member name twice in one object, at any depth
├── original-material/
└── verification-package/  full worked example
```

**Two canonicalizations coexist, on purpose.** Some artifacts sign
insertion-ordered bytes (`level1-binding`), others sign JCS (`operator-receipt`,
`capacity-evidence`). Neither can be guessed from the other, so each vector pins
its own — and `level1-binding` additionally pins the digest JCS would have
produced, as a tripwire for the natural wrong guess.

Each vector file is self-describing JSON: inputs + the exact expected output.
A conformant implementation passes iff it reproduces every `expected` value
byte-for-byte.

**Some families pin something other than bytes.** `artifact-shape` pins the field
SET of each signed preimage, and `manifest-resolution` pins a refusal. Neither
has an output to compare, and that is exactly why they exist: an implementation
that signs a preimage with one field too many, or resolves a key it does not
hold, computes a perfectly correct digest over the wrong object. Every byte
vector passes and two implementations still disagree. `submission-set-limits`
is the third of this kind — constants that decide admission before a byte is
hashed. `issuer-key-derivation` is the fourth: besides the two public keys, it pins that
the issuer key id does NOT enter the derivation, because two issuers that
disagree on that sign the same seed's certificates under two identities, and
every one of those certificates still verifies.

## Provenance

Authored from `certcrypt-node-core` (the reference Rust implementation) and
pinned. Three goldens embed signatures produced by the reference producer
implementation with test keys; their ML-DSA-65 components are hedged, so they are
verified rather than reproduced. `ccvp-consistency/` is written by
`generator/generate_fixtures.py`, because its certificates carry signatures the
generator produces. `issuer-key-derivation/` and `ecdsa-p256-deterministic/` are
authored by
`generator/author_issuer_key_derivation_vectors.py` and
`generator/author_ecdsa_p256_deterministic_vectors.py` from the generator's own
primitives, and re-authored with

```sh
cd generator && PYTHONPATH=. python author_issuer_key_derivation_vectors.py ../fixtures/primitives/issuer-key-derivation/vectors.json
cd generator && PYTHONPATH=. python author_ecdsa_p256_deterministic_vectors.py ../fixtures/primitives/ecdsa-p256-deterministic/vectors.json
```

`operator-domain-binding/` is authored by
`generator/author_operator_domain_binding_vectors.py`, which computes the bytes
(keys from fixed seeds, JCS, digests, FIPS 204 deterministic ML-DSA-65
signatures) but not the verdicts: every expected acceptance, refusal rule and
match is written out from `operator.domain-binding/1` (Frozen), and
`emit_primitives.py` re-derives each one with its own implementation of the
rules, reproduces the signatures and verifies them. Re-authored with

```sh
cd generator && PYTHONPATH=. python author_operator_domain_binding_vectors.py ../fixtures/primitives/operator-domain-binding
```

`emit_primitives.py` then checks every case, as for the other families: it
recomputes every deterministic value from each vector's own inputs. Any change is
a normative change to the conformance contract and MUST go through a version bump
per the root `README.md`.
