# CERTCRYPT Conformance Suite

Reference conformance suite for CERTCRYPT: the contract that binds every implementation, on either side of the protocol. It carries the JSON Schemas for verifier inputs and outputs, the deterministic fixtures that fix the verdict a verifier MUST return, and the primitive byte-contract vectors that fix the exact bytes an issuer, a node or a verifier MUST reproduce.

CERTCRYPT is infrastructure that makes certification independently verifiable under public rules. It supports `Proof of Independence`: a structural result that allows selected artifacts to reach `Independent`, so later verification no longer depends on the issuer's live systems.

This repository is the language-independent contract that any implementation — in any language, on either side of the protocol — is evaluated against. It carries the JSON Schemas (normative declaration of the contract), the fixtures (deterministic test vectors), the primitive byte-contract vectors, and the reference generator that produces them byte-for-byte. It does not carry any implementation or language-specific bindings of the schemas.

The two halves bind different audiences. `fixtures/conformance/` and `fixtures/adversarial/` assert a `VerifierResult`, so they bind verifier toolkits. `fixtures/primitives/` asserts exact bytes for the constructions underneath — key derivation, holder key sets, submission sets, subject canonicalization — so they bind SDKs and `certcrypt-node` as strictly as the verdicts bind a verifier. An issuer that derives a key set is held to those vectors the same way.

> [!NOTE]
> **Released contract versions are frozen.**
>
> After a version is released, its fixture identifiers and expected results are stable. Changing an expected result, or adding a fixture, requires a MAJOR bump — see [Versioning](#versioning) for why adding one is breaking rather than additive.
>
> The fixtures, primitive byte-contract vectors, reference generator, and the normative JSON Schemas are present, reconciled, and reproducible, and the generator verifies them on every run.

## The repository today

This repository carries the conformance contract as data, plus the reference generator that produces it:

- `fixtures/conformance/` and `fixtures/adversarial/` — the positive and negative test vectors (see the inventory below).
- `generator/` — the Python reference generator that reproduces those fixtures byte-for-byte, including the ECDSA P-256, ML-DSA-65 and Ed25519 signatures.
- **Public scope.** This README: what the conformance suite is for, what the contract guarantees, and what it explicitly does not.
- **License.** The license under which the schemas, fixtures and generator are released.
- **Security process.** How to report and how disclosures are handled.
- **Code ownership.** Codeowners attached to the repository.
- **Terminology boundary.** The terms used to describe `Issued`, `Independent`, `Proof of Independence`, the verifier's role, conformance and fixture taxonomy — set in the same way the rest of the public documentation sets them.
- **`VERSION`.** The active version of the conformance contract, currently `1.0.0`, alongside a changelog of every change to it.

The `fixtures/primitives/*` cross-language byte-contract vectors are present and the generator reproduces/verifies them: `generator/emit_primitives.py` recomputes every deterministic value from each vector's own inputs and asserts a byte-for-byte match, and verifies the three goldens whose embedded signatures were produced by the reference producer implementation with test keys (hedged ML-DSA-65 + composite, so verified rather than reproduced) against the pinned public keys. The JSON Schemas in `schemas/` are the normative declaration of the verifier input and output shapes; `generator/validate_schemas.py` checks they are valid JSON Schema Draft 2020-12 and that every fixture request conforms to the input schema, and the verifier-toolkit test suite validates a real full `VerifierResult` against the output schema.

## The shape of the contract

This repository carries:

- `schemas/input/` — JSON Schemas for verifier inputs: the `VerifierRequest`, the CCSP/1 `base_certificate` (`base-certificate.schema.json`) and the settlement material of `settlement.aggregated.xrpl/1` §9.5 (`settlement-material.schema.json`) and the `verification_package` of `verification-package/1` §9.4 (`verification-package.schema.json`); the artifact schemas are necessary, not sufficient — the rules a schema cannot express are listed in their `$comment`.
- `schemas/output/` — JSON Schemas for verifier outputs (`VerifierResult` and related types); `failed_check_ids` admits only the check identifiers of `verifier-toolkit/1` §9.7.
- `fixtures/conformance/` — positive test vectors (`P001`–`P016`, `F001`, `F005`, `S001`, `S006`, `Q001`, `Q002`, `C001`); a conformant verifier MUST return the expected `*_VALID` result for each.
- `fixtures/adversarial/` — negative test vectors (`V001`–`V083`, `F002`–`F004`, `F006`–`F018`, `S002`–`S005`, `S007`–`S011`, `Q003`–`Q005`, `QN1`–`QN8`, `C002`–`C019`); a conformant verifier MUST return the expected result for each (`*_INVALID`, `INCOMPLETE`, `UNSUPPORTED` or `REJECTED`), with the expected `failed_check_ids`.
- `generator/` — reference fixture generator, written in Python, depending only on widely available cryptographic standards. It produces the fixtures committed in `fixtures/` from synthetic inputs by applying the public rules. Python is chosen because it is the standard language of the cryptographic regulatory sector (NIST, IETF drafts, auditors), readable and reproducible by any third party without learning a verifier's implementation language.
- `VERSION` — the active version of the conformance contract.

What the repository does **not** carry, at any phase:

- any verifier implementation,
- any issuer-side code,
- any language-specific binding of the schemas (verifiers generate their own bindings),
- live or operational secrets.

Implementations live in their own repositories, per language and per side of the protocol.

The reference verifier implementation is [`certcrypt-verifier-toolkit-js`](https://github.com/CERTCRYPT/certcrypt-verifier-toolkit-js); the remaining languages are planned. On the issuer side, [`certcrypt-sdk-js`](https://github.com/CERTCRYPT/certcrypt-sdk-js) and [`certcrypt-sdk-python`](https://github.com/CERTCRYPT/certcrypt-sdk-python) consume the primitive vectors, as does the Rust `certcrypt-node-core` — which is what those vectors exist to keep in step.

Verifier implementations are planned for the following additional languages and platforms, listed alphabetically, to be released as each implementation stabilizes. The order here is not a sequence:

- `certcrypt-verifier-toolkit-android` — Kotlin (Android)
- `certcrypt-verifier-toolkit-dotnet` — .NET
- `certcrypt-verifier-toolkit-go` — Go
- `certcrypt-verifier-toolkit-ios` — Swift (iOS)
- `certcrypt-verifier-toolkit-java` — Java
- `certcrypt-verifier-toolkit-kotlin` — Kotlin (JVM)
- `certcrypt-verifier-toolkit-php` — PHP
- `certcrypt-verifier-toolkit-python` — Python
- `certcrypt-verifier-toolkit-ruby` — Ruby
- `certcrypt-verifier-toolkit-rust` — Rust

CERTCRYPT verification is offline by design: every verifier evaluates artifacts under public rules without contacting any live authority. Native implementations in each language are required so verification can happen on the consumer's device — including mobile, where sending the material to a server would defeat the offline and privacy properties of the protocol.

## How verifiers consume the suite

A conformant verifier consumes this repository as a versioned dependency, pinned to a release:

- as a git submodule, pinned to a tag,
- as a vendored copy with the version recorded in the verifier's lockfile,
- as a downloaded archive of a specific tagged release.

For each fixture, the verifier will:

1. Read the artifacts in `fixtures/<category>/<id>/artifacts/`.
2. Construct the `VerifierRequest` that `fixtures/<category>/<id>/input.json` states.
3. Execute its `verify(request)` operation.
4. Compare the produced `VerifierResult` to the expected one in `fixtures/<category>/<id>/expected-result.json`.
5. Pass the fixture if and only if `result_code` and `verification_target` are equal to the expected values and `failed_check_ids` is the same SET — nothing missing and nothing extra; its order is not compared. A fixture that declares further members (`certcrypt_lineage`, `additional_verifications`, `attested_node`, `subject_scope`, `production_verification`, `complete_verification_against_original_material_*`) passes only if those are equal too; `required_artifacts_missing`, like `failed_check_ids`, is compared as a set. Every fixture states its request in `input.json`, including whether it supplies a `verification_package`; no fixture depends on a mode of the verifier.

A verifier implementation is **conformant** if and only if it passes every fixture in the version of the suite it claims to support. Partial conformance is not a defined state.

**The core property of the contract:** every conformant verifier, regardless of implementation language, MUST return the same `VerifierResult` for the same fixture. This is what conformance means under public rules.

## Which vectors apply to which implementation

The verdict fixtures bind verifiers, and every verifier is held to all of them.
The primitive vectors are different: they bind whoever performs the construction
each one fixes, and no single implementation performs them all. An issuer SDK
never assembles a settlement preimage; a verifier never mints an operator
receipt. Holding every implementation to all 29 families would make conformance
unachievable and therefore meaningless.

So the primitive vectors divide by ROLE — by what an implementation does, not by
what product it is. An implementation is held to every family for a construction
it performs, in either direction: producing those bytes, or reconstructing them
to check a signature.

| Role | What it does | Families it is held to |
| --- | --- | --- |
| **Any implementation** | Handles subjects and digests at all | `subject-*`, `strict-json`, `collection-merkle`, `original-material`, `pseudonym`, `key-derivation`, `artifact-shape` |
| **Issuer side** | Mints certificates and capacity evidence | the above, plus `holder-keyset`, `capacity-evidence`, `level1-binding`, `submission-set`, `submission-set-limits`, `issuer-key-derivation`, `ecdsa-p256-deterministic`, and `ccvp-consistency` when it mints context snapshots (the composite key fingerprint) |
| **Transport side** | Carries submission sets on an issuer's behalf | the above, plus `operator-receipt`, and `operator-domain-binding` when it signs `operator.domain-binding/1` statements |
| **Settlement side** | Assembles the material that makes a certificate `Independent` | the above, plus `settlement-preimages`, `independence-proof-signature`, `verification-package` |
| **Verifier side** | Returns a `VerifierResult` | the 160 verdict fixtures, plus every family whose bytes it reconstructs to check: `capacity-evidence`, `level1-binding`, `independence-proof-signature`, `ccvp-consistency`, `rules-domain`, `manifest-resolution`, `artifact-shape`, `composite-m-prime`, `composite-verification` |

**`issuer-key-derivation` binds the issuer that signs base_certificates with a
key derived from its seed.** A verifier reads the public keys a certificate
carries and never derives them, and a node never holds the seed, so neither is
held to it.

**`ecdsa-p256-deterministic` binds the issuer that signs, and pins the
signature itself.** An issuer signs its base_certificates with an RFC 6979
deterministic nonce, so one key over one message has exactly one signature and
two implementations can be compared byte for byte. A verifier accepts any valid
low-s signature, deterministic or not, so it is not held to the family.

**`operator-receipt` is transport-side only, and that is a decision.** The receipt
is a detachable, opt-in artifact: a verifier that receives one can confirm which
operator carried a submission set, and a verifier WITHOUT one reaches the same
verdict. Nothing in the 160 verdict fixtures depends on it. So a toolkit that never
handles a receipt is fully conformant — holding it to that family would demand
code the contract does not require.

**`operator-domain-binding` binds whoever signs or checks an
`operator.domain-binding/1` statement**: the node that declares a host name with
its operator key, and any party that checks the declaration — fetches the
host's `/.well-known/certcrypt-node.json` and decides whether the key and the
origin declare each other. The binding is no part of an independence proof and
no input to its verification, so a verifier is not held to it. The
specification is a Draft; the family fixes it as it stands.

A role is a set of behaviours, not a deployment. One program often has several:
an SDK that both mints and verifies is held to both columns.

**`artifact-shape` appears in every row on purpose.** It fixes the field SET of
each signed preimage, and getting that wrong is the one divergence no digest can
catch — an implementation that signs one field too many computes a perfectly
correct digest over the wrong object. Both producing and checking a signature
depend on agreeing about what is inside it.

**State your role when you state conformance.** "Conformant against 1.0.0" is
incomplete for anything that is not a verifier; the honest claim names the
families, so a reader can tell what was checked from what was merely present.

## Fixture taxonomy

Fixture identifiers carry meaning. The prefix names the dimension being tested; the directory (`conformance/` or `adversarial/`) names the polarity, and a dimension can have fixtures on both sides:

- `P` — end-to-end positive paths through `Issued` and `Independent`,
- `V` — verification-path violations (emission binding, rules and system domain, settlement reference and profile, finality, capacity binding, anti-splicing, original material, input handling),
- `F` — the `system-foundation/1` statement (`F001` and `F005` are valid statements; the others fail closed),
- `S` — signature authenticity: the base certificate's composite issuer signature (`S001`–`S005`) and the mandatory signature of the `independence_proof` itself (`S006` valid, `S007` node attestation altered after signing, `S008` unsigned, `S009`–`S011` a composite whose layout is not the profile's: components reordered, `low_s` false, an extra member),
- `Q` — the post-quantum composite: the ML-DSA-65 component is normative,
- `QN` — k-of-n quorum counting for the bootstrap statement and successor bindings,
- `C` — the CCSP/1 certificate envelope: closed objects, reserved names, field formats, the single issuer signature, published digests, the system and rules domain the certificate names, and repeated member names (`C001` is valid and carries every optional member).

A conformant verifier MUST be fail-closed: in the absence of evidence or under structural doubt, the result is never `Independent`.

## Fixture reproducibility

The fixtures in this repository are deterministic and reproducible. They are produced by applying the public rules — SHA3-256 digests, RFC 8785 (JCS) canonicalization, Merkle construction, and the published settlement profile — to synthetic inputs.

The reference generator lives at `generator/`, written in Python. Any independent generator implementation in any language that produces byte-identical fixtures from the same synthetic inputs is equally valid. The authoritative artifacts of the conformance contract are the JSON fixtures committed here — not any specific generator that produced them.

If an independent implementation produces fixtures that diverge from the ones committed here, the divergence MUST be resolved before any release. Either the generator is wrong, the committed fixtures are wrong, or both — the public rules are the arbiter.

## Authority of schemas

The JSON Schemas in `schemas/` are the normative declaration of the shape of verifier inputs and outputs. Any verifier implementation MUST conform to these schemas. Any language-native types in any verifier implementation are conveniences, not normative — the schemas are the contract.

## Versioning

The conformance suite is versioned independently from any verifier implementation. A verifier that claims conformance MUST state which version of this suite it was tested against.

Version bumps follow semantic versioning relative to the conformance contract:

- **major** — a fixture's expected result changes, a fixture is added or removed, or a schema breaks backward compatibility,
- **minor** — new optional schema fields are introduced, or a schema is extended in a backward-compatible way,
- **patch** — non-normative changes (typos in README, additional comments in test cases, fixture-internal annotations that do not change inputs or expected outputs).

**Adding a fixture is a MAJOR bump, not a minor one**, and this is the one place
this contract departs from how a library would version itself. A verifier
conformant against `N` vectors is not automatically conformant against `N+1`, and
partial conformance is not a defined state — so a new vector can turn a truthful
conformance claim into a false one without a line of the verifier changing. Calling
that minor would invite exactly the silent regression the suite exists to catch.

By the same reasoning a changed `expected-result.json` is breaking even when no
file is added or removed: an implementation that passed before can fail after,
with nothing in its own code having moved.

The active version is recorded in [`VERSION`](VERSION) at the root of the repository, and changes to the contract are recorded in [`CHANGELOG.md`](CHANGELOG.md).

## CERTCRYPT boundary

- not a claim of factual truth
- not a validator of correctness
- not a custodian of documents
- not blockchain notarization
- not a trust badge

## Boundary of this conformance suite

- not a verifier (it is the input to verifiers, not a verifier itself)
- not a determiner of semantic truth, legal validity, or factual correctness
- not a substitute for the public rules under which an artifact is evaluated
- not an endorsement of any issuer or of any underlying material
- not a runtime dependency of any verifier in production (it is a test-time dependency)

A verifier that passes the suite is conformant to the suite's version. Conformance to the suite is a necessary but not sufficient condition for being a useful verifier in practice — operational concerns (performance, packaging, error reporting) live outside this contract.

## What conformance is, and what it is not

This section governs what an implementer may state publicly on the basis of this
suite. It is a statement of scope, not a restriction on use: the suite is Apache-2.0
and anyone may run it, vendor it, and build against it.

### Two different things the word "conformance" can mean

**Verifier conformance — what this suite establishes.** An implementation is
conformant if it passes every fixture in the version of the suite it claims to
support (see *Versioning*). This is objective, reproducible by anyone, and requires
no permission from CERTCRYPT: run the fixtures and read the results.

**Domain recognition — what this suite does NOT establish.** Whether artifacts are
attributed to the CERTCRYPT system domain is a separate question, decided by
`system-domain/1` attribution against a published bootstrap fingerprint — not by
passing tests. A conformant verifier pointed at another root is a correct verifier
of *another system*. That is a legitimate thing to build, and the fixtures cover it:
artifacts under a foreign root yield `INDEPENDENT_INVALID` with
`CLONE_OR_FORK_REJECTED` among the failed checks (`V002`, `V019`).

The two are independent. An implementation can be fully conformant and have no
relationship with CERTCRYPT whatsoever.

### Stating conformance

Accurate, and needs no permission — it is a factual claim anyone can re-check:

> "Passes the CERTCRYPT conformance suite `<version>`."

Always name the version you actually ran against — the one in `VERSION` at the
time — rather than copying a number from here. A claim without a version is
unverifiable, and the suite is versioned precisely so the claim can be re-run.

Not supported by this suite, because each asserts a relationship or an approval that
passing tests does not create:

- "CERTCRYPT-certified", "CERTCRYPT-approved", "officially recognized"
- "a CERTCRYPT system", "CERTCRYPT-compatible infrastructure"
- any wording implying that CERTCRYPT audited, endorsed, or is responsible for the
  implementation, or that artifacts it produces are attributed to the CERTCRYPT
  system domain

The distinction is not pedantry. A relying party reading "CERTCRYPT-certified"
reasonably concludes that CERTCRYPT stands behind the result. Nothing in this
repository creates that, and a claim that implies it misleads the party least able
to check.

### Trademarks

The Apache-2.0 grant covers copyright, not marks: §6 of the licence grants no
permission to use CERTCRYPT trade names, trademarks, service marks or product names
beyond describing the origin of the work. Naming the suite you tested against is
such a use. Naming your product after CERTCRYPT is not.

## Documentation

Technical documentation and the public specifications are published at
[docs.certcrypt.com](https://docs.certcrypt.com): the model, the terminology, the
claims boundary, and the normative specifications this contract encodes as
fixtures. Where a fixture and a specification disagree, the specification is the
arbiter.

## Links

| Surface | Address |
| --- | --- |
| Website | [certcrypt.com](https://certcrypt.com) |
| Documentation | [docs.certcrypt.com](https://docs.certcrypt.com) |
| Verify an artifact | [verify.certcrypt.dev](https://verify.certcrypt.dev) |
| Blog | [blog.certcrypt.com](https://blog.certcrypt.com) |
| Support | [support.certcrypt.com](https://support.certcrypt.com) |
| Service status | [status.certcrypt.com](https://status.certcrypt.com) |
| Open source | opensource@certcrypt.com |
| Security | security@certcrypt.com — see [`SECURITY.md`](SECURITY.md) |

**Verifier implementations**, held to the verdicts:

| Language | Repository |
| --- | --- |
| JavaScript / TypeScript | [certcrypt-verifier-toolkit-js](https://github.com/CERTCRYPT/certcrypt-verifier-toolkit-js) |

**Issuer-side implementations**, held to the primitive byte-contract vectors
rather than to the verdicts. They do not return a `VerifierResult`, so they are
not conformant *verifiers*; what they must reproduce is the bytes:

| Language | Repository |
| --- | --- |
| JavaScript / TypeScript | [certcrypt-sdk-js](https://github.com/CERTCRYPT/certcrypt-sdk-js) |
| Python | [certcrypt-sdk-python](https://github.com/CERTCRYPT/certcrypt-sdk-python) |
| Rust | [certcrypt-node](https://github.com/CERTCRYPT/certcrypt-node) (`certcrypt-node-core`) |

**Where the conformance claim lives.** Not here. Each implementation states, in
its own repository and against its own release, which version of this suite it
was tested against — this repository versions the contract, not its consumers. A
table of who-passed-what would go stale on someone else's release, and would
invert the dependency the contract exists to hold in one direction.

The point of keeping the contract as data is that the identical fixture must
produce the identical `VerifierResult` in every language, so a second binding
proves the contract rather than being trusted on its own. The byte half works the
same way: the SDKs and the node core reproduce the same primitive vectors, which
is what keeps the two sides of the protocol from drifting apart. Conformance is per version, and partial
conformance is not a defined state.

## Changelog

Changes to the contract are recorded in [`CHANGELOG.md`](CHANGELOG.md), against
the version in [`VERSION`](VERSION).

Read it before pinning a version: this repository is data, so a changed
`expected-result.json` — or an added fixture — is a breaking change for a verifier
that passed the previous set, even though nothing in its own code moved.

## License

Copyright © 2025-2026 CERTCRYPT, Inc., its affiliates or licensors. All rights reserved.

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) for the full text.
