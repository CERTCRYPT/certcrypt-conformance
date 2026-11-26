# Deterministic reproducibility design

The conformance generator MUST be **byte-for-byte reproducible**: running it from
a clean checkout reproduces the committed fixtures in `../fixtures/` exactly
(README §Fixture reproducibility). This document fixes how.

## Principle

Every byte in a committed fixture MUST be a deterministic function of:

1. the fixture's synthetic inputs (its hardcoded parameters), and
2. the public rules (JCS, SHA3-256, Merkle, settlement profile, signature algs),

and of nothing else — no wall clock, no OS randomness, no per-run key material.
A regeneration that diverges from the committed set is a defect to resolve before
release (README §Fixture reproducibility); determinism is what makes that check meaningful.

Any independent generator, in any language, that follows this design produces the
same committed fixtures byte-for-byte. The rules below are the shared contract
such an implementation MUST honour.

## Sources of non-determinism and their fix

### 1. Nonces (and any per-artifact "random" field)

No OS randomness. Each nonce is derived from fixed inputs:

```text
nonce_hex = SHA3-256( utf8("certcrypt/conformance/nonce/1:" || fixture_id || ":" || field_path || ":" || index) )
```

The domain-tagged preimage gives distinct, stable nonces per (fixture, field,
occurrence) without a clock or RNG. The exact tag string is frozen here.

### 2. Signing keys (Ed25519, ML-DSA-65, ECDSA P-256)

Keys are **fixed test material**, never generated per run:

- **Ed25519**: a fixed `TEST_ROOT_*` key; RFC 8032 signing is deterministic.
  Adversarial fixtures that need a different ("attacker") key derive it from a
  fixed label — `SHA3-256("certcrypt/conformance/ed25519/1:" || label)` as the
  32-byte seed — never from a random keygen.
- **ML-DSA-65**: the keypair is derived from a **fixed 32-byte seed** (`ξ`) via
  the standard ML-DSA internal keygen, which is deterministic. A fixture that
  needs *several distinct* ML-DSA keypairs — the zero-data capacity path needs a
  holder operation-key tree plus a system-domain Level-1 key — derives each from
  a fixed label, the same discipline as the Ed25519 attacker key:
  `ξ = SHA3-256("certcrypt/conformance/ml-dsa/1:" || label)[:32]`, never an RNG.
  The label namespaces the role (e.g. `holder-op-key-2`, `system-domain`), so a
  fixture's full key material is a pure function of frozen label strings.
- **ECDSA P-256** (classical component of the composite profile, and each root
  quorum member's classical key): the private scalar is derived from a master
  seed via HKDF-SHA3-256 with the frozen info string `certcrypt/composite/p256/v1`
  (`P256_DERIVE_INFO`), byte-identical to the runtime `signing_key_from_seed`.
  Root quorum members derive their seed from a fixed label
  `SHA3-256("certcrypt/conformance/member-p256/1:" || member_kid)[:32]`.

### 3. Signatures (ML-DSA-65 and ECDSA P-256)

FIPS 204 defines both a hedged (randomized) and a **deterministic** signing
variant; the deterministic variant fixes the per-signature randomness to zero.
The generator MUST use the **deterministic variant** so a signature is a pure
function of (secret key, message), and therefore byte-for-byte reproducible.

This is also what makes ML-DSA reproducible *across implementations*: the
deterministic FIPS 204 signature is interoperable — the same seed + message yield
byte-identical keypair and signature regardless of the library. The generator's
ML-DSA dependency MUST expose deterministic signing; a library that cannot is
unsuitable for the canonical generator (the contract requires reproducibility
over convenience).

**ECDSA P-256** has the same requirement, with a sharper trap: most libraries
(including Python's `cryptography`) sign with a **random** nonce, which is NOT
reproducible. The generator MUST use **RFC 6979 deterministic** ECDSA over the
SHA3-256 prehash, with H = SHA3-256 for the nonce's HMAC as well, low-s
normalization, and raw `r||s` (64 bytes). The reference Python generator routes
P-256 signing through `python-ecdsa` (`sign_digest_deterministic` with
`hashfunc=sha3_256`, `sigencode_string_canonize`).
Because RFC 6979 fixes the nonce as a function of (key, message, H), any signer
that follows this rule produces **byte-identical** P-256 components; the
`ecdsa-p256-deterministic` primitive family pins them. A signer that is
deterministic under a different HMAC hash (for example HMAC-SHA-256 over the same
SHA3-256 prehash) produces components that verify against every fixture here but
are not byte-identical to them. The Rust signer (`capacity-verify`) derives its
nonce with HMAC-SHA3-256 as well and is held to the family byte for byte.

## What gets pinned in fixtures

With the above, **both** the signing bytes AND the raw signature are
deterministic, so a fixture pins the full signed artifact. (Contrast with the
hedged-signature primitive vectors elsewhere in the suite, which deliberately pin
only signing bytes + digests because they model production hedged signing — those
stay as they are; this determinism rule governs the GENERATOR's output, not the
production signing path.)

## How the property is checked

Determinism that is asserted but never re-run decays silently, so the suite checks
it two ways and both are release gates.

**The primitive oracle.** `emit_primitives.py` recomputes every deterministic
value in `fixtures/primitives/` from that vector's own inputs — using only
`primitives.py`, never the committed file — and asserts a byte-for-byte match. For
the three goldens that embed signatures produced by the reference producer
implementation with test keys (hedged, so verified rather than reproduced) it
recomputes the
deterministic envelope (JCS, digests, Merkle) and verifies the embedded signatures
against the pinned public keys. A non-zero exit means a primitive drifted from the
rules:

```bash
cd generator
PYTHONPATH=. python emit_primitives.py                 # against ../fixtures
PYTHONPATH=. python emit_primitives.py --fixtures DIR  # against another tree
```

**The generator's own gate.** `generate_fixtures.py` calls that same oracle at the
end of every run, against the canonical repository fixtures regardless of `--out`,
so a rules drift fails the run that produced it rather than surfacing later.

Both need three third-party packages that are not vendored: `dilithium-py`
(ML-DSA-65), `ecdsa` (RFC 6979 P-256) and `cryptography` (Ed25519, key
serialization). A generator in another language substitutes its own equivalents;
what it may not substitute is the deterministic mode of each — see §3.

## Frozen shared constants

Any conformant generator MUST use exactly these:

- the nonce derivation tag, the Ed25519 attacker-key derivation tag, the ML-DSA
  label-derivation tag, the P-256 HKDF info string `certcrypt/composite/p256/v1`
  and the quorum-member label tag (§1–§2),
- the Ed25519 test key and the fixed ML-DSA-65 seed (§2),
- the deterministic ML-DSA signing mode, and RFC 6979 ECDSA over the SHA3-256
  prehash (HMAC-SHA3-256 nonce) with low-s normalization and raw `r||s`
  encoding (§3),
- JCS (RFC 8785), SHA3-256, both Merkle schemes (settlement `0x00`/`0x01`;
  collection domain-tag + `u64be`), and the settlement profile.

Changing any of them changes the committed fixtures, which is a change to the
conformance contract and takes a version bump — see the root `README.md`
§Versioning. They are frozen here so that a generator in another language has one
place to read them from.

## JCS number/string parity

RFC 8785 number serialization follows ECMAScript `Number.prototype.toString`,
which not every language's default JSON encoder reproduces. A generator MUST
implement RFC 8785 number formatting explicitly rather than rely on a stock JSON
encoder, and validate against the committed fixtures and the `primitives/*`
signing-byte vectors, which pin exact JCS output. The reference Python generator
implements JCS in-tree (`primitives.py`) for this reason.

**Null members are preserved.** RFC 8785 does NOT drop members whose value is
JSON `null`; they serialize as `"key":null`. A generator MUST keep them. This is
load-bearing for `system-manifest/1`: the bootstrap entry carries five null
members (`valid_until`, `predecessor_kid`, `successor_kid`,
`predecessor_signatures`, `predecessor_manifest_fingerprint`), and
`system_root_fingerprint = SHA3-256(JCS(manifest))` only matches the reference
implementation (`serde_json_canonicalizer`) when those nulls are present in the
canonical bytes. A JCS that strips null members produces a different digest and
breaks the cross-stack arbiter.
