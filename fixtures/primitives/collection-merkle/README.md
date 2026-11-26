# `collection-merkle` — primitive conformance vectors

Canonical test vectors for the `collection.merkle-sha3-256/1` commitment scheme —
the Merkle scheme that hides the leaves of a `subject.collection/1` subject behind a
single `root`. These are the reference cross-implementation parity vectors: any two
conforming implementations MUST agree on every `root` and every `inclusion_proof`
below, or at least one is non-conformant.

Origin: normative spec `collection.merkle-sha3-256/1 §10-§13` (leaf preimage, node
preimage, tree construction). The generator's oracle (`generator/emit_primitives.py`)
recomputes every leaf hash, `root` and `inclusion_proof` from each vector's own leaves
with `generator/primitives.py`, so a vector that drifts from the spec fails the run.

## Vectors — one per algorithm branch

| file | leaves | branch exercised |
|------|--------|------------------|
| `vector-01-leaf.json`        | 1    | single-leaf tree; root equals the only leaf hash |
| `vector-02-leaves.json`      | 2    | balanced two-leaf tree |
| `vector-03-leaves-odd.json`  | 3    | odd-width promotion at level 0 |
| `vector-04-leaves.json`      | 4    | balanced four-leaf tree |
| `vector-05-leaves-odd.json`  | 5    | odd-width promotion at levels 0 **and** 1 |
| `vector-06-1024-leaves.json` | 1024 | balanced ten-level tree, no odd-width |

## Element-level inclusion — negative & control oracle

`negative-inclusion.json` is the cross-implementation oracle for the **element-level
inclusion operation** (`verifyCollectionInclusion`, spec §14 proof object / §15
procedure / §16 failure conditions) — the capacity of checking ONE declared leaf
against the root on its own, without supplying the rest of the collection. Each `cases[]`
entry gives one `leaf_hex` (canonical bytes under `leaf_profile`), its `proof`
(`{proof_version, leaf_index, sibling_hashes}`), the `declared_cardinality` and `root`
to check against, and `expected_valid`. A conforming toolkit MUST return
`valid == expected_valid` for every case. `reason_class` names the §16 failure class
(informative; not byte-pinned). Cases cover: a control positive, false leaf, false
path (tampered sibling), non-matching root, path too long / too short, out-of-bounds
and non-canonical `leaf_index`, wrong `proof_version`, malformed sibling, a proof
object with an additional member (§14.4), and a non-hex64 root. The verifier-toolkit-js unit test
`core/crypto/collection-inclusion.test.ts` consumes this file directly, and the Python
oracle (`generator/emit_primitives.py` → `verify_collection_inclusion`) checks the
same verdicts — so both implementations agree on the whole rejection surface.

## Element-level inclusion from the certificate alone

`certificate-element.json` is the oracle for `verifier-toolkit/1` §8.4.2: given a
certificate and ONE leaf value — no inclusion proof from anyone — the toolkit decides
membership itself. `certificates` holds three signed certificates of the conformance
domain: `A` declares a heterogeneous collection (`subject.binary/1` "alpha",
`subject.text/1` "beta", "alpha" again, "gamma"), `B` declares the same leaves under a
root they do not fold to, and `A_altered` is `A` changed after signing. Each `cases[]`
entry names a certificate, a `value_utf8` and the `expected` outcome (`member`,
`not_member`, `rejected` or `certificate_not_issued_valid`) with every match
(`subject_index`, `profile`, `leaf_indices`). The certificates are written by
`generator/generate_fixtures.py`, the outcomes are recomputed independently by
`generator/emit_primitives.py`, and the verifier-toolkit-js test
`core/issued/verify-collection-element.test.ts` runs every case.

## Fixture format

- `label` — human-readable description.
- `commitment_scheme` — `collection.merkle-sha3-256/1`.
- `leaf_profile` — the subject profile each leaf material is canonicalized under.
- `declared_cardinality` — canonical unsigned-integer string; equals `len(leaves_hex)`.
- `leaves_hex` — the ordered leaf materials, hex-encoded (already the canonical bytes
  under `leaf_profile`).
- `root` — the expected collection root (lowercase hex).
- `inclusion_proofs` — one per leaf: `{proof_version, leaf_index, sibling_hashes}`.

## How to consume

For each vector: `leaf_hash_i = collectionLeafHash(leaf_profile, leaves_hex[i])`;
reconstruct the root by pairing left-to-right and promoting a lone right-edge hash
unchanged; assert it equals `root`. For each inclusion proof, fold the leaf hash with
its `sibling_hashes` and assert the result equals `root`. The verifier-toolkit-js unit
test `core/crypto/collection-merkle.test.ts` runs exactly this against these files.
