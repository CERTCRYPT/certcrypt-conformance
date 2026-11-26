# Copyright © 2025-2026 CERTCRYPT, Inc., its affiliates or licensors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Author fixtures/primitives/issuer-key-derivation/vectors.json from the
generator's own primitives (run with PYTHONPATH=<conformance>/generator).

Deterministic: every value is a pure function of the seeds and tree sizes below,
so a re-run reproduces the committed file byte for byte."""
import base64
import hashlib
import json
import sys
from collections import OrderedDict

from ecdsa import NIST256p, SigningKey

import primitives as P

OUT = sys.argv[1]

P256_LABEL = "issuer-cert-key/p256"
MLDSA_LABEL = "issuer-cert-key/mldsa"
N = NIST256p.order


def holder_root(master: bytes, size: int) -> str:
    pks = []
    for i in range(size):
        leaf_seed = hashlib.sha3_256(master + f"op-key/{i}".encode("utf-8")).digest()
        pks.append(P.ml_dsa65_keypair_from_seed(leaf_seed)[0])
    return P.holder_key_set_root(pks)


def issuer_key(master: bytes) -> OrderedDict:
    material = hashlib.sha3_256(master + P256_LABEL.encode("utf-8")).digest()
    scalar = int.from_bytes(material, "big") % (N - 1) + 1
    vk = SigningKey.from_secret_exponent(scalar, curve=NIST256p).get_verifying_key()
    xi = hashlib.sha3_256(master + MLDSA_LABEL.encode("utf-8")).digest()
    mldsa_pk, _ = P.ml_dsa65_keypair_from_seed(xi)
    return OrderedDict(
        [
            ("expected_p256_material_hex", material.hex()),
            ("expected_p256_scalar_hex", scalar.to_bytes(32, "big").hex()),
            ("expected_pub_p256_b64", base64.b64encode(b"\x04" + vk.to_string()).decode("ascii")),
            ("expected_mldsa_xi_hex", xi.hex()),
            ("expected_pub_mldsa_b64", base64.b64encode(mldsa_pk).decode("ascii")),
        ]
    )


def vector(name, master_hex, size, why):
    master = bytes.fromhex(master_hex)
    root = holder_root(master, size)
    out = OrderedDict(
        [
            ("name", name),
            ("why", why),
            ("master_seed_hex", master_hex),
            ("tree_size", size),
            ("expected_holder_key_set_root", root),
        ]
    )
    out.update(issuer_key(master))
    out["expected_default_key_id"] = f"issuer:{root[:32]}"
    return out


COUNTING = bytes(range(32)).hex()
vectors = [
    vector("counting seed, single-leaf key set", COUNTING, 1,
           "the stable-mode issuer: one leaf, so the default key id comes from a one-leaf root"),
    vector("counting seed, two-leaf key set", COUNTING, 2,
           "same seed, larger tree: the root and therefore the default key id change, the key does not"),
    vector("counting seed, five-leaf key set", COUNTING, 5,
           "an odd-width tree: again a new default key id over the same key"),
    vector("0x42 seed, single-leaf key set", "42" * 32, 1,
           "a second seed: a different key, as expected"),
    vector("0x42 seed, three-leaf key set", "42" * 32, 3,
           "the second seed at another tree size: the key stays put"),
    vector("all-ff seed, single-leaf key set", "ff" * 32, 1,
           "the top of the seed range, where a wrong reduction would show"),
]

base = issuer_key(bytes.fromhex(COUNTING))
key_id_cases = [
    OrderedDict(
        [
            ("name", name),
            ("why", why),
            ("master_seed_hex", COUNTING),
            ("issuer_key_id", kid),
            ("expected_pub_p256_b64", base["expected_pub_p256_b64"]),
            ("expected_pub_mldsa_b64", base["expected_pub_mldsa_b64"]),
        ]
    )
    for name, kid, why in [
        ("default key id of the single-leaf tree", vectors[0]["expected_default_key_id"],
         "the id an issuer gets when it configures none"),
        ("default key id of the five-leaf tree", vectors[2]["expected_default_key_id"],
         "another tree size's default: still the same key"),
        ("caller-chosen label", "issuer:custom-label",
         "a label the integrator picked"),
        ("external key-management label", "kms:example/issuer-7",
         "a label shaped like a key-management reference; it names the key and changes nothing about it"),
    ]
]

doc = OrderedDict(
    [
        ("profile", "issuer-key-derivation/1"),
        (
            "description",
            "The composite key an issuer signs its base_certificates with, derived from the same 32-byte master seed "
            "as its operation-key tree. The key depends on the seed alone: the issuer key id is a label stamped into "
            "the certificate's signer block and never enters the derivation. Two implementations that derive "
            "differently give one issuer two signing identities, and certificates from the same seed stop being "
            "recognizable as the same issuer's.",
        ),
        (
            "rules",
            OrderedDict(
                [
                    (
                        "p256",
                        "material = SHA3-256(master_seed || UTF-8(\"issuer-cert-key/p256\")). scalar = (int_be(material) "
                        "mod (n - 1)) + 1, with n the P-256 group order, so the scalar is always in [1, n-1]; written as "
                        "32 big-endian bytes. Public key: SEC1 uncompressed (0x04 || X || Y, 65 bytes), standard base64 "
                        "with padding.",
                    ),
                    (
                        "mldsa65",
                        "xi = SHA3-256(master_seed || UTF-8(\"issuer-cert-key/mldsa\")). FIPS 204 ML-DSA-65 "
                        "KeyGen_internal with that xi. Public key: standard base64 with padding.",
                    ),
                    (
                        "key_id",
                        "The issuer key id is a label only. It is carried in signer.id and changes neither component: "
                        "the same seed under any id yields the same two public keys.",
                    ),
                    (
                        "default_key_id",
                        "When no id is configured: \"issuer:\" + holder_key_set_root[0:32], where holder_key_set_root is "
                        "the holder-keyset root of the issuer's own operation-key tree (leaf i's ML-DSA-65 key is "
                        "KeyGen_internal with xi = SHA3-256(master_seed || UTF-8(\"op-key/\" + decimal(i))), for i in "
                        "[0, tree_size)). The root depends on tree_size, so the default id does too; the key does not.",
                    ),
                    (
                        "domain_separation",
                        "The two labels differ from each other and from \"op-key/<i>\", so the signing key is "
                        "independent of every operation key derived from the same seed.",
                    ),
                    (
                        "not_key_derivation_1",
                        "This is not key-derivation/1. That family fixes the composite key materialized from a "
                        "ceremony seed (HKDF-SHA3-256, mod n, the seed itself as the ML-DSA-65 xi). The construction "
                        "here is the issuer's and folds its P-256 scalar differently; the two give different keys from "
                        "the same seed by design.",
                    ),
                ]
            ),
        ),
        (
            "why_this_is_a_primitive",
            "A divergence here produces certificates that verify: each one carries its own public keys in the signer "
            "block. What breaks is that the same issuer, running two implementations from one seed, signs under two "
            "identities, so a verifier that recognizes issuers by their public keys sees two strangers. No digest "
            "comparison catches that.",
        ),
        ("vectors", vectors),
        ("key_id_cases", key_id_cases),
    ]
)

with open(OUT, "w", encoding="utf-8") as fh:
    json.dump(doc, fh, indent=2, ensure_ascii=False)
    fh.write("\n")
print("vectors:", len(vectors), "key_id_cases:", len(key_id_cases))
