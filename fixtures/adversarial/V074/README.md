# V074 — Opaque Subject Delivered As Records

The certificate's one subject is subject.binary/1: one opaque input. The delivery
hands it over as a list of leaf files, as if it were a collection. Proving a
container is not proving its contents, and the verifier does not decompose an
opaque subject (verifier-toolkit/1 §8.5.4).
Expected: REJECTED (ORIGINAL_MATERIAL_COMPARISON_VALID)